const std = @import("std");
const constants = @import("constants.zig");
const index_list = @import("../index_list.zig");
const Handle = @import("../quic/engine.zig").Handle;
const StreamHandle = @import("../quic/engine.zig").StreamHandle;
const MessageId = @import("topic.zig").MessageId;
const Version = @import("protocol.zig").Version;
const Options = @import("options.zig").Options;
pub const Outbound = union(enum) {
    /// No scheduled opening. New inbound stream evidence may return this to pending.
    none,
    pending,
    retry_at: u64,
    negotiating: StreamHandle,
    live: struct { stream: StreamHandle, version: Version },
    closing: StreamHandle,
};

pub const Session = struct {
    io: @import("peer_io.zig").PeerIo,
    outbound: Outbound = .none,
    /// Membership of `Sessions.ready`.
    ready_link: index_list.Link = .{},
    logical: @import("peer_book.zig").Ref = undefined,
    active: bool = false,
    generation: u64 = 0,
    conn: Handle = undefined,
    /// Named by the connection's identify exchange; unknown until it completes.
    client: @import("../peers/client.zig").Client = .Unknown,
    /// The budget of the turn that stopped before visiting this session while it was writable. It
    /// clears at the session's next visit or when its output is cancelled.
    unserved: ?@import("turn.zig").Budget = null,
    in_stream: ?StreamHandle = null,
    dont_send: [constants.dont_send_cap]MessageId = undefined,
    dont_send_until: [constants.dont_send_cap]u64 = undefined,
    dont_send_head: u8 = 0,
    dont_send_len: u8 = 0,

    pub fn start(self: *Session, conn: Handle) void {
        std.debug.assert(!self.active and self.generation < std.math.maxInt(u64));
        std.debug.assert(!self.ready_link.linked);
        self.io.startSession();
        self.* = .{ .io = self.io, .generation = self.generation + 1, .conn = conn, .active = true, .outbound = .pending };
    }

    /// The session can make progress now: an outbound opening or close to run, an inbound stream
    /// with unread bytes, or writable output.
    pub fn wants(self: *const Session) bool {
        if (self.outbound == .pending or self.outbound == .closing) return true;
        if (self.in_stream != null and self.io.rx_ready) return true;
        return self.writable();
    }

    /// Output queued on an out stream whose last write did not block.
    pub fn writable(self: *const Session) bool {
        const tx = &self.io.tx;
        return self.outStream() != null and tx.ready and (tx.pending() or tx.subscription_dirty.count() > 0);
    }

    /// The earliest IO deadline or outbound retry.
    pub fn deadline(self: *const Session, options: *const Options) ?u64 {
        var next = self.io.deadlines(options).next();
        if (self.outbound == .retry_at) next = @min(next orelse self.outbound.retry_at, self.outbound.retry_at);
        return next;
    }

    pub fn suppresses(self: *const Session, id: MessageId, now: u64) bool {
        for (0..self.dont_send_len) |offset| {
            const at = (@as(usize, self.dont_send_head) + constants.dont_send_cap - 1 - offset) %
                constants.dont_send_cap;
            if (now < self.dont_send_until[at] and std.mem.eql(u8, &self.dont_send[at], &id)) return true;
        }
        return false;
    }

    pub fn suppress(self: *Session, id: MessageId, now: u64, ttl: u64) void {
        if (self.suppresses(id, now)) return;
        self.dont_send[self.dont_send_head] = id;
        self.dont_send_until[self.dont_send_head] = now +| ttl;
        self.dont_send_head = @intCast((self.dont_send_head + 1) % constants.dont_send_cap);
        if (self.dont_send_len < constants.dont_send_cap) self.dont_send_len += 1;
    }
    pub fn outStream(self: *const Session) ?StreamHandle {
        return switch (self.outbound) {
            .live => |live| live.stream,
            else => null,
        };
    }
};
