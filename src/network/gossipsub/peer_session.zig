const std = @import("std");
const constants = @import("constants.zig");
const Handle = @import("../quic/engine.zig").Handle;
const StreamHandle = @import("../quic/engine.zig").StreamHandle;
const MessageId = @import("topic.zig").MessageId;
const Version = @import("sessions.zig").Version;
pub const Outbound = union(enum) { none, pending, negotiating: StreamHandle, live: StreamHandle, closing: StreamHandle };

pub const Session = struct {
    io: @import("peer_io.zig").PeerIo,
    outbound: Outbound = .none,
    needs_service: bool = false,
    logical: @import("peer_book.zig").Ref = undefined,
    active: bool = false,
    generation: u64 = 0,
    conn: Handle = undefined,
    version: Version = .v1_0,
    inbound_version: Version = .v1_0,
    in_stream: ?StreamHandle = null,
    dont_send: [constants.dont_send_cap]MessageId = undefined,
    dont_send_until: [constants.dont_send_cap]u64 = undefined,
    dont_send_head: u8 = 0,
    dont_send_len: u8 = 0,

    pub fn start(self: *Session, conn: Handle, version: Version) void {
        std.debug.assert(!self.active and self.generation < std.math.maxInt(u64));
        self.io.startSession();
        self.* = .{ .io = self.io, .generation = self.generation + 1, .conn = conn, .version = version, .active = true, .outbound = .pending };
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
            .live => |stream| stream,
            else => null,
        };
    }
};
