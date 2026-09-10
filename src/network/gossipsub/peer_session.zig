const std = @import("std");
const constants = @import("constants.zig");
const Handle = @import("../quic/engine.zig").Handle;
const StreamHandle = @import("../quic/engine.zig").StreamHandle;
const MessageId = @import("topic.zig").MessageId;
const Version = @import("sessions.zig").Version;
pub const retry_min_ms: u64 = 1000;
pub const retry_max_ms: u64 = 30000;
pub const Outbound = union(enum) { waiting: u64, negotiating: StreamHandle, live: StreamHandle };

pub const Session = struct {
    io: @import("peer_io.zig").PeerIo,
    outbound: Outbound = .{ .waiting = 0 },
    failures: u8 = 0,
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

    pub fn retry(self: *Session, now_ms: u64) void {
        const delay = @min(retry_max_ms, retry_min_ms << @as(u6, @intCast(self.failures)));
        self.failures = @min(self.failures + 1, 5);
        self.outbound = .{ .waiting = now_ms +| delay };
        self.needs_service = true;
    }
};
