const std = @import("std");
const api = @import("api.zig");
const binding = @import("binding.zig");
const connection = @import("connection.zig");
const limits = @import("limits.zig");

const assert = std.debug.assert;
const c = binding.c;

pub const Readiness = enum { readable, writable };

pub fn StreamIterator(comptime readiness: Readiness) type {
    return struct {
        const Self = @This();

        iter: ?*c.quiche_stream_iter,
        slot: ?*connection.Slot,
        conn: api.Handle,
        seen: u16 = 0,

        pub fn open(slot: *connection.Slot, conn: api.Handle) Self {
            assert(slot.conn != null);
            assert(slot.generation == conn.generation);
            const iter = switch (readiness) {
                .readable => c.quiche_conn_readable(slot.conn.?),
                .writable => c.quiche_conn_writable(slot.conn.?),
            };
            return .{ .iter = iter, .slot = slot, .conn = conn };
        }

        pub fn empty(conn: api.Handle) Self {
            return .{ .iter = null, .slot = null, .conn = conn };
        }

        pub fn next(self: *Self) ?api.StreamHandle {
            const iter = self.iter orelse return null;
            const slot = self.slot orelse return null;
            assert(self.seen <= limits.streams_per_connection);
            var id: u64 = 0;
            while (self.seen < limits.streams_per_connection) : (self.seen += 1) {
                if (!c.quiche_stream_iter_next(iter, &id)) return null;
                const index = slot.streamIndex(id) orelse continue;
                assert(index < limits.streams_per_connection);
                if (!slot.table.matches(index, id)) continue;
                self.seen += 1;
                return .{ .conn = self.conn, .id = id, .slot = index };
            }
            return null;
        }

        pub fn deinit(self: *Self) void {
            if (self.iter) |iter| c.quiche_stream_iter_free(iter);
            self.* = undefined;
        }
    };
}
