const std = @import("std");
const limits = @import("limits.zig");
const types = @import("../types.zig");

const assert = std.debug.assert;

const half: usize = @divExact(limits.streams_per_connection, 2);

comptime {
    assert(limits.streams_per_connection <= std.math.maxInt(u8) + 1);
}

pub const Entry = struct {
    id: ?u64 = null,
    opened_pending: bool = false,
    fin_sent: bool = false,
    fin_received: bool = false,
};

pub const StreamTable = struct {
    entries: [limits.streams_per_connection]Entry = [_]Entry{.{}} ** limits.streams_per_connection,
    pending: u16 = 0,
    next_local_id: u64 = 0,

    pub fn init(direction: types.Direction) StreamTable {
        const first: u64 = if (direction == .outbound) 0 else 1;
        assert(first < 4);
        assert(!isPeerInitiated(direction, first));
        return .{ .next_local_id = first };
    }

    pub fn isPeerInitiated(direction: types.Direction, id: u64) bool {
        const peer_bit: u64 = if (direction == .outbound) 1 else 0;
        return (id & 0x3) == peer_bit;
    }

    pub fn find(self: *const StreamTable, id: u64) ?u8 {
        for (&self.entries, 0..) |*entry, index| {
            const claimed = entry.id orelse continue;
            if (claimed == id) return @intCast(index);
        }
        return null;
    }

    pub fn freeLocal(self: *const StreamTable) ?u8 {
        return self.freeIn(0);
    }

    pub fn claimLocal(self: *StreamTable, index: u8, id: u64) void {
        assert(id == self.next_local_id);
        assert(self.find(id) == null);
        assert(index < half);
        assert(self.entries[index].id == null);
        self.entries[index] = .{ .id = id };
        self.next_local_id = id + 4;
    }

    pub fn claimPeer(self: *StreamTable, id: u64) ?u8 {
        assert(self.find(id) == null);
        assert(self.pending <= half);
        const index = self.freeIn(half) orelse return null;
        assert(index >= half);
        self.entries[index] = .{ .id = id, .opened_pending = true };
        self.pending += 1;
        assert(self.pending <= half);
        return index;
    }

    pub fn markFinSent(self: *StreamTable, index: u8) void {
        assert(index < limits.streams_per_connection);
        assert(self.entries[index].id != null);
        self.entries[index].fin_sent = true;
    }

    pub fn markFinReceived(self: *StreamTable, index: u8) void {
        assert(index < limits.streams_per_connection);
        assert(self.entries[index].id != null);
        self.entries[index].fin_received = true;
    }

    pub fn clear(self: *StreamTable, index: u8) void {
        assert(index < limits.streams_per_connection);
        const entry = &self.entries[index];
        if (entry.opened_pending) {
            assert(self.pending > 0);
            self.pending -= 1;
        }
        entry.* = .{};
        assert(entry.id == null);
    }

    fn freeIn(self: *const StreamTable, start: usize) ?u8 {
        assert(start == 0 or start == half);
        for (self.entries[start .. start + half], start..) |*entry, index| {
            if (entry.id == null) return @intCast(index);
        }
        return null;
    }
};
