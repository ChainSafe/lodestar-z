const std = @import("std");
const limits = @import("limits.zig");
const types = @import("../types.zig");

const assert = std.debug.assert;

const half: usize = @divExact(limits.streams_per_connection, 2);
const pending_max: u16 = 3 * half;

comptime {
    assert(limits.streams_per_connection <= std.math.maxInt(u8) + 1);
}

pub const Entry = struct {
    id: u64 = 0,
    reset_code: u64 = 0,
    claimed: bool = false,
    reset: bool = false,
    opened_pending: bool = false,
    closed_pending: bool = false,
    fin_sent: bool = false,
    fin_received: bool = false,
};

comptime {
    assert(@sizeOf(Entry) <= 24);
}

pub const StreamTable = struct {
    entries: [limits.streams_per_connection]Entry = [_]Entry{.{}} ** limits.streams_per_connection,
    pending: u16 = 0,
    next_local_id: u64 = 0,
    event_cursor: u8 = 0,

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
            if (!entry.claimed) continue;
            if (entry.id == id) return @intCast(index);
        }
        return null;
    }

    pub fn matches(self: *const StreamTable, index: u8, id: u64) bool {
        if (index >= limits.streams_per_connection) return false;
        const entry = &self.entries[index];
        if (!entry.claimed) return false;
        if (entry.closed_pending) return false;
        return entry.id == id;
    }

    pub fn freeLocal(self: *const StreamTable) ?u8 {
        return self.freeIn(0);
    }

    pub fn claimLocal(self: *StreamTable, index: u8, id: u64) void {
        assert(id == self.next_local_id);
        assert(self.find(id) == null);
        assert(index < half);
        assert(!self.entries[index].claimed);
        self.entries[index] = .{ .id = id, .claimed = true };
        self.next_local_id = id + 4;
    }

    pub fn claimPeer(self: *StreamTable, id: u64) ?u8 {
        assert(self.find(id) == null);
        assert(self.pending < pending_max);
        const index = self.freeIn(half) orelse return null;
        assert(index >= half);
        self.entries[index] = .{ .id = id, .claimed = true, .opened_pending = true };
        self.pending += 1;
        assert(self.pending <= pending_max);
        return index;
    }

    pub fn markFinSent(self: *StreamTable, index: u8) void {
        assert(index < limits.streams_per_connection);
        assert(self.entries[index].claimed);
        assert(!self.entries[index].closed_pending);
        self.entries[index].fin_sent = true;
    }

    pub fn markFinReceived(self: *StreamTable, index: u8) void {
        assert(index < limits.streams_per_connection);
        assert(self.entries[index].claimed);
        assert(!self.entries[index].closed_pending);
        self.entries[index].fin_received = true;
    }

    pub fn clear(self: *StreamTable, index: u8, reset_code: ?u64) void {
        assert(index < limits.streams_per_connection);
        const entry = &self.entries[index];
        assert(entry.claimed);
        if (entry.closed_pending) return;
        assert(self.pending < pending_max);
        entry.closed_pending = true;
        if (reset_code) |code| {
            entry.reset = true;
            entry.reset_code = code;
        }
        self.pending += 1;
        assert(self.pending <= pending_max);
    }

    pub fn takeOpened(self: *StreamTable, index: u8) void {
        assert(index < limits.streams_per_connection);
        const entry = &self.entries[index];
        assert(entry.opened_pending);
        assert(self.pending > 0);
        entry.opened_pending = false;
        self.pending -= 1;
    }

    pub fn takeClosed(self: *StreamTable, index: u8) ?struct { id: u64, reset_code: ?u64 } {
        assert(index < limits.streams_per_connection);
        const entry = &self.entries[index];
        if (!entry.closed_pending) return null;
        assert(!entry.opened_pending);
        assert(self.pending > 0);
        const id = entry.id;
        const reset_code: ?u64 = if (entry.reset) entry.reset_code else null;
        entry.* = .{};
        self.pending -= 1;
        return .{ .id = id, .reset_code = reset_code };
    }

    pub fn discard(self: *StreamTable, index: u8) void {
        assert(index < limits.streams_per_connection);
        const entry = &self.entries[index];
        assert(entry.claimed);
        var reported: u16 = 0;
        if (entry.opened_pending) reported += 1;
        if (entry.closed_pending) reported += 1;
        assert(self.pending >= reported);
        entry.* = .{};
        self.pending -= reported;
    }

    fn freeIn(self: *const StreamTable, start: usize) ?u8 {
        assert(start == 0 or start == half);
        for (self.entries[start .. start + half], start..) |*entry, index| {
            if (!entry.claimed) return @intCast(index);
        }
        return null;
    }
};
