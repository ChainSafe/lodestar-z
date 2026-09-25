const std = @import("std");
const n = @import("network");
const t = n.peers.types;
const identity_index = n.peers.identity_index;
const capacity = 512;
/// Reports of one action per identity beyond this add nothing.
pub const report_max = 100;
const Row = struct {
    occupied: bool = false,
    identity: n.PeerId = undefined,
    counts: [4]u8 = @splat(0),
};
pub const Report = struct { identity: n.PeerId, action: t.PeerAction };

pub const Table = struct {
    rows: [capacity]Row = @splat(.{}),
    by_identity: [identity_index.capacity(capacity)]u16 = @splat(identity_index.empty),
    seed: u64 = 0,
    pending: u32 = 0,
    ignored: u64 = 0,
    cursor: u16 = 0,

    fn index(self: *Table) identity_index.Index {
        return .{ .slots = &self.by_identity, .seed = self.seed };
    }

    /// Adds `count` reports of one action, saturating at `report_max` per identity and action.
    pub fn addCount(self: *Table, identity: *const n.PeerId, action: t.PeerAction, count: u8) void {
        const lookup = self.index();
        const row_index = lookup.find(&self.rows, identity) orelse vacant: {
            for (&self.rows, 0..) |*row, i| {
                if (row.occupied) continue;
                row.* = .{ .occupied = true, .identity = identity.* };
                lookup.insert(&self.rows, @intCast(i));
                break :vacant @as(u16, @intCast(i));
            }
            self.ignored +|= 1;
            return;
        };
        const counted = &self.rows[row_index].counts[@intFromEnum(action)];
        // A hundred of the smallest penalty already reaches the score floor.
        const added = @min(count, report_max - counted.*);
        counted.* += added;
        self.pending += added;
    }

    pub fn next(self: *Table) ?Report {
        if (self.pending == 0) return null;
        for (0..capacity) |_| {
            const row_index = self.cursor;
            self.cursor = (self.cursor + 1) % capacity;
            const row = &self.rows[row_index];
            if (!row.occupied) continue;
            for (&row.counts, 0..) |*count, action| {
                if (count.* == 0) continue;
                count.* -= 1;
                self.pending -= 1;
                const report: Report = .{ .identity = row.identity, .action = @enumFromInt(action) };
                if (std.mem.allEqual(u8, &row.counts, 0)) {
                    self.index().remove(&self.rows, &row.identity);
                    row.* = .{};
                }
                return report;
            }
            unreachable;
        }
        unreachable;
    }
};

test {
    _ = @import("network_peer_reports_test.zig");
}
