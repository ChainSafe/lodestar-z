const std = @import("std");
const n = @import("network");
const t = n.peers.types;
const capacity = 512;
const Row = struct {
    generation: u64 = 0,
    identity: ?n.PeerId = null,
    counts: [4]u8 = @splat(0),
};
pub const Report = struct { peer: t.PeerRef, action: t.PeerAction };

pub const Table = struct {
    rows: [capacity]Row = @splat(.{}),
    pending: u32 = 0,
    ignored: u64 = 0,
    cursor: u16 = 0,

    pub fn sync(self: *Table, catalog: *const n.peers.catalog.Catalog) void {
        std.debug.assert(catalog.rows.len <= capacity);
        for (catalog.rows, 0..) |*source, i| {
            const row = &self.rows[i];
            if (source.occupied and row.identity != null and source.generation == row.generation) continue;
            for (row.counts) |count| self.pending -= count;
            row.* = .{ .generation = source.generation, .identity = if (source.occupied) source.identity else null };
        }
    }

    pub fn add(self: *Table, identity: *const n.PeerId, action: t.PeerAction) void {
        for (&self.rows) |*row| {
            const known = row.identity orelse continue;
            if (!known.eql(identity)) continue;
            const count = &row.counts[@intFromEnum(action)];
            // A hundred of the smallest penalty already reaches the score floor.
            if (count.* < 100) {
                count.* += 1;
                self.pending += 1;
            }
            return;
        }
        self.ignored +|= 1;
    }

    pub fn next(self: *Table) ?Report {
        if (self.pending == 0) return null;
        for (0..capacity) |_| {
            const index = self.cursor;
            self.cursor = (self.cursor + 1) % capacity;
            const row = &self.rows[index];
            for (&row.counts, 0..) |*count, action| {
                if (count.* == 0) continue;
                count.* -= 1;
                self.pending -= 1;
                return .{ .peer = .{ .index = index, .generation = row.generation }, .action = @enumFromInt(action) };
            }
        }
        unreachable;
    }
};

test "peer reports accumulate independently and retire with the peer generation" {
    var table: Table = .{};
    const identity: n.PeerId = .{ .bytes = @splat(1) };
    table.rows[0] = .{ .identity = identity, .generation = 1 };
    for (0..3) |_| table.add(&identity, .high_tolerance);
    table.add(&identity, .low_tolerance);
    var counts = [_]u8{0} ** 4;
    for (0..4) |_| {
        const report = table.next().?;
        try std.testing.expectEqual(@as(u64, 1), report.peer.generation);
        counts[@intFromEnum(report.action)] += 1;
    }
    try std.testing.expectEqual(@as(u8, 3), counts[@intFromEnum(t.PeerAction.high_tolerance)]);
    try std.testing.expectEqual(@as(u8, 1), counts[@intFromEnum(t.PeerAction.low_tolerance)]);
    try std.testing.expect(table.next() == null);
    for (0..256) |_| table.add(&identity, .high_tolerance);
    try std.testing.expectEqual(@as(u32, 100), table.pending);
    var catalog = try n.peers.catalog.Catalog.init(std.testing.allocator, .{});
    defer catalog.deinit(std.testing.allocator);
    table.sync(&catalog);
    try std.testing.expect(table.next() == null);
    table.add(&identity, .fatal);
    try std.testing.expectEqual(@as(u64, 1), table.ignored);
}
