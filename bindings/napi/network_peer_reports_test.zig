const std = @import("std");
const n = @import("network");
const Table = @import("network_peer_reports.zig").Table;

fn identity(value: u32) n.PeerId {
    var result: n.PeerId = .{ .bytes = @splat(0) };
    std.mem.writeInt(u32, result.bytes[0..4], value, .little);
    return result;
}

test "peer reports coalesce by identity, rotate fairly and release drained rows" {
    var table: Table = .{};
    for (0..300) |_| table.add(&identity(1), .high_tolerance);
    table.add(&identity(2), .fatal);
    table.add(&identity(1), .low_tolerance);
    try std.testing.expectEqual(@as(u32, 102), table.pending);
    try std.testing.expect(table.next().?.identity.eql(&identity(1)));
    try std.testing.expect(table.next().?.identity.eql(&identity(2)));
    for (0..100) |_| try std.testing.expect(table.next().?.identity.eql(&identity(1)));
    try std.testing.expect(table.next() == null);
    for (table.rows) |row| try std.testing.expect(!row.occupied);
    table.add(&identity(1), .fatal);
    try std.testing.expectEqual(n.peers.PeerAction.fatal, table.next().?.action);
    try std.testing.expect(table.next() == null);
}

test "full report table still coalesces existing identities and reuses released capacity" {
    var table: Table = .{};
    for (0..table.rows.len) |i| table.add(&identity(@intCast(i)), .high_tolerance);
    table.add(&identity(600), .fatal);
    try std.testing.expectEqual(@as(u64, 1), table.ignored);
    table.add(&identity(0), .high_tolerance);
    try std.testing.expectEqual(@as(u32, 513), table.pending);
    _ = table.next().?;
    _ = table.next().?;
    table.add(&identity(600), .fatal);
    try std.testing.expectEqual(@as(u64, 1), table.ignored);
    var count: usize = 0;
    for (0..513) |_| {
        const report = table.next() orelse break;
        if (report.identity.eql(&identity(600))) count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(@as(u32, 0), table.pending);
}
