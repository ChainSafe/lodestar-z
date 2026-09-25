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
    for (0..300) |_| table.addCount(&identity(1), .high_tolerance, 1);
    table.addCount(&identity(2), .fatal, 1);
    table.addCount(&identity(1), .low_tolerance, 1);
    try std.testing.expectEqual(@as(u32, 102), table.pending);
    try std.testing.expect(table.next().?.identity.eql(&identity(1)));
    try std.testing.expect(table.next().?.identity.eql(&identity(2)));
    for (0..100) |_| try std.testing.expect(table.next().?.identity.eql(&identity(1)));
    try std.testing.expect(table.next() == null);
    for (table.rows) |row| try std.testing.expect(!row.occupied);
    table.addCount(&identity(1), .fatal, 1);
    try std.testing.expectEqual(n.peers.PeerAction.fatal, table.next().?.action);
    try std.testing.expect(table.next() == null);
}

test "full report table still coalesces existing identities and reuses released capacity" {
    var table: Table = .{};
    for (0..table.rows.len) |i| table.addCount(&identity(@intCast(i)), .high_tolerance, 1);
    table.addCount(&identity(600), .fatal, 1);
    try std.testing.expectEqual(@as(u64, 1), table.ignored);
    table.addCount(&identity(0), .high_tolerance, 1);
    try std.testing.expectEqual(@as(u32, 513), table.pending);
    _ = table.next().?;
    _ = table.next().?;
    table.addCount(&identity(600), .fatal, 1);
    try std.testing.expectEqual(@as(u64, 1), table.ignored);
    var count: usize = 0;
    for (0..513) |_| {
        const report = table.next() orelse break;
        if (report.identity.eql(&identity(600))) count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(@as(u32, 0), table.pending);
}

test "counted reports saturate as the same number of single reports do" {
    var counted: Table = .{};
    var single: Table = .{};
    for ([_]u8{ 1, 40, 70, 100 }) |count| {
        counted.addCount(&identity(1), .mid_tolerance, count);
        for (0..count) |_| single.addCount(&identity(1), .mid_tolerance, 1);
        try std.testing.expectEqual(single.pending, counted.pending);
        try std.testing.expectEqualSlices(u8, &single.rows[0].counts, &counted.rows[0].counts);
    }
    try std.testing.expectEqual(@as(u32, @import("network_peer_reports.zig").report_max), counted.pending);
}
