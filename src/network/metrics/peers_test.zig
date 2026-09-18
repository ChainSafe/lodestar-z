const ConnectionClients = @import("peers.zig").ConnectionClients;
const Snapshot = @import("peers.zig").Snapshot;
const catalog = @import("../peers/catalog.zig");
const client = @import("../peers/client.zig");
const prom = @import("registry.zig");
const std = @import("std");

test "peer population metrics preserve metadata availability, direction, age and source scores" {
    var snapshot: Snapshot = .{};
    var row: catalog.Row = .{ .connection = .{ .index = 0, .generation = 0 }, .connected_at_ms = 1000 };
    row.reputation.score = -20;
    snapshot.observe(&row, .Unknown, 6000);
    row.direction = .outbound;
    row.metadata = .{ .seq_number = 1, .attnets = @splat(255), .syncnets = 0, .custody_group_count = 128 };
    snapshot.observe(&row, .Unknown, 500);
    try std.testing.expectEqual(@as(u16, 1), snapshot.metadata);
    try std.testing.expectEqual(@as(u16, 1), snapshot.custody_metadata);
    try std.testing.expectEqualSlices(u16, &.{ 1, 1 }, &snapshot.directions[@intFromEnum(client.Client.Unknown)]);
    try std.testing.expectEqual(@as(u16, 2), snapshot.clientCount(.Unknown));
    try std.testing.expectEqualSlices(u16, &.{ 1, 1 }, &snapshot.directionCounts());
    try std.testing.expectEqual(@as(u64, 2), snapshot.ages.buckets[0]);
    try std.testing.expectEqual(@as(f64, 5), snapshot.ages.sum);
    try std.testing.expectEqual(@as(f64, 64), snapshot.attnets.sum);
    try std.testing.expectEqual(@as(f64, 128), snapshot.custody.sum);
    try std.testing.expectEqual(@as(f64, -20), row.reputation.score);
    var buffer: [16 * 1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    var encoder: prom.Encoder = .{ .writer = &writer };
    try snapshot.write(&encoder);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "lodestar_app_peer_score_bucket{client=\"Unknown\",le=\"-20\"} 2\n") != null);
}

test "metrics connection attribution checks generations and unknown slots" {
    var clients: ConnectionClients = .{};
    try std.testing.expectEqual(client.Client.Unknown, clients.get(.{ .index = 7, .generation = 0 }));
    clients.put(.{ .index = 7, .generation = 1 }, .Lighthouse);
    try std.testing.expectEqual(client.Client.Lighthouse, clients.get(.{ .index = 7, .generation = 1 }));
    try std.testing.expectEqual(client.Client.Unknown, clients.get(.{ .index = 7, .generation = 2 }));
    clients.put(.{ .index = 7, .generation = 2 }, .Lodestar);
    try std.testing.expectEqual(client.Client.Unknown, clients.get(.{ .index = 7, .generation = 1 }));
    try std.testing.expectEqual(client.Client.Lodestar, clients.get(.{ .index = 7, .generation = 2 }));
}
