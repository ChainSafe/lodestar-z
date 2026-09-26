const Distribution = @import("peers.zig").Distribution;
const catalog = @import("../peers/catalog.zig");
const client = @import("../peers/client.zig");
const prom = @import("registry.zig");
const std = @import("std");

test "peer population metrics count direction, client and connection age" {
    var snapshot: Distribution = .{};
    var row: catalog.Row = .{ .connection = .{ .index = 0, .generation = 0 }, .connected_at_ms = 1000 };
    snapshot.observe(&row, .Unknown, 6000);
    row.direction = .outbound;
    snapshot.observe(&row, .Unknown, 500);
    try std.testing.expectEqualSlices(u16, &.{ 1, 1 }, &snapshot.directions[@intFromEnum(client.Client.Unknown)]);
    try std.testing.expectEqual(@as(u16, 2), snapshot.clientCount(.Unknown));
    try std.testing.expectEqualSlices(u16, &.{ 1, 1 }, &snapshot.directionCounts());
    try std.testing.expectEqual(@as(u64, 2), snapshot.ages.buckets[0]);
    try std.testing.expectEqual(@as(f64, 5), snapshot.ages.sum);
    var buffer: [16 * 1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    var encoder: prom.Encoder = .{ .writer = &writer };
    try snapshot.write(&encoder);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "lodestar_peer_connection_seconds_count 2\n") != null);
}
