const std = @import("std");
const catalog = @import("peers/catalog.zig");
const client = @import("peers/client.zig");
const prom = @import("metrics_prometheus.zig");
const Distribution = @import("metrics_distribution.zig").Distribution;
const client_count = @typeInfo(client.Client).@"enum".fields.len;
const AppScore = Distribution(&.{ -100, -50, -20, 0, 25 });
const GossipScore = Distribution(&.{ -16000, -8000, -4000, -1000, 0, 5, 100 });

pub const Snapshot = struct {
    app_scores: [client_count]AppScore = @splat(.{}),
    gossip_scores: [client_count]GossipScore = @splat(.{}),
    directions: [client_count][2]u16 = @splat(@splat(0)),
    ages: Distribution(&.{ 5, 20, 60, 180, 600, 1200, 3600, 21600, 86400 }) = .{},
    attnets: Distribution(&.{ 0, 4, 16, 32, 64 }) = .{},
    custody: Distribution(&.{ 0, 4, 8, 16, 32, 64, 128 }) = .{},
    metadata: u16 = 0,
    custody_metadata: u16 = 0,
    identified: u16 = 0,
    closing: u16 = 0,

    pub fn observe(self: *Snapshot, row: *const catalog.Row, now_ms: u64) void {
        std.debug.assert(row.connection != null);
        const index = @intFromEnum(client.fromIdentify(&row.identify));
        self.directions[index][@intFromEnum(row.direction)] += 1;
        self.ages.observe(@as(f64, @floatFromInt(now_ms -| row.connected_at_ms)) / 1000);
        self.app_scores[index].observe(row.reputation.score);
        self.identified += @intFromBool(row.identify != null);
        self.closing += @intFromBool(row.closing_reason != null);
        var attnets: u8 = 0;
        var custody: u64 = 0;
        if (row.metadata) |metadata| {
            self.metadata += 1;
            for (metadata.attnets) |byte| attnets += @popCount(byte);
            if (metadata.custody_group_count) |count| {
                custody = count;
                self.custody_metadata += 1;
            }
        }
        self.attnets.observe(@floatFromInt(attnets));
        self.custody.observe(@floatFromInt(custody));
    }

    pub fn write(self: *const Snapshot, w: *std.Io.Writer) std.Io.Writer.Error!void {
        inline for (.{
            .{ "lodestar_peer_connection_seconds", "ages", "Current connection ages in seconds; rebuilt each snapshot" },
            .{ "lodestar_peer_long_lived_attnets_count", "attnets", "Current connected peer attnet counts; unavailable metadata counts as zero" },
            .{ "lodestar_peer_column_group_count", "custody", "Current advertised custody group counts; unavailable metadata counts as zero" },
        }) |metric| {
            try prom.family(w, metric[0], .histogram, metric[2]);
            try prom.histogram(w, metric[0], null, "", &@field(self, metric[1]));
        }
        inline for (.{
            .{ "lodestar_app_peer_score", "app_scores" },
            .{ "lodestar_gossip_score_by_client", "gossip_scores" },
        }) |metric| {
            try prom.family(w, metric[0], .histogram, "Current connected peer scores; rebuilt each snapshot");
            inline for (@typeInfo(client.Client).@"enum".fields) |field|
                try prom.histogram(w, metric[0], "client", field.name, &@field(self, metric[1])[field.value]);
        }
        try prom.family(w, "lodestar_native_peers_by_client_direction", .gauge, "Connected peers by client and direction");
        inline for (@typeInfo(client.Client).@"enum".fields) |field| {
            inline for (.{ "inbound", "outbound" }, 0..) |direction, index| {
                try w.print("lodestar_native_peers_by_client_direction{{client=\"" ++ field.name ++
                    "\",direction=\"" ++ direction ++ "\"}} {d}\n", .{self.directions[field.value][index]});
            }
        }
        inline for (.{ "metadata", "custody_metadata", "identified", "closing" }) |field|
            try prom.scalar(w, "lodestar_native_peers_" ++ field, .gauge, "Connected peers with " ++ field, @field(self, field));
    }
};

test "peer population metrics preserve metadata availability, direction, age and source scores" {
    var snapshot: Snapshot = .{};
    var row: catalog.Row = .{ .connection = .{ .index = 0, .generation = 0 }, .connected_at_ms = 1000 };
    row.reputation.score = -20;
    snapshot.observe(&row, 6000);
    row.direction = .outbound;
    row.metadata = .{ .seq_number = 1, .attnets = @splat(255), .syncnets = 0, .custody_group_count = 128 };
    snapshot.observe(&row, 500);
    try std.testing.expectEqual(@as(u16, 1), snapshot.metadata);
    try std.testing.expectEqual(@as(u16, 1), snapshot.custody_metadata);
    try std.testing.expectEqualSlices(u16, &.{ 1, 1 }, &snapshot.directions[@intFromEnum(client.Client.Unknown)]);
    try std.testing.expectEqual(@as(u64, 2), snapshot.ages.buckets[0]);
    try std.testing.expectEqual(@as(f64, 5), snapshot.ages.sum);
    try std.testing.expectEqual(@as(f64, 64), snapshot.attnets.sum);
    try std.testing.expectEqual(@as(f64, 128), snapshot.custody.sum);
    try std.testing.expectEqual(@as(f64, -20), row.reputation.score);
    var buffer: [16 * 1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try snapshot.write(&writer);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "lodestar_app_peer_score_bucket{client=\"Unknown\",le=\"-20\"} 2\n") != null);
}
