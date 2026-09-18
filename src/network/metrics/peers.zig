const std = @import("std");
const catalog = @import("../peers/catalog.zig");
const client = @import("../peers/client.zig");
const prom = @import("registry.zig");
const Distribution = @import("histogram.zig").Distribution;
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

    pub fn observe(self: *Snapshot, row: *const catalog.Row, kind: client.Client, now_ms: u64) void {
        std.debug.assert(row.connection != null);
        const index = @intFromEnum(kind);
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

    pub fn clientCount(self: *const Snapshot, kind: client.Client) u16 {
        const counts = self.directions[@intFromEnum(kind)];
        return counts[0] + counts[1];
    }

    pub fn directionCounts(self: *const Snapshot) [2]u16 {
        var counts: [2]u16 = @splat(0);
        for (self.directions) |row| for (&counts, row) |*total, count| {
            total.* += count;
        };
        return counts;
    }

    pub fn directionCount(self: *const Snapshot, direction: @import("../types.zig").Direction) u16 {
        return self.directionCounts()[@intFromEnum(direction)];
    }

    pub fn write(self: *const Snapshot, w: *prom.Encoder) prom.Error!void {
        inline for (.{
            .{ "lodestar_peer_connection_seconds", "ages", "Current connection ages in seconds; rebuilt each snapshot", prom.Unit.seconds },
            .{ "lodestar_peer_long_lived_attnets_count", "attnets", "Current connected peer attnet counts; unavailable metadata counts as zero", prom.Unit.scalar },
            .{ "lodestar_peer_column_group_count", "custody", "Current advertised custody group counts; unavailable metadata counts as zero", prom.Unit.scalar },
        }) |metric| {
            const population = try w.histograms(.{
                .name = metric[0],
                .kind = .histogram,
                .help = metric[2],
                .labels = &.{},
                .unit = metric[3],
            }, @TypeOf(@field(self, metric[1])));
            try population.histogram(.{}, &@field(self, metric[1]));
        }
        inline for (.{
            .{ "lodestar_app_peer_score", "app_scores" },
            .{ "lodestar_gossip_score_by_client", "gossip_scores" },
        }) |metric| {
            const scores = try w.histograms(.{
                .name = metric[0],
                .kind = .histogram,
                .help = "Current connected peer scores; rebuilt each snapshot",
                .labels = &.{"client"},
                .unit = .scalar,
            }, @TypeOf(@field(self, metric[1])[0]));
            inline for (@typeInfo(client.Client).@"enum".fields) |field|
                try scores.histogram(.{field.name}, &@field(self, metric[1])[field.value]);
        }
        const directions = try w.family(.{
            .name = "lodestar_native_peers_by_client_direction",
            .kind = .gauge,
            .help = "Connected peers by client and direction",
            .labels = &.{ "client", "direction" },
        });
        inline for (@typeInfo(client.Client).@"enum".fields) |field| {
            inline for (.{ "inbound", "outbound" }, 0..) |direction, index| {
                try directions.sample(.{ field.name, direction }, self.directions[field.value][index]);
            }
        }
        inline for (.{ "metadata", "custody_metadata", "identified", "closing" }) |field|
            try w.scalar(.{
                .name = "lodestar_native_peers_" ++ field,
                .kind = .gauge,
                .help = "Connected peers with " ++ field,
            }, @field(self, field));
    }
};

pub const ConnectionClients = struct {
    const Handle = @import("../types.zig").Handle;
    const Entry = struct { generation: u32 = 0, client: client.Client = .Unknown };
    entries: [@import("../quic/limits.zig").connections_max_ceiling]Entry = @splat(.{}),

    pub fn put(self: *ConnectionClients, connection: Handle, kind: client.Client) void {
        std.debug.assert(connection.index < self.entries.len);
        self.entries[connection.index] = .{ .generation = connection.generation, .client = kind };
    }

    pub fn get(self: *const ConnectionClients, connection: Handle) client.Client {
        std.debug.assert(connection.index < self.entries.len);
        const entry = self.entries[connection.index];
        return if (entry.generation == connection.generation) entry.client else .Unknown;
    }
};

test {
    _ = @import("peers_test.zig");
}
