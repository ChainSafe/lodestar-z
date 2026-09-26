const std = @import("std");
const catalog = @import("../peers/catalog.zig");
const client = @import("../peers/client.zig");
const prom = @import("registry.zig");
const Histogram = @import("histogram.zig").Distribution;
const client_count = @typeInfo(client.Client).@"enum".fields.len;

/// Connected peers by client and direction, and their connection ages, from the current population.
pub const Distribution = struct {
    directions: [client_count][2]u16 = @splat(@splat(0)),
    ages: Histogram(&.{ 5, 20, 60, 180, 600, 1200, 3600, 21600, 86400 }) = .{},

    pub fn observe(self: *Distribution, row: *const catalog.Row, kind: client.Client, now_ms: u64) void {
        std.debug.assert(row.connection != null);
        self.directions[@intFromEnum(kind)][@intFromEnum(row.direction)] += 1;
        self.ages.observe(@as(f64, @floatFromInt(now_ms -| row.connected_at_ms)) / 1000);
    }

    pub fn clientCount(self: *const Distribution, kind: client.Client) u16 {
        const counts = self.directions[@intFromEnum(kind)];
        return counts[0] + counts[1];
    }

    pub fn directionCounts(self: *const Distribution) [2]u16 {
        var counts: [2]u16 = @splat(0);
        for (self.directions) |row| for (&counts, row) |*total, count| {
            total.* += count;
        };
        return counts;
    }

    pub fn write(self: *const Distribution, w: *prom.Encoder) prom.Error!void {
        const ages = try w.histograms(.{
            .name = "lodestar_peer_connection_seconds",
            .kind = .histogram,
            .help = "Current connection ages in seconds; collected from the current population",
            .labels = &.{},
            .unit = .seconds,
        }, @TypeOf(self.ages));
        try ages.histogram(.{}, &self.ages);
    }
};

test {
    _ = @import("peers_test.zig");
}
