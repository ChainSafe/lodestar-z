const std = @import("std");
const score = @import("gossipsub/score.zig");

pub const Snapshot = struct {
    count: u16 = 0,
    sum: f64 = 0,
    min: f64 = 0,
    max: f64 = 0,
    graylist: u16 = 0,
    publish: u16 = 0,
    gossip: u16 = 0,
    mesh: u16 = 0,

    pub fn observe(self: *Snapshot, value: f64, params: *const score.Params) void {
        std.debug.assert(std.math.isFinite(value) and self.count < score.peer_capacity);
        self.min = if (self.count == 0) value else @min(self.min, value);
        self.max = if (self.count == 0) value else @max(self.max, value);
        self.sum += value;
        self.count += 1;
        self.graylist += @intFromBool(value >= params.graylist_threshold);
        self.publish += @intFromBool(value >= params.publish_threshold);
        self.gossip += @intFromBool(value >= params.gossip_threshold);
        self.mesh += @intFromBool(value >= 0);
        std.debug.assert(std.math.isFinite(self.sum));
    }

    pub fn average(self: *const Snapshot) f64 {
        return if (self.count == 0) 0 else self.sum / @as(f64, @floatFromInt(self.count));
    }
};

test "score gauges include inclusive thresholds, negative-only populations and empty peers" {
    var snapshot: Snapshot = .{};
    const params: score.Params = .{};
    try std.testing.expectEqual(@as(f64, 0), snapshot.average());
    snapshot.observe(-16000, &params);
    snapshot.observe(-8000, &params);
    snapshot.observe(-4000, &params);
    try std.testing.expectEqual(@as(f64, -4000), snapshot.max);
    try std.testing.expectEqual(@as(u16, 0), snapshot.mesh);
    snapshot.observe(0, &params);
    try std.testing.expectEqual(@as(u16, 4), snapshot.graylist);
    try std.testing.expectEqual(@as(u16, 3), snapshot.publish);
    try std.testing.expectEqual(@as(u16, 2), snapshot.gossip);
    try std.testing.expectEqual(@as(u16, 1), snapshot.mesh);
    try std.testing.expectEqual(@as(f64, -7000), snapshot.average());
}
