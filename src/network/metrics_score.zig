const std = @import("std");
const score = @import("gossipsub/score.zig");
const policy = @import("gossipsub/topic_policy.zig");
const constants = @import("gossipsub/constants.zig");
const prom = @import("metrics_prometheus.zig");

pub const kind_count = policy.kind_count + 1;
pub const TopicKinds = [constants.topics_cap]?u8;
const topic_fields = std.meta.fields(score.TopicWeights);
const global_fields = std.meta.fields(score.GlobalWeights);

pub const Range = struct {
    count: u16 = 0,
    sum: f64 = 0,
    min: f64 = 0,
    max: f64 = 0,

    pub fn observe(self: *Range, value: f64) void {
        std.debug.assert(std.math.isFinite(value) and self.count < score.peer_capacity);
        self.min = if (self.count == 0) value else @min(self.min, value);
        self.max = if (self.count == 0) value else @max(self.max, value);
        self.sum += value;
        self.count += 1;
        std.debug.assert(std.math.isFinite(self.sum));
    }

    pub fn average(self: *const Range) f64 {
        return if (self.count == 0) 0 else self.sum / @as(f64, @floatFromInt(self.count));
    }
};

pub const Snapshot = struct {
    values: Range = .{},
    weights: [kind_count][topic_fields.len]Range = @splat(@splat(.{})),
    global: [global_fields.len]Range = @splat(.{}),
    mesh_scores: [kind_count]Range = @splat(.{}),
    calls: u64 = 0,
    runs: u64 = 0,
    cache_delta: score.CacheDelta = .{},
    penalties: score.Penalties = .{},
    graylist: u16 = 0,
    publish: u16 = 0,
    gossip: u16 = 0,
    mesh: u16 = 0,

    pub fn observe(self: *Snapshot, value: f64, params: *const score.Params) void {
        self.values.observe(value);
        self.graylist += @intFromBool(value >= params.graylist_threshold);
        self.publish += @intFromBool(value >= params.publish_threshold);
        self.gossip += @intFromBool(value >= params.gossip_threshold);
        self.mesh += @intFromBool(value >= 0);
    }

    pub fn average(self: *const Snapshot) f64 {
        return self.values.average();
    }

    pub fn observeWeights(self: *Snapshot, details: *const score.Breakdown, kinds: *const TopicKinds) void {
        var totals: [kind_count][topic_fields.len]f64 = @splat(@splat(0));
        for (&details.topics, kinds) |*weights, kind| {
            const index = kind orelse continue;
            inline for (topic_fields, 0..) |field, p| totals[index][p] += @field(weights, field.name);
        }
        for (&self.weights, totals) |*ranges, values| {
            for (ranges, values) |*range, value| range.observe(value);
        }
        inline for (global_fields, 0..) |field, p| self.global[p].observe(@field(details.global, field.name));
    }

    pub fn write(self: *const Snapshot, w: *std.Io.Writer) std.Io.Writer.Error!void {
        inline for (.{ "min", "max", "avg" }) |stat| {
            const value = if (comptime std.mem.eql(u8, stat, "avg")) self.average() else @field(self.values, stat);
            try prom.scalar(w, "gossipsub_score_" ++ stat, .gauge, "Connected gossip peer scores", value);
            try prom.family(w, "gossipsub_score_weights_" ++ stat, .gauge, "Per-peer score components after component weights, before topic weight and topic cap; topics of the same kind are summed per peer");
            for (&self.weights, 0..) |*ranges, kind| {
                inline for (topic_fields, 0..) |field, p| {
                    const component = if (comptime std.mem.eql(u8, stat, "avg")) ranges[p].average() else @field(ranges[p], stat);
                    try w.print("gossipsub_score_weights_" ++ stat ++ "{{topic=\"{s}\",p=\"{s}\"}} {d}\n", .{ kindName(kind), field.name, component });
                }
            }
            inline for (global_fields, 0..) |field, p| {
                const component = if (comptime std.mem.eql(u8, stat, "avg")) self.global[p].average() else @field(self.global[p], stat);
                try w.print("gossipsub_score_weights_" ++ stat ++ "{{topic=\"\",p=\"{s}\"}} {d}\n", .{ field.name, component });
            }
            try prom.family(w, "gossipsub_score_per_mesh_" ++ stat, .gauge, "Scores of distinct connected peers in meshes of each topic kind");
            for (&self.mesh_scores, 0..) |*range, kind| {
                const value_mesh = if (comptime std.mem.eql(u8, stat, "avg")) range.average() else @field(range, stat);
                try prom.sample(w, "gossipsub_score_per_mesh_" ++ stat, "topic", kindName(kind), value_mesh);
            }
        }
        try prom.family(w, "gossipsub_peers_by_score_threshold_count", .gauge, "Connected gossip peers at or above configured thresholds");
        inline for (.{ "graylist", "publish", "gossip", "mesh" }) |threshold|
            try prom.sample(w, "gossipsub_peers_by_score_threshold_count", "threshold", threshold, @field(self, threshold));
        try prom.scalar(w, "gossipsub_score_fn_calls_total", .counter, "Policy score calls, excluding telemetry snapshots", self.calls);
        try prom.scalar(w, "gossipsub_score_fn_runs_total", .counter, "Policy score calculations that did not use the cache", self.runs);
        try prom.family(w, "gossipsub_score_cache_delta", .histogram, "Absolute change from the previous cached score for the same peer identity");
        try prom.histogram(w, "gossipsub_score_cache_delta", null, "", &self.cache_delta);
        try prom.family(w, "gossipsub_scoring_penalties_total", .counter, "Score penalty events; message deficits count retained mesh-failure penalties on prune");
        inline for (std.meta.fields(score.Penalties)) |field|
            try prom.sample(w, "gossipsub_scoring_penalties_total", "penalty", field.name, @field(self.penalties, field.name));
    }
};

test "score gauges include inclusive thresholds, negative-only populations and empty peers" {
    var snapshot: Snapshot = .{};
    const params: score.Params = .{};
    try std.testing.expectEqual(@as(f64, 0), snapshot.average());
    snapshot.observe(-16000, &params);
    snapshot.observe(-8000, &params);
    snapshot.observe(-4000, &params);
    try std.testing.expectEqual(@as(f64, -4000), snapshot.values.max);
    try std.testing.expectEqual(@as(u16, 0), snapshot.mesh);
    snapshot.observe(0, &params);
    try std.testing.expectEqual(@as(u16, 4), snapshot.graylist);
    try std.testing.expectEqual(@as(u16, 3), snapshot.publish);
    try std.testing.expectEqual(@as(u16, 2), snapshot.gossip);
    try std.testing.expectEqual(@as(u16, 1), snapshot.mesh);
    try std.testing.expectEqual(@as(f64, -7000), snapshot.average());
}

fn kindName(index: usize) []const u8 {
    return if (index == policy.kind_count) "unknown" else @tagName(@as(policy.Kind, @enumFromInt(index)));
}

test "metrics score weights sum subnet contributions before averaging peers" {
    var values: Snapshot = .{};
    var details: score.Breakdown = .{};
    var kinds: TopicKinds = @splat(null);
    kinds[0] = @intFromEnum(policy.Kind.beacon_attestation);
    kinds[1] = kinds[0];
    details.topics[0].p2 = 2;
    details.topics[1].p2 = 4;
    details.global.p7 = -8;
    values.observeWeights(&details, &kinds);
    details = .{};
    values.observeWeights(&details, &kinds);
    const index = @intFromEnum(policy.Kind.beacon_attestation);
    try std.testing.expectEqual(@as(f64, 3), values.weights[index][1].average());
    try std.testing.expectEqual(@as(f64, 6), values.weights[index][1].max);
    try std.testing.expectEqual(@as(f64, -4), values.global[2].average());
    var bytes: [32768]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    try values.write(&writer);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "gossipsub_score_weights_avg{topic=\"beacon_attestation\",p=\"p2\"} 3\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "gossipsub_score_weights_avg{topic=\"\",p=\"p7\"} -4\n") != null);
}
