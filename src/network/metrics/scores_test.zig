const Distribution = @import("scores.zig").Distribution;
const TopicKinds = @import("scores.zig").TopicKinds;
const policy = @import("../gossipsub/topic_policy.zig");
const prom = @import("registry.zig");
const score = @import("../gossipsub/score.zig");
const std = @import("std");

test "score gauges include inclusive thresholds, negative-only populations and empty peers" {
    var snapshot: Distribution = .{};
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

test "metrics score weights sum subnet contributions before averaging peers" {
    var values: Distribution = .{};
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
    var encoder: prom.Encoder = .{ .writer = &writer };
    try values.write(&encoder);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "gossipsub_score_weights_avg{topic=\"beacon_attestation\",p=\"p2\"} 3\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "gossipsub_score_weights_avg{topic=\"\",p=\"p7\"} -4\n") != null);
}
