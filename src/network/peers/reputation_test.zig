const std = @import("std");
const r = @import("reputation.zig");
const t = @import("types.zig");
test "peer reputation exact thresholds cooldown expiry and long gap" {
    var state: r.State = .{};
    try std.testing.expectEqual(t.ReputationDecision.none, state.apply(.low_tolerance, 0));
    try std.testing.expectEqual(t.ReputationDecision.disconnect, state.apply(.low_tolerance, 0));
    _ = state.apply(.low_tolerance, 0);
    _ = state.apply(.low_tolerance, 0);
    try std.testing.expectEqual(t.ReputationDecision.ban, state.apply(.low_tolerance, 0));
    state.decay(1_799_999);
    try std.testing.expectEqual(@as(f64, -50), state.score);
    try std.testing.expect(state.banned(1_799_999));
    try std.testing.expect(state.banned(1_800_000));
    state.decay(1_800_000);
    try std.testing.expectEqual(@as(f64, -50), state.score);
    state.decay(2_400_000);
    try std.testing.expectApproxEqAbs(@as(f64, -25), state.score, 0.00001);
    state.decay(std.math.maxInt(u64));
    try std.testing.expectEqual(@as(f64, 0), state.score);
}
test "peer reputation fatal clamps and goodbye has separate deadline" {
    var state: r.State = .{};
    _ = state.apply(.fatal, 100);
    _ = state.apply(.fatal, 100);
    try std.testing.expectEqual(@as(f64, -100), state.score);
    state.remoteGoodbye(200, 500);
    try std.testing.expectEqual(@as(u64, 700), state.goodbye_until_ms);
    try std.testing.expectEqual(@as(u64, 1_800_100), state.ban_until_ms);
    try std.testing.expect(state.retained(700));
}

test "peer reputation ban survives cooldown and exact threshold until further decay" {
    var state: r.State = .{};
    _ = state.apply(.fatal, 0);
    state.decay(1_800_000);
    try std.testing.expect(state.banned(1_800_000));
    state.decay(2_400_000);
    try std.testing.expectEqual(@as(f64, -50), state.score);
    try std.testing.expect(state.banned(2_400_000));
    state.decay(2_400_001);
    try std.testing.expect(!state.banned(2_400_001));
    state.decay(3_000_000);
    try std.testing.expectApproxEqAbs(@as(f64, -25), state.score, 0.00001);
}
test "peer reputation deadlines advance from cooldown through threshold to retention expiry" {
    var state: r.State = .{};
    _ = state.apply(.fatal, 0);
    try std.testing.expectEqual(@as(u64, 1_800_000), state.nextDeadline(0).?);
    try std.testing.expectEqual(@as(u64, 2_400_001), state.nextDeadline(1_800_000).?);
    const expiry = state.nextDeadline(2_400_001).?;
    state.decay(expiry);
    try std.testing.expect(!state.retained(expiry));
    try std.testing.expect(state.nextDeadline(expiry) == null);
}
