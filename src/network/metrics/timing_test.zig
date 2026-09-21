const std = @import("std");
const timing = @import("timing.zig");

test "maintenance retains unfinished work and measures submillisecond slices separately from cycle latency" {
    var metrics: timing.Gossip = .{ .started_ns = 100_000 };
    metrics.setup.observe(50_000);
    metrics.topics.observe(150_000);
    metrics.lateness.observe(2_000_000_000);
    try std.testing.expectEqual(@as(u64, 0), metrics.cycles.count);
    try std.testing.expectEqual(@as(i64, 0), metrics.completed_unix_s);
    metrics.topics.observe(100_000);
    metrics.completed(1_000_100_000, 1234);
    try std.testing.expectEqual(@as(u128, 1_000_000_000), metrics.cycles.sum);
    try std.testing.expectEqual(@as(u128, 250_000), metrics.topics.sum);
    try std.testing.expectApproxEqAbs(@as(f64, 0.00025), timing.Duration.output(metrics.topics.sum), 0.0000001);
    try std.testing.expect(metrics.started_ns == null);
    try std.testing.expectEqual(@as(i64, 1234), metrics.completed_unix_s);
}
