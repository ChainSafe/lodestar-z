const std = @import("std");
const limiter = @import("limiter.zig");
const protocol = @import("protocol.zig");

const Limiter = limiter.Limiter;
const Protocol = protocol.Protocol;

test "limiter grants the quota then refuses until the period refills it" {
    var buckets = try Limiter.init(std.testing.allocator, 4, null);
    defer buckets.deinit(std.testing.allocator);

    var granted: u32 = 0;
    while (buckets.take(2, .ping_v1, 1, 0)) granted += 1;
    try std.testing.expectEqual(@as(u32, 2), granted);
    try std.testing.expect(!buckets.take(2, .ping_v1, 1, 0));
    try std.testing.expect(buckets.take(3, .ping_v1, 1, 0));
    try std.testing.expect(buckets.take(2, .status_v1, 1, 0));

    try std.testing.expectEqual(@as(u32, 1), buckets.available(2, .ping_v1, 5_000));
    try std.testing.expect(buckets.take(2, .ping_v1, 1, 5_000));
    try std.testing.expect(!buckets.take(2, .ping_v1, 1, 5_000));
    try std.testing.expectEqual(@as(u32, 2), buckets.available(2, .ping_v1, 1_000_000));
    try std.testing.expect(!buckets.take(2, .ping_v1, 3, 1_000_000));
}

test "limiter accumulates fractional refill instead of dropping it" {
    var buckets = try Limiter.init(std.testing.allocator, 1, null);
    defer buckets.deinit(std.testing.allocator);
    try std.testing.expect(buckets.take(0, .ping_v1, 2, 0));
    var now: u64 = 0;
    var refilled: u32 = 0;
    while (now < 6_000) : (now += 1_000) refilled = buckets.available(0, .ping_v1, now);
    try std.testing.expectEqual(@as(u32, 1), refilled);
    try std.testing.expectEqual(@as(u32, 1), buckets.available(0, .ping_v1, 9_999));
    try std.testing.expectEqual(@as(u32, 2), buckets.available(0, .ping_v1, 10_000));
}

test "limiter overrides quotas, resets peers, and weighs requests" {
    var quotas = limiter.defaultQuotas();
    quotas[@intFromEnum(Protocol.blocks_by_range_v2)] = .{ .tokens = 3, .period_ms = 30_000 };
    var buckets = try Limiter.init(std.testing.allocator, 2, quotas);
    defer buckets.deinit(std.testing.allocator);

    try std.testing.expect(buckets.take(1, .blocks_by_range_v2, 2, 100));
    try std.testing.expect(!buckets.take(1, .blocks_by_range_v2, 2, 100));
    try std.testing.expect(buckets.take(1, .blocks_by_range_v2, 1, 100));
    buckets.reset(1, 100);
    try std.testing.expect(buckets.take(1, .blocks_by_range_v2, 3, 100));
    try std.testing.expectEqual(@as(u32, 0), buckets.available(1, .blocks_by_range_v2, 100));
    try std.testing.expectEqual(@as(u32, 1), buckets.available(1, .blocks_by_range_v2, 10_100));
    try std.testing.expectEqual(@as(u32, 3), buckets.available(0, .blocks_by_range_v2, 0));
    try std.testing.expectEqual(@as(u32, 5), buckets.available(0, .status_v1, 0));
    try std.testing.expectEqual(@as(u32, 128), limiter.defaultQuotas()[@intFromEnum(Protocol.blocks_by_range_v2)].tokens);
}
