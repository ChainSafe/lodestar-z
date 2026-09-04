const std = @import("std");
const limiter = @import("limiter.zig");
const protocol = @import("protocol.zig");

const Limiter = limiter.Limiter;
const Protocol = protocol.Protocol;

test "limiter grants the quota then refuses until the period refills it" {
    var buckets = try peerLimiter(4, null);
    defer buckets.deinit(std.testing.allocator);

    var granted: u32 = 0;
    while (granted < 16 and buckets.take(.{ .index = 2, .generation = 1 }, .ping_v1, 1, 0)) granted += 1;
    try std.testing.expectEqual(@as(u32, 2), granted);
    try std.testing.expect(!buckets.take(.{ .index = 2, .generation = 1 }, .ping_v1, 1, 0));
    try std.testing.expect(buckets.take(.{ .index = 3, .generation = 1 }, .ping_v1, 1, 0));
    try std.testing.expect(buckets.take(.{ .index = 2, .generation = 1 }, .status_v1, 1, 0));

    try std.testing.expectEqual(@as(u32, 1), buckets.peerAvailable(.{ .index = 2, .generation = 1 }, .ping_v1, 5_000));
    try std.testing.expect(buckets.take(.{ .index = 2, .generation = 1 }, .ping_v1, 1, 5_000));
    try std.testing.expect(!buckets.take(.{ .index = 2, .generation = 1 }, .ping_v1, 1, 5_000));
    try std.testing.expectEqual(@as(u32, 2), buckets.peerAvailable(.{ .index = 2, .generation = 1 }, .ping_v1, 1_000_000));
    try std.testing.expect(!buckets.take(.{ .index = 2, .generation = 1 }, .ping_v1, 3, 1_000_000));
}

test "limiter accumulates fractional refill instead of dropping it" {
    var buckets = try peerLimiter(1, null);
    defer buckets.deinit(std.testing.allocator);
    try std.testing.expect(buckets.take(.{ .index = 0, .generation = 1 }, .ping_v1, 2, 0));
    var now: u64 = 0;
    var refilled: u32 = 0;
    while (now < 6_000) : (now += 1_000) refilled = buckets.peerAvailable(.{ .index = 0, .generation = 1 }, .ping_v1, now);
    try std.testing.expectEqual(@as(u32, 1), refilled);
    try std.testing.expectEqual(@as(u32, 1), buckets.peerAvailable(.{ .index = 0, .generation = 1 }, .ping_v1, 9_999));
    try std.testing.expectEqual(@as(u32, 2), buckets.peerAvailable(.{ .index = 0, .generation = 1 }, .ping_v1, 10_000));
}

test "limiter overrides quotas, resets peers, and weighs requests" {
    var quotas = limiter.defaultQuotas();
    quotas[@intFromEnum(Protocol.blocks_by_range_v2)] = .{ .tokens = 3, .period_ms = 30_000 };
    var buckets = try peerLimiter(2, quotas);
    defer buckets.deinit(std.testing.allocator);

    try std.testing.expect(buckets.take(.{ .index = 1, .generation = 1 }, .blocks_by_range_v2, 2, 100));
    try std.testing.expect(!buckets.take(.{ .index = 1, .generation = 1 }, .blocks_by_range_v2, 2, 100));
    try std.testing.expect(buckets.take(.{ .index = 1, .generation = 1 }, .blocks_by_range_v2, 1, 100));
    buckets.bind(.{ .index = 1, .generation = 2 }, 100);
    try std.testing.expect(buckets.take(.{ .index = 1, .generation = 2 }, .blocks_by_range_v2, 3, 100));
    try std.testing.expectEqual(@as(u32, 0), buckets.peerAvailable(.{ .index = 1, .generation = 2 }, .blocks_by_range_v2, 100));
    try std.testing.expectEqual(@as(u32, 1), buckets.peerAvailable(.{ .index = 1, .generation = 2 }, .blocks_by_range_v2, 10_100));
    try std.testing.expectEqual(@as(u32, 3), buckets.peerAvailable(.{ .index = 0, .generation = 1 }, .blocks_by_range_v2, 0));
    try std.testing.expectEqual(@as(u32, 5), buckets.peerAvailable(.{ .index = 0, .generation = 1 }, .status_v1, 0));
    try std.testing.expectEqual(@as(u32, 128), limiter.defaultQuotas()[@intFromEnum(Protocol.blocks_by_range_v2)].tokens);
}

test "limiter does not mint repeated credit at the same timestamp" {
    var buckets = try peerLimiter(1, null);
    defer buckets.deinit(std.testing.allocator);
    try std.testing.expect(buckets.take(.{ .index = 0, .generation = 1 }, .data_column_sidecars_by_root_v1, 16384, 0));
    try std.testing.expect(buckets.take(.{ .index = 0, .generation = 1 }, .data_column_sidecars_by_root_v1, 1, 1));
    for (0..10) |_| try std.testing.expect(!buckets.take(.{ .index = 0, .generation = 1 }, .data_column_sidecars_by_root_v1, 1, 1));
}

test "limiter joint quotas reject atomically and generation reuse resets only peer credit" {
    var quotas = limiter.defaultQuotas();
    quotas[@intFromEnum(Protocol.ping_v1)] = .{ .tokens = 2, .period_ms = 10_000 };
    var global = quotas;
    global[@intFromEnum(Protocol.ping_v1)].tokens = 1;
    var buckets = try Limiter.initWithGlobal(std.testing.allocator, 2, quotas, global);
    defer buckets.deinit(std.testing.allocator);
    const a = @import("../quic/api.zig").Handle{ .index = 0, .generation = 1 };
    const b = @import("../quic/api.zig").Handle{ .index = 1, .generation = 1 };
    buckets.bind(a, 0);
    buckets.bind(b, 0);
    try std.testing.expect(buckets.take(a, .ping_v1, 1, 0));
    try std.testing.expect(!buckets.take(b, .ping_v1, 1, 0));
    try std.testing.expectEqual(@as(u32, 2), buckets.peerAvailable(b, .ping_v1, 0));
    const reused = @import("../quic/api.zig").Handle{ .index = 0, .generation = 2 };
    buckets.bind(reused, 0);
    try std.testing.expect(!buckets.take(a, .ping_v1, 1, 0));
    try std.testing.expectEqual(@as(u32, 2), buckets.peerAvailable(reused, .ping_v1, 0));
    try std.testing.expect(!buckets.take(reused, .ping_v1, 1, 0));
    try std.testing.expectEqual(@as(?u64, 10_000), buckets.nextToken(reused, .ping_v1, 0));
    try std.testing.expect(buckets.take(reused, .ping_v1, 1, 10_000));
}

test "limiter rejects invalid capacities and quota policy" {
    try std.testing.expectError(error.InvalidOptions, Limiter.init(std.testing.allocator, 1025, null));
    try std.testing.expectError(error.InvalidOptions, Limiter.init(std.testing.allocator, 0, null));
    var quotas = limiter.defaultQuotas();
    quotas[0].tokens = 0;
    try std.testing.expectError(error.InvalidQuota, Limiter.init(std.testing.allocator, 1, quotas));
    quotas[0] = .{ .tokens = 1, .period_ms = 0 };
    try std.testing.expectError(error.InvalidQuota, Limiter.init(std.testing.allocator, 1, quotas));
}

fn peerLimiter(peers: u16, quotas: ?limiter.Quotas) !Limiter {
    var global = limiter.defaultQuotas();
    for (&global) |*quota| quota.tokens = 1_000_000;
    var buckets = try Limiter.initWithGlobal(std.testing.allocator, peers, quotas, global);
    for (0..peers) |index| buckets.bind(.{ .index = @intCast(index), .generation = 1 }, 0);
    return buckets;
}

test "limiter peer rejection preserves aggregate credit and wide refill saturates safely" {
    var quotas = limiter.defaultQuotas();
    quotas[0] = .{ .tokens = 1, .period_ms = 1000 };
    var aggregate = quotas;
    aggregate[0].tokens = 2;
    var buckets = try Limiter.initWithGlobal(std.testing.allocator, 2, quotas, aggregate);
    defer buckets.deinit(std.testing.allocator);
    const a = @import("../quic/api.zig").Handle{ .index = 0, .generation = 1 };
    const b = @import("../quic/api.zig").Handle{ .index = 1, .generation = 1 };
    buckets.bind(a, 0);
    buckets.bind(b, 0);
    try std.testing.expect(buckets.take(a, .status_v1, 1, 0));
    try std.testing.expect(!buckets.take(a, .status_v1, 1, 0));
    try std.testing.expect(buckets.take(b, .status_v1, 1, 0));
    quotas[0] = .{ .tokens = std.math.maxInt(u32), .period_ms = std.math.maxInt(u64) };
    var wide = try Limiter.init(std.testing.allocator, 1, quotas);
    defer wide.deinit(std.testing.allocator);
    wide.bind(a, 0);
    try std.testing.expect(wide.take(a, .status_v1, std.math.maxInt(u32), 0));
    try std.testing.expectEqual(@as(?u64, 4_294_967_297), wide.nextToken(a, .status_v1, 0));
    try std.testing.expect(wide.take(a, .status_v1, std.math.maxInt(u32), std.math.maxInt(u64)));
    try std.testing.expect(!wide.take(a, .status_v1, 1, std.math.maxInt(u64)));
}
