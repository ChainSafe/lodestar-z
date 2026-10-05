const std = @import("std");
const root = @import("root.zig");
const constants = @import("constants.zig");
const Reservations = @import("../reservations.zig").Reservations;
const sessions = @import("sessions.zig");

test "topic namespace implements immutable canonical lookup and subscriptions" {
    try canonical();
}

fn canonical() !void {
    const p = root.topic_policy;
    var boundaries = [_]p.Boundary{ full(.{ 1, 2, 3, 4 }), full(.{ 0xab, 0xcd, 0xef, 0x01 }) };
    var ns = try p.Namespace.init(std.testing.allocator, &boundaries, 2);
    defer ns.deinit(std.testing.allocator);
    boundaries[0].rules[0].ssz_max = 0;
    const cases = .{
        .{ "beacon_block", 0 },                  .{ "beacon_aggregate_and_proof", 1 },
        .{ "beacon_attestation_0", 2 },          .{ "beacon_attestation_63", 65 },
        .{ "proposer_slashing", 66 },            .{ "attester_slashing", 67 },
        .{ "voluntary_exit", 68 },               .{ "sync_committee_contribution_and_proof", 69 },
        .{ "sync_committee_0", 70 },             .{ "sync_committee_3", 73 },
        .{ "light_client_finality_update", 74 }, .{ "light_client_optimistic_update", 75 },
        .{ "bls_to_execution_change", 76 },      .{ "blob_sidecar_0", 77 },
        .{ "blob_sidecar_127", 204 },            .{ "data_column_sidecar_0", 205 },
        .{ "data_column_sidecar_127", 332 },
    };
    inline for (cases) |case| {
        const first = ns.lookup("/eth2/01020304/" ++ case[0] ++ "/ssz_snappy").?;
        try std.testing.expectEqual(case[1], first.ordinal);
        try std.testing.expectEqual(@as(u32, 100), first.rule.ssz_max);
        try std.testing.expectEqual(case[1] + 333, ns.lookup("/eth2/abcdef01/" ++ case[0] ++ "/ssz_snappy").?.ordinal);
    }
    const bad = [_][]const u8{
        "/eth2/ABCDEF01/beacon_block/ssz_snappy",            "/eth2/abcdef02/beacon_block/ssz_snappy",
        "/eth2/01020304/beacon_attestation_64/ssz_snappy",   "/eth2/01020304/beacon_attestation_00/ssz_snappy",
        "/eth2/01020304/beacon_attestation_+1/ssz_snappy",   "/eth2/01020304/beacon_attestation_-1/ssz_snappy",
        "/eth2/01020304/beacon_attestation/ssz_snappy",      "/eth2/01020304/beacon_block_0/ssz_snappy",
        "/eth2/01020304/sync_committee_4/ssz_snappy",        "/eth2/01020304/blob_sidecar_128/ssz_snappy",
        "/eth2/01020304/data_column_sidecar_128/ssz_snappy", "/eth2/01020304/Beacon_block/ssz_snappy",
        "/eth2/01020304/beacon_block/ssz",                   "/eth2/01020304/beacon_block/ssz_snappy/",
        "",
    };
    for (bad) |name| try std.testing.expect(ns.lookup(name) == null);
}

const full = @import("topic_fixture.zig").full;

test "topic namespace coverage is fork exact and duplicate announcements do not dirty policy" {
    var ns = try root.topic_policy.Namespace.init(std.testing.allocator, &.{ full(@splat(0)), full(@splat(1)) }, 2);
    defer ns.deinit(std.testing.allocator);
    const current = ns.lookup("/eth2/00000000/beacon_attestation_63/ssz_snappy").?.ordinal;
    const future = ns.lookup("/eth2/01010101/sync_committee_3/ssz_snappy").?.ordinal;
    ns.setSubscription(0, current, true);
    ns.setSubscription(0, future, true);
    try std.testing.expectEqual(@as(u64, 2), ns.revision);
    for (0..100) |_| ns.setSubscription(0, current, true);
    try std.testing.expectEqual(@as(u64, 2), ns.revision);
    try std.testing.expectEqual(@as(u64, 1) << 63, ns.subnets(0, @splat(0)).attnets);
    try std.testing.expectEqual(@as(u4, 0), ns.subnets(0, @splat(0)).syncnets);
    try std.testing.expectEqual(@as(u4, 8), ns.subnets(0, @splat(1)).syncnets);
    try std.testing.expectEqual(@as(u64, 0), ns.subnets(1, @splat(0)).attnets);
    ns.clearPeer(0);
    try std.testing.expectEqual(@as(u64, 3), ns.revision);
    try std.testing.expectEqual(@as(u64, 0), ns.subnets(0, @splat(0)).attnets);
    ns.clearPeer(0);
    try std.testing.expectEqual(@as(u64, 3), ns.revision);
}

test "topic namespace validates descriptors before allocation" {
    const p = root.topic_policy;
    const a = std.testing.allocator;
    var boundary = full(.{ 1, 2, 3, 4 });
    try std.testing.expectError(error.InvalidTopicPolicy, p.Namespace.init(a, &.{}, 1));
    try std.testing.expectError(error.InvalidTopicPolicy, p.Namespace.init(a, &.{ boundary, boundary }, 1));
    try std.testing.expectError(error.InvalidTopicPolicy, p.Namespace.init(a, &.{boundary}, 0));
    try std.testing.expectError(error.InvalidTopicPolicy, p.Namespace.init(a, &.{boundary}, 257));
    var excessive: [65]p.Boundary = undefined;
    for (&excessive, 0..) |*b, i| b.* = full(.{ @intCast(i), 0, 0, 0 });
    try std.testing.expectError(error.InvalidTopicPolicy, p.Namespace.init(a, &excessive, 1));
    var maximum = try p.Namespace.init(a, excessive[0..64], 256);
    defer maximum.deinit(a);
    try std.testing.expectEqual(@as(u16, 21312), maximum.topic_count);
    maximum.setSubscription(255, 21311, true);
    try std.testing.expect(maximum.subscribed(255, 21311));
    inline for (.{ 0, 2, 7, 11, 12 }) |kind| {
        boundary = full(.{ 1, 2, 3, 4 });
        boundary.rules[kind].count += 1;
        try std.testing.expectError(error.InvalidTopicPolicy, p.Namespace.init(a, &.{boundary}, 1));
    }
    for ([_]p.Rule{
        .{ .count = 0, .ssz_min = 0, .ssz_max = 1 },
        .{ .count = 1, .ssz_min = 11, .ssz_max = 10 },
        .{ .count = 1, .ssz_min = 0, .ssz_max = constants.MAX_PAYLOAD_SIZE + 1 },
    }) |rule| {
        boundary = full(.{ 1, 2, 3, 4 });
        boundary.rules[0] = rule;
        try std.testing.expectError(error.InvalidTopicPolicy, p.Namespace.init(a, &.{boundary}, 1));
    }
    boundary = .{ .digest = .{ 1, 2, 3, 4 } };
    try std.testing.expectError(error.InvalidTopicPolicy, p.Namespace.init(a, &.{boundary}, 1));
    boundary.rules[0] = .{ .count = 1, .ssz_min = 0, .ssz_max = 0 };
    var ns = try p.Namespace.init(a, &.{boundary}, 1);
    defer ns.deinit(a);
    try std.testing.expect(ns.lookup("/eth2/01020304/beacon_block/ssz_snappy") != null);
    try std.testing.expect(ns.lookup("/eth2/01020304/beacon_attestation_0/ssz_snappy") == null);
}

const hoodi = @import("topic_fixture.zig").hoodi;

test "topic namespace exact bitmap capacity clears and isolates physical rows" {
    const p = root.topic_policy;
    var one: p.Boundary = .{ .digest = .{ 1, 2, 3, 4 } };
    one.rules[0] = .{ .count = 1, .ssz_min = 0, .ssz_max = 100 };
    var sixty_four: p.Boundary = .{ .digest = .{ 1, 2, 3, 4 } };
    sixty_four.rules[2] = .{ .count = 64, .ssz_min = 0, .ssz_max = 100 };
    var sixty_five = sixty_four;
    sixty_five.rules[0] = one.rules[0];
    const hoodi_boundaries = hoodi();
    const cases = [_]struct { boundaries: []const p.Boundary, count: u16, words: usize }{
        .{ .boundaries = &.{one}, .count = 1, .words = 1 },
        .{ .boundaries = &.{sixty_four}, .count = 64, .words = 1 },
        .{ .boundaries = &.{sixty_five}, .count = 65, .words = 2 },
        .{ .boundaries = &hoodi_boundaries, .count = 784, .words = 13 },
    };
    for (cases) |case| {
        var ledger: Reservations = .{ .backing = std.testing.allocator };
        var ns = try p.Namespace.init(ledger.allocator(), case.boundaries, 256);
        try std.testing.expectEqual(case.count, ns.topic_count);
        try std.testing.expectEqual(case.words, ns.words_per_peer);
        try std.testing.expectEqual(256 * case.words * 8, ns.subscriptions.len * 8);
        try std.testing.expectEqual(ledger.bytes, ns.allocatedBytes());
        ns.setSubscription(0, case.count - 1, true);
        ns.setSubscription(255, case.count - 1, true);
        ns.setSubscription(255, case.count - 1, true);
        try std.testing.expectEqual(@as(u16, 2), ns.subscriber_counts[case.count - 1]);
        try std.testing.expectEqual(@as(usize, 2), ns.subscription_count);
        try std.testing.expect(ns.subscribed(0, case.count - 1));
        try std.testing.expect(!ns.subscribed(1, case.count - 1));
        var subscribers: sessions.PeerSet = .initEmpty();
        ns.initializeSubscribers(case.count - 1, &subscribers);
        try std.testing.expectEqual(@as(usize, 2), subscribers.count());
        ns.clearPeer(0);
        ns.clearPeer(0);
        try std.testing.expectEqual(@as(u16, 1), ns.subscriber_counts[case.count - 1]);
        try std.testing.expectEqual(@as(usize, 1), ns.subscription_count);
        try std.testing.expect(!ns.subscribed(0, case.count - 1));
        try std.testing.expect(ns.subscribed(255, case.count - 1));
        ns.setSubscription(255, case.count - 1, false);
        ns.setSubscription(255, case.count - 1, false);
        try std.testing.expectEqual(@as(u16, 0), ns.subscriber_counts[case.count - 1]);
        try std.testing.expectEqual(@as(usize, 0), ns.subscription_count);
        ns.setSubscription(0, case.count - 1, true);
        ns.clearPeer(0);
        try std.testing.expectEqual(@as(usize, 0), ns.subscription_count);
        ns.initializeSubscribers(case.count - 1, &subscribers);
        try std.testing.expectEqual(@as(usize, 0), subscribers.count());
        ns.deinit(ledger.allocator());
        try std.testing.expectEqual(@as(usize, 0), ledger.bytes);
    }
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFailure, .{});
}

fn allocationFailure(a: std.mem.Allocator) !void {
    const boundaries = hoodi();
    var ns = try root.topic_policy.Namespace.init(a, &boundaries, 3);
    defer ns.deinit(a);
}

test "topic namespace metrics agree with the subscription matrix after mixed updates and peer reuse" {
    var ns = try root.topic_policy.Namespace.init(std.testing.allocator, &.{ full(@splat(0)), full(@splat(1)) }, 4);
    defer ns.deinit(std.testing.allocator);
    for (0..ns.connected_capacity) |peer| {
        for (0..ns.topic_count) |ordinal| {
            ns.setSubscription(@intCast(peer), @intCast(ordinal), ordinal % 5 <= peer);
        }
    }
    try expectSubscriptionCounts(&ns);
    ns.clearPeer(1);
    ns.clearPeer(1);
    for (0..ns.topic_count) |ordinal| ns.setSubscription(0, @intCast(ordinal), false);
    try expectSubscriptionCounts(&ns);
    for (0..ns.topic_count) |ordinal| {
        ns.setSubscription(1, @intCast(ordinal), true);
        ns.setSubscription(1, @intCast(ordinal), true);
    }
    try expectSubscriptionCounts(&ns);
}

fn expectSubscriptionCounts(ns: *const root.topic_policy.Namespace) !void {
    var total: usize = 0;
    for (0..ns.topic_count) |ordinal| {
        var count: u16 = 0;
        for (0..ns.connected_capacity) |peer| count += @intFromBool(ns.subscribed(@intCast(peer), @intCast(ordinal)));
        try std.testing.expectEqual(count, ns.subscriber_counts[ordinal]);
        total += count;
    }
    try std.testing.expectEqual(total, ns.subscription_count);
}
