const std = @import("std");
const root = @import("root.zig");

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

pub fn full(digest: [4]u8) root.topic_policy.Boundary {
    var boundary: root.topic_policy.Boundary = .{ .digest = digest };
    for (&boundary.rules) |*rule| rule.* = .{ .count = 1, .ssz_min = 10, .ssz_max = 100 };
    boundary.rules[2].count = 64;
    boundary.rules[7].count = 4;
    boundary.rules[11].count = 128;
    boundary.rules[12].count = 128;
    return boundary;
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
        .{ .count = 1, .ssz_min = 0, .ssz_max = @import("constants.zig").MAX_PAYLOAD_SIZE + 1 },
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

pub fn hoodi() [5]root.topic_policy.Boundary {
    var out: [5]root.topic_policy.Boundary = undefined;
    const digests = [_][4]u8{ .{ 0xd2, 0xf1, 0x99, 0x7f }, .{ 0x82, 0x55, 0x6a, 0x32 }, .{ 0xe2, 0xab, 0xcc, 0xa4 }, .{ 0xae, 0x9f, 0x70, 0xa0 }, .{ 0xc6, 0xec, 0xb7, 0x6c } };
    for (&out, digests, 0..) |*b, digest, i| {
        b.* = full(digest);
        b.rules[11] = if (i < 2) .{ .count = if (i == 0) 6 else 9, .ssz_min = 10, .ssz_max = 100 } else .{};
        if (i < 2) b.rules[12] = .{};
    }
    return out;
}

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
        var ledger: @import("../reservations.zig").Reservations = .{ .backing = std.testing.allocator };
        var ns = try p.Namespace.init(ledger.allocator(), case.boundaries, 256);
        try std.testing.expectEqual(case.count, ns.topic_count);
        try std.testing.expectEqual(case.words, ns.words_per_peer);
        try std.testing.expectEqual(256 * case.words * 8, ns.subscriptions.len * 8);
        try std.testing.expectEqual(ledger.bytes, ns.allocatedBytes());
        ns.setSubscription(0, case.count - 1, true);
        ns.setSubscription(255, case.count - 1, true);
        try std.testing.expect(ns.subscribed(0, case.count - 1));
        try std.testing.expect(!ns.subscribed(1, case.count - 1));
        var subscribers: @import("sessions.zig").PeerSet = .initEmpty();
        ns.initializeSubscribers(case.count - 1, &subscribers);
        try std.testing.expectEqual(@as(usize, 2), subscribers.count());
        ns.clearPeer(0);
        try std.testing.expect(!ns.subscribed(0, case.count - 1));
        try std.testing.expect(ns.subscribed(255, case.count - 1));
        ns.setSubscription(255, case.count - 1, false);
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
