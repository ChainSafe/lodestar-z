const std = @import("std");
const p = @import("policy.zig");
const t = @import("types.zig");
const expect = std.testing.expect;
const equal = std.testing.expectEqual;
const options: t.Options = .{ .capacity = 8, .outbound_reserve = 1, .target_peers = 2, .max_peers = 4, .min_outbound = 1, .engine_capacity = 4 };
test "peer policy overlapping coverage updates after each removal" {
    var demand: t.Demand = .{ .attnets = 1, .syncnets = 1, .expires_at_slot = 10 };
    demand.group_targets[5] = 1;
    var inputs = [_]p.Input{
        .{ .coverage = .{ .attnets = 1, .syncnets = 1 }, .outbound = true },
        .{ .coverage = .{ .attnets = 1, .syncnets = 1 }, .outbound = true },
        .{},
        .{},
        .{},
    };
    const only_custody_peer = 2;
    inputs[only_custody_peer].coverage.groups.set(5);
    const result = p.select(&inputs, &demand, options, 7);
    try equal(@as(u16, 0), result.deficits.sync);
    try expect(result.retained.isSet(only_custody_peer));
    try expect(result.retained_count <= options.max_peers);
    try equal(@as(u16, 2), result.retained_count);
    try expect(result.retained.isSet(0) != result.retained.isSet(1));
}

test "peer policy direct bans hard capacity deficits and outbound replacement" {
    var configured = options;
    configured.max_peers = 2;
    const demand: t.Demand = .{};
    const inputs = [_]p.Input{ .{ .direct = true, .reject = .banned }, .{ .direct = true, .reject = .incompatible_fork }, .{ .direct = true }, .{ .direct = true }, .{ .direct = true } };
    var result = p.select(&inputs, &demand, configured, 3);
    try equal(t.DisconnectReason.banned, result.reasons[0].?);
    try equal(t.DisconnectReason.incompatible_fork, result.reasons[1].?);
    try equal(@as(u16, 2), result.retained_count);
    try equal(@as(u16, 1), result.deficits.outbound);
    try equal(@as(u16, 0), result.dial_budget);
    const inbound = [_]p.Input{ .{}, .{} };
    result = p.select(&inbound, &demand, options, 3);
    try equal(@as(u16, 1), result.dial_budget);
    result = p.select(&inbound, &demand, configured, 3);
    try equal(@as(u16, 1), result.retained_count);
    try equal(@as(u16, 1), result.dial_budget);
}

test "peer policy finite ranking expiry and infeasible demanded coverage" {
    var demand: t.Demand = .{ .attnets = 1, .syncnets = 1, .attestation_target = 2 };
    const inputs = [_]p.Input{ .{ .score = std.math.nan(f64) }, .{ .coverage = .{ .attnets = 1 }, .outbound = true }, .{ .direct = true } };
    var result = p.select(&inputs, &demand, options, 7);
    try equal(@as(u16, 1), result.deficits.attestation);
    try equal(@as(u16, 1), result.deficits.sync);
    try expect(result.retained.isSet(1));
    try equal(@as(u16, 1), result.dial_budget);
    demand = .{};
    result = p.select(&inputs, &demand, options, 7);
    try equal(@as(u16, 0), result.deficits.attestation);
    try equal(@as(u16, 0), result.deficits.sync);
    try equal(@as(u16, 0), result.dial_budget);
    try std.testing.expectError(error.InvalidDemand, (t.Demand{ .sync_target = 0 }).validate(&.{}, 4));
    demand.group_targets[64] = 1;
    try std.testing.expectError(error.InvalidDemand, demand.validate(&.{ .custody_groups = 64 }, 4));
}

test "peer policy retained set stays stable across health changes after actual pruning" {
    const demand: t.Demand = .{ .attnets = 1, .syncnets = 1 };
    const original = [_]p.Input{
        .{ .coverage = .{ .attnets = 1 }, .score = -10 },
        .{ .coverage = .{ .syncnets = 1 }, .score = -9 },
        .{ .outbound = true, .score = -8 },
        .{ .score = -7 },
    };
    var configured = options;
    configured.target_peers = 1;
    const first = p.select(&original, &demand, configured, 7);
    try equal(@as(u16, 3), first.retained_count);
    try expect(first.retained_count > configured.target_peers);
    try equal(@as(u16, 0), first.deficits.outbound);
    try expect(first.reasons[3] != null);
    var retained: [4]p.Input = undefined;
    var count: usize = 0;
    for (original, 0..) |input, index| if (first.retained.isSet(index)) {
        retained[count] = input;
        count += 1;
    };
    for (0..8) |permutation| {
        for (retained[0..count], 0..) |*input, index| input.score = if (permutation & (@as(usize, 1) << @intCast(index)) != 0) -1e6 else 1e6;
        const next = p.select(retained[0..count], &demand, configured, 7);
        try equal(first.retained_count, next.retained_count);
        try equal(first.deficits, next.deficits);
        for (next.reasons[0..count]) |reason| try expect(reason == null);
    }

    configured.target_peers = configured.max_peers;
    const inbound = [_]p.Input{ .{ .score = -10 }, .{ .score = -9 }, .{ .score = -8 }, .{ .score = -7 } };
    const replacement = p.select(&inbound, &.{}, configured, 7);
    try equal(@as(u16, 3), replacement.retained_count);
    count = 0;
    for (inbound, 0..) |input, index| if (replacement.retained.isSet(index)) {
        retained[count] = input;
        retained[count].score = -input.score;
        count += 1;
    };
    const stable = p.select(retained[0..count], &.{}, configured, 7);
    try equal(replacement.retained_count, stable.retained_count);
    try equal(replacement.deficits, stable.deficits);
    try equal(@as(u16, 1), stable.dial_budget);
}

test "peer policy explicit group targets match Hoodi sampling deficits" {
    var demand: t.Demand = .{ .group_targets = @splat(4) };
    var inputs = [_]p.Input{.{}};
    for ([_]u8{ 1, 17, 19, 42, 75, 87, 102, 117 }) |group| {
        demand.group_targets[group] = 6;
        inputs[0].coverage.groups.set(group);
    }
    const configured: t.Options = .{ .capacity = 256, .max_peers = 256, .engine_capacity = 256, .target_peers = 1, .min_outbound = 0 };
    const result = p.select(&inputs, &demand, configured, 1);
    try equal(@as(u16, 520), result.deficits.groups);
    try equal(@as(usize, 128), result.deficits.missing.groups.count());
    for (0..128) |group| {
        var one: t.Demand = .{};
        one.group_targets[group] = demand.group_targets[group];
        try equal(@as(u16, if (inputs[0].coverage.groups.isSet(group)) 5 else 4), p.select(&inputs, &one, configured, 1).deficits.groups);
    }
    try equal(@as(u16, 0), p.select(&inputs, &.{}, configured, 1).deficits.groups);
}

test "peer policy group targets validate boundaries and saturate exactly" {
    var demand: t.Demand = .{ .attnets = 3, .syncnets = 2 };
    demand.group_targets[0] = 1;
    demand.group_targets[127] = 256;
    try demand.validate(&.{ .custody_groups = 128 }, 256);
    try equal(@as(usize, 2), demand.wanted().groups.count());
    try equal(@as(u64, 3), demand.wanted().attnets);
    try equal(@as(u4, 2), demand.wanted().syncnets);
    demand.group_targets[127] = 257;
    try std.testing.expectError(error.InvalidDemand, demand.validate(&.{}, 256));
    demand.group_targets[127] = 1;
    try std.testing.expectError(error.InvalidDemand, demand.validate(&.{ .custody_groups = 64 }, 256));
    demand = .{ .group_targets = @splat(256) };
    const configured: t.Options = .{ .capacity = 256, .max_peers = 256, .engine_capacity = 256, .target_peers = 256, .min_outbound = 0 };
    try equal(@as(u16, 32768), p.select(&.{}, &demand, configured, 1).deficits.groups);
    var inputs: [256]p.Input = @splat(.{});
    for (&inputs) |*input| input.coverage.groups.setRangeValue(.{ .start = 0, .end = 128 }, true);
    try equal(@as(u16, 0), p.select(&inputs, &demand, configured, 1).deficits.groups);
    try equal(@as(u16, 128), p.select(inputs[0..255], &demand, configured, 1).deficits.groups);
    demand = .{};
    try equal(@as(u16, 0), p.select(&inputs, &demand, configured, 1).deficits.groups);
}

test "peer policy per group protection yields to hard capacity and bans" {
    var demand: t.Demand = .{};
    demand.group_targets[5] = 2;
    demand.group_targets[9] = 1;
    var inputs: [4]p.Input = @splat(.{});
    inputs[0].coverage.groups.set(5);
    inputs[1].coverage.groups.set(5);
    inputs[2].coverage.groups.set(5);
    inputs[3].coverage.groups.set(9);
    var configured = options;
    configured.target_peers = 1;
    configured.min_outbound = 0;
    var result = p.select(&inputs, &demand, configured, 1);
    try equal(@as(u16, 3), result.retained_count);
    try equal(@as(u16, 0), result.deficits.groups);
    try expect(result.retained.isSet(3));
    configured.max_peers = 2;
    result = p.select(&inputs, &demand, configured, 1);
    try equal(@as(u16, 2), result.retained_count);
    try equal(@as(u16, 1), result.deficits.groups);
    inputs[3].reject = .banned;
    result = p.select(&inputs, &demand, configured, 1);
    try equal(t.DisconnectReason.banned, result.reasons[3].?);
    try expect(result.deficits.missing.groups.isSet(9));
}
