const std = @import("std");
const p = @import("policy.zig");
const t = @import("types.zig");
const expect = std.testing.expect;
const equal = std.testing.expectEqual;
const options: t.Options = .{ .capacity = 8, .outbound_reserve = 1, .target_peers = 2, .max_peers = 4, .min_outbound = 1, .engine_capacity = 4 };
test "peer policy overlapping coverage updates after each removal" {
    var demand: t.Demand = .{ .coverage = .{ .attnets = 1, .syncnets = 1 }, .expires_at_slot = 10 };
    demand.coverage.custody.set(5);
    var inputs = [_]p.Input{
        .{ .coverage = .{ .attnets = 1, .syncnets = 1 }, .outbound = true },
        .{ .coverage = .{ .attnets = 1, .syncnets = 1 }, .outbound = true },
        .{},
        .{},
        .{},
    };
    const only_custody_peer = 2;
    inputs[only_custody_peer].coverage.custody.set(5);
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
    var demand: t.Demand = .{ .coverage = .{ .attnets = 1, .syncnets = 1 }, .attestation_target = 2 };
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
    demand.coverage.custody.set(64);
    try std.testing.expectError(error.InvalidDemand, demand.validate(&.{ .custody_groups = 64 }, 4));
}
