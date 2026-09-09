const std = @import("std");
const t = @import("types.zig");
pub const Input = struct {
    peer: t.PeerRef = .{ .index = 0, .generation = 0 },
    coverage: t.Coverage = .{},
    direct: bool = false,
    outbound: bool = false,
    relevant: bool = true,
    score: f64 = 0,
    reject: ?t.DisconnectReason = null,
};
pub const Deficits = struct {
    attestation: u16 = 0,
    sync: u16 = 0,
    groups: u16 = 0,
    outbound: u16 = 0,
    missing: t.Coverage = .{},
};
pub const Result = struct {
    retained: std.StaticBitSet(256) = .initEmpty(),
    retained_count: u16 = 0,
    reasons: [256]?t.DisconnectReason = @splat(null),
    deficits: Deficits = .{},
    dial_budget: u16 = 0,
    coverage: Counts = .{},
};
pub fn utility(coverage: *const t.Coverage, wanted: *const t.Coverage) u16 {
    return @as(u16, @popCount(coverage.attnets & wanted.attnets)) +
        @as(u16, @popCount(coverage.syncnets & wanted.syncnets)) +
        @as(u16, @intCast(coverage.groups.intersectWith(wanted.groups).count()));
}
pub const Counts = struct {
    attestation: [64]u16 = @splat(0),
    sync: [4]u16 = @splat(0),
    groups: [128]u16 = @splat(0),
    outbound: u16 = 0,

    fn change(self: *Counts, input: *const Input, add: bool) void {
        if (input.outbound and input.relevant) adjust(&self.outbound, add);
        for (0..64) |i| if (input.coverage.attnets & (@as(u64, 1) << @intCast(i)) != 0) {
            adjust(&self.attestation[i], add);
        };
        for (0..4) |i| if (input.coverage.syncnets & (@as(u4, 1) << @intCast(i)) != 0) {
            adjust(&self.sync[i], add);
        };
        for (0..128) |i| if (input.coverage.groups.isSet(i)) {
            adjust(&self.groups[i], add);
        };
    }
    fn protects(self: *const Counts, input: *const Input, demand: *const t.Demand, minimum: u16) bool {
        if (input.direct or !input.relevant or (input.outbound and self.outbound <= minimum)) return true;
        for (0..64) |i| {
            const bit = @as(u64, 1) << @intCast(i);
            if (input.coverage.attnets & demand.attnets & bit != 0 and self.attestation[i] <= demand.attestation_target) return true;
        }
        for (0..4) |i| {
            const bit = @as(u4, 1) << @intCast(i);
            if (input.coverage.syncnets & demand.syncnets & bit != 0 and self.sync[i] <= demand.sync_target) return true;
        }
        for (0..128) |i| if (input.coverage.groups.isSet(i) and demand.group_targets[i] > 0 and self.groups[i] <= demand.group_targets[i]) return true;
        return false;
    }
    fn deficits(self: *const Counts, demand: *const t.Demand, minimum: u16) Deficits {
        var result: Deficits = .{ .outbound = minimum -| self.outbound };
        for (0..64) |i| {
            const bit = @as(u64, 1) << @intCast(i);
            if (demand.attnets & bit == 0) continue;
            const missing = demand.attestation_target -| self.attestation[i];
            result.attestation += missing;
            if (missing > 0) result.missing.attnets |= bit;
        }
        for (0..4) |i| {
            const bit = @as(u4, 1) << @intCast(i);
            if (demand.syncnets & bit == 0) continue;
            const missing = demand.sync_target -| self.sync[i];
            result.sync += missing;
            if (missing > 0) result.missing.syncnets |= bit;
        }
        for (0..128) |i| {
            if (demand.group_targets[i] == 0) continue;
            const missing = demand.group_targets[i] -| self.groups[i];
            result.groups += missing;
            if (missing > 0) result.missing.groups.set(i);
        }
        return result;
    }
};
fn adjust(value: *u16, add: bool) void {
    if (add) value.* += 1 else {
        std.debug.assert(value.* > 0);
        value.* -= 1;
    }
}
const Rank = struct { index: u16, direct: bool, usefulness: u16, health: f64, outbound: bool, tie: u32 };
fn less(_: void, a: Rank, b: Rank) bool {
    if (a.direct != b.direct) return !a.direct;
    if (a.usefulness != b.usefulness) return a.usefulness < b.usefulness;
    if (a.health != b.health) return a.health < b.health;
    if (a.outbound != b.outbound) return !a.outbound;
    return a.tie < b.tie;
}
/// Inputs are stable copied values, bounded by the managed connection ceiling.
pub fn select(inputs: []const Input, demand: *const t.Demand, options: t.Options, seed: u64) Result {
    std.debug.assert(inputs.len <= 256);
    var result: Result = .{};
    var counts: Counts = .{};
    var order: [256]Rank = undefined;
    var random: std.Random.DefaultPrng = .init(seed);
    var len: usize = 0;
    const demanded = demand.wanted();
    for (inputs, 0..) |*input, i| {
        if (input.reject) |reason| {
            result.reasons[i] = reason;
            continue;
        }
        result.retained.set(i);
        result.retained_count += 1;
        counts.change(input, true);
        order[len] = .{ .index = @intCast(i), .direct = input.direct, .usefulness = utility(&input.coverage, &demanded), .health = if (std.math.isFinite(input.score)) std.math.clamp(input.score, -1e6, 1e6) else -1e6, .outbound = input.outbound, .tie = random.random().int(u32) };
        len += 1;
    }
    std.sort.insertion(Rank, order[0..len], {}, less);
    for (order[0..len]) |rank| {
        const input = &inputs[rank.index];
        const hard = result.retained_count > options.max_peers;
        const replacement = result.retained_count == options.max_peers and counts.outbound < options.min_outbound and !input.outbound;
        if (!hard and result.retained_count <= options.target_peers and !replacement) continue;
        if (!hard and counts.protects(input, demand, options.min_outbound)) continue;
        result.retained.unset(rank.index);
        result.reasons[rank.index] = if (hard) .capacity else .count_pruning;
        result.retained_count -= 1;
        counts.change(input, false);
    }
    result.coverage = counts;
    result.deficits = counts.deficits(demand, options.min_outbound);
    const coverage_missing = result.deficits.attestation > 0 or result.deficits.sync > 0 or result.deficits.groups > 0;
    const wanted = @max(options.target_peers -| result.retained_count, @max(result.deficits.outbound, @as(u16, if (coverage_missing) 1 else 0)));
    result.dial_budget = @min(wanted, options.max_peers -| result.retained_count);
    return result;
}
test {
    _ = @import("policy_test.zig");
}
