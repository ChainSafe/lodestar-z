const std = @import("std");
const t = @import("types.zig");
const reputation = @import("reputation.zig");
pub const Input = struct {
    peer: t.PeerRef = .{ .index = 0, .generation = 0 },
    coverage: t.Coverage = .{},
    direct: bool = false,
    outbound: bool = false,
    relevant: bool = true,
    ready: bool = true,
    evaluating: bool = false,
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
    fn scarce(self: *const Counts, demand: *const t.Demand) t.Coverage {
        var result: t.Coverage = .{};
        for (0..64) |i| {
            const bit = @as(u64, 1) << @intCast(i);
            if (demand.attnets & bit != 0 and self.attestation[i] <= demand.attestation_target)
                result.attnets |= bit;
        }
        for (0..4) |i| {
            const bit = @as(u4, 1) << @intCast(i);
            if (demand.syncnets & bit != 0 and self.sync[i] <= demand.sync_target)
                result.syncnets |= bit;
        }
        for (0..128) |i| {
            if (demand.group_targets[i] > 0 and self.groups[i] <= demand.group_targets[i])
                result.groups.set(i);
        }
        return result;
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
const Rank = struct {
    index: u16,
    direct: bool,
    outbound_floor: bool,
    evaluating: bool,
    ready: bool,
    health: f64,
    coverage_loss: u16,
    outbound: bool,
    tie: u32,
};
fn less(a: *const Rank, b: *const Rank) bool {
    if (a.direct != b.direct) return !a.direct;
    if (a.outbound_floor != b.outbound_floor) return !a.outbound_floor;
    if (a.evaluating != b.evaluating) return !a.evaluating;
    if (a.ready != b.ready) return !a.ready;
    const a_poor = a.health < reputation.prune_score;
    const b_poor = b.health < reputation.prune_score;
    if (a_poor != b_poor) return a_poor;
    if (a_poor and a.health != b.health) return a.health < b.health;
    if (a.coverage_loss != b.coverage_loss) return a.coverage_loss < b.coverage_loss;
    if (a.health != b.health) return a.health < b.health;
    if (a.outbound != b.outbound) return !a.outbound;
    return a.tie < b.tie;
}

fn removal(
    inputs: []const Input,
    result: *const Result,
    demand: *const t.Demand,
    options: t.Options,
    ties: []const u32,
) ?u16 {
    const scarce = result.coverage.scarce(demand);
    const hard = result.retained_count > options.max_peers;
    var best: ?Rank = null;
    for (inputs, 0..) |*input, i| {
        if (!result.retained.isSet(i)) continue;
        const outbound_floor = input.outbound and input.relevant and
            result.coverage.outbound <= options.min_outbound;
        if (!hard and (input.direct or input.evaluating or outbound_floor)) continue;
        const rank: Rank = .{
            .index = @intCast(i),
            .direct = input.direct,
            .outbound_floor = outbound_floor,
            .evaluating = input.evaluating,
            .ready = input.ready,
            .health = if (std.math.isFinite(input.score))
                std.math.clamp(input.score, -1e6, 1e6)
            else
                -1e6,
            .coverage_loss = utility(&input.coverage, &scarce),
            .outbound = input.outbound,
            .tie = ties[i],
        };
        if (best == null or less(&rank, &best.?)) best = rank;
    }
    return if (best) |rank| rank.index else null;
}

fn needsReplacement(result: *const Result, demand: *const t.Demand, minimum: u16) bool {
    const missing = result.coverage.deficits(demand, minimum);
    return missing.outbound > 0 or missing.attestation > 0 or
        missing.sync > 0 or missing.groups > 0;
}

/// Inputs are stable copied values, bounded by the managed connection ceiling.
pub fn select(inputs: []const Input, demand: *const t.Demand, options: t.Options, seed: u64) Result {
    std.debug.assert(inputs.len <= 256);
    std.debug.assert(options.target_peers <= options.max_peers);
    var result: Result = .{};
    var evaluating: u16 = 0;
    var ties: [256]u32 = undefined;
    var random: std.Random.DefaultPrng = .init(seed);
    for (inputs, 0..) |*input, i| {
        ties[i] = random.random().int(u32);
        if (input.reject) |reason| {
            result.reasons[i] = reason;
            continue;
        }
        result.retained.set(i);
        result.retained_count += 1;
        result.coverage.change(input, true);
        if (input.evaluating) evaluating += 1;
    }
    for (0..inputs.len) |_| {
        const hard = result.retained_count > options.max_peers;
        const replacement = result.retained_count == options.max_peers and evaluating == 0 and
            needsReplacement(&result, demand, options.min_outbound);
        if (!hard and result.retained_count - evaluating <= options.target_peers and !replacement)
            break;
        const index = removal(inputs, &result, demand, options, ties[0..inputs.len]) orelse break;
        const input = &inputs[index];
        result.retained.unset(index);
        result.reasons[index] = if (hard) .capacity else .count_pruning;
        result.retained_count -= 1;
        result.coverage.change(input, false);
        if (input.evaluating) evaluating -= 1;
    }
    std.debug.assert(result.retained_count <= options.max_peers);
    result.deficits = result.coverage.deficits(demand, options.min_outbound);
    const coverage_missing = result.deficits.attestation > 0 or result.deficits.sync > 0 or result.deficits.groups > 0;
    const wanted = @max(options.target_peers -| result.retained_count, @max(result.deficits.outbound, @as(u16, if (coverage_missing) 1 else 0)));
    result.dial_budget = @min(wanted, options.max_peers -| result.retained_count);
    return result;
}
test {
    _ = @import("policy_test.zig");
}
