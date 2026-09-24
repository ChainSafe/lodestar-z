const std = @import("std");
const preset = @import("preset").preset;
const constants = @import("constants");
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const status = @import("../utils/attester_status.zig");
const isInInactivityLeak = @import("../epoch/inactivity_leak.zig").isInInactivityLeak;

pub const IdealAttestationsReward = struct {
    effective_balance: u64,
    head: f64 = 0,
    target: f64 = 0,
    source: f64 = 0,
    inclusion_delay: f64 = 0,
    inactivity: f64 = 0,
};

pub const TotalAttestationsReward = struct {
    validator_index: u64,
    head: f64 = 0,
    target: f64 = 0,
    source: f64 = 0,
    inclusion_delay: f64 = 0,
    inactivity: f64 = 0,
};

pub const AttestationsRewards = struct {
    ideal_rewards: []IdealAttestationsReward,
    total_rewards: []TotalAttestationsReward,

    pub fn deinit(self: AttestationsRewards, allocator: std.mem.Allocator) void {
        allocator.free(self.ideal_rewards);
        allocator.free(self.total_rewards);
    }
};

/// Returns caller-owned rewards. Filters must be sorted ascending; null selects all,
/// while an empty slice selects none. Serialize with other EpochTransitionCache borrowers.
pub fn computeAttestationsRewards(
    allocator: std.mem.Allocator,
    io: std.Io,
    state: *CachedBeaconState,
    validator_indices: ?[]const u64,
) !AttestationsRewards {
    const fork = state.state.forkSeq();
    if (fork == .phase0) return error.AttestationsRewardsUnsupportedFork;
    if (validator_indices) |indices| std.debug.assert(std.sort.isSorted(u64, indices, {}, std.sort.asc(u64)));

    var cache = try EpochTransitionCache.init(allocator, io, state.config, state.epoch_cache, state.state);
    defer cache.deinit(allocator);

    const max_balance: u64 = if (fork.gte(.electra)) preset.MAX_EFFECTIVE_BALANCE_ELECTRA else preset.MAX_EFFECTIVE_BALANCE;
    const ideal_rewards = try allocator.alloc(IdealAttestationsReward, max_balance / preset.EFFECTIVE_BALANCE_INCREMENT + 1);
    errdefer allocator.free(ideal_rewards);

    const leak = isInInactivityLeak(state.epoch_cache.epoch, try state.state.finalizedEpoch());
    const base_reward_per_increment: f64 = @floatFromInt(cache.base_reward_per_increment);
    const active_increments: f64 = @floatFromInt(cache.total_active_stake_by_increment);
    const unslashed_increments = [_]u64{
        cache.prev_epoch_unslashed_stake_source_by_increment,
        cache.prev_epoch_unslashed_stake_target_by_increment,
        cache.prev_epoch_unslashed_stake_head_by_increment,
    };
    for (ideal_rewards, 0..) |*reward, increment| {
        reward.* = .{ .effective_balance = increment * preset.EFFECTIVE_BALANCE_INCREMENT };
        if (leak) continue;
        const base_reward = @as(f64, @floatFromInt(increment)) * base_reward_per_increment;
        inline for (.{ "source", "target", "head" }, 0..) |field, flag_index| {
            const numerator = base_reward * constants.PARTICIPATION_FLAG_WEIGHTS[flag_index] *
                @as(f64, @floatFromInt(unslashed_increments[flag_index]));
            // The API rounds to the nearest Gwei, unlike consensus epoch deltas.
            @field(reward, field) = @round(numerator / active_increments / constants.WEIGHT_DENOMINATOR);
        }
    }

    var total_rewards = try std.ArrayList(TotalAttestationsReward).initCapacity(
        allocator,
        if (validator_indices) |indices| @min(indices.len, cache.flags.len) else cache.flags.len,
    );
    errdefer total_rewards.deinit(allocator);

    const quotient: u64 = if (fork == .altair) preset.INACTIVITY_PENALTY_QUOTIENT_ALTAIR else preset.INACTIVITY_PENALTY_QUOTIENT_BELLATRIX;
    const inactivity_denominator: f64 = @floatFromInt(state.config.chain.INACTIVITY_SCORE_BIAS * quotient);
    const effective_increments = state.epoch_cache.getEffectiveBalanceIncrements().items;
    var inactivity_scores = try state.state.inactivityScores();
    var filter_index: usize = 0;
    for (cache.flags, 0..) |flag, i| {
        if (validator_indices) |indices| {
            while (filter_index < indices.len and indices[filter_index] < i) : (filter_index += 1) {}
            if (filter_index == indices.len) break;
            if (indices[filter_index] != i) continue;
        }
        if (!status.hasMarkers(flag, status.FLAG_ELIGIBLE_ATTESTER)) continue;

        const increment = effective_increments[i];
        const base_reward = @as(f64, @floatFromInt(increment)) * base_reward_per_increment;
        var reward = TotalAttestationsReward{ .validator_index = i };
        reward.source = if (status.hasMarkers(flag, status.FLAG_PREV_SOURCE_ATTESTER_UNSLASHED))
            ideal_rewards[increment].source
        else
            -@round(base_reward * constants.PARTICIPATION_FLAG_WEIGHTS[constants.TIMELY_SOURCE_FLAG_INDEX] / constants.WEIGHT_DENOMINATOR);
        if (status.hasMarkers(flag, status.FLAG_PREV_TARGET_ATTESTER_UNSLASHED)) {
            reward.target = ideal_rewards[increment].target;
        } else {
            reward.target = -@round(base_reward * constants.PARTICIPATION_FLAG_WEIGHTS[constants.TIMELY_TARGET_FLAG_INDEX] / constants.WEIGHT_DENOMINATOR);
            const numerator = @as(f64, @floatFromInt(increment)) * preset.EFFECTIVE_BALANCE_INCREMENT *
                @as(f64, @floatFromInt(try inactivity_scores.get(i)));
            reward.inactivity = -@floor(numerator / inactivity_denominator);
        }
        if (status.hasMarkers(flag, status.FLAG_PREV_HEAD_ATTESTER_UNSLASHED)) reward.head = ideal_rewards[increment].head;
        total_rewards.appendAssumeCapacity(reward);
    }

    return .{ .ideal_rewards = ideal_rewards, .total_rewards = try total_rewards.toOwnedSlice(allocator) };
}

test {
    _ = @import("attestations_rewards_test.zig");
}
