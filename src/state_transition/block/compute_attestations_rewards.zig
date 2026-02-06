const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const c = @import("constants");
const ForkSeq = @import("config").ForkSeq;

const attester_status = @import("../utils/attester_status.zig");
const FLAG_ELIGIBLE_ATTESTER = attester_status.FLAG_ELIGIBLE_ATTESTER;
const FLAG_PREV_HEAD_ATTESTER = attester_status.FLAG_PREV_HEAD_ATTESTER;
const FLAG_PREV_SOURCE_ATTESTER = attester_status.FLAG_PREV_SOURCE_ATTESTER;
const FLAG_PREV_TARGET_ATTESTER = attester_status.FLAG_PREV_TARGET_ATTESTER;
const FLAG_UNSLASHED = attester_status.FLAG_UNSLASHED;
const hasMarkers = attester_status.hasMarkers;

const isInInactivityLeak = @import("../epoch/inactivity_leak.zig").isInInactivityLeak;

const ValidatorIndex = types.primitive.ValidatorIndex.Type;

const FLAG_PREV_SOURCE_ATTESTER_UNSLASHED = FLAG_PREV_SOURCE_ATTESTER | FLAG_UNSLASHED;
const FLAG_PREV_TARGET_ATTESTER_UNSLASHED = FLAG_PREV_TARGET_ATTESTER | FLAG_UNSLASHED;
const FLAG_PREV_HEAD_ATTESTER_UNSLASHED = FLAG_PREV_HEAD_ATTESTER | FLAG_UNSLASHED;

/// Ideal rewards for a given effective balance
pub const IdealAttestationsReward = struct {
    effective_balance: u64,
    head: u64,
    target: u64,
    source: u64,
    inclusion_delay: u64, // phase0 only
    inactivity: u64,
};

/// Penalties for a given effective balance (for non-participation)
const AttestationsPenalty = struct {
    effective_balance: u64,
    target: u64,
    source: u64,
};

/// Actual rewards for a specific validator
pub const TotalAttestationsReward = struct {
    validator_index: ValidatorIndex,
    head: i64,
    target: i64,
    source: i64,
    inclusion_delay: i64, // phase0 only
    inactivity: i64,
};

pub const AttestationsRewards = struct {
    ideal_rewards: std.ArrayList(IdealAttestationsReward),
    total_rewards: std.ArrayList(TotalAttestationsReward),

    pub fn deinit(self: *AttestationsRewards) void {
        self.ideal_rewards.deinit();
        self.total_rewards.deinit();
    }
};

/// Calculate attestation rewards for all eligible validators.
/// Returns ideal rewards (per effective balance) and total rewards (per validator).
pub fn computeAttestationsRewards(allocator: Allocator, cached_state: *CachedBeaconState, validator_ids: []const ValidatorIndex) !AttestationsRewards {
    const fork_seq = cached_state.state.forkSeq();
    if (fork_seq == .phase0) {
        return error.UnsupportedFork; // phase0 attestation rewards not supported
    }

    const transition_cache = try EpochTransitionCache.init(
        allocator,
        cached_state.config,
        cached_state.getEpochCache(),
        cached_state.state,
    );
    var transition_cache_mut = transition_cache;
    defer transition_cache_mut.deinit();

    var ideal_rewards = std.ArrayList(IdealAttestationsReward).init(allocator);
    errdefer ideal_rewards.deinit();

    var penalties = std.ArrayList(AttestationsPenalty).init(allocator);
    defer penalties.deinit();

    try computeIdealAttestationsRewardsAndPenaltiesAltair(
        allocator,
        cached_state,
        &transition_cache_mut,
        &ideal_rewards,
        &penalties,
    );

    var total_rewards = std.ArrayList(TotalAttestationsReward).init(allocator);
    errdefer total_rewards.deinit();

    try computeTotalAttestationsRewardsAltair(
        allocator,
        cached_state,
        &transition_cache_mut,
        ideal_rewards.items,
        penalties.items,
        validator_ids,
        &total_rewards,
    );

    return .{
        .ideal_rewards = ideal_rewards,
        .total_rewards = total_rewards,
    };
}

fn computeIdealAttestationsRewardsAndPenaltiesAltair(
    allocator: Allocator,
    cached_state: *CachedBeaconState,
    transition_cache: *EpochTransitionCache,
    out_ideal_rewards: *std.ArrayList(IdealAttestationsReward),
    out_penalties: *std.ArrayList(AttestationsPenalty),
) !void {
    _ = allocator;
    const fork_seq = cached_state.state.forkSeq();
    const base_reward_per_increment = transition_cache.base_reward_per_increment;
    const total_active_stake_by_increment = transition_cache.total_active_stake_by_increment;
    const epoch_cache = cached_state.getEpochCache();
    const in_inactivity_leak = isInInactivityLeak(epoch_cache.epoch, try cached_state.state.finalizedEpoch());

    const max_effective_balance: u64 = if (fork_seq.gte(.electra))
        preset.MAX_EFFECTIVE_BALANCE_ELECTRA
    else
        preset.MAX_EFFECTIVE_BALANCE;
    const max_effective_balance_by_increment: u64 = max_effective_balance / preset.EFFECTIVE_BALANCE_INCREMENT;

    // Pre-allocate arrays for each effective balance increment
    try out_ideal_rewards.ensureTotalCapacity(max_effective_balance_by_increment + 1);
    try out_penalties.ensureTotalCapacity(max_effective_balance_by_increment + 1);

    const participation_flag_weights = [3]u64{
        c.TIMELY_SOURCE_WEIGHT,
        c.TIMELY_TARGET_WEIGHT,
        c.TIMELY_HEAD_WEIGHT,
    };

    const unslashed_stakes = [3]u64{
        transition_cache.prev_epoch_unslashed_stake_source_by_increment,
        transition_cache.prev_epoch_unslashed_stake_target_by_increment,
        transition_cache.prev_epoch_unslashed_stake_head_by_increment,
    };

    // For each effective balance increment level
    var eff_bal_inc: u64 = 0;
    while (eff_bal_inc <= max_effective_balance_by_increment) : (eff_bal_inc += 1) {
        var ideal_reward = IdealAttestationsReward{
            .effective_balance = eff_bal_inc * preset.EFFECTIVE_BALANCE_INCREMENT,
            .head = 0,
            .target = 0,
            .source = 0,
            .inclusion_delay = 0,
            .inactivity = 0,
        };
        var penalty = AttestationsPenalty{
            .effective_balance = eff_bal_inc * preset.EFFECTIVE_BALANCE_INCREMENT,
            .target = 0,
            .source = 0,
        };

        const base_reward = eff_bal_inc * base_reward_per_increment;

        // Source (index 0)
        {
            const weight = participation_flag_weights[0];
            const unslashed_stake = unslashed_stakes[0];
            const reward_numerator = base_reward * weight * unslashed_stake;
            const reward_denominator = total_active_stake_by_increment * c.WEIGHT_DENOMINATOR;
            const ideal = (reward_numerator + reward_denominator / 2) / reward_denominator; // Math.round()
            const penalty_denominator = c.WEIGHT_DENOMINATOR;
            const pen = (base_reward * weight + penalty_denominator / 2) / penalty_denominator; // Math.round()

            ideal_reward.source = if (in_inactivity_leak) 0 else ideal;
            penalty.source = pen;
        }

        // Target (index 1)
        {
            const weight = participation_flag_weights[1];
            const unslashed_stake = unslashed_stakes[1];
            const reward_numerator = base_reward * weight * unslashed_stake;
            const reward_denominator = total_active_stake_by_increment * c.WEIGHT_DENOMINATOR;
            const ideal = (reward_numerator + reward_denominator / 2) / reward_denominator; // Math.round()
            const penalty_denominator = c.WEIGHT_DENOMINATOR;
            const pen = (base_reward * weight + penalty_denominator / 2) / penalty_denominator; // Math.round()

            ideal_reward.target = if (in_inactivity_leak) 0 else ideal;
            penalty.target = pen;
        }

        // Head (index 2) - no penalty for head
        {
            const weight = participation_flag_weights[2];
            const unslashed_stake = unslashed_stakes[2];
            const reward_numerator = base_reward * weight * unslashed_stake;
            const reward_denominator = total_active_stake_by_increment * c.WEIGHT_DENOMINATOR;
            const ideal = (reward_numerator + reward_denominator / 2) / reward_denominator; // Math.round()

            ideal_reward.head = if (in_inactivity_leak) 0 else ideal;
        }

        try out_ideal_rewards.append(ideal_reward);
        try out_penalties.append(penalty);
    }
}

fn computeTotalAttestationsRewardsAltair(
    allocator: Allocator,
    cached_state: *CachedBeaconState,
    transition_cache: *EpochTransitionCache,
    ideal_rewards: []const IdealAttestationsReward,
    penalties: []const AttestationsPenalty,
    validator_ids: []const ValidatorIndex,
    out_total_rewards: *std.ArrayList(TotalAttestationsReward),
) !void {
    const state = cached_state.state;
    const config = cached_state.config;
    const epoch_cache = cached_state.getEpochCache();
    const flags = transition_cache.flags;
    const effective_balance_increments = epoch_cache.getEffectiveBalanceIncrements().items;

    const inactivity_penalty_denominator = config.chain.INACTIVITY_SCORE_BIAS * preset.INACTIVITY_PENALTY_QUOTIENT_ALTAIR;

    // Build filter set if validatorIds provided
    var filter_set = std.AutoHashMap(ValidatorIndex, void).init(allocator);
    defer filter_set.deinit();
    for (validator_ids) |vid| {
        try filter_set.put(vid, {});
    }

    var inactivity_scores = try state.inactivityScores();

    for (0..flags.len) |i| {
        if (validator_ids.len > 0 and !filter_set.contains(@intCast(i))) {
            continue;
        }

        const flag = flags[i];

        // Only process eligible attesters
        if (!hasMarkers(flag, FLAG_ELIGIBLE_ATTESTER)) {
            continue;
        }

        const eff_bal_inc = effective_balance_increments[i];
        var reward = TotalAttestationsReward{
            .validator_index = @intCast(i),
            .head = 0,
            .target = 0,
            .source = 0,
            .inclusion_delay = 0,
            .inactivity = 0,
        };

        if (hasMarkers(flag, FLAG_PREV_SOURCE_ATTESTER_UNSLASHED)) {
            reward.source = @intCast(ideal_rewards[eff_bal_inc].source);
        } else {
            reward.source = @as(i64, @intCast(penalties[eff_bal_inc].source)) * -1;
        }

        if (hasMarkers(flag, FLAG_PREV_TARGET_ATTESTER_UNSLASHED)) {
            reward.target = @intCast(ideal_rewards[eff_bal_inc].target);
        } else {
            reward.target = @as(i64, @intCast(penalties[eff_bal_inc].target)) * -1;

            const inactivity_score = try inactivity_scores.get(i);
            const inactivity_penalty_numerator = @as(u64, eff_bal_inc) * preset.EFFECTIVE_BALANCE_INCREMENT * inactivity_score;
            reward.inactivity = @as(i64, @intCast(@divFloor(inactivity_penalty_numerator, inactivity_penalty_denominator))) * -1;
        }

        if (hasMarkers(flag, FLAG_PREV_HEAD_ATTESTER_UNSLASHED)) {
            reward.head = @intCast(ideal_rewards[eff_bal_inc].head);
        }

        try out_total_rewards.append(reward);
    }
}
