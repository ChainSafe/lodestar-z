const std = @import("std");
const Allocator = std.mem.Allocator;
const ForkSeq = @import("config").ForkSeq;
const BeaconConfig = @import("config").BeaconConfig;
const BeaconState = @import("fork_types").BeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const attester_status = @import("../utils/attester_status.zig");
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const preset = @import("preset").preset;
const c = @import("constants");

const EFFECTIVE_BALANCE_INCREMENT = preset.EFFECTIVE_BALANCE_INCREMENT;
const INACTIVITY_PENALTY_QUOTIENT_ALTAIR = preset.INACTIVITY_PENALTY_QUOTIENT_ALTAIR;
const INACTIVITY_PENALTY_QUOTIENT_BELLATRIX = preset.INACTIVITY_PENALTY_QUOTIENT_BELLATRIX;
const PARTICIPATION_FLAG_WEIGHTS = c.PARTICIPATION_FLAG_WEIGHTS;
const TIMELY_HEAD_FLAG_INDEX = c.TIMELY_HEAD_FLAG_INDEX;
const TIMELY_SOURCE_FLAG_INDEX = c.TIMELY_SOURCE_FLAG_INDEX;
const TIMELY_TARGET_FLAG_INDEX = c.TIMELY_TARGET_FLAG_INDEX;
const WEIGHT_DENOMINATOR = c.WEIGHT_DENOMINATOR;

const FLAG_ELIGIBLE_ATTESTER = attester_status.FLAG_ELIGIBLE_ATTESTER;
const FLAG_PREV_HEAD_ATTESTER_UNSLASHED = attester_status.FLAG_PREV_HEAD_ATTESTER_UNSLASHED;
const FLAG_PREV_SOURCE_ATTESTER_UNSLASHED = attester_status.FLAG_PREV_SOURCE_ATTESTER_UNSLASHED;
const FLAG_PREV_TARGET_ATTESTER_UNSLASHED = attester_status.FLAG_PREV_TARGET_ATTESTER_UNSLASHED;
const hasMarkers = attester_status.hasMarkers;

const isInInactivityLeak = @import("inactivity_leak.zig").isInInactivityLeak;

const RewardPenaltyItem = struct {
    base_reward: u64,
    timely_source_reward: u64,
    timely_source_penalty: u64,
    timely_target_reward: u64,
    timely_target_penalty: u64,
    timely_head_reward: u64,
};

/// consumer should deinit `rewards` and `penalties` arrays
pub fn getRewardsAndPenaltiesAltair(
    comptime fork: ForkSeq,
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *BeaconState(fork),
    cache: *const EpochTransitionCache,
    rewards: []u64,
    penalties: []u64,
) !void {
    const validator_count = try state.validatorsCount();
    const active_increments = cache.total_active_stake_by_increment;
    if (rewards.len != validator_count or penalties.len != validator_count) {
        return error.InvalidArrayLength;
    }
    @memset(rewards, 0);
    @memset(penalties, 0);

    const is_in_inactivity_leak = isInInactivityLeak(epoch_cache.epoch, try state.finalizedEpoch());
    // effectiveBalance is multiple of EFFECTIVE_BALANCE_INCREMENT and less than MAX_EFFECTIVE_BALANCE
    // so there are limited values of them like 32, 31, 30
    var reward_penalty_item_cache = std.AutoHashMap(u64, RewardPenaltyItem).init(allocator);
    defer reward_penalty_item_cache.deinit();

    const inactivity_penality_multiplier: u64 =
        if (fork == ForkSeq.altair) INACTIVITY_PENALTY_QUOTIENT_ALTAIR else INACTIVITY_PENALTY_QUOTIENT_BELLATRIX;
    const penalty_denominator = config.chain.INACTIVITY_SCORE_BIAS * inactivity_penality_multiplier;

    const flags = cache.flags;
    const effective_balance_increments = epoch_cache.getEffectiveBalanceIncrements().items;
    var inactivity_scores = try state.inactivityScores();
    for (flags, 0..) |flag, i| {
        if (!hasMarkers(flag, FLAG_ELIGIBLE_ATTESTER)) {
            continue;
        }

        const effective_balance_increment = effective_balance_increments[i];

        const reward_penalty_item = if (reward_penalty_item_cache.get(effective_balance_increment)) |rpi| rpi else blk: {
            const base_reward = effective_balance_increment * cache.base_reward_per_increment;
            const ts_weigh = PARTICIPATION_FLAG_WEIGHTS[TIMELY_SOURCE_FLAG_INDEX];
            const tt_weigh = PARTICIPATION_FLAG_WEIGHTS[TIMELY_TARGET_FLAG_INDEX];
            const th_weigh = PARTICIPATION_FLAG_WEIGHTS[TIMELY_HEAD_FLAG_INDEX];
            const ts_unslashed_participating_increments = cache.prev_epoch_unslashed_stake_source_by_increment;
            const tt_unslashed_participating_increments = cache.prev_epoch_unslashed_stake_target_by_increment;
            const th_unslashed_participating_increments = cache.prev_epoch_unslashed_stake_head_by_increment;
            const ts_reward_numerator = base_reward * ts_weigh * ts_unslashed_participating_increments;
            const tt_reward_numerator = base_reward * tt_weigh * tt_unslashed_participating_increments;
            const th_reward_numerator = base_reward * th_weigh * th_unslashed_participating_increments;
            const rpi = RewardPenaltyItem{
                .base_reward = base_reward,
                .timely_source_reward = @divFloor(ts_reward_numerator, active_increments * WEIGHT_DENOMINATOR),
                .timely_target_reward = @divFloor(tt_reward_numerator, active_increments * WEIGHT_DENOMINATOR),
                .timely_head_reward = @divFloor(th_reward_numerator, active_increments * WEIGHT_DENOMINATOR),
                .timely_source_penalty = @divFloor(base_reward * ts_weigh, WEIGHT_DENOMINATOR),
                .timely_target_penalty = @divFloor(base_reward * tt_weigh, WEIGHT_DENOMINATOR),
            };
            try reward_penalty_item_cache.put(effective_balance_increment, rpi);
            break :blk rpi;
        };

        const timely_source_reward = reward_penalty_item.timely_source_reward;
        const timely_source_penalty = reward_penalty_item.timely_source_penalty;
        const timely_target_reward = reward_penalty_item.timely_target_reward;
        const timely_target_penalty = reward_penalty_item.timely_target_penalty;
        const timely_head_reward = reward_penalty_item.timely_head_reward;

        // same logic to getFlagIndexDeltas
        if (hasMarkers(flag, FLAG_PREV_SOURCE_ATTESTER_UNSLASHED)) {
            if (is_in_inactivity_leak) {} else {
                rewards[i] += timely_source_reward;
            }
        } else {
            penalties[i] += timely_source_penalty;
        }

        if (hasMarkers(flag, FLAG_PREV_TARGET_ATTESTER_UNSLASHED)) {
            if (is_in_inactivity_leak) {} else {
                rewards[i] += timely_target_reward;
            }
        } else {
            penalties[i] += timely_target_penalty;
        }

        if (hasMarkers(flag, FLAG_PREV_HEAD_ATTESTER_UNSLASHED) and !is_in_inactivity_leak) {
            rewards[i] += timely_head_reward;
        }

        // Same logic to getInactivityPenaltyDeltas
        // TODO: if we have limited value in inactivityScores we can provide a cache too
        if (!hasMarkers(flag, FLAG_PREV_TARGET_ATTESTER_UNSLASHED)) {
            const penalty_numerator: u64 = @as(u64, effective_balance_increment) * EFFECTIVE_BALANCE_INCREMENT * (try inactivity_scores.get(i));
            penalties[i] += @divFloor(penalty_numerator, penalty_denominator);
        }
    }
}


const testing = std.testing;
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const Node = @import("persistent_merkle_tree").Node;
const attester_status_mod = @import("../utils/attester_status.zig");

test "getRewardsAndPenaltiesAltair - all validators participating" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 50_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 64);
    defer test_state.deinit();

    const validator_count = 64;
    var rewards: [validator_count]u64 = undefined;
    var penalties: [validator_count]u64 = undefined;

    try getRewardsAndPenaltiesAltair(
        .electra,
        allocator,
        test_state.cached_state.config,
        test_state.cached_state.epoch_cache,
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
        &rewards,
        &penalties,
    );

    // All validators are participating (flags have source+target+head+unslashed+eligible)
    // So they should receive rewards and no penalties
    for (0..validator_count) |i| {
        try testing.expect(rewards[i] > 0);
        try testing.expectEqual(@as(u64, 0), penalties[i]);
    }

    // All validators have same effective balance, so rewards should be equal
    for (1..validator_count) |i| {
        try testing.expectEqual(rewards[0], rewards[i]);
    }
}

test "getRewardsAndPenaltiesAltair - non-participating validators get penalties" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 50_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 64);
    defer test_state.deinit();

    const validator_count = 64;

    // Modify flags for the first validator: eligible but not attesting (no source/target/head flags)
    // The flags field is []const u8 borrowed from reused cache, but for testing we can cast
    const flags_mut: []u8 = @constCast(test_state.epoch_transition_cache.flags);
    // Clear participation flags for validator 0 but keep eligible + unslashed
    flags_mut[0] = attester_status_mod.FLAG_ELIGIBLE_ATTESTER | attester_status_mod.FLAG_UNSLASHED;

    var rewards: [validator_count]u64 = undefined;
    var penalties: [validator_count]u64 = undefined;

    try getRewardsAndPenaltiesAltair(
        .electra,
        allocator,
        test_state.cached_state.config,
        test_state.cached_state.epoch_cache,
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
        &rewards,
        &penalties,
    );

    // Validator 0: no participation flags → should get penalties, no rewards
    try testing.expectEqual(@as(u64, 0), rewards[0]);
    try testing.expect(penalties[0] > 0);

    // Other validators still participating → should get rewards, no penalties
    try testing.expect(rewards[1] > 0);
    try testing.expectEqual(@as(u64, 0), penalties[1]);
}

test "getRewardsAndPenaltiesAltair - partial participation (source only)" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 50_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 64);
    defer test_state.deinit();

    const validator_count = 64;

    // Validator 0: only source attested (no target, no head)
    const flags_mut: []u8 = @constCast(test_state.epoch_transition_cache.flags);
    flags_mut[0] = attester_status_mod.FLAG_ELIGIBLE_ATTESTER |
        attester_status_mod.FLAG_UNSLASHED |
        attester_status_mod.FLAG_PREV_SOURCE_ATTESTER;

    var rewards: [validator_count]u64 = undefined;
    var penalties: [validator_count]u64 = undefined;

    try getRewardsAndPenaltiesAltair(
        .electra,
        allocator,
        test_state.cached_state.config,
        test_state.cached_state.epoch_cache,
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
        &rewards,
        &penalties,
    );

    // Validator 0 should get source reward but target and head penalties
    // Rewards should be positive (source reward)
    try testing.expect(rewards[0] > 0);
    // Penalties should be positive (target + head penalties + inactivity penalty for missing target)
    try testing.expect(penalties[0] > 0);

    // Fully participating validator should have higher rewards and no penalties
    try testing.expect(rewards[1] > rewards[0]);
    try testing.expectEqual(@as(u64, 0), penalties[1]);
}

test "getRewardsAndPenaltiesAltair - slashed validator gets no rewards" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 50_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 64);
    defer test_state.deinit();

    const validator_count = 64;

    // Validator 0: eligible but slashed (no UNSLASHED flag), with participation flags
    const flags_mut: []u8 = @constCast(test_state.epoch_transition_cache.flags);
    flags_mut[0] = attester_status_mod.FLAG_ELIGIBLE_ATTESTER |
        attester_status_mod.FLAG_PREV_SOURCE_ATTESTER |
        attester_status_mod.FLAG_PREV_TARGET_ATTESTER |
        attester_status_mod.FLAG_PREV_HEAD_ATTESTER;
    // Note: without FLAG_UNSLASHED, the participation flags don't count

    var rewards: [validator_count]u64 = undefined;
    var penalties: [validator_count]u64 = undefined;

    try getRewardsAndPenaltiesAltair(
        .electra,
        allocator,
        test_state.cached_state.config,
        test_state.cached_state.epoch_cache,
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
        &rewards,
        &penalties,
    );

    // Slashed validator: participation flags ignored without UNSLASHED
    // Should get penalties for source, target, head + inactivity penalty for missing target
    try testing.expectEqual(@as(u64, 0), rewards[0]);
    try testing.expect(penalties[0] > 0);
}

test "getRewardsAndPenaltiesAltair - non-eligible validator skipped" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 50_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 64);
    defer test_state.deinit();

    const validator_count = 64;

    // Validator 0: not eligible (e.g. not yet activated)
    const flags_mut: []u8 = @constCast(test_state.epoch_transition_cache.flags);
    flags_mut[0] = 0; // no flags at all

    var rewards: [validator_count]u64 = undefined;
    var penalties: [validator_count]u64 = undefined;

    try getRewardsAndPenaltiesAltair(
        .electra,
        allocator,
        test_state.cached_state.config,
        test_state.cached_state.epoch_cache,
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
        &rewards,
        &penalties,
    );

    // Non-eligible: completely skipped, no rewards or penalties
    try testing.expectEqual(@as(u64, 0), rewards[0]);
    try testing.expectEqual(@as(u64, 0), penalties[0]);
}

test "getRewardsAndPenaltiesAltair - reward values match spec formula" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 50_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 64);
    defer test_state.deinit();

    const validator_count = 64;
    var rewards: [validator_count]u64 = undefined;
    var penalties: [validator_count]u64 = undefined;

    try getRewardsAndPenaltiesAltair(
        .electra,
        allocator,
        test_state.cached_state.config,
        test_state.cached_state.epoch_cache,
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
        &rewards,
        &penalties,
    );

    // Manually compute expected reward for a fully participating validator
    const cache = test_state.epoch_transition_cache;
    const effective_balance_increment: u64 = 32; // 32 ETH / EFFECTIVE_BALANCE_INCREMENT
    const base_reward = effective_balance_increment * cache.base_reward_per_increment;
    const active_increments = cache.total_active_stake_by_increment;

    // Source weight=14, Target weight=26, Head weight=14, denominator=64
    // All validators participating, so unslashed_stake == total_active_stake
    const source_reward = @divFloor(base_reward * 14 * active_increments, active_increments * 64);
    const target_reward = @divFloor(base_reward * 26 * active_increments, active_increments * 64);
    const head_reward = @divFloor(base_reward * 14 * active_increments, active_increments * 64);
    const expected_total = source_reward + target_reward + head_reward;

    try testing.expectEqual(expected_total, rewards[0]);
    try testing.expectEqual(@as(u64, 0), penalties[0]);
}
