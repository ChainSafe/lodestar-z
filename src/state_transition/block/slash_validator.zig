const std = @import("std");
const BeaconConfig = @import("config").BeaconConfig;
const ForkSeq = @import("config").ForkSeq;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const c = @import("constants");
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const BeaconState = @import("fork_types").BeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const SlashingsCache = @import("../cache/slashings_cache.zig").SlashingsCache;
const decreaseBalance = @import("../utils/balance.zig").decreaseBalance;
const increaseBalance = @import("../utils/balance.zig").increaseBalance;
const initiateValidatorExit = @import("./initiate_validator_exit.zig").initiateValidatorExit;
const getBeaconProposer = @import("../cache/get_beacon_proposer.zig").getBeaconProposer;

/// Same to https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.5/specs/altair/beacon-chain.md#has_flag
const TIMELY_TARGET = 1 << c.TIMELY_TARGET_FLAG_INDEX;

pub fn slashValidator(
    comptime fork: ForkSeq,
    config: *const BeaconConfig,
    epoch_cache: *EpochCache,
    state: *BeaconState(fork),
    slashings_cache: *SlashingsCache,
    slashed_index: ValidatorIndex,
    whistle_blower_index: ?ValidatorIndex,
) !void {
    const epoch = epoch_cache.epoch;
    const effective_balance_increments = epoch_cache.effective_balance_increments;
    const slashed_effective_balance_increments = effective_balance_increments.get().items[@intCast(slashed_index)];

    var validators = try state.validators();
    var validator = try validators.get(@intCast(slashed_index));

    try initiateValidatorExit(fork, config, epoch_cache, state, validator);
    try validator.set("slashed", true);

    var latest_block_header = try state.latestBlockHeader();
    const latest_block_slot = try latest_block_header.get("slot");
    try slashings_cache.recordValidatorSlashing(latest_block_slot, slashed_index);
    const cur_withdrawable_epoch = try validator.get("withdrawable_epoch");
    try validator.set(
        "withdrawable_epoch",
        @max(cur_withdrawable_epoch, epoch + preset.EPOCHS_PER_SLASHINGS_VECTOR),
    );

    const effective_balance = try validator.get("effective_balance");
    try validator.commit();
    try validators.commit();
    try state.commit();

    // state.slashings is initially a Gwei (BigInt) vector, however since Nov 2023 it's converted to UintNum64 (number) vector in the state transition because:
    //  - state.slashings[nextEpoch % EPOCHS_PER_SLASHINGS_VECTOR] is reset per epoch in processSlashingsReset()
    //  - max slashed validators per epoch is SLOTS_PER_EPOCH * MAX_ATTESTER_SLASHINGS * MAX_VALIDATORS_PER_COMMITTEE which is 32 * 2 * 2048 = 131072 on mainnet
    //  - with that and 32_000_000_000 MAX_EFFECTIVE_BALANCE or 2048_000_000_000 MAX_EFFECTIVE_BALANCE_ELECTRA, it still fits in a number given that Math.floor(Number.MAX_SAFE_INTEGER / 32_000_000_000) = 281474
    //  - we don't need to compute the total slashings from state.slashings, it's handled by totalSlashingsByIncrement in EpochCache
    const slashing_index = epoch % preset.EPOCHS_PER_SLASHINGS_VECTOR;
    var slashings = try state.slashings();
    const cur_slashings = try slashings.get(@intCast(slashing_index));
    try slashings.set(@intCast(slashing_index), cur_slashings + effective_balance);
    epoch_cache.total_slashings_by_increment += slashed_effective_balance_increments;

    const min_slashing_penalty_quotient: usize = switch (fork) {
        .phase0 => preset.MIN_SLASHING_PENALTY_QUOTIENT,
        .altair => preset.MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR,
        .bellatrix, .capella, .deneb => preset.MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX,
        .electra, .fulu, .gloas => preset.MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA,
    };

    try decreaseBalance(fork, state, slashed_index, @divFloor(effective_balance, min_slashing_penalty_quotient));

    // apply proposer and whistleblower rewards
    const whistleblower_reward = switch (fork) {
        .electra, .fulu, .gloas => @divFloor(effective_balance, preset.WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA),
        else => @divFloor(effective_balance, preset.WHISTLEBLOWER_REWARD_QUOTIENT),
    };

    const proposer_reward = switch (fork) {
        .phase0 => @divFloor(whistleblower_reward, preset.PROPOSER_REWARD_QUOTIENT),
        else => @divFloor(whistleblower_reward * c.PROPOSER_WEIGHT, c.WEIGHT_DENOMINATOR),
    };

    const proposer_index = try getBeaconProposer(fork, epoch_cache, state, try state.slot());

    if (whistle_blower_index) |_whistle_blower_index| {
        try increaseBalance(fork, state, proposer_index, proposer_reward);
        try increaseBalance(fork, state, _whistle_blower_index, whistleblower_reward - proposer_reward);
        // TODO: implement RewardCache
        // state.proposer_rewards.slashing += proposer_reward;
    } else {
        try increaseBalance(fork, state, proposer_index, whistleblower_reward);
        // TODO: implement RewardCache
        // state.proposerRewards.slashing += whistleblowerReward;
    }

    if (fork.gte(.altair)) {
        var previous_participation = try state.previousEpochParticipation();
        if ((try previous_participation.get(@intCast(slashed_index))) & TIMELY_TARGET == TIMELY_TARGET) {
            if (epoch_cache.previous_target_unslashed_balance_increments < slashed_effective_balance_increments) {
                return error.PreviousTargetUnslashedBalanceUnderflow;
            }
            epoch_cache.previous_target_unslashed_balance_increments -= slashed_effective_balance_increments;
        }

        var current_participation = try state.currentEpochParticipation();
        if ((try current_participation.get(@intCast(slashed_index))) & TIMELY_TARGET == TIMELY_TARGET) {
            if (epoch_cache.current_target_unslashed_balance_increments < slashed_effective_balance_increments) {
                return error.CurrentTargetUnslashedBalanceUnderflow;
            }
            epoch_cache.current_target_unslashed_balance_increments -= slashed_effective_balance_increments;
        }
    }
}

test "slashValidator keeps current target unslashed balance consistent" {
    const test_utils = @import("../test_utils/root.zig");
    const TestCachedBeaconState = test_utils.TestCachedBeaconState;
    const Node = @import("persistent_merkle_tree").Node;
    const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;

    const allocator = std.testing.allocator;
    const num_validators: usize = 256;
    const pool_size = num_validators * 5;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = pool_size });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, num_validators);
    defer test_state.deinit();

    try @import("../cache/slashings_cache.zig").buildFromStateIfNeeded(
        allocator,
        test_state.cached_state.state.castToFork(.electra),
        &test_state.cached_state.slashings_cache,
    );

    var current_epoch_participation = try test_state.cached_state.state.currentEpochParticipation();
    try current_epoch_participation.set(0, 0b111);
    try current_epoch_participation.commit();
    try test_state.cached_state.state.commit();

    // Slash validator at index 0
    try slashValidator(
        .electra,
        test_state.config,
        test_state.cached_state.epoch_cache,
        test_state.cached_state.state.castToFork(.electra),
        &test_state.cached_state.slashings_cache,
        0,
        null,
    );

    // First validator should be slashed
    var validators = try test_state.cached_state.state.validators();
    var validator = try validators.getReadonly(0);
    try std.testing.expect(try validator.get("slashed"));
    var validators_it = validators.iteratorReadonly(0);
    const validator_from_iterator = try validators_it.nextValuePtr();
    try std.testing.expect(validator_from_iterator.slashed);
    try std.testing.expectEqual(
        @as(u64, (num_validators - 1) * test_utils.EFFECTIVE_BALANCE_INCREMENT),
        test_state.cached_state.epoch_cache.current_target_unslashed_balance_increments,
    );

    var epoch_transition_cache = try EpochTransitionCache.init(
        allocator,
        std.testing.io,
        test_state.cached_state.config,
        test_state.cached_state.epoch_cache,
        test_state.cached_state.state,
    );
    // Assert transition cache consistency
    try std.testing.expectEqual(
        test_state.cached_state.epoch_cache.current_target_unslashed_balance_increments,
        epoch_transition_cache.curr_epoch_unslashed_target_stake_by_increment,
    );
    epoch_transition_cache.deinit(allocator);
}
