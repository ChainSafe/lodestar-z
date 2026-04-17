const std = @import("std");

const api_mod = @import("api");
const api_types = api_mod.types;
const chain_mod = @import("chain");
const ChainQuery = chain_mod.Query;
const state_transition = @import("state_transition");
const fork_types = @import("fork_types");
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const AnyBeaconBlock = fork_types.AnyBeaconBlock;
const consensus_types = @import("consensus_types");
const preset = @import("preset").preset;
const c = @import("constants");
const attester_status = state_transition.attester_status;
const isInInactivityLeak = state_transition.isInInactivityLeak;
const computeEndSlotAtEpoch = state_transition.computeEndSlotAtEpoch;

const CachedBeaconState = state_transition.CachedBeaconState;
const EpochTransitionCache = state_transition.EpochTransitionCache;
const ImportBlockOpts = chain_mod.blocks.ImportBlockOpts;
const DataAvailabilityStatus = chain_mod.DataAvailabilityStatus;
const Root = consensus_types.primitive.Root.Type;
const ValidatorIndex = consensus_types.primitive.ValidatorIndex.Type;

const EFFECTIVE_BALANCE_INCREMENT = preset.EFFECTIVE_BALANCE_INCREMENT;
const PARTICIPATION_FLAG_WEIGHTS = c.PARTICIPATION_FLAG_WEIGHTS;
const TIMELY_SOURCE_FLAG_INDEX = c.TIMELY_SOURCE_FLAG_INDEX;
const TIMELY_TARGET_FLAG_INDEX = c.TIMELY_TARGET_FLAG_INDEX;
const TIMELY_HEAD_FLAG_INDEX = c.TIMELY_HEAD_FLAG_INDEX;
const WEIGHT_DENOMINATOR = c.WEIGHT_DENOMINATOR;
const INACTIVITY_PENALTY_QUOTIENT_ALTAIR = preset.INACTIVITY_PENALTY_QUOTIENT_ALTAIR;
const INACTIVITY_PENALTY_QUOTIENT_BELLATRIX = preset.INACTIVITY_PENALTY_QUOTIENT_BELLATRIX;
const FLAG_ELIGIBLE_ATTESTER = attester_status.FLAG_ELIGIBLE_ATTESTER;
const FLAG_PREV_HEAD_ATTESTER_UNSLASHED = attester_status.FLAG_PREV_HEAD_ATTESTER_UNSLASHED;
const FLAG_PREV_SOURCE_ATTESTER_UNSLASHED = attester_status.FLAG_PREV_SOURCE_ATTESTER_UNSLASHED;
const FLAG_PREV_TARGET_ATTESTER_UNSLASHED = attester_status.FLAG_PREV_TARGET_ATTESTER_UNSLASHED;
const hasMarkers = attester_status.hasMarkers;

const AttestationPenalty = struct {
    target: u64 = 0,
    source: u64 = 0,
};

const IdealRewardField = enum {
    source,
    target,
    head,
};

const IdealRewardFieldInfo = struct {
    field: IdealRewardField,
    unslashed_stake_by_increment: u64,
};

const LoadedBlock = struct {
    bytes: []const u8,
    any_signed: AnySignedBeaconBlock,

    fn deinit(self: *LoadedBlock, allocator: std.mem.Allocator) void {
        self.any_signed.deinit(allocator);
        allocator.free(self.bytes);
    }
};

pub fn computeBlockRewards(
    allocator: std.mem.Allocator,
    query: ChainQuery,
    block_root: Root,
) !api_types.BlockRewards {
    var loaded = try loadFullBlock(allocator, query, block_root);
    defer loaded.deinit(allocator);

    const block = loaded.any_signed.beaconBlock();
    const pre_state = try getPreStateForBlock(query, &block);

    const stf_result = try chain_mod.blocks.executeStateTransition(
        allocator,
        query.chain.state_graph_gate.io,
        .{
            .block = loaded.any_signed,
            .source = .api,
            .da_status = .available,
            .seen_timestamp_sec = 0,
        },
        pre_state,
        DataAvailabilityStatus.available,
        ImportBlockOpts{
            .skip_signatures = true,
            .skip_execution = true,
            .skip_future_slot = true,
            .valid_signatures = true,
            .valid_proposer_signature = true,
        },
        null,
        query.chain.state_graph_gate,
        null,
    );
    defer {
        stf_result.post_state.deinit();
        allocator.destroy(stf_result.post_state);
    }

    const proposer_rewards = stf_result.post_state.getProposerRewards();
    return .{
        .proposer_index = block.proposerIndex(),
        .total = proposer_rewards.total(),
        .attestations = proposer_rewards.attestations,
        .sync_aggregate = proposer_rewards.sync_aggregate,
        .proposer_slashings = proposer_rewards.proposer_slashings,
        .attester_slashings = proposer_rewards.attester_slashings,
    };
}

pub fn computeAttestationRewards(
    allocator: std.mem.Allocator,
    query: ChainQuery,
    epoch: u64,
    validator_indices: []const u64,
) !api_types.AttestationRewardsData {
    const slot = computeEndSlotAtEpoch(epoch + 1);
    const state = try query.stateBySlot(slot) orelse return error.StateNotAvailable;

    var working_state = try cloneStateForApiWork(allocator, query, state);
    defer {
        working_state.deinit();
        allocator.destroy(working_state);
    }

    if (working_state.state.forkSeq() == .phase0) return error.NotImplemented;

    var transition_cache = try EpochTransitionCache.init(
        allocator,
        working_state.config,
        working_state.epoch_cache,
        working_state.state,
    );
    defer transition_cache.deinit();

    const ideal_and_penalties = try computeIdealAttestationRewardsAndPenalties(
        allocator,
        working_state,
        &transition_cache,
    );
    errdefer {
        allocator.free(ideal_and_penalties.ideal_rewards);
        allocator.free(ideal_and_penalties.penalties);
    }

    const total_rewards = try computeTotalAttestationRewards(
        allocator,
        working_state,
        &transition_cache,
        ideal_and_penalties.ideal_rewards,
        ideal_and_penalties.penalties,
        validator_indices,
    );
    allocator.free(ideal_and_penalties.penalties);

    return .{
        .ideal_rewards = ideal_and_penalties.ideal_rewards,
        .total_rewards = total_rewards,
    };
}

pub fn computeSyncCommitteeRewards(
    allocator: std.mem.Allocator,
    query: ChainQuery,
    block_root: Root,
    validator_indices: []const u64,
) ![]const api_types.SyncCommitteeReward {
    var loaded = try loadFullBlock(allocator, query, block_root);
    defer loaded.deinit(allocator);

    const block = loaded.any_signed.beaconBlock();
    if (block.slot() == 0 or query.chain.config.forkSeq(block.slot()) == .phase0) {
        return error.NotImplemented;
    }

    const pre_state = try getPreStateForBlock(query, &block);
    var working_state = try cloneStateForApiWork(allocator, query, pre_state);
    defer {
        working_state.deinit();
        allocator.destroy(working_state);
    }

    try state_transition.processSlots(allocator, working_state, block.slot(), .{});

    const block_body = block.beaconBlockBody();
    const sync_aggregate = try block_body.syncAggregate();
    const committee_indices = @as(
        *const [preset.SYNC_COMMITTEE_SIZE]ValidatorIndex,
        @ptrCast(working_state.epoch_cache.current_sync_committee_indexed.get().getValidatorIndices()),
    );

    var reward_deltas: std.array_hash_map.Auto(u64, i64) = .empty;
    defer reward_deltas.deinit(allocator);

    const sync_participant_reward = try u64ToI64(working_state.epoch_cache.sync_participant_reward);
    for (0..preset.SYNC_COMMITTEE_SIZE) |i| {
        const validator_index = committee_indices[i];
        const current_delta = reward_deltas.get(validator_index) orelse 0;
        const next_delta = if (try sync_aggregate.sync_committee_bits.get(i))
            current_delta + sync_participant_reward
        else
            current_delta - sync_participant_reward;
        try reward_deltas.put(allocator, validator_index, next_delta);
    }

    var filter = try makeValidatorFilter(allocator, validator_indices);
    defer filter.deinit();

    var rewards = std.ArrayListUnmanaged(api_types.SyncCommitteeReward).empty;
    errdefer rewards.deinit(allocator);

    var it = reward_deltas.iterator();
    while (it.next()) |entry| {
        const validator_index = entry.key_ptr.*;
        if (filter.count() > 0 and !filter.contains(validator_index)) continue;
        try rewards.append(allocator, .{
            .validator_index = validator_index,
            .reward = entry.value_ptr.*,
        });
    }

    return rewards.toOwnedSlice(allocator);
}

fn loadFullBlock(
    allocator: std.mem.Allocator,
    query: ChainQuery,
    block_root: Root,
) !LoadedBlock {
    const block_bytes = (try query.blockBytesByRoot(block_root)) orelse return error.BlockNotFound;
    errdefer allocator.free(block_bytes);

    const slot = readSignedBlockSlotFromSsz(block_bytes) orelse return error.BlockNotFound;
    const fork_seq = query.chain.config.forkSeq(slot);
    const any_signed = try AnySignedBeaconBlock.deserialize(allocator, .full, fork_seq, block_bytes);
    return .{
        .bytes = block_bytes,
        .any_signed = any_signed,
    };
}

fn getPreStateForBlock(query: ChainQuery, block: *const AnyBeaconBlock) !*CachedBeaconState {
    const parent_root = block.parentRoot().*;
    const parent_state_root = (try query.stateRootByBlockRoot(parent_root)) orelse return error.StateNotAvailable;
    const parent_block_bytes = (try query.blockBytesByRoot(parent_root)) orelse return error.StateNotAvailable;
    defer query.chain.allocator.free(parent_block_bytes);
    const parent_slot = readSignedBlockSlotFromSsz(parent_block_bytes) orelse return error.StateNotAvailable;

    return query.chain.queued_regen.getPreState(parent_root, parent_state_root, parent_slot, block.slot(), .api) catch |err| switch (err) {
        error.NoPreStateAvailable => error.StateNotAvailable,
        else => err,
    };
}

fn cloneStateForApiWork(
    allocator: std.mem.Allocator,
    query: ChainQuery,
    state: *CachedBeaconState,
) !*CachedBeaconState {
    var lease = query.chain.acquireStateGraphLease();
    defer lease.release();
    return state.clone(allocator, .{ .transfer_cache = false });
}

fn computeIdealAttestationRewardsAndPenalties(
    allocator: std.mem.Allocator,
    state: *CachedBeaconState,
    transition_cache: *const EpochTransitionCache,
) !struct {
    ideal_rewards: []api_types.IdealAttestationReward,
    penalties: []AttestationPenalty,
} {
    const fork = state.state.forkSeq();
    if (fork == .phase0) return error.NotImplemented;

    const max_effective_balance: u64 = if (fork.gte(.electra))
        preset.MAX_EFFECTIVE_BALANCE_ELECTRA
    else
        preset.MAX_EFFECTIVE_BALANCE;
    const max_effective_balance_increment = @divFloor(max_effective_balance, EFFECTIVE_BALANCE_INCREMENT);

    const ideal_rewards = try allocator.alloc(api_types.IdealAttestationReward, max_effective_balance_increment + 1);
    errdefer allocator.free(ideal_rewards);
    const penalties = try allocator.alloc(AttestationPenalty, max_effective_balance_increment + 1);
    errdefer allocator.free(penalties);

    const is_in_inactivity_leak = isInInactivityLeak(state.epoch_cache.epoch, try state.state.finalizedEpoch());
    const active_increments = transition_cache.total_active_stake_by_increment;
    const base_reward_per_increment = transition_cache.base_reward_per_increment;

    for (0..ideal_rewards.len) |effective_balance_increment| {
        const balance: u64 = @intCast(effective_balance_increment);
        ideal_rewards[effective_balance_increment] = .{
            .effective_balance = balance * EFFECTIVE_BALANCE_INCREMENT,
            .head = 0,
            .target = 0,
            .source = 0,
            .inclusion_delay = 0,
            .inactivity = 0,
        };
        penalties[effective_balance_increment] = .{};
    }

    for (0..PARTICIPATION_FLAG_WEIGHTS.len) |flag_index| {
        const weight = PARTICIPATION_FLAG_WEIGHTS[flag_index];
        const field_info: IdealRewardFieldInfo = switch (flag_index) {
            TIMELY_SOURCE_FLAG_INDEX => .{ .field = IdealRewardField.source, .unslashed_stake_by_increment = transition_cache.prev_epoch_unslashed_stake_source_by_increment },
            TIMELY_TARGET_FLAG_INDEX => .{ .field = IdealRewardField.target, .unslashed_stake_by_increment = transition_cache.prev_epoch_unslashed_stake_target_by_increment },
            TIMELY_HEAD_FLAG_INDEX => .{ .field = IdealRewardField.head, .unslashed_stake_by_increment = transition_cache.prev_epoch_unslashed_stake_head_by_increment },
            else => return error.InternalError,
        };

        for (0..ideal_rewards.len) |effective_balance_increment| {
            const base_reward: u64 = @intCast(effective_balance_increment);
            const base_reward_gwei = base_reward * base_reward_per_increment;
            const reward_numerator = @as(u128, base_reward_gwei) * weight * field_info.unslashed_stake_by_increment;
            const reward_denominator = @as(u128, active_increments) * WEIGHT_DENOMINATOR;
            const ideal_reward = roundedDiv(reward_numerator, reward_denominator);
            const penalty = roundedDiv(@as(u128, base_reward_gwei) * weight, WEIGHT_DENOMINATOR);

            switch (field_info.field) {
                .source => {
                    ideal_rewards[effective_balance_increment].source = if (is_in_inactivity_leak) 0 else ideal_reward;
                    penalties[effective_balance_increment].source = penalty;
                },
                .target => {
                    ideal_rewards[effective_balance_increment].target = if (is_in_inactivity_leak) 0 else ideal_reward;
                    penalties[effective_balance_increment].target = penalty;
                },
                .head => {
                    ideal_rewards[effective_balance_increment].head = if (is_in_inactivity_leak) 0 else ideal_reward;
                },
            }
        }
    }

    return .{
        .ideal_rewards = ideal_rewards,
        .penalties = penalties,
    };
}

fn computeTotalAttestationRewards(
    allocator: std.mem.Allocator,
    state: *CachedBeaconState,
    transition_cache: *const EpochTransitionCache,
    ideal_rewards: []const api_types.IdealAttestationReward,
    penalties: []const AttestationPenalty,
    validator_indices: []const u64,
) ![]api_types.TotalAttestationReward {
    var filter = try makeValidatorFilter(allocator, validator_indices);
    defer filter.deinit();

    var total_rewards = std.ArrayListUnmanaged(api_types.TotalAttestationReward).empty;
    errdefer total_rewards.deinit(allocator);

    const fork = state.state.forkSeq();
    const inactivity_penalty_multiplier: u64 = if (fork == .altair)
        INACTIVITY_PENALTY_QUOTIENT_ALTAIR
    else
        INACTIVITY_PENALTY_QUOTIENT_BELLATRIX;
    const penalty_denominator = state.config.chain.INACTIVITY_SCORE_BIAS * inactivity_penalty_multiplier;

    var inactivity_scores = try state.state.inactivityScores();
    const flags = transition_cache.flags;
    const effective_balance_increments = state.epoch_cache.getEffectiveBalanceIncrements().items;

    for (flags, 0..) |flag, i| {
        if (filter.count() > 0 and !filter.contains(@intCast(i))) continue;
        if (!hasMarkers(flag, FLAG_ELIGIBLE_ATTESTER)) continue;

        const effective_balance_increment = effective_balance_increments[i];
        var reward = api_types.TotalAttestationReward{
            .validator_index = @intCast(i),
            .head = 0,
            .target = 0,
            .source = 0,
            .inclusion_delay = 0,
            .inactivity = 0,
        };

        if (hasMarkers(flag, FLAG_PREV_SOURCE_ATTESTER_UNSLASHED)) {
            reward.source = try u64ToI64(ideal_rewards[effective_balance_increment].source);
        } else {
            reward.source = -try u64ToI64(penalties[effective_balance_increment].source);
        }

        if (hasMarkers(flag, FLAG_PREV_TARGET_ATTESTER_UNSLASHED)) {
            reward.target = try u64ToI64(ideal_rewards[effective_balance_increment].target);
        } else {
            reward.target = -try u64ToI64(penalties[effective_balance_increment].target);
            const inactivity_penalty_numerator = @as(u128, effective_balance_increment) * EFFECTIVE_BALANCE_INCREMENT * (try inactivity_scores.get(i));
            reward.inactivity = -try u64ToI64(@intCast(@divFloor(inactivity_penalty_numerator, penalty_denominator)));
        }

        if (hasMarkers(flag, FLAG_PREV_HEAD_ATTESTER_UNSLASHED)) {
            reward.head = try u64ToI64(ideal_rewards[effective_balance_increment].head);
        }

        try total_rewards.append(allocator, reward);
    }

    return total_rewards.toOwnedSlice(allocator);
}

fn makeValidatorFilter(
    allocator: std.mem.Allocator,
    validator_indices: []const u64,
) !std.AutoHashMap(u64, void) {
    var filter = std.AutoHashMap(u64, void).init(allocator);
    errdefer filter.deinit();
    for (validator_indices) |validator_index| {
        try filter.put(validator_index, {});
    }
    return filter;
}

fn roundedDiv(numerator: u128, denominator: u128) u64 {
    if (denominator == 0) return 0;
    return @intCast(@divFloor(numerator + denominator / 2, denominator));
}

fn u64ToI64(value: u64) !i64 {
    return std.math.cast(i64, value) orelse error.InternalError;
}

fn readSignedBlockSlotFromSsz(block_bytes: []const u8) ?u64 {
    if (block_bytes.len < 108) return null;
    return std.mem.readInt(u64, block_bytes[100..108], .little);
}
