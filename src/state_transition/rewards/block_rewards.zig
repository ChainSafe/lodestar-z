const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;
const ForkSeq = @import("config").ForkSeq;
const BeaconConfig = @import("config").BeaconConfig;
const fork_types = @import("fork_types");
const BeaconState = fork_types.BeaconState;
const BeaconBlock = fork_types.BeaconBlock;
const BlockType = fork_types.BlockType;
const AnyBeaconBlock = fork_types.AnyBeaconBlock;

const state_cache = @import("../cache/state_cache.zig");
const CachedBeaconState = state_cache.CachedBeaconState;
const ProposerRewards = state_cache.ProposerRewards;
const processAttestationsAltair = @import("../block/process_attestation_altair.zig").processAttestationsAltair;
const findAttesterSlashableIndices = @import("../utils/attestation.zig").findAttesterSlashableIndices;

const ValidatorIndex = types.primitive.ValidatorIndex.Type;

pub const BlockRewards = struct {
    proposer_index: ValidatorIndex,
    total: u64,
    attestations: u64,
    sync_aggregate: u64,
    proposer_slashings: u64,
    attester_slashings: u64,
};

pub const Error = error{BlockAttestationRewardUnsupportedFork};

fn whistleblowerRewardQuotient(comptime fork: ForkSeq) u64 {
    return if (comptime fork.gte(.electra))
        preset.WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA
    else
        preset.WHISTLEBLOWER_REWARD_QUOTIENT;
}

fn effectiveBalance(
    comptime fork: ForkSeq,
    allocator: Allocator,
    state: *BeaconState(fork),
    index: ValidatorIndex,
) !u64 {
    var validators = try state.validators();
    var validator: types.phase0.Validator.Type = undefined;
    try validators.getValue(allocator, index, &validator);
    return validator.effective_balance;
}

pub fn computeBlockRewards(
    comptime fork: ForkSeq,
    comptime block_type: BlockType,
    allocator: Allocator,
    io: std.Io,
    pre_state: *CachedBeaconState,
    block: *const BeaconBlock(block_type, fork),
    cached: ?ProposerRewards,
) !BlockRewards {
    const body = block.body();
    const fork_state = pre_state.state.castToFork(fork);
    const quotient = comptime whistleblowerRewardQuotient(fork);

    const cached_rewards = cached orelse ProposerRewards{};

    const attestations = if (cached_rewards.attestations != 0)
        cached_rewards.attestations
    else
        try computeAttestationsReward(fork, block_type, allocator, io, pre_state, body);

    const sync_aggregate = if (cached_rewards.sync_aggregate != 0)
        cached_rewards.sync_aggregate
    else
        try computeSyncAggregateReward(fork, block_type, pre_state, body);

    var proposer_slashings: u64 = 0;
    for (body.inner.proposer_slashings.items) |*slashing| {
        const offender = slashing.signed_header_1.message.proposer_index;
        proposer_slashings += @divFloor(try effectiveBalance(fork, allocator, fork_state, offender), quotient);
    }

    var attester_slashings: u64 = 0;
    for (body.inner.attester_slashings.items) |*slashing| {
        var indices: std.ArrayList(ValidatorIndex) = .empty;
        defer indices.deinit(allocator);
        try findAttesterSlashableIndices(allocator, slashing, &indices);
        for (indices.items) |offender| {
            attester_slashings += @divFloor(try effectiveBalance(fork, allocator, fork_state, offender), quotient);
        }
    }

    return .{
        .proposer_index = block.inner.proposer_index,
        .total = attestations + sync_aggregate + proposer_slashings + attester_slashings,
        .attestations = attestations,
        .sync_aggregate = sync_aggregate,
        .proposer_slashings = proposer_slashings,
        .attester_slashings = attester_slashings,
    };
}

fn computeAttestationsReward(
    comptime fork: ForkSeq,
    comptime block_type: BlockType,
    allocator: Allocator,
    io: std.Io,
    pre_state: *CachedBeaconState,
    body: *const fork_types.BeaconBlockBody(block_type, fork),
) !u64 {
    if (comptime !fork.gte(.altair)) return Error.BlockAttestationRewardUnsupportedFork;

    var scratch = try pre_state.clone(allocator, .{ .transfer_cache = false });
    defer {
        scratch.deinit();
        allocator.destroy(scratch);
    }

    try processAttestationsAltair(
        fork,
        allocator,
        io,
        scratch.config,
        scratch.epoch_cache,
        scratch.state.castToFork(fork),
        &scratch.proposer_rewards,
        &scratch.slashings_cache,
        body.inner.attestations.items,
        false,
    );

    return scratch.proposer_rewards.attestations;
}

fn computeSyncAggregateReward(
    comptime fork: ForkSeq,
    comptime block_type: BlockType,
    pre_state: *CachedBeaconState,
    body: *const fork_types.BeaconBlockBody(block_type, fork),
) !u64 {
    if (comptime !fork.gte(.altair)) return 0;

    const bits = body.syncAggregate().sync_committee_bits;
    var participants: u64 = 0;
    for (0..preset.SYNC_COMMITTEE_SIZE) |i| {
        if (try bits.get(i)) participants += 1;
    }
    return participants * pre_state.epoch_cache.sync_proposer_reward;
}

fn forkOf(comptime tag: @typeInfo(AnyBeaconBlock).@"union".tag_type.?) ForkSeq {
    return switch (tag) {
        .phase0 => .phase0,
        .altair => .altair,
        .full_bellatrix, .blinded_bellatrix => .bellatrix,
        .full_capella, .blinded_capella => .capella,
        .full_deneb, .blinded_deneb => .deneb,
        .full_electra, .blinded_electra => .electra,
        .full_fulu, .blinded_fulu => .fulu,
        .full_gloas => .gloas,
    };
}

fn blockTypeOf(comptime tag: @typeInfo(AnyBeaconBlock).@"union".tag_type.?) BlockType {
    return switch (tag) {
        .blinded_bellatrix, .blinded_capella, .blinded_deneb, .blinded_electra, .blinded_fulu => .blinded,
        else => .full,
    };
}

pub fn computeBlockRewardsAny(
    allocator: Allocator,
    io: std.Io,
    pre_state: *CachedBeaconState,
    block: AnyBeaconBlock,
    cached: ?ProposerRewards,
) !BlockRewards {
    return switch (block) {
        inline else => |inner, tag| blk: {
            const fork = comptime forkOf(tag);
            const block_type = comptime blockTypeOf(tag);
            const wrapped = fork_types.BeaconBlock(block_type, fork){ .inner = inner.* };
            break :blk try computeBlockRewards(fork, block_type, allocator, io, pre_state, &wrapped, cached);
        },
    };
}

test {
    _ = @import("block_rewards_test.zig");
}
