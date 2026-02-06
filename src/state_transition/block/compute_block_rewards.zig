const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const AnyBeaconBlock = @import("fork_types").AnyBeaconBlock;
const ForkSeq = @import("config").ForkSeq;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const getAttesterSlashableIndices = @import("../utils/attestation.zig").getAttesterSlashableIndices;
const processAttestationsAltair = @import("./process_attestation_altair.zig").processAttestationsAltair;

const ValidatorIndex = types.primitive.ValidatorIndex.Type;

pub const BlockRewards = struct {
    proposer_index: ValidatorIndex,
    total: u64,
    attestations: u64,
    sync_aggregate: u64,
    proposer_slashings: u64,
    attester_slashings: u64,
};

/// Calculate total proposer block rewards given block and the beacon state of the same slot before the block is applied (preState).
/// Standard (Non MEV) rewards for proposing a block consists of:
///  1) Including attestations from (beacon) committee
///  2) Including attestations from sync committee
///  3) Reporting slashable behaviours from proposer and attester
pub fn computeBlockRewards(allocator: Allocator, cached_state: *CachedBeaconState, block: AnyBeaconBlock) !BlockRewards {
    const fork_seq = cached_state.state.forkSeq();

    // Use the proposer rewards already tracked in cached_state
    const proposer_rewards = cached_state.getProposerRewards();

    var attestations_reward = proposer_rewards.attestations;
    if (attestations_reward == 0) {
        if (fork_seq == .phase0) {
            return error.UnsupportedFork;
        }
        //note
        attestations_reward = try computeBlockAttestationRewardAltair(allocator, cached_state, block);
    }

    var sync_aggregate_reward = proposer_rewards.sync_aggregate;
    if (sync_aggregate_reward == 0) {
        sync_aggregate_reward = try computeSyncAggregateReward(cached_state, block);
    }

    const proposer_slashings_reward = try computeBlockProposerSlashingsReward(cached_state, block);
    const attester_slashings_reward = try computeBlockAttesterSlashingsReward(allocator, cached_state, block);

    const total = attestations_reward + sync_aggregate_reward + proposer_slashings_reward + attester_slashings_reward;

    return BlockRewards{
        .proposer_index = block.proposerIndex(),
        .total = total,
        .attestations = attestations_reward,
        .sync_aggregate = sync_aggregate_reward,
        .proposer_slashings = proposer_slashings_reward,
        .attester_slashings = attester_slashings_reward,
    };
}

/// Calculate rewards received by block proposer for including attestations since Altair.
/// Reuses processAttestationsAltair(). Has dependency on RewardCache.
fn computeBlockAttestationRewardAltair(allocator: Allocator, cached_state: *CachedBeaconState, block: AnyBeaconBlock) !u64 {
    const fork_seq = cached_state.state.forkSeq();
    const config = cached_state.config;
    const epoch_cache = cached_state.getEpochCache();
    const attestations = block.beaconBlockBody().attestations();

    switch (fork_seq) {
        inline .altair, .bellatrix, .capella, .deneb => |fork| {
            const state = try cached_state.state.tryCastToFork(fork);
            const atts = attestations.phase0;
            try processAttestationsAltair(fork, allocator, config, epoch_cache, state, &cached_state.slashings_cache, atts.items, false);
        },
        else => return error.UnsupportedFork,
    }

    return cached_state.proposer_rewards.attestations;
}

/// Calculate rewards received by block proposer for including sync aggregate.
fn computeSyncAggregateReward(cached_state: *CachedBeaconState, block: AnyBeaconBlock) !u64 {
    const fork_seq = cached_state.state.forkSeq();
    if (fork_seq == .phase0) {
        return 0; // phase0 block does not have syncAggregate
    }

    const epoch_cache = cached_state.getEpochCache();
    const sync_aggregate = try block.beaconBlockBody().syncAggregate();
    const sync_proposer_reward = epoch_cache.sync_proposer_reward;

    var participant_count: u64 = 0;
    for (0..preset.SYNC_COMMITTEE_SIZE) |i| {
        if (sync_aggregate.sync_committee_bits.get(i) catch false) {
            participant_count += 1;
        }
    }

    return participant_count * sync_proposer_reward;
}

/// Calculate rewards received by block proposer for including proposer slashings.
fn computeBlockProposerSlashingsReward(cached_state: *CachedBeaconState, block: AnyBeaconBlock) !u64 {
    const fork_seq = cached_state.state.forkSeq();
    const state = cached_state.state;
    var validators = try state.validators();

    var proposer_slashing_reward: u64 = 0;

    for (block.beaconBlockBody().proposerSlashings()) |proposer_slashing| {
        const offending_proposer_index = proposer_slashing.signed_header_1.message.proposer_index;
        var validator = try validators.get(offending_proposer_index);
        const effective_balance = try validator.get("effective_balance");

        const whistleblower_reward_quotient: u64 = if (fork_seq.gte(.electra))
            preset.WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA
        else
            preset.WHISTLEBLOWER_REWARD_QUOTIENT;

        proposer_slashing_reward += @divFloor(effective_balance, whistleblower_reward_quotient);
    }

    return proposer_slashing_reward;
}

/// Calculate rewards received by block proposer for including attester slashings.
fn computeBlockAttesterSlashingsReward(allocator: Allocator, cached_state: *CachedBeaconState, block: AnyBeaconBlock) !u64 {
    const fork_seq = cached_state.state.forkSeq();
    const state = cached_state.state;
    var validators = try state.validators();

    var attester_slashing_reward: u64 = 0;

    const whistleblower_reward_quotient: u64 = if (fork_seq.gte(.electra))
        preset.WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA
    else
        preset.WHISTLEBLOWER_REWARD_QUOTIENT;

    const attester_slashings = block.beaconBlockBody().attesterSlashings();
    switch (attester_slashings) {
        inline else => |slashings| {
            for (slashings.items) |*slashing| {
                const slashable_indices = try getAttesterSlashableIndices(allocator, slashing);
                defer slashable_indices.deinit();

                for (slashable_indices.items) |offending_attester_index| {
                    var validator = try validators.get(offending_attester_index);
                    const offending_attester_balance = try validator.get("effective_balance");

                    attester_slashing_reward += @divFloor(offending_attester_balance, whistleblower_reward_quotient);
                }
            }
        },
    }

    return attester_slashing_reward;
}
