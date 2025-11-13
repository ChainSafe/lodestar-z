const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const BeaconStateAllForks = @import("../types/beacon_state.zig").BeaconStateAllForks;
const types = @import("consensus_types");
const Epoch = types.primitive.Epoch.Type;
const preset = @import("preset").preset;
const ForkSeq = @import("config").ForkSeq;
const c = @import("constants");
const RootCache = @import("../utils/root_cache.zig").RootCache;
const validateAttestation = @import("./process_attestation_phase0.zig").validateAttestation;
const getAttestationWithIndicesSignatureSet = @import("../signature_sets/indexed_attestation.zig").getAttestationWithIndicesSignatureSet;
const verifyAggregatedSignatureSet = @import("../utils/signature_sets.zig").verifyAggregatedSignatureSet;
const Phase0Attestation = types.phase0.Attestation.Type;
const ElectraAttestation = types.electra.Attestation.Type;
const Checkpoint = types.phase0.Checkpoint.Type;
const isTimelyTarget = @import("./process_attestation_phase0.zig").isTimelyTarget;
const increaseBalance = @import("../utils/balance.zig").increaseBalance;

const PROPOSER_REWARD_DOMINATOR = ((c.WEIGHT_DENOMINATOR - c.PROPOSER_WEIGHT) * c.WEIGHT_DENOMINATOR) / c.PROPOSER_WEIGHT;

/// Same to https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.5/specs/altair/beacon-chain.md#has_flag
const TIMELY_SOURCE = 1 << c.TIMELY_SOURCE_FLAG_INDEX;
const TIMELY_TARGET = 1 << c.TIMELY_TARGET_FLAG_INDEX;
const TIMELY_HEAD = 1 << c.TIMELY_HEAD_FLAG_INDEX;
const SLOTS_PER_EPOCH_SQRT = std.math.sqrt(preset.SLOTS_PER_EPOCH);

/// AT = AttestationType
/// for phase0 it's `types.phase0.Attestation.Type`
/// for electra it's `types.electra.Attestation.Type`
pub fn processAttestationsAltair(allocator: Allocator, cached_state: *const CachedBeaconStateAllForks, comptime AT: type, attestations: []AT, verify_signature: bool) !void {
    const state = cached_state.state;
    const epoch_cache = cached_state.getEpochCache();
    const effective_balance_increments = epoch_cache.effective_balance_increment.get().items;
    const state_slot = state.slot();
    const current_epoch = epoch_cache.epoch;

    const root_cache = try RootCache.init(allocator, cached_state);
    // TODO: should use arena allocator per block processing?
    defer root_cache.deinit();

    // Process all attestations first and then increase the balance of the proposer once
    // let newSeenAttesters = 0;
    // let newSeenAttestersEffectiveBalance = 0;

    var proposer_reward: u64 = 0;
    for (attestations) |*attestation| {
        const data = attestation.data;
        try validateAttestation(cached_state, attestation);

        // Retrieve the validator indices from the attestation participation bitfield
        const attesting_indices = try if (AT == Phase0Attestation) epoch_cache.getAttestingIndicesPhase0(attestation) else epoch_cache.getAttestingIndicesElectra(attestation);
        defer attesting_indices.deinit();

        // this check is done last because its the most expensive (if signature verification is toggled on)
        // TODO: Why should we verify an indexed attestation that we just created? If it's just for the signature
        // we can verify only that and nothing else.
        if (verify_signature) {
            const sig_set = try getAttestationWithIndicesSignatureSet(allocator, cached_state, &attestation.data, attestation.signature, attesting_indices.items);
            defer allocator.free(sig_set.pubkeys);
            if (!try verifyAggregatedSignatureSet(&sig_set)) {
                return error.InvalidSignature;
            }
        }

        const in_current_epoch = data.target.epoch == current_epoch;
        var epoch_participation = if (in_current_epoch) state.currentEpochParticipations().items else state.previousEpochParticipations().items;
        const flags_attestation = try getAttestationParticipationStatus(state, data, state_slot - data.slot, current_epoch, root_cache);

        // For each participant, update their participation
        // In epoch processing, this participation info is used to calculate balance updates
        var total_balance_increments_with_weight: u64 = 0;
        const validators = state.validators().items;
        for (attesting_indices.items) |validator_index| {
            const flags = epoch_participation[validator_index];

            // For normal block, > 90% of attestations belong to current epoch
            // At epoch boundary, 100% of attestations belong to previous epoch
            // so we want to update the participation flag tree in batch

            // no setBitwiseOR implemented in zig ssz, so we do it manually here
            epoch_participation[validator_index] = flags_attestation | flags;

            // Returns flags that are NOT set before (~ bitwise NOT) AND are set after
            const flags_new_set = ~flags & flags_attestation;

            // Spec:
            // baseReward = state.validators[index].effectiveBalance / EFFECTIVE_BALANCE_INCREMENT * baseRewardPerIncrement;
            // proposerRewardNumerator += baseReward * totalWeight
            var total_weight: u64 = 0;
            if ((flags_new_set & TIMELY_SOURCE) == TIMELY_SOURCE) total_weight += c.TIMELY_SOURCE_WEIGHT;
            if ((flags_new_set & TIMELY_TARGET) == TIMELY_TARGET) total_weight += c.TIMELY_TARGET_WEIGHT;
            if ((flags_new_set & TIMELY_HEAD) == TIMELY_HEAD) total_weight += c.TIMELY_HEAD_WEIGHT;

            if (total_weight > 0) {
                total_balance_increments_with_weight += effective_balance_increments[validator_index] * total_weight;
            }

            // TODO: describe issue. Compute progressive target balances
            // When processing each attestation, increase the cummulative target balance. Only applies post-altair
            if ((flags_new_set & TIMELY_TARGET) == TIMELY_TARGET) {
                const validator = validators[validator_index];
                if (!validator.slashed) {
                    if (in_current_epoch) {
                        epoch_cache.current_target_unslashed_balance_increments += effective_balance_increments[validator_index];
                    } else {
                        epoch_cache.previous_target_unslashed_balance_increments += effective_balance_increments[validator_index];
                    }
                }
            }
        }
        // Do the discrete math inside the loop to ensure a deterministic result
        const total_increments = total_balance_increments_with_weight;
        const proposer_reward_numerator = total_increments * epoch_cache.base_reward_per_increment;
        proposer_reward += @divFloor(proposer_reward_numerator, PROPOSER_REWARD_DOMINATOR);
    }
    increaseBalance(state, try epoch_cache.getBeaconProposer(state_slot), proposer_reward);
}

pub fn getAttestationParticipationStatus(state: *const BeaconStateAllForks, data: types.phase0.AttestationData.Type, inclusion_delay: u64, current_epoch: Epoch, root_cache: *RootCache) !u8 {
    const justified_checkpoint: Checkpoint = if (data.target.epoch == current_epoch)
        root_cache.current_justified_checkpoint
    else
        root_cache.previous_justified_checkpoint;
    const is_matching_source = checkpointValueEquals(data.source, justified_checkpoint);
    if (!is_matching_source) return error.InvalidAttestationSource;

    const is_matching_target = std.mem.eql(u8, &data.target.root, &try root_cache.getBlockRoot(data.target.epoch));

    // a timely head is only be set if the target is _also_ matching
    const is_matching_head =
        is_matching_target and std.mem.eql(u8, &data.beacon_block_root, &try root_cache.getBlockRootAtSlot(data.slot));

    var flags: u8 = 0;
    if (is_matching_source and inclusion_delay <= SLOTS_PER_EPOCH_SQRT) flags |= TIMELY_SOURCE;
    if (is_matching_target and isTimelyTarget(state, inclusion_delay)) flags |= TIMELY_TARGET;
    if (is_matching_head and inclusion_delay == preset.MIN_ATTESTATION_INCLUSION_DELAY) flags |= TIMELY_HEAD;
    return flags;
}

pub fn checkpointValueEquals(cp1: Checkpoint, cp2: Checkpoint) bool {
    return cp1.epoch == cp2.epoch and std.mem.eql(u8, &cp1.root, &cp2.root);
}
