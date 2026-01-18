const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const BeaconStateAllForks = @import("../types/beacon_state.zig").BeaconStateAllForks;
const ssz = @import("ssz");
const types = @import("consensus_types");
const preset = @import("preset").preset;
const ForkSeq = @import("config").ForkSeq;
const computeEpochAtSlot = @import("../epoch.zig").computeEpochAtSlot;
const isValidIndexedAttestation = @import("./is_valid_indexed_attestation.zig").isValidIndexedAttestation;
const Slot = types.primitive.Slot.Type;
const Checkpoint = types.phase0.Checkpoint.Type;
const Phase0Attestation = types.phase0.Attestation.Type;
const ElectraAttestation = types.electra.Attestation.Type;
const PendingAttestation = types.phase0.PendingAttestation.Type;

pub fn processAttestationPhase0(allocator: Allocator, cached_state: *CachedBeaconStateAllForks, attestation: *const Phase0Attestation, verify_signature: bool) !void {
    const state = cached_state.state;
    const epoch_cache = cached_state.getEpochCache();
    const slot = state.slot();
    const data = attestation.data;

    try validateAttestation(types.phase0.Attestation.Type, cached_state, attestation);

    // should store a clone of aggregation_bits on Phase0 BeaconState to avoid double free error
    var cloned_aggregation_bits: ssz.BitListType(preset.MAX_VALIDATORS_PER_COMMITTEE).Type = undefined;
    try ssz.BitListType(preset.MAX_VALIDATORS_PER_COMMITTEE).clone(allocator, &attestation.aggregation_bits, &cloned_aggregation_bits);
    var appended: bool = false;
    errdefer {
        if (!appended) {
            cloned_aggregation_bits.deinit(allocator);
        }
    }

    const pending_attestation = PendingAttestation{
        .data = data,
        .aggregation_bits = cloned_aggregation_bits,
        .inclusion_delay = slot - data.slot,
        .proposer_index = try epoch_cache.getBeaconProposer(slot),
    };

    if (data.target.epoch == epoch_cache.epoch) {
        if (!types.phase0.Checkpoint.equals(&data.source, state.currentJustifiedCheckpoint())) {
            return error.InvalidAttestationSourceNotEqualToCurrentJustifiedCheckpoint;
        }
        if (state.currentEpochPendingAttestations().append(allocator, pending_attestation)) |_| {
            appended = true;
        } else |err| return err;
    } else {
        if (!types.phase0.Checkpoint.equals(&data.source, state.previousJustifiedCheckpoint())) {
            return error.InvalidAttestationSourceNotEqualToPreviousJustifiedCheckpoint;
        }
        if (state.previousEpochPendingAttestations().append(allocator, pending_attestation)) |_| {
            appended = true;
        } else |err| return err;
    }

    var indexed_attestation: types.phase0.IndexedAttestation.Type = undefined;
    try epoch_cache.computeIndexedAttestationPhase0(attestation, &indexed_attestation);
    defer types.phase0.IndexedAttestation.deinit(allocator, &indexed_attestation);

    if (!try isValidIndexedAttestation(types.phase0.IndexedAttestation.Type, cached_state, &indexed_attestation, verify_signature)) {
        return error.InvalidAttestationInvalidIndexedAttestation;
    }
}

/// AT could be either Phase0Attestation or ElectraAttestation
pub fn validateAttestation(comptime AT: type, cached_state: *const CachedBeaconStateAllForks, attestation: *const AT) !void {
    const epoch_cache = cached_state.getEpochCache();
    const state = cached_state.state;
    const state_slot = state.slot();
    const data = attestation.data;
    const computed_epoch = computeEpochAtSlot(data.slot);
    const committee_count = try epoch_cache.getCommitteeCountPerSlot(computed_epoch);
    if (data.target.epoch != epoch_cache.previous_shuffling.get().epoch and data.target.epoch != epoch_cache.epoch) {
        // TODO: print to stderr?
        return error.InvalidAttestationTargetEpochNotInPreviousOrCurrentEpoch;
    }

    if (data.target.epoch != computed_epoch) {
        return error.InvalidAttestationTargetEpochDoesNotMatchComputedEpoch;
    }

    // post deneb, the attestations are valid till end of next epoch
    if (!(data.slot + preset.MIN_ATTESTATION_INCLUSION_DELAY <= state_slot and isTimelyTarget(state, state_slot - data.slot))) {
        return error.InvalidAttestationSlotNotWithInInclusionWindow;
    }

    // same to fork >= ForkSeq.electra but more type safe
    if (AT == ElectraAttestation) {
        if (data.index != 0) {
            return error.InvalidAttestationNonZeroDataIndex;
        }
        var committee_indices_buffer: [preset.MAX_COMMITTEES_PER_SLOT]usize = undefined;
        const committee_indices_len = try attestation.committee_bits.getTrueBitIndexes(committee_indices_buffer[0..]);
        const committee_indices = committee_indices_buffer[0..committee_indices_len];
        if (committee_indices.len == 0) {
            return error.InvalidAttestationCommitteeBitsEmpty;
        }

        const last_committee_index = committee_indices[committee_indices.len - 1];

        if (last_committee_index >= committee_count) {
            return error.InvalidAttestationInvalidLstCommitteeIndex;
        }

        var aggregation_bits_buffer: [preset.MAX_VALIDATORS_PER_COMMITTEE * preset.MAX_COMMITTEES_PER_SLOT]bool = undefined;
        var aggregation_bits_slice = aggregation_bits_buffer[0..attestation.aggregation_bits.bit_len];
        try attestation.aggregation_bits.toBoolSlice(&aggregation_bits_slice);
        const aggregation_bits_array = aggregation_bits_slice;
        // instead of implementing/calling getBeaconCommittees(slot, committee_indices.items), we call getBeaconCommittee(slot, index)
        var committee_offset: usize = 0;
        for (committee_indices) |committee_index| {
            const committee_validators = try epoch_cache.getBeaconCommittee(data.slot, committee_index);
            if (committee_offset + committee_validators.len > aggregation_bits_array.len) {
                return error.InvalidAttestationCommitteeAggregationBitsLengthTooShort;
            }
            const committee_aggregation_bits = aggregation_bits_array[committee_offset..(committee_offset + committee_validators.len)];

            // Assert aggregation bits in this committee have at least one true bit
            var all_false: bool = true;
            for (committee_aggregation_bits) |bit| {
                if (bit == true) {
                    all_false = false;
                    break;
                }
            }

            if (all_false) {
                return error.InvalidAttestationCommitteeAggregationBitsAllFalse;
            }
            committee_offset += committee_validators.len;
        }

        if (attestation.aggregation_bits.bit_len != committee_offset) {
            return error.InvalidAttestationCommitteeAggregationBitsLengthMismatch;
        }
    } else {
        // specific logic of phase to deneb
        if (!(data.index < committee_count)) {
            return error.InvalidAttestationInvalidCommitteeIndex;
        }

        const committee = try epoch_cache.getBeaconCommittee(data.slot, data.index);
        if (attestation.aggregation_bits.bit_len != committee.len) {
            return error.InvalidAttestationInvalidAggregationBitLen;
        }
    }
}

pub fn isTimelyTarget(state: *const BeaconStateAllForks, inclusion_distance: Slot) bool {
    // post deneb attestation is valid till end of next epoch for target
    if (state.isPostDeneb()) {
        return true;
    }

    return inclusion_distance <= preset.SLOTS_PER_EPOCH;
}
