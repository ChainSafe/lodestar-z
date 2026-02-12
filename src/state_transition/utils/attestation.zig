const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const AttestationData = types.phase0.AttestationData.Type;
const AttesterSlashing = types.phase0.AttesterSlashing.Type;

const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const Slot = types.primitive.Slot.Type;

pub fn isSlashableAttestationData(data1: *const AttestationData, data2: *const AttestationData) bool {
    // Double vote
    if (!types.phase0.AttestationData.equals(data1, data2) and data1.target.epoch == data2.target.epoch) {
        return true;
    }
    // Surround vote
    if (data1.source.epoch < data2.source.epoch and data2.target.epoch < data1.target.epoch) {
        return true;
    }
    return false;
}

pub fn isValidAttestationSlot(attestation_slot: Slot, current_slot: Slot) bool {
    return attestation_slot + preset.MIN_ATTESTATION_INCLUSION_DELAY <= current_slot and
        current_slot <= attestation_slot + preset.SLOTS_PER_EPOCH;
}

/// Two-pointer sorted merge membership check for attesting indices to slash without auxiliary allocations.
///
/// Pre-requisite: isValidIndexedAttestation already checks for attesting indices to be sorted and unique.
/// Without that check, this would be incorrect.
pub fn findAttesterSlashableIndices(attester_slashing: *const AttesterSlashing, indices: *std.ArrayList(ValidatorIndex)) !void {
    const a = attester_slashing.attestation_1.attesting_indices.items;
    const b = attester_slashing.attestation_2.attesting_indices.items;
    var i: usize = 0;
    var j: usize = 0;
    while (i < a.len and j < b.len) {
        if (a[i] == b[j]) {
            try indices.append(a[i]);
            i += 1;
            j += 1;
        } else if (a[i] < b[j]) {
            i += 1;
        } else {
            j += 1;
        }
    }
    // we must reach the end of one of the indices
    std.debug.assert(i == a.len or j == b.len);
}
