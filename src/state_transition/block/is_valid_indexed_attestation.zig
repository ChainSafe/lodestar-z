const std = @import("std");
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const ForkSeq = @import("config").ForkSeq;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const verifySingleSignatureSet = @import("../utils/signature_sets.zig").verifySingleSignatureSet;
const verifyAggregatedSignatureSet = @import("../utils/signature_sets.zig").verifyAggregatedSignatureSet;
const getIndexedAttestationSignatureSet = @import("../signature_sets/indexed_attestation.zig").getIndexedAttestationSignatureSet;

pub fn isValidIndexedAttestation(
    comptime IA: type,
    cached_state: *const CachedBeaconState,
    indexed_attestation: *const IA,
    verify_signature: bool,
) !bool {
    if (!(try isValidIndexedAttestationIndices(cached_state, indexed_attestation.attesting_indices.items))) {
        return false;
    }

    if (verify_signature) {
        const signature_set = try getIndexedAttestationSignatureSet(IA, cached_state.allocator, cached_state, indexed_attestation);
        defer cached_state.allocator.free(signature_set.pubkeys);
        return try verifyAggregatedSignatureSet(&signature_set);
    } else {
        return true;
    }
}

pub fn isValidIndexedAttestationIndices(cached_state: *const CachedBeaconState, indices: []const ValidatorIndex) !bool {
    // verify max number of indices
    const fork_seq = cached_state.state.forkSeq();
    const max_indices: usize = if (fork_seq.gte(.electra))
        preset.MAX_VALIDATORS_PER_COMMITTEE * preset.MAX_COMMITTEES_PER_SLOT
    else
        preset.MAX_VALIDATORS_PER_COMMITTEE;

    if (!(indices.len > 0 and indices.len <= max_indices)) {
        return false;
    }

    // verify indices are sorted and unique.
    // Just check if they are monotonically increasing,
    // instead of creating a set and sorting it. Should be (O(n)) instead of O(n log(n))
    var prev: ValidatorIndex = 0;
    for (indices, 0..) |index, i| {
        if (i >= 1 and index <= prev) {
            return false;
        }
        prev = index;
    }

    // check if indices are out of bounds, by checking the highest index (since it is sorted)
    const validator_count = try cached_state.state.validatorsCount();
    if (indices.len > 0) {
        const last_index = indices[indices.len - 1];
        if (last_index >= validator_count) {
            return false;
        }
    }

    return true;
}
