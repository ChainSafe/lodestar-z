const std = @import("std");
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const ForkSeq = @import("config").ForkSeq;
const types = @import("consensus_types");
const AttesterSlashing = types.phase0.AttesterSlashing.Type;
const isSlashableAttestationData = @import("../utils/attestation.zig").isSlashableAttestationData;
const getAttesterSlashableIndices = @import("../utils/attestation.zig").getAttesterSlashableIndices;
const isValidIndexedAttestation = @import("./is_valid_indexed_attestation.zig").isValidIndexedAttestation;
const isSlashableValidator = @import("../utils/validator.zig").isSlashableValidator;
const slashValidator = @import("./slash_validator.zig").slashValidator;

/// AS is the AttesterSlashing type
/// - for phase0 it is `types.phase0.AttesterSlashing.Type`
/// - for electra it is `types.electra.AttesterSlashing.Type`
pub fn processAttesterSlashing(comptime AS: type, cached_state: *CachedBeaconState, attester_slashing: *const AS, verify_signature: bool) !void {
    var state = cached_state.state;
    const epoch = cached_state.getEpochCache().epoch;
    try assertValidAttesterSlashing(AS, cached_state, attester_slashing, verify_signature);

    const intersecting_indices = try getAttesterSlashableIndices(cached_state.allocator, attester_slashing);
    defer intersecting_indices.deinit();

    var slashed_any: bool = false;
    var validators = try state.validators();
    // Spec requires to sort indices beforehand but we validated sorted asc AttesterSlashing in the above functions
    for (intersecting_indices.items) |validator_index| {
        var validator: types.phase0.Validator.Type = undefined;
        try validators.getValue(undefined, validator_index, &validator);

        if (isSlashableValidator(&validator, epoch)) {
            try slashValidator(cached_state, validator_index, null);
            slashed_any = true;
        }
    }

    if (!slashed_any) {
        return error.InvalidAttesterSlashingNoSlashableValidators;
    }
}

/// AS is the AttesterSlashing type
/// - for phase0 it is `types.phase0.AttesterSlashing.Type`
/// - for electra it is `types.electra.AttesterSlashing.Type`
pub fn assertValidAttesterSlashing(comptime AS: type, cached_state: *const CachedBeaconState, attester_slashing: *const AS, verify_signatures: bool) !void {
    const attestations = &.{ attester_slashing.attestation_1, attester_slashing.attestation_2 };
    if (!isSlashableAttestationData(&attestations[0].data, &attestations[1].data)) {
        return error.InvalidAttesterSlashingNotSlashable;
    }

    inline for (@typeInfo(AS).@"struct".fields, 0..2) |f, i| {
        if (!try isValidIndexedAttestation(f.type, cached_state, &attestations[i], verify_signatures)) {
            return error.InvalidAttesterSlashingAttestationInvalid;
        }
    }
}
