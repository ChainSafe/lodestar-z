const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const ForkSeq = @import("config").ForkSeq;
const ForkTypes = @import("fork_types").ForkTypes;
const BeaconState = @import("fork_types").BeaconState;
const types = @import("consensus_types");
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const SlashingsCache = @import("../cache/slashings_cache.zig").SlashingsCache;
const buildSlashingsCacheIfNeeded = @import("../cache/slashings_cache.zig").buildFromStateIfNeeded;
const isSlashableAttestationData = @import("../utils/attestation.zig").isSlashableAttestationData;
const findAttesterSlashableIndices = @import("../utils/attestation.zig").findAttesterSlashableIndices;
const isValidIndexedAttestation = @import("./is_valid_indexed_attestation.zig").isValidIndexedAttestation;
const isSlashableValidator = @import("../utils/validator.zig").isSlashableValidator;
const slashValidator = @import("./slash_validator.zig").slashValidator;

/// AS is the AttesterSlashing type
/// - for phase0 it is `types.phase0.AttesterSlashing.Type`
/// - for electra it is `types.electra.AttesterSlashing.Type`
pub fn processAttesterSlashing(
    comptime fork: ForkSeq,
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *EpochCache,
    state: *BeaconState(fork),
    slashings_cache: *SlashingsCache,
    current_epoch: u64,
    attester_slashing: *const ForkTypes(fork).AttesterSlashing.Type,
    verify_signature: bool,
) !void {
    try buildSlashingsCacheIfNeeded(allocator, state, slashings_cache);
    try assertValidAttesterSlashing(
        fork,
        allocator,
        config,
        epoch_cache,
        try state.validatorsCount(),
        attester_slashing,
        verify_signature,
    );

    var intersecting_indices = try std.ArrayList(types.primitive.ValidatorIndex.Type).initCapacity(
        allocator,
        @min(
            attester_slashing.attestation_1.attesting_indices.items.len,
            attester_slashing.attestation_2.attesting_indices.items.len,
        ),
    );
    try findAttesterSlashableIndices(attester_slashing, &intersecting_indices);
    defer intersecting_indices.deinit();

    var slashed_any: bool = false;
    var validators = try state.validators();
    // Spec requires to sort indices beforehand but we validated sorted asc AttesterSlashing in the above functions
    for (intersecting_indices.items) |validator_index| {
        var validator: types.phase0.Validator.Type = undefined;
        try validators.getValue(undefined, validator_index, &validator);

        if (isSlashableValidator(&validator, current_epoch)) {
            try slashValidator(fork, config, epoch_cache, state, slashings_cache, validator_index, null);
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
pub fn assertValidAttesterSlashing(
    comptime fork: ForkSeq,
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    validators_count: usize,
    attester_slashing: *const ForkTypes(fork).AttesterSlashing.Type,
    verify_signatures: bool,
) !void {
    const attestations = &.{ attester_slashing.attestation_1, attester_slashing.attestation_2 };
    if (!isSlashableAttestationData(&attestations[0].data, &attestations[1].data)) {
        return error.InvalidAttesterSlashingNotSlashable;
    }

    if (!try isValidIndexedAttestation(
        fork,
        allocator,
        config,
        epoch_cache,
        validators_count,
        &attestations[0],
        verify_signatures,
    )) {
        return error.InvalidAttesterSlashingAttestationInvalid;
    }
    if (!try isValidIndexedAttestation(
        fork,
        allocator,
        config,
        epoch_cache,
        validators_count,
        &attestations[1],
        verify_signatures,
    )) {
        return error.InvalidAttesterSlashingAttestationInvalid;
    }
}
