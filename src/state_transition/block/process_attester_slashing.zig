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

const testing = std.testing;
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const Node = @import("persistent_merkle_tree").Node;
const preset = @import("preset").preset;
const AttestationData = types.phase0.AttestationData.Type;
const Checkpoint = types.phase0.Checkpoint.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;

const TestEnvironment = struct {
    allocator: Allocator,
    pool: Node.Pool,
    test_state: TestCachedBeaconState,
    slashings_cache: SlashingsCache,

    fn init(self: *TestEnvironment, allocator: Allocator, num_validators: u32) !void {
        const pool_size = num_validators * 5;

        self.allocator = allocator;
        self.pool = try Node.Pool.init(allocator, pool_size);
        errdefer self.pool.deinit();
        self.test_state = try TestCachedBeaconState.init(allocator, &self.pool, num_validators);
        errdefer self.test_state.deinit();
        self.slashings_cache = try SlashingsCache.initEmpty(allocator);
        errdefer self.slashings_cache.deinit();
        {
            var lbh = try self.test_state.cached_state.state.castToFork(.electra).latestBlockHeader();
            const slot = try lbh.get("slot");
            self.slashings_cache.updateLatestBlockSlot(slot);
        }
    }

    fn deinit(self: *TestEnvironment) void {
        self.slashings_cache.deinit();
        self.test_state.deinit();
        self.pool.deinit();
    }
};

/// Helper to construct a double-vote attester slashing.
/// attestation_1 and attestation_2 have the same target epoch but different roots.
fn makeDoubleVoteSlashing(
    allocator: Allocator,
    indices: []const ValidatorIndex,
) !types.phase0.AttesterSlashing.Type {
    var idx_list_1 = try std.ArrayListUnmanaged(ValidatorIndex).initCapacity(allocator, indices.len);
    var idx_list_2 = try std.ArrayListUnmanaged(ValidatorIndex).initCapacity(allocator, indices.len);
    for (indices) |idx| {
        idx_list_1.appendAssumeCapacity(idx);
        idx_list_2.appendAssumeCapacity(idx);
    }

    const data_1 = AttestationData{
        .slot = 10,
        .index = 0,
        .beacon_block_root = [_]u8{0xaa} ** 32,
        .source = Checkpoint{ .epoch = 1, .root = [_]u8{0} ** 32 },
        .target = Checkpoint{ .epoch = 5, .root = [_]u8{0x11} ** 32 },
    };
    const data_2 = AttestationData{
        .slot = 10,
        .index = 0,
        .beacon_block_root = [_]u8{0xbb} ** 32,
        .source = Checkpoint{ .epoch = 1, .root = [_]u8{0} ** 32 },
        .target = Checkpoint{ .epoch = 5, .root = [_]u8{0x22} ** 32 },
    };

    return .{
        .attestation_1 = .{
            .attesting_indices = idx_list_1,
            .data = data_1,
            .signature = [_]u8{0} ** 96,
        },
        .attestation_2 = .{
            .attesting_indices = idx_list_2,
            .data = data_2,
            .signature = [_]u8{0} ** 96,
        },
    };
}

fn freeSlashing(allocator: Allocator, slashing: *types.phase0.AttesterSlashing.Type) void {
    slashing.attestation_1.attesting_indices.deinit(allocator);
    slashing.attestation_2.attesting_indices.deinit(allocator);
}

test "assertValidAttesterSlashing - double vote sanity" {
    const allocator = testing.allocator;
    var env: TestEnvironment = undefined;
    try env.init(allocator, 256);
    defer env.deinit();

    const indices = &[_]ValidatorIndex{ 1, 2, 3 };
    var slashing = try makeDoubleVoteSlashing(allocator, indices);
    defer freeSlashing(allocator, &slashing);

    // Should succeed with signature verification disabled
    try assertValidAttesterSlashing(
        .electra,
        allocator,
        env.test_state.cached_state.config,
        env.test_state.cached_state.epoch_cache,
        try env.test_state.cached_state.state.castToFork(.electra).validatorsCount(),
        &slashing,
        false, // skip signature verification
    );
}

test "assertValidAttesterSlashing - not slashable (same data)" {
    const allocator = testing.allocator;
    var env: TestEnvironment = undefined;
    try env.init(allocator, 256);
    defer env.deinit();

    const indices = &[_]ValidatorIndex{ 1, 2, 3 };
    var slashing = try makeDoubleVoteSlashing(allocator, indices);
    defer freeSlashing(allocator, &slashing);

    // Make both attestations have identical data — not slashable
    slashing.attestation_2.data = slashing.attestation_1.data;

    try testing.expectError(
        error.InvalidAttesterSlashingNotSlashable,
        assertValidAttesterSlashing(
            .electra,
            allocator,
            env.test_state.cached_state.config,
            env.test_state.cached_state.epoch_cache,
            try env.test_state.cached_state.state.castToFork(.electra).validatorsCount(),
            &slashing,
            false,
        ),
    );
}

test "assertValidAttesterSlashing - empty attesting indices" {
    const allocator = testing.allocator;
    var env: TestEnvironment = undefined;
    try env.init(allocator, 256);
    defer env.deinit();

    var slashing = try makeDoubleVoteSlashing(allocator, &[_]ValidatorIndex{});
    defer freeSlashing(allocator, &slashing);

    // Empty indices should fail validation (isValidIndexedAttestation requires non-empty)
    try testing.expectError(
        error.InvalidAttesterSlashingAttestationInvalid,
        assertValidAttesterSlashing(
            .electra,
            allocator,
            env.test_state.cached_state.config,
            env.test_state.cached_state.epoch_cache,
            try env.test_state.cached_state.state.castToFork(.electra).validatorsCount(),
            &slashing,
            false,
        ),
    );
}

test "assertValidAttesterSlashing - unsorted indices" {
    const allocator = testing.allocator;
    var env: TestEnvironment = undefined;
    try env.init(allocator, 256);
    defer env.deinit();

    // Indices must be sorted ascending
    const unsorted_indices = &[_]ValidatorIndex{ 3, 1, 2 };
    var slashing = try makeDoubleVoteSlashing(allocator, unsorted_indices);
    defer freeSlashing(allocator, &slashing);

    try testing.expectError(
        error.InvalidAttesterSlashingAttestationInvalid,
        assertValidAttesterSlashing(
            .electra,
            allocator,
            env.test_state.cached_state.config,
            env.test_state.cached_state.epoch_cache,
            try env.test_state.cached_state.state.castToFork(.electra).validatorsCount(),
            &slashing,
            false,
        ),
    );
}

test "processAttesterSlashing - slashes intersecting validators" {
    const allocator = testing.allocator;
    var env: TestEnvironment = undefined;
    try env.init(allocator, 256);
    defer env.deinit();

    const state = env.test_state.cached_state.state.castToFork(.electra);
    const epoch_cache = env.test_state.cached_state.epoch_cache;
    const current_epoch = epoch_cache.epoch;

    // Pick a validator that's active and not already slashed
    const target_index: ValidatorIndex = 42;
    const indices = &[_]ValidatorIndex{target_index};
    var slashing = try makeDoubleVoteSlashing(allocator, indices);
    defer freeSlashing(allocator, &slashing);

    // Read balance before slashing
    var balances = try state.balances();
    const balance_before = try balances.get(target_index);

    try processAttesterSlashing(
        .electra,
        allocator,
        env.test_state.cached_state.config,
        epoch_cache,
        state,
        &env.slashings_cache,
        current_epoch,
        &slashing,
        false,
    );

    // Verify the validator was actually slashed
    var validators = try state.validators();
    var validator: types.phase0.Validator.Type = undefined;
    try validators.getValue(undefined, target_index, &validator);
    try testing.expect(validator.slashed);

    // Balance should have decreased (slashing penalty)
    const balance_after = try balances.get(target_index);
    try testing.expect(balance_after < balance_before);
}

test "processAttesterSlashing - already slashed validator returns error" {
    const allocator = testing.allocator;
    var env: TestEnvironment = undefined;
    try env.init(allocator, 256);
    defer env.deinit();

    const state = env.test_state.cached_state.state.castToFork(.electra);
    const epoch_cache = env.test_state.cached_state.epoch_cache;
    const current_epoch = epoch_cache.epoch;

    const target_index: ValidatorIndex = 42;
    const indices = &[_]ValidatorIndex{target_index};

    // First slashing should succeed
    var slashing1 = try makeDoubleVoteSlashing(allocator, indices);
    defer freeSlashing(allocator, &slashing1);

    try processAttesterSlashing(
        .electra,
        allocator,
        env.test_state.cached_state.config,
        epoch_cache,
        state,
        &env.slashings_cache,
        current_epoch,
        &slashing1,
        false,
    );

    // Second slashing of same validator — should fail (already slashed, not slashable)
    var slashing2 = try makeDoubleVoteSlashing(allocator, indices);
    defer freeSlashing(allocator, &slashing2);
    // Use different block roots to avoid being identical
    slashing2.attestation_1.data.beacon_block_root = [_]u8{0xcc} ** 32;
    slashing2.attestation_2.data.beacon_block_root = [_]u8{0xdd} ** 32;

    try testing.expectError(
        error.InvalidAttesterSlashingNoSlashableValidators,
        processAttesterSlashing(
            .electra,
            allocator,
            env.test_state.cached_state.config,
            epoch_cache,
            state,
            &env.slashings_cache,
            current_epoch,
            &slashing2,
            false,
        ),
    );
}
