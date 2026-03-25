const std = @import("std");
const BeaconConfig = @import("config").BeaconConfig;
const ForkSeq = @import("config").ForkSeq;
const ForkTypes = @import("fork_types").ForkTypes;
const BeaconState = @import("fork_types").BeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const SlashingsCache = @import("../cache/slashings_cache.zig").SlashingsCache;
const buildSlashingsCacheIfNeeded = @import("../cache/slashings_cache.zig").buildFromStateIfNeeded;
const types = @import("consensus_types");
const isSlashableValidator = @import("../utils/validator.zig").isSlashableValidator;
const getProposerSlashingSignatureSets = @import("../signature_sets/proposer_slashings.zig").getProposerSlashingSignatureSets;
const verifySignature = @import("../utils/signature_sets.zig").verifySingleSignatureSet;
const slashValidator = @import("./slash_validator.zig").slashValidator;

pub fn processProposerSlashing(
    comptime fork: ForkSeq,
    allocator: std.mem.Allocator,
    config: *const BeaconConfig,
    epoch_cache: *EpochCache,
    state: *BeaconState(fork),
    slashings_cache: *SlashingsCache,
    proposer_slashing: *const ForkTypes(fork).ProposerSlashing.Type,
    verify_signatures: bool,
) !void {
    try buildSlashingsCacheIfNeeded(allocator, state, slashings_cache);
    try assertValidProposerSlashing(fork, config, epoch_cache, state, proposer_slashing, verify_signatures);
    const proposer_index = proposer_slashing.signed_header_1.message.proposer_index;
    try slashValidator(fork, config, epoch_cache, state, slashings_cache, proposer_index, null);
}

pub fn assertValidProposerSlashing(
    comptime fork: ForkSeq,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *BeaconState(fork),
    proposer_slashing: *const ForkTypes(fork).ProposerSlashing.Type,
    verify_signature: bool,
) !void {
    const header_1 = proposer_slashing.signed_header_1.message;
    const header_2 = proposer_slashing.signed_header_2.message;

    // verify header slots match
    if (header_1.slot != header_2.slot) {
        return error.InvalidProposerSlashingSlotMismatch;
    }

    // verify header proposer indices match
    if (header_1.proposer_index != header_2.proposer_index) {
        return error.InvalidProposerSlashingProposerIndexMismatch;
    }

    var validators_view = try state.validators();
    const validators_len = try validators_view.length();
    if (header_1.proposer_index >= validators_len) {
        return error.InvalidProposerSlashingProposerIndexOutOfRange;
    }

    // verify headers are different
    if (types.phase0.BeaconBlockHeader.equals(&header_1, &header_2)) {
        return error.InvalidProposerSlashingHeadersEqual;
    }

    // verify the proposer is slashable
    var proposer_view = try validators_view.get(header_1.proposer_index);
    var proposer: types.phase0.Validator.Type = undefined;
    try proposer_view.toValue(undefined, &proposer);
    if (!isSlashableValidator(&proposer, epoch_cache.epoch)) {
        return error.InvalidProposerSlashingProposerNotSlashable;
    }

    // verify signatures
    if (verify_signature) {
        const signature_sets = try getProposerSlashingSignatureSets(
            config,
            epoch_cache,
            proposer_slashing,
        );
        if (!try verifySignature(&signature_sets[0]) or !try verifySignature(&signature_sets[1])) {
            return error.InvalidProposerSlashingSignature;
        }
    }
}

const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const Node = @import("persistent_merkle_tree").Node;
const ProposerSlashing = types.phase0.ProposerSlashing.Type;

fn makeValidProposerSlashing(proposer_index: u64, slot: u64) ProposerSlashing {
    var slashing = types.phase0.ProposerSlashing.default_value;
    slashing.signed_header_1.message.slot = slot;
    slashing.signed_header_1.message.proposer_index = proposer_index;
    slashing.signed_header_1.message.body_root = [_]u8{0xaa} ** 32;
    slashing.signed_header_2.message.slot = slot;
    slashing.signed_header_2.message.proposer_index = proposer_index;
    slashing.signed_header_2.message.body_root = [_]u8{0xbb} ** 32;
    return slashing;
}

test "assertValidProposerSlashing - valid proposer slashing" {
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    const slashing = makeValidProposerSlashing(0, 0);

    try assertValidProposerSlashing(
        .electra,
        test_state.config,
        test_state.cached_state.epoch_cache,
        test_state.cached_state.state.castToFork(.electra),
        &slashing,
        false,
    );
}

test "assertValidProposerSlashing - InvalidProposerSlashingSlotMismatch" {
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var slashing = makeValidProposerSlashing(0, 0);
    slashing.signed_header_2.message.slot = 1;

    try std.testing.expectError(
        error.InvalidProposerSlashingSlotMismatch,
        assertValidProposerSlashing(
            .electra,
            test_state.config,
            test_state.cached_state.epoch_cache,
            test_state.cached_state.state.castToFork(.electra),
            &slashing,
            false,
        ),
    );
}

test "assertValidProposerSlashing - InvalidProposerSlashingProposerIndexMismatch" {
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var slashing = makeValidProposerSlashing(0, 0);
    slashing.signed_header_2.message.proposer_index = 1;

    try std.testing.expectError(
        error.InvalidProposerSlashingProposerIndexMismatch,
        assertValidProposerSlashing(
            .electra,
            test_state.config,
            test_state.cached_state.epoch_cache,
            test_state.cached_state.state.castToFork(.electra),
            &slashing,
            false,
        ),
    );
}

test "assertValidProposerSlashing - InvalidProposerSlashingProposerIndexOutOfRange" {
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    const slashing = makeValidProposerSlashing(999, 0);

    try std.testing.expectError(
        error.InvalidProposerSlashingProposerIndexOutOfRange,
        assertValidProposerSlashing(
            .electra,
            test_state.config,
            test_state.cached_state.epoch_cache,
            test_state.cached_state.state.castToFork(.electra),
            &slashing,
            false,
        ),
    );
}

test "assertValidProposerSlashing - InvalidProposerSlashingHeadersEqual" {
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var slashing = makeValidProposerSlashing(0, 0);
    // Make headers identical
    slashing.signed_header_2.message.body_root = slashing.signed_header_1.message.body_root;

    try std.testing.expectError(
        error.InvalidProposerSlashingHeadersEqual,
        assertValidProposerSlashing(
            .electra,
            test_state.config,
            test_state.cached_state.epoch_cache,
            test_state.cached_state.state.castToFork(.electra),
            &slashing,
            false,
        ),
    );
}

test "assertValidProposerSlashing - InvalidProposerSlashingProposerNotSlashable" {
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    // Mark validator 0 as already slashed
    var validators_view = try test_state.cached_state.state.castToFork(.electra).validators();
    var validator_view = try validators_view.get(0);
    try validator_view.set("slashed", true);

    const slashing = makeValidProposerSlashing(0, 0);

    try std.testing.expectError(
        error.InvalidProposerSlashingProposerNotSlashable,
        assertValidProposerSlashing(
            .electra,
            test_state.config,
            test_state.cached_state.epoch_cache,
            test_state.cached_state.state.castToFork(.electra),
            &slashing,
            false,
        ),
    );
}
