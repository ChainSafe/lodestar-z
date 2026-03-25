const std = @import("std");
const ForkSeq = @import("config").ForkSeq;
const BeaconConfig = @import("config").BeaconConfig;
const BeaconState = @import("fork_types").BeaconState;
const types = @import("consensus_types");
const Root = types.primitive.Root.Type;
const SignedBLSToExecutionChange = types.capella.SignedBLSToExecutionChange.Type;
const c = @import("constants");
const verifyBlsToExecutionChangeSignature = @import("../signature_sets/bls_to_execution_change.zig").verifyBlsToExecutionChangeSignature;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub fn processBlsToExecutionChange(
    comptime fork: ForkSeq,
    config: *const BeaconConfig,
    state: *BeaconState(fork),
    signed_bls_to_execution_change: *const SignedBLSToExecutionChange,
) !void {
    const address_change = signed_bls_to_execution_change.message;

    try isValidBlsToExecutionChange(fork, config, state, signed_bls_to_execution_change, true);

    var new_withdrawal_credentials: Root = [_]u8{0} ** 32;
    const validator_index = address_change.validator_index;
    var validators = try state.validators();
    var validator = try validators.get(@intCast(validator_index));
    new_withdrawal_credentials[0] = c.ETH1_ADDRESS_WITHDRAWAL_PREFIX;
    @memcpy(new_withdrawal_credentials[12..], &address_change.to_execution_address);

    // Set the new credentials back
    try validator.setValue("withdrawal_credentials", &new_withdrawal_credentials);
}

pub fn isValidBlsToExecutionChange(
    comptime fork: ForkSeq,
    config: *const BeaconConfig,
    state: *BeaconState(fork),
    signed_bls_to_execution_change: *const SignedBLSToExecutionChange,
    verify_signature: bool,
) !void {
    const address_change = signed_bls_to_execution_change.message;
    const validator_index = address_change.validator_index;
    var validators = try state.validators();
    const validators_len = try validators.length();
    if (validator_index >= validators_len) {
        return error.InvalidBlsToExecutionChange;
    }

    var validator = try validators.get(@intCast(validator_index));
    const withdrawal_credentials = try validator.getFieldRoot("withdrawal_credentials");
    if (withdrawal_credentials[0] != c.BLS_WITHDRAWAL_PREFIX) {
        return error.InvalidWithdrawalCredentialsPrefix;
    }

    var digest_credentials: Root = undefined;
    Sha256.hash(&address_change.from_bls_pubkey, &digest_credentials, .{});
    // Set the BLS_WITHDRAWAL_PREFIX on the digest_credentials for direct match
    digest_credentials[0] = c.BLS_WITHDRAWAL_PREFIX;
    if (!std.mem.eql(u8, withdrawal_credentials, &digest_credentials)) {
        return error.InvalidWithdrawalCredentials;
    }

    if (verify_signature) {
        if (!try verifyBlsToExecutionChangeSignature(config, signed_bls_to_execution_change)) {
            return error.InvalidBlsToExecutionChangeSignature;
        }
    }
}

const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const interopPubkeysCached = @import("../test_utils/interop_pubkeys.zig").interopPubkeysCached;
const Node = @import("persistent_merkle_tree").Node;
const BLSPubkey = types.primitive.BLSPubkey.Type;

/// Helper to set up a valid BLS-to-execution-change scenario for validator 0.
/// Returns the signed message and sets the validator's withdrawal_credentials to match.
fn setupValidBlsToExecutionChange(state: anytype) !SignedBLSToExecutionChange {
    // Get validator 0's interop pubkey
    var pubkeys: [1]BLSPubkey = undefined;
    try interopPubkeysCached(1, &pubkeys);

    // Hash the pubkey and set byte 0 to BLS_WITHDRAWAL_PREFIX
    var expected_credentials: Root = undefined;
    Sha256.hash(&pubkeys[0], &expected_credentials, .{});
    expected_credentials[0] = c.BLS_WITHDRAWAL_PREFIX;

    // Set validator 0's withdrawal_credentials to match
    var validators = try state.validators();
    var validator = try validators.get(0);
    try validator.setValue("withdrawal_credentials", &expected_credentials);

    const signed_msg: SignedBLSToExecutionChange = .{
        .message = .{
            .validator_index = 0,
            .from_bls_pubkey = pubkeys[0],
            .to_execution_address = [_]u8{0xab} ** 20,
        },
        .signature = [_]u8{0} ** 96,
    };
    return signed_msg;
}

test "bls to execution change - valid" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    const state = test_state.cached_state.state.castToFork(.electra);
    const signed_msg = try setupValidBlsToExecutionChange(state);

    // Should succeed with verify_signature=false
    try isValidBlsToExecutionChange(.electra, test_state.config, state, &signed_msg, false);
}

test "bls to execution change - invalid validator index" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    const state = test_state.cached_state.state.castToFork(.electra);

    const signed_msg: SignedBLSToExecutionChange = .{
        .message = .{
            .validator_index = 9999, // out of bounds
            .from_bls_pubkey = [_]u8{0} ** 48,
            .to_execution_address = [_]u8{0} ** 20,
        },
        .signature = [_]u8{0} ** 96,
    };

    try std.testing.expectError(
        error.InvalidBlsToExecutionChange,
        isValidBlsToExecutionChange(.electra, test_state.config, state, &signed_msg, false),
    );
}

test "bls to execution change - invalid withdrawal credentials prefix" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    const state = test_state.cached_state.state.castToFork(.electra);

    // Set validator 0's withdrawal_credentials prefix to ETH1 (not BLS)
    var bad_credentials: Root = [_]u8{0} ** 32;
    bad_credentials[0] = c.ETH1_ADDRESS_WITHDRAWAL_PREFIX;
    var validators = try state.validators();
    var validator = try validators.get(0);
    try validator.setValue("withdrawal_credentials", &bad_credentials);

    const signed_msg: SignedBLSToExecutionChange = .{
        .message = .{
            .validator_index = 0,
            .from_bls_pubkey = [_]u8{0} ** 48,
            .to_execution_address = [_]u8{0} ** 20,
        },
        .signature = [_]u8{0} ** 96,
    };

    try std.testing.expectError(
        error.InvalidWithdrawalCredentialsPrefix,
        isValidBlsToExecutionChange(.electra, test_state.config, state, &signed_msg, false),
    );
}

test "bls to execution change - mismatched credentials" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    const state = test_state.cached_state.state.castToFork(.electra);

    // Validator 0 has withdrawal_credentials = all zeros (first byte 0x00 = BLS_WITHDRAWAL_PREFIX)
    // but the hash of from_bls_pubkey won't match the rest of the zeros
    const signed_msg: SignedBLSToExecutionChange = .{
        .message = .{
            .validator_index = 0,
            .from_bls_pubkey = [_]u8{0xff} ** 48, // hash won't match all-zero credentials
            .to_execution_address = [_]u8{0} ** 20,
        },
        .signature = [_]u8{0} ** 96,
    };

    try std.testing.expectError(
        error.InvalidWithdrawalCredentials,
        isValidBlsToExecutionChange(.electra, test_state.config, state, &signed_msg, false),
    );
}
