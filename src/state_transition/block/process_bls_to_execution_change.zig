const std = @import("std");
const ForkSeq = @import("config").ForkSeq;
const BeaconConfig = @import("config").BeaconConfig;
const BeaconState = @import("fork_types").BeaconState;
const types = @import("consensus_types");
const Root = types.primitive.Root.Type;
const SignedBLSToExecutionChange = types.capella.SignedBLSToExecutionChange.Type;
const c = @import("constants");
const verifyBlsToExecutionChangeSignature = @import("../signature_sets/bls_to_execution_change.zig").verifyBlsToExecutionChangeSignature;
const getBlsToExecutionChangeSignatureSet = @import("../signature_sets/bls_to_execution_change.zig").getBlsToExecutionChangeSignatureSet;
const verifySingleSignatureSetOrDefer = @import("../utils/signature_sets.zig").verifySingleSignatureSetOrDefer;
const BatchVerifier = @import("bls").BatchVerifier;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub fn processBlsToExecutionChange(
    comptime fork: ForkSeq,
    config: *const BeaconConfig,
    state: *BeaconState(fork),
    signed_bls_to_execution_change: *const SignedBLSToExecutionChange,
    batch_verifier: ?*BatchVerifier,
) !void {
    const address_change = signed_bls_to_execution_change.message;

    try isValidBlsToExecutionChange(fork, config, state, signed_bls_to_execution_change, true, batch_verifier);

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
    batch_verifier: ?*BatchVerifier,
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
        if (batch_verifier != null) {
            const sig_set = try getBlsToExecutionChangeSignatureSet(config, signed_bls_to_execution_change);
            if (!try verifySingleSignatureSetOrDefer(&sig_set, batch_verifier)) {
                return error.InvalidBlsToExecutionChangeSignature;
            }
        } else {
            if (!try verifyBlsToExecutionChangeSignature(config, signed_bls_to_execution_change)) {
                return error.InvalidBlsToExecutionChangeSignature;
            }
        }
    }
}
