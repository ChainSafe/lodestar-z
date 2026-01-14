const std = @import("std");
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const types = @import("consensus_types");
const Root = types.primitive.Root.Type;
const SignedBLSToExecutionChange = types.capella.SignedBLSToExecutionChange.Type;
const c = @import("constants");
const Sha256 = std.crypto.hash.sha2.Sha256;
const verifyBlsToExecutionChangeSignature = @import("../signature_sets/bls_to_execution_change.zig").verifyBlsToExecutionChangeSignature;

pub fn processBlsToExecutionChange(cached_state: *CachedBeaconStateAllForks, signed_bls_to_execution_change: *const SignedBLSToExecutionChange) !void {
    const address_change = signed_bls_to_execution_change.message;
    const state = cached_state.state;

    try isValidBlsToExecutionChange(cached_state, signed_bls_to_execution_change, true);

    var new_withdrawal_credentials: Root = [_]u8{0} ** 32;
    const validator_index = address_change.validator_index;
    var validator = &state.validators().items[validator_index];
    new_withdrawal_credentials[0] = c.ETH1_ADDRESS_WITHDRAWAL_PREFIX;
    @memcpy(new_withdrawal_credentials[12..], &address_change.to_execution_address);

    // Set the new credentials back
    validator.withdrawal_credentials = new_withdrawal_credentials;
}

pub fn isValidBlsToExecutionChange(cached_state: *CachedBeaconStateAllForks, signed_bls_to_execution_change: *const SignedBLSToExecutionChange, verify_signature: bool) !void {
    const state = cached_state.state;
    const address_change = signed_bls_to_execution_change.message;
    const validator_index = address_change.validator_index;
    if (validator_index >= state.validators().items.len) {
        return error.InvalidBlsToExecutionChange;
    }

    const validator = state.validators().items[validator_index];
    const withdrawal_credentials = validator.withdrawal_credentials;
    if (withdrawal_credentials[0] != c.BLS_WITHDRAWAL_PREFIX) {
        return error.InvalidWithdrawalCredentialsPrefix;
    }

    var digest_credentials: Root = undefined;
    Sha256.hash(&address_change.from_bls_pubkey, &digest_credentials, .{});
    // Set the BLS_WITHDRAWAL_PREFIX on the digest_credentials for direct match
    digest_credentials[0] = c.BLS_WITHDRAWAL_PREFIX;
    if (!std.mem.eql(u8, &withdrawal_credentials, &digest_credentials)) {
        return error.InvalidWithdrawalCredentials;
    }

    if (verify_signature) {
        if (!try verifyBlsToExecutionChangeSignature(cached_state, signed_bls_to_execution_change)) {
            return error.InvalidBlsToExecutionChangeSignature;
        }
    }
}
