const std = @import("std");
const c = @import("constants");
const COMPOUNDING_WITHDRAWAL_PREFIX = c.COMPOUNDING_WITHDRAWAL_PREFIX;
const ssz = @import("consensus_types");
const MIN_ACTIVATION_BALANCE = @import("preset").preset.MIN_ACTIVATION_BALANCE;
const GENESIS_SLOT = @import("preset").GENESIS_SLOT;

pub const WithdrawalCredentials = ssz.primitive.Root.Type;
pub const WithdrawalCredentialsLength = ssz.primitive.Root.length;
const BLSPubkey = ssz.primitive.BLSPubkey.Type;
const ValidatorIndex = ssz.primitive.ValidatorIndex.Type;

const BeaconStateAllForks = @import("../types/beacon_state.zig").BeaconStateAllForks;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const hasEth1WithdrawalCredential = @import("./capella.zig").hasEth1WithdrawalCredential;
const G2_POINT_AT_INFINITY = @import("constants").G2_POINT_AT_INFINITY;
const Allocator = std.mem.Allocator;

pub fn hasCompoundingWithdrawalCredential(withdrawal_credentials: WithdrawalCredentials) bool {
    return withdrawal_credentials[0] == COMPOUNDING_WITHDRAWAL_PREFIX;
}

pub fn hasExecutionWithdrawalCredential(withdrawal_credentials: WithdrawalCredentials) bool {
    return hasCompoundingWithdrawalCredential(withdrawal_credentials) or hasEth1WithdrawalCredential(withdrawal_credentials);
}

pub fn switchToCompoundingValidator(allocator: Allocator, state_cache: *CachedBeaconStateAllForks, index: ValidatorIndex) !void {
    var validator = &state_cache.state.validators().items[index];

    // directly modifying the byte leads to ssz.primitive missing the modification resulting into
    // wrong root compute, although slicing can be avoided but anyway this is not going
    // to be a hot path so its better to clean slice and avoid side effects
    var new_withdrawal_credentials = [_]u8{0} ** WithdrawalCredentialsLength;
    std.mem.copyForwards(u8, new_withdrawal_credentials[0..], validator.withdrawal_credentials[0..]);
    new_withdrawal_credentials[0] = COMPOUNDING_WITHDRAWAL_PREFIX;
    @memcpy(validator.withdrawal_credentials[0..], new_withdrawal_credentials[0..]);
    try queueExcessActiveBalance(allocator, state_cache, index);
}

pub fn queueExcessActiveBalance(allocator: Allocator, cached_state: *CachedBeaconStateAllForks, index: ValidatorIndex) !void {
    const state = cached_state.state;
    const balance = &state.balances().items[index];
    if (balance.* > MIN_ACTIVATION_BALANCE) {
        const validator = state.validators().items[index];
        const excess_balance = balance.* - MIN_ACTIVATION_BALANCE;
        balance.* = MIN_ACTIVATION_BALANCE;

        const pending_deposit = ssz.electra.PendingDeposit.Type{
            .pubkey = validator.pubkey,
            .withdrawal_credentials = validator.withdrawal_credentials,
            .amount = excess_balance,
            // Use bls.G2_POINT_AT_INFINITY as a signature field placeholder
            .signature = G2_POINT_AT_INFINITY,
            //  Use GENESIS_SLOT to distinguish from a pending deposit request
            .slot = GENESIS_SLOT,
        };

        try state.pendingDeposits().append(allocator, pending_deposit);
    }
}

pub fn isPubkeyKnown(cached_state: *const CachedBeaconStateAllForks, pubkey: BLSPubkey) bool {
    return isValidatorKnown(cached_state.state, cached_state.getEpochCache().getValidatorIndex(&pubkey));
}

pub fn isValidatorKnown(state: *const BeaconStateAllForks, index: ?ValidatorIndex) bool {
    const validator_index = index orelse return false;
    return validator_index < state.validators().items.len;
}
