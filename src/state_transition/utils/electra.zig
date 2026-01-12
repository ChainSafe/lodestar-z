const std = @import("std");
const c = @import("constants");
const COMPOUNDING_WITHDRAWAL_PREFIX = c.COMPOUNDING_WITHDRAWAL_PREFIX;
const ct = @import("consensus_types");
const MIN_ACTIVATION_BALANCE = @import("preset").preset.MIN_ACTIVATION_BALANCE;
const GENESIS_SLOT = @import("preset").GENESIS_SLOT;

pub const WithdrawalCredentials = ct.primitive.Root.Type;
const BLSPubkey = ct.primitive.BLSPubkey.Type;
const ValidatorIndex = ct.primitive.ValidatorIndex.Type;

const BeaconState = @import("../types/beacon_state.zig").BeaconState;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const hasEth1WithdrawalCredential = @import("./capella.zig").hasEth1WithdrawalCredential;
const G2_POINT_AT_INFINITY = @import("constants").G2_POINT_AT_INFINITY;
const Allocator = std.mem.Allocator;

pub fn hasCompoundingWithdrawalCredential(withdrawal_credentials: *const WithdrawalCredentials) bool {
    return withdrawal_credentials[0] == COMPOUNDING_WITHDRAWAL_PREFIX;
}

pub fn hasExecutionWithdrawalCredential(withdrawal_credentials: *const WithdrawalCredentials) bool {
    return hasCompoundingWithdrawalCredential(withdrawal_credentials) or hasEth1WithdrawalCredential(withdrawal_credentials);
}

pub fn switchToCompoundingValidator(state_cache: *CachedBeaconState, index: ValidatorIndex) !void {
    var validators = try state_cache.state.validators();
    var validator = try validators.get(index);
    const old_withdrawal_credentials = try validator.getRoot("withdrawal_credentials");

    var new_withdrawal_credentials: [32]u8 = undefined;
    @memcpy(new_withdrawal_credentials[0..], old_withdrawal_credentials[0..]);
    new_withdrawal_credentials[0] = COMPOUNDING_WITHDRAWAL_PREFIX;

    try validator.setValue("withdrawal_credentials", &new_withdrawal_credentials);

    try queueExcessActiveBalance(state_cache, index, &new_withdrawal_credentials, try validator.getValue(undefined, "pubkey"));
}

pub fn queueExcessActiveBalance(
    cached_state: *CachedBeaconState,
    index: ValidatorIndex,
    withdrawal_credentials: *const WithdrawalCredentials,
    pubkey: ct.primitive.BLSPubkey.Type,
) !void {
    const state = cached_state.state;
    var balances = try state.balances();
    const balance = try balances.get(index);
    if (balance > MIN_ACTIVATION_BALANCE) {
        const excess_balance = balance - MIN_ACTIVATION_BALANCE;
        try balances.set(index, MIN_ACTIVATION_BALANCE);

        const pending_deposit = ct.electra.PendingDeposit.Type{
            .pubkey = pubkey,
            .withdrawal_credentials = withdrawal_credentials.*,
            .amount = excess_balance,
            // Use bls.G2_POINT_AT_INFINITY as a signature field placeholder
            .signature = G2_POINT_AT_INFINITY,
            //  Use GENESIS_SLOT to distinguish from a pending deposit request
            .slot = GENESIS_SLOT,
        };
        var pending_deposits = try state.pendingDeposits();
        try pending_deposits.pushValue(&pending_deposit);
    }
}

pub fn isPubkeyKnown(cached_state: *CachedBeaconState, pubkey: BLSPubkey) !bool {
    return try isValidatorKnown(cached_state.state, cached_state.getEpochCache().getValidatorIndex(&pubkey));
}

pub fn isValidatorKnown(state: *BeaconState, index: ?ValidatorIndex) !bool {
    const validator_index = index orelse return false;
    const validators_count = try state.validatorsCount();
    return validator_index < validators_count;
}
