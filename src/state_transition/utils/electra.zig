const std = @import("std");
const c = @import("constants");
const COMPOUNDING_WITHDRAWAL_PREFIX = c.COMPOUNDING_WITHDRAWAL_PREFIX;
const ct = @import("consensus_types");
const MIN_ACTIVATION_BALANCE = @import("preset").preset.MIN_ACTIVATION_BALANCE;
const GENESIS_SLOT = @import("preset").GENESIS_SLOT;

pub const WithdrawalCredentials = ct.primitive.Root.Type;
pub const WithdrawalCredentialsLength = ct.primitive.Root.length;
const BLSPubkey = ct.primitive.BLSPubkey.Type;
const ValidatorIndex = ct.primitive.ValidatorIndex.Type;

const BeaconState = @import("../types/beacon_state.zig").BeaconState;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const hasEth1WithdrawalCredential = @import("./capella.zig").hasEth1WithdrawalCredential;
const G2_POINT_AT_INFINITY = @import("constants").G2_POINT_AT_INFINITY;
const Allocator = std.mem.Allocator;

pub fn hasCompoundingWithdrawalCredential(withdrawal_credentials: WithdrawalCredentials) bool {
    return withdrawal_credentials[0] == COMPOUNDING_WITHDRAWAL_PREFIX;
}

pub fn hasExecutionWithdrawalCredential(withdrawal_credentials: WithdrawalCredentials) bool {
    return hasCompoundingWithdrawalCredential(withdrawal_credentials) or hasEth1WithdrawalCredential(withdrawal_credentials);
}

pub fn switchToCompoundingValidator(state_cache: *CachedBeaconState, index: ValidatorIndex) !void {
    const validator = try (try state_cache.state.validators()).get(index);
    const old_withdrawal_credentials = try validator.getValue("withdrawal_credentials");

    // directly modifying the byte leads to types.primitive missing the modification resulting into
    // wrong root compute, although slicing can be avoided but anyway this is not going
    // to be a hot path so its better to clean slice and avoid side effects
    var new_withdrawal_credentials = [_]u8{0} ** WithdrawalCredentialsLength;
    std.mem.copyForwards(u8, new_withdrawal_credentials[0..], old_withdrawal_credentials[0..]);
    new_withdrawal_credentials[0] = COMPOUNDING_WITHDRAWAL_PREFIX;

    try validator.set("withdrawal_credentials", new_withdrawal_credentials);

    try queueExcessActiveBalance(state_cache, index, new_withdrawal_credentials, try validator.getValue("pubkey"));
}

pub fn queueExcessActiveBalance(
    cached_state: *CachedBeaconState,
    index: ValidatorIndex,
    withdrawal_credentials: ct.primitive.Root.Type,
    pubkey: ct.primitive.BLSPubkey.Type,
) !void {
    const state = cached_state.state;
    const balances = try state.balances();
    const balance = try balances.get(index);
    if (balance.* > MIN_ACTIVATION_BALANCE) {
        const excess_balance = balance.* - MIN_ACTIVATION_BALANCE;
        balance.* = MIN_ACTIVATION_BALANCE;

        const pending_deposit = ct.electra.PendingDeposit.Type{
            .pubkey = pubkey,
            .withdrawal_credentials = withdrawal_credentials,
            .amount = excess_balance,
            // Use bls.G2_POINT_AT_INFINITY as a signature field placeholder
            .signature = G2_POINT_AT_INFINITY,
            //  Use GENESIS_SLOT to distinguish from a pending deposit request
            .slot = GENESIS_SLOT,
        };

        try (try state.pendingDeposits()).pushValue(pending_deposit);
    }
}

pub fn isPubkeyKnown(cached_state: *const CachedBeaconState, pubkey: BLSPubkey) bool {
    return isValidatorKnown(cached_state.state, cached_state.getEpochCache().getValidatorIndex(&pubkey));
}

pub fn isValidatorKnown(state: *const BeaconState, index: ?ValidatorIndex) bool {
    const validator_index = index orelse return false;
    return validator_index < state.validators().items.len;
}
