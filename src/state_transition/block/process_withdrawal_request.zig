const std = @import("std");
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const c = @import("constants");
const types = @import("consensus_types");
const preset = @import("preset").preset;
const WithdrawalRequest = types.electra.WithdrawalRequest.Type;
const PendingPartialWithdrawal = types.electra.PendingPartialWithdrawal.Type;
const hasCompoundingWithdrawalCredential = @import("../utils/electra.zig").hasCompoundingWithdrawalCredential;
const hasExecutionWithdrawalCredential = @import("../utils/electra.zig").hasExecutionWithdrawalCredential;
const isActiveValidatorView = @import("../validator.zig").isActiveValidatorView;
const getPendingBalanceToWithdraw = @import("../validator.zig").getPendingBalanceToWithdraw;
const initiateValidatorExit = @import("./initiate_validator_exit.zig").initiateValidatorExit;
const computeExitEpochAndUpdateChurn = @import("../utils/epoch.zig").computeExitEpochAndUpdateChurn;

pub fn processWithdrawalRequest(cached_state: *CachedBeaconState, withdrawal_request: *const WithdrawalRequest) !void {
    var state = cached_state.state;
    const epoch_cache = cached_state.getEpochCache();
    const config = epoch_cache.config;

    const amount = withdrawal_request.amount;
    // no need to use unfinalized pubkey cache from 6110 as validator won't be active anyway
    const pubkey_to_index = epoch_cache.pubkey_to_index;
    const is_full_exit_request = amount == c.FULL_EXIT_REQUEST_AMOUNT;

    var pending_partial_withdrawals = try state.pendingPartialWithdrawals();

    // If partial withdrawal queue is full, only full exits are processed
    if (try pending_partial_withdrawals.length() >= preset.PENDING_PARTIAL_WITHDRAWALS_LIMIT and
        !is_full_exit_request)
    {
        return;
    }

    // bail out if validator is not in beacon state
    // note that we don't need to check for 6110 unfinalized vals as they won't be eligible for withdraw/exit anyway
    const validator_index = pubkey_to_index.get(&withdrawal_request.validator_pubkey) orelse return;

    var validators = try state.validators();
    if (validator_index >= try validators.length()) return;
    var validator = try validators.get(@intCast(validator_index));
    if (!(try isValidatorEligibleForWithdrawOrExit(&validator, &withdrawal_request.source_address, cached_state))) {
        return;
    }

    // TODO Electra: Consider caching pendingPartialWithdrawals
    const pending_balance_to_withdraw = try getPendingBalanceToWithdraw(state, validator_index);
    var balances = try state.balances();
    const validator_balance = try balances.get(@intCast(validator_index));

    if (is_full_exit_request) {
        // only exit validator if it has no pending withdrawals in the queue
        if (pending_balance_to_withdraw == 0) {
            try initiateValidatorExit(cached_state, &validator);
        }
        return;
    }

    // partial withdrawal request
    const effective_balance = try validator.get("effective_balance");
    const withdrawal_credentials = try validator.getRoot("withdrawal_credentials");

    const has_sufficient_effective_balance = effective_balance >= preset.MIN_ACTIVATION_BALANCE;
    const has_excess_balance = validator_balance > preset.MIN_ACTIVATION_BALANCE + pending_balance_to_withdraw;

    // Only allow partial withdrawals with compounding withdrawal credentials
    if (hasCompoundingWithdrawalCredential(withdrawal_credentials) and
        has_sufficient_effective_balance and
        has_excess_balance)
    {
        const amount_to_withdraw = @min(validator_balance - preset.MIN_ACTIVATION_BALANCE - pending_balance_to_withdraw, amount);
        const exit_queue_epoch = try computeExitEpochAndUpdateChurn(cached_state, amount_to_withdraw);
        const withdrawable_epoch = exit_queue_epoch + config.chain.MIN_VALIDATOR_WITHDRAWABILITY_DELAY;

        const pending_partial_withdrawal = PendingPartialWithdrawal{
            .validator_index = validator_index,
            .amount = amount_to_withdraw,
            .withdrawable_epoch = withdrawable_epoch,
        };
        try pending_partial_withdrawals.pushValue(&pending_partial_withdrawal);
    }
}

fn isValidatorEligibleForWithdrawOrExit(validator: *types.phase0.Validator.TreeView, source_address: []const u8, cached_state: *const CachedBeaconState) !bool {
    const withdrawal_credentials = try validator.getRoot("withdrawal_credentials");
    const address = withdrawal_credentials[12..];
    const epoch_cache = cached_state.getEpochCache();
    const config = epoch_cache.config;
    const current_epoch = epoch_cache.epoch;

    const activation_epoch = try validator.get("activation_epoch");
    const exit_epoch = try validator.get("exit_epoch");

    return (hasExecutionWithdrawalCredential(withdrawal_credentials) and
        std.mem.eql(u8, address, source_address) and
        (try isActiveValidatorView(validator, current_epoch)) and
        exit_epoch == c.FAR_FUTURE_EPOCH and
        current_epoch >= activation_epoch + config.chain.SHARD_COMMITTEE_PERIOD);
}
