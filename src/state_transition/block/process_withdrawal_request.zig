const std = @import("std");
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const c = @import("constants");
const ssz = @import("consensus_types");
const preset = @import("preset").preset;
const Validator = ssz.phase0.Validator.Type;
const WithdrawalRequest = ssz.electra.WithdrawalRequest.Type;
const PendingPartialWithdrawal = ssz.electra.PendingPartialWithdrawal.Type;
const hasExecutionWithdrawalCredential = @import("../utils/electra.zig").hasExecutionWithdrawalCredential;
const hasCompoundingWithdrawalCredential = @import("../utils/electra.zig").hasCompoundingWithdrawalCredential;
const isActiveValidator = @import("../utils/validator.zig").isActiveValidator;
const getPendingBalanceToWithdraw = @import("../utils/validator.zig").getPendingBalanceToWithdraw;
const initiateValidatorExit = @import("./initiate_validator_exit.zig").initiateValidatorExit;
const computeExitEpochAndUpdateChurn = @import("../utils/epoch.zig").computeExitEpochAndUpdateChurn;

pub fn processWithdrawalRequest(allocator: std.mem.Allocator, cached_state: *CachedBeaconStateAllForks, withdrawal_request: *const WithdrawalRequest) !void {
    const state = cached_state.state;
    const epoch_cache = cached_state.getEpochCache();
    const config = epoch_cache.config;

    const amount = withdrawal_request.amount;
    const pending_partial_withdrawals = state.pendingPartialWithdrawals();
    const validators = state.validators();

    // no need to use unfinalized pubkey cache from 6110 as validator won't be active anyway
    const pubkey_to_index = epoch_cache.pubkey_to_index;
    const is_full_exit_request = amount == c.FULL_EXIT_REQUEST_AMOUNT;

    // If partial withdrawal queue is full, only full exits are processed
    if (pending_partial_withdrawals.items.len >= preset.PENDING_PARTIAL_WITHDRAWALS_LIMIT and
        !is_full_exit_request)
    {
        return;
    }

    // bail out if validator is not in beacon state
    // note that we don't need to check for 6110 unfinalized vals as they won't be eligible for withdraw/exit anyway
    const validator_index = pubkey_to_index.get(&withdrawal_request.validator_pubkey) orelse return;

    const validator = &validators.items[validator_index];
    if (!isValidatorEligibleForWithdrawOrExit(validator, &withdrawal_request.source_address, cached_state)) {
        return;
    }

    // TODO Electra: Consider caching pendingPartialWithdrawals
    const pending_balance_to_withdraw = getPendingBalanceToWithdraw(state, validator_index);
    const validator_balance = state.balances().items[validator_index];

    if (is_full_exit_request) {
        // only exit validator if it has no pending withdrawals in the queue
        if (pending_balance_to_withdraw == 0) {
            try initiateValidatorExit(cached_state, validator);
        }
        return;
    }

    // partial withdrawal request
    const has_sufficient_effective_balance = validator.effective_balance >= preset.MIN_ACTIVATION_BALANCE;
    const has_excess_balance = validator_balance > preset.MIN_ACTIVATION_BALANCE + pending_balance_to_withdraw;

    // Only allow partial withdrawals with compounding withdrawal credentials
    if (hasExecutionWithdrawalCredential(validator.withdrawal_credentials) and
        has_sufficient_effective_balance and
        has_excess_balance)
    {
        const amount_to_withdraw = @min(validator_balance - preset.MIN_ACTIVATION_BALANCE - pending_balance_to_withdraw, amount);
        const exit_queue_epoch = computeExitEpochAndUpdateChurn(cached_state, amount_to_withdraw);
        const withdrawable_epoch = exit_queue_epoch + config.chain.MIN_VALIDATOR_WITHDRAWABILITY_DELAY;

        const pending_partial_withdrawal = PendingPartialWithdrawal{
            .validator_index = validator_index,
            .amount = amount_to_withdraw,
            .withdrawable_epoch = withdrawable_epoch,
        };
        try state.pendingPartialWithdrawals().append(allocator, pending_partial_withdrawal);
    }
}

fn isValidatorEligibleForWithdrawOrExit(validator: *const Validator, source_address: []const u8, cached_state: *const CachedBeaconStateAllForks) bool {
    const withdrawal_credentials = validator.withdrawal_credentials;
    const address = withdrawal_credentials[12..];
    const epoch_cache = cached_state.getEpochCache();
    const config = epoch_cache.config;
    const current_epoch = epoch_cache.epoch;

    return (hasExecutionWithdrawalCredential(withdrawal_credentials) and
        std.mem.eql(u8, address, source_address) and
        isActiveValidator(validator, current_epoch) and
        validator.exit_epoch == c.FAR_FUTURE_EPOCH and
        current_epoch >= validator.activation_epoch + config.chain.SHARD_COMMITTEE_PERIOD);
}
