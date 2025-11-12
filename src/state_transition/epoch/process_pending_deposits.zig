const std = @import("std");
const ct = @import("consensus_types");
const Allocator = std.mem.Allocator;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const getActivationExitChurnLimit = @import("../utils/validator.zig").getActivationExitChurnLimit;
const preset = @import("preset").preset;
const isValidatorKnown = @import("../utils/electra.zig").isValidatorKnown;
const ForkSeq = @import("config").ForkSeq;
const isValidDepositSignature = @import("../block/process_deposit.zig").isValidDepositSignature;
const addValidatorToRegistry = @import("../block/process_deposit.zig").addValidatorToRegistry;
const hasCompoundingWithdrawalCredential = @import("../utils/electra.zig").hasCompoundingWithdrawalCredential;
const increaseBalance = @import("../utils/balance.zig").increaseBalance;
const computeStartSlotAtEpoch = @import("../utils/epoch.zig").computeStartSlotAtEpoch;
const PendingDeposit = ct.electra.PendingDeposit.Type;
const GENESIS_SLOT = @import("preset").GENESIS_SLOT;
const c = @import("constants");

/// we append EpochTransitionCache.is_compounding_validator_arr in this flow
pub fn processPendingDeposits(allocator: Allocator, cached_state: *CachedBeaconStateAllForks, cache: *EpochTransitionCache) !void {
    const epoch_cache = cached_state.getEpochCache();
    const state = cached_state.state;
    const next_epoch = epoch_cache.epoch + 1;
    const deposit_balance_to_consume = state.depositBalanceToConsume();
    const available_for_processing = deposit_balance_to_consume.* + getActivationExitChurnLimit(epoch_cache);
    var processed_amount: u64 = 0;
    var next_deposit_index: u64 = 0;
    var is_churn_limit_reached = false;
    const finalized_slot = computeStartSlotAtEpoch(state.finalizedCheckpoint().epoch);

    var start_index: usize = 0;
    // TODO: is this a good number?
    const chunk = 100;
    const pending_deposits = state.pendingDeposits();
    const pending_deposits_len = pending_deposits.items.len;
    outer: while (start_index < pending_deposits_len) : (start_index += chunk) {
        // TODO(ct.primitive): implement getReadonlyByRange api for TreeView
        // const deposits: []PendingDeposit = state.getPendingDeposits().getReadonlyByRange(start_index, chunk);
        const deposits: []PendingDeposit = pending_deposits.items[start_index..@min(start_index + chunk, pending_deposits_len)];
        for (deposits) |deposit| {
            // Do not process deposit requests if Eth1 bridge deposits are not yet applied.
            if (
            // Is deposit request
            deposit.slot > GENESIS_SLOT and
                // There are pending Eth1 bridge deposits
                state.eth1DepositIndex() < state.depositRequestsStartIndex().*)
            {
                break :outer;
            }

            // Check if deposit has been finalized, otherwise, stop processing.
            if (deposit.slot > finalized_slot) {
                break :outer;
            }

            // Check if number of processed deposits has not reached the limit, otherwise, stop processing.
            // TODO(ct): define MAX_PENDING_DEPOSITS_PER_EPOCH in preset
            if (next_deposit_index >= preset.MAX_PENDING_DEPOSITS_PER_EPOCH) {
                break :outer;
            }

            // Read validator state
            var is_validator_exited = false;
            var is_validator_withdrawn = false;
            const validator_index = epoch_cache.getValidatorIndex(&deposit.pubkey);

            if (isValidatorKnown(state, validator_index)) {
                const validator = state.validators().items[validator_index.?];
                is_validator_exited = validator.exit_epoch < c.FAR_FUTURE_EPOCH;
                is_validator_withdrawn = validator.withdrawable_epoch < next_epoch;
            }

            if (is_validator_withdrawn) {
                // Deposited balance will never become active. Increase balance but do not consume churn
                try applyPendingDeposit(allocator, cached_state, deposit, cache);
            } else if (is_validator_exited) {
                // TODO: typescript version accumulate to temp array while in zig we append directly
                try pending_deposits.append(allocator, deposit);
            } else {
                // Check if deposit fits in the churn, otherwise, do no more deposit processing in this epoch.
                is_churn_limit_reached = processed_amount + deposit.amount > available_for_processing;
                if (is_churn_limit_reached) {
                    break :outer;
                }
                // Consume churn and apply deposit.
                processed_amount += deposit.amount;
                try applyPendingDeposit(allocator, cached_state, deposit, cache);
            }

            // Regardless of how the deposit was handled, we move on in the queue.
            next_deposit_index += 1;
        }
    }

    if (next_deposit_index > 0) {
        const new_len = pending_deposits_len - next_deposit_index;
        @memcpy(pending_deposits.items[0..new_len], pending_deposits.items[next_deposit_index..]);
        try pending_deposits.resize(allocator, new_len);
    }

    // TODO: consider doing this for TreeView
    //   for (const deposit of depositsToPostpone) {
    //   state.pendingDeposits.push(deposit);
    // }

    // no need to append to pending_deposits again because we did that in the for loop above already
    // Accumulate churn only if the churn limit has been hit.
    deposit_balance_to_consume.* =
        if (is_churn_limit_reached)
            available_for_processing - processed_amount
        else
            0;
}

/// we append EpochTransitionCache.is_compounding_validator_arr in this flow
fn applyPendingDeposit(allocator: Allocator, cached_state: *CachedBeaconStateAllForks, deposit: PendingDeposit, cache: *EpochTransitionCache) !void {
    const epoch_cache = cached_state.getEpochCache();
    const state = cached_state.state;
    const validator_index = epoch_cache.getValidatorIndex(&deposit.pubkey) orelse null;
    const pubkey = deposit.pubkey;
    // TODO: is this withdrawal_credential(s) the same to spec?
    const withdrawal_credential = deposit.withdrawal_credentials;
    const amount = deposit.amount;
    const signature = deposit.signature;
    const is_validator_known = isValidatorKnown(state, validator_index);

    if (!is_validator_known) {
        // Verify the deposit signature (proof of possession) which is not checked by the deposit contract
        if (isValidDepositSignature(cached_state.config, pubkey, withdrawal_credential, amount, signature)) {
            try addValidatorToRegistry(allocator, cached_state, pubkey, withdrawal_credential, amount);
            try cache.is_compounding_validator_arr.append(hasCompoundingWithdrawalCredential(withdrawal_credential));
            // set balance, so that the next deposit of same pubkey will increase the balance correctly
            // this is to fix the double deposit issue found in mekong
            // see https://github.com/ChainSafe/lodestar/pull/7255
            if (cache.balances) |*balances| {
                try balances.append(amount);
            }
        }
    } else {
        if (validator_index) |val_idx| {
            // Increase balance
            increaseBalance(state, val_idx, amount);
            if (cache.balances) |*balances| {
                balances.items[val_idx] += amount;
            }
        } else {
            // should not happen since we checked in isValidatorKnown() above
            return error.UnexpectedNullValidatorIndex;
        }
    }
}
