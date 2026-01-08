const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const Validator = types.phase0.Validator.Type;

const Epoch = types.primitive.Epoch.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const BeaconState = @import("../types/beacon_state.zig").BeaconState;
const BeaconConfig = @import("config").BeaconConfig;
const ForkSeq = @import("config").ForkSeq;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const WithdrawalCredentials = types.primitive.Root.Type;
const hasCompoundingWithdrawalCredential = @import("./electra.zig").hasCompoundingWithdrawalCredential;

pub fn isActiveValidator(validator: *const Validator, epoch: Epoch) bool {
    return validator.activation_epoch <= epoch and epoch < validator.exit_epoch;
}

pub fn isSlashableValidator(validator: *const Validator, epoch: Epoch) bool {
    return !validator.slashed and validator.activation_epoch <= epoch and epoch < validator.withdrawable_epoch;
}

pub fn getActiveValidatorIndices(allocator: Allocator, state: *const BeaconState, epoch: Epoch) !std.ArrayList(ValidatorIndex) {
    var indices = std.ArrayList(ValidatorIndex).init(allocator);

    const validators = state.validators();
    for (0..validators.items.len) |i| {
        const validator = &validators.items[i];
        if (isActiveValidator(validator, epoch)) {
            try indices.append(@intCast(i));
        }
    }

    return indices;
}

pub fn getActivationChurnLimit(config: *const BeaconConfig, fork: ForkSeq, active_validator_count: usize) usize {
    if (fork.gte(.deneb)) {
        return @min(config.chain.MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT, getChurnLimit(config, active_validator_count));
    }

    return getChurnLimit(config, active_validator_count);
}

pub fn getChurnLimit(config: *const BeaconConfig, active_validator_count: usize) usize {
    return @max(config.chain.MIN_PER_EPOCH_CHURN_LIMIT, @divFloor(active_validator_count, config.chain.CHURN_LIMIT_QUOTIENT));
}

pub fn getBalanceChurnLimit(total_active_balance_increments: u64, churn_limit_quotient: u64, min_per_epoch_churn_limit: u64) u64 {
    const churn_limit_by_total_active_balance = (total_active_balance_increments / churn_limit_quotient) * preset.EFFECTIVE_BALANCE_INCREMENT;

    const churn = @max(churn_limit_by_total_active_balance, min_per_epoch_churn_limit);

    return churn - (churn % preset.EFFECTIVE_BALANCE_INCREMENT);
}

pub fn getBalanceChurnLimitFromCache(epoch_cache: *const EpochCache) u64 {
    return getBalanceChurnLimit(epoch_cache.total_active_balance_increments, epoch_cache.config.chain.CHURN_LIMIT_QUOTIENT, epoch_cache.config.chain.MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA);
}

pub fn getActivationExitChurnLimit(epoch_cache: *const EpochCache) u64 {
    return @min(epoch_cache.config.chain.MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT, getBalanceChurnLimitFromCache(epoch_cache));
}

pub fn getConsolidationChurnLimit(epoch_cache: *const EpochCache) u64 {
    return getBalanceChurnLimitFromCache(epoch_cache) - getActivationExitChurnLimit(epoch_cache);
}

pub fn getMaxEffectiveBalance(withdrawal_credentials: WithdrawalCredentials) u64 {
    // Compounding withdrawal credential only available since Electra
    if (hasCompoundingWithdrawalCredential(withdrawal_credentials)) {
        return preset.MAX_EFFECTIVE_BALANCE_ELECTRA;
    }
    return preset.MIN_ACTIVATION_BALANCE;
}

pub fn getPendingBalanceToWithdraw(state: *const BeaconState, validator_index: ValidatorIndex) u64 {
    var total: u64 = 0;
    const pending_partial_withdrawals = state.pendingPartialWithdrawals();
    for (0..pending_partial_withdrawals.items.len) |i| {
        const pending_partial_withdrawal = pending_partial_withdrawals.items[i];
        if (pending_partial_withdrawal.validator_index == validator_index) {
            total += pending_partial_withdrawal.amount;
        }
    }
    return total;
}
