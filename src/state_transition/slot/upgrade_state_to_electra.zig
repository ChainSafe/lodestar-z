const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const ssz = @import("consensus_types");
const ValidatorIndex = ssz.primitive.ValidatorIndex.Type;
const constants = @import("constants");
const computeActivationExitEpoch = @import("../utils/epoch.zig").computeActivationExitEpoch;
const getActivationExitChurnLimit = @import("../utils/validator.zig").getActivationExitChurnLimit;
const getConsolidationChurnLimit = @import("../utils/validator.zig").getConsolidationChurnLimit;
const hasCompoundingWithdrawalCredential = @import("../utils/electra.zig").hasCompoundingWithdrawalCredential;
const queueExcessActiveBalance = @import("../utils/electra.zig").queueExcessActiveBalance;

pub fn upgradeStateToElectra(allocator: Allocator, cached_state: *CachedBeaconStateAllForks) !void {
    var state = cached_state.state;
    if (!state.isDeneb()) {
        return error.StateIsNotDeneb;
    }

    const deneb_state = state.deneb;
    defer {
        ssz.deneb.BeaconState.deinit(allocator, deneb_state);
        allocator.destroy(deneb_state);
    }
    _ = try state.upgradeUnsafe(allocator);
    state.forkPtr().* = .{
        .previous_version = deneb_state.fork.current_version,
        .current_version = cached_state.config.chain.ELECTRA_FORK_VERSION,
        .epoch = cached_state.getEpochCache().epoch,
    };

    state.depositRequestsStartIndex().* = constants.UNSET_DEPOSIT_REQUESTS_START_INDEX;
    state.depositBalanceToConsume().* = 0;
    state.exitBalanceToConsume().* = 0;

    const current_epoch_pre = cached_state.getEpochCache().epoch;
    var earliest_exit_epoch = computeActivationExitEpoch(current_epoch_pre);
    // [EIP-7251]: add validators that are not yet active to pending balance deposits
    var pre_activation = std.ArrayList(ssz.primitive.ValidatorIndex.Type).init(allocator);
    defer pre_activation.deinit();
    const validators = state.validators().items;
    for (validators, 0..) |validator, validator_index| {
        const activation_epoch = validator.activation_epoch;
        const exit_epoch = validator.exit_epoch;
        if (activation_epoch == constants.FAR_FUTURE_EPOCH) {
            try pre_activation.append(validator_index);
        }
        if (exit_epoch != constants.FAR_FUTURE_EPOCH and exit_epoch > earliest_exit_epoch) {
            earliest_exit_epoch = exit_epoch;
        }
    }

    state.earliestExitEpoch().* = earliest_exit_epoch + 1;
    state.earliestConsolidationEpoch().* = computeActivationExitEpoch(current_epoch_pre);
    state.exitBalanceToConsume().* = getActivationExitChurnLimit(cached_state.getEpochCache());
    state.consolidationBalanceToConsume().* = getConsolidationChurnLimit(cached_state.getEpochCache());

    const sort_fn = struct {
        pub fn sort(validator_arr: []ssz.phase0.Validator.Type, a: ValidatorIndex, b: ValidatorIndex) bool {
            const activation_eligibility_epoch_a = validator_arr[a].activation_eligibility_epoch;
            const activation_eligibility_epoch_b = validator_arr[b].activation_eligibility_epoch;
            return if (activation_eligibility_epoch_a != activation_eligibility_epoch_b) activation_eligibility_epoch_a < activation_eligibility_epoch_b else a < b;
        }
    }.sort;
    std.mem.sort(ValidatorIndex, pre_activation.items, validators, sort_fn);

    // const electra_state = state.electra;
    const balances = state.balances().items;
    const effective_balance_increments = cached_state.getEpochCache().getEffectiveBalanceIncrements();
    for (pre_activation.items) |validator_index| {
        const balance = balances[validator_index];
        state.balances().items[validator_index] = 0;

        const validator = &state.validators().items[validator_index];
        validator.effective_balance = 0;
        effective_balance_increments.items[validator_index] = 0;
        validator.activation_eligibility_epoch = constants.FAR_FUTURE_EPOCH;

        try state.pendingDeposits().append(allocator, .{
            .pubkey = validator.pubkey,
            .withdrawal_credentials = validator.withdrawal_credentials,
            .amount = balance,
            .signature = constants.G2_POINT_AT_INFINITY,
            .slot = constants.GENESIS_SLOT,
        });
    }

    for (validators, 0..) |validator, validator_index| {
        // [EIP-7251]: Ensure early adopters of compounding credentials go through the activation churn
        const withdrawal_credential = validator.withdrawal_credentials;
        if (hasCompoundingWithdrawalCredential(withdrawal_credential)) {
            try queueExcessActiveBalance(allocator, cached_state, validator_index);
        }
    }
}
