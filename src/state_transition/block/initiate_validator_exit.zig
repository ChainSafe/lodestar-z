const std = @import("std");
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const ForkSeq = @import("config").ForkSeq;
const types = @import("consensus_types");
const Validator = types.phase0.Validator.Type;
const c = @import("constants");
const FAR_FUTURE_EPOCH = c.FAR_FUTURE_EPOCH;
const computeExitEpochAndUpdateChurn = @import("../utils/epoch.zig").computeExitEpochAndUpdateChurn;

/// Initiate the exit of the validator with index ``index``
///
/// NOTE: This function takes a `validator` as argument instead of the validator index.
/// SSZ TreeViews have a dangerous edge case that may break the code here in a non-obvious way.
/// When running `state.validators[i]` you get a SubTree of that validator with a hook to the state.
/// Then, when a property of `validator` is set it propagates the changes upwards to the parent tree up to the state.
/// This means that `validator` will propagate its new state along with the current state of its parent tree up to
/// the state, potentially overwriting changes done in other SubTrees before.
/// ```ts
/// // default state.validators, all zeroes
/// const validatorsA = state.validators
/// const validatorsB = state.validators
/// validatorsA[0].exitEpoch = 9
/// validatorsB[0].exitEpoch = 9 // Setting a value in validatorsB will overwrite all changes from validatorsA
/// // validatorsA[0].exitEpoch is 0
/// // validatorsB[0].exitEpoch is 9
/// ```
/// Forcing consumers to pass the SubTree of `validator` directly mitigates this issue.
///
pub fn initiateValidatorExit(cached_state: *const CachedBeaconState, validator: *Validator) !void {
    const config = cached_state.config.chain;
    const epoch_cache = cached_state.getEpochCache();
    const state = cached_state.state;

    // return if validator already initiated exit
    if (validator.exit_epoch != FAR_FUTURE_EPOCH) {
        return;
    }

    if (state.isPreElectra()) {
        // Limits the number of validators that can exit on each epoch.
        // Expects all state.validators to follow this rule, i.e. no validator.exitEpoch is greater than exitQueueEpoch.
        // If there the churnLimit is reached at this current exitQueueEpoch, advance epoch and reset churn.
        if (epoch_cache.exit_queue_churn >= epoch_cache.churn_limit) {
            epoch_cache.exit_queue_epoch += 1;
            // = 1 to account for this validator with exitQueueEpoch
            epoch_cache.exit_queue_churn = 1;
        } else {
            // Add this validator to the current exitQueueEpoch churn
            epoch_cache.exit_queue_churn += 1;
        }

        // set validator exit epoch
        validator.exit_epoch = epoch_cache.exit_queue_epoch;
    } else {
        // set validator exit epoch
        // Note we don't use epochCtx.exitQueueChurn and exitQueueEpoch anymore
        validator.exit_epoch = computeExitEpochAndUpdateChurn(cached_state, validator.effective_balance);
    }

    validator.withdrawable_epoch = try std.math.add(u64, validator.exit_epoch, config.MIN_VALIDATOR_WITHDRAWABILITY_DELAY);
}
