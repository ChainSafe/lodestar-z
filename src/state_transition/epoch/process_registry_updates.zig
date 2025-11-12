const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const types = @import("consensus_types");
const Epoch = types.primitive.Epoch.Type;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const ForkSeq = @import("config").ForkSeq;
const computeActivationExitEpoch = @import("../utils/epoch.zig").computeActivationExitEpoch;
const initiateValidatorExit = @import("../block/initiate_validator_exit.zig").initiateValidatorExit;

pub fn processRegistryUpdates(cached_state: *CachedBeaconStateAllForks, cache: *const EpochTransitionCache) !void {
    const epoch_cache = cached_state.getEpochCache();
    const state = cached_state.state;

    // Get the validators sub tree once for all the loop
    const validators = state.validators();

    // TODO: Batch set this properties in the tree at once with setMany() or setNodes()

    // process ejections
    for (cache.indices_to_eject.items) |index| {
        // set validator exit epoch and withdrawable epoch
        // TODO: Figure out a way to quickly set properties on the validators tree
        const validator = &validators.items[index];
        try initiateValidatorExit(cached_state, validator);
    }

    // set new activation eligibilities
    for (cache.indices_eligible_for_activation_queue.items) |index| {
        validators.items[index].activation_eligibility_epoch = epoch_cache.epoch + 1;
    }

    const finality_epoch = state.finalizedCheckpoint().epoch;
    const len = if (state.isPreElectra()) @min(cache.indices_eligible_for_activation.items.len, epoch_cache.activation_churn_limit) else cache.indices_eligible_for_activation.items.len;
    const activation_epoch = computeActivationExitEpoch(cache.current_epoch);

    // dequeue validators for activation up to churn limit
    for (0..len) |i| {
        const validator_index = cache.indices_eligible_for_activation.items[i];
        const validator = &validators.items[validator_index];
        // placement in queue is finalized
        if (validator.activation_eligibility_epoch > finality_epoch) {
            // remaining validators all have an activationEligibilityEpoch that is higher anyway, break early
            // activationEligibilityEpoch has been sorted in epoch process in ascending order.
            // At that point the finalityEpoch was not known because processJustificationAndFinalization() wasn't called yet.
            // So we need to filter by finalityEpoch here to comply with the spec.
            break;
        }
        validator.activation_epoch = activation_epoch;
    }
}
