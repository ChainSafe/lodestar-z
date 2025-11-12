const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const ct = @import("consensus_types");
const preset = @import("preset").preset;
const GENESIS_EPOCH = @import("preset").GENESIS_EPOCH;
const Slot = ct.primitive.Slot.Type;
const Epoch = ct.primitive.Epoch.Type;
const SyncPeriod = ct.primitive.SyncPeriod.Type;
const BeaconStateAllForks = @import("../types/beacon_state.zig").BeaconStateAllForks;
const Gwei = ct.primitive.Gwei.Type;
const getActivationExitChurnLimit = @import("../utils/validator.zig").getActivationExitChurnLimit;
const getConsolidationChurnLimit = @import("../utils/validator.zig").getConsolidationChurnLimit;

pub fn computeEpochAtSlot(slot: Slot) Epoch {
    return @divFloor(slot, preset.SLOTS_PER_EPOCH);
}

pub fn computeCheckpointEpochAtStateSlot(slot: Slot) Epoch {
    const epoch = computeEpochAtSlot(slot);
    return if (slot % preset.SLOTS_PER_EPOCH == 0)
        epoch
    else
        epoch + 1;
}

pub fn computeStartSlotAtEpoch(epoch: Epoch) Slot {
    return epoch * preset.SLOTS_PER_EPOCH;
}

pub fn computeEndSlotAtEpoch(epoch: Epoch) Slot {
    return computeStartSlotAtEpoch(epoch + 1) - 1;
}

pub fn computeActivationExitEpoch(epoch: Epoch) Epoch {
    return epoch + 1 + preset.MAX_SEED_LOOKAHEAD;
}

pub fn computeExitEpochAndUpdateChurn(cached_state: *const CachedBeaconStateAllForks, exit_balance: Gwei) u64 {
    const state = cached_state.state;
    const epoch_cache = cached_state.getEpochCache();
    const state_earliest_exit_epoch = state.earliestExitEpoch();
    var earliest_exit_epoch = @max(state_earliest_exit_epoch.*, computeActivationExitEpoch(epoch_cache.epoch));
    const per_epoch_churn = getActivationExitChurnLimit(epoch_cache);

    const state_exit_balance_to_consume = state.exitBalanceToConsume();
    // New epoch for exits.
    var exit_balance_to_consume = if (state_earliest_exit_epoch.* < earliest_exit_epoch) per_epoch_churn else state_exit_balance_to_consume.*;

    // Exit doesn't fit in the current earliest epoch.
    if (exit_balance > exit_balance_to_consume) {
        const balance_to_process = exit_balance - exit_balance_to_consume;
        const additional_epochs = @divFloor(balance_to_process - 1, per_epoch_churn) + 1;
        earliest_exit_epoch += additional_epochs;
        exit_balance_to_consume += additional_epochs * per_epoch_churn;
    }

    // Consume the balance and update state variables.
    state_exit_balance_to_consume.* = exit_balance_to_consume - exit_balance;
    state_earliest_exit_epoch.* = earliest_exit_epoch;

    return state_earliest_exit_epoch.*;
}

pub fn computeConsolidationEpochAndUpdateChurn(cached_state: *const CachedBeaconStateAllForks, consolidation_balance: Gwei) u64 {
    const state = cached_state.state;
    const epoch_cache = cached_state.getEpochCache();

    const state_earliest_consolidation_epoch = state.earliestConsolidationEpoch();
    var earliest_consolidation_epoch = @max(state_earliest_consolidation_epoch.*, computeActivationExitEpoch(epoch_cache.epoch));
    const per_epoch_consolidation_churn = getConsolidationChurnLimit(epoch_cache);

    const state_consolidation_balance_to_consume = state.consolidationBalanceToConsume();

    // New epoch for consolidations
    var consolidation_balance_to_consume = if (state_earliest_consolidation_epoch.* < earliest_consolidation_epoch)
        per_epoch_consolidation_churn
    else
        state_consolidation_balance_to_consume.*;

    // Consolidation doesn't fit in the current earliest epoch.
    if (consolidation_balance > consolidation_balance_to_consume) {
        const balance_to_process = consolidation_balance - consolidation_balance_to_consume;
        const additional_epochs = @divFloor(balance_to_process - 1, per_epoch_consolidation_churn) + 1;
        earliest_consolidation_epoch += additional_epochs;
        consolidation_balance_to_consume += additional_epochs * per_epoch_consolidation_churn;
    }

    // Consume the balance and update state variables.
    state_consolidation_balance_to_consume.* = consolidation_balance_to_consume - consolidation_balance;
    state_earliest_consolidation_epoch.* = earliest_consolidation_epoch;

    return state_earliest_consolidation_epoch.*;
}

pub fn getCurrentEpoch(state: BeaconStateAllForks) Epoch {
    return computeEpochAtSlot(state.slot());
}

pub fn getPreviousEpoch(state: BeaconStateAllForks) Epoch {
    const current_epoch = getCurrentEpoch(state);
    return if (current_epoch == GENESIS_EPOCH) GENESIS_EPOCH else current_epoch - 1;
}

pub fn computeSyncPeriodAtSlot(slot: Slot) SyncPeriod {
    return computeSyncPeriodAtEpoch(computeEpochAtSlot(slot));
}

pub fn computeSyncPeriodAtEpoch(epoch: Epoch) SyncPeriod {
    return @divFloor(epoch, preset.EPOCHS_PER_SYNC_COMMITTEE_PERIOD);
}

pub fn isStartSlotOfEpoch(slot: Slot) bool {
    return slot % preset.SLOTS_PER_EPOCH == 0;
}
