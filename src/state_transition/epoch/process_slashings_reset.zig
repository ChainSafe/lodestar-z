const std = @import("std");
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const ForkSeq = @import("config").ForkSeq;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const ct = @import("consensus_types");
const preset = @import("preset").preset;

/// Resets slashings for the next epoch.
/// PERF: Almost no (constant) cost
pub fn processSlashingsReset(cached_state: *CachedBeaconStateAllForks, cache: *const EpochTransitionCache) void {
    const state = cached_state.state;
    const epoch_cache = cached_state.getEpochCache();
    const next_epoch = cache.current_epoch + 1;

    // reset slashings
    const slash_index = next_epoch % preset.EPOCHS_PER_SLASHINGS_VECTOR;
    const slashings = state.slashings();
    const slashing = slashings[slash_index];
    const old_slashing_value_by_increment = slashing / preset.EFFECTIVE_BALANCE_INCREMENT;
    slashings[slash_index] = 0;
    epoch_cache.total_slashings_by_increment = @max(0, epoch_cache.total_slashings_by_increment - old_slashing_value_by_increment);
}
