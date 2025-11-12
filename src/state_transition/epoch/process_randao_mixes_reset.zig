const std = @import("std");
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const ForkSeq = @import("config").ForkSeq;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const ct = @import("consensus_types");
const preset = @import("preset").preset;

pub fn processRandaoMixesReset(cached_state: *CachedBeaconStateAllForks, cache: *const EpochTransitionCache) void {
    const state = cached_state.state;
    const current_epoch = cache.current_epoch;
    const next_epoch = current_epoch + 1;

    const state_randao_mixes = state.randaoMixes();
    state_randao_mixes[next_epoch % preset.EPOCHS_PER_HISTORICAL_VECTOR] =
        state_randao_mixes[current_epoch % preset.EPOCHS_PER_HISTORICAL_VECTOR];
}
