const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const preset = @import("preset").preset;
const EPOCHS_PER_ETH1_VOTING_PERIOD = preset.EPOCHS_PER_ETH1_VOTING_PERIOD;

/// Reset eth1DataVotes tree every `EPOCHS_PER_ETH1_VOTING_PERIOD`.
pub fn processEth1DataReset(cached_state: *CachedBeaconState, cache: *const EpochTransitionCache) !void {
    const next_epoch = cache.current_epoch + 1;

    // reset eth1 data votes
    if (next_epoch % EPOCHS_PER_ETH1_VOTING_PERIOD == 0) {
        var state = cached_state.state;
        try state.resetEth1DataVotes();
    }
}
