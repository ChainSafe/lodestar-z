const Allocator = @import("std").mem.Allocator;
const types = @import("consensus_types");
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const preset = @import("preset").preset;
const EPOCHS_PER_ETH1_VOTING_PERIOD = preset.EPOCHS_PER_ETH1_VOTING_PERIOD;

/// Reset eth1DataVotes tree every `EPOCHS_PER_ETH1_VOTING_PERIOD`.
pub fn processEth1DataReset(allocator: Allocator, cached_state: *CachedBeaconState, cache: *const EpochTransitionCache) void {
    const next_epoch = cache.current_epoch + 1;

    // reset eth1 data votes
    if (next_epoch % EPOCHS_PER_ETH1_VOTING_PERIOD == 0) {
        const state = cached_state.state;
        const state_eth1_data_votes = state.eth1DataVotes();
        state_eth1_data_votes.clearAndFree(allocator);
    }
}
