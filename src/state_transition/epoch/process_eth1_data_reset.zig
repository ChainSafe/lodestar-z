const types = @import("consensus_types");
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const preset = @import("preset").preset;
const EPOCHS_PER_ETH1_VOTING_PERIOD = preset.EPOCHS_PER_ETH1_VOTING_PERIOD;

/// Reset eth1DataVotes tree every `EPOCHS_PER_ETH1_VOTING_PERIOD`.
pub fn processEth1DataReset(cached_state: *CachedBeaconState, cache: *const EpochTransitionCache) !void {
    const next_epoch = cache.current_epoch + 1;

    // reset eth1 data votes
    if (next_epoch % EPOCHS_PER_ETH1_VOTING_PERIOD == 0) {
        const state = &cached_state.state;
        // TODO: Provide a "default view" API (default TreeView / DU) so callers don't have to
        // manually build a TreeView from `default_value` to reset fields.
        var votes = try state.eth1DataVotes();

        const VotesST = types.phase0.Eth1DataVotes;
        const empty_root = try VotesST.tree.fromValue(votes.base_view.pool, &VotesST.default_value);
        errdefer votes.base_view.pool.unref(empty_root);
        const empty_view = try VotesST.TreeView.init(
            votes.base_view.allocator,
            votes.base_view.pool,
            empty_root,
        );

        try state.setEth1DataVotes(empty_view);
    }
}
