const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const ForkSeq = @import("config").ForkSeq;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const types = @import("consensus_types");
const Root = types.primitive.Root.Type;
const preset = @import("preset").preset;

pub fn processHistoricalSummariesUpdate(cached_state: *CachedBeaconState, cache: *const EpochTransitionCache) !void {
    const state = &cached_state.state;
    const next_epoch = cache.current_epoch + 1;

    // set historical root accumulator
    if (next_epoch % @divFloor(preset.SLOTS_PER_HISTORICAL_ROOT, preset.SLOTS_PER_EPOCH) == 0) {
        var block_roots_view = try state.blockRoots();
        var block_summary_root: Root = undefined;
        try block_roots_view.hashTreeRoot(&block_summary_root);

        var state_roots_view = try state.stateRoots();
        var state_summary_root: Root = undefined;
        try state_roots_view.hashTreeRoot(&state_summary_root);

        var historical_summaries = try state.historicalSummaries();
        const summary: types.capella.HistoricalSummary.Type = .{
            .block_summary_root = block_summary_root,
            .state_summary_root = state_summary_root,
        };
        try historical_summaries.pushValue(&summary);
    }
}
