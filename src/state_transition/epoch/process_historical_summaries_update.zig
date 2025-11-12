const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const ForkSeq = @import("config").ForkSeq;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const types = @import("consensus_types");
const Root = types.primitive.Root.Type;
const preset = @import("preset").preset;

pub fn processHistoricalSummariesUpdate(allocator: Allocator, cached_state: *CachedBeaconStateAllForks, cache: *const EpochTransitionCache) !void {
    const state = cached_state.state;
    const next_epoch = cache.current_epoch + 1;

    // set historical root accumulator
    if (next_epoch % @divFloor(preset.SLOTS_PER_HISTORICAL_ROOT, preset.SLOTS_PER_EPOCH) == 0) {
        var block_summary_root: Root = undefined;
        try types.phase0.HistoricalBlockRoots.hashTreeRoot(state.blockRoots(), &block_summary_root);
        var state_summary_root: Root = undefined;
        try types.phase0.HistoricalStateRoots.hashTreeRoot(state.stateRoots(), &state_summary_root);
        const historical_summaries = state.historicalSummaries();
        try historical_summaries.append(allocator, .{
            .block_summary_root = block_summary_root,
            .state_summary_root = state_summary_root,
        });
    }
}
