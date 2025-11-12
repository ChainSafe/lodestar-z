const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const ForkSeq = @import("config").ForkSeq;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const Root = types.primitive.Root.Type;

pub fn processHistoricalRootsUpdate(allocator: Allocator, cached_state: *CachedBeaconStateAllForks, cache: *const EpochTransitionCache) !void {
    const state = cached_state.state;
    const next_epoch = cache.current_epoch + 1;

    // set historical root accumulator
    if (next_epoch % @divFloor(preset.SLOTS_PER_HISTORICAL_ROOT, preset.SLOTS_PER_EPOCH) == 0) {
        var block_roots: Root = undefined;
        try types.phase0.HistoricalBlockRoots.hashTreeRoot(state.blockRoots(), &block_roots);
        var state_roots: Root = undefined;
        try types.phase0.HistoricalStateRoots.hashTreeRoot(state.stateRoots(), &state_roots);
        var root: Root = undefined;
        // HistoricalBatchRoots = Non-spec'ed helper type to allow efficient hashing in epoch transition.
        // This type is like a 'Header' of HistoricalBatch where its fields are hashed.
        try types.phase0.HistoricalBatchRoots.hashTreeRoot(&.{
            .block_roots = block_roots,
            .state_roots = state_roots,
        }, &root);
        const historical_roots = state.historicalRoots();
        try historical_roots.append(allocator, root);
    }
}
