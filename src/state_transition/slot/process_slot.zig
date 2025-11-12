const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const ct = @import("consensus_types");
const preset = @import("preset").preset;
const Root = ct.primitive.Root.Type;
const ZERO_HASH = @import("constants").ZERO_HASH;

pub fn processSlot(allocator: Allocator, cached_state: *CachedBeaconStateAllForks) !void {
    const state = cached_state.state;

    // Cache state root
    var previous_state_root: Root = undefined;
    try state.hashTreeRoot(allocator, &previous_state_root);
    const state_roots = state.stateRoots();
    @memcpy(state_roots[state.slot() % preset.SLOTS_PER_HISTORICAL_ROOT][0..], previous_state_root[0..]);

    // Cache latest block header state root
    var latest_block_header = state.latestBlockHeader();
    if (std.mem.eql(u8, &latest_block_header.state_root, &ZERO_HASH)) {
        latest_block_header.state_root = previous_state_root;
    }

    // Cache block root
    var previous_block_root: Root = undefined;
    try ct.phase0.BeaconBlockHeader.hashTreeRoot(latest_block_header, &previous_block_root);
    const block_roots = state.blockRoots();
    @memcpy(block_roots[state.slot() % preset.SLOTS_PER_HISTORICAL_ROOT][0..], previous_block_root[0..]);
}
