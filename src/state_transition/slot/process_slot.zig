const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const Root = types.primitive.Root.Type;
const ZERO_HASH = @import("constants").ZERO_HASH;

pub fn processSlot(cached_state: *CachedBeaconState) !void {
    const state = cached_state.state;

    // Cache state root
    const previous_state_root = try state.hashTreeRoot();
    const state_roots = try state.stateRoots();
    try state_roots.setValue(state.slot() % preset.SLOTS_PER_HISTORICAL_ROOT, previous_state_root);

    // Cache latest block header state root
    var latest_block_header = state.latestBlockHeader();
    if (std.mem.eql(u8, try latest_block_header.getRoot("state_root"), &ZERO_HASH)) {
        try latest_block_header.setValue("state_root", previous_state_root);
    }

    // Cache block root
    const previous_block_root = try latest_block_header.hashTreeRoot();
    const block_roots = try state.blockRoots();
    try block_roots.setValue(state.slot() % preset.SLOTS_PER_HISTORICAL_ROOT, previous_block_root[0..]);
}
