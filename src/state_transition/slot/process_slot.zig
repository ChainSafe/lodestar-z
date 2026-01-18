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
    var state_roots = try state.stateRoots();
    try state_roots.setValue(try state.slot() % preset.SLOTS_PER_HISTORICAL_ROOT, previous_state_root);

    // Cache latest block header state root
    var latest_block_header = try state.latestBlockHeader();
    var latest_header_state_root: [32]u8 = undefined;
    try latest_block_header.getValue(cached_state.allocator, "state_root", &latest_header_state_root);

    if (std.mem.eql(u8, latest_header_state_root[0..], ZERO_HASH[0..])) {
        try latest_block_header.setValue("state_root", previous_state_root);
    }

    // Cache block root
    const previous_block_root = try latest_block_header.hashTreeRoot();
    var block_roots = try state.blockRoots();
    try block_roots.setValue(try state.slot() % preset.SLOTS_PER_HISTORICAL_ROOT, previous_block_root[0..]);
}
