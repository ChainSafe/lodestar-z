const std = @import("std");
const AnyBeaconState = @import("fork_types").AnyBeaconState;
const preset = @import("preset").preset;
const ZERO_HASH = @import("constants").ZERO_HASH;

pub fn processSlot(state: *AnyBeaconState) !void {

    // Cache state root
    const previous_state_root = try state.hashTreeRoot();
    var state_roots = try state.stateRoots();
    try state_roots.setValue(try state.slot() % preset.SLOTS_PER_HISTORICAL_ROOT, previous_state_root);

    // Cache latest block header state root
    var latest_block_header = try state.latestBlockHeader();
    var latest_header_state_root = try latest_block_header.getRoot("state_root");

    if (std.mem.eql(u8, latest_header_state_root[0..], ZERO_HASH[0..])) {
        try latest_block_header.setValue("state_root", previous_state_root);
    }

    // Cache block root
    const previous_block_root = try latest_block_header.hashTreeRoot();
    var block_roots = try state.blockRoots();
    try block_roots.setValue(try state.slot() % preset.SLOTS_PER_HISTORICAL_ROOT, previous_block_root[0..]);
}
