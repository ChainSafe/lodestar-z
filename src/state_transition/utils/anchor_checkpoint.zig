const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");
const BeaconState = @import("../types/beacon_state.zig").BeaconState;
const BeaconBlock = @import("../types/beacon_block.zig").BeaconBlock;
const c = @import("constants");
const ZERO_HASH = c.ZERO_HASH;
const computeCheckpointEpochAtStateSlot = @import("./epoch.zig").computeCheckpointEpochAtStateSlot;

pub const AnchorCheckpoint = struct {
    checkpoint: types.phase0.Checkpoint.Type,
    block_header: types.phase0.BeaconBlockHeader.Type,
};

/// Compute the anchor checkpoint for a given state.
/// Returns both the checkpoint and block header.
pub fn computeAnchorCheckpoint(allocator: Allocator, state: *BeaconState) !AnchorCheckpoint {
    const slot = try state.slot();
    var header: types.phase0.BeaconBlockHeader.Type = undefined;
    var root: [32]u8 = undefined;

    if (slot == c.GENESIS_SLOT) {
        // At genesis, create header from default block (no SignedBlock exists)
        const block = BeaconBlock.defaultValue(state.forkSeq());
        try block.beaconBlockBody().hashTreeRoot(allocator, &header.body_root);
        header.slot = block.slot();
        header.proposer_index = block.proposerIndex();
        header.parent_root = block.parentRoot();
        header.state_root = (try state.hashTreeRoot()).*;
        try types.phase0.BeaconBlockHeader.hashTreeRoot(&header, &root);
    } else {
        // After genesis, clone latestBlockHeader
        var latest_block_header = try state.latestBlockHeader();
        try latest_block_header.toValue(allocator, &header);

        if (std.mem.eql(u8, &header.state_root, &ZERO_HASH)) {
            header.state_root = (try state.hashTreeRoot()).*;
        }
        try types.phase0.BeaconBlockHeader.hashTreeRoot(&header, &root);
    }

    const checkpoint_epoch = computeCheckpointEpochAtStateSlot(slot);

    return AnchorCheckpoint{
        .checkpoint = .{
            .epoch = checkpoint_epoch,
            .root = root,
        },
        .block_header = header,
    };
}
