const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const BeaconBlock = @import("../types/beacon_block.zig").BeaconBlock;
const BeaconConfig = @import("config").BeaconConfig;
const BeaconBlockHeader = types.phase0.BeaconBlockHeader.Type;
const Root = types.primitive.Root;
const SignedBlock = @import("../types/block.zig").SignedBlock;
const ZERO_HASH = @import("constants").ZERO_HASH;
const Block = @import("../types/block.zig").Block;

pub fn processBlockHeader(allocator: Allocator, cached_state: *CachedBeaconState, block: Block) !void {
    const state = cached_state.state;
    const slot = try state.slot();

    // verify that the slots match
    if (block.slot() != slot) {
        return error.BlockSlotMismatch;
    }

    // Verify that the block is newer than latest block header
    var latest_header_view = try state.latestBlockHeader();
    const latest_header_slot = try latest_header_view.get("slot");
    if (!(block.slot() > latest_header_slot)) {
        return error.BlockNotNewerThanLatestHeader;
    }

    // verify that proposer index is the correct index
    const proposer_index = try cached_state.getBeaconProposer(slot);
    if (block.proposerIndex() != proposer_index) {
        return error.BlockProposerIndexMismatch;
    }

    // verify that the parent matches
    const header_parent_root = try latest_header_view.hashTreeRoot();
    if (!std.mem.eql(u8, &block.parentRoot(), header_parent_root)) {
        return error.BlockParentRootMismatch;
    }
    var body_root: [32]u8 = undefined;
    try block.beaconBlockBody().hashTreeRoot(allocator, &body_root);
    // cache current block as the new latest block
    const latest_block_header: BeaconBlockHeader = .{
        .slot = slot,
        .proposer_index = proposer_index,
        .parent_root = block.parentRoot(),
        .state_root = ZERO_HASH,
        .body_root = body_root,
    };
    try state.setLatestBlockHeader(&latest_block_header);

    // verify proposer is not slashed. Only once per block, may use the slower read from tree
    var validators_view = try state.validators();
    var proposer_validator_view = try validators_view.get(proposer_index);
    const proposer_slashed = try proposer_validator_view.get("slashed");
    if (proposer_slashed) {
        return error.BlockProposerSlashed;
    }
}

pub fn blockToHeader(allocator: Allocator, signed_block: SignedBlock, out: *BeaconBlockHeader) !void {
    const block = signed_block.message();
    out.slot = block.slot();
    out.proposer_index = block.proposerIndex();
    out.parent_root = block.parentRoot();
    out.state_root = block.stateRoot();
    try block.hashTreeRoot(allocator, &out.body_root);
}
