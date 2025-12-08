const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const BeaconBlock = @import("../types/beacon_block.zig").BeaconBlock;
const BeaconConfig = @import("config").BeaconConfig;
const BeaconBlockHeader = types.phase0.BeaconBlockHeader.Type;
const Root = types.primitive.Root;
const SignedBlock = @import("../types/block.zig").SignedBlock;
const ZERO_HASH = @import("constants").ZERO_HASH;
const Block = @import("../types/block.zig").Block;

pub fn processBlockHeader(allocator: Allocator, cached_state: *const CachedBeaconStateAllForks, block: Block) !void {
    const state = cached_state.state;
    const slot = state.slot();

    // verify that the slots match
    if (block.slot() != slot) {
        return error.BlockSlotMismatch;
    }

    // Verify that the block is newer than latest block header
    if (!(block.slot() > state.latestBlockHeader().slot)) {
        return error.BlockNotNewerThanLatestHeader;
    }

    // verify that proposer index is the correct index
    const proposer_index = try cached_state.getBeaconProposer(slot);
    if (block.proposerIndex() != proposer_index) {
        return error.BlockProposerIndexMismatch;
    }

    // verify that the parent matches
    var header_parent_root: [32]u8 = undefined;
    try types.phase0.BeaconBlockHeader.hashTreeRoot(state.latestBlockHeader(), &header_parent_root);
    if (!std.mem.eql(u8, &block.parentRoot(), &header_parent_root)) {
        return error.BlockParentRootMismatch;
    }
    var body_root: [32]u8 = undefined;
    try block.beaconBlockBody().hashTreeRoot(allocator, &body_root);
    // cache current block as the new latest block
    const state_latest_block_header = state.latestBlockHeader();
    const latest_block_header: BeaconBlockHeader = .{
        .slot = slot,
        .proposer_index = proposer_index,
        .parent_root = block.parentRoot(),
        .state_root = ZERO_HASH,
        .body_root = body_root,
    };
    state_latest_block_header.* = latest_block_header;

    // verify proposer is not slashed. Only once per block, may use the slower read from tree
    if (state.validators().items[proposer_index].slashed) {
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
