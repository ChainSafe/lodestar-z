const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");
const config = @import("config");
const ForkSeq = @import("config").ForkSeq;
const ForkTypes = @import("fork_types").ForkTypes;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const BlockType = @import("fork_types").BlockType;
const AnySignedBeaconBlock = @import("fork_types").AnySignedBeaconBlock;
const ForkBeaconBlock = @import("fork_types").ForkBeaconBlock;
const BeaconBlockHeader = types.phase0.BeaconBlockHeader.Type;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const ZERO_HASH = @import("constants").ZERO_HASH;
const getBeaconProposer = @import("../cache/get_beacon_proposer.zig").getBeaconProposer;
const Node = @import("persistent_merkle_tree").Node;

pub fn processBlockHeader(
    comptime fork: ForkSeq,
    allocator: Allocator,
    epoch_cache: *const EpochCache,
    state: *ForkBeaconState(fork),
    comptime block_type: BlockType,
    block: *const ForkBeaconBlock(block_type, fork),
) !void {
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
    const proposer_index = try getBeaconProposer(fork, epoch_cache, state, slot);
    if (block.proposerIndex() != proposer_index) {
        return error.BlockProposerIndexMismatch;
    }

    // verify that the parent matches
    const header_parent_root = try latest_header_view.hashTreeRoot();
    if (!std.mem.eql(u8, block.parentRoot(), header_parent_root)) {
        return error.BlockParentRootMismatch;
    }

    var body_root: [32]u8 = undefined;
    try block.body().hashTreeRoot(allocator, &body_root);
    // cache current block as the new latest block
    const latest_block_header: BeaconBlockHeader = .{
        .slot = slot,
        .proposer_index = proposer_index,
        .parent_root = block.parentRoot().*,
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

pub fn blockToHeader(allocator: Allocator, signed_block: AnySignedBeaconBlock, out: *BeaconBlockHeader) !void {
    const block = signed_block.beaconBlock();
    out.slot = block.slot();
    out.proposer_index = block.proposerIndex();
    out.parent_root = block.parentRoot().*;
    out.state_root = block.stateRoot().*;
    try block.hashTreeRoot(allocator, &out.body_root);
}

const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const preset = @import("preset").preset;

test "process block header - sanity" {
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();
    const slot = config.mainnet.chain_config.ELECTRA_FORK_EPOCH * preset.SLOTS_PER_EPOCH + 2025 * preset.SLOTS_PER_EPOCH - 1;

    const proposers = test_state.cached_state.getEpochCache().proposers;

    var message: types.electra.BeaconBlock.Type = types.electra.BeaconBlock.default_value;
    const proposer_index = proposers[slot % preset.SLOTS_PER_EPOCH];

    var header = try test_state.cached_state.state.latestBlockHeader();
    const header_parent_root = try header.hashTreeRoot();

    message.slot = slot;
    message.proposer_index = proposer_index;
    message.parent_root = header_parent_root.*;

    const fork_block = ForkBeaconBlock(.full, .electra){ .inner = message };

    try processBlockHeader(
        .electra,
        allocator,
        test_state.cached_state.getEpochCache(),
        test_state.cached_state.state.castToFork(.electra),
        .full,
        &fork_block,
    );
}
