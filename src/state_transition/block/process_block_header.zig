const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");
const config = @import("config");
const ForkSeq = @import("config").ForkSeq;
const ForkTypes = @import("fork_types").ForkTypes;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const BlockType = @import("fork_types").BlockType;
const ForkBeaconBlock = @import("fork_types").ForkBeaconBlock;
const BeaconBlockHeader = types.phase0.BeaconBlockHeader.Type;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const ZERO_HASH = @import("constants").ZERO_HASH;
const getBeaconProposer = @import("../cache/get_beacon_proposer.zig").getBeaconProposer;
const SignedBlock = @import("../types/block.zig").SignedBlock;

pub fn processBlockHeader(
    comptime fork: ForkSeq,
    allocator: Allocator,
    epoch_cache: *const EpochCache,
    state: *ForkBeaconState(fork),
    comptime block_type: BlockType,
    block: ForkBeaconBlock(fork, block_type),
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
    try ForkTypes(fork).BeaconBlockBody.hashTreeRoot(allocator, block.body(), &body_root);
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
    out.state_root = switch (block) {
        .regular => |b| b.stateRoot(),
        .blinded => |b| b.stateRoot(),
    };
    try block.hashTreeRoot(allocator, &out.body_root);
}

const BeaconBlock = @import("../types/beacon_block.zig").BeaconBlock;
const Block = @import("../types/block.zig").Block;
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const preset = @import("preset").preset;
const Node = @import("persistent_merkle_tree").Node;

test "process block header - sanity" {
    const allocator = std.testing.allocator;

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    const slot = config.mainnet.chain_config.ELECTRA_FORK_EPOCH * preset.SLOTS_PER_EPOCH + 2025 * preset.SLOTS_PER_EPOCH - 1;
    defer test_state.deinit();

    const proposers = test_state.cached_state.getEpochCache().proposers;

    var message: types.electra.BeaconBlock.Type = types.electra.BeaconBlock.default_value;
    const proposer_index = proposers[slot % preset.SLOTS_PER_EPOCH];

    var header = try test_state.cached_state.state.latestBlockHeader();
    const header_parent_root = try header.hashTreeRoot();

    message.slot = slot;
    message.proposer_index = proposer_index;
    message.parent_root = header_parent_root.*;

    const beacon_block = BeaconBlock{ .electra = &message };
    const block = Block{ .regular = beacon_block };

    const fork_state = switch (test_state.cached_state.state.*) {
        .electra => |*state_view| @as(*ForkBeaconState(.electra), @ptrCast(state_view)),
        else => return error.UnexpectedForkSeq,
    };
    var fork_block = ForkBeaconBlock(.electra, .full){ .inner = message };

    try processBlockHeader(.electra, allocator, test_state.cached_state.getEpochCache(), fork_state, .full, fork_block);
}
