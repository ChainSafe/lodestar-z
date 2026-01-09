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

    var header_parent_root: [32]u8 = undefined;
    var latest_header_view = try test_state.cached_state.state.latestBlockHeader();
    try latest_header_view.hashTreeRoot(&header_parent_root);

    message.slot = slot;
    message.proposer_index = proposer_index;
    message.parent_root = header_parent_root;

    const beacon_block = BeaconBlock{ .electra = &message };

    const block = Block{ .regular = beacon_block };
    try processBlockHeader(allocator, test_state.cached_state, block);
}

const std = @import("std");
const types = @import("consensus_types");
const config = @import("config");
const state_transition = @import("state_transition");
const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
const preset = @import("preset").preset;
const processBlockHeader = state_transition.processBlockHeader;
const Block = state_transition.Block;
const BeaconBlock = state_transition.BeaconBlock;
const Node = @import("persistent_merkle_tree").Node;
