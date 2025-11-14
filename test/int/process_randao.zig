test "process randao - sanity" {
    const allocator = std.testing.allocator;

    var test_state = try TestCachedBeaconStateAllForks.init(allocator, 256);
    const slot = config.mainnet_chain_config.ELECTRA_FORK_EPOCH * preset.SLOTS_PER_EPOCH + 2025 * preset.SLOTS_PER_EPOCH - 1;
    defer test_state.deinit();

    const proposers = test_state.cached_state.getEpochCache().proposers;

    var message: types.electra.BeaconBlock.Type = types.electra.BeaconBlock.default_value;
    const proposer_index = proposers[slot % preset.SLOTS_PER_EPOCH];

    var header_parent_root: [32]u8 = undefined;
    try types.phase0.BeaconBlockHeader.hashTreeRoot(test_state.cached_state.state.latestBlockHeader(), &header_parent_root);

    message.slot = slot;
    message.proposer_index = proposer_index;
    message.parent_root = header_parent_root;

    const beacon_block = BeaconBlock{ .electra = &message };
    const block = Block{ .regular = beacon_block };
    try processRandao(test_state.cached_state, block.beaconBlockBody(), block.proposerIndex(), false);
}

const std = @import("std");
const types = @import("consensus_types");
const config = @import("config");

const Allocator = std.mem.Allocator;
const state_transition = @import("state_transition");
const TestCachedBeaconStateAllForks = state_transition.test_utils.TestCachedBeaconStateAllForks;

const preset = @import("preset").preset;

const processRandao = state_transition.processRandao;
const Block = state_transition.Block;
const BeaconBlock = state_transition.BeaconBlock;
