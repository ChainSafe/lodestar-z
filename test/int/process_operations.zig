test "process operations" {
    const allocator = std.testing.allocator;

    var test_state = try TestCachedBeaconState.init(allocator, 256);
    defer test_state.deinit();

    const electra_block = types.electra.BeaconBlock.default_value;
    const beacon_block = BeaconBlock{ .electra = &electra_block };

    const block = Block{ .regular = beacon_block };
    try processOperations(allocator, test_state.cached_state, block.beaconBlockBody(), .{});
}

const std = @import("std");
const types = @import("consensus_types");

const state_transition = @import("state_transition");
const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
const processOperations = state_transition.processOperations;
const Block = state_transition.Block;
const BeaconBlock = state_transition.BeaconBlock;
