test "process eth1 data - sanity" {
    const allocator = std.testing.allocator;

    var test_state = try TestCachedBeaconStateAllForks.init(allocator, 256);
    defer test_state.deinit();

    const block = types.electra.BeaconBlock.default_value;
    try processEth1Data(allocator, test_state.cached_state, &block.body.eth1_data);
}

const std = @import("std");
const types = @import("consensus_types");

const state_transition = @import("state_transition");
const TestCachedBeaconStateAllForks = state_transition.test_utils.TestCachedBeaconStateAllForks;
const processEth1Data = state_transition.processEth1Data;
const SignedBlock = state_transition.SignedBlock;
const SignedBeaconBlock = state_transition.SignedBeaconBlock;
