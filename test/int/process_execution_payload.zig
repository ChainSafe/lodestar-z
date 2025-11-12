test "process execution payload - sanity" {
    const allocator = std.testing.allocator;

    var test_state = try TestCachedBeaconStateAllForks.init(allocator, 256);
    defer test_state.deinit();

    var execution_payload: types.electra.ExecutionPayload.Type = types.electra.ExecutionPayload.default_value;
    execution_payload.timestamp = test_state.cached_state.state.genesisTime() + test_state.cached_state.state.slot() * config.mainnet_chain_config.SECONDS_PER_SLOT;
    var body: types.electra.BeaconBlockBody.Type = types.electra.BeaconBlockBody.default_value;
    body.execution_payload = execution_payload;

    var message: types.electra.BeaconBlock.Type = types.electra.BeaconBlock.default_value;
    message.body = body;

    var beacon_block: types.electra.SignedBeaconBlock.Type = types.electra.SignedBeaconBlock.default_value;
    beacon_block.message = message;

    const signed_beacon_block = SignedBeaconBlock{ .electra = &beacon_block };
    const block = SignedBlock{ .regular = &signed_beacon_block };

    try processExecutionPayload(
        allocator,
        test_state.cached_state,
        block.beaconBlockBody(),
        .{ .execution_payload_status = .valid, .data_availability_status = .available },
    );
}

const std = @import("std");
const types = @import("consensus_types");
const config = @import("config");

const state_transition = @import("state_transition");
const TestCachedBeaconStateAllForks = state_transition.test_utils.TestCachedBeaconStateAllForks;
const processExecutionPayload = state_transition.processExecutionPayload;
const SignedBlock = state_transition.SignedBlock;
const SignedBeaconBlock = state_transition.SignedBeaconBlock;
