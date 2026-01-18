const Node = @import("persistent_merkle_tree").Node;

test "process execution payload - sanity" {
    const allocator = std.testing.allocator;

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var execution_payload: types.electra.ExecutionPayload.Type = types.electra.ExecutionPayload.default_value;
    execution_payload.timestamp = (try test_state.cached_state.state.genesisTime()) + (try test_state.cached_state.state.slot()) * config.mainnet.chain_config.SECONDS_PER_SLOT;
    var body: types.electra.BeaconBlockBody.Type = types.electra.BeaconBlockBody.default_value;
    body.execution_payload = execution_payload;

    var message: types.electra.BeaconBlock.Type = types.electra.BeaconBlock.default_value;
    message.body = body;

    const beacon_block = BeaconBlock{ .electra = &message };
    const block = Block{ .regular = beacon_block };

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
const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
const processExecutionPayload = state_transition.processExecutionPayload;
const SignedBlock = state_transition.SignedBlock;
const Block = state_transition.Block;
const SignedBeaconBlock = state_transition.SignedBeaconBlock;
const BeaconBlock = state_transition.BeaconBlock;
