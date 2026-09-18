//! Tests for `process_execution_payload.zig`.

const std = @import("std");
const types = @import("consensus_types");
const config = @import("config");
const BeaconBlockBody = @import("fork_types").BeaconBlockBody;
const Node = @import("persistent_merkle_tree").Node;
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const processExecutionPayload = @import("process_execution_payload.zig").processExecutionPayload;

test "process execution payload - sanity" {
    const allocator = std.testing.allocator;
    const pool_size = 180_000;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = pool_size });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var execution_payload: types.electra.ExecutionPayload.Type = types.electra.ExecutionPayload.default_value;
    const beacon_config = test_state.cached_state.config;
    execution_payload.timestamp = try test_state.cached_state.state.genesisTime() + try test_state.cached_state.state.slot() * beacon_config.chain.SECONDS_PER_SLOT;
    var body: types.electra.BeaconBlockBody.Type = types.electra.BeaconBlockBody.default_value;
    body.execution_payload = execution_payload;

    var message: types.electra.BeaconBlock.Type = types.electra.BeaconBlock.default_value;
    message.body = body;

    const fork_body = BeaconBlockBody(.full, .electra){ .inner = body };

    try processExecutionPayload(
        .electra,
        allocator,
        beacon_config,
        test_state.cached_state.state.castToFork(.electra),
        test_state.cached_state.epoch_cache.epoch,
        .full,
        &fork_body,
        .{ .execution_payload_status = .valid, .data_availability_status = .available },
    );
}

test "process execution payload - blinded" {
    const allocator = std.testing.allocator;
    const pool_size = 180_000;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = pool_size });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    const beacon_config = test_state.cached_state.config;

    var body: types.electra.BlindedBeaconBlockBody.Type = types.electra.BlindedBeaconBlockBody.default_value;
    body.execution_payload_header.timestamp = try test_state.cached_state.state.genesisTime() +
        try test_state.cached_state.state.slot() * beacon_config.chain.SECONDS_PER_SLOT;
    try body.execution_payload_header.extra_data.appendSlice(allocator, &[_]u8{ 0x01, 0x02, 0x03 });
    defer types.electra.BlindedBeaconBlockBody.deinit(allocator, &body);

    const fork_body = BeaconBlockBody(.blinded, .electra){ .inner = body };

    try processExecutionPayload(
        .electra,
        allocator,
        beacon_config,
        test_state.cached_state.state.castToFork(.electra),
        test_state.cached_state.epoch_cache.epoch,
        .blinded,
        &fork_body,
        .{ .execution_payload_status = .valid, .data_availability_status = .available },
    );
}
