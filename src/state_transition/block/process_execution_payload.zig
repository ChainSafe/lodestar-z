const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");
const config = @import("config");
const ForkSeq = config.ForkSeq;
const ForkTypes = @import("fork_types").ForkTypes;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const BlockType = @import("fork_types").BlockType;
const ForkBeaconBlockBody = @import("fork_types").ForkBeaconBlockBody;
const BlockExternalData = @import("../state_transition.zig").BlockExternalData;
const BeaconConfig = config.BeaconConfig;
const isMergeTransitionComplete = @import("../utils/execution.zig").isMergeTransitionComplete;
const getRandaoMix = @import("../utils/seed.zig").getRandaoMix;
const Node = @import("persistent_merkle_tree").Node;

pub fn processExecutionPayload(
    comptime fork: ForkSeq,
    allocator: Allocator,
    beacon_config: *const BeaconConfig,
    state: *ForkBeaconState(fork),
    current_epoch: u64,
    comptime block_type: BlockType,
    body: *const ForkBeaconBlockBody(block_type, fork),
    external_data: BlockExternalData,
) !void {
    const parent_hash, const prev_randao, const timestamp = switch (block_type) {
        .full => .{
            body.executionPayload().parentHash(),
            body.executionPayload().prevRandao(),
            body.executionPayload().timestamp(),
        },
        .blinded => .{
            body.executionPayloadHeader().parentHash(),
            body.executionPayloadHeader().prevRandao(),
            body.executionPayloadHeader().timestamp(),
        },
    };

    // Verify consistency of the parent hash, block number, base fee per gas and gas limit
    // with respect to the previous execution payload header
    if (isMergeTransitionComplete(fork, state)) {
        const latest_block_hash = try state.latestExecutionPayloadHeaderBlockHash();
        if (!std.mem.eql(u8, parent_hash, latest_block_hash)) {
            return error.InvalidExecutionPayloadParentHash;
        }
    }

    // Verify random
    const expected_random = try getRandaoMix(fork, state, current_epoch);
    if (!std.mem.eql(u8, prev_randao, expected_random)) {
        return error.InvalidExecutionPayloadRandom;
    }

    // Verify timestamp
    //
    // Note: inlined function in if statement
    // def compute_timestamp_at_slot(state: BeaconState, slot: Slot) -> uint64:
    //   slots_since_genesis = slot - GENESIS_SLOT
    //   return uint64(state.genesis_time + slots_since_genesis * SECONDS_PER_SLOT)
    if (timestamp != (try state.genesisTime()) + (try state.slot()) * beacon_config.chain.SECONDS_PER_SLOT) {
        return error.InvalidExecutionPayloadTimestamp;
    }

    if (comptime fork.gte(.deneb)) {
        const max_blobs_per_block = beacon_config.getMaxBlobsPerBlock(current_epoch);
        if (body.blobKzgCommitments().len > max_blobs_per_block) {
            return error.BlobKzgCommitmentsExceedsLimit;
        }
    }

    // Verify the execution payload is valid
    //
    // if executionEngine is null, executionEngine.onPayload MUST be called after running processBlock to get the
    // correct randao mix. Since executionEngine will be an async call in most cases it is called afterwards to keep
    // the state transition sync
    //
    // Equivalent to `assert executionEngine.notifyNewPayload(payload)
    if (external_data.execution_payload_status == .pre_merge) {
        return error.ExecutionPayloadStatusPreMerge;
    } else if (external_data.execution_payload_status == .invalid) {
        return error.InvalidExecutionPayload;
    }

    var payload_header = ForkTypes(fork).ExecutionPayloadHeader.default_value;
    switch (block_type) {
        .full => try body.executionPayload().createExecutionPayloadHeader(allocator, &payload_header),
        .blinded => try ForkTypes(fork).ExecutionPayloadHeader.clone(
            allocator,
            &body.executionPayloadHeader().inner,
            &payload_header,
        ),
    }
    defer ForkTypes(fork).ExecutionPayloadHeader.deinit(allocator, &payload_header);

    try state.setLatestExecutionPayloadHeader(&payload_header);
}

const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;

test "process execution payload - sanity" {
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
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

    const fork_body = ForkBeaconBlockBody(.full, .electra){ .inner = body };

    try processExecutionPayload(
        .electra,
        allocator,
        beacon_config,
        test_state.cached_state.state.castToFork(.electra),
        test_state.cached_state.getEpochCache().epoch,
        .full,
        &fork_body,
        .{ .execution_payload_status = .valid, .data_availability_status = .available },
    );
}

test "process execution payload - blinded" {
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    const beacon_config = test_state.cached_state.config;

    var body: types.electra.BlindedBeaconBlockBody.Type = types.electra.BlindedBeaconBlockBody.default_value;
    body.execution_payload_header.timestamp = try test_state.cached_state.state.genesisTime() +
        try test_state.cached_state.state.slot() * beacon_config.chain.SECONDS_PER_SLOT;
    try body.execution_payload_header.extra_data.appendSlice(allocator, &[_]u8{ 0x01, 0x02, 0x03 });
    defer types.electra.BlindedBeaconBlockBody.deinit(allocator, &body);

    const fork_body = ForkBeaconBlockBody(.blinded, .electra){ .inner = body };

    try processExecutionPayload(
        .electra,
        allocator,
        beacon_config,
        test_state.cached_state.state.castToFork(.electra),
        test_state.cached_state.getEpochCache().epoch,
        .blinded,
        &fork_body,
        .{ .execution_payload_status = .valid, .data_availability_status = .available },
    );
}
