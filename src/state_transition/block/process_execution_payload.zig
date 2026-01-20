const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const config = @import("config");
const ForkSeq = config.ForkSeq;
const SignedBlock = @import("../types/block.zig").SignedBlock;
const Body = @import("../types/block.zig").Body;
const ExecutionPayloadStatus = @import("../state_transition.zig").ExecutionPayloadStatus;
const ExecutionPayloadHeader = @import("../types/execution_payload.zig").ExecutionPayloadHeader;
const SignedBlindedBeaconBlock = @import("../types/beacon_block.zig").SignedBlindedBeaconBlock;
const BlockExternalData = @import("../state_transition.zig").BlockExternalData;
const BeaconConfig = config.BeaconConfig;
const isMergeTransitionComplete = @import("../utils/execution.zig").isMergeTransitionComplete;
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;
const getRandaoMix = @import("../utils/seed.zig").getRandaoMix;

const PartialPayload = struct {
    parent_hash: [32]u8 = undefined,
    block_hash: [32]u8 = undefined,
    prev_randao: types.primitive.Bytes32.Type = undefined,
    timestamp: u64 = undefined,
};

pub fn processExecutionPayload(
    allocator: Allocator,
    cached_state: *CachedBeaconState,
    body: Body,
    external_data: BlockExternalData,
) !void {
    const state = cached_state.state;
    const epoch_cache = cached_state.getEpochCache();
    var partial_payload = PartialPayload{};
    switch (body) {
        .regular => |b| {
            partial_payload = .{
                .parent_hash = b.executionPayload().getParentHash(),
                .block_hash = b.executionPayload().getBlockHash(),
                .prev_randao = b.executionPayload().getPrevRandao(),
                .timestamp = b.executionPayload().getTimestamp(),
            };
        },
        .blinded => |b| {
            partial_payload = .{
                .parent_hash = b.executionPayloadHeader().getParentHash(),
                .block_hash = b.executionPayloadHeader().getBlockHash(),
                .prev_randao = b.executionPayloadHeader().getPrevRandao(),
                .timestamp = b.executionPayloadHeader().getTimestamp(),
            };
        },
    }

    // Verify consistency of the parent hash, block number, base fee per gas and gas limit
    // with respect to the previous execution payload header
    if (isMergeTransitionComplete(state)) {
        const latest_block_hash = try state.latestExecutionPayloadHeaderBlockHash();
        if (!std.mem.eql(u8, &partial_payload.parent_hash, latest_block_hash)) {
            return error.InvalidExecutionPayloadParentHash;
        }
    }

    // Verify random
    const expected_random = try getRandaoMix(state, epoch_cache.epoch);
    if (!std.mem.eql(u8, &partial_payload.prev_randao, expected_random)) {
        return error.InvalidExecutionPayloadRandom;
    }

    // Verify timestamp
    //
    // Note: inlined function in if statement
    // def compute_timestamp_at_slot(state: BeaconState, slot: Slot) -> uint64:
    //   slots_since_genesis = slot - GENESIS_SLOT
    //   return uint64(state.genesis_time + slots_since_genesis * SECONDS_PER_SLOT)
    if (partial_payload.timestamp != try state.genesisTime() + try state.slot() * config.mainnet.chain_config.SECONDS_PER_SLOT) {
        return error.InvalidExecutionPayloadTimestamp;
    }

    if (state.forkSeq().gte(.deneb)) {
        const max_blobs_per_block = config.mainnet.config.getMaxBlobsPerBlock(computeEpochAtSlot(try state.slot()));
        if (body.blobKzgCommitmentsLen() > max_blobs_per_block) {
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

    var payload_header = try ExecutionPayloadHeader.init(state.forkSeq());
    switch (body) {
        .regular => |b| try b.executionPayload().createPayloadHeader(allocator, &payload_header),
        .blinded => |b| try b.executionPayloadHeader().clone(allocator, &payload_header),
    }
    defer payload_header.deinit(allocator);

    try state.setLatestExecutionPayloadHeader(&payload_header);
}

const BeaconBlock = @import("../types/beacon_block.zig").BeaconBlock;
const Block = @import("../types/block.zig").Block;
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const Node = @import("persistent_merkle_tree").Node;

test "process execution payload - sanity" {
    const allocator = std.testing.allocator;

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var execution_payload: types.electra.ExecutionPayload.Type = types.electra.ExecutionPayload.default_value;
    execution_payload.timestamp = try test_state.cached_state.state.genesisTime() + try test_state.cached_state.state.slot() * config.mainnet.chain_config.SECONDS_PER_SLOT;
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
