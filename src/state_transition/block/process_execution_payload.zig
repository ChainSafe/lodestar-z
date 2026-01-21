const std = @import("std");
const Allocator = std.mem.Allocator;
const ForkSeq = @import("config").ForkSeq;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const BlockType = @import("fork_types").BlockType;
const ForkBeaconBlockBody = @import("fork_types").ForkBeaconBlockBody;
const BlockExternalData = @import("../state_transition.zig").BlockExternalData;
const BeaconConfig = @import("config").BeaconConfig;
const isMergeTransitionComplete = @import("../utils/execution.zig").isMergeTransitionComplete;
const getRandaoMix = @import("../utils/seed.zig").getRandaoMix;

pub fn processExecutionPayload(
    comptime fork: ForkSeq,
    allocator: Allocator,
    config: *const BeaconConfig,
    state: *ForkBeaconState(fork),
    current_epoch: u64,
    comptime block_type: BlockType,
    body: ForkBeaconBlockBody(fork, block_type),
    external_data: BlockExternalData,
) !void {
    const parent_hash, const prev_randao, const timestamp = switch (block_type) {
        .full => .{
            &body.executionPayload().parent_hash,
            &body.executionPayload().prev_randao,
            body.executionPayload().timestamp,
        },
        .blinded => .{
            &body.executionPayloadHeader().parent_hash,
            &body.executionPayloadHeader().prev_randao,
            body.executionPayloadHeader().timestamp,
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
    if (timestamp != (try state.genesisTime()) + (try state.slot()) * config.chain.SECONDS_PER_SLOT) {
        return error.InvalidExecutionPayloadTimestamp;
    }

    if (comptime fork.gte(.deneb)) {
        const max_blobs_per_block = config.getMaxBlobsPerBlock(current_epoch);
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
