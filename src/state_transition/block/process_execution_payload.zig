const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const ct = @import("consensus_types");
const preset = @import("preset").preset;
const ForkSeq = @import("config").ForkSeq;
const SignedBlock = @import("../types/signed_block.zig").SignedBlock;
const ExecutionPayloadStatus = @import("../state_transition.zig").ExecutionPayloadStatus;
const SignedBlindedBeaconBlock = @import("../types/beacon_block.zig").SignedBlindedBeaconBlock;
const BlockExternalData = @import("../state_transition.zig").BlockExternalData;
const BeaconConfig = @import("config").BeaconConfig;
const isMergeTransitionComplete = @import("../utils/execution.zig").isMergeTransitionComplete;
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;
const getRandaoMix = @import("../utils/seed.zig").getRandaoMix;

const PartialPayload = struct {
    parent_hash: [32]u8 = undefined,
    block_hash: [32]u8 = undefined,
    prev_randao: ct.primitive.Bytes32.Type = undefined,
    timestamp: u64 = undefined,
};

pub fn processExecutionPayload(
    allocator: Allocator,
    cached_state: *const CachedBeaconStateAllForks,
    body: SignedBlock.Body,
    external_data: BlockExternalData,
) !void {
    const state = cached_state.state;
    const epoch_cache = cached_state.getEpochCache();
    const config = epoch_cache.config;
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
        const latest_header = state.latestExecutionPayloadHeader();
        if (!std.mem.eql(u8, &partial_payload.parent_hash, &latest_header.getBlockHash())) {
            return error.InvalidExecutionPayloadParentHash;
        }
    }

    // Verify random
    const expected_random = getRandaoMix(state, epoch_cache.epoch);
    if (!std.mem.eql(u8, &partial_payload.prev_randao, &expected_random)) {
        return error.InvalidExecutionPayloadRandom;
    }

    // Verify timestamp
    //
    // Note: inlined function in if statement
    // def compute_timestamp_at_slot(state: BeaconState, slot: Slot) -> uint64:
    //   slots_since_genesis = slot - GENESIS_SLOT
    //   return uint64(state.genesis_time + slots_since_genesis * SECONDS_PER_SLOT)
    if (partial_payload.timestamp != state.genesisTime() + state.slot() * config.chain.SECONDS_PER_SLOT) {
        return error.InvalidExecutionPayloadTimestamp;
    }

    if (state.isPostDeneb()) {
        const max_blobs_per_block = config.getMaxBlobsPerBlock(computeEpochAtSlot(state.slot()));
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

    const payload_header = switch (body) {
        .regular => |b| try b.executionPayload().toPayloadHeader(allocator),
        .blinded => |b| b.executionPayloadHeader(),
    };

    state.setLatestExecutionPayloadHeader(&payload_header);
}
