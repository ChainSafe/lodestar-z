const std = @import("std");
const ForkSeq = @import("config").ForkSeq;
const ForkTypes = @import("fork_types").ForkTypes;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const ForkBeaconBlock = @import("fork_types").ForkBeaconBlock;
const BlockType = @import("fork_types").BlockType;
const types = @import("consensus_types");
// const ExecutionPayloadHeader
const ZERO_HASH = @import("constants").ZERO_HASH;

pub fn isExecutionEnabled(comptime fork: ForkSeq, state: *ForkBeaconState(fork), comptime block_type: BlockType, block: *const ForkBeaconBlock(fork, block_type)) bool {
    if (comptime fork.lt(.bellatrix)) return false;
    if (isMergeTransitionComplete(fork, state)) return true;

    switch (block_type) {
        inline .blinded => {
            return ForkTypes(fork).ExecutionPayloadHeader.equals(&block.body().execution_payload_header, &ForkTypes(fork).ExecutionPayloadHeader.default_value);
        },
        inline .full => {
            return ForkTypes(fork).ExecutionPayload.equals(&block.body().execution_payload, &ForkTypes(fork).ExecutionPayload.default_value);
        },
    }
}

pub fn isMergeTransitionBlock(
    comptime fork: ForkSeq,
    state: *ForkBeaconState(fork),
    body: *const ForkTypes(fork).BeaconBlockBody.Type,
) bool {
    if (comptime fork != .bellatrix) {
        return false;
    }

    return (!isMergeTransitionComplete(fork, state) and
        !ForkTypes(fork).ExecutionPayload.equals(&body.execution_payload, &types.bellatrix.ExecutionPayload.default_value));
}

pub fn isMergeTransitionComplete(comptime fork: ForkSeq, state: *ForkBeaconState(fork)) bool {
    if (comptime fork.lt(.bellatrix)) {
        return false;
    }
    const block_hash = state.latestExecutionPayloadHeaderBlockHash() catch return false;
    return !std.mem.eql(u8, block_hash[0..], ZERO_HASH[0..]);
}
