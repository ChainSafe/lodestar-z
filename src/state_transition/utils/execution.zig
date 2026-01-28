const std = @import("std");
const ForkSeq = @import("config").ForkSeq;
const ForkTypes = @import("fork_types").ForkTypes;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const ForkBeaconBlock = @import("fork_types").ForkBeaconBlock;
const ForkBeaconBlockBody = @import("fork_types").ForkBeaconBlockBody;
const BlockType = @import("fork_types").BlockType;
// const ExecutionPayloadHeader
const ZERO_HASH = @import("constants").ZERO_HASH;

pub fn isExecutionEnabled(comptime fork: ForkSeq, state: *ForkBeaconState(fork), comptime block_type: BlockType, block: *const ForkBeaconBlock(block_type, fork)) bool {
    if (comptime fork.lt(.bellatrix)) return false;
    if (isMergeTransitionComplete(fork, state)) return true;

    switch (block_type) {
        inline .blinded => {
            return !ForkTypes(fork).ExecutionPayloadHeader.equals(&block.body().inner.execution_payload_header, &ForkTypes(fork).ExecutionPayloadHeader.default_value);
        },
        inline .full => {
            return !ForkTypes(fork).ExecutionPayload.equals(&block.body().inner.execution_payload, &ForkTypes(fork).ExecutionPayload.default_value);
        },
    }
}

pub fn isMergeTransitionBlock(
    comptime fork: ForkSeq,
    state: *ForkBeaconState(fork),
    comptime block_type: BlockType,
    body: *const ForkBeaconBlockBody(fork, block_type),
) bool {
    if (comptime fork != .bellatrix) {
        return false;
    }

    if (isMergeTransitionComplete(fork, state)) {
        return false;
    }

    return switch (block_type) {
        .full => !ForkTypes(fork).ExecutionPayload.equals(
            &body.executionPayload().inner,
            &ForkTypes(fork).ExecutionPayload.default_value,
        ),
        .blinded => !ForkTypes(fork).ExecutionPayloadHeader.equals(
            &body.executionPayloadHeader().inner,
            &ForkTypes(fork).ExecutionPayloadHeader.default_value,
        ),
    };
}

pub fn isMergeTransitionComplete(comptime fork: ForkSeq, state: *ForkBeaconState(fork)) bool {
    if (comptime fork.lt(.bellatrix)) {
        return false;
    }
    const block_hash = state.latestExecutionPayloadHeaderBlockHash() catch return false;
    return !std.mem.eql(u8, block_hash[0..], ZERO_HASH[0..]);
}
