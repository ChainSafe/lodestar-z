const std = @import("std");
const types = @import("consensus_types");
const ForkSeq = @import("config").ForkSeq;
const ForkTypes = @import("fork_types").ForkTypes;
const AnyBeaconState = @import("fork_types").AnyBeaconState;
const BeaconState = @import("fork_types").BeaconState;
const BeaconBlock = @import("fork_types").BeaconBlock;
const BeaconBlockBody = @import("fork_types").BeaconBlockBody;
const BlockType = @import("fork_types").BlockType;
const Node = @import("persistent_merkle_tree").Node;
const ZERO_HASH = @import("constants").ZERO_HASH;

pub fn isExecutionEnabled(comptime fork: ForkSeq, state: *BeaconState(fork), comptime block_type: BlockType, block: *const BeaconBlock(block_type, fork)) bool {
    if (comptime fork.lt(.bellatrix)) return false;
    if (comptime fork.gte(.capella)) return true;
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

pub fn isMergeTransitionComplete(comptime fork: ForkSeq, state: *BeaconState(fork)) bool {
    if (comptime fork.lt(.bellatrix)) {
        return false;
    }
    if (comptime fork.gte(.capella)) {
        return true;
    }
    const block_hash = state.latestExecutionPayloadHeaderBlockHash() catch return false;
    return !std.mem.eql(u8, block_hash[0..], ZERO_HASH[0..]);
}

test "Capella enables execution for default full and blinded blocks" {
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(.{
        .page_allocator = allocator,
        .allocator = allocator,
        .pool_size = pool_size,
    });
    defer pool.deinit();

    var any_state = try AnyBeaconState.fromValue(
        allocator,
        &pool,
        .capella,
        &types.capella.BeaconState.default_value,
    );
    defer any_state.deinit();
    const state = any_state.castToFork(.capella);

    const full_block = BeaconBlock(.full, .capella){
        .inner = types.capella.BeaconBlock.default_value,
    };
    const blinded_block = BeaconBlock(.blinded, .capella){
        .inner = types.capella.BlindedBeaconBlock.default_value,
    };

    try std.testing.expect(isMergeTransitionComplete(.capella, state));
    try std.testing.expect(isExecutionEnabled(.capella, state, .full, &full_block));
    try std.testing.expect(isExecutionEnabled(.capella, state, .blinded, &blinded_block));
}
