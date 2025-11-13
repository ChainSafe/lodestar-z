const std = @import("std");
const ForkSeq = @import("config").ForkSeq;
const types = @import("consensus_types");
const BeaconBlock = @import("../types/beacon_block.zig").BeaconBlock;
const Block = @import("../types/block.zig").Block;
const BeaconBlockBody = @import("../types/beacon_block.zig").BeaconBlockBody;
const ExecutionPayload = @import("../types/beacon_block.zig").ExecutionPayload;
// const ExecutionPayloadHeader
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const BeaconStateAllForks = @import("../types/beacon_state.zig").BeaconStateAllForks;

pub fn isExecutionEnabled(state: *const BeaconStateAllForks, block: Block) bool {
    if (!state.isPostBellatrix()) return false;
    if (isMergeTransitionComplete(state)) return true;

    // TODO(bing): in lodestar prod, state root comparison should be enough but spec tests were failing. This switch block is a failsafe for that.
    //
    // Ref: https://github.com/ChainSafe/lodestar/blob/7f2271a1e2506bf30378da98a0f548290441bdc5/packages/state-transition/src/util/execution.ts#L37-L42
    switch (block) {
        .blinded => |b| {
            const body = b.beaconBlockBody();

            return switch (body) {
                .capella => |bd| !types.capella.ExecutionPayloadHeader.equals(&bd.execution_payload_header, &types.capella.ExecutionPayloadHeader.default_value),
                .deneb => |bd| !types.deneb.ExecutionPayloadHeader.equals(&bd.execution_payload_header, &types.deneb.ExecutionPayloadHeader.default_value),
                .electra => |bd| !types.electra.ExecutionPayloadHeader.equals(&bd.execution_payload_header, &types.electra.ExecutionPayloadHeader.default_value),
            };
        },
        .regular => |b| {
            const body = b.beaconBlockBody();

            return switch (body) {
                .phase0, .altair => @panic("Unsupported"),
                .bellatrix => |bd| !types.bellatrix.ExecutionPayload.equals(&bd.execution_payload, &types.bellatrix.ExecutionPayload.default_value),
                .capella => |bd| !types.capella.ExecutionPayload.equals(&bd.execution_payload, &types.capella.ExecutionPayload.default_value),
                .deneb => |bd| !types.deneb.ExecutionPayload.equals(&bd.execution_payload, &types.deneb.ExecutionPayload.default_value),
                .electra => |bd| !types.electra.ExecutionPayload.equals(&bd.execution_payload, &types.electra.ExecutionPayload.default_value),
            };
        },
    }
}

pub fn isMergeTransitionBlock(state: *const BeaconStateAllForks, body: *const BeaconBlockBody) bool {
    if (!state.isBellatrix()) {
        return false;
    }

    return (!isMergeTransitionComplete(state) and
        !types.bellatrix.ExecutionPayload.equals(body.getExecutionPayload().bellatrix, types.bellatrix.ExecutionPayload.default_value));
}

pub fn isMergeTransitionComplete(state: *const BeaconStateAllForks) bool {
    if (!state.isPostCapella()) {
        return switch (state.*) {
            .bellatrix => |s| !types.bellatrix.ExecutionPayloadHeader.equals(&s.latest_execution_payload_header, &types.bellatrix.ExecutionPayloadHeader.default_value),
            else => false,
        };
    }

    return switch (state.*) {
        .capella => |s| !types.capella.ExecutionPayloadHeader.equals(&s.latest_execution_payload_header, &types.capella.ExecutionPayloadHeader.default_value),
        .deneb => |s| !types.deneb.ExecutionPayloadHeader.equals(&s.latest_execution_payload_header, &types.deneb.ExecutionPayloadHeader.default_value),
        .electra => |s| !types.electra.ExecutionPayloadHeader.equals(&s.latest_execution_payload_header, &types.electra.ExecutionPayloadHeader.default_value),
        else => false,
    };
}
