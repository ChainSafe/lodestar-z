const std = @import("std");
const ForkSeq = @import("config").ForkSeq;
const ct = @import("consensus_types");
const BeaconBlock = @import("../types/beacon_block.zig").BeaconBlock;
const SignedBlock = @import("../types/signed_block.zig").SignedBlock;
const BeaconBlockBody = @import("../types/beacon_block.zig").BeaconBlockBody;
const ExecutionPayload = @import("../types/beacon_block.zig").ExecutionPayload;
// const ExecutionPayloadHeader
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const BeaconStateAllForks = @import("../types/beacon_state.zig").BeaconStateAllForks;

pub fn isExecutionEnabled(state: *const BeaconStateAllForks, block: *const SignedBlock) bool {
    if (!state.isPostBellatrix()) return false;
    if (isMergeTransitionComplete(state)) return true;

    // TODO(bing): in lodestar prod, state root comparison should be enough but spec tests were failing. This switch block is a failsafe for that.
    //
    // Ref: https://github.com/ChainSafe/lodestar/blob/7f2271a1e2506bf30378da98a0f548290441bdc5/packages/state-transition/src/util/execution.ts#L37-L42
    switch (block.*) {
        .blinded => |b| {
            const body = b.beaconBlock().beaconBlockBody();

            return switch (body) {
                .capella => |bd| !ct.capella.ExecutionPayloadHeader.equals(&bd.execution_payload_header, &ct.capella.ExecutionPayloadHeader.default_value),
                .deneb => |bd| !ct.deneb.ExecutionPayloadHeader.equals(&bd.execution_payload_header, &ct.deneb.ExecutionPayloadHeader.default_value),
                .electra => |bd| !ct.electra.ExecutionPayloadHeader.equals(&bd.execution_payload_header, &ct.electra.ExecutionPayloadHeader.default_value),
            };
        },
        .regular => |b| {
            const body = b.beaconBlock().beaconBlockBody();

            return switch (body) {
                .phase0, .altair => @panic("Unsupported"),
                .bellatrix => |bd| !ct.bellatrix.ExecutionPayload.equals(&bd.execution_payload, &ct.bellatrix.ExecutionPayload.default_value),
                .capella => |bd| !ct.capella.ExecutionPayload.equals(&bd.execution_payload, &ct.capella.ExecutionPayload.default_value),
                .deneb => |bd| !ct.deneb.ExecutionPayload.equals(&bd.execution_payload, &ct.deneb.ExecutionPayload.default_value),
                .electra => |bd| !ct.electra.ExecutionPayload.equals(&bd.execution_payload, &ct.electra.ExecutionPayload.default_value),
            };
        },
    }
}

pub fn isMergeTransitionBlock(state: *const BeaconStateAllForks, body: *const BeaconBlockBody) bool {
    if (!state.isBellatrix()) {
        return false;
    }

    return (!isMergeTransitionComplete(state) and
        !ct.bellatrix.ExecutionPayload.equals(body.getExecutionPayload().bellatrix, ct.bellatrix.ExecutionPayload.default_value));
}

pub fn isMergeTransitionComplete(state: *const BeaconStateAllForks) bool {
    if (!state.isPostCapella()) {
        return switch (state.*) {
            .bellatrix => |s| !ct.bellatrix.ExecutionPayloadHeader.equals(&s.latest_execution_payload_header, &ct.bellatrix.ExecutionPayloadHeader.default_value),
            else => false,
        };
    }

    return switch (state.*) {
        .capella => |s| !ct.capella.ExecutionPayloadHeader.equals(&s.latest_execution_payload_header, &ct.capella.ExecutionPayloadHeader.default_value),
        .deneb => |s| !ct.deneb.ExecutionPayloadHeader.equals(&s.latest_execution_payload_header, &ct.deneb.ExecutionPayloadHeader.default_value),
        .electra => |s| !ct.electra.ExecutionPayloadHeader.equals(&s.latest_execution_payload_header, &ct.electra.ExecutionPayloadHeader.default_value),
        else => false,
    };
}
