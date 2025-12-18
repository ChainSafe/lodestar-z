const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const ssz = @import("consensus_types");

pub fn upgradeStateToDeneb(allocator: Allocator, cached_state: *CachedBeaconStateAllForks) !void {
    var state = cached_state.state;
    if (!state.isCapella()) {
        return error.StateIsNotCapella;
    }

    const capella_state = state.capella;
    defer {
        ssz.capella.BeaconState.deinit(allocator, capella_state);
        allocator.destroy(capella_state);
    }
    _ = try state.upgradeUnsafe(allocator);
    state.forkPtr().* = .{
        .previous_version = capella_state.fork.current_version,
        .current_version = cached_state.config.chain.DENEB_FORK_VERSION,
        .epoch = cached_state.getEpochCache().epoch,
    };

    // ownership is transferred to BeaconState
    var deneb_latest_execution_payload_header = ssz.deneb.ExecutionPayloadHeader.default_value;
    const capella_latest_execution_payload_header = capella_state.latest_execution_payload_header;
    try ssz.capella.ExecutionPayloadHeader.clone(allocator, &capella_latest_execution_payload_header, &deneb_latest_execution_payload_header);
    // add excessBlobGas and blobGasUsed to latestExecutionPayloadHeader
    deneb_latest_execution_payload_header.excess_blob_gas = 0;
    deneb_latest_execution_payload_header.blob_gas_used = 0;

    state.setLatestExecutionPayloadHeader(allocator, .{
        .deneb = &deneb_latest_execution_payload_header,
    });
}
