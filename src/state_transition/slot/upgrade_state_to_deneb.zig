const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const ssz = @import("consensus_types");
const toExecutionPayloadHeader = @import("../types/execution_payload.zig").toExecutionPayloadHeader;

pub fn upgradeStateToDeneb(allocator: Allocator, cached_state: *CachedBeaconState) !void {
    var capella_state = cached_state.state;
    if (capella_state.forkSeq() != .capella) {
        return error.StateIsNotCapella;
    }

    const state = try capella_state.upgradeUnsafe();
    defer capella_state.deinit();

    state.setFork(.{
        .previous_version = capella_state.fork().getValue("current_version"),
        .current_version = cached_state.config.chain.DENEB_FORK_VERSION,
        .epoch = cached_state.getEpochCache().epoch,
    });

    // add excessBlobGas and blobGasUsed to latestExecutionPayloadHeader
    // ownership is transferred to BeaconState
    var deneb_latest_execution_payload_header = ssz.deneb.ExecutionPayloadHeader.default_value;
    const capella_latest_execution_payload_header = capella_state.latestExecutionPayloadHeader(allocator);
    defer capella_latest_execution_payload_header.deinit(allocator);
    if (capella_latest_execution_payload_header != .capella) {
        return error.UnexpectedLatestExecutionPayloadHeaderType;
    }

    toExecutionPayloadHeader(
        allocator,
        ssz.deneb.ExecutionPayloadHeader.Type,
        capella_latest_execution_payload_header.capella,
        &deneb_latest_execution_payload_header,
    );

    // new in deneb
    deneb_latest_execution_payload_header.excess_blob_gas = 0;
    deneb_latest_execution_payload_header.blob_gas_used = 0;

    state.setLatestExecutionPayloadHeader(allocator, .{
        .deneb = &deneb_latest_execution_payload_header,
    });
}
