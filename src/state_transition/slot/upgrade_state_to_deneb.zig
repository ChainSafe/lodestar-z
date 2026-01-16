const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const ssz = @import("consensus_types");
const ExecutionPayloadHeader = @import("../types/execution_payload.zig").ExecutionPayloadHeader;

pub fn upgradeStateToDeneb(allocator: Allocator, cached_state: *CachedBeaconState) !void {
    var capella_state = cached_state.state;
    if (capella_state.forkSeq() != .capella) {
        return error.StateIsNotCapella;
    }

    var state = try capella_state.upgradeUnsafe();
    errdefer state.deinit();

    const new_fork: ssz.phase0.Fork.Type = .{
        .previous_version = try capella_state.forkCurrentVersion(),
        .current_version = cached_state.config.chain.DENEB_FORK_VERSION,
        .epoch = cached_state.getEpochCache().epoch,
    };
    try state.setFork(&new_fork);

    // ownership is transferred to BeaconState
    var new_latest_execution_payload_header: ExecutionPayloadHeader = .{ .deneb = ssz.deneb.ExecutionPayloadHeader.default_value };
    var capella_latest_execution_payload_header: ExecutionPayloadHeader = undefined;
    try capella_state.latestExecutionPayloadHeader(allocator, &capella_latest_execution_payload_header);
    defer capella_latest_execution_payload_header.deinit(allocator);
    if (capella_latest_execution_payload_header != .capella) {
        return error.UnexpectedLatestExecutionPayloadHeaderType;
    }

    try ssz.capella.ExecutionPayloadHeader.clone(
        allocator,
        &capella_latest_execution_payload_header.capella,
        &new_latest_execution_payload_header.deneb,
    );

    // new in deneb
    new_latest_execution_payload_header.deneb.excess_blob_gas = 0;
    new_latest_execution_payload_header.deneb.blob_gas_used = 0;

    try state.setLatestExecutionPayloadHeader(&new_latest_execution_payload_header);

    capella_state.deinit();
    cached_state.state.* = state;
}
