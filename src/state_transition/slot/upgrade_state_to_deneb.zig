const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const BeaconState = @import("fork_types").BeaconState;
const ct = @import("consensus_types");

pub fn upgradeStateToDeneb(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    capella_state: *BeaconState(.capella),
) !BeaconState(.deneb) {
    var state = try capella_state.upgradeUnsafe();
    errdefer state.deinit();

    const new_fork: ct.phase0.Fork.Type = .{
        .previous_version = try capella_state.forkCurrentVersion(),
        .current_version = config.chain.DENEB_FORK_VERSION,
        .epoch = epoch_cache.epoch,
    };
    try state.setFork(&new_fork);

    // ownership is transferred to BeaconState
    var new_latest_execution_payload_header = ct.deneb.ExecutionPayloadHeader.default_value;
    var capella_latest_execution_payload_header = ct.capella.ExecutionPayloadHeader.default_value;
    try capella_state.latestExecutionPayloadHeader(allocator, &capella_latest_execution_payload_header);
    defer ct.capella.ExecutionPayloadHeader.deinit(allocator, &capella_latest_execution_payload_header);

    try ct.capella.ExecutionPayloadHeader.clone(
        allocator,
        &capella_latest_execution_payload_header,
        &new_latest_execution_payload_header,
    );

    // new in deneb
    new_latest_execution_payload_header.excess_blob_gas = 0;
    new_latest_execution_payload_header.blob_gas_used = 0;

    try state.setLatestExecutionPayloadHeader(&new_latest_execution_payload_header);

    capella_state.deinit();
    return state;
}
