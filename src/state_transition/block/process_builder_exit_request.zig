const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const BeaconState = @import("fork_types").BeaconState;
const types = @import("consensus_types");
const gloas_utils = @import("../utils/gloas.zig");
const findBuilderIndexByPubkey = gloas_utils.findBuilderIndexByPubkey;
const getPendingBalanceToWithdrawForBuilder = gloas_utils.getPendingBalanceToWithdrawForBuilder;
const initiateBuilderExit = gloas_utils.initiateBuilderExit;
const isActiveBuilder = gloas_utils.isActiveBuilder;

pub fn processBuilderExitRequest(
    allocator: Allocator,
    config: *const BeaconConfig,
    state: *BeaconState(.gloas),
    request: *const types.gloas.BuilderExitRequest.Type,
) !void {
    const maybe_builder_index = try findBuilderIndexByPubkey(allocator, state, &request.pubkey);
    const builder_index = maybe_builder_index orelse return;

    var builders = try state.inner.get("builders");
    var builder: types.gloas.Builder.Type = undefined;
    try builders.getValue(allocator, builder_index, &builder);

    if (!isActiveBuilder(&builder, try state.finalizedEpoch())) {
        return;
    }
    if (!std.mem.eql(u8, &builder.execution_address, &request.source_address)) {
        return;
    }
    if (try getPendingBalanceToWithdrawForBuilder(allocator, state, builder_index) != 0) {
        return;
    }

    try initiateBuilderExit(config, state, allocator, builder_index);
}
