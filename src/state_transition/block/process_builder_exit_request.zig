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

/// Apply a builder exit request. Authorizes the exit via `source_address` (the builder's
/// execution_address), not the BLS key — mirroring EIP-7002's 0x01 credential exit.
///
/// Drops the request silently if any precondition fails; the EL has already dequeued it
/// deterministically, so the fee is forfeited but `requests_hash` agreement is unaffected.
///
/// Spec: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.11/specs/gloas/beacon-chain.md#new-process_builder_exit_request
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
