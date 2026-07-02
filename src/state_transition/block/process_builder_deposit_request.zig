const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const BeaconState = @import("fork_types").BeaconState;
const types = @import("consensus_types");
const c = @import("constants");
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;
const gloas_utils = @import("../utils/gloas.zig");
const addBuilderToRegistry = gloas_utils.addBuilderToRegistry;
const findBuilderIndexByPubkey = gloas_utils.findBuilderIndexByPubkey;
const isValidBuilderDepositSignature = gloas_utils.isValidBuilderDepositSignature;

pub fn processBuilderDepositRequest(
    allocator: Allocator,
    config: *const BeaconConfig,
    state: *BeaconState(.gloas),
    request: *const types.gloas.BuilderDepositRequest.Type,
) !void {
    const builder_index = try findBuilderIndexByPubkey(allocator, state, &request.pubkey);

    if (builder_index) |idx| {
        var builders = try state.inner.get("builders");
        var builder: types.gloas.Builder.Type = undefined;
        try builders.getValue(allocator, idx, &builder);

        if (builder.withdrawable_epoch != c.FAR_FUTURE_EPOCH) {
            builder.withdrawable_epoch = computeEpochAtSlot(try state.slot()) + config.chain.MIN_BUILDER_WITHDRAWABILITY_DELAY;
        }

        builder.balance += request.amount;

        try builders.setValue(idx, &builder);
        return;
    }

    if (!isValidBuilderDepositSignature(
        config,
        &request.pubkey,
        &request.withdrawal_credentials,
        request.amount,
        request.signature,
    )) {
        return;
    }

    var execution_address: types.primitive.ExecutionAddress.Type = undefined;
    @memcpy(&execution_address, request.withdrawal_credentials[12..32]);

    try addBuilderToRegistry(
        allocator,
        state,
        &request.pubkey,
        request.withdrawal_credentials[0],
        &execution_address,
        request.amount,
        try state.slot(),
    );
}
