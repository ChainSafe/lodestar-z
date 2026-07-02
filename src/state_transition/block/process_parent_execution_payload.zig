const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const BeaconState = @import("fork_types").BeaconState;
const BeaconBlock = @import("fork_types").BeaconBlock;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const processDepositRequest = @import("./process_deposit_request.zig").processDepositRequest;
const processWithdrawalRequest = @import("./process_withdrawal_request.zig").processWithdrawalRequest;
const processConsolidationRequest = @import("./process_consolidation_request.zig").processConsolidationRequest;
const processBuilderDepositRequest = @import("./process_builder_deposit_request.zig").processBuilderDepositRequest;
const processBuilderExitRequest = @import("./process_builder_exit_request.zig").processBuilderExitRequest;
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;

pub fn processParentExecutionPayload(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *EpochCache,
    state: *BeaconState(.gloas),
    block: *const BeaconBlock(.full, .gloas),
) !void {
    const bid = &block.body().inner.signed_execution_payload_bid.message;
    var parent_bid = types.gloas.ExecutionPayloadBid.default_value;
    try state.inner.getValue(allocator, "latest_execution_payload_bid", &parent_bid);
    defer types.gloas.ExecutionPayloadBid.deinit(allocator, &parent_bid);

    const requests = &block.body().inner.parent_execution_requests;
    const is_parent_block_full = std.mem.eql(u8, &bid.parent_block_hash, &parent_bid.block_hash);
    if (!is_parent_block_full) {
        try assertEmptyExecutionRequests(requests);
        return;
    }

    var requests_root: [32]u8 = undefined;
    try types.gloas.ExecutionRequests.hashTreeRoot(allocator, requests, &requests_root);
    if (!std.mem.eql(u8, &requests_root, &parent_bid.execution_requests_root)) {
        return error.ParentExecutionRequestsRootMismatch;
    }

    try applyParentExecutionPayload(allocator, config, epoch_cache, state, requests, &parent_bid);
}

pub fn applyParentExecutionPayload(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *EpochCache,
    state: *BeaconState(.gloas),
    requests: *const types.gloas.ExecutionRequests.Type,
    parent_bid: *const types.gloas.ExecutionPayloadBid.Type,
) !void {
    const parent_slot = parent_bid.slot;
    const parent_epoch = computeEpochAtSlot(parent_slot);
    const current_epoch = computeEpochAtSlot(try state.slot());

    for (requests.deposits.items) |*deposit| {
        try processDepositRequest(.gloas, state, deposit);
    }

    for (requests.withdrawals.items) |*withdrawal| {
        try processWithdrawalRequest(.gloas, config, epoch_cache, state, withdrawal);
    }

    for (requests.consolidations.items) |*consolidation| {
        try processConsolidationRequest(.gloas, config, epoch_cache, state, consolidation);
    }

    for (requests.builder_deposits.items) |*builder_deposit| {
        try processBuilderDepositRequest(allocator, config, state, builder_deposit);
    }

    for (requests.builder_exits.items) |*builder_exit| {
        try processBuilderExitRequest(allocator, config, state, builder_exit);
    }

    if (parent_epoch == current_epoch) {
        try settleBuilderPayment(allocator, state, preset.SLOTS_PER_EPOCH + (parent_slot % preset.SLOTS_PER_EPOCH));
    } else if (parent_epoch + 1 == current_epoch) {
        try settleBuilderPayment(allocator, state, parent_slot % preset.SLOTS_PER_EPOCH);
    } else if (parent_bid.value > 0) {
        var builder_pending_withdrawals = try state.inner.get("builder_pending_withdrawals");
        const withdrawal = types.gloas.BuilderPendingWithdrawal.Type{
            .fee_recipient = parent_bid.fee_recipient,
            .amount = parent_bid.value,
            .builder_index = parent_bid.builder_index,
        };
        try builder_pending_withdrawals.pushValue(&withdrawal);
        try state.inner.set("builder_pending_withdrawals", builder_pending_withdrawals);
    }

    var execution_payload_availability = try state.inner.get("execution_payload_availability");
    try execution_payload_availability.set(parent_slot % preset.SLOTS_PER_HISTORICAL_ROOT, true);
    try state.inner.set("execution_payload_availability", execution_payload_availability);
    try state.inner.setValue("latest_block_hash", &parent_bid.block_hash);
}

fn settleBuilderPayment(allocator: Allocator, state: *BeaconState(.gloas), payment_index: u64) !void {
    var builder_pending_payments = try state.inner.get("builder_pending_payments");
    if (payment_index >= 2 * preset.SLOTS_PER_EPOCH) return error.InvalidBuilderPendingPaymentIndex;

    var payment: types.gloas.BuilderPendingPayment.Type = undefined;
    try builder_pending_payments.getValue(allocator, payment_index, &payment);
    if (payment.withdrawal.amount > 0) {
        var builder_pending_withdrawals = try state.inner.get("builder_pending_withdrawals");
        try builder_pending_withdrawals.pushValue(&payment.withdrawal);
        try state.inner.set("builder_pending_withdrawals", builder_pending_withdrawals);
    }

    const default_payment = types.gloas.BuilderPendingPayment.default_value;
    try builder_pending_payments.setValue(payment_index, &default_payment);
}

fn assertEmptyExecutionRequests(requests: *const types.gloas.ExecutionRequests.Type) !void {
    if (requests.deposits.items.len != 0 or
        requests.withdrawals.items.len != 0 or
        requests.consolidations.items.len != 0 or
        requests.builder_deposits.items.len != 0 or
        requests.builder_exits.items.len != 0)
    {
        return error.ParentExecutionRequestsNotEmpty;
    }
}
