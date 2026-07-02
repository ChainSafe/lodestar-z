const std = @import("std");
const Allocator = std.mem.Allocator;
const ForkSeq = @import("config").ForkSeq;
const BeaconState = @import("fork_types").BeaconState;
const ct = @import("consensus_types");
const preset = @import("preset").preset;
const getBuilderPaymentQuorumThreshold = @import("../utils/gloas.zig").getBuilderPaymentQuorumThreshold;

/// Processes the builder pending payments from the previous epoch.
pub fn processBuilderPendingPayments(allocator: Allocator, state: *BeaconState(.gloas), epoch_cache: *const @import("../cache/epoch_cache.zig").EpochCache) !void {
    const quorum = getBuilderPaymentQuorumThreshold(epoch_cache);

    var builderPendingPayments = try state.inner.get("builder_pending_payments");
    var builderPendingWithdrawals = try state.inner.get("builder_pending_withdrawals");

    for (0..preset.SLOTS_PER_EPOCH) |i| {
        var payment: ct.gloas.BuilderPendingPayment.Type = undefined;
        try builderPendingPayments.getValue(allocator, i, &payment);
        if (payment.weight >= quorum) {
            try builderPendingWithdrawals.pushValue(&payment.withdrawal);
        }
    }
    // TODO: Gloas - Optimization needed
    const total_payments = @TypeOf(builderPendingPayments.*).length;
    for (0..total_payments) |i| {
        if (i < preset.SLOTS_PER_EPOCH) {
            var nextEpochPayment: ct.gloas.BuilderPendingPayment.Type = undefined;
            try builderPendingPayments.getValue(allocator, i + preset.SLOTS_PER_EPOCH, &nextEpochPayment);
            try builderPendingPayments.setValue(i, &nextEpochPayment);
        } else {
            const defaultPayment = ct.gloas.BuilderPendingPayment.default_value;
            try builderPendingPayments.setValue(i, &defaultPayment);
        }
    }
}
