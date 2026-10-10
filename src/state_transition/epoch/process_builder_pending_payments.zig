const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconState = @import("fork_types").BeaconState;
const ct = @import("consensus_types");
const preset = @import("preset").preset;
const getBuilderPaymentQuorumThreshold = @import("../utils/gloas.zig").getBuilderPaymentQuorumThreshold;

pub fn processBuilderPendingPayments(allocator: Allocator, state: *BeaconState(.gloas), epoch_cache: *const @import("../cache/epoch_cache.zig").EpochCache) !void {
    const quorum = getBuilderPaymentQuorumThreshold(epoch_cache);

    var pending_payments = try state.inner.get("builder_pending_payments");
    var pending_withdrawals = try state.inner.get("builder_pending_withdrawals");
    for (0..preset.SLOTS_PER_EPOCH) |index| {
        var previous: ct.gloas.BuilderPendingPayment.Type = undefined;
        try pending_payments.getValue(allocator, index, &previous);
        if (previous.weight >= quorum) try pending_withdrawals.pushValue(&previous.withdrawal);
        var current: ct.gloas.BuilderPendingPayment.Type = undefined;
        try pending_payments.getValue(allocator, index + preset.SLOTS_PER_EPOCH, &current);
        try pending_payments.setValue(index, &current);
        try pending_payments.setValue(index + preset.SLOTS_PER_EPOCH, &ct.gloas.BuilderPendingPayment.default_value);
    }
}
