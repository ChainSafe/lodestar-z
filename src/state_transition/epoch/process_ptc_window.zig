const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconState = @import("fork_types").BeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const ct = @import("consensus_types");
const preset = @import("preset").preset;
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;
const computeStartSlotAtEpoch = @import("../utils/epoch.zig").computeStartSlotAtEpoch;
const computePtc = @import("../utils/gloas.zig").computePtc;
const ValidatorIndex = ct.primitive.ValidatorIndex.Type;

pub fn processPtcWindow(
    allocator: Allocator,
    epoch_cache: *const EpochCache,
    state: *BeaconState(.gloas),
) !void {
    var ptc_window = try state.inner.get("ptc_window");
    const ptc_window_len = ct.gloas.PtcWindow.length;

    var ptc_entry: [ct.gloas.PtcWindow.Element.length]ValidatorIndex = undefined;
    for (0..ptc_window_len - preset.SLOTS_PER_EPOCH) |i| {
        try ptc_window.getValue(undefined, i + preset.SLOTS_PER_EPOCH, &ptc_entry);
        try ptc_window.setValue(i, &ptc_entry);
    }

    const next_epoch = computeEpochAtSlot(try state.slot()) + preset.MIN_SEED_LOOKAHEAD + 1;
    const start_slot = computeStartSlotAtEpoch(next_epoch);

    for (0..preset.SLOTS_PER_EPOCH) |slot_offset| {
        const ptc = try computePtc(allocator, state, start_slot + slot_offset, null, epoch_cache.effective_balance_increments.get().items);
        try ptc_window.setValue(ptc_window_len - preset.SLOTS_PER_EPOCH + slot_offset, &ptc);
    }
}
