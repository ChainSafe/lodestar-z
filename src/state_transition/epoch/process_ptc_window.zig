const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconState = @import("fork_types").BeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
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
    epoch_transition_cache: *EpochTransitionCache,
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
    const next_shuffling = try epoch_transition_cache.getNextShuffling(allocator, .gloas, state);

    var next_epoch_payload_timeliness_committees: [preset.SLOTS_PER_EPOCH][preset.PTC_SIZE]ValidatorIndex = undefined;
    for (0..preset.SLOTS_PER_EPOCH) |slot_offset| {
        next_epoch_payload_timeliness_committees[slot_offset] = try computePtc(
            allocator,
            state,
            start_slot + slot_offset,
            next_shuffling,
            epoch_cache.effective_balance_increments.get().items,
        );
        try ptc_window.setValue(
            ptc_window_len - preset.SLOTS_PER_EPOCH + slot_offset,
            &next_epoch_payload_timeliness_committees[slot_offset],
        );
    }

    try state.inner.set("ptc_window", ptc_window);
    epoch_transition_cache.next_epoch_payload_timeliness_committees = next_epoch_payload_timeliness_committees;
}
