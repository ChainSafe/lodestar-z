const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconState = @import("fork_types").BeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const ct = @import("consensus_types");
const preset = @import("preset").preset;
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;
const computePayloadTimelinessCommitteesForEpoch = @import("../utils/seed.zig").computePayloadTimelinessCommitteesForEpoch;
const ValidatorIndex = ct.primitive.ValidatorIndex.Type;

/// Update the `ptc_window` field in the beacon state by shifting out the oldest epoch's
/// PTC entries and appending newly computed entries for the next lookahead epoch.
/// Stashes the computed PTCs in the transition cache for finalProcessEpoch to shift
/// into the epoch cache without reading from state.
///
/// Spec: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/gloas/beacon-chain.md#new-process_ptc_window
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
    const next_shuffling = try epoch_transition_cache.getNextShuffling(allocator, .gloas, state);

    const next_epoch_payload_timeliness_committees = try computePayloadTimelinessCommitteesForEpoch(
        .gloas,
        allocator,
        state,
        next_epoch,
        &next_shuffling.committees,
        epoch_cache.effective_balance_increments.get().items,
    );
    for (0..preset.SLOTS_PER_EPOCH) |slot_offset| {
        try ptc_window.setValue(
            ptc_window_len - preset.SLOTS_PER_EPOCH + slot_offset,
            &next_epoch_payload_timeliness_committees[slot_offset],
        );
    }

    try state.inner.set("ptc_window", ptc_window);
    epoch_transition_cache.next_epoch_payload_timeliness_committees = next_epoch_payload_timeliness_committees;
}
