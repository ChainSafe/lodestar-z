const std = @import("std");
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const ForkSeq = @import("config").ForkSeq;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const types = @import("consensus_types");
const preset = @import("preset").preset;

pub fn processRandaoMixesReset(cached_state: *CachedBeaconState, cache: *const EpochTransitionCache) !void {
    const state = cached_state.state;
    const current_epoch = cache.current_epoch;
    const next_epoch = current_epoch + 1;

    var randao_mixes = try state.randaoMixes();
    var old = try randao_mixes.get(current_epoch % preset.EPOCHS_PER_HISTORICAL_VECTOR);
    try randao_mixes.set(
        next_epoch % preset.EPOCHS_PER_HISTORICAL_VECTOR,
        // TODO inspect why this clone was needed
        try old.clone(.{}),
    );
}

test "processRandaoMixesReset - sanity" {
    try @import("../test_utils/test_runner.zig").TestRunner(processRandaoMixesReset, .{
        .alloc = false,
        .err_return = true,
        .void_return = true,
    }).testProcessEpochFn();
    defer @import("../state_transition.zig").deinitStateTransition();
}
