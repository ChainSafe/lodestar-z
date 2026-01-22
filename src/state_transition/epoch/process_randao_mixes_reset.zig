const ForkSeq = @import("config").ForkSeq;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const preset = @import("preset").preset;

pub fn processRandaoMixesReset(
    comptime fork: ForkSeq,
    state: *ForkBeaconState(fork),
    cache: *const EpochTransitionCache,
) !void {
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

const std = @import("std");
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;

test "processRandaoMixesReset - sanity" {
    const allocator = std.testing.allocator;

    var test_state = try TestCachedBeaconState.init(allocator, 10_000);
    defer test_state.deinit();

    try processRandaoMixesReset(
        .electra,
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
    );
}
