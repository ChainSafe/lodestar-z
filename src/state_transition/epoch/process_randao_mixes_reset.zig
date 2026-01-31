const ForkSeq = @import("config").ForkSeq;
const BeaconState = @import("fork_types").BeaconState;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const preset = @import("preset").preset;

pub fn processRandaoMixesReset(
    comptime fork: ForkSeq,
    state: *BeaconState(fork),
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
const Node = @import("persistent_merkle_tree").Node;

test "processRandaoMixesReset - sanity" {
    const allocator = std.testing.allocator;
    const pool_size = 10_000 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 10_000);
    defer test_state.deinit();

    try processRandaoMixesReset(
        .electra,
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
    );
}
