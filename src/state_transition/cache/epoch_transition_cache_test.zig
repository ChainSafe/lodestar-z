//! Tests for `epoch_transition_cache.zig`.

const std = @import("std");
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const upgradeStateToFulu = @import("../slot/upgrade_state_to_fulu.zig").upgradeStateToFulu;
const Node = @import("persistent_merkle_tree").Node;
const EpochTransitionCache = @import("epoch_transition_cache.zig").EpochTransitionCache;
const deinitReusedEpochTransitionCache = @import("epoch_transition_cache.zig").deinitReusedEpochTransitionCache;

test "EpochTransitionCache - finalProcessEpoch" {
    const allocator = std.testing.allocator;
    const pool_size = 350_000;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = pool_size });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    const fulu_state = try upgradeStateToFulu(
        allocator,
        test_state.cached_state.config,
        test_state.cached_state.epoch_cache,
        try test_state.cached_state.state.tryCastToFork(.electra),
    );
    test_state.cached_state.state.* = .{ .fulu = fulu_state.inner };

    const epoch_cache = test_state.cached_state.epoch_cache;
    try epoch_cache.finalProcessEpoch(test_state.cached_state.state);
}

test "EpochTransitionCache.beforeProcessEpoch" {
    const allocator = std.testing.allocator;
    const validator_count_arr = &.{ 256, 10_000 };

    inline for (validator_count_arr) |validator_count| {
        const pool_size = 200_000;
        var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = pool_size });
        defer pool.deinit();

        var test_state = try TestCachedBeaconState.init(allocator, &pool, validator_count);
        defer test_state.deinit();

        var epoch_transition_cache = try EpochTransitionCache.init(
            allocator,
            std.testing.io,
            test_state.cached_state.config,
            test_state.cached_state.epoch_cache,
            test_state.cached_state.state,
        );
        defer epoch_transition_cache.deinit(allocator);
    }

    deinitReusedEpochTransitionCache(std.testing.io);
}
