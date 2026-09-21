//! Tests for `epoch_transition_cache.zig`.

const std = @import("std");
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const upgradeStateToFulu = @import("../slot/upgrade_state_to_fulu.zig").upgradeStateToFulu;
const Node = @import("persistent_merkle_tree").Node;
const EpochTransitionCache = @import("epoch_transition_cache.zig").EpochTransitionCache;
const deinitReusedEpochTransitionCache = @import("epoch_transition_cache.zig").deinitReusedEpochTransitionCache;
const metrics = @import("../metrics.zig");

test "shuffling job records completed builds" {
    const allocator = std.testing.allocator;
    try metrics.init(allocator, std.testing.io, .{});
    defer metrics.deinit();

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 200_000 });
    defer pool.deinit();

    {
        var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
        defer test_state.deinit();

        const cache = test_state.epoch_transition_cache;
        const seed = [_]u8{0} ** 32;
        const epoch = cache.current_epoch + 2;
        try cache.startShuffling(allocator, std.testing.io, seed, epoch);
        const shuffling = try cache.joinShuffling();
        shuffling.deinit();

        try cache.startShuffling(allocator, std.testing.io, seed, epoch);
    }

    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    try metrics.write(&aw.writer);
    try std.testing.expect(std.mem.indexOf(u8, aw.written(), "lodestar_stfn_epoch_shuffling_job_seconds_count 2\n") != null);
}

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
        defer epoch_transition_cache.deinit();
    }

    deinitReusedEpochTransitionCache(std.testing.io);
}

test "memory_safety: borrowed scratch growth stays with the owner across sequential callers" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 200_000 });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var second_caller = std.testing.FailingAllocator.init(allocator, .{});

    var cache = try EpochTransitionCache.init(
        second_caller.allocator(),
        std.testing.io,
        test_state.cached_state.config,
        test_state.cached_state.epoch_cache,
        test_state.cached_state.state,
    );
    defer cache.deinit();

    const scratch = cache.is_compounding_validator_arr;
    const owner_is_not_caller = scratch.owner_allocator.ptr != second_caller.allocator().ptr;
    try std.testing.expect(owner_is_not_caller);

    const grown_len = scratch.array.capacity + 1;
    const bytes_before = second_caller.allocated_bytes;
    while (scratch.items().len < grown_len) {
        try scratch.append(true);
    }

    try std.testing.expectEqual(bytes_before, second_caller.allocated_bytes);
    try std.testing.expectEqual(grown_len, scratch.items().len);

    deinitReusedEpochTransitionCache(std.testing.io);
}
