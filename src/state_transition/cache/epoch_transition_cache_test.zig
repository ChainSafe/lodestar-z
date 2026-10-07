//! Tests for `epoch_transition_cache.zig`.

const std = @import("std");
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const upgradeStateToFulu = @import("../slot/upgrade_state_to_fulu.zig").upgradeStateToFulu;
const Node = @import("persistent_merkle_tree").Node;
const EpochTransitionCache = @import("epoch_transition_cache.zig").EpochTransitionCache;
const deinitReusedEpochTransitionCache = @import("epoch_transition_cache.zig").deinitReusedEpochTransitionCache;
const metrics = @import("../metrics.zig");
const preset = @import("preset").preset;

test "shuffling job records completed builds" {
    const allocator = std.testing.allocator;
    try metrics.init(allocator, std.testing.io, .{});
    defer metrics.deinit();

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 375_000 });
    defer pool.deinit();

    {
        var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
        defer test_state.deinit();

        const fulu_state = try upgradeStateToFulu(
            allocator,
            test_state.cached_state.config,
            test_state.cached_state.epoch_cache,
            try test_state.cached_state.state.tryCastToFork(.electra),
        );
        test_state.cached_state.state.* = .{ .fulu = fulu_state.inner };

        {
            var joined = try EpochTransitionCache.init(
                allocator,
                test_state.cached_state.config,
                test_state.cached_state.epoch_cache,
                test_state.cached_state.state,
                std.testing.io,
            );
            defer joined.deinit();
            const shuffling = try joined.joinShuffling();
            shuffling.deinit();
        }

        var cancelled = try EpochTransitionCache.init(
            allocator,
            test_state.cached_state.config,
            test_state.cached_state.epoch_cache,
            test_state.cached_state.state,
            std.testing.io,
        );
        defer cancelled.deinit();
    }

    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    try metrics.write(&aw.writer);
    try std.testing.expect(std.mem.find(u8, aw.written(), "lodestar_stfn_epoch_shuffling_job_seconds_count 2\n") != null);
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

test "EpochTransitionCache stores added compounding flags in a fixed tail" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 200_000 });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    const cache = test_state.epoch_transition_cache;
    const initial_validator_count = try test_state.cached_state.state.validatorsCount();
    for (0..preset.MAX_PENDING_DEPOSITS_PER_EPOCH) |i| {
        cache.appendCompoundingValidatorFlag(i % 2 == 0);
    }
    for (0..preset.MAX_PENDING_DEPOSITS_PER_EPOCH) |i| {
        try std.testing.expectEqual(i % 2 == 0, cache.isCompoundingValidator(initial_validator_count + i));
    }
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
            test_state.cached_state.config,
            test_state.cached_state.epoch_cache,
            test_state.cached_state.state,
            null,
        );
        defer epoch_transition_cache.deinit();
    }

    deinitReusedEpochTransitionCache();
}

test "memory_safety: fixed compounding flag tail does not allocate for sequential callers" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 200_000 });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    test_state.epoch_transition_cache.deinit();
    allocator.destroy(test_state.epoch_transition_cache);
    defer {
        test_state.cached_state.deinit();
        allocator.destroy(test_state.cached_state);
        test_state.pubkey_cache.deinit();
        allocator.destroy(test_state.pubkey_cache);
        deinitReusedEpochTransitionCache();
        allocator.destroy(test_state.config);
    }

    var second_caller = std.testing.FailingAllocator.init(allocator, .{});

    var cache = try EpochTransitionCache.init(
        second_caller.allocator(),
        test_state.cached_state.config,
        test_state.cached_state.epoch_cache,
        test_state.cached_state.state,
        null,
    );
    defer cache.deinit();

    const initial_validator_count = try test_state.cached_state.state.validatorsCount();
    const bytes_before = second_caller.allocated_bytes;
    for (0..preset.MAX_PENDING_DEPOSITS_PER_EPOCH) |i| {
        cache.appendCompoundingValidatorFlag(i % 2 == 0);
    }

    try std.testing.expectEqual(bytes_before, second_caller.allocated_bytes);
    for (0..preset.MAX_PENDING_DEPOSITS_PER_EPOCH) |i| {
        try std.testing.expectEqual(i % 2 == 0, cache.isCompoundingValidator(initial_validator_count + i));
    }
}

test "memory_safety: early shuffling is reclaimed when cache initialization fails" {
    const allocator = std.testing.allocator;
    inline for (.{ false, true }) |scheduled| {
        var threaded: std.Io.Threaded = .init(allocator, .{ .async_limit = if (scheduled) .limited(1) else .nothing });
        defer threaded.deinit();

        var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 375_000 });
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

        var validators = try test_state.cached_state.state.validators();
        var validator = try validators.get(0);
        try validator.set("activation_epoch", @import("constants").FAR_FUTURE_EPOCH);
        try validator.set("activation_eligibility_epoch", 0);

        {
            var cache = try EpochTransitionCache.init(
                allocator,
                test_state.cached_state.config,
                test_state.cached_state.epoch_cache,
                test_state.cached_state.state,
                null,
            );
            defer cache.deinit();
            try std.testing.expect(cache.shuffling_job == null);
            try std.testing.expectEqualSlices(u64, &.{0}, cache.indices_eligible_for_activation.items);
        }

        try metrics.init(allocator, threaded.io(), .{});
        defer metrics.deinit();

        try std.testing.checkAllAllocationFailures(allocator, struct {
            fn run(cache_allocator: std.mem.Allocator, fixture: *const TestCachedBeaconState, io: std.Io) !void {
                var cache = try EpochTransitionCache.init(
                    cache_allocator,
                    fixture.cached_state.config,
                    fixture.cached_state.epoch_cache,
                    fixture.cached_state.state,
                    io,
                );
                defer cache.deinit();
                try std.testing.expectEqual(scheduled, cache.shuffling_job.?.future.any_future != null);
                const shuffling = try cache.joinShuffling();
                defer shuffling.deinit();
                try std.testing.expectEqualSlices(u64, cache.next_shuffling_active_indices, shuffling.active_indices);
            }
        }.run, .{ &test_state, threaded.io() });

        // The successful run records one build. Any other comes from a job cancelled by a failure after launch.
        try std.testing.expect(metrics.state_transition.epoch_shuffling_job.impl.count > 1);
    }
}

test "memory_safety: early shuffling releases its inputs on every epoch cache OOM" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{ .async_limit = .nothing });
    defer threaded.deinit();

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 375_000 });
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

    // Sweeps the balance clone, the job's input copy, and every worker allocation.
    try std.testing.checkAllAllocationFailures(allocator, struct {
        fn run(epoch_cache_allocator: std.mem.Allocator, fixture: *const TestCachedBeaconState, io: std.Io) !void {
            const epoch_cache = fixture.cached_state.epoch_cache;
            const previous_allocator = epoch_cache.allocator;
            const previous_balances = epoch_cache.effective_balance_increments.ref();
            epoch_cache.allocator = epoch_cache_allocator;
            defer {
                epoch_cache.effective_balance_increments.unref();
                epoch_cache.effective_balance_increments = previous_balances;
                epoch_cache.allocator = previous_allocator;
            }

            var cache = try EpochTransitionCache.init(
                previous_allocator,
                fixture.cached_state.config,
                epoch_cache,
                fixture.cached_state.state,
                io,
            );
            defer cache.deinit();
            const shuffling = try cache.joinShuffling();
            shuffling.deinit();
        }
    }.run, .{ &test_state, threaded.io() });
}
