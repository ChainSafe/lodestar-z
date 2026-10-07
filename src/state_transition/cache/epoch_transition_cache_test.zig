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

        var counting = std.testing.FailingAllocator.init(allocator, .{});
        {
            var cache = try EpochTransitionCache.init(
                counting.allocator(),
                test_state.cached_state.config,
                test_state.cached_state.epoch_cache,
                test_state.cached_state.state,
                threaded.io(),
            );
            defer cache.deinit();
            try std.testing.expect(cache.shuffling_job != null);
            try std.testing.expectEqual(scheduled, (try cache.shuffling_job.?).future.any_future != null);
            const shuffling = try cache.joinShuffling();
            defer shuffling.deinit();
            try std.testing.expectEqualSlices(u64, cache.next_shuffling_active_indices, shuffling.active_indices);
        }
        try std.testing.expectEqual(counting.allocated_bytes, counting.freed_bytes);

        var saw_post_launch_oom = false;
        for (0..counting.alloc_index) |fail_index| {
            try metrics.init(allocator, threaded.io(), .{});
            defer metrics.deinit();

            var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
            const result = EpochTransitionCache.init(
                failing.allocator(),
                test_state.cached_state.config,
                test_state.cached_state.epoch_cache,
                test_state.cached_state.state,
                threaded.io(),
            );
            if (result) |value| {
                var cache = value;
                cache.deinit();
                return error.ExpectedOutOfMemory;
            } else |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
            }
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);

            var output: std.Io.Writer.Allocating = .init(allocator);
            defer output.deinit();
            try metrics.write(&output.writer);
            if (std.mem.find(u8, output.written(), "lodestar_stfn_epoch_shuffling_job_seconds_count 1\n") != null) {
                saw_post_launch_oom = true;
            }
        }
        try std.testing.expect(saw_post_launch_oom);
    }
}

test "memory_safety: early shuffling preserves preparation and worker error boundaries" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{ .async_limit = .nothing });
    defer threaded.deinit();

    try metrics.init(allocator, threaded.io(), .{});
    defer metrics.deinit();

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 375_000 });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    const epoch_cache = test_state.cached_state.epoch_cache;
    const state = test_state.cached_state.state;
    const fulu_state = try upgradeStateToFulu(
        allocator,
        test_state.cached_state.config,
        epoch_cache,
        try state.tryCastToFork(.electra),
    );
    state.* = .{ .fulu = fulu_state.inner };

    var counting = std.testing.FailingAllocator.init(allocator, .{});
    {
        const previous_balances = epoch_cache.effective_balance_increments.ref();
        epoch_cache.allocator = counting.allocator();
        defer {
            epoch_cache.effective_balance_increments.unref();
            epoch_cache.effective_balance_increments = previous_balances;
            epoch_cache.allocator = allocator;
        }
        try epoch_cache.beforeEpochTransition();
    }
    try std.testing.expectEqual(counting.allocated_bytes, counting.freed_bytes);

    for (0..2) |worker_offset| {
        var failing = std.testing.FailingAllocator.init(allocator, .{
            .fail_index = counting.alloc_index + worker_offset,
        });
        {
            const previous_balances = epoch_cache.effective_balance_increments.ref();
            epoch_cache.allocator = failing.allocator();
            defer {
                epoch_cache.effective_balance_increments.unref();
                epoch_cache.effective_balance_increments = previous_balances;
                epoch_cache.allocator = allocator;
            }
            if (worker_offset == 0) {
                const slot = try state.slot();
                try std.testing.expectEqual(preset.SLOTS_PER_EPOCH - 1, slot % preset.SLOTS_PER_EPOCH);
                try std.testing.expectError(error.OutOfMemory, @import("../state_transition.zig").processSlots(
                    allocator,
                    threaded.io(),
                    test_state.cached_state,
                    slot + 1,
                    null,
                ));
                try std.testing.expectEqual(slot, try state.slot());

                var output: std.Io.Writer.Allocating = .init(allocator);
                defer output.deinit();
                try metrics.write(&output.writer);
                try std.testing.expect(std.mem.find(u8, output.written(), "lodestar_stfn_epoch_transition_step_seconds_count{step=\"before_process_epoch\"} 1\n") != null);
                try std.testing.expect(std.mem.find(u8, output.written(), "step=\"process_justification_and_finalization\"") == null);
            } else {
                var cache = try EpochTransitionCache.init(
                    allocator,
                    test_state.cached_state.config,
                    epoch_cache,
                    state,
                    threaded.io(),
                );
                defer cache.deinit();
                _ = try cache.shuffling_job.?;
                try std.testing.expectError(error.OutOfMemory, cache.joinShuffling());
                try std.testing.expect(cache.shuffling_job == null);
            }
            try std.testing.expect(failing.has_induced_failure);
        }
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}
