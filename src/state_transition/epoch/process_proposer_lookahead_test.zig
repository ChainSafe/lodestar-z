const std = @import("std");
const preset = @import("preset").preset;
const Node = @import("persistent_merkle_tree").Node;
const ValidatorIndex = @import("consensus_types").primitive.ValidatorIndex.Type;
const ProposerLookahead = @import("consensus_types").fulu.ProposerLookahead;
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const upgradeStateToFulu = @import("../slot/upgrade_state_to_fulu.zig").upgradeStateToFulu;
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;
const computeEpochShufflingForFork = @import("../utils/epoch_shuffling.zig").computeEpochShufflingForFork;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const processProposerLookahead = @import("process_proposer_lookahead.zig").processProposerLookahead;

test "memory_safety: proposer lookahead shuffling should belong to the epoch cache allocator" {
    const allocator = std.testing.allocator;
    inline for (.{ true, false }) |start_async| {
        const pool_size = 375_000;
        var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = pool_size });
        defer pool.deinit();

        var test_state = try TestCachedBeaconState.init(allocator, &pool, 10_000);
        defer test_state.deinit();

        const fulu_state = try upgradeStateToFulu(
            allocator,
            test_state.cached_state.config,
            test_state.cached_state.epoch_cache,
            try test_state.cached_state.state.tryCastToFork(.electra),
        );
        test_state.cached_state.state.* = .{ .fulu = fulu_state.inner };

        var cache = try EpochTransitionCache.init(
            allocator,
            test_state.cached_state.config,
            test_state.cached_state.epoch_cache,
            test_state.cached_state.state,
            if (start_async) std.testing.io else null,
        );
        defer cache.deinit();
        try std.testing.expectEqual(start_async, cache.shuffling_job != null);

        const current_epoch = computeEpochAtSlot(try test_state.cached_state.state.slot());
        const new_epoch = current_epoch + preset.MIN_SEED_LOOKAHEAD + 1;
        const fulu = test_state.cached_state.state.castToFork(.fulu);
        const expected_shuffling = blk: {
            const expected_indices = try allocator.dupe(ValidatorIndex, cache.next_shuffling_active_indices);
            errdefer allocator.free(expected_indices);
            break :blk try computeEpochShufflingForFork(.fulu, allocator, fulu, expected_indices, new_epoch);
        };
        defer expected_shuffling.deinit();

        var caller_allocator_state = std.testing.FailingAllocator.init(allocator, .{});

        try processProposerLookahead(
            .fulu,
            caller_allocator_state.allocator(),
            test_state.cached_state.epoch_cache,
            test_state.cached_state.state.castToFork(.fulu),
            &cache,
        );

        const next_shuffling = cache.next_shuffling.?;
        try std.testing.expectEqual(caller_allocator_state.allocated_bytes, caller_allocator_state.freed_bytes);
        try std.testing.expectEqual(allocator.ptr, next_shuffling.allocator.ptr);

        const actual_shuffling = next_shuffling.get();
        try std.testing.expectEqual(allocator.ptr, actual_shuffling.allocator.ptr);
        try std.testing.expectEqualSlices(ValidatorIndex, expected_shuffling.active_indices, actual_shuffling.active_indices);
        try std.testing.expectEqualSlices(ValidatorIndex, expected_shuffling.shuffling, actual_shuffling.shuffling);
    }
}

test "memory_safety: processProposerLookahead should release shuffling on proposer and wrapper OOM" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{ .async_limit = .nothing });
    defer threaded.deinit();

    inline for (.{ false, true }) |fail_wrapper| {
        var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 375_000 });
        defer pool.deinit();

        var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
        defer test_state.deinit();

        const epoch_cache = test_state.cached_state.epoch_cache;
        const fulu_state = try upgradeStateToFulu(
            allocator,
            test_state.cached_state.config,
            epoch_cache,
            try test_state.cached_state.state.tryCastToFork(.electra),
        );
        test_state.cached_state.state.* = .{ .fulu = fulu_state.inner };
        const state = test_state.cached_state.state.castToFork(.fulu);
        var cache = try EpochTransitionCache.init(
            allocator,
            test_state.cached_state.config,
            epoch_cache,
            test_state.cached_state.state,
            threaded.io(),
        );
        defer cache.deinit();

        var previous_lookahead: [ProposerLookahead.length]u64 = undefined;
        try state.proposerLookaheadInto(&previous_lookahead);

        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        if (fail_wrapper) epoch_cache.allocator = failing.allocator();
        defer epoch_cache.allocator = allocator;

        try std.testing.expectError(error.OutOfMemory, processProposerLookahead(
            .fulu,
            if (fail_wrapper) allocator else failing.allocator(),
            epoch_cache,
            state,
            &cache,
        ));
        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expect(cache.next_shuffling == null);
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);

        var actual_lookahead: [ProposerLookahead.length]u64 = undefined;
        try state.proposerLookaheadInto(&actual_lookahead);
        try std.testing.expectEqualSlices(u64, &previous_lookahead, &actual_lookahead);
    }
}
