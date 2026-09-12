//! Tests for `epoch_cache.zig`.

const std = @import("std");
const ct = @import("consensus_types");
const Node = @import("persistent_merkle_tree").Node;
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const SyncCommitteeCache = @import("sync_committee_cache.zig").SyncCommitteeCache;
const EpochCache = @import("epoch_cache.zig").EpochCache;
const SyncCommitteeCacheRc = @import("sync_committee_cache.zig").SyncCommitteeCacheRc;

test "memory_safety: setSyncCommitteesIndexed should release each cache once on allocation failure" {
    const allocator = std.testing.allocator;
    const ValidatorIndex = ct.primitive.ValidatorIndex.Type;
    const indices = [_]ValidatorIndex{ 0, 0, 2 };
    var counting_allocator = std.testing.FailingAllocator.init(allocator, .{});
    var cache = try SyncCommitteeCache.initValidatorIndices(counting_allocator.allocator(), &indices);
    const cache_allocations = counting_allocator.alloc_index;
    cache.deinit();

    // Fail either RC allocation or the first allocation after the next cache transfers to its RC.
    const failure_indices = [_]usize{ cache_allocations, cache_allocations + 1, 2 * cache_allocations + 1 };
    for (failure_indices) |fail_index| {
        var failing_allocator = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
        var epoch_cache: EpochCache = undefined;
        epoch_cache.allocator = failing_allocator.allocator();
        epoch_cache.current_sync_committee_indexed = try SyncCommitteeCacheRc.init(allocator, .initEmpty());
        defer epoch_cache.current_sync_committee_indexed.unref();

        epoch_cache.next_sync_committee_indexed = try SyncCommitteeCacheRc.init(allocator, .initEmpty());
        defer epoch_cache.next_sync_committee_indexed.unref();

        const old_current = epoch_cache.current_sync_committee_indexed;
        const old_next = epoch_cache.next_sync_committee_indexed;
        try std.testing.expectError(error.OutOfMemory, epoch_cache.setSyncCommitteesIndexed(&indices));
        try std.testing.expect(failing_allocator.has_induced_failure);
        try std.testing.expectEqual(old_current, epoch_cache.current_sync_committee_indexed);
        try std.testing.expectEqual(old_next, epoch_cache.next_sync_committee_indexed);
        try std.testing.expectEqual(failing_allocator.allocated_bytes, failing_allocator.freed_bytes);

        failing_allocator.fail_index = std.math.maxInt(usize);
        try epoch_cache.setSyncCommitteesIndexed(&indices);
        try std.testing.expectEqualSlices(ValidatorIndex, &indices, epoch_cache.current_sync_committee_indexed.get().getValidatorIndices());
        try std.testing.expectEqualSlices(ValidatorIndex, &indices, epoch_cache.next_sync_committee_indexed.get().getValidatorIndices());
    }
}

test "memory_safety: setSyncCommitteesIndexed should preserve caches on every OOM" {
    const ValidatorIndex = ct.primitive.ValidatorIndex.Type;
    const indices = [_]ValidatorIndex{ 0, 0, 2 };
    var accounting = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var saw_oom = false;

    try std.testing.checkAllAllocationFailures(accounting.allocator(), struct {
        fn run(
            allocator: std.mem.Allocator,
            input: []const ValidatorIndex,
            counter: *const std.testing.FailingAllocator,
            failed: *bool,
        ) !void {
            var epoch_cache: EpochCache = undefined;
            epoch_cache.allocator = allocator;
            epoch_cache.current_sync_committee_indexed = try SyncCommitteeCacheRc.init(
                std.testing.allocator,
                .initEmpty(),
            );
            defer epoch_cache.current_sync_committee_indexed.unref();

            epoch_cache.next_sync_committee_indexed = try SyncCommitteeCacheRc.init(
                std.testing.allocator,
                .initEmpty(),
            );
            defer epoch_cache.next_sync_committee_indexed.unref();

            const old_current = epoch_cache.current_sync_committee_indexed;
            const old_next = epoch_cache.next_sync_committee_indexed;
            const outstanding_bytes = counter.allocated_bytes - counter.freed_bytes;
            epoch_cache.setSyncCommitteesIndexed(input) catch |err| {
                failed.* = true;
                try std.testing.expectEqual(old_current, epoch_cache.current_sync_committee_indexed);
                try std.testing.expectEqual(old_next, epoch_cache.next_sync_committee_indexed);
                try std.testing.expectEqual(
                    outstanding_bytes,
                    counter.allocated_bytes - counter.freed_bytes,
                );
                return err;
            };
            try std.testing.expectEqualSlices(
                ValidatorIndex,
                input,
                epoch_cache.current_sync_committee_indexed.get().getValidatorIndices(),
            );
            try std.testing.expectEqualSlices(
                ValidatorIndex,
                input,
                epoch_cache.next_sync_committee_indexed.get().getValidatorIndices(),
            );
        }
    }.run, .{ &indices, &accounting, &saw_oom });
    try std.testing.expect(saw_oom);
}

test "memory_safety: rotateSyncCommitteeIndexed should preserve shared caches on allocation failure" {
    const allocator = std.testing.allocator;
    const ValidatorIndex = ct.primitive.ValidatorIndex.Type;
    const indices = [_]ValidatorIndex{ 0, 0, 2 };
    var counting_allocator = std.testing.FailingAllocator.init(allocator, .{});
    var cache = try SyncCommitteeCache.initValidatorIndices(counting_allocator.allocator(), &indices);
    const cache_allocations = counting_allocator.alloc_index;
    cache.deinit();

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 500_000 });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();
    const pre_cache = test_state.cached_state.epoch_cache;
    const old_current = pre_cache.current_sync_committee_indexed;
    const old_next = pre_cache.next_sync_committee_indexed;
    const current_indices = try allocator.dupe(ValidatorIndex, old_current.get().getValidatorIndices());
    defer allocator.free(current_indices);
    const next_indices = try allocator.dupe(ValidatorIndex, old_next.get().getValidatorIndices());
    defer allocator.free(next_indices);

    // Fail the initial allocation and the RC allocation after the raw cache is complete.
    for ([_]usize{ 0, cache_allocations }) |fail_index| {
        var failing_allocator = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
        {
            const candidate = try pre_cache.clone(allocator);
            defer candidate.deinit();

            try std.testing.expectError(error.OutOfMemory, candidate.rotateSyncCommitteeIndexed(failing_allocator.allocator(), &indices));
            try std.testing.expect(failing_allocator.has_induced_failure);
            try std.testing.expectEqual(old_current, candidate.current_sync_committee_indexed);
            try std.testing.expectEqual(old_next, candidate.next_sync_committee_indexed);
            try std.testing.expectEqual(failing_allocator.allocated_bytes, failing_allocator.freed_bytes);

            failing_allocator.fail_index = std.math.maxInt(usize);
            try candidate.rotateSyncCommitteeIndexed(failing_allocator.allocator(), &indices);
            try std.testing.expectEqual(old_next, candidate.current_sync_committee_indexed);
            try std.testing.expectEqualSlices(ValidatorIndex, &indices, candidate.next_sync_committee_indexed.get().getValidatorIndices());
        }
        try std.testing.expectEqual(failing_allocator.allocated_bytes, failing_allocator.freed_bytes);
        try std.testing.expectEqualSlices(ValidatorIndex, current_indices, pre_cache.current_sync_committee_indexed.get().getValidatorIndices());
        try std.testing.expectEqualSlices(ValidatorIndex, next_indices, pre_cache.next_sync_committee_indexed.get().getValidatorIndices());
    }
}

test "memory_safety: EpochCache.clone does not retain shared references when allocation fails" {
    const allocator = std.testing.allocator;

    var pool = try Node.Pool.init(.{
        .page_allocator = allocator,
        .allocator = allocator,
        .pool_size = 200_000,
    });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    // Leaked refs prevent test_state teardown from releasing the last shared owners.
    var saw_operation_oom = false;
    try std.testing.checkAllAllocationFailures(allocator, struct {
        fn run(
            clone_allocator: std.mem.Allocator,
            source: *@import("epoch_cache.zig").EpochCache,
            saw_oom: *bool,
        ) !void {
            errdefer saw_oom.* = true;
            const cloned = try source.clone(clone_allocator);
            defer cloned.deinit();
        }
    }.run, .{ test_state.cached_state.epoch_cache, &saw_operation_oom });
    try std.testing.expect(saw_operation_oom);
}

test "memory_safety: afterProcessEpoch should preserve shuffling state when decision-root calculation fails" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 500_000 });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    const epoch_cache = test_state.cached_state.epoch_cache;
    const previous_shuffling = epoch_cache.previous_shuffling;
    const current_shuffling = epoch_cache.current_shuffling;
    const next_shuffling = epoch_cache.next_shuffling;
    const previous_decision_root = epoch_cache.previous_decision_root;
    const current_decision_root = epoch_cache.current_decision_root;
    const next_decision_root = epoch_cache.next_decision_root;

    // The replacement shuffling is built before decision-root lookup fails.
    try std.testing.expectError(
        error.SlotTooBig,
        epoch_cache.afterProcessEpoch(
            test_state.cached_state.state,
            test_state.epoch_transition_cache,
        ),
    );

    // The failed update must leave every shuffling owner paired with its original decision root.
    try std.testing.expectEqual(previous_shuffling, epoch_cache.previous_shuffling);
    try std.testing.expectEqual(current_shuffling, epoch_cache.current_shuffling);
    try std.testing.expectEqual(next_shuffling, epoch_cache.next_shuffling);
    try std.testing.expectEqual(previous_decision_root, epoch_cache.previous_decision_root);
    try std.testing.expectEqual(current_decision_root, epoch_cache.current_decision_root);
    try std.testing.expectEqual(next_decision_root, epoch_cache.next_decision_root);
}
