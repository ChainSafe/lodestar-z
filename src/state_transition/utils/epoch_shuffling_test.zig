//! Tests for `epoch_shuffling.zig`.

const std = @import("std");
const ct = @import("consensus_types");
const preset = @import("preset").preset;
const Node = @import("persistent_merkle_tree").Node;
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const EpochShuffling = @import("epoch_shuffling.zig").EpochShuffling;
const computeEpochShuffling = @import("epoch_shuffling.zig").computeEpochShuffling;

test "memory_safety: EpochShuffling.init should free completed committees when a later slot allocation fails" {
    const allocator = std.testing.allocator;
    const active_indices = try allocator.alloc(ct.primitive.ValidatorIndex.Type, 256);
    defer allocator.free(active_indices);
    for (active_indices, 0..) |*index, i| {
        index.* = @intCast(i);
    }

    // The shuffling and first slot allocations succeed; the second slot allocation fails.
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 2 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        EpochShuffling.init(
            failing.allocator(),
            [_]u8{0} ** 32,
            0,
            active_indices,
        ),
    );
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

test "memory_safety: EpochShuffling.init should free completed committees when the last slot allocation fails" {
    const allocator = std.testing.allocator;
    const active_indices = try allocator.alloc(ct.primitive.ValidatorIndex.Type, 256);
    defer allocator.free(active_indices);
    for (active_indices, 0..) |*index, i| {
        index.* = @intCast(i);
    }

    // The shuffling allocation precedes one allocation per slot; the last slot fails.
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = preset.SLOTS_PER_EPOCH },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        EpochShuffling.init(
            failing.allocator(),
            [_]u8{0} ** 32,
            0,
            active_indices,
        ),
    );
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

test "memory_safety: computeEpochShuffling should leave active_indices to the caller on failure" {
    const allocator = std.testing.allocator;
    const validator_count = 256;

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 350_000 });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, validator_count);
    defer test_state.deinit();

    // Owned by the test allocator, not the failing one: freeing it here double-frees if
    // computeEpochShuffling wrongly adopts the slice on the error path.
    const active_indices = try allocator.alloc(ct.primitive.ValidatorIndex.Type, validator_count);
    defer allocator.free(active_indices);

    for (active_indices, 0..) |*index, i| {
        index.* = @intCast(i);
    }

    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(
        error.OutOfMemory,
        computeEpochShuffling(failing.allocator(), test_state.cached_state.state, active_indices, 0),
    );
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}
