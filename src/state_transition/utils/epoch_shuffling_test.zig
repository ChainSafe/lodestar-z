//! Tests for `epoch_shuffling.zig`.

const std = @import("std");
const ct = @import("consensus_types");
const preset = @import("preset").preset;
const EpochShuffling = @import("epoch_shuffling.zig").EpochShuffling;

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

test "memory_safety: EpochShuffling.init should free committees when the final allocation fails" {
    const allocator = std.testing.allocator;
    const active_indices = try allocator.alloc(ct.primitive.ValidatorIndex.Type, 256);
    defer allocator.free(active_indices);
    for (active_indices, 0..) |*index, i| {
        index.* = @intCast(i);
    }

    // One shuffling allocation and one allocation per slot precede the final struct allocation.
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 1 + preset.SLOTS_PER_EPOCH },
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
