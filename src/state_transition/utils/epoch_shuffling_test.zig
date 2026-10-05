//! Tests for `epoch_shuffling.zig`.

const std = @import("std");
const ct = @import("consensus_types");
const preset = @import("preset").preset;
const EpochShuffling = @import("epoch_shuffling.zig").EpochShuffling;
const innerShuffleList = @import("swap_or_not_shuffle").innerShuffleList;

test "EpochShuffling matches u64 shuffling for wide validator indices" {
    const allocator = std.testing.allocator;
    for ([_]usize{ 0, 1, 2, 3, 31, 255, 256, 257, 4097 }) |count| {
        for ([_]u8{ 0, 1, 255 }) |seed_byte| {
            const input = try allocator.alloc(u64, count);
            defer allocator.free(input);
            for (input, 0..) |*index, i| index.* = std.math.maxInt(u64) - i * 17;
            const seed = [_]u8{seed_byte} ** 32;

            const expected = try allocator.dupe(u64, input);
            defer allocator.free(expected);
            try innerShuffleList(u64, expected, &seed, preset.SHUFFLE_ROUND_COUNT, false);

            const actual = blk: {
                const active_indices = try allocator.dupe(u64, input);
                errdefer allocator.free(active_indices);
                break :blk try EpochShuffling.init(allocator, seed, 42, active_indices);
            };
            defer actual.deinit();

            try std.testing.expectEqualSlices(u64, input, actual.active_indices);
            try std.testing.expectEqualSlices(u64, expected, actual.shuffling);
            var offset: usize = 0;
            for (actual.committees) |committees| {
                for (committees) |committee| {
                    try std.testing.expectEqualSlices(u64, expected[offset..][0..committee.len], committee);
                    offset += committee.len;
                }
            }
            try std.testing.expectEqual(count, offset);
        }
    }
}

test "memory_safety: EpochShuffling.init frees output when positions allocation fails" {
    const allocator = std.testing.allocator;
    const active_indices = try allocator.dupe(u64, &.{ 1, 7, std.math.maxInt(u64) });
    defer allocator.free(active_indices);

    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
    try std.testing.expectError(
        error.OutOfMemory,
        EpochShuffling.init(failing.allocator(), [_]u8{0} ** 32, 0, active_indices),
    );
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    try std.testing.expectEqualSlices(u64, &.{ 1, 7, std.math.maxInt(u64) }, active_indices);
}

test "memory_safety: EpochShuffling.init should free completed committees when a later slot allocation fails" {
    const allocator = std.testing.allocator;
    const active_indices = try allocator.alloc(ct.primitive.ValidatorIndex.Type, 256);
    defer allocator.free(active_indices);
    for (active_indices, 0..) |*index, i| {
        index.* = @intCast(i);
    }

    // The shuffling, positions, and first slot allocations succeed; the second slot allocation fails.
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 3 },
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

    // Shuffling, positions, and one allocation per slot precede the final struct allocation.
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 2 + preset.SLOTS_PER_EPOCH },
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
