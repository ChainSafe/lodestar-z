//! Tests for `epoch_shuffling.zig`.

const std = @import("std");
const ct = @import("consensus_types");
const EpochShuffling = @import("epoch_shuffling.zig").EpochShuffling;

test "memory_safety: EpochShuffling.init should free partial allocations on OOM" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            const active_indices = try allocator.alloc(ct.primitive.ValidatorIndex.Type, 256);
            errdefer allocator.free(active_indices);
            for (active_indices, 0..) |*index, i| index.* = @intCast(i);

            const shuffling = try EpochShuffling.init(allocator, [_]u8{0} ** 32, 0, active_indices);
            defer shuffling.deinit();
        }
    }.run, .{});
}
