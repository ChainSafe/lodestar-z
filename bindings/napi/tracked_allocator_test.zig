const std = @import("std");
const Node = @import("persistent_merkle_tree").Node;
const TrackedAllocator = @import("tracked_allocator.zig");

test "tracks live bytes through allocation, resize, remap, failures, and free" {
    var buffer: [1024]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&buffer);
    var failing = std.testing.FailingAllocator.init(fixed.allocator(), .{});
    var tracked: TrackedAllocator = .{ .backing = failing.allocator() };
    const allocator = tracked.allocator();

    var bytes = try allocator.alloc(u8, 128);
    try std.testing.expectEqual(128, tracked.bytes_in_use);
    const other = try allocator.alloc(u8, 32);
    try std.testing.expectEqual(160, tracked.bytes_in_use);
    allocator.free(other);
    try std.testing.expectEqual(128, tracked.bytes_in_use);
    try std.testing.expect(allocator.resize(bytes, 256));
    bytes = bytes.ptr[0..256];
    try std.testing.expectEqual(256, tracked.bytes_in_use);
    bytes = allocator.remap(bytes, 64).?;
    try std.testing.expectEqual(64, tracked.bytes_in_use);

    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;
    try std.testing.expectError(error.OutOfMemory, allocator.alloc(u8, 1));
    try std.testing.expect(!allocator.resize(bytes, 128));
    try std.testing.expectEqual(null, allocator.remap(bytes, 128));
    try std.testing.expectEqual(64, tracked.bytes_in_use);

    allocator.free(bytes);
    try std.testing.expectEqual(0, tracked.bytes_in_use);
}

test "shared pool payload stays charged until its last parent is released" {
    var tracked: TrackedAllocator = .{ .backing = std.testing.allocator };
    var pool = try Node.Pool.init(.{
        .allocator = tracked.allocator(),
        .page_allocator = std.testing.allocator,
        .pool_size = 3,
    });
    defer pool.deinit();
    const baseline_nodes = pool.getNodesInUse();

    const leaf = try pool.createChunkedLeafEmpty(1);
    const payload_bytes = tracked.bytes_in_use;
    try std.testing.expect(payload_bytes > 0);
    const first = try pool.createBranch(leaf, leaf);
    const second = try pool.createBranch(leaf, leaf);
    try std.testing.expectEqual(payload_bytes, tracked.bytes_in_use);
    try std.testing.expectEqual(baseline_nodes + 3, pool.getNodesInUse());

    pool.unref(first);
    try std.testing.expectEqual(payload_bytes, tracked.bytes_in_use);
    pool.unref(second);
    try std.testing.expectEqual(0, tracked.bytes_in_use);
    try std.testing.expectEqual(baseline_nodes, pool.getNodesInUse());
}
