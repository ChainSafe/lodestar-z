const std = @import("std");
const progressive = @import("progressive.zig");
const Node = @import("persistent_merkle_tree").Node;

test "progressive builder needs no subtree offset allocation" {
    const allocator = std.testing.allocator;
    inline for (.{ 0, 1, 2, 5, 6, 21, 22, 85, 86, 341, 342 }) |count| {
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = failing.allocator(), .pool_size = 2048 });
        defer pool.deinit();
        const baseline = pool.getNodesInUse();
        var nodes: [count]Node.Id = undefined;
        var chunks: [count][32]u8 = undefined;
        for (&chunks, &nodes, 0..) |*chunk, *node, i| {
            chunk.* = @splat(@truncate(i));
            node.* = try pool.createLeaf(chunk);
        }
        const tree = try progressive.fillWithContents(failing.allocator(), &pool, &nodes);
        var expected: [32]u8 = undefined;
        try progressive.merkleizeChunks(allocator, &chunks, &expected);
        try std.testing.expectEqualSlices(u8, &expected, tree.getRoot(&pool));
        pool.unref(tree);
        try std.testing.expectEqual(baseline, pool.getNodesInUse());
        try std.testing.expect(!failing.has_induced_failure);
    }
}

test "progressive Merkleization matches tree roots without scratch allocation" {
    const allocator = std.testing.allocator;
    inline for (.{ 0, 1, 2, 5, 6, 21, 22, 85, 86, 341, 342, 1365, 1366 }) |count| {
        var chunks: [count][32]u8 = undefined;
        var nodes: [count]Node.Id = undefined;
        var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 8192 });
        defer pool.deinit();
        for (&chunks, &nodes, 0..) |*chunk, *node, i| {
            chunk.* = @splat(@truncate(i));
            node.* = try pool.createLeaf(chunk);
        }
        const tree = try progressive.fillWithContents(allocator, &pool, &nodes);
        defer pool.unref(tree);
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        var root: [32]u8 = undefined;
        try progressive.merkleizeChunks(failing.allocator(), &chunks, &root);
        try std.testing.expectEqualSlices(u8, tree.getRoot(&pool), &root);
        try progressive.merkleizeChunksComptime(count, &chunks, &root);
        try std.testing.expectEqualSlices(u8, tree.getRoot(&pool), &root);
        for (chunks, 0..) |chunk, i| try std.testing.expectEqual([_]u8{@truncate(i)} ** 32, chunk);
    }
}
