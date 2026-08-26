const std = @import("std");

const Node = @import("Node.zig");
const Gindex = @import("gindex.zig").Gindex;

test "setNodesGrouped should release an intermediate root when a later group runs out of memory" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .resize_fail_index = 0 });

    var pool = try Node.Pool.init(.{
        .page_allocator = failing.allocator(),
        .allocator = std.testing.allocator,
        .pool_size = 16,
    });
    defer pool.deinit();

    // A list tree stores its content on the left and its length on the right.
    const content_root = try pool.createBranch(
        try pool.createLeafFromUint(1),
        try pool.createLeafFromUint(2),
    );
    const original_length_node = try pool.createLeafFromUint(2);
    const root = try pool.createBranch(content_root, original_length_node);
    defer pool.unref(root);

    const replacement_length_node = try pool.createLeafFromUint(100);
    defer if (!replacement_length_node.getState(&pool).isFree()) {
        pool.unref(replacement_length_node);
    };

    const replacement_data_node = try pool.createLeafFromUint(101);
    defer pool.unref(replacement_data_node);

    // From here on, the pool can reuse free slots but cannot grow.
    failing.fail_index = failing.alloc_index;

    var capacity_fill_nodes: std.ArrayList(Node.Id) = .empty;
    defer capacity_fill_nodes.deinit(std.testing.allocator);

    // Fill the pool, then free one slot. The length update uses it, forcing the data update to
    // grow the pool and fail.
    while (pool.createLeafFromUint(0)) |id| {
        try capacity_fill_nodes.append(std.testing.allocator, id);
    } else |err| switch (err) {
        error.OutOfMemory => {},
    }
    pool.unref(capacity_fill_nodes.pop().?);

    const nodes_in_use_before_update = pool.getNodesInUse();
    const replacement_length_gindex = Gindex.fromDepth(1, 1);
    const replacement_data_gindex = Gindex.fromDepth(2, 0);
    const replacement_gindices = [_]Gindex{
        replacement_length_gindex,
        replacement_data_gindex,
    };
    var replacement_nodes = [_]Node.Id{ replacement_length_node, replacement_data_node };

    try std.testing.expectError(
        error.OutOfMemory,
        root.setNodesGrouped(&pool, &replacement_gindices, &replacement_nodes),
    );

    // Rolling back the temporary root also frees the replacement length it owned. The temporary
    // root itself cancels out of the count, while the original root and replacement data stay ours.
    try std.testing.expect(replacement_length_node.getState(&pool).isFree());
    try std.testing.expectEqual(nodes_in_use_before_update - 1, pool.getNodesInUse());
    try std.testing.expect(!root.getState(&pool).isFree());
    try std.testing.expect(!replacement_data_node.getState(&pool).isFree());

    for (capacity_fill_nodes.items) |id| pool.unref(id);
}
