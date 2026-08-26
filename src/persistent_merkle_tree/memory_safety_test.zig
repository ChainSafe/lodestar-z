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

    // This matches a list root: content subtree on the left and length leaf on the right.
    const content_root = try pool.createBranch(
        try pool.createLeafFromUint(1),
        try pool.createLeafFromUint(2),
    );
    const original_length_node = try pool.createLeafFromUint(2);
    const root = try pool.createBranch(content_root, original_length_node);
    defer pool.unref(root);

    // The first group consumes this node; teardown owns it only if rollback does not free it.
    const replacement_length_node = try pool.createLeafFromUint(100);
    defer if (!replacement_length_node.getState(&pool).isFree()) {
        pool.unref(replacement_length_node);
    };

    // The second group fails before consuming this node, so the test retains ownership.
    const replacement_data_node = try pool.createLeafFromUint(101);
    defer pool.unref(replacement_data_node);

    // Fail only later pool growth after the fixture is fully allocated.
    failing.fail_index = failing.alloc_index;

    var capacity_fill_nodes: std.ArrayList(Node.Id) = .empty;
    defer capacity_fill_nodes.deinit(std.testing.allocator);

    // Fill every current pool slot; the next allocation reaches the armed growth OOM.
    while (pool.createLeafFromUint(0)) |id| {
        try capacity_fill_nodes.append(std.testing.allocator, id);
    } else |err| switch (err) {
        error.OutOfMemory => {},
    }
    // Free exactly one slot for the depth-1 group, leaving none for the depth-2 group.
    pool.unref(capacity_fill_nodes.pop().?);

    // Both replacement nodes are rc=0 caller-owned slots, but they still count as in use.
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

    // The first group consumed the replacement length, so grouped rollback must free it.
    try std.testing.expect(replacement_length_node.getState(&pool).isFree());

    // Creating and freeing the intermediate root cancel out. Freeing the replacement length,
    // which was already included in the baseline, leaves one fewer node in use.
    try std.testing.expectEqual(nodes_in_use_before_update - 1, pool.getNodesInUse());

    // The failed grouped update returns no new root, leaving the original root caller-owned.
    try std.testing.expect(!root.getState(&pool).isFree());

    // The second group failed before consuming the replacement data, which remains caller-owned.
    try std.testing.expect(!replacement_data_node.getState(&pool).isFree());

    for (capacity_fill_nodes.items) |id| pool.unref(id);
}
