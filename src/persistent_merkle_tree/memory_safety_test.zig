const std = @import("std");

const Node = @import("Node.zig");
const Gindex = @import("gindex.zig").Gindex;
const proof = @import("proof.zig");

test "setNodesGrouped should release an intermediate root when a later group exhausts the pool" {
    var pool = try Node.Pool.init(.{
        .page_allocator = std.testing.allocator,
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

    // The length update runs first. Once it succeeds, its temporary root owns this node.
    const replacement_length_node = try pool.createLeafFromUint(100);
    defer if (!replacement_length_node.getState(&pool).isFree()) {
        pool.unref(replacement_length_node);
    };

    // The data update runs second, and the test fails before this node is attached.
    const replacement_data_node = try pool.createLeafFromUint(101);
    defer pool.unref(replacement_data_node);

    var capacity_fill_nodes: std.ArrayList(Node.Id) = .empty;
    defer capacity_fill_nodes.deinit(std.testing.allocator);

    // Fill the pool, then give one slot back. The length update needs that one slot; the data
    // update needs more space and exhausts the fixed pool.
    while (pool.createLeafFromUint(0)) |id| {
        try capacity_fill_nodes.append(std.testing.allocator, id);
    } else |err| switch (err) {
        error.PoolExhausted => {},
    }
    pool.unref(capacity_fill_nodes.pop().?);

    const nodes_in_use_before_update = pool.getNodesInUse();
    // A list commit updates the length at depth 1 and the first data leaf at depth 2.
    const replacement_length_gindex = Gindex.fromDepth(1, 1);
    const replacement_data_gindex = Gindex.fromDepth(2, 0);
    const replacement_gindices = [_]Gindex{
        replacement_length_gindex,
        replacement_data_gindex,
    };
    var replacement_nodes = [_]Node.Id{ replacement_length_node, replacement_data_node };

    try std.testing.expectError(
        error.PoolExhausted,
        root.setNodesGrouped(&pool, &replacement_gindices, &replacement_nodes),
    );

    // The first update put the replacement length under the intermediate root. When the second
    // update fails, rolling back that root frees the length with it.
    try std.testing.expect(replacement_length_node.getState(&pool).isFree());

    // The original root was never consumed, and the failed second update never attached the data.
    try std.testing.expect(!root.getState(&pool).isFree());
    try std.testing.expect(!replacement_data_node.getState(&pool).isFree());

    // The intermediate root adds one node and rollback removes it again. The baseline already
    // counted the replacement length, so freeing that node is the only net change.
    try std.testing.expectEqual(nodes_in_use_before_update - 1, pool.getNodesInUse());

    for (capacity_fill_nodes.items) |id| pool.unref(id);
}

test "compact multiproof reconstruction should reclaim partial nodes on pool exhaustion" {
    var leaves = [_][32]u8{
        [_]u8{1} ** 32,
        [_]u8{2} ** 32,
    };
    // The descriptor is a branch with two leaf children.
    const descriptor = [_]u8{0b0110_0000};

    // One free slot fails on the right leaf; two fail on the parent branch.
    for ([_]usize{ 1, 2 }) |available_slots| {
        var pool = try Node.Pool.init(.{
            .page_allocator = std.testing.allocator,
            .allocator = std.testing.allocator,
            .pool_size = 8,
        });
        defer pool.deinit();

        var capacity_fill_nodes: std.ArrayList(Node.Id) = .empty;
        defer capacity_fill_nodes.deinit(std.testing.allocator);

        while (pool.createLeafFromUint(0)) |id| {
            try capacity_fill_nodes.append(std.testing.allocator, id);
        } else |err| switch (err) {
            error.PoolExhausted => {},
        }
        for (0..available_slots) |_| {
            pool.unref(capacity_fill_nodes.pop().?);
        }

        const baseline = pool.getNodesInUse();
        try std.testing.expectError(
            error.PoolExhausted,
            proof.createNodeFromCompactMultiProof(&pool, &leaves, &descriptor),
        );

        try std.testing.expectEqual(baseline, pool.getNodesInUse());

        for (capacity_fill_nodes.items) |id| pool.unref(id);
    }
}

test "fillWithContents exhaustion should preserve inputs and restore pool slots" {
    const test_cases = [_]struct {
        contents_len: usize,
        pool_size: u32,
    }{
        // A partially built level above one completed level.
        .{ .contents_len = 8, .pool_size = 6 },
        // No parent in the failing level above two completed levels.
        .{ .contents_len = 8, .pool_size = 7 },
        // An odd completed level whose last parent includes a zero child.
        .{ .contents_len = 5, .pool_size = 5 },
    };

    for (test_cases) |test_case| {
        var pool = try Node.Pool.init(.{
            .page_allocator = std.testing.allocator,
            .allocator = std.testing.allocator,
            .pool_size = test_case.pool_size,
        });
        defer pool.deinit();

        const leaf = try pool.createLeafFromUint(1);
        defer pool.unref(leaf);

        var contents = [_]Node.Id{leaf} ** 8;
        const contents_before = contents;
        const leaf_state_before = leaf.getState(&pool);
        const nodes_in_use_before = pool.getNodesInUse();

        try std.testing.expectError(
            error.PoolExhausted,
            Node.fillWithContents(&pool, contents[0..test_case.contents_len], 3),
        );

        try std.testing.expectEqualSlices(
            Node.Id,
            contents_before[0..test_case.contents_len],
            contents[0..test_case.contents_len],
        );
        try std.testing.expectEqual(nodes_in_use_before, pool.getNodesInUse());
        try std.testing.expectEqual(leaf_state_before, leaf.getState(&pool));
    }
}
