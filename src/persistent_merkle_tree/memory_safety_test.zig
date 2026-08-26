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

    const p = &pool;

    const left = try pool.createBranch(
        try pool.createLeafFromUint(1),
        try pool.createLeafFromUint(2),
    );
    const right = try pool.createBranch(
        try pool.createLeafFromUint(3),
        try pool.createLeafFromUint(4),
    );
    const root = try pool.createBranch(left, right);
    defer pool.unref(root);

    const new_length = try pool.createLeafFromUint(100);
    defer if (!new_length.getState(p).isFree()) pool.unref(new_length);

    const new_data = try pool.createLeafFromUint(101);
    defer pool.unref(new_data);

    // Arm OOM after setup: within-capacity node creation still succeeds, but pool growth fails.
    failing.fail_index = failing.alloc_index;

    var filler: std.ArrayList(Node.Id) = .empty;
    defer filler.deinit(std.testing.allocator);

    // Leave one free slot for the depth-1 group, forcing the depth-2 group to grow the pool.
    while (pool.createLeafFromUint(0)) |id| {
        try filler.append(std.testing.allocator, id);
    } else |err| switch (err) {
        error.OutOfMemory => {},
    }
    pool.unref(filler.pop().?);

    const in_use_before = pool.getNodesInUse();
    // Model a list commit: gindex 3 stores the length mix-in and gindex 4 stores data.
    const gindices = [_]Gindex{ Gindex.fromUint(3), Gindex.fromUint(4) };
    var nodes = [_]Node.Id{ new_length, new_data };

    try std.testing.expectError(error.OutOfMemory, root.setNodesGrouped(p, &gindices, &nodes));

    failing.fail_index = std.math.maxInt(usize);

    // The first group consumes new_length, so its rollback must release that node together with
    // the intermediate root. The original root and the unprocessed new_data remain caller-owned.
    try std.testing.expectEqual(in_use_before - 1, pool.getNodesInUse());
    try std.testing.expect(!root.getState(p).isFree());
    try std.testing.expect(!new_data.getState(p).isFree());

    for (filler.items) |id| pool.unref(id);
}
