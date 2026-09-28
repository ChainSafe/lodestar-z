const std = @import("std");
const pmt = @import("persistent_merkle_tree");
const Node = pmt.Node;
const Gindex = pmt.Gindex;
const ChunkedLeaf = pmt.ChunkedLeaf;
const TreeViewState = @import("tree_view_state.zig").TreeViewState;
const Uint64 = @import("../../type/uint.zig").UintType(64);

test "getChildNode does not publish a cache entry when lookup fails" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{
        .page_allocator = allocator,
        .allocator = allocator,
        .pool_size = 1,
    });
    defer pool.deinit();

    const root = try pool.createLeaf(&([_]u8{0} ** 32));
    var state: TreeViewState = undefined;
    try state.init(allocator, &pool, root);
    defer state.deinit();

    // Failed leaf child navigation must not publish a cache entry.
    const child_gindex = Gindex.fromDepth(1, 0);
    try std.testing.expectError(error.InvalidNode, state.getChildNode(child_gindex));
    try std.testing.expectEqual(@as(usize, 0), state.children_nodes.count());
}

test "editChunkedLeaf copies shared storage once and preserves snapshots" {
    const allocator = std.testing.allocator;
    var counter = std.testing.FailingAllocator.init(allocator, .{});
    var view_counter = std.testing.FailingAllocator.init(allocator, .{});
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = counter.allocator(), .pool_size = 4 });
    defer pool.deinit();

    const root = try pool.createChunkedLeafEmpty(2);
    var state: TreeViewState = undefined;
    try state.init(view_counter.allocator(), &pool, root);
    defer state.deinit();
    var snapshot: TreeViewState = undefined;
    try snapshot.init(allocator, &pool, root);
    defer snapshot.deinit();

    const gindex: Gindex = @enumFromInt(1);
    const original_hash = root.getRoot(&pool).*;
    const allocations_before = counter.alloc_index;
    try state.editChunkedLeaf(gindex, 0, 2, u64, 0, &42, Uint64.tree.fromValuePackedIntoChunk);
    const pending = try state.getChildNode(gindex);
    try std.testing.expect(pending != root);
    try std.testing.expectEqual(allocations_before + 1, counter.alloc_index);
    try std.testing.expectEqual(@as(usize, 1), state.changed.count());
    const first_hash = pending.getRoot(&pool).*;
    const view_allocations = view_counter.alloc_index;

    try state.editChunkedLeaf(gindex, 1, 2, u64, 4, &99, Uint64.tree.fromValuePackedIntoChunk);
    try std.testing.expectEqual(pending, try state.getChildNode(gindex));
    try std.testing.expectEqual(allocations_before + 1, counter.alloc_index);
    try std.testing.expectEqual(view_allocations, view_counter.alloc_index);
    try std.testing.expect(!std.mem.eql(u8, &first_hash, pending.getRoot(&pool)));
    try std.testing.expectEqualSlices(u8, &original_hash, snapshot.root.getRoot(&pool));
    try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, (try root.getChunkedLeafChunks(&pool))[0][0..8], .little));

    try state.commitNodes();
    try std.testing.expectEqual(pending, state.root);
    try std.testing.expectEqual(@as(usize, 0), state.changed.count());
    const committed_hash = state.root.getRoot(&pool).*;
    try state.editChunkedLeaf(gindex, 0, 2, u64, 1, &123, Uint64.tree.fromValuePackedIntoChunk);
    try std.testing.expect(pending != try state.getChildNode(gindex));
    try std.testing.expectEqual(allocations_before + 2, counter.alloc_index);
    try std.testing.expectEqualSlices(u8, &committed_hash, state.root.getRoot(&pool));
}

test "editChunkedLeaf materializes sparse storage and grows valid chunks" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 2 });
    defer pool.deinit();

    const root: Node.Id = @enumFromInt(ChunkedLeaf.k_log2);
    var state: TreeViewState = undefined;
    try state.init(allocator, &pool, root);
    defer state.deinit();

    const gindex: Gindex = @enumFromInt(1);
    try state.editChunkedLeaf(gindex, 0, 3, u64, 0, &42, Uint64.tree.fromValuePackedIntoChunk);
    const pending = try state.getChildNode(gindex);
    try std.testing.expectEqual(@as(u16, 3), try pending.getChunkedLeafLen(&pool));
    const chunks = try pending.getChunkedLeafChunks(&pool);
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(chunks[1..]), 0));

    try state.editChunkedLeaf(gindex, 3, 4, u64, 12, &99, Uint64.tree.fromValuePackedIntoChunk);
    try std.testing.expectEqual(pending, try state.getChildNode(gindex));
    try std.testing.expectEqual(@as(u16, 4), try pending.getChunkedLeafLen(&pool));
    try std.testing.expectEqual(@as(u64, 99), std.mem.readInt(u64, chunks[3][0..8], .little));
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(chunks[4..]), 0));
}

fn editWithAllocationFailures(allocator: std.mem.Allocator, sparse: bool) !void {
    var pool = try Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = allocator, .pool_size = 2 });
    defer pool.deinit();

    const root: Node.Id = if (sparse) @enumFromInt(ChunkedLeaf.k_log2) else try pool.createChunkedLeafEmpty(1);
    var state: TreeViewState = undefined;
    state.init(allocator, &pool, root) catch |err| {
        pool.unref(root);
        return err;
    };
    defer state.deinit();

    const original_hash = root.getRoot(&pool).*;
    const nodes_before = pool.getNodesInUse();
    const gindex: Gindex = @enumFromInt(1);
    state.editChunkedLeaf(gindex, 0, 1, u64, 0, &42, Uint64.tree.fromValuePackedIntoChunk) catch |err| {
        try std.testing.expectEqual(error.OutOfMemory, err);
        try std.testing.expectEqual(nodes_before, pool.getNodesInUse());
        try std.testing.expectEqual(@as(usize, 0), state.changed.count());
        if (state.children_nodes.get(gindex)) |cached| try std.testing.expectEqual(root, cached);
        try std.testing.expectEqualSlices(u8, &original_hash, root.getRoot(&pool));
        return err;
    };
    const chunks = try (try state.getChildNode(gindex)).getChunkedLeafChunks(&pool);
    try std.testing.expectEqual(@as(u64, 42), std.mem.readInt(u64, chunks[0][0..8], .little));
    try std.testing.expectEqualSlices(u8, &original_hash, root.getRoot(&pool));
}

test "memory_safety: editChunkedLeaf allocation failures preserve values and ownership" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, editWithAllocationFailures, .{false});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, editWithAllocationFailures, .{true});
}

test "memory_safety: editChunkedLeaf pool exhaustion preserves values and ownership" {
    const allocator = std.testing.allocator;
    for ([_]bool{ false, true }) |sparse| {
        var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1 });
        defer pool.deinit();

        const root: Node.Id = if (sparse) @enumFromInt(ChunkedLeaf.k_log2) else try pool.createChunkedLeafEmpty(1);
        const blocker: ?Node.Id = if (sparse) try pool.createLeafFromUint(0) else null;
        defer if (blocker) |node| pool.unref(node);
        var state: TreeViewState = undefined;
        try state.init(allocator, &pool, root);
        defer state.deinit();

        const original_hash = root.getRoot(&pool).*;
        const nodes_before = pool.getNodesInUse();
        const gindex: Gindex = @enumFromInt(1);
        try std.testing.expectError(error.PoolExhausted, state.editChunkedLeaf(gindex, 0, 1, u64, 0, &42, Uint64.tree.fromValuePackedIntoChunk));
        try std.testing.expectEqual(nodes_before, pool.getNodesInUse());
        try std.testing.expectEqual(@as(usize, 0), state.changed.count());
        try std.testing.expectEqual(root, try state.getChildNode(gindex));
        try std.testing.expectEqualSlices(u8, &original_hash, root.getRoot(&pool));
    }
}
