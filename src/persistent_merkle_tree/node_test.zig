const std = @import("std");

const max_depth = @import("hashing").max_depth;

const Node = @import("Node.zig");
const Gindex = @import("gindex.zig").Gindex;

test "Node.State" {
    const State = Node.State;

    var state: State = State.initNextFree(@enumFromInt(100));
    try std.testing.expect(state.isFree());
    try std.testing.expectEqual(@as(Node.Id, @enumFromInt(100)), state.getNextFree());

    state = State.branch_lazy;
    try std.testing.expect(state.isBranch());
    try std.testing.expect(state.isBranchLazy());
    try std.testing.expect(!state.isZero());
    try std.testing.expect(!state.isLeaf());
    try std.testing.expect(!state.isBranchComputed());

    _ = try state.incRefCount();
    try std.testing.expect(state.isBranch());
    try std.testing.expect(state.isBranchLazy());
    try std.testing.expect(!state.isZero());
    try std.testing.expect(!state.isLeaf());
    try std.testing.expect(!state.isBranchComputed());

    state.setBranchComputed();
    try std.testing.expect(state.isBranch());
    try std.testing.expect(state.isBranchComputed());
    try std.testing.expect(!state.isBranchLazy());
    try std.testing.expect(!state.isZero());
    try std.testing.expect(!state.isLeaf());

    state = State.zero;
    try std.testing.expect(state.isZero());
    try std.testing.expect(!state.isLeaf());
    try std.testing.expect(!state.isBranch());
    try std.testing.expect(!state.isBranchLazy());
    try std.testing.expect(!state.isBranchComputed());

    state = State.leaf;
    try std.testing.expect(state.isLeaf());
    try std.testing.expect(!state.isZero());
    try std.testing.expect(!state.isBranch());
    try std.testing.expect(!state.isBranchLazy());
    try std.testing.expect(!state.isBranchComputed());
}

test "Pool" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 10);
    defer pool.deinit();
    const p = &pool;

    const hash1: [32]u8 = [_]u8{1} ** 32;
    const hash2: [32]u8 = [_]u8{2} ** 32;

    const leaf1_id = try pool.createLeaf(&hash1);
    const leaf2_id = try pool.createLeaf(&hash2);

    const branch1_id = try pool.createBranch(leaf1_id, leaf2_id);
    const branch2_id = try pool.createBranch(branch1_id, @enumFromInt(0));
    const branch3_id = try pool.createBranch(leaf2_id, @enumFromInt(0));

    // unrefing branch2 should unref all linked nodes except branch3 and leaf2 which is still refed by branch3
    pool.unref(branch2_id);

    try std.testing.expect(branch2_id.getState(p).isFree());
    try std.testing.expect(branch1_id.getState(p).isFree());
    try std.testing.expect(leaf1_id.getState(p).isFree());

    // unrefing branch3 should unref remaining linked nodes
    pool.unref(branch3_id);

    try std.testing.expect(leaf2_id.getState(p).isFree());
    try std.testing.expect(branch3_id.getState(p).isFree());

    // check if the free list is correct
    const next_free: Node.Id = pool.next_free_node;
    try std.testing.expectEqual(leaf2_id, next_free);
    try std.testing.expectEqual(branch3_id, next_free.getState(p).getNextFree());
    try std.testing.expectEqual(leaf1_id, next_free.getState(p).getNextFree().getState(p).getNextFree());
    try std.testing.expectEqual(branch1_id, next_free.getState(p).getNextFree().getState(p).getNextFree().getState(p).getNextFree());
    try std.testing.expectEqual(branch2_id, next_free.getState(p).getNextFree().getState(p).getNextFree().getState(p).getNextFree().getState(p).getNextFree());
}

test "Pool - automatic capacity growth beyond pre-heat" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1); // intentionally tiny
    defer pool.deinit();
    const p = &pool;

    var ids: [50]Node.Id = undefined;
    for (0..50) |i| {
        ids[i] = try pool.createLeafFromUint(@intCast(i));
    }

    // The backing ArrayList should have grown to accommodate all 50 leaves
    try std.testing.expect(pool.nodes.len >= max_depth + 50);

    // All allocated leaves must still be live, then unref
    for (ids) |id| {
        try std.testing.expect(!id.getState(p).isFree());
        pool.unref(id);
    }
}

test "All zero hashes (depth>0) point both children to the previous depth" {
    var pool = try Node.Pool.init(std.testing.allocator, 1);
    defer pool.deinit();
    const p = &pool;

    // depth i lives at Id i (0‑based)
    for (1..max_depth) |d| {
        const id: Node.Id = @enumFromInt(d);
        const prev: Node.Id = @enumFromInt(d - 1);

        try std.testing.expectEqual(prev, try id.getLeft(p));
        try std.testing.expectEqual(prev, try id.getRight(p));
    }
}

test "Node free-list re-uses the lowest recently-freed Id first" {
    var pool = try Node.Pool.init(std.testing.allocator, 2);
    defer pool.deinit();

    const n1 = try pool.createLeafFromUint(1);
    pool.unref(n1); // n1 is back on the freelist
    const n2 = try pool.createLeafFromUint(2);
    defer pool.unref(n2);
    try std.testing.expectEqual(n1, n2); // should recycle the same Id
}

test "Navigation - invalid node access is rejected" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 8);
    defer pool.deinit();
    const p = &pool;

    // A freshly‑minted leaf has no children
    const leaf = try pool.createLeafFromUint(42);
    defer pool.unref(leaf);
    try std.testing.expectError(Node.Error.InvalidNode, leaf.getLeft(p));
    try std.testing.expectError(Node.Error.InvalidNode, leaf.getRight(p));

    // The depth‑0 zero‑hash node (Id 0) likewise has no children
    const zero0: Node.Id = @enumFromInt(0);
    try std.testing.expectError(Node.Error.InvalidNode, zero0.getLeft(p));
    try std.testing.expectError(Node.Error.InvalidNode, zero0.getRight(p));
}

test "alloc returns a set of unique nodes" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1);
    defer pool.deinit();
    const p = &pool;

    var nodes: [max_depth]Node.Id = undefined;
    _ = try p.alloc(&nodes);
    defer p.free(&nodes);

    var node_set = std.AutoHashMap(Node.Id, void).init(allocator);
    defer node_set.deinit();

    for (nodes) |node| {
        try node_set.put(node, {});
    }

    try std.testing.expectEqual(nodes.len, node_set.count());
}

test "get/setNode" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1);
    defer pool.deinit();
    const p = &pool;

    const zero3: Node.Id = @enumFromInt(3);

    try std.testing.expectEqual(@as(Node.Id, @enumFromInt(0)), try zero3.getNode(p, Gindex.fromDepth(3, 0)));

    const leaf = try pool.createLeafFromUint(42);
    const new_node = try zero3.setNode(p, Gindex.fromDepth(3, 0), leaf);
    defer pool.unref(new_node);
    try std.testing.expectEqual(leaf, try new_node.getNode(p, Gindex.fromDepth(3, 0)));
}

test "setNodes for checkpoint tree" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 10);
    defer pool.deinit();
    const p = &pool;

    const epoch_node = try pool.createLeafFromUint(42);
    const root = [_]u8{0} ** 32;
    const root_node = try pool.createLeaf(&root);
    const parent = try pool.createBranch(epoch_node, root_node);
    defer pool.unref(parent);

    const new_epoch_node = try pool.createLeafFromUint(100);
    const new_root_node = try pool.createLeaf(&root);

    var new_nodes = [_]Node.Id{ new_epoch_node, new_root_node };
    const new_parent = try parent.setNodes(p, &[_]Gindex{ Gindex.fromUint(2), Gindex.fromUint(3) }, &new_nodes);
    try std.testing.expectEqual(new_epoch_node, try new_parent.getNode(p, Gindex.fromDepth(1, 0)));

    var out: [2]Node.Id = undefined;
    try new_parent.getNodesAtDepth(p, 1, 0, &out);
    defer pool.unref(new_parent);
    try std.testing.expectEqual(new_epoch_node, out[0]);
    try std.testing.expectEqual(new_root_node, out[1]);
}

test "Depth helpers - round-trip setNodesAtDepth / getNodesAtDepth" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();
    const p = &pool;

    // A ‘blank’ root: branch of two depth‑1 zero‑nodes ensures proper navigation
    const root = try pool.createBranch(@enumFromInt(1), @enumFromInt(1));
    defer pool.unref(root);
    // Four leaves to be inserted at depth 2 (gindexes 4-7)
    var leaves: [4]Node.Id = undefined;
    for (0..4) |i| {
        leaves[i] = try pool.createLeafFromUint(@intCast(i + 100));
    }

    const indices = [_]usize{ 0, 1, 2, 3 };
    const depth: u8 = 2;

    const new_root = try root.setNodesAtDepth(p, depth, &indices, &leaves);
    defer pool.unref(new_root);
    // Verify individual look‑ups
    for (indices, 0..) |idx, i| {
        const g = Gindex.fromDepth(depth, idx);
        try std.testing.expectEqual(leaves[i], try new_root.getNode(p, g));
    }

    // Verify bulk retrieval helper
    var out: [4]Node.Id = undefined;
    try new_root.getNodesAtDepth(p, depth, 0, &out);
    for (0..4) |i| try std.testing.expectEqual(leaves[i], out[i]);
}

const TestCase = struct {
    depth: u6,
    gindexes: []const usize,
    new_nodes: ?u8,
};

fn createTestCase(d: u6, gindexes: anytype, new_nodes: ?u8) TestCase {
    return .{
        .depth = d,
        .gindexes = &gindexes,
        .new_nodes = new_nodes,
    };
}

// refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/persistent-merkle-tree/test/unit/tree.test.ts#L138
const test_cases = [_]TestCase{
    // depth 1
    createTestCase(1, [_]usize{2}, null),
    createTestCase(1, [_]usize{ 2, 3 }, null),
    // depth 2
    createTestCase(2, [_]usize{4}, null),
    createTestCase(2, [_]usize{6}, null),
    createTestCase(2, [_]usize{ 4, 6 }, null),
    // depth 3
    createTestCase(3, [_]usize{9}, null),
    createTestCase(3, [_]usize{12}, null),
    createTestCase(3, [_]usize{ 9, 10 }, null),
    createTestCase(3, [_]usize{ 13, 14 }, null),
    createTestCase(3, [_]usize{ 9, 10, 13, 14 }, null),
    createTestCase(3, [_]usize{ 8, 9, 10, 11, 12, 13, 14, 15 }, null),
    // depth 4
    createTestCase(4, [_]usize{16}, null),
    createTestCase(4, [_]usize{ 16, 17 }, null),
    createTestCase(4, [_]usize{ 16, 20 }, null),
    createTestCase(4, [_]usize{ 16, 20, 30 }, null),
    createTestCase(4, [_]usize{ 16, 20, 30, 31 }, null),
    // depth 5
    createTestCase(5, [_]usize{33}, null),
    createTestCase(5, [_]usize{ 33, 34 }, null),
    // depth 10
    createTestCase(10, [_]usize{ 1024, 1061, 1098, 1135, 1172, 1209, 1246, 1283 }, null),
    // depth 40
    createTestCase(40, [_]usize{ (2 << 39) + 1000, (2 << 39) + 1_000_000, (2 << 39) + 1_000_000_000 }, null),
    createTestCase(40, [_]usize{ 1157505940782, 1349082402477, 1759777921993 }, null),
    // new tests to also confirm the new nodes created to make sure there is no leaked/orphaned nodes during setNodes apis
    // set all leaves at depth 4, need 15 new branch nodes
    createTestCase(4, [_]usize{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 }, 15),
    // set first and last leafs, need 7 new branch nodes
    createTestCase(4, [_]usize{ 16, 31 }, 7),
    // set first, second last and last leafs, need 7 new branch nodes
    createTestCase(4, [_]usize{ 16, 30, 31 }, 7),
    // same to above plus first node in the right branch, need 9 new branch nodes
    createTestCase(4, [_]usize{ 16, 24, 30, 31 }, 9),
    // same to above, 24 and 25 should need only 1 parent, still need 9 new branch nodes
    createTestCase(4, [_]usize{ 16, 24, 25, 30, 31 }, 9),
    // first node plus the whole right branch, need 11 new branch nodes
    createTestCase(4, [_]usize{ 16, 24, 25, 26, 27, 28, 29, 30, 31 }, 11),
    // first node plus even nodes in the right branch, need 11 new branch nodes
    createTestCase(4, [_]usize{ 16, 24, 26, 28, 30 }, 11),
    // first node plus odd nodes in the right branch, need 11 new branch nodes
    createTestCase(4, [_]usize{ 16, 25, 27, 29, 31 }, 11),
};

test "setNodesAtDepth, setNodes vs setNode multiple times" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 10);
    defer pool.deinit();
    const p = &pool;

    for (test_cases) |tc| {
        const depth = tc.depth;
        const base_gindex = Gindex.fromDepth(depth, 0);
        var gindexes = try allocator.alloc(Gindex, tc.gindexes.len);
        defer allocator.free(gindexes);
        var indexes = try allocator.alloc(usize, gindexes.len);
        defer allocator.free(indexes);
        var leaves = try allocator.alloc(Node.Id, gindexes.len);
        defer allocator.free(leaves);
        var root_ok: Node.Id = @enumFromInt(depth);
        defer pool.unref(root_ok);
        var root: Node.Id = @enumFromInt(depth);
        defer pool.unref(root);
        var root2: Node.Id = @enumFromInt(depth);
        defer pool.unref(root2);

        for (tc.gindexes, 0..) |gindex, i| {
            gindexes[i] = Gindex.fromUint(@intCast(gindex));
            indexes[i] = gindex - @intFromEnum(base_gindex);
            const leaf = try pool.createLeafFromUint(@intCast(gindex));
            leaves[i] = leaf;
            const old_root_ok = root_ok;
            root_ok = try root_ok.setNode(p, gindexes[i], leaf);
            // Unref the old root after setNode creates a new one
            if (old_root_ok != @as(Node.Id, @enumFromInt(depth))) {
                pool.unref(old_root_ok);
            }
        }

        var old_nodes = pool.getNodesInUse();
        root = try root.setNodesAtDepth(p, depth, indexes, leaves);
        if (tc.new_nodes) |n| {
            const new_nodes = pool.getNodesInUse() - old_nodes;
            try std.testing.expectEqual(n, new_nodes);
        }
        old_nodes = pool.getNodesInUse();
        root2 = try root.setNodes(p, gindexes, leaves);
        if (tc.new_nodes) |n| {
            const new_nodes = pool.getNodesInUse() - old_nodes;
            try std.testing.expectEqual(n, new_nodes);
        }

        const hash_ok = root_ok.getRoot(p);

        const hash = root.getRoot(p);
        try std.testing.expectEqualSlices(u8, hash_ok, hash);

        const hash2 = root2.getRoot(p);
        try std.testing.expectEqualSlices(u8, hash_ok, hash2);
    }
}

test "hashing sanity check" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 10);
    defer pool.deinit();
    const p = &pool;

    const leaf = try pool.createLeafFromUint(0);
    const zero0: Node.Id = @enumFromInt(0);

    // sanity check that a manually zeroed node is actually zero
    try std.testing.expectEqualSlices(u8, zero0.getRoot(p), leaf.getRoot(p));

    const branch1 = try pool.createBranch(leaf, leaf);
    const branch2 = try pool.createBranch(branch1, branch1);
    defer pool.unref(branch2);
    const zero2: Node.Id = @enumFromInt(2);

    try std.testing.expectEqualSlices(u8, zero2.getRoot(p), branch2.getRoot(p));
}

test "Pool serialization - basic round trip" {
    const allocator = std.testing.allocator;

    var pool = try Node.Pool.init(allocator, 10);

    const hash1: [32]u8 = [_]u8{1} ** 32;
    const hash2: [32]u8 = [_]u8{2} ** 32;
    const hash3: [32]u8 = [_]u8{3} ** 32;

    const leaf1_id = try pool.createLeaf(&hash1);
    const leaf2_id = try pool.createLeaf(&hash2);
    const leaf3_id = try pool.createLeaf(&hash3);
    const branch1_id = try pool.createBranch(leaf1_id, leaf2_id);
    const root_id = try pool.createBranch(branch1_id, leaf3_id);

    const original_root_hash = root_id.getRoot(&pool).*;

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try pool.serialize(buffer.writer());

    pool.unref(root_id);
    pool.deinit();

    var fbs = std.io.fixedBufferStream(buffer.items);
    const header = try Node.Pool.readHeader(fbs.reader());
    var restored_pool = try Node.Pool.deserialize(allocator, fbs.reader(), header);
    defer {
        restored_pool.unref(root_id);
        restored_pool.deinit();
    }

    const restored_root_hash = root_id.getRoot(&restored_pool).*;
    try std.testing.expectEqualSlices(u8, &original_root_hash, &restored_root_hash);

    try std.testing.expect(!leaf1_id.getState(&restored_pool).isFree());
    try std.testing.expect(!leaf2_id.getState(&restored_pool).isFree());
    try std.testing.expect(!leaf3_id.getState(&restored_pool).isFree());
    try std.testing.expect(!branch1_id.getState(&restored_pool).isFree());
    try std.testing.expect(!root_id.getState(&restored_pool).isFree());
}

test "Pool serialization - with free nodes" {
    const allocator = std.testing.allocator;

    var pool = try Node.Pool.init(allocator, 20);

    const hash1: [32]u8 = [_]u8{1} ** 32;
    const hash2: [32]u8 = [_]u8{2} ** 32;

    const leaf1_id = try pool.createLeaf(&hash1);
    const leaf2_id = try pool.createLeaf(&hash2);
    const leaf3_id = try pool.createLeaf(&hash1);
    const leaf4_id = try pool.createLeaf(&hash2);

    const branch1_id = try pool.createBranch(leaf1_id, leaf2_id);
    const branch2_id = try pool.createBranch(leaf3_id, leaf4_id);
    const root_id = try pool.createBranch(branch1_id, branch2_id);

    pool.unref(branch2_id);

    try std.testing.expect(branch2_id.getState(&pool).isFree());
    try std.testing.expect(leaf3_id.getState(&pool).isFree());
    try std.testing.expect(leaf4_id.getState(&pool).isFree());
    try std.testing.expect(!root_id.getState(&pool).isFree());

    const original_root_hash = root_id.getRoot(&pool).*;
    const original_next_free = pool.next_free_node;

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try pool.serialize(buffer.writer());

    pool.unref(root_id);
    pool.deinit();

    var fbs = std.io.fixedBufferStream(buffer.items);
    const header = try Node.Pool.readHeader(fbs.reader());
    var restored_pool = try Node.Pool.deserialize(allocator, fbs.reader(), header);
    defer {
        restored_pool.unref(root_id);
        restored_pool.deinit();
    }

    const restored_root_hash = root_id.getRoot(&restored_pool).*;
    try std.testing.expectEqualSlices(u8, &original_root_hash, &restored_root_hash);

    try std.testing.expect(branch2_id.getState(&restored_pool).isFree());
    try std.testing.expect(leaf3_id.getState(&restored_pool).isFree());
    try std.testing.expect(leaf4_id.getState(&restored_pool).isFree());

    try std.testing.expect(!root_id.getState(&restored_pool).isFree());
    try std.testing.expect(!branch1_id.getState(&restored_pool).isFree());
    try std.testing.expect(!leaf1_id.getState(&restored_pool).isFree());
    try std.testing.expect(!leaf2_id.getState(&restored_pool).isFree());

    try std.testing.expectEqual(original_next_free, restored_pool.next_free_node);

    const new_leaf = try restored_pool.createLeaf(&hash1);
    defer restored_pool.unref(new_leaf);
    try std.testing.expect(!new_leaf.getState(&restored_pool).isFree());
}

test "Pool serialization - empty pool" {
    const allocator = std.testing.allocator;

    var pool = try Node.Pool.init(allocator, 10);

    const original_next_free = pool.next_free_node;

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try pool.serialize(buffer.writer());

    pool.deinit();

    var fbs = std.io.fixedBufferStream(buffer.items);
    const header = try Node.Pool.readHeader(fbs.reader());
    var restored_pool = try Node.Pool.deserialize(allocator, fbs.reader(), header);
    defer restored_pool.deinit();

    try std.testing.expectEqual(original_next_free, restored_pool.next_free_node);

    const zero0: Node.Id = @enumFromInt(0);
    try std.testing.expect(zero0.getState(&restored_pool).isZero());
}

test "Pool serialization - file header validation" {
    {
        var bad_magic = [_]u8{0} ** 24;
        var fbs = std.io.fixedBufferStream(&bad_magic);
        const result = Node.Pool.readHeader(fbs.reader());
        try std.testing.expectError(error.InvalidMagic, result);
    }

    {
        var bad_version: [24]u8 = undefined;
        @memset(&bad_version, 0);
        @memcpy(bad_version[0..8], "LSMTPOOL");
        std.mem.writeInt(u32, bad_version[8..12], 99, .little);
        var fbs = std.io.fixedBufferStream(&bad_version);
        const result = Node.Pool.readHeader(fbs.reader());
        try std.testing.expectError(error.UnsupportedVersion, result);
    }
}

test "Pool serialization - compression effectiveness" {
    const allocator = std.testing.allocator;

    var pool = try Node.Pool.init(allocator, 100);

    const hash1: [32]u8 = [_]u8{1} ** 32;
    const hash2: [32]u8 = [_]u8{2} ** 32;

    const leaf1_id = try pool.createLeaf(&hash1);
    const leaf2_id = try pool.createLeaf(&hash2);
    const branch_id = try pool.createBranch(leaf1_id, leaf2_id);

    const original_root_hash = branch_id.getRoot(&pool).*;

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try pool.serialize(buffer.writer());

    const raw_size: usize = 20 + 100 * (32 + 4 + 4 + 4);
    try std.testing.expect(buffer.items.len < raw_size);

    pool.unref(branch_id);
    pool.deinit();

    var fbs = std.io.fixedBufferStream(buffer.items);
    const header = try Node.Pool.readHeader(fbs.reader());
    var restored_pool = try Node.Pool.deserialize(allocator, fbs.reader(), header);
    defer {
        restored_pool.unref(branch_id);
        restored_pool.deinit();
    }

    const restored_root_hash = branch_id.getRoot(&restored_pool).*;
    try std.testing.expectEqualSlices(u8, &original_root_hash, &restored_root_hash);
}
