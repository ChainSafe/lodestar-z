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

    const leaf1_id = try pool.createLeaf(&hash1, false);
    const leaf2_id = try pool.createLeaf(&hash2, false);

    const branch1_id = try pool.createBranch(leaf1_id, leaf2_id, false);
    const branch2_id = try pool.createBranch(branch1_id, @enumFromInt(0), false);
    const branch3_id = try pool.createBranch(leaf2_id, @enumFromInt(0), false);

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
    for (0..50) |i| ids[i] = try pool.createLeafFromUint(@intCast(i), true);

    // The backing ArrayList should have grown to accommodate all 50 leaves
    try std.testing.expect(pool.nodes.len >= max_depth + 50);

    // All allocated leaves must still be live
    for (ids) |id| try std.testing.expect(!id.getState(p).isFree());
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

    const n1 = try pool.createLeafFromUint(1, true);
    pool.unref(n1); // n1 is back on the freelist
    const n2 = try pool.createLeafFromUint(2, true);

    try std.testing.expectEqual(n1, n2); // should recycle the same Id
}

test "Navigation - invalid node access is rejected" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 8);
    defer pool.deinit();
    const p = &pool;

    // A freshly‑minted leaf has no children
    const leaf = try pool.createLeafFromUint(42, true);
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

    const leaf = try pool.createLeafFromUint(42, true);
    const new_node = try zero3.setNode(p, Gindex.fromDepth(3, 0), leaf);

    try std.testing.expectEqual(leaf, try new_node.getNode(p, Gindex.fromDepth(3, 0)));
}

test "getSingleProof returns witnesses from leaf to root" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 8);
    defer pool.deinit();
    const p = &pool;

    const hash_a: [32]u8 = [_]u8{0x0A} ** 32;
    const hash_b: [32]u8 = [_]u8{0x0B} ** 32;
    const hash_c: [32]u8 = [_]u8{0x0C} ** 32;
    const hash_d: [32]u8 = [_]u8{0x0D} ** 32;

    const leaf0 = try pool.createLeaf(&hash_a, false);
    const leaf1 = try pool.createLeaf(&hash_b, false);
    const leaf2 = try pool.createLeaf(&hash_c, false);
    const leaf3 = try pool.createLeaf(&hash_d, false);

    const left_branch = try pool.createBranch(leaf0, leaf1, false);
    const right_branch = try pool.createBranch(leaf2, leaf3, false);
    const root = try pool.createBranch(left_branch, right_branch, true);
    defer pool.unref(root);

    const gindex = Gindex.fromDepth(2, 1);
    const witnesses = try root.getSingleProof(allocator, p, gindex);
    defer allocator.free(witnesses);

    try std.testing.expectEqual(@as(usize, 2), witnesses.len);

    const expected_leaf_sibling = leaf0.getRoot(p);
    try std.testing.expectEqual(expected_leaf_sibling.*, witnesses[0]);

    const expected_branch_sibling = right_branch.getRoot(p);
    try std.testing.expectEqual(expected_branch_sibling.*, witnesses[1]);
}

test "setNodes for checkpoint tree" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 10);
    defer pool.deinit();
    const p = &pool;

    const epoch_node = try pool.createLeafFromUint(42, true);
    const root = [_]u8{0} ** 32;
    const root_node = try pool.createLeaf(&root, true);
    const parent = try pool.createBranch(epoch_node, root_node, true);

    const new_epoch_node = try pool.createLeafFromUint(100, true);
    const new_root_node = try pool.createLeaf(&root, true);

    var new_nodes = [_]Node.Id{ new_epoch_node, new_root_node };
    const new_parent = try parent.setNodes(p, &[_]Gindex{ Gindex.fromUint(2), Gindex.fromUint(3) }, &new_nodes);

    try std.testing.expectEqual(new_epoch_node, try new_parent.getNode(p, Gindex.fromDepth(1, 0)));

    var out: [2]Node.Id = undefined;
    try new_parent.getNodesAtDepth(p, 1, 0, &out);
    try std.testing.expectEqual(new_epoch_node, out[0]);
    try std.testing.expectEqual(new_root_node, out[1]);
}

test "Depth helpers - round-trip setNodesAtDepth / getNodesAtDepth" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();
    const p = &pool;

    // A ‘blank’ root: branch of two depth‑1 zero‑nodes ensures proper navigation
    const root = try pool.createBranch(@enumFromInt(1), @enumFromInt(1), true);

    // Four leaves to be inserted at depth 2 (gindexes 4-7)
    var leaves: [4]Node.Id = undefined;
    for (0..4) |i| leaves[i] = try pool.createLeafFromUint(@intCast(i + 100), true);

    const indices = [_]usize{ 0, 1, 2, 3 };
    const depth: u8 = 2;

    const new_root = try root.setNodesAtDepth(p, depth, &indices, &leaves);

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
        var root: Node.Id = @enumFromInt(depth);
        var root2: Node.Id = @enumFromInt(depth);

        for (tc.gindexes, 0..) |gindex, i| {
            gindexes[i] = Gindex.fromUint(@intCast(gindex));
            indexes[i] = gindex - @intFromEnum(base_gindex);
            const leaf = try pool.createLeafFromUint(@intCast(gindex), true);
            leaves[i] = leaf;
            root_ok = try root_ok.setNode(p, gindexes[i], leaf);
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

    const leaf = try pool.createLeafFromUint(0, false);
    const zero0: Node.Id = @enumFromInt(0);

    // sanity check that a manually zeroed node is actually zero
    try std.testing.expectEqualSlices(u8, zero0.getRoot(p), leaf.getRoot(p));

    const branch1 = try pool.createBranch(leaf, leaf, false);
    const branch2 = try pool.createBranch(branch1, branch1, false);
    const zero2: Node.Id = @enumFromInt(2);

    try std.testing.expectEqualSlices(u8, zero2.getRoot(p), branch2.getRoot(p));
}
