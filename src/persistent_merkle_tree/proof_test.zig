const std = @import("std");
const testing = std.testing;

const Node = @import("Node.zig");
const Gindex = @import("gindex.zig").Gindex;
const proof = @import("proof.zig");
const Depth = @import("hashing").Depth;

fn makeLeaf(value: u8) [32]u8 {
    var out: [32]u8 = [_]u8{0} ** 32;
    out[0] = value;
    return out;
}

fn buildFullTree(pool: *Node.Pool, depth: usize, next_value: *u8) Node.Error!Node.Id {
    if (depth == 0) {
        const leaf_hash = makeLeaf(next_value.*);
        next_value.* +%= 1;
        return pool.createLeaf(&leaf_hash);
    }

    const left = try buildFullTree(pool, depth - 1, next_value);
    const right = try buildFullTree(pool, depth - 1, next_value);
    return pool.createBranch(left, right);
}

// Verifies a proof for gindex 6 (depth 2, index 2) reconstructs the original root.
test "single proof roundtrip" {
    var pool = try Node.Pool.init(testing.allocator, 128);
    defer pool.deinit();

    const leaf_hashes = [_][32]u8{
        makeLeaf(1),
        makeLeaf(2),
        makeLeaf(3),
        makeLeaf(4),
    };

    const leaf0 = try pool.createLeaf(&leaf_hashes[0]);
    const leaf1 = try pool.createLeaf(&leaf_hashes[1]);
    const leaf2 = try pool.createLeaf(&leaf_hashes[2]);
    const leaf3 = try pool.createLeaf(&leaf_hashes[3]);

    const left = try pool.createBranch(leaf0, leaf1);
    const right = try pool.createBranch(leaf2, leaf3);
    const root = try pool.createBranch(left, right);
    try pool.ref(root);
    defer pool.unref(root);

    const gindex = Gindex.fromDepth(2, 2);

    var single_proof = try proof.createSingleProof(testing.allocator, &pool, root, gindex);
    defer single_proof.deinit(testing.allocator);

    try testing.expectEqualSlices(u8, &leaf_hashes[2], &single_proof.leaf);
    try testing.expectEqual(@as(usize, 2), single_proof.witnesses.len);

    const root_hash = root.getRoot(&pool).*;

    var pool2 = try Node.Pool.init(testing.allocator, 128);
    defer pool2.deinit();

    const reconstructed = try proof.createNodeFromSingleProof(&pool2, gindex, single_proof.leaf, single_proof.witnesses);
    defer pool2.unref(reconstructed);

    const reconstructed_hash = reconstructed.getRoot(&pool2).*;
    try testing.expectEqualSlices(u8, &root_hash, &reconstructed_hash);
}

// Checks every leaf in a depth-4 tree produces the same root after reconstruction.
test "single proof root matches across leaves" {
    const build_depth: usize = 4;
    const pool_capacity: u32 = @intCast((@as(usize, 1) << (build_depth + 1)));

    var pool = try Node.Pool.init(testing.allocator, pool_capacity);
    defer pool.deinit();

    var next_value: u8 = 1;
    const raw_root = try buildFullTree(&pool, build_depth, &next_value);
    try pool.ref(raw_root);
    defer pool.unref(raw_root);

    const expected_root = raw_root.getRoot(&pool).*;
    const leaf_depth: Depth = @intCast(build_depth);
    const leaf_count = @as(usize, 1) << build_depth;

    for (0..leaf_count) |leaf_index| {
        const gindex = Gindex.fromDepth(leaf_depth, leaf_index);
        var single_proof = try proof.createSingleProof(testing.allocator, &pool, raw_root, gindex);
        defer single_proof.deinit(testing.allocator);

        var temp_pool = try Node.Pool.init(testing.allocator, 64);
        defer temp_pool.deinit();

        const rebuilt = try proof.createNodeFromSingleProof(&temp_pool, gindex, single_proof.leaf, single_proof.witnesses);
        defer temp_pool.unref(rebuilt);

        const rebuilt_root = rebuilt.getRoot(&temp_pool).*;
        try testing.expectEqualSlices(u8, &expected_root, &rebuilt_root);
    }
}

// Attempting to prove beyond the tree height should bubble up Node.InvalidNode.
test "single proof invalid navigation" {
    var pool = try Node.Pool.init(testing.allocator, 64);
    defer pool.deinit();

    const leaf_hash = makeLeaf(42);
    const root = try pool.createLeaf(&leaf_hash);
    try pool.ref(root);
    defer pool.unref(root);

    const gindex = Gindex.fromDepth(3, 0);
    try testing.expectError(Node.Error.InvalidNode, proof.createSingleProof(testing.allocator, &pool, root, gindex));
}

// Zero gindex must be rejected by both proof creation and reconstruction entry points.
test "single proof invalid gindex" {
    var pool = try Node.Pool.init(testing.allocator, 8);
    defer pool.deinit();

    const leaf_hash = makeLeaf(9);
    const root = try pool.createLeaf(&leaf_hash);
    try pool.ref(root);
    defer pool.unref(root);

    const zero_gindex: Gindex = @enumFromInt(0);
    try testing.expectError(proof.Error.InvalidGindex, proof.createSingleProof(testing.allocator, &pool, root, zero_gindex));

    const empty_witnesses: []const [32]u8 = &[_][32]u8{};
    try testing.expectError(proof.Error.InvalidGindex, proof.createNodeFromSingleProof(&pool, zero_gindex, leaf_hash, empty_witnesses));
}
