const std = @import("std");
const testing = std.testing;

const Node = @import("Node.zig");
const Gindex = @import("gindex.zig").Gindex;
const proof = @import("proof.zig");
const Depth = @import("hashing").Depth;
const max_depth: usize = @import("hashing").max_depth;
const hashOne = @import("hashing").hashOne;
const ChunkedLeaf = @import("ChunkedLeaf.zig");

const DescriptorTestCase = struct {
    input: []const u8,
    output: []const bool,
};

const descriptor_test_cases = [_]DescriptorTestCase{
    .{
        .input = &[_]u8{0b1000_0000},
        .output = &[_]bool{true},
    },
    .{
        .input = &[_]u8{ 0b0010_0101, 0b1110_0000 },
        .output = &[_]bool{ false, false, true, false, false, true, false, true, true, true, true },
    },
    .{
        .input = &[_]u8{ 0b0101_0101, 0b1000_0000 },
        .output = &[_]bool{ false, true, false, true, false, true, false, true, true },
    },
    .{
        .input = &[_]u8{0b0101_0110},
        .output = &[_]bool{ false, true, false, true, false, true, true },
    },
};

const descriptor_error_cases = [_][]const u8{
    &[_]u8{ 0b1000_0000, 0 },
    &[_]u8{ 0b0000_0001, 0 },
    &[_]u8{0b0101_0111},
    &[_]u8{ 0b0101_0110, 0 },
};

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

// Fill `chunks[0..valid]` with distinct non-zero leaves; the rest stay zero,
// satisfying the chunked_leaf trailing-zero invariant for partial payloads.
fn fillChunks(chunks: *align(64) [ChunkedLeaf.K][32]u8, valid: usize) void {
    chunks.* = [_][32]u8{[_]u8{0} ** 32} ** ChunkedLeaf.K;
    for (0..valid) |i| chunks[i] = makeLeaf(@truncate(i +% 1));
}

// Verifies a proof for gindex 6 (depth 2, index 2) reconstructs the original root.
test "single proof roundtrip" {
    var pool = try Node.Pool.init(.{ .page_allocator = testing.allocator, .allocator = testing.allocator, .pool_size = 128 });
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
    defer pool.unref(root);

    const gindex = Gindex.fromDepth(2, 2);

    var single_proof = try proof.createSingleProof(testing.allocator, &pool, root, gindex);
    defer single_proof.deinit(testing.allocator);

    try testing.expectEqualSlices(u8, &leaf_hashes[2], &single_proof.leaf);
    try testing.expectEqual(@as(usize, 2), single_proof.witnesses.len);

    const root_hash = root.getRoot(&pool).*;

    var pool2 = try Node.Pool.init(.{ .page_allocator = testing.allocator, .allocator = testing.allocator, .pool_size = 128 });
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

    var pool = try Node.Pool.init(.{ .page_allocator = testing.allocator, .allocator = testing.allocator, .pool_size = pool_capacity });
    defer pool.deinit();

    var next_value: u8 = 1;
    const raw_root = try buildFullTree(&pool, build_depth, &next_value);
    defer pool.unref(raw_root);

    const expected_root = raw_root.getRoot(&pool).*;
    const leaf_depth: Depth = @intCast(build_depth);
    const leaf_count = @as(usize, 1) << build_depth;

    for (0..leaf_count) |leaf_index| {
        const gindex = Gindex.fromDepth(leaf_depth, leaf_index);
        var single_proof = try proof.createSingleProof(testing.allocator, &pool, raw_root, gindex);
        defer single_proof.deinit(testing.allocator);

        var temp_pool = try Node.Pool.init(.{ .page_allocator = testing.allocator, .allocator = testing.allocator, .pool_size = 64 });
        defer temp_pool.deinit();

        const rebuilt = try proof.createNodeFromSingleProof(&temp_pool, gindex, single_proof.leaf, single_proof.witnesses);
        defer temp_pool.unref(rebuilt);

        const rebuilt_root = rebuilt.getRoot(&temp_pool).*;
        try testing.expectEqualSlices(u8, &expected_root, &rebuilt_root);
    }
}

// Attempting to prove beyond the tree height should bubble up Node.InvalidNode.
test "single proof invalid navigation" {
    var pool = try Node.Pool.init(.{ .page_allocator = testing.allocator, .allocator = testing.allocator, .pool_size = 64 });
    defer pool.deinit();

    const leaf_hash = makeLeaf(42);
    const root = try pool.createLeaf(&leaf_hash);
    defer pool.unref(root);

    const gindex = Gindex.fromDepth(3, 0);
    try testing.expectError(Node.Error.InvalidNode, proof.createSingleProof(testing.allocator, &pool, root, gindex));
}

// Zero gindex must be rejected by both proof creation and reconstruction entry points.
test "single proof invalid gindex" {
    var pool = try Node.Pool.init(.{ .page_allocator = testing.allocator, .allocator = testing.allocator, .pool_size = 8 });
    defer pool.deinit();

    const leaf_hash = makeLeaf(9);
    const root = try pool.createLeaf(&leaf_hash);
    defer pool.unref(root);

    const zero_gindex: Gindex = @enumFromInt(0);
    try testing.expectError(proof.Error.InvalidGindex, proof.createSingleProof(testing.allocator, &pool, root, zero_gindex));

    const empty_witnesses: []const [32]u8 = &[_][32]u8{};
    try testing.expectError(proof.Error.InvalidGindex, proof.createNodeFromSingleProof(&pool, zero_gindex, leaf_hash, empty_witnesses));
}

test "descriptorToBitlist - should convert valid descriptor to a bitlist" {
    for (descriptor_test_cases) |case| {
        const result = try proof.descriptorToBitlist(testing.allocator, case.input);
        defer testing.allocator.free(result);
        try testing.expectEqualSlices(bool, case.output, result);
    }
}

test "descriptorToBitlist - should throw on invalid descriptors" {
    for (descriptor_error_cases) |case| {
        try testing.expectError(proof.Error.InvalidWitnessLength, proof.descriptorToBitlist(testing.allocator, case));
    }
}

test "computeDescriptor - should convert gindices to a descriptor" {
    const gindex = Gindex.fromUint(42);
    const expected = [_]u8{ 0x25, 0xe0 };

    const descriptor = try proof.computeDescriptor(testing.allocator, &[_]Gindex{gindex});
    defer testing.allocator.free(descriptor);

    try testing.expectEqualSlices(u8, &expected, descriptor);
}

test "computeDescriptor preserves path order and redundant targets" {
    const Case = struct { indices: []const Gindex.Uint, expected: []const u8 };
    const cases = [_]Case{
        .{ .indices = &.{}, .expected = &.{} },
        .{ .indices = &.{1}, .expected = &.{0x80} },
        .{ .indices = &.{2}, .expected = &.{0x60} },
        .{ .indices = &.{4}, .expected = &.{0x38} },
        .{ .indices = &.{ 5, 4, 4 }, .expected = &.{0x38} },
        .{ .indices = &.{ 4, 6 }, .expected = &.{0x36} },
        .{ .indices = &.{ 2, 4 }, .expected = &.{0x38} },
        .{ .indices = &.{ 43, 42, 11 }, .expected = &.{ 0x25, 0xe0 } },
    };
    for (cases) |case| {
        var indices: [3]Gindex = undefined;
        for (case.indices, 0..) |index, i| indices[i] = Gindex.fromUint(index);
        const descriptor = try proof.computeDescriptor(testing.allocator, indices[0..case.indices.len]);
        defer testing.allocator.free(descriptor);

        try testing.expectEqualSlices(u8, case.expected, descriptor);
    }
    try testing.expectError(error.InvalidGindex, proof.computeDescriptor(testing.allocator, &.{Gindex.fromUint(0)}));
}

test "computeDescriptor supports the deepest leftmost path" {
    const depth = @bitSizeOf(Gindex.Uint) - 1;
    const descriptor = try proof.computeDescriptor(testing.allocator, &.{
        Gindex.fromUint(@as(Gindex.Uint, 1) << depth),
    });
    defer testing.allocator.free(descriptor);

    var expected: [(depth * 2 + 1 + 7) / 8]u8 = @splat(0);
    for (depth..depth * 2 + 1) |bit| expected[bit / 8] |= @as(u8, 0x80) >> @intCast(bit % 8);
    try testing.expectEqualSlices(u8, &expected, descriptor);
}

test "memory_safety: computeDescriptor cleans up every allocation failure" {
    try testing.checkAllAllocationFailures(testing.allocator, computeDescriptorWithAllocator, .{});
}

fn computeDescriptorWithAllocator(allocator: std.mem.Allocator) !void {
    const descriptor = try proof.computeDescriptor(allocator, &.{
        Gindex.fromUint(43), Gindex.fromUint(42), Gindex.fromUint(11),
    });
    defer allocator.free(descriptor);

    try testing.expectEqualSlices(u8, &.{ 0x25, 0xe0 }, descriptor);
}

test "compact multiproof - should roundtrip node -> proof -> node" {
    const build_depth: usize = 5;
    const pool_capacity: u32 = @intCast((@as(usize, 1) << (build_depth + 1)) * 2);

    var pool = try Node.Pool.init(.{ .page_allocator = testing.allocator, .allocator = testing.allocator, .pool_size = pool_capacity });
    defer pool.deinit();

    var next_value: u8 = 1;
    const root = try buildFullTree(&pool, build_depth, &next_value);
    defer pool.unref(root);

    for (descriptor_test_cases) |case| {
        const leaves = try proof.createCompactMultiProof(testing.allocator, &pool, root, case.input);
        defer testing.allocator.free(leaves);

        var pool2 = try Node.Pool.init(.{ .page_allocator = testing.allocator, .allocator = testing.allocator, .pool_size = pool_capacity });
        defer pool2.deinit();

        const reconstructed = try proof.createNodeFromCompactMultiProof(&pool2, leaves, case.input);
        defer pool2.unref(reconstructed);

        const original_root = root.getRoot(&pool).*;
        const reconstructed_root = reconstructed.getRoot(&pool2).*;
        try testing.expectEqualSlices(u8, &original_root, &reconstructed_root);
    }
}

test "compact multiproof reconstruction should reject empty leaves" {
    var pool = try Node.Pool.init(.{
        .page_allocator = testing.allocator,
        .allocator = testing.allocator,
        .pool_size = 0,
    });
    defer pool.deinit();

    var leaves = [_][32]u8{};
    const descriptor = [_]u8{0b1000_0000};

    try testing.expectError(
        proof.Error.InvalidWitnessLength,
        proof.createNodeFromCompactMultiProof(&pool, &leaves, &descriptor),
    );
}

fn spineDescriptor(depth: usize, left: bool, out: []u8) []const u8 {
    const bit_length = 2 * depth + 1;
    const bytes = out[0 .. (bit_length + 7) / 8];
    @memset(bytes, 0);
    for (0..depth + 1) |i| {
        const bit_index = if (left) depth + i else @min(2 * i + 1, bit_length - 1);
        bytes[bit_index / 8] |= @as(u8, 0x80) >> @intCast(bit_index % 8);
    }
    return bytes;
}

test "compact multiproof reconstruction rejects paths beyond max_depth" {
    const depth = max_depth + 1;
    var descriptor_bytes: [(2 * depth + 8) / 8]u8 = undefined;
    var leaves: [depth + 1][32]u8 = @splat(makeLeaf(1));
    for ([_]bool{ true, false }) |left| {
        var pool = try Node.Pool.init(.{
            .page_allocator = testing.allocator,
            .allocator = testing.allocator,
            .pool_size = 2 * depth + 1,
        });
        defer pool.deinit();
        const baseline = pool.getNodesInUse();
        const descriptor = spineDescriptor(depth, left, &descriptor_bytes);

        try testing.expectError(error.InvalidProofDepth, proof.createNodeFromCompactMultiProof(&pool, &leaves, descriptor));
        try testing.expectEqual(baseline, pool.getNodesInUse());
    }
}

test "memory_safety: compact multiproof depth validation precedes allocation" {
    const depth = max_depth + 1;
    var descriptor_bytes: [(2 * depth + 8) / 8]u8 = undefined;
    var leaves: [depth + 1][32]u8 = @splat(makeLeaf(1));
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var pool = try Node.Pool.init(.{
        .page_allocator = testing.allocator,
        .allocator = failing.allocator(),
        .pool_size = 0,
    });
    defer pool.deinit();
    const baseline = pool.getNodesInUse();

    for ([_]bool{ true, false }) |left| {
        const descriptor = spineDescriptor(depth, left, &descriptor_bytes);
        try testing.expectError(error.InvalidProofDepth, proof.descriptorToBitlist(failing.allocator(), descriptor));
        try testing.expectError(error.InvalidProofDepth, proof.createNodeFromCompactMultiProof(&pool, &leaves, descriptor));
        try testing.expectEqual(baseline, pool.getNodesInUse());
        try testing.expect(!failing.has_induced_failure);
    }
}

test "compact multiproof reconstruction hashes depth zero and max_depth spines" {
    var descriptor_bytes: [(2 * max_depth + 8) / 8]u8 = undefined;
    var leaves: [max_depth + 1][32]u8 = undefined;
    for (&leaves, 0..) |*leaf, i| leaf.* = makeLeaf(@intCast(i));

    for ([_]usize{ 0, max_depth }) |depth| {
        for ([_]bool{ true, false }) |left| {
            var pool = try Node.Pool.init(.{
                .page_allocator = testing.allocator,
                .allocator = testing.allocator,
                .pool_size = @intCast(2 * depth + 1),
            });
            defer pool.deinit();
            const descriptor = spineDescriptor(depth, left, &descriptor_bytes);
            const root = try proof.createNodeFromCompactMultiProof(&pool, leaves[0 .. depth + 1], descriptor);
            defer pool.unref(root);

            var expected = if (left) leaves[0] else leaves[depth];
            for (0..depth) |i| {
                var next: [32]u8 = undefined;
                if (left) {
                    hashOne(&next, &expected, &leaves[i + 1]);
                } else {
                    hashOne(&next, &leaves[depth - i - 1], &expected);
                }
                expected = next;
            }
            try testing.expectEqualSlices(u8, &expected, root.getRoot(&pool));
        }
    }
}

// Prove individual chunks inside a `.chunked_leaf` node: createSingleProof
// must materialize the packed leaf to collect intermediate witnesses.
test "single proof through chunked_leaf" {
    const K: usize = ChunkedLeaf.K;
    const pool_capacity: u32 = @intCast(K * 4);
    var pool = try Node.Pool.init(.{ .page_allocator = testing.allocator, .allocator = testing.allocator, .pool_size = pool_capacity });
    defer pool.deinit();

    var chunks: [ChunkedLeaf.K][32]u8 align(64) = undefined;
    fillChunks(&chunks, K);

    const cl = try pool.createChunkedLeaf(&chunks, ChunkedLeaf.K);
    const sibling = try pool.createLeaf(&makeLeaf(0xFF));
    const root = try pool.createBranch(cl, sibling);
    defer pool.unref(root);

    const expected_root = root.getRoot(&pool).*;
    // The chunked_leaf is the root's left child (depth 1) and expands to a
    // depth-k_log2 subtree, so chunk i sits at gindex fromDepth(1+k_log2, i).
    const chunk_depth: Depth = ChunkedLeaf.k_log2 + 1;

    for ([_]usize{ 0, 1, K / 2, K - 1 }) |chunk_index| {
        const gindex = Gindex.fromDepth(chunk_depth, chunk_index);
        var single_proof = try proof.createSingleProof(testing.allocator, &pool, root, gindex);
        defer single_proof.deinit(testing.allocator);

        try testing.expectEqualSlices(u8, &chunks[chunk_index], &single_proof.leaf);

        var pool2 = try Node.Pool.init(.{ .page_allocator = testing.allocator, .allocator = testing.allocator, .pool_size = pool_capacity });
        defer pool2.deinit();

        const rebuilt = try proof.createNodeFromSingleProof(&pool2, gindex, single_proof.leaf, single_proof.witnesses);
        defer pool2.unref(rebuilt);

        const rebuilt_root = rebuilt.getRoot(&pool2).*;
        try testing.expectEqualSlices(u8, &expected_root, &rebuilt_root);
    }
}

// Compact multiproof descending through a `.chunked_leaf`: exercises the
// opaque-materialization path in nodeToCompactMultiProof, which the plain
// `compact multiproof` test never reaches.
test "compact multiproof through chunked_leaf" {
    const K: usize = ChunkedLeaf.K;
    const pool_capacity: u32 = @intCast(K * 6);
    var pool = try Node.Pool.init(.{ .page_allocator = testing.allocator, .allocator = testing.allocator, .pool_size = pool_capacity });
    defer pool.deinit();

    var chunks: [ChunkedLeaf.K][32]u8 align(64) = undefined;
    fillChunks(&chunks, K);

    const cl = try pool.createChunkedLeaf(&chunks, ChunkedLeaf.K);
    const sibling = try pool.createLeaf(&makeLeaf(0xFF));
    const root = try pool.createBranch(cl, sibling);
    defer pool.unref(root);

    const chunk_depth: Depth = ChunkedLeaf.k_log2 + 1;
    // Three leaves inside the chunked_leaf, ascending gindex order.
    const descriptor = try proof.computeDescriptor(testing.allocator, &[_]Gindex{
        Gindex.fromDepth(chunk_depth, 0),
        Gindex.fromDepth(chunk_depth, K / 2),
        Gindex.fromDepth(chunk_depth, K - 1),
    });
    defer testing.allocator.free(descriptor);

    const leaves = try proof.createCompactMultiProof(testing.allocator, &pool, root, descriptor);
    defer testing.allocator.free(leaves);

    var pool2 = try Node.Pool.init(.{ .page_allocator = testing.allocator, .allocator = testing.allocator, .pool_size = pool_capacity });
    defer pool2.deinit();

    const reconstructed = try proof.createNodeFromCompactMultiProof(&pool2, leaves, descriptor);
    defer pool2.unref(reconstructed);

    const original_root = root.getRoot(&pool).*;
    const reconstructed_root = reconstructed.getRoot(&pool2).*;
    try testing.expectEqualSlices(u8, &original_root, &reconstructed_root);
}

// A partial `.chunked_leaf` (len < K) zero-pads its tail. Proofs must work
// for both populated chunks and the zero-padding region.
test "single proof through partial chunked_leaf" {
    const K: usize = ChunkedLeaf.K;
    const pool_capacity: u32 = @intCast(K * 4);
    var pool = try Node.Pool.init(.{ .page_allocator = testing.allocator, .allocator = testing.allocator, .pool_size = pool_capacity });
    defer pool.deinit();

    const valid: usize = K / 2 + 1;
    var chunks: [ChunkedLeaf.K][32]u8 align(64) = undefined;
    fillChunks(&chunks, valid);

    const cl = try pool.createChunkedLeaf(&chunks, @intCast(valid));
    const sibling = try pool.createLeaf(&makeLeaf(0xFF));
    const root = try pool.createBranch(cl, sibling);
    defer pool.unref(root);

    const expected_root = root.getRoot(&pool).*;
    const chunk_depth: Depth = ChunkedLeaf.k_log2 + 1;

    // populated, last populated, first zero-pad, last (zero-pad) chunk.
    for ([_]usize{ 0, valid - 1, valid, K - 1 }) |chunk_index| {
        const gindex = Gindex.fromDepth(chunk_depth, chunk_index);
        var single_proof = try proof.createSingleProof(testing.allocator, &pool, root, gindex);
        defer single_proof.deinit(testing.allocator);

        try testing.expectEqualSlices(u8, &chunks[chunk_index], &single_proof.leaf);

        var pool2 = try Node.Pool.init(.{ .page_allocator = testing.allocator, .allocator = testing.allocator, .pool_size = pool_capacity });
        defer pool2.deinit();

        const rebuilt = try proof.createNodeFromSingleProof(&pool2, gindex, single_proof.leaf, single_proof.witnesses);
        defer pool2.unref(rebuilt);

        const rebuilt_root = rebuilt.getRoot(&pool2).*;
        try testing.expectEqualSlices(u8, &expected_root, &rebuilt_root);
    }
}

test "memory_safety: compact multiproof reconstruction should reclaim partial nodes on pool exhaustion" {
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

test "compact multiproof reconstruction needs no allocator scratch" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var pool = try Node.Pool.init(.{ .page_allocator = testing.allocator, .allocator = failing.allocator(), .pool_size = 256 });
    defer pool.deinit();
    var descriptor_bytes: [(2 * max_depth + 8) / 8]u8 = undefined;
    var leaves: [max_depth + 1][32]u8 = @splat(makeLeaf(7));
    for ([_]bool{ true, false }) |left| {
        const descriptor = spineDescriptor(max_depth, left, &descriptor_bytes);
        const baseline = pool.getNodesInUse();
        const root = try proof.createNodeFromCompactMultiProof(&pool, &leaves, descriptor);
        pool.unref(root);
        try testing.expectEqual(baseline, pool.getNodesInUse());
        try testing.expect(!failing.has_induced_failure);
    }
}

test "memory_safety: iterative proof reconstruction releases every unfinished frontier" {
    const depth = 5;
    var descriptor_bytes: [(2 * depth + 8) / 8]u8 = undefined;
    var leaves: [depth + 1][32]u8 = @splat(makeLeaf(9));
    for ([_]bool{ true, false }) |left| {
        const descriptor = spineDescriptor(depth, left, &descriptor_bytes);
        for (0..2 * depth + 1) |capacity| {
            var pool = try Node.Pool.init(.{ .page_allocator = testing.allocator, .allocator = testing.allocator, .pool_size = @intCast(capacity) });
            defer pool.deinit();
            const baseline = pool.getNodesInUse();
            try testing.expectError(error.PoolExhausted, proof.createNodeFromCompactMultiProof(&pool, &leaves, descriptor));
            try testing.expectEqual(baseline, pool.getNodesInUse());
            for (0..capacity) |_| _ = try pool.createLeafFromUint(0);
            try testing.expectError(error.PoolExhausted, pool.createLeafFromUint(0));
        }
    }
}
