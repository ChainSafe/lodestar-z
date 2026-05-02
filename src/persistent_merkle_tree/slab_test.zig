const std = @import("std");

const Slab = @import("slab.zig");
const Node = @import("Node.zig");

test "slab: allocZero produces zero chunks" {
    const allocator = std.testing.allocator;
    const slab = try Slab.allocZero(allocator);
    defer Slab.destroy(allocator, slab);

    for (slab.chunks) |chunk| {
        try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &chunk);
    }
}

test "slab: computeRoot for all-zero slab equals getZeroHash(k_log2)" {
    const allocator = std.testing.allocator;
    const slab = try Slab.allocZero(allocator);
    defer Slab.destroy(allocator, slab);

    var slab_root: [32]u8 = undefined;
    Slab.computeRoot(slab, &slab_root);

    const expected = @import("hashing").getZeroHash(Slab.k_log2);
    try std.testing.expectEqualSlices(u8, expected, &slab_root);
}

test "slab: computeRoot for non-zero pattern matches std merkleize" {
    const allocator = std.testing.allocator;
    const slab = try Slab.allocZero(allocator);
    defer Slab.destroy(allocator, slab);

    for (0..Slab.K) |i| {
        std.mem.writeInt(u256, &slab.chunks[i], @as(u256, @intCast(i + 1)), .little);
    }

    var slab_root: [32]u8 = undefined;
    Slab.computeRoot(slab, &slab_root);

    var pairs = try allocator.alloc([2][32]u8, Slab.K / 2);
    defer allocator.free(pairs);
    for (0..Slab.K / 2) |i| {
        pairs[i][0] = slab.chunks[2 * i];
        pairs[i][1] = slab.chunks[2 * i + 1];
    }
    var ref_root: [32]u8 = undefined;
    try @import("hashing").merkleize(pairs, Slab.k_log2, &ref_root);

    try std.testing.expectEqualSlices(u8, &ref_root, &slab_root);
}

test "Pool.createSlab: round-trips chunks via getSlabChunks/getSlabLen" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 16);
    defer pool.deinit();

    var src: [Slab.K][32]u8 align(64) = [_][32]u8{[_]u8{0} ** 32} ** Slab.K;
    src[0][0] = 0xAB;
    src[Slab.K - 1][31] = 0xCD;

    const slab_id = try pool.createSlab(&src, Slab.K);
    defer pool.unref(slab_id);

    const got = try slab_id.getSlabChunks(&pool);
    try std.testing.expectEqual(@as(u8, 0xAB), got[0][0]);
    try std.testing.expectEqual(@as(u8, 0xCD), got[Slab.K - 1][31]);
    try std.testing.expectEqual(@as(u16, Slab.K), try slab_id.getSlabLen(&pool));
}

test "Pool.unref: slab payload heap is freed (no leak under test allocator)" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 16);
    defer pool.deinit();

    const src: [Slab.K][32]u8 align(64) = [_][32]u8{[_]u8{0} ** 32} ** Slab.K;
    const slab_id = try pool.createSlab(&src, Slab.K);
    pool.unref(slab_id);
    // No external destroy — Pool.unref must release the heap Storage,
    // and std.testing.allocator will fail this test on any leak.
}

test "Id.getRoot: Pool-created slab returns merkleized root and caches it" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 16);
    defer pool.deinit();

    var src: [Slab.K][32]u8 align(64) = [_][32]u8{[_]u8{0} ** 32} ** Slab.K;
    for (0..Slab.K) |i| {
        std.mem.writeInt(u256, &src[i], @as(u256, @intCast(i + 1)), .little);
    }

    const slab_id = try pool.createSlab(&src, Slab.K);
    defer pool.unref(slab_id);

    const root_first = slab_id.getRoot(&pool);

    // Reference: build same merkleization via std hashing.
    var ref: [32]u8 = undefined;
    var pairs = try allocator.alloc([2][32]u8, Slab.K / 2);
    defer allocator.free(pairs);
    for (0..Slab.K / 2) |i| {
        pairs[i][0] = src[2 * i];
        pairs[i][1] = src[2 * i + 1];
    }
    try @import("hashing").merkleize(pairs, Slab.k_log2, &ref);
    try std.testing.expectEqualSlices(u8, &ref, root_first);

    // Second call returns the same root (cached).
    const root_second = slab_id.getRoot(&pool);
    try std.testing.expectEqualSlices(u8, root_first, root_second);
}

test "Id.setSlabChunk: CoW one chunk; original unchanged; root differs" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 32);
    defer pool.deinit();

    var src: [Slab.K][32]u8 align(64) = [_][32]u8{[_]u8{0} ** 32} ** Slab.K;
    src[42][0] = 0x11;
    const a = try pool.createSlab(&src, Slab.K);
    defer pool.unref(a);

    var new_chunk: [32]u8 = [_]u8{0} ** 32;
    new_chunk[0] = 0x22;
    const b = try a.setSlabChunk(&pool, 42, &new_chunk);
    defer pool.unref(b);

    try std.testing.expect(a != b);

    const a_chunks = try a.getSlabChunks(&pool);
    const b_chunks = try b.getSlabChunks(&pool);
    try std.testing.expectEqual(@as(u8, 0x11), a_chunks[42][0]);
    try std.testing.expectEqual(@as(u8, 0x22), b_chunks[42][0]);

    // Other chunks identical between a and b (verify a few).
    try std.testing.expectEqualSlices(u8, &a_chunks[0], &b_chunks[0]);
    try std.testing.expectEqualSlices(u8, &a_chunks[Slab.K - 1], &b_chunks[Slab.K - 1]);

    // Roots differ.
    try std.testing.expect(!std.mem.eql(u8, a.getRoot(&pool), b.getRoot(&pool)));
}

test "Id.setSlabChunk: preserves len" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 16);
    defer pool.deinit();

    const src: [Slab.K][32]u8 align(64) = [_][32]u8{[_]u8{0} ** 32} ** Slab.K;
    const a = try pool.createSlab(&src, 100); // partial slab (len = 100)
    defer pool.unref(a);

    var new_chunk: [32]u8 = [_]u8{0xFF} ** 32;
    const b = try a.setSlabChunk(&pool, 50, &new_chunk);
    defer pool.unref(b);

    try std.testing.expectEqual(@as(u16, 100), try b.getSlabLen(&pool));
}

test "Id.setSlabChunks: batch CoW with multiple updates" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 32);
    defer pool.deinit();

    const src: [Slab.K][32]u8 align(64) = [_][32]u8{[_]u8{0} ** 32} ** Slab.K;
    const a = try pool.createSlab(&src, Slab.K);
    defer pool.unref(a);

    const idxs = [_]u16{ 0, 7, 100, 999 };
    const c0 = [_]u8{0xAA} ** 32;
    const c1 = [_]u8{0xBB} ** 32;
    const c2 = [_]u8{0xCC} ** 32;
    const c3 = [_]u8{0xDD} ** 32;
    const ptrs = [_]*const [32]u8{ &c0, &c1, &c2, &c3 };

    const b = try a.setSlabChunks(&pool, &idxs, &ptrs);
    defer pool.unref(b);

    const got = try b.getSlabChunks(&pool);
    try std.testing.expectEqual(@as(u8, 0xAA), got[0][0]);
    try std.testing.expectEqual(@as(u8, 0xBB), got[7][0]);
    try std.testing.expectEqual(@as(u8, 0xCC), got[100][0]);
    try std.testing.expectEqual(@as(u8, 0xDD), got[999][0]);

    // Original unchanged.
    const a_chunks = try a.getSlabChunks(&pool);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &a_chunks[0]);
}

test "Id.setSlabChunks: empty batch produces a clone with empty dirty" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 16);
    defer pool.deinit();

    const src: [Slab.K][32]u8 align(64) = [_][32]u8{[_]u8{0} ** 32} ** Slab.K;
    const a = try pool.createSlab(&src, Slab.K);
    defer pool.unref(a);

    const idxs: []const u16 = &.{};
    const ptrs: []const *const [32]u8 = &.{};
    const b = try a.setSlabChunks(&pool, idxs, ptrs);
    defer pool.unref(b);

    try std.testing.expect(a != b);
    // Roots equal — no chunks changed.
    try std.testing.expectEqualSlices(u8, a.getRoot(&pool), b.getRoot(&pool));
}

test "Id.setSlabChunk: non-slab Id returns Error.InvalidNode" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 16);
    defer pool.deinit();

    // Use a leaf node — clearly not a slab.
    const leaf_id = try pool.createLeaf(&([_]u8{0xEE} ** 32));
    defer pool.unref(leaf_id);

    var new_chunk: [32]u8 = [_]u8{0xFF} ** 32;
    try std.testing.expectError(error.InvalidNode, leaf_id.setSlabChunk(&pool, 0, &new_chunk));
}

test "tree of slabs: build via FillWithContentsIterator; root matches per-leaf tree" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1 << 14);
    defer pool.deinit();

    // Deterministic chunk data: chunks[s][i] = u256(s * K + i + 1).
    var raw: [4][Slab.K][32]u8 align(64) = undefined;
    @memset(std.mem.asBytes(&raw), 0);
    for (0..4) |s| for (0..Slab.K) |i| {
        std.mem.writeInt(u256, &raw[s][i], @as(u256, @intCast(s * Slab.K + i + 1)), .little);
    };

    // Build path 1: 4 slabs appended at iterator depth 2.
    var slab_it = Node.FillWithContentsIterator.init(&pool, 2);
    errdefer slab_it.deinit();
    for (0..4) |s| {
        const sid = try pool.createSlab(&raw[s], Slab.K);
        try slab_it.append(sid);
    }
    const slab_root_id = try slab_it.finish();
    defer pool.unref(slab_root_id);

    // Build path 2: same 4*K=4096 chunks appended as per-chunk leaves at
    // iterator depth Slab.k_log2 + 2 = 12.
    var leaf_it = Node.FillWithContentsIterator.init(&pool, Slab.k_log2 + 2);
    errdefer leaf_it.deinit();
    for (0..4) |s| for (0..Slab.K) |i| {
        var c = raw[s][i];
        try leaf_it.append(try pool.createLeaf(&c));
    };
    const leaf_root_id = try leaf_it.finish();
    defer pool.unref(leaf_root_id);

    // The two trees must produce the same root.
    try std.testing.expectEqualSlices(u8, slab_root_id.getRoot(&pool), leaf_root_id.getRoot(&pool));
}
