const std = @import("std");

const ChunkedLeaf = @import("chunked_leaf.zig");
const Node = @import("Node.zig");

test "chunked_leaf: allocZero produces zero chunks" {
    const allocator = std.testing.allocator;
    const chunked_leaf = try ChunkedLeaf.allocZero(allocator);
    defer ChunkedLeaf.destroy(allocator, chunked_leaf);

    for (chunked_leaf.chunks) |chunk| {
        try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &chunk);
    }
}

test "chunked_leaf: computeRoot for all-zero chunked_leaf equals getZeroHash(k_log2)" {
    const allocator = std.testing.allocator;
    const chunked_leaf = try ChunkedLeaf.allocZero(allocator);
    defer ChunkedLeaf.destroy(allocator, chunked_leaf);

    var chunked_leaf_root: [32]u8 = undefined;
    ChunkedLeaf.computeRoot(chunked_leaf, &chunked_leaf_root);

    const expected = @import("hashing").getZeroHash(ChunkedLeaf.k_log2);
    try std.testing.expectEqualSlices(u8, expected, &chunked_leaf_root);
}

test "chunked_leaf: computeRoot for non-zero pattern matches std merkleize" {
    const allocator = std.testing.allocator;
    const chunked_leaf = try ChunkedLeaf.allocZero(allocator);
    defer ChunkedLeaf.destroy(allocator, chunked_leaf);

    for (0..ChunkedLeaf.K) |i| {
        std.mem.writeInt(u256, &chunked_leaf.chunks[i], @as(u256, @intCast(i + 1)), .little);
    }

    var chunked_leaf_root: [32]u8 = undefined;
    ChunkedLeaf.computeRoot(chunked_leaf, &chunked_leaf_root);

    var pairs = try allocator.alloc([2][32]u8, ChunkedLeaf.K / 2);
    defer allocator.free(pairs);
    for (0..ChunkedLeaf.K / 2) |i| {
        pairs[i][0] = chunked_leaf.chunks[2 * i];
        pairs[i][1] = chunked_leaf.chunks[2 * i + 1];
    }
    var ref_root: [32]u8 = undefined;
    try @import("hashing").merkleize(pairs, ChunkedLeaf.k_log2, &ref_root);

    try std.testing.expectEqualSlices(u8, &ref_root, &chunked_leaf_root);
}

test "Pool.createChunkedLeaf: round-trips chunks via getChunkedLeafChunks/getChunkedLeafLen" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 16);
    defer pool.deinit();

    var src: [ChunkedLeaf.K][32]u8 align(64) = [_][32]u8{[_]u8{0} ** 32} ** ChunkedLeaf.K;
    src[0][0] = 0xAB;
    src[ChunkedLeaf.K - 1][31] = 0xCD;

    const chunked_leaf_id = try pool.createChunkedLeaf(&src, ChunkedLeaf.K);
    defer pool.unref(chunked_leaf_id);

    const got = try chunked_leaf_id.getChunkedLeafChunks(&pool);
    try std.testing.expectEqual(@as(u8, 0xAB), got[0][0]);
    try std.testing.expectEqual(@as(u8, 0xCD), got[ChunkedLeaf.K - 1][31]);
    try std.testing.expectEqual(@as(u16, ChunkedLeaf.K), try chunked_leaf_id.getChunkedLeafLen(&pool));
}

test "Pool.unref: chunked_leaf payload heap is freed (no leak under test allocator)" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 16);
    defer pool.deinit();

    const src: [ChunkedLeaf.K][32]u8 align(64) = [_][32]u8{[_]u8{0} ** 32} ** ChunkedLeaf.K;
    const chunked_leaf_id = try pool.createChunkedLeaf(&src, ChunkedLeaf.K);
    pool.unref(chunked_leaf_id);
    // No external destroy — Pool.unref must release the heap Storage,
    // and std.testing.allocator will fail this test on any leak.
}

test "Id.getRoot: Pool-created chunked_leaf returns merkleized root and caches it" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 16);
    defer pool.deinit();

    var src: [ChunkedLeaf.K][32]u8 align(64) = [_][32]u8{[_]u8{0} ** 32} ** ChunkedLeaf.K;
    for (0..ChunkedLeaf.K) |i| {
        std.mem.writeInt(u256, &src[i], @as(u256, @intCast(i + 1)), .little);
    }

    const chunked_leaf_id = try pool.createChunkedLeaf(&src, ChunkedLeaf.K);
    defer pool.unref(chunked_leaf_id);

    const root_first = chunked_leaf_id.getRoot(&pool);

    // Reference: build same merkleization via std hashing.
    var ref: [32]u8 = undefined;
    var pairs = try allocator.alloc([2][32]u8, ChunkedLeaf.K / 2);
    defer allocator.free(pairs);
    for (0..ChunkedLeaf.K / 2) |i| {
        pairs[i][0] = src[2 * i];
        pairs[i][1] = src[2 * i + 1];
    }
    try @import("hashing").merkleize(pairs, ChunkedLeaf.k_log2, &ref);
    try std.testing.expectEqualSlices(u8, &ref, root_first);

    // Second call returns the same root (cached).
    const root_second = chunked_leaf_id.getRoot(&pool);
    try std.testing.expectEqualSlices(u8, root_first, root_second);
}

test "Id.setChunkedLeafChunk: CoW one chunk; original unchanged; root differs" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 32);
    defer pool.deinit();

    var src: [ChunkedLeaf.K][32]u8 align(64) = [_][32]u8{[_]u8{0} ** 32} ** ChunkedLeaf.K;
    src[42][0] = 0x11;
    const a = try pool.createChunkedLeaf(&src, ChunkedLeaf.K);
    defer pool.unref(a);

    var new_chunk: [32]u8 = [_]u8{0} ** 32;
    new_chunk[0] = 0x22;
    const b = try a.setChunkedLeafChunk(&pool, 42, &new_chunk);
    defer pool.unref(b);

    try std.testing.expect(a != b);

    const a_chunks = try a.getChunkedLeafChunks(&pool);
    const b_chunks = try b.getChunkedLeafChunks(&pool);
    try std.testing.expectEqual(@as(u8, 0x11), a_chunks[42][0]);
    try std.testing.expectEqual(@as(u8, 0x22), b_chunks[42][0]);

    // Other chunks identical between a and b (verify a few).
    try std.testing.expectEqualSlices(u8, &a_chunks[0], &b_chunks[0]);
    try std.testing.expectEqualSlices(u8, &a_chunks[ChunkedLeaf.K - 1], &b_chunks[ChunkedLeaf.K - 1]);

    // Roots differ.
    try std.testing.expect(!std.mem.eql(u8, a.getRoot(&pool), b.getRoot(&pool)));
}

test "Id.setChunkedLeafChunk: preserves len" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 16);
    defer pool.deinit();

    const src: [ChunkedLeaf.K][32]u8 align(64) = [_][32]u8{[_]u8{0} ** 32} ** ChunkedLeaf.K;
    const a = try pool.createChunkedLeaf(&src, 100); // partial chunked_leaf (len = 100)
    defer pool.unref(a);

    var new_chunk: [32]u8 = [_]u8{0xFF} ** 32;
    const b = try a.setChunkedLeafChunk(&pool, 50, &new_chunk);
    defer pool.unref(b);

    try std.testing.expectEqual(@as(u16, 100), try b.getChunkedLeafLen(&pool));
}

test "Id.setChunkedLeafChunks: batch CoW with multiple updates" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 32);
    defer pool.deinit();

    const src: [ChunkedLeaf.K][32]u8 align(64) = [_][32]u8{[_]u8{0} ** 32} ** ChunkedLeaf.K;
    const a = try pool.createChunkedLeaf(&src, ChunkedLeaf.K);
    defer pool.unref(a);

    const idxs = [_]u16{ 0, 7, 100, 999 };
    const c0 = [_]u8{0xAA} ** 32;
    const c1 = [_]u8{0xBB} ** 32;
    const c2 = [_]u8{0xCC} ** 32;
    const c3 = [_]u8{0xDD} ** 32;
    const ptrs = [_]*const [32]u8{ &c0, &c1, &c2, &c3 };

    const b = try a.setChunkedLeafChunks(&pool, &idxs, &ptrs);
    defer pool.unref(b);

    const got = try b.getChunkedLeafChunks(&pool);
    try std.testing.expectEqual(@as(u8, 0xAA), got[0][0]);
    try std.testing.expectEqual(@as(u8, 0xBB), got[7][0]);
    try std.testing.expectEqual(@as(u8, 0xCC), got[100][0]);
    try std.testing.expectEqual(@as(u8, 0xDD), got[999][0]);

    // Original unchanged.
    const a_chunks = try a.getChunkedLeafChunks(&pool);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &a_chunks[0]);
}

test "Id.setChunkedLeafChunks: empty batch produces a clone with empty dirty" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 16);
    defer pool.deinit();

    const src: [ChunkedLeaf.K][32]u8 align(64) = [_][32]u8{[_]u8{0} ** 32} ** ChunkedLeaf.K;
    const a = try pool.createChunkedLeaf(&src, ChunkedLeaf.K);
    defer pool.unref(a);

    const idxs: []const u16 = &.{};
    const ptrs: []const *const [32]u8 = &.{};
    const b = try a.setChunkedLeafChunks(&pool, idxs, ptrs);
    defer pool.unref(b);

    try std.testing.expect(a != b);
    // Roots equal — no chunks changed.
    try std.testing.expectEqualSlices(u8, a.getRoot(&pool), b.getRoot(&pool));
}

test "Id.setChunkedLeafChunk: non-chunked_leaf Id returns Error.InvalidNode" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 16);
    defer pool.deinit();

    // Use a leaf node — clearly not a chunked_leaf.
    const leaf_id = try pool.createLeaf(&([_]u8{0xEE} ** 32));
    defer pool.unref(leaf_id);

    var new_chunk: [32]u8 = [_]u8{0xFF} ** 32;
    try std.testing.expectError(error.InvalidNode, leaf_id.setChunkedLeafChunk(&pool, 0, &new_chunk));
}

test "tree of chunked leaves: build via FillWithContentsIterator; root matches per-leaf tree" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1 << 14);
    defer pool.deinit();

    // Deterministic chunk data: chunks[s][i] = u256(s * K + i + 1).
    var raw: [4][ChunkedLeaf.K][32]u8 align(64) = undefined;
    @memset(std.mem.asBytes(&raw), 0);
    for (0..4) |s| for (0..ChunkedLeaf.K) |i| {
        std.mem.writeInt(u256, &raw[s][i], @as(u256, @intCast(s * ChunkedLeaf.K + i + 1)), .little);
    };

    // Build path 1: 4 chunked leaves appended at iterator depth 2.
    var chunked_leaf_it = Node.FillWithContentsIterator.init(&pool, 2);
    errdefer chunked_leaf_it.deinit();
    for (0..4) |s| {
        const sid = try pool.createChunkedLeaf(&raw[s], ChunkedLeaf.K);
        try chunked_leaf_it.append(sid);
    }
    const chunked_leaf_root_id = try chunked_leaf_it.finish();
    defer pool.unref(chunked_leaf_root_id);

    // Build path 2: same 4*K=4096 chunks appended as per-chunk leaves at
    // iterator depth ChunkedLeaf.k_log2 + 2 = 12.
    var leaf_it = Node.FillWithContentsIterator.init(&pool, ChunkedLeaf.k_log2 + 2);
    errdefer leaf_it.deinit();
    for (0..4) |s| for (0..ChunkedLeaf.K) |i| {
        var c = raw[s][i];
        try leaf_it.append(try pool.createLeaf(&c));
    };
    const leaf_root_id = try leaf_it.finish();
    defer pool.unref(leaf_root_id);

    // The two trees must produce the same root.
    try std.testing.expectEqualSlices(u8, chunked_leaf_root_id.getRoot(&pool), leaf_root_id.getRoot(&pool));
}

test "FillWithContentsIterator: initWithOffset enables chunked_leaf leaves with correct zero filler" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1 << 14);
    defer pool.deinit();

    // Build a 4-chunked_leaf tree at iterator depth 2 with leaf_offset = ChunkedLeaf.k_log2.
    // Expected: the result is a depth-(ChunkedLeaf.k_log2 + 2) tree whose root equals
    // the same chunks built per-leaf at depth ChunkedLeaf.k_log2 + 2.
    var raw: [4][ChunkedLeaf.K][32]u8 align(64) = undefined;
    @memset(std.mem.asBytes(&raw), 0);
    for (0..4) |s| for (0..ChunkedLeaf.K) |i| {
        std.mem.writeInt(u256, &raw[s][i], @as(u256, @intCast(s * ChunkedLeaf.K + i + 1)), .little);
    };

    // Path A: chunked_leaf iterator with offset.
    var chunked_leaf_it = Node.FillWithContentsIterator.initWithOffset(&pool, 2, ChunkedLeaf.k_log2);
    errdefer chunked_leaf_it.deinit();
    for (0..4) |s| {
        const sid = try pool.createChunkedLeaf(&raw[s], ChunkedLeaf.K);
        try chunked_leaf_it.append(sid);
    }
    const chunked_leaf_root_id = try chunked_leaf_it.finish();
    defer pool.unref(chunked_leaf_root_id);

    // Path B: per-chunk leaves (default offset = 0).
    var leaf_it = Node.FillWithContentsIterator.init(&pool, ChunkedLeaf.k_log2 + 2);
    errdefer leaf_it.deinit();
    for (0..4) |s| for (0..ChunkedLeaf.K) |i| {
        var c = raw[s][i];
        try leaf_it.append(try pool.createLeaf(&c));
    };
    const leaf_root_id = try leaf_it.finish();
    defer pool.unref(leaf_root_id);

    try std.testing.expectEqualSlices(u8, chunked_leaf_root_id.getRoot(&pool), leaf_root_id.getRoot(&pool));
}

test "FillWithContentsIterator: initWithOffset with partial fill (zero-padded chunked leaves)" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1 << 14);
    defer pool.deinit();

    // Build a 3-chunked_leaf tree at iterator depth 2 (capacity 4). Final slot must
    // be zero-filled at absolute depth (ChunkedLeaf.k_log2 + 1), not depth 1.
    var raw: [3][ChunkedLeaf.K][32]u8 align(64) = undefined;
    @memset(std.mem.asBytes(&raw), 0);
    for (0..3) |s| for (0..ChunkedLeaf.K) |i| {
        std.mem.writeInt(u256, &raw[s][i], @as(u256, @intCast(s * ChunkedLeaf.K + i + 1)), .little);
    };

    var chunked_leaf_it = Node.FillWithContentsIterator.initWithOffset(&pool, 2, ChunkedLeaf.k_log2);
    errdefer chunked_leaf_it.deinit();
    for (0..3) |s| {
        const sid = try pool.createChunkedLeaf(&raw[s], ChunkedLeaf.K);
        try chunked_leaf_it.append(sid);
    }
    const chunked_leaf_root_id = try chunked_leaf_it.finish();
    defer pool.unref(chunked_leaf_root_id);

    // Reference: per-leaf path with 3*K real chunks and 1*K zero chunks.
    var leaf_it = Node.FillWithContentsIterator.init(&pool, ChunkedLeaf.k_log2 + 2);
    errdefer leaf_it.deinit();
    for (0..3) |s| for (0..ChunkedLeaf.K) |i| {
        var c = raw[s][i];
        try leaf_it.append(try pool.createLeaf(&c));
    };
    // The 4th chunked_leaf worth of leaves are zero (omitted = filled by finish()).
    const leaf_root_id = try leaf_it.finish();
    defer pool.unref(leaf_root_id);

    try std.testing.expectEqualSlices(u8, chunked_leaf_root_id.getRoot(&pool), leaf_root_id.getRoot(&pool));
}
