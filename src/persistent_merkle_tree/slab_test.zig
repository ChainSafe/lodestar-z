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
