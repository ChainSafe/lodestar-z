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

test "Node.slab: variant constructible and getRoot via direct pool slot" {
    const allocator = std.testing.allocator;

    // Prepare slab storage with deterministic content.
    const storage = try Slab.allocZero(allocator);
    defer Slab.destroy(allocator, storage);
    for (0..Slab.K) |i| {
        std.mem.writeInt(u256, &storage.chunks[i], @as(u256, @intCast(i + 1)), .little);
    }

    // Build Pool, manually plant a slab Node into a known slot for getRoot test.
    var pool = try Node.Pool.init(allocator, 16);
    defer pool.deinit();

    // Reserve a slot via a sentinel branch, then overwrite it with slab.
    // Two zero-leaf branches give us a real Node.Id we control.
    const tmp_id = try pool.createBranch(@enumFromInt(0), @enumFromInt(0));
    defer pool.unref(tmp_id);

    pool.nodes.items(.node)[@intFromEnum(tmp_id)] = .{ .slab = .{
        .chunks = @ptrCast(&storage.chunks),
        .len = Slab.K,
        .dirty = std.StaticBitSet(Slab.K).initEmpty(),
        .root = null,
    } };

    // getRoot must compute slab merkleization and cache it.
    const root_first = tmp_id.getRoot(&pool);
    try std.testing.expect(pool.nodes.items(.node)[@intFromEnum(tmp_id)].slab.root != null);

    // Reference root via Slab.computeRoot directly.
    var ref: [32]u8 = undefined;
    Slab.computeRoot(storage, &ref);
    try std.testing.expectEqualSlices(u8, &ref, root_first);

    // Second call returns the cached root (same pointer or same value).
    const root_second = tmp_id.getRoot(&pool);
    try std.testing.expectEqualSlices(u8, root_first, root_second);
}
