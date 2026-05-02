const std = @import("std");

const Slab = @import("slab.zig");

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
