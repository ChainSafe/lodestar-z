const std = @import("std");
const ssz = @import("ssz");
const Node = @import("persistent_merkle_tree").Node;
const build_options = @import("build_options");

test "TreeView vector element roundtrip" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 128);
    defer pool.deinit();

    const Uint64 = ssz.UintType(64);
    const VectorType = ssz.FixedVectorType(Uint64, 4);

    const original: VectorType.Type = [_]u64{ 11, 22, 33, 44 };

    const root_node = try VectorType.tree.fromValue(&pool, &original);
    var view = try VectorType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    try std.testing.expectEqual(@as(u64, 11), try view.get(0));
    try std.testing.expectEqual(@as(u64, 44), try view.get(3));

    try view.set(1, 77);
    try view.set(2, 88);

    try view.commit();

    var expected = original;
    expected[1] = 77;
    expected[2] = 88;

    var expected_root: [32]u8 = undefined;
    try VectorType.hashTreeRoot(&expected, &expected_root);

    var actual_root: [32]u8 = undefined;
    try view.hashTreeRoot(&actual_root);

    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);

    var roundtrip: VectorType.Type = undefined;
    try VectorType.tree.toValue(view.rootNodeId(), &pool, &roundtrip);
    try std.testing.expectEqualSlices(u64, &expected, &roundtrip);
}

test "TreeView vector getAll fills provided buffer" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const VectorType = ssz.FixedVectorType(Uint32, 8);

    const values = [_]u32{ 9, 8, 7, 6, 5, 4, 3, 2 };
    const root_node = try VectorType.tree.fromValue(&pool, &values);
    var view = try VectorType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    const out = try allocator.alloc(u32, values.len);
    defer allocator.free(out);

    const filled = try view.getAllInto(out);
    try std.testing.expectEqual(out.ptr, filled.ptr);
    try std.testing.expectEqual(out.len, filled.len);
    try std.testing.expectEqualSlices(u32, values[0..], filled);

    const wrong = try allocator.alloc(u32, values.len - 1);
    defer allocator.free(wrong);
    try std.testing.expectError(error.InvalidSize, view.getAllInto(wrong));
}

test "TreeView vector getAllAlloc roundtrip" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint16 = ssz.UintType(16);
    const VectorType = ssz.FixedVectorType(Uint16, 5);
    const values = [_]u16{ 3, 1, 4, 1, 5 };

    const root_node = try VectorType.tree.fromValue(&pool, &values);
    var view = try VectorType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    const filled = try view.getAll(allocator);
    defer allocator.free(filled);

    try std.testing.expectEqualSlices(u16, values[0..], filled);
}

test "TreeView vector getAllAlloc repeat reflects updates" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const VectorType = ssz.FixedVectorType(Uint32, 6);
    var values = [_]u32{ 10, 20, 30, 40, 50, 60 };

    const root_node = try VectorType.tree.fromValue(&pool, &values);
    var view = try VectorType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    const first = try view.getAll(allocator);
    defer allocator.free(first);
    try std.testing.expectEqualSlices(u32, values[0..], first);

    try view.set(3, 99);

    const second = try view.getAll(allocator);
    defer allocator.free(second);
    values[3] = 99;
    try std.testing.expectEqualSlices(u32, values[0..], second);
}

test "TreeView vector prefetch POC updates metadata" {
    if (!build_options.container_viewstore_poc) return;

    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const VectorType = ssz.FixedVectorType(Uint32, 8);

    const values = [_]u32{ 9, 8, 7, 6, 5, 4, 3, 2 };
    const root_node = try VectorType.tree.fromValue(&pool, &values);

    const VecPOCView = ssz.ArrayBasicTreeViewViewStorePOC(VectorType);
    var view = try VecPOCView.init(allocator, &pool, root_node);
    defer view.deinit();

    try std.testing.expectEqual(@as(?usize, null), view.prefetchedCount());

    const out = try allocator.alloc(u32, values.len);
    defer allocator.free(out);

    _ = try view.getAllInto(out);
    try std.testing.expectEqual(@as(?usize, 1), view.prefetchedCount());
    try std.testing.expectEqualSlices(u32, values[0..], out);

    _ = try view.getAllInto(out);
    try std.testing.expectEqual(@as(?usize, 1), view.prefetchedCount());

    view.invalidatePrefetch();
    try std.testing.expectEqual(@as(?usize, null), view.prefetchedCount());
    _ = try view.getAllInto(out);
    try std.testing.expectEqual(@as(?usize, 1), view.prefetchedCount());
}
