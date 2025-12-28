const std = @import("std");
const ssz = @import("ssz");
const Node = @import("persistent_merkle_tree").Node;
const build_options = @import("build_options");

test "TreeView vector composite element set/get/commit" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const Inner = ssz.FixedContainerType(struct {
        a: Uint32,
        b: ssz.ByteVectorType(4),
    });
    const VectorType = ssz.FixedVectorType(Inner, 2);

    const v0: Inner.Type = .{ .a = 1, .b = [_]u8{ 1, 1, 1, 1 } };
    const v1: Inner.Type = .{ .a = 2, .b = [_]u8{ 2, 2, 2, 2 } };
    const original: VectorType.Type = .{ v0, v1 };

    const root_node = try VectorType.tree.fromValue(&pool, &original);
    var store = ssz.ViewStore.init(allocator, &pool);
    defer store.deinit();
    var view = try VectorType.TreeView.init(&store, root_node);
    defer view.deinit();

    const e0_view = try view.get(0);
    var e0_value: Inner.Type = undefined;
    try Inner.tree.toValue(e0_view.rootNodeId(), &pool, &e0_value);
    try std.testing.expectEqual(@as(u32, 1), e0_value.a);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 1, 1, 1 }, e0_value.b[0..]);

    const replacement: Inner.Type = .{ .a = 9, .b = [_]u8{ 9, 9, 9, 9 } };
    const replacement_root = try Inner.tree.fromValue(&pool, &replacement);
    var replacement_view: ?Inner.TreeView = try Inner.TreeView.init(&store, replacement_root);
    defer if (replacement_view) |*v| v.deinit();
    try view.set(1, replacement_view.?);
    replacement_view = null;

    try view.commit();

    var actual_root: [32]u8 = undefined;
    try view.hashTreeRoot(&actual_root);

    var expected: VectorType.Type = .{ v0, replacement };
    var expected_root: [32]u8 = undefined;
    try VectorType.hashTreeRoot(&expected, &expected_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);

    var roundtrip: VectorType.Type = undefined;
    try VectorType.tree.toValue(view.rootNodeId(), &pool, &roundtrip);
    try std.testing.expectEqual(@as(u32, 1), roundtrip[0].a);
    try std.testing.expectEqual(@as(u32, 9), roundtrip[1].a);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 9, 9, 9, 9 }, roundtrip[1].b[0..]);
}

test "TreeView vector composite index bounds" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Inner = ssz.FixedContainerType(struct { x: ssz.UintType(64) });
    const VectorType = ssz.FixedVectorType(Inner, 2);
    const original: VectorType.Type = .{ .{ .x = 1 }, .{ .x = 2 } };

    const root_node = try VectorType.tree.fromValue(&pool, &original);
    var store = ssz.ViewStore.init(allocator, &pool);
    defer store.deinit();
    var view = try VectorType.TreeView.init(&store, root_node);
    defer view.deinit();

    try std.testing.expectError(error.IndexOutOfBounds, view.get(2));

    const replacement: Inner.Type = .{ .x = 3 };
    const replacement_root = try Inner.tree.fromValue(&pool, &replacement);
    var replacement_view: ?Inner.TreeView = try Inner.TreeView.init(&store, replacement_root);
    defer if (replacement_view) |*v| v.deinit();
    try std.testing.expectError(error.IndexOutOfBounds, view.set(2, replacement_view.?));
}

test "TreeView vector composite clearCache does not break subsequent commits" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const InnerVec = ssz.FixedVectorType(Uint32, 2);
    const Inner = ssz.FixedContainerType(struct {
        id: Uint32,
        vec: InnerVec,
    });
    const VectorType = ssz.FixedVectorType(Inner, 2);

    const v0: Inner.Type = .{ .id = 1, .vec = [_]u32{ 0, 1 } };
    const v1: Inner.Type = .{ .id = 2, .vec = [_]u32{ 2, 3 } };
    const original: VectorType.Type = .{ v0, v1 };

    const root_node = try VectorType.tree.fromValue(&pool, &original);
    var store = ssz.ViewStore.init(allocator, &pool);
    defer store.deinit();
    var view = try VectorType.TreeView.init(&store, root_node);
    defer view.deinit();

    view.clearCache();

    const replacement: Inner.Type = .{ .id = 1, .vec = [_]u32{ 0, 9 } };
    const replacement_root = try Inner.tree.fromValue(&pool, &replacement);
    var replacement_view: ?Inner.TreeView = try Inner.TreeView.init(&store, replacement_root);
    defer if (replacement_view) |*v| v.deinit();
    try view.set(0, replacement_view.?);
    replacement_view = null;

    var actual_root: [32]u8 = undefined;
    try view.hashTreeRoot(&actual_root);

    var expected: VectorType.Type = .{ replacement, v1 };
    var expected_root: [32]u8 = undefined;
    try VectorType.hashTreeRoot(&expected, &expected_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

test "TreeView vector composite POC sub-view mutate + commit" {
    if (!build_options.container_viewstore_poc) return;

    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const Inner = ssz.FixedContainerType(struct {
        a: Uint32,
        b: Uint32,
    });
    const VectorType = ssz.FixedVectorType(Inner, 2);

    var values: VectorType.Type = .{ .{ .a = 1, .b = 2 }, .{ .a = 3, .b = 4 } };
    const root_node = try VectorType.tree.fromValue(&pool, &values);

    const VecPOC = ssz.ArrayCompositeTreeViewViewStorePOC(VectorType);
    var store = ssz.ViewStore.init(allocator, &pool);
    defer store.deinit();

    var view = try VecPOC.init(&store, root_node);
    defer view.deinit();

    var e0 = try view.get(0);
    try e0.set("a", @as(u32, 11));
    try view.commit();

    values[0].a = 11;
    var expected_root: [32]u8 = undefined;
    try VectorType.hashTreeRoot(&values, &expected_root);

    var actual_root: [32]u8 = undefined;
    try view.hashTreeRoot(&actual_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}
