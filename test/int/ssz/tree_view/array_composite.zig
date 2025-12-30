const std = @import("std");
const ssz = @import("ssz");
const Node = @import("persistent_merkle_tree").Node;

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
    var view = try VectorType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    const e0_view = try view.get(0);
    var e0_value: Inner.Type = undefined;
    try Inner.tree.toValue(e0_view.base_view.data.root, &pool, &e0_value);
    try std.testing.expectEqual(@as(u32, 1), e0_value.a);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 1, 1, 1 }, e0_value.b[0..]);

    const replacement: Inner.Type = .{ .a = 9, .b = [_]u8{ 9, 9, 9, 9 } };
    const replacement_root = try Inner.tree.fromValue(&pool, &replacement);
    var replacement_view: ?Inner.TreeView = try Inner.TreeView.init(allocator, &pool, replacement_root);
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
    try VectorType.tree.toValue(view.base_view.data.root, &pool, &roundtrip);
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
    var view = try VectorType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    try std.testing.expectError(error.IndexOutOfBounds, view.get(2));

    const replacement: Inner.Type = .{ .x = 3 };
    const replacement_root = try Inner.tree.fromValue(&pool, &replacement);
    var replacement_view: ?Inner.TreeView = try Inner.TreeView.init(allocator, &pool, replacement_root);
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
    var view = try VectorType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    view.clearCache();

    const replacement: Inner.Type = .{ .id = 1, .vec = [_]u32{ 0, 9 } };
    const replacement_root = try Inner.tree.fromValue(&pool, &replacement);
    var replacement_view: ?Inner.TreeView = try Inner.TreeView.init(allocator, &pool, replacement_root);
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

test "TreeView vector composite clone isolates updates" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const Inner = ssz.FixedContainerType(struct { a: Uint32 });
    const VectorType = ssz.FixedVectorType(Inner, 2);

    const original: VectorType.Type = .{ .{ .a = 1 }, .{ .a = 2 } };
    const root = try VectorType.tree.fromValue(&pool, &original);

    var v1 = try VectorType.TreeView.init(allocator, &pool, root);
    defer v1.deinit();

    var v2 = try v1.clone(false);
    defer v2.deinit();

    const replacement: Inner.Type = .{ .a = 9 };
    const replacement_root = try Inner.tree.fromValue(&pool, &replacement);
    var replacement_view: ?Inner.TreeView = try Inner.TreeView.init(allocator, &pool, replacement_root);
    defer if (replacement_view) |*v| v.deinit();
    try v2.set(1, replacement_view.?);
    replacement_view = null;

    try v2.commit();

    const v1_e1 = try v1.get(1);
    var v1_e1_value: Inner.Type = undefined;
    try Inner.tree.toValue(v1_e1.base_view.data.root, &pool, &v1_e1_value);

    const v2_e1 = try v2.get(1);
    var v2_e1_value: Inner.Type = undefined;
    try Inner.tree.toValue(v2_e1.base_view.data.root, &pool, &v2_e1_value);

    try std.testing.expectEqual(@as(u32, 2), v1_e1_value.a);
    try std.testing.expectEqual(@as(u32, 9), v2_e1_value.a);
}

test "TreeView vector composite clone reads committed state" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const Inner = ssz.FixedContainerType(struct { a: Uint32 });
    const VectorType = ssz.FixedVectorType(Inner, 2);

    const original: VectorType.Type = .{ .{ .a = 1 }, .{ .a = 2 } };
    const root = try VectorType.tree.fromValue(&pool, &original);

    var v1 = try VectorType.TreeView.init(allocator, &pool, root);
    defer v1.deinit();

    const replacement: Inner.Type = .{ .a = 9 };
    const replacement_root = try Inner.tree.fromValue(&pool, &replacement);
    var replacement_view: ?Inner.TreeView = try Inner.TreeView.init(allocator, &pool, replacement_root);
    defer if (replacement_view) |*v| v.deinit();
    try v1.set(1, replacement_view.?);
    replacement_view = null;
    try v1.commit();

    var v2 = try v1.clone(false);
    defer v2.deinit();

    const v2_e1 = try v2.get(1);
    var v2_e1_value: Inner.Type = undefined;
    try Inner.tree.toValue(v2_e1.base_view.data.root, &pool, &v2_e1_value);

    try std.testing.expectEqual(@as(u32, 9), v2_e1_value.a);
}

test "TreeView vector composite clone drops uncommitted changes" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const Inner = ssz.FixedContainerType(struct { a: Uint32 });
    const VectorType = ssz.FixedVectorType(Inner, 2);

    const original: VectorType.Type = .{ .{ .a = 1 }, .{ .a = 2 } };
    const root = try VectorType.tree.fromValue(&pool, &original);

    var v = try VectorType.TreeView.init(allocator, &pool, root);
    defer v.deinit();

    const replacement: Inner.Type = .{ .a = 9 };
    const replacement_root = try Inner.tree.fromValue(&pool, &replacement);
    var replacement_view: ?Inner.TreeView = try Inner.TreeView.init(allocator, &pool, replacement_root);
    defer if (replacement_view) |*v0| v0.deinit();
    try v.set(1, replacement_view.?);
    replacement_view = null;

    const v_e1_before = try v.get(1);
    var v_e1_before_value: Inner.Type = undefined;
    try Inner.tree.toValue(v_e1_before.base_view.data.root, &pool, &v_e1_before_value);
    try std.testing.expectEqual(@as(u32, 9), v_e1_before_value.a);

    var dropped = try v.clone(false);
    defer dropped.deinit();

    const v_e1_after = try v.get(1);
    var v_e1_after_value: Inner.Type = undefined;
    try Inner.tree.toValue(v_e1_after.base_view.data.root, &pool, &v_e1_after_value);

    const dropped_e1 = try dropped.get(1);
    var dropped_e1_value: Inner.Type = undefined;
    try Inner.tree.toValue(dropped_e1.base_view.data.root, &pool, &dropped_e1_value);

    try std.testing.expectEqual(@as(u32, 2), v_e1_after_value.a);
    try std.testing.expectEqual(@as(u32, 2), dropped_e1_value.a);
}

test "TreeView vector composite clone(true) does not transfer cache" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const Inner = ssz.FixedContainerType(struct {
        a: Uint32,
    });
    const VectorType = ssz.FixedVectorType(Inner, 2);

    const original: VectorType.Type = .{ .{ .a = 1 }, .{ .a = 2 } };
    const root_node = try VectorType.tree.fromValue(&pool, &original);
    var view = try VectorType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    _ = try view.get(0);
    try view.commit();

    try std.testing.expect(view.base_view.data.children_data.count() > 0);

    var cloned_no_cache = try view.clone(true);
    defer cloned_no_cache.deinit();

    try std.testing.expect(view.base_view.data.children_data.count() > 0);
    try std.testing.expectEqual(@as(usize, 0), cloned_no_cache.base_view.data.children_data.count());
}

test "TreeView vector composite clone(false) transfers cache and clears source" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const Inner = ssz.FixedContainerType(struct {
        a: Uint32,
    });
    const VectorType = ssz.FixedVectorType(Inner, 2);

    const original: VectorType.Type = .{ .{ .a = 1 }, .{ .a = 2 } };
    const root_node = try VectorType.tree.fromValue(&pool, &original);
    var view = try VectorType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    _ = try view.get(0);
    try view.commit();

    try std.testing.expect(view.base_view.data.children_data.count() > 0);

    var cloned = try view.clone(false);
    defer cloned.deinit();

    try std.testing.expectEqual(@as(usize, 0), view.base_view.data.children_data.count());
    try std.testing.expect(cloned.base_view.data.children_data.count() > 0);
}

// Tests ported from TypeScript ssz packages/ssz/test/unit/byType/vector/tree.test.ts
test "ArrayCompositeTreeView - serialize (ByteVector32 vector)" {
    const allocator = std.testing.allocator;

    const Root32 = ssz.ByteVectorType(32);
    const VecRootsType = ssz.FixedVectorType(Root32, 4);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const value = [4][32]u8{
        [_]u8{0xaa} ** 32,
        [_]u8{0xbb} ** 32,
        [_]u8{0xcc} ** 32,
        [_]u8{0xdd} ** 32,
    };

    var value_serialized: [VecRootsType.fixed_size]u8 = undefined;
    _ = VecRootsType.serializeIntoBytes(&value, &value_serialized);

    const tree_node = try VecRootsType.tree.fromValue(&pool, &value);
    var view = try VecRootsType.TreeView.init(allocator, &pool, tree_node);
    defer view.deinit();

    var view_serialized: [VecRootsType.fixed_size]u8 = undefined;
    const written = try view.serializeIntoBytes(&view_serialized);
    try std.testing.expectEqual(view_serialized.len, written);

    try std.testing.expectEqualSlices(u8, &value_serialized, &view_serialized);

    const view_size = try view.serializedSize();
    try std.testing.expectEqual(@as(usize, 128), view_size);

    try std.testing.expectEqualSlices(u8, &value[0], view_serialized[0..32]);
    try std.testing.expectEqualSlices(u8, &value[1], view_serialized[32..64]);
    try std.testing.expectEqualSlices(u8, &value[2], view_serialized[64..96]);
    try std.testing.expectEqualSlices(u8, &value[3], view_serialized[96..128]);
}

test "ArrayCompositeTreeView - serialize (Container vector)" {
    const allocator = std.testing.allocator;

    const Uint64 = ssz.UintType(64);
    const TestContainer = ssz.FixedContainerType(struct {
        a: ssz.UintType(64),
        b: ssz.UintType(64),
    });
    _ = Uint64;
    const VecContainerType = ssz.FixedVectorType(TestContainer, 4);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const value = [4]TestContainer.Type{
        .{ .a = 0, .b = 0 },
        .{ .a = 123456, .b = 654321 },
        .{ .a = 234567, .b = 765432 },
        .{ .a = 345678, .b = 876543 },
    };

    var value_serialized: [VecContainerType.fixed_size]u8 = undefined;
    _ = VecContainerType.serializeIntoBytes(&value, &value_serialized);

    const tree_node = try VecContainerType.tree.fromValue(&pool, &value);
    var view = try VecContainerType.TreeView.init(allocator, &pool, tree_node);
    defer view.deinit();

    var view_serialized: [VecContainerType.fixed_size]u8 = undefined;
    const written = try view.serializeIntoBytes(&view_serialized);
    try std.testing.expectEqual(view_serialized.len, written);

    try std.testing.expectEqualSlices(u8, &value_serialized, &view_serialized);

    // 0x0000000000000000000000000000000040e2010000000000f1fb0900000000004794030000000000f8ad0b00000000004e46050000000000ff5f0d0000000000
    const expected = [_]u8{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0xe2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1, 0xfb, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x47, 0x94, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xad, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x4e, 0x46, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x5f, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    try std.testing.expectEqualSlices(u8, &expected, &view_serialized);

    var hash_root: [32]u8 = undefined;
    try view.hashTreeRoot(&hash_root);
    // 0xb1a797eb50654748ba239010edccea7b46b55bf740730b700684f48b0c478372
    const expected_root = [_]u8{ 0xb1, 0xa7, 0x97, 0xeb, 0x50, 0x65, 0x47, 0x48, 0xba, 0x23, 0x90, 0x10, 0xed, 0xcc, 0xea, 0x7b, 0x46, 0xb5, 0x5b, 0xf7, 0x40, 0x73, 0x0b, 0x70, 0x06, 0x84, 0xf4, 0x8b, 0x0c, 0x47, 0x83, 0x72 };
    try std.testing.expectEqualSlices(u8, &expected_root, &hash_root);
}

test "ArrayCompositeTreeView - get and set" {
    const allocator = std.testing.allocator;

    const Root32 = ssz.ByteVectorType(32);
    const VecRootsType = ssz.FixedVectorType(Root32, 4);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const value = [4][32]u8{
        [_]u8{0xaa} ** 32,
        [_]u8{0xbb} ** 32,
        [_]u8{0xcc} ** 32,
        [_]u8{0xdd} ** 32,
    };

    const tree_node = try VecRootsType.tree.fromValue(&pool, &value);
    var view = try VecRootsType.TreeView.init(allocator, &pool, tree_node);
    defer view.deinit();

    var elem0 = try view.get(0);
    defer elem0.deinit();
    var bytes0: [Root32.fixed_size]u8 = undefined;
    const bytes0_written = try elem0.serializeIntoBytes(&bytes0);
    try std.testing.expectEqual(bytes0.len, bytes0_written);
    try std.testing.expectEqualSlices(u8, &value[0], &bytes0);

    const new_val = [_]u8{0xff} ** 32;
    const new_node = try Root32.tree.fromValue(&pool, &new_val);
    const new_elem = try Root32.TreeView.init(allocator, &pool, new_node);
    try view.set(1, new_elem);

    var elem1 = try view.get(1);
    defer elem1.deinit();
    var bytes1: [Root32.fixed_size]u8 = undefined;
    const bytes1_written = try elem1.serializeIntoBytes(&bytes1);
    try std.testing.expectEqual(bytes1.len, bytes1_written);
    try std.testing.expectEqualSlices(u8, &new_val, &bytes1);
}
