const std = @import("std");
const ssz = @import("ssz");
const Node = @import("persistent_merkle_tree").Node;

const Checkpoint = ssz.FixedContainerType(struct {
    epoch: ssz.UintType(64),
    root: ssz.ByteVectorType(32),
});

test "TreeView container field roundtrip" {
    var pool = try Node.Pool.init(std.testing.allocator, 1000);
    defer pool.deinit();
    const checkpoint: Checkpoint.Type = .{
        .epoch = 42,
        .root = [_]u8{1} ** 32,
    };

    const root_node = try Checkpoint.tree.fromValue(&pool, &checkpoint);
    var cp_view = try ssz.TreeView(Checkpoint).init(std.testing.allocator, &pool, root_node);
    defer cp_view.deinit();

    // get field "epoch"
    try std.testing.expectEqual(42, try cp_view.getField("epoch"));

    // get field "root"
    var root_view = try cp_view.getField("root");
    var root = [_]u8{0} ** 32;
    const RootView = ssz.TreeView(Checkpoint).Field("root");
    try RootView.SszType.tree.toValue(root_view.data.root, &pool, root[0..]);
    try std.testing.expectEqualSlices(u8, ([_]u8{1} ** 32)[0..], root[0..]);

    // modify field "epoch"
    try cp_view.setField("epoch", 100);
    try std.testing.expectEqual(100, try cp_view.getField("epoch"));

    // modify field "root"
    var new_root = [_]u8{2} ** 32;
    const new_root_node = try RootView.SszType.tree.fromValue(&pool, &new_root);
    const new_root_view = try RootView.init(std.testing.allocator, &pool, new_root_node);
    try cp_view.setField("root", new_root_view);

    // confirm "root" has been modified
    root_view = try cp_view.getField("root");
    try RootView.SszType.tree.toValue(root_view.data.root, &pool, root[0..]);
    try std.testing.expectEqualSlices(u8, ([_]u8{2} ** 32)[0..], root[0..]);

    // commit and check hash_tree_root
    try cp_view.commit();
    var htr_from_value: [32]u8 = undefined;
    const expected_checkpoint: Checkpoint.Type = .{
        .epoch = 100,
        .root = [_]u8{2} ** 32,
    };
    try Checkpoint.hashTreeRoot(&expected_checkpoint, &htr_from_value);

    var htr_from_tree: [32]u8 = undefined;
    try cp_view.hashTreeRoot(&htr_from_tree);

    try std.testing.expectEqualSlices(
        u8,
        &htr_from_value,
        &htr_from_tree,
    );
}

test "TreeView vector element roundtrip" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 128);
    defer pool.deinit();

    const Uint64 = ssz.UintType(64);
    const VectorType = ssz.FixedVectorType(Uint64, 4);

    const original: VectorType.Type = [_]u64{ 11, 22, 33, 44 };

    const root_node = try VectorType.tree.fromValue(&pool, &original);
    var view = try ssz.TreeView(VectorType).init(allocator, &pool, root_node);
    defer view.deinit();

    try std.testing.expectEqual(@as(u64, 11), try view.getElement(0));
    try std.testing.expectEqual(@as(u64, 44), try view.getElement(3));

    try view.setElement(1, 77);
    try view.setElement(2, 88);

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
    try VectorType.tree.toValue(view.data.root, &pool, &roundtrip);
    try std.testing.expectEqualSlices(u64, &expected, &roundtrip);
}

test "TreeView list element roundtrip" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const ListType = ssz.FixedListType(Uint32, 16);

    const base_values = [_]u32{ 5, 15, 25, 35, 45 };

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &base_values);

    var expected_list: ListType.Type = .empty;
    defer expected_list.deinit(allocator);
    try expected_list.appendSlice(allocator, &base_values);

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
    defer view.deinit();

    try std.testing.expectEqual(@as(u32, 5), try view.getElement(0));
    try std.testing.expectEqual(@as(u32, 45), try view.getElement(4));

    try view.setElement(2, 99);
    try view.setElement(4, 123);

    try view.commit();

    expected_list.items[2] = 99;
    expected_list.items[4] = 123;

    var expected_root: [32]u8 = undefined;
    try ListType.hashTreeRoot(allocator, &expected_list, &expected_root);

    var actual_root: [32]u8 = undefined;
    try view.hashTreeRoot(&actual_root);

    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);

    var roundtrip: ListType.Type = .empty;
    defer roundtrip.deinit(allocator);
    try ListType.tree.toValue(allocator, view.data.root, &pool, &roundtrip);
    try std.testing.expectEqual(roundtrip.items.len, expected_list.items.len);
    try std.testing.expectEqualSlices(u32, expected_list.items, roundtrip.items);
}

test "TreeView list push updates cached length" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const ListType = ssz.FixedListType(Uint32, 16);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &[_]u32{ 1, 2, 3 });

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
    defer view.deinit();

    try std.testing.expectEqual(@as(usize, 3), try view.getLength());

    try view.push(@as(u32, 55));

    try std.testing.expectEqual(@as(usize, 4), try view.getLength());
    try std.testing.expectEqual(@as(u32, 55), try view.getElement(3));

    try view.commit();

    try std.testing.expectEqual(@as(usize, 4), try view.getLength());

    var expected: ListType.Type = .empty;
    defer expected.deinit(allocator);
    try expected.appendSlice(allocator, &[_]u32{ 1, 2, 3, 55 });

    var expected_root: [32]u8 = undefined;
    try ListType.hashTreeRoot(allocator, &expected, &expected_root);

    var actual_root: [32]u8 = undefined;
    try view.hashTreeRoot(&actual_root);

    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

test "TreeView vector getAllElements fills provided buffer" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const VectorType = ssz.FixedVectorType(Uint32, 8);

    const values = [_]u32{ 9, 8, 7, 6, 5, 4, 3, 2 };
    const root_node = try VectorType.tree.fromValue(&pool, &values);
    var view = try ssz.TreeView(VectorType).init(allocator, &pool, root_node);
    defer view.deinit();

    const out = try allocator.alloc(u32, values.len);
    defer allocator.free(out);

    const filled = try view.getAllElements(out);
    try std.testing.expectEqual(out.ptr, filled.ptr);
    try std.testing.expectEqual(out.len, filled.len);
    try std.testing.expectEqualSlices(u32, values[0..], filled);

    const wrong = try allocator.alloc(u32, values.len - 1);
    defer allocator.free(wrong);
    try std.testing.expectError(error.InvalidSize, view.getAllElements(wrong));
}

test "TreeView vector getAllElementsAlloc roundtrip" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint16 = ssz.UintType(16);
    const VectorType = ssz.FixedVectorType(Uint16, 5);
    const values = [_]u16{ 3, 1, 4, 1, 5 };

    const root_node = try VectorType.tree.fromValue(&pool, &values);
    var view = try ssz.TreeView(VectorType).init(allocator, &pool, root_node);
    defer view.deinit();

    const filled = try view.getAllElementsAlloc(allocator);
    defer allocator.free(filled);

    try std.testing.expectEqualSlices(u16, values[0..], filled);
}

test "TreeView vector getAllElementsAlloc repeat reflects updates" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const VectorType = ssz.FixedVectorType(Uint32, 6);
    var values = [_]u32{ 10, 20, 30, 40, 50, 60 };

    const root_node = try VectorType.tree.fromValue(&pool, &values);
    var view = try ssz.TreeView(VectorType).init(allocator, &pool, root_node);
    defer view.deinit();

    const first = try view.getAllElementsAlloc(allocator);
    defer allocator.free(first);
    try std.testing.expectEqualSlices(u32, values[0..], first);

    try view.setElement(3, 99);

    const second = try view.getAllElementsAlloc(allocator);
    defer allocator.free(second);
    values[3] = 99;
    try std.testing.expectEqualSlices(u32, values[0..], second);
}

test "TreeView list getAllElementsAlloc handles zero length" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();

    const Uint8 = ssz.UintType(8);
    const ListType = ssz.FixedListType(Uint8, 4);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
    defer view.deinit();

    const filled = try view.getAllElementsAlloc(allocator);
    defer allocator.free(filled);

    try std.testing.expectEqual(@as(usize, 0), filled.len);
}

test "TreeView list getAllElementsAlloc spans multiple chunks" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    const Uint16 = ssz.UintType(16);
    const ListType = ssz.FixedListType(Uint16, 64);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);

    var values: [20]u16 = undefined;
    for (&values, 0..) |*val, idx| {
        val.* = @intCast((idx * 3 + 1) % 17);
    }
    try list.appendSlice(allocator, &values);

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
    defer view.deinit();

    const filled = try view.getAllElementsAlloc(allocator);
    defer allocator.free(filled);

    try std.testing.expectEqualSlices(u16, values[0..], filled);
}

test "TreeView list push batches before commit" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const ListType = ssz.FixedListType(Uint32, 16);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &[_]u32{ 1, 2, 3, 4 });

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
    defer view.deinit();

    try view.push(@as(u32, 5));
    try view.push(@as(u32, 6));
    try view.push(@as(u32, 7));
    try view.push(@as(u32, 8));
    try view.push(@as(u32, 9));

    try std.testing.expectEqual(@as(usize, 9), try view.getLength());
    try std.testing.expectEqual(@as(u32, 9), try view.getElement(8));

    try view.commit();

    try std.testing.expectEqual(@as(usize, 9), try view.getLength());
    try std.testing.expectEqual(@as(u32, 9), try view.getElement(8));

    var expected: ListType.Type = .empty;
    defer expected.deinit(allocator);
    try expected.appendSlice(allocator, &[_]u32{ 1, 2, 3, 4, 5, 6, 7, 8, 9 });

    var expected_root: [32]u8 = undefined;
    try ListType.hashTreeRoot(allocator, &expected, &expected_root);
    var actual_root: [32]u8 = undefined;
    try view.hashTreeRoot(&actual_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

test "TreeView list push across chunk boundary resets prefetch" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const ListType = ssz.FixedListType(Uint32, 32);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &[_]u32{ 0, 1, 2, 3, 4, 5, 6, 7 });

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
    defer view.deinit();

    const initial = try view.getAllElementsAlloc(allocator);
    defer allocator.free(initial);
    try std.testing.expectEqual(@as(usize, 8), initial.len);

    try view.push(@as(u32, 8));
    try view.push(@as(u32, 9));

    try std.testing.expectEqual(@as(usize, 10), try view.getLength());
    try std.testing.expectEqual(@as(u32, 9), try view.getElement(9));

    const filled = try view.getAllElementsAlloc(allocator);
    defer allocator.free(filled);
    var expected: [10]u32 = [_]u32{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    try std.testing.expectEqualSlices(u32, expected[0..], filled);
}

test "TreeView list push enforces limit" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const ListType = ssz.FixedListType(Uint32, 2);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &[_]u32{ 1, 2 });

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
    defer view.deinit();

    try std.testing.expectError(error.LengthOverLimit, view.push(@as(u32, 3)));
    try std.testing.expectEqual(@as(usize, 2), try view.getLength());
}
