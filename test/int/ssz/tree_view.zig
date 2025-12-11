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

test "TreeView list of containers setElement twice then commit" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    const ContainerType = ssz.FixedContainerType(struct {
        a: ssz.UintType(64),
        b: ssz.UintType(64),
    });
    const ListType = ssz.FixedListType(ContainerType, 8);
    const ListView = ssz.TreeView(ListType);
    const ElemView = ListView.Element;

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.append(allocator, .{ .a = 1, .b = 2 });
    try list.append(allocator, .{ .a = 3, .b = 4 });
    try list.append(allocator, .{ .a = 5, .b = 6 });

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ListView.init(allocator, &pool, root_node);
    defer view.deinit();

    const new_container0: ContainerType.Type = .{ .a = 100, .b = 200 };
    const new_node0 = try ContainerType.tree.fromValue(&pool, &new_container0);
    const new_view0 = try ElemView.init(allocator, &pool, new_node0);
    try view.setElement(0, new_view0);

    const new_container1: ContainerType.Type = .{ .a = 300, .b = 400 };
    const new_node1 = try ContainerType.tree.fromValue(&pool, &new_container1);
    const new_view1 = try ElemView.init(allocator, &pool, new_node1);
    try view.setElement(1, new_view1);

    try view.commit();

    var expected_list: ListType.Type = .empty;
    defer expected_list.deinit(allocator);
    try expected_list.append(allocator, .{ .a = 100, .b = 200 });
    try expected_list.append(allocator, .{ .a = 300, .b = 400 });
    try expected_list.append(allocator, .{ .a = 5, .b = 6 });

    var expected_root: [32]u8 = undefined;
    try ListType.hashTreeRoot(allocator, &expected_list, &expected_root);

    var actual_root: [32]u8 = undefined;
    try view.hashTreeRoot(&actual_root);

    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

test "TreeView list of containers getElement modify setElement" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    const ContainerType = ssz.FixedContainerType(struct {
        a: ssz.UintType(64),
        b: ssz.UintType(64),
    });
    const ListType = ssz.FixedListType(ContainerType, 8);
    const ListView = ssz.TreeView(ListType);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.append(allocator, .{ .a = 1, .b = 2 });
    try list.append(allocator, .{ .a = 3, .b = 4 });
    try list.append(allocator, .{ .a = 5, .b = 6 });

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ListView.init(allocator, &pool, root_node);
    defer view.deinit();

    var elem0 = try view.getElement(0);
    try elem0.setField("a", 100);
    try elem0.setField("b", 200);
    try view.setElement(0, elem0);

    var elem1 = try view.getElement(1);
    try elem1.setField("a", 300);
    try view.setElement(1, elem1);

    try view.commit();

    var expected_list: ListType.Type = .empty;
    defer expected_list.deinit(allocator);
    try expected_list.append(allocator, .{ .a = 100, .b = 200 });
    try expected_list.append(allocator, .{ .a = 300, .b = 4 });
    try expected_list.append(allocator, .{ .a = 5, .b = 6 });

    var expected_root: [32]u8 = undefined;
    try ListType.hashTreeRoot(allocator, &expected_list, &expected_root);

    var actual_root: [32]u8 = undefined;
    try view.hashTreeRoot(&actual_root);

    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}
