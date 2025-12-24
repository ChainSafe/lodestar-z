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
    var cp_view = try Checkpoint.TreeView.init(std.testing.allocator, &pool, root_node);
    defer cp_view.deinit();

    // get field "epoch"
    try std.testing.expectEqual(42, try cp_view.get("epoch"));

    // get field "root"
    var root_view = try cp_view.get("root");
    var root = [_]u8{0} ** 32;
    const RootView = @typeInfo(Checkpoint.TreeView.Field("root")).pointer.child;
    try RootView.SszType.tree.toValue(root_view.getRoot(), &pool, root[0..]);
    try std.testing.expectEqualSlices(u8, ([_]u8{1} ** 32)[0..], root[0..]);

    // modify field "epoch"
    try cp_view.set("epoch", 100);
    try std.testing.expectEqual(100, try cp_view.get("epoch"));

    // modify field "root"
    var new_root = [_]u8{2} ** 32;
    const new_root_node = try RootView.SszType.tree.fromValue(&pool, &new_root);
    const new_root_view = try RootView.init(std.testing.allocator, &pool, new_root_node);
    try cp_view.set("root", new_root_view);

    // confirm "root" has been modified
    root_view = try cp_view.get("root");
    try RootView.SszType.tree.toValue(root_view.getRoot(), &pool, root[0..]);
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

test "TreeView container nested types set/get/commit" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 2048);
    defer pool.deinit();

    const Uint16 = ssz.UintType(16);
    const Uint32 = ssz.UintType(32);
    const Uint64 = ssz.UintType(64);

    const Bytes = ssz.ByteListType(16);
    const BasicVec = ssz.FixedVectorType(Uint16, 4);

    const InnerFixed = ssz.FixedContainerType(struct {
        a: Uint32,
        b: ssz.ByteVectorType(4),
    });
    const CompVec = ssz.FixedVectorType(InnerFixed, 2);

    const InnerVar = ssz.VariableContainerType(struct {
        id: Uint32,
        payload: ssz.ByteListType(8),
    });
    const CompList = ssz.VariableListType(InnerVar, 4);

    const Outer = ssz.VariableContainerType(struct {
        n: Uint64,
        bytes: Bytes,
        basic_vec: BasicVec,
        comp_vec: CompVec,
        comp_list: CompList,
    });

    var outer_value: Outer.Type = Outer.default_value;
    defer Outer.deinit(allocator, &outer_value);

    const root = try Outer.tree.fromValue(allocator, &pool, &outer_value);
    var view = try Outer.TreeView.init(allocator, &pool, root);
    defer view.deinit();

    try std.testing.expectEqual(@as(u64, 0), try view.get("n"));
    try view.set("n", @as(u64, 7));
    try std.testing.expectEqual(@as(u64, 7), try view.get("n"));

    {
        var bytes_value: Bytes.Type = Bytes.default_value;
        defer bytes_value.deinit(allocator);
        const bytes_root = try Bytes.tree.fromValue(allocator, &pool, &bytes_value);
        var bytes_view = try Bytes.TreeView.init(allocator, &pool, bytes_root);

        try bytes_view.push(@as(u8, 0xAA));
        try bytes_view.push(@as(u8, 0xBB));
        try bytes_view.set(1, @as(u8, 0xCC));

        const all = try bytes_view.getAll();
        defer allocator.free(all);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xCC }, all);

        try view.set("bytes", bytes_view);
    }

    {
        const basic_vec_value: BasicVec.Type = [_]u16{ 0, 0, 0, 0 };
        const basic_vec_root = try BasicVec.tree.fromValue(&pool, &basic_vec_value);
        var basic_vec_view = try BasicVec.TreeView.init(allocator, &pool, basic_vec_root);

        try std.testing.expectEqual(@as(u16, 0), try basic_vec_view.get(0));
        try basic_vec_view.set(0, @as(u16, 1));
        try basic_vec_view.set(3, @as(u16, 4));

        const all = try basic_vec_view.getAll();
        defer allocator.free(all);
        try std.testing.expectEqual(@as(usize, 4), all.len);
        try std.testing.expectEqual(@as(u16, 1), all[0]);
        try std.testing.expectEqual(@as(u16, 0), all[1]);
        try std.testing.expectEqual(@as(u16, 0), all[2]);
        try std.testing.expectEqual(@as(u16, 4), all[3]);

        try view.set("basic_vec", basic_vec_view);
    }

    {
        const comp_vec_value: CompVec.Type = .{ InnerFixed.default_value, InnerFixed.default_value };
        const comp_vec_root = try CompVec.tree.fromValue(&pool, &comp_vec_value);
        var comp_vec_view = try CompVec.TreeView.init(allocator, &pool, comp_vec_root);

        const e0: InnerFixed.Type = .{ .a = 11, .b = [_]u8{ 1, 2, 3, 4 } };
        const e0_root = try InnerFixed.tree.fromValue(&pool, &e0);
        var e0_view: ?*InnerFixed.TreeView = try InnerFixed.TreeView.init(allocator, &pool, e0_root);
        defer if (e0_view) |v| v.deinit();
        try comp_vec_view.set(0, e0_view.?);
        e0_view = null;

        const e1: InnerFixed.Type = .{ .a = 22, .b = [_]u8{ 4, 3, 2, 1 } };
        const e1_root = try InnerFixed.tree.fromValue(&pool, &e1);
        var e1_view: ?*InnerFixed.TreeView = try InnerFixed.TreeView.init(allocator, &pool, e1_root);
        defer if (e1_view) |v| v.deinit();
        try comp_vec_view.set(1, e1_view.?);
        e1_view = null;

        try view.set("comp_vec", comp_vec_view);
    }

    {
        var comp_list_value: CompList.Type = .empty;
        defer CompList.deinit(allocator, &comp_list_value);
        const comp_list_root = try CompList.tree.fromValue(allocator, &pool, &comp_list_value);
        var comp_list_view = try CompList.TreeView.init(allocator, &pool, comp_list_root);

        var inner_value: InnerVar.Type = InnerVar.default_value;
        defer InnerVar.deinit(allocator, &inner_value);
        const inner_root = try InnerVar.tree.fromValue(allocator, &pool, &inner_value);
        var inner_view: ?*InnerVar.TreeView = try InnerVar.TreeView.init(allocator, &pool, inner_root);
        defer if (inner_view) |v| v.deinit();
        const inner = inner_view.?;

        try inner.set("id", @as(u32, 99));

        const payload_value_ssz_type = @typeInfo(InnerVar.TreeView.Field("payload")).pointer.child.SszType;
        var payload_value = payload_value_ssz_type.default_value;
        defer payload_value.deinit(allocator);
        const payload_root = try payload_value_ssz_type.tree.fromValue(allocator, &pool, &payload_value);
        var payload_view = try payload_value_ssz_type.TreeView.init(allocator, &pool, payload_root);
        try payload_view.push(@as(u8, 0x5A));
        try inner.set("payload", payload_view);

        try comp_list_view.push(inner_view.?);
        inner_view = null;

        try view.set("comp_list", comp_list_view);
    }

    try view.commit();

    var roundtrip: Outer.Type = Outer.default_value;
    defer Outer.deinit(allocator, &roundtrip);
    try Outer.tree.toValue(allocator, view.getRoot(), &pool, &roundtrip);

    try std.testing.expectEqual(@as(u64, 7), roundtrip.n);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xCC }, roundtrip.bytes.items);
    try std.testing.expectEqualSlices(u16, &[_]u16{ 1, 0, 0, 4 }, roundtrip.basic_vec[0..]);
    try std.testing.expectEqual(@as(u32, 11), roundtrip.comp_vec[0].a);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, roundtrip.comp_vec[0].b[0..]);
    try std.testing.expectEqual(@as(u32, 22), roundtrip.comp_vec[1].a);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 4, 3, 2, 1 }, roundtrip.comp_vec[1].b[0..]);
    try std.testing.expectEqual(@as(usize, 1), roundtrip.comp_list.items.len);
    try std.testing.expectEqual(@as(u32, 99), roundtrip.comp_list.items[0].id);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x5A}, roundtrip.comp_list.items[0].payload.items);
}
