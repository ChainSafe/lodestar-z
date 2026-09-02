//! Tests for `container.zig`.

const std = @import("std");
const Node = @import("persistent_merkle_tree").Node;
const FixedContainerType = @import("../type/container.zig").FixedContainerType;
const VariableContainerType = @import("../type/container.zig").VariableContainerType;
const StructContainerType = @import("../type/container.zig").StructContainerType;
const UintType = @import("../type/uint.zig").UintType;
const ByteVectorType = @import("../type/byte_vector.zig").ByteVectorType;
const BoolType = @import("../type/bool.zig").BoolType;
const ByteListType = @import("../type/byte_list.zig").ByteListType;
const FixedListType = @import("../type/list.zig").FixedListType;
const VariableListType = @import("../type/list.zig").VariableListType;
const FixedVectorType = @import("../type/vector.zig").FixedVectorType;
const ContainerTreeView = @import("container.zig").ContainerTreeView;
const StructContainerTreeView = @import("container.zig").StructContainerTreeView;

const Checkpoint = FixedContainerType(struct {
    epoch: UintType(64),
    root: ByteVectorType(32),
});

test "StructContainerTreeView - basic get/set/commit/root" {
    const allocator = std.testing.allocator;
    const StructValidator = StructContainerType(struct {
        pubkey: ByteVectorType(48),
        withdrawal_credentials: ByteVectorType(32),
        effective_balance: UintType(64),
        slashed: BoolType(),
        activation_eligibility_epoch: UintType(64),
        activation_epoch: UintType(64),
        exit_epoch: UintType(64),
        withdrawable_epoch: UintType(64),
    });

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    const v: StructValidator.Type = .{
        .pubkey = [_]u8{0} ** 48,
        .withdrawal_credentials = [_]u8{1} ** 32,
        .effective_balance = 32_000_000_000,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = std.math.maxInt(u64),
        .withdrawable_epoch = std.math.maxInt(u64),
    };

    const root_node = try StructValidator.tree.fromValue(&pool, &v);

    var view = try StructContainerTreeView(StructValidator).init(allocator, &pool, root_node);
    defer view.deinit();

    var view_root: [32]u8 = undefined;
    try view.hashTreeRootInto(&view_root);
    var expected_root: [32]u8 = undefined;
    try StructValidator.hashTreeRoot(&v, &expected_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &view_root);

    try std.testing.expectEqual(@as(u64, 32_000_000_000), try view.get("effective_balance"));
    try std.testing.expectEqual(false, try view.get("slashed"));

    try view.set("effective_balance", 32_100_000_000);
    try view.set("slashed", true);
    try view.commit();

    try std.testing.expectEqual(@as(u64, 32_100_000_000), try view.get("effective_balance"));
    try std.testing.expectEqual(true, try view.get("slashed"));

    var v2 = v;
    v2.effective_balance = 32_100_000_000;
    v2.slashed = true;
    var expected2: [32]u8 = undefined;
    try StructValidator.hashTreeRoot(&v2, &expected2);
    var view_root2: [32]u8 = undefined;
    try view.hashTreeRootInto(&view_root2);
    try std.testing.expectEqualSlices(u8, &expected2, &view_root2);
}

test "ContainerTreeView" {
    const Foo = FixedContainerType(struct {
        a: UintType(64),
        b: UintType(64),
    });

    var pool = try Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = std.testing.allocator, .pool_size = 1000 });
    defer pool.deinit();

    const foo_value: Foo.Type = .{
        .a = 123,
        .b = 456,
    };
    const root_node = try Foo.tree.fromValue(&pool, &foo_value);
    var foo_view = try ContainerTreeView(Foo).init(std.testing.allocator, &pool, root_node);
    defer foo_view.deinit();

    // test get() and set() and commit()
    try std.testing.expectEqual(123, try foo_view.get("a"));
    try std.testing.expectEqual(456, try foo_view.get("b"));
    try foo_view.set("a", 1230);
    try std.testing.expectEqual(1230, try foo_view.get("a"));
    try foo_view.commit();
    try std.testing.expectEqual(1230, try foo_view.get("a"));

    // test hashTreeRoot()
    var value_root: [32]u8 = undefined;
    var expected_foo_value: Foo.Type = .{ .a = 1230, .b = 456 };
    try Foo.hashTreeRoot(&expected_foo_value, &value_root);
    var view_root: [32]u8 = undefined;
    try foo_view.hashTreeRootInto(&view_root);
    try std.testing.expectEqualSlices(u8, value_root[0..], view_root[0..]);

    const Bar = FixedContainerType(struct {
        foo: Foo,
        c: UintType(32),
    });

    const bar_value: Bar.Type = .{
        .foo = foo_value,
        .c = 789,
    };
    const bar_root_node = try Bar.tree.fromValue(&pool, &bar_value);
    var bar_view = try ContainerTreeView(Bar).init(std.testing.allocator, &pool, bar_root_node);
    defer bar_view.deinit();

    // test nested get() and set() and commit()
    var foo_field_view = try bar_view.get("foo");
    try std.testing.expectEqual(123, try foo_field_view.get("a"));
    try std.testing.expectEqual(456, try foo_field_view.get("b"));
    try std.testing.expectEqual(789, try bar_view.get("c"));

    try foo_field_view.set("a", 1230);
    try std.testing.expectEqual(1230, try foo_field_view.get("a"));
    try bar_view.commit();
    try std.testing.expectEqual(1230, try foo_field_view.get("a"));

    // test hashTreeRoot() after nested modification
    const expected_bar_value: Bar.Type = .{
        .foo = .{ .a = 1230, .b = 456 },
        .c = 789,
    };
    try Bar.hashTreeRoot(&expected_bar_value, &value_root);
    try bar_view.hashTreeRootInto(&view_root);
    try std.testing.expectEqualSlices(u8, value_root[0..], view_root[0..]);

    const cloned_foo_view_node = try Foo.tree.fromValue(&pool, &expected_foo_value);
    const cloned_foo_view = try ContainerTreeView(Foo).init(std.testing.allocator, &pool, cloned_foo_view_node);
    // do not deinit cloned_foo_view, it will be transferred
    try bar_view.set("foo", cloned_foo_view);
    try bar_view.hashTreeRootInto(&view_root);
    try std.testing.expectEqualSlices(u8, value_root[0..], view_root[0..]);
}

test "TreeView container field roundtrip" {
    var pool = try Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = std.testing.allocator, .pool_size = 1000 });
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
    try cp_view.hashTreeRootInto(&htr_from_tree);

    try std.testing.expectEqualSlices(
        u8,
        &htr_from_value,
        &htr_from_tree,
    );
}

test "StructContainerTreeView clone drops uncommitted changes" {
    var pool = try Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = std.testing.allocator, .pool_size = 256 });
    defer pool.deinit();

    const StructCheckpoint = StructContainerType(struct {
        epoch: UintType(64),
        root: ByteVectorType(32),
    });
    const value: StructCheckpoint.Type = .{ .epoch = 1, .root = [_]u8{1} ** 32 };
    var view = try StructCheckpoint.TreeView.fromValue(std.testing.allocator, &pool, &value);
    defer view.deinit();
    const committed_root = view.getRoot();

    try view.set("epoch", 9);
    var cloned = try view.clone(.{});
    defer cloned.deinit();

    try std.testing.expectEqual(@as(u64, 1), try cloned.get("epoch"));
    try std.testing.expectEqual(@as(u64, 1), try view.get("epoch"));
    try std.testing.expectEqual(committed_root, cloned.getRoot());
    try std.testing.expectEqual(committed_root, view.getRoot());

    try view.set("epoch", 5);
    var kept = try view.clone(.{ .transfer_cache = false });
    defer kept.deinit();
    try std.testing.expectEqual(@as(u64, 1), try kept.get("epoch"));
    try std.testing.expectEqual(@as(u64, 5), try view.get("epoch"));
}

test "TreeView container nested types set/get/commit" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 2048 });
    defer pool.deinit();

    const Uint16 = UintType(16);
    const Uint32 = UintType(32);
    const Uint64 = UintType(64);

    const Bytes = ByteListType(16);
    const BasicVec = FixedVectorType(Uint16, 4, .{});

    const InnerFixed = FixedContainerType(struct {
        a: Uint32,
        b: ByteVectorType(4),
    });
    const CompVec = FixedVectorType(InnerFixed, 2, .{});

    const InnerVar = VariableContainerType(struct {
        id: Uint32,
        payload: ByteListType(8),
    });
    const CompList = VariableListType(InnerVar, 4);

    const Outer = VariableContainerType(struct {
        n: Uint64,
        bytes: Bytes,
        basic_vec: BasicVec,
        comp_vec: CompVec,
        comp_list: CompList,
    });

    var outer_value: Outer.Type = Outer.default_value;
    defer Outer.deinit(allocator, &outer_value);

    const root = try Outer.tree.fromValue(&pool, &outer_value);
    var view = try Outer.TreeView.init(allocator, &pool, root);
    defer view.deinit();

    try std.testing.expectEqual(@as(u64, 0), try view.get("n"));
    try view.set("n", @as(u64, 7));
    try std.testing.expectEqual(@as(u64, 7), try view.get("n"));

    {
        var bytes_value: Bytes.Type = Bytes.default_value;
        defer bytes_value.deinit(allocator);
        const bytes_root = try Bytes.tree.fromValue(&pool, &bytes_value);
        var bytes_view = try Bytes.TreeView.init(allocator, &pool, bytes_root);

        try bytes_view.push(@as(u8, 0xAA));
        try bytes_view.push(@as(u8, 0xBB));
        try bytes_view.set(1, @as(u8, 0xCC));

        const all = try bytes_view.getAll(null);
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

        const all = try basic_vec_view.getAll(allocator);
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
        const comp_list_root = try CompList.tree.fromValue(&pool, &comp_list_value);
        var comp_list_view = try CompList.TreeView.init(allocator, &pool, comp_list_root);

        var inner_value: InnerVar.Type = InnerVar.default_value;
        defer InnerVar.deinit(allocator, &inner_value);
        const inner_root = try InnerVar.tree.fromValue(&pool, &inner_value);
        var inner_view: ?*InnerVar.TreeView = try InnerVar.TreeView.init(allocator, &pool, inner_root);
        defer if (inner_view) |v| v.deinit();
        const inner = inner_view.?;

        try inner.set("id", @as(u32, 99));

        const payload_value_ssz_type = @typeInfo(InnerVar.TreeView.Field("payload")).pointer.child.SszType;
        var payload_value = payload_value_ssz_type.default_value;
        defer payload_value.deinit(allocator);
        const payload_root = try payload_value_ssz_type.tree.fromValue(&pool, &payload_value);
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

test "TreeView container clone isolates updates" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    const Uint64 = UintType(64);
    const C = FixedContainerType(struct {
        n: Uint64,
    });

    const value: C.Type = .{ .n = 1 };
    const root = try C.tree.fromValue(&pool, &value);

    var v1 = try C.TreeView.init(allocator, &pool, root);
    defer v1.deinit();

    var v2 = try v1.clone(.{});
    defer v2.deinit();

    try v2.set("n", @as(u64, 99));
    try v2.commit();

    try std.testing.expectEqual(@as(u64, 1), try v1.get("n"));
    try std.testing.expectEqual(@as(u64, 99), try v2.get("n"));
}

test "TreeView container clone drops uncommitted changes" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    const Uint64 = UintType(64);
    const C = FixedContainerType(struct {
        n: Uint64,
    });

    const value: C.Type = .{ .n = 1 };
    const root = try C.tree.fromValue(&pool, &value);

    var v = try C.TreeView.init(allocator, &pool, root);
    defer v.deinit();

    try v.set("n", @as(u64, 7));
    try std.testing.expectEqual(@as(u64, 7), try v.get("n"));

    var dropped = try v.clone(.{});
    defer dropped.deinit();

    try std.testing.expectEqual(@as(u64, 1), try v.get("n"));
    try std.testing.expectEqual(@as(u64, 1), try dropped.get("n"));
}

test "TreeView container clone(false) does not transfer cache" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    const Uint64 = UintType(64);
    const C = FixedContainerType(struct {
        n: Uint64,
    });

    const value: C.Type = .{ .n = 1 };
    const root = try C.tree.fromValue(&pool, &value);

    var v = try C.TreeView.init(allocator, &pool, root);
    defer v.deinit();

    _ = try v.get("n");
    try std.testing.expect(v.child_data[0] != null);

    var cloned_no_cache = try v.clone(.{ .transfer_cache = false });
    defer cloned_no_cache.deinit();

    try std.testing.expect(v.child_data[0] != null);
    try std.testing.expect(cloned_no_cache.child_data[0] == null);
}

test "TreeView container clone(true) transfers cache and clears source" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    const Uint64 = UintType(64);
    const C = FixedContainerType(struct {
        n: Uint64,
    });

    const value: C.Type = .{ .n = 1 };
    const root = try C.tree.fromValue(&pool, &value);

    var v = try C.TreeView.init(allocator, &pool, root);
    defer v.deinit();

    _ = try v.get("n");
    try std.testing.expect(v.child_data[0] != null);

    var cloned = try v.clone(.{});
    defer cloned.deinit();

    try std.testing.expect(v.child_data[0] == null);
    try std.testing.expect(cloned.child_data[0] != null);
}

// Tests ported from TypeScript ssz packages/ssz/test/unit/byType/container/tree.test.ts
test "ContainerTreeView - serialize (basic fields)" {
    const allocator = std.testing.allocator;

    const Uint64 = UintType(64);
    const TestContainer = FixedContainerType(struct {
        a: UintType(64),
        b: UintType(64),
    });
    _ = Uint64;

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    const TestCase = struct {
        id: []const u8,
        a: u64,
        b: u64,
        expected_serialized: []const u8,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "zero",
            .a = 0,
            .b = 0,
            // 0x00000000000000000000000000000000
            .expected_serialized = &[_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            // 0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b
            .expected_root = [_]u8{ 0xf5, 0xa5, 0xfd, 0x42, 0xd1, 0x6a, 0x20, 0x30, 0x27, 0x98, 0xef, 0x6e, 0xd3, 0x09, 0x97, 0x9b, 0x43, 0x00, 0x3d, 0x23, 0x20, 0xd9, 0xf0, 0xe8, 0xea, 0x98, 0x31, 0xa9, 0x27, 0x59, 0xfb, 0x4b },
        },
        .{
            .id = "some value",
            .a = 123456,
            .b = 654321,
            // 0x40e2010000000000f1fb090000000000
            .expected_serialized = &[_]u8{ 0x40, 0xe2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1, 0xfb, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00 },
            // 0x53b38aff7bf2dd1a49903d07a33509b980c6acc9f2235a45aac342b0a9528c22
            .expected_root = [_]u8{ 0x53, 0xb3, 0x8a, 0xff, 0x7b, 0xf2, 0xdd, 0x1a, 0x49, 0x90, 0x3d, 0x07, 0xa3, 0x35, 0x09, 0xb9, 0x80, 0xc6, 0xac, 0xc9, 0xf2, 0x23, 0x5a, 0x45, 0xaa, 0xc3, 0x42, 0xb0, 0xa9, 0x52, 0x8c, 0x22 },
        },
    };

    for (test_cases) |tc| {
        const value: TestContainer.Type = .{ .a = tc.a, .b = tc.b };

        var value_serialized: [TestContainer.fixed_size]u8 = undefined;
        _ = TestContainer.serializeIntoBytes(&value, &value_serialized);

        const tree_node = try TestContainer.tree.fromValue(&pool, &value);
        var view = try TestContainer.TreeView.init(allocator, &pool, tree_node);
        defer view.deinit();

        var view_serialized: [TestContainer.fixed_size]u8 = undefined;
        const written = try view.serializeIntoBytes(&view_serialized);
        try std.testing.expectEqual(view_serialized.len, written);

        try std.testing.expectEqualSlices(u8, tc.expected_serialized, &view_serialized);
        try std.testing.expectEqualSlices(u8, &value_serialized, &view_serialized);

        const view_size = try view.serializedSize();
        try std.testing.expectEqual(tc.expected_serialized.len, view_size);

        var hash_root: [32]u8 = undefined;
        try view.hashTreeRootInto(&hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "ContainerTreeView - get and set basic fields" {
    const allocator = std.testing.allocator;

    const Uint64 = UintType(64);
    const TestContainer = FixedContainerType(struct {
        a: UintType(64),
        b: UintType(64),
    });
    _ = Uint64;

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    const value: TestContainer.Type = .{ .a = 100, .b = 200 };
    const tree_node = try TestContainer.tree.fromValue(&pool, &value);
    var view = try TestContainer.TreeView.init(allocator, &pool, tree_node);
    defer view.deinit();

    try std.testing.expectEqual(@as(u64, 100), try view.get("a"));
    try std.testing.expectEqual(@as(u64, 200), try view.get("b"));

    try view.set("a", 999);
    try std.testing.expectEqual(@as(u64, 999), try view.get("a"));

    var serialized: [TestContainer.fixed_size]u8 = undefined;
    const written = try view.serializeIntoBytes(&serialized);
    try std.testing.expectEqual(serialized.len, written);

    const expected: TestContainer.Type = .{ .a = 999, .b = 200 };
    var expected_serialized: [TestContainer.fixed_size]u8 = undefined;
    _ = TestContainer.serializeIntoBytes(&expected, &expected_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &serialized);
}

test "ContainerTreeView - serialize (with nested list)" {
    const allocator = std.testing.allocator;

    const Uint64 = UintType(64);
    const ListU64 = FixedListType(Uint64, 128, .{});
    const TestContainer = VariableContainerType(struct {
        a: FixedListType(UintType(64), 128, .{}),
        b: UintType(64),
    });
    _ = ListU64;

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    var value: TestContainer.Type = .{
        .a = FixedListType(UintType(64), 128, .{}).default_value,
        .b = 0,
    };
    defer TestContainer.deinit(allocator, &value);

    const value_serialized = try allocator.alloc(u8, TestContainer.serializedSize(&value));
    defer allocator.free(value_serialized);
    _ = TestContainer.serializeIntoBytes(&value, value_serialized);

    const tree_node = try TestContainer.tree.fromValue(&pool, &value);
    var view = try TestContainer.TreeView.init(allocator, &pool, tree_node);
    defer view.deinit();

    const view_size = try view.serializedSize();
    const view_serialized = try allocator.alloc(u8, view_size);
    defer allocator.free(view_serialized);
    const written = try view.serializeIntoBytes(view_serialized);
    try std.testing.expectEqual(view_size, written);

    // Expected: offset (4 bytes) + b (8 bytes) + empty list data (0 bytes)
    // 0x0c0000000000000000000000
    const expected_serialized = [_]u8{ 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try std.testing.expectEqualSlices(u8, &expected_serialized, view_serialized);
    try std.testing.expectEqualSlices(u8, value_serialized, view_serialized);

    var hash_root: [32]u8 = undefined;
    try view.hashTreeRootInto(&hash_root);
    // 0xdc3619cbbc5ef0e0a3b38e3ca5d31c2b16868eacb6e4bcf8b4510963354315f5
    const expected_root = [_]u8{ 0xdc, 0x36, 0x19, 0xcb, 0xbc, 0x5e, 0xf0, 0xe0, 0xa3, 0xb3, 0x8e, 0x3c, 0xa5, 0xd3, 0x1c, 0x2b, 0x16, 0x86, 0x8e, 0xac, 0xb6, 0xe4, 0xbc, 0xf8, 0xb4, 0x51, 0x09, 0x63, 0x35, 0x43, 0x15, 0xf5 };
    try std.testing.expectEqualSlices(u8, &expected_root, &hash_root);
}
