const std = @import("std");
const Allocator = std.mem.Allocator;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const isBasicType = @import("../type/type_kind.zig").isBasicType;
const isFixedType = @import("../type/type_kind.zig").isFixedType;
const tree_view_root = @import("root.zig");
const TreeViewData = tree_view_root.TreeViewData;
const BaseTreeView = tree_view_root.BaseTreeView;

/// A specialized tree view for SSZ container types, enabling efficient access and modification of container fields, given a backing merkle tree.
///
/// This struct wraps a `BaseTreeView` and provides methods to get and set fields by name.
///
/// For basic-type fields, it returns or accepts values directly; for complex fields, it returns or accepts corresponding tree views.
pub fn ContainerTreeView(comptime ST: type) type {
    return struct {
        base_view: BaseTreeView,

        pub const SszType = ST;

        const Self = @This();

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !Self {
            return .{
                .base_view = try BaseTreeView.init(allocator, pool, root),
            };
        }

        pub fn clone(self: *Self, opts: BaseTreeView.CloneOpts) !Self {
            return Self{ .base_view = try self.base_view.clone(opts) };
        }

        pub fn deinit(self: *Self) void {
            self.base_view.deinit();
        }

        pub fn commit(self: *Self) !void {
            try self.base_view.commit();
        }

        /// Return the root hash of the tree.
        /// The returned array is owned by the internal pool and must not be modified.
        pub fn hashTreeRoot(self: *Self) !*const [32]u8 {
            return try self.base_view.hashTreeRoot();
        }

        pub fn Field(comptime field_name: []const u8) type {
            comptime {
                @setEvalBranchQuota(20000);
            }
            const ChildST = ST.getFieldType(field_name);
            if (comptime isBasicType(ChildST)) {
                return ChildST.Type;
            } else {
                return ChildST.TreeView;
            }
        }

        pub fn FieldValue(comptime field_name: []const u8) type {
            const ChildST = ST.getFieldType(field_name);
            return ChildST.Type;
        }

        pub fn getGindex(comptime field_name: []const u8) Gindex {
            const field_index = comptime ST.getFieldIndex(field_name);
            return Gindex.fromDepth(ST.chunk_depth, field_index);
        }

        pub fn getRootNode(self: *Self, comptime field_name: []const u8) !Node.Id {
            const field_gindex = Self.getGindex(field_name);
            return try self.base_view.getChildNode(field_gindex);
        }

        pub fn setRootNode(self: *Self, comptime field_name: []const u8, root: Node.Id) !void {
            const field_gindex = Self.getGindex(field_name);
            return try self.base_view.setChildNode(field_gindex, root);
        }

        pub fn getRoot(self: *Self, comptime field_name: []const u8) !*const [32]u8 {
            const field_node = try self.getRootNode(field_name);
            return field_node.getRoot(self.base_view.pool);
        }

        /// Get a field by name. If the field is a basic type, returns the value directly.
        /// Caller borrows a copy of the value so there is no need to deinit it.
        pub fn get(self: *Self, comptime field_name: []const u8) !Field(field_name) {
            comptime {
                @setEvalBranchQuota(20000);
            }
            const field_index = comptime ST.getFieldIndex(field_name);
            const ChildST = ST.getFieldType(field_name);
            const child_gindex = Gindex.fromDepth(ST.chunk_depth, field_index);
            if (comptime isBasicType(ChildST)) {
                var value: ChildST.Type = undefined;
                const child_node = try self.base_view.getChildNode(child_gindex);
                try ChildST.tree.toValue(child_node, self.base_view.pool, &value);
                return value;
            } else {
                const child_data = try self.base_view.getChildData(child_gindex);

                return .{
                    .base_view = .{
                        .allocator = self.base_view.allocator,
                        .pool = self.base_view.pool,
                        .data = child_data,
                    },
                };
            }
        }

        pub fn getValue(self: *Self, allocator: Allocator, comptime field_name: []const u8) !FieldValue(field_name) {
            const ChildST = ST.getFieldType(field_name);
            if (comptime isBasicType(ChildST)) {
                return self.get(field_name);
            }

            var child_view = try self.get(field_name);
            var out = ChildST.default_value;
            if (comptime isFixedType(ChildST)) {
                try child_view.toValue(&out);
            } else {
                try child_view.toValue(allocator, &out);
            }
            return out;
        }

        /// Set a field by name. If the field is a basic type, pass the value directly.
        /// If the field is a complex type, pass a TreeView of the corresponding type.
        /// The caller transfers ownership of the `value` TreeView to this parent view.
        /// The existing TreeView, if any, will be deinited by this function.
        pub fn set(self: *Self, comptime field_name: []const u8, value: Field(field_name)) !void {
            comptime {
                @setEvalBranchQuota(20000);
            }
            const field_index = comptime ST.getFieldIndex(field_name);
            const ChildST = ST.getFieldType(field_name);
            const child_gindex = Gindex.fromDepth(ST.chunk_depth, field_index);
            if (comptime isBasicType(ChildST)) {
                try self.base_view.setChildNode(
                    child_gindex,
                    try ChildST.tree.fromValue(
                        self.base_view.pool,
                        &value,
                    ),
                );
            } else {
                try self.base_view.setChildData(child_gindex, value.base_view.data);
            }
        }

        /// Serialize the tree view into a provided buffer.
        /// Returns the number of bytes written.
        pub fn serializeIntoBytes(self: *Self, out: []u8) !usize {
            try self.commit();
            return try ST.tree.serializeIntoBytes(self.base_view.data.root, self.base_view.pool, out);
        }

        /// Get the serialized size of this tree view.
        pub fn serializedSize(self: *Self) !usize {
            try self.commit();
            if (comptime isFixedType(ST)) {
                return ST.fixed_size;
            } else {
                return try ST.tree.serializedSize(self.base_view.data.root, self.base_view.pool);
            }
        }

        pub fn deserialize(allocator: Allocator, pool: *Node.Pool, bytes: []const u8) !Self {
            const root = try ST.tree.deserializeFromBytes(pool, bytes);
            return try Self.init(allocator, pool, root);
        }

        pub fn fromValue(allocator: Allocator, pool: *Node.Pool, value: *const ST.Type) !Self {
            const root = try ST.tree.fromValue(pool, value);
            errdefer pool.unref(root);
            return try Self.init(allocator, pool, root);
        }

        pub fn toValue(self: *Self, allocator: Allocator, out: *ST.Type) !void {
            try self.commit();
            if (comptime isFixedType(ST)) {
                try ST.tree.toValue(self.base_view.data.root, self.base_view.pool, out);
            } else {
                try ST.tree.toValue(allocator, self.base_view.data.root, self.base_view.pool, out);
            }
        }

        pub fn setValue(self: *Self, comptime field_name: []const u8, value: *const FieldValue(field_name)) !void {
            const ChildST = ST.getFieldType(field_name);
            if (comptime isBasicType(ChildST)) {
                try self.set(field_name, value.*);
            } else {
                const root = try ChildST.tree.fromValue(self.base_view.pool, value);
                errdefer self.base_view.pool.unref(root);
                const child_view = try ChildST.TreeView.init(
                    self.base_view.allocator,
                    self.base_view.pool,
                    root,
                );
                try self.set(field_name, child_view);
            }
        }
    };
}

const FixedContainerType = @import("../type/container.zig").FixedContainerType;
const VariableContainerType = @import("../type/container.zig").VariableContainerType;
const UintType = @import("../type/uint.zig").UintType;
const ByteVectorType = @import("../type/byte_vector.zig").ByteVectorType;
const ByteListType = @import("../type/byte_list.zig").ByteListType;
const FixedListType = @import("../type/list.zig").FixedListType;
const VariableListType = @import("../type/list.zig").VariableListType;
const FixedVectorType = @import("../type/vector.zig").FixedVectorType;

const Checkpoint = FixedContainerType(struct {
    epoch: UintType(64),
    root: ByteVectorType(32),
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
    const RootView = Checkpoint.TreeView.Field("root");
    try RootView.SszType.tree.toValue(root_view.base_view.data.root, &pool, root[0..]);
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
    try RootView.SszType.tree.toValue(root_view.base_view.data.root, &pool, root[0..]);
    try std.testing.expectEqualSlices(u8, ([_]u8{2} ** 32)[0..], root[0..]);

    // commit and check hash_tree_root
    try cp_view.commit();
    var htr_from_value: [32]u8 = undefined;
    const expected_checkpoint: Checkpoint.Type = .{
        .epoch = 100,
        .root = [_]u8{2} ** 32,
    };
    try Checkpoint.hashTreeRoot(&expected_checkpoint, &htr_from_value);

    const htr_from_tree = try cp_view.hashTreeRoot();
    try std.testing.expectEqualSlices(u8, &htr_from_value, htr_from_tree);
}

test "TreeView container nested types set/get/commit" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 2048);
    defer pool.deinit();

    const Uint16 = UintType(16);
    const Uint32 = UintType(32);
    const Uint64 = UintType(64);

    const Bytes = ByteListType(16);
    const BasicVec = FixedVectorType(Uint16, 4);

    const InnerFixed = FixedContainerType(struct {
        a: Uint32,
        b: ByteVectorType(4),
    });
    const CompVec = FixedVectorType(InnerFixed, 2);

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
        try bytes_view.commit();

        const all = try bytes_view.getAll(allocator);
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
        try basic_vec_view.commit();

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
        var e0_view: ?InnerFixed.TreeView = try InnerFixed.TreeView.init(allocator, &pool, e0_root);
        defer if (e0_view) |*v| v.deinit();
        try comp_vec_view.set(0, e0_view.?);
        e0_view = null;

        const e1: InnerFixed.Type = .{ .a = 22, .b = [_]u8{ 4, 3, 2, 1 } };
        const e1_root = try InnerFixed.tree.fromValue(&pool, &e1);
        var e1_view: ?InnerFixed.TreeView = try InnerFixed.TreeView.init(allocator, &pool, e1_root);
        defer if (e1_view) |*v| v.deinit();
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
        var inner_view: ?InnerVar.TreeView = try InnerVar.TreeView.init(allocator, &pool, inner_root);
        defer if (inner_view) |*v| v.deinit();
        const inner = &inner_view.?;

        try inner.set("id", @as(u32, 99));

        var payload_value: InnerVar.TreeView.Field("payload").SszType.Type = InnerVar.TreeView.Field("payload").SszType.default_value;
        defer payload_value.deinit(allocator);
        const payload_root = try InnerVar.TreeView.Field("payload").SszType.tree.fromValue(&pool, &payload_value);
        var payload_view = try InnerVar.TreeView.Field("payload").init(allocator, &pool, payload_root);
        try payload_view.push(@as(u8, 0x5A));
        try inner.set("payload", payload_view);

        try comp_list_view.push(inner_view.?);
        inner_view = null;

        try view.set("comp_list", comp_list_view);
    }

    try view.commit();

    var roundtrip: Outer.Type = Outer.default_value;
    defer Outer.deinit(allocator, &roundtrip);
    try Outer.tree.toValue(allocator, view.base_view.data.root, &pool, &roundtrip);

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
    var pool = try Node.Pool.init(allocator, 1024);
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
    var pool = try Node.Pool.init(allocator, 1024);
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

test "TreeView container clone(true) does not transfer cache" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1024);
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
    try std.testing.expect(v.base_view.data.children_nodes.count() > 0);

    var cloned_no_cache = try v.clone(.{ .transfer_cache = false });
    defer cloned_no_cache.deinit();

    try std.testing.expect(v.base_view.data.children_nodes.count() > 0);
    try std.testing.expectEqual(@as(usize, 0), cloned_no_cache.base_view.data.children_nodes.count());
}

test "TreeView container clone(false) transfers cache and clears source" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1024);
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
    try std.testing.expect(v.base_view.data.children_nodes.count() > 0);

    var cloned = try v.clone(.{});
    defer cloned.deinit();

    try std.testing.expectEqual(@as(usize, 0), v.base_view.data.children_nodes.count());
    try std.testing.expect(cloned.base_view.data.children_nodes.count() > 0);
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

    var pool = try Node.Pool.init(allocator, 1024);
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

        const hash_root = try view.hashTreeRoot();
        try std.testing.expectEqualSlices(u8, &tc.expected_root, hash_root);
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

    var pool = try Node.Pool.init(allocator, 1024);
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
    const ListU64 = FixedListType(Uint64, 128);
    const TestContainer = VariableContainerType(struct {
        a: FixedListType(UintType(64), 128),
        b: UintType(64),
    });
    _ = ListU64;

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    var value: TestContainer.Type = .{
        .a = FixedListType(UintType(64), 128).default_value,
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

    // 0xdc3619cbbc5ef0e0a3b38e3ca5d31c2b16868eacb6e4bcf8b4510963354315f5
    const expected_root = [_]u8{ 0xdc, 0x36, 0x19, 0xcb, 0xbc, 0x5e, 0xf0, 0xe0, 0xa3, 0xb3, 0x8e, 0x3c, 0xa5, 0xd3, 0x1c, 0x2b, 0x16, 0x86, 0x8e, 0xac, 0xb6, 0xe4, 0xbc, 0xf8, 0xb4, 0x51, 0x09, 0x63, 0x35, 0x43, 0x15, 0xf5 };
    const hash_root = try view.hashTreeRoot();
    try std.testing.expectEqualSlices(u8, &expected_root, hash_root);
}
