const std = @import("std");
const Allocator = std.mem.Allocator;
const hashing = @import("hashing");
const Depth = hashing.Depth;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const isBasicType = @import("../type/type_kind.zig").isBasicType;
const isFixedType = @import("../type/type_kind.zig").isFixedType;

const type_root = @import("../type/root.zig");
const chunkDepth = type_root.chunkDepth;

const tree_view_root = @import("root.zig");
const BaseTreeView = tree_view_root.BaseTreeView;
const CompositeChunks = @import("chunks.zig").CompositeChunks;

/// A specialized tree view for SSZ vector types with composite element types.
/// Each element occupies its own subtree.
pub fn ArrayCompositeTreeView(comptime ST: type) type {
    comptime {
        if (ST.kind != .vector) {
            @compileError("ArrayCompositeTreeView can only be used with Vector types");
        }
        if (!@hasDecl(ST, "Element") or isBasicType(ST.Element)) {
            @compileError("ArrayCompositeTreeView can only be used with Vector of composite element types");
        }
    }

    return struct {
        base_view: BaseTreeView,

        pub const SszType = ST;
        pub const Element = ST.Element.TreeView;
        pub const length = ST.length;

        const Self = @This();

        const base_chunk_depth: Depth = @intCast(ST.chunk_depth);
        const chunk_depth: Depth = chunkDepth(Depth, base_chunk_depth, ST);
        const Chunks = CompositeChunks(ST, chunk_depth);

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

        pub fn clearCache(self: *Self) void {
            self.base_view.clearCache();
        }

        /// Return the root hash of the tree.
        /// The returned array is owned by the internal pool and must not be modified.
        pub fn hashTreeRoot(self: *Self) !*const [32]u8 {
            return try self.base_view.hashTreeRoot();
        }

        pub fn getRoot(self: *Self, index: usize) !*const [32]u8 {
            if (index >= length) return error.IndexOutOfBounds;
            const field_node = try self.base_view.getChildNode(Gindex.fromDepth(chunk_depth, index));
            return field_node.getRoot(self.base_view.pool);
        }

        pub fn get(self: *Self, index: usize) !Element {
            if (index >= length) return error.IndexOutOfBounds;
            return try Chunks.get(&self.base_view, index);
        }

        pub fn getReadonly(self: *Self, index: usize) !Element {
            // TODO: Implement read-only access after other PRs land.
            _ = self;
            _ = index;
            return error.NotImplemented;
        }

        pub fn set(self: *Self, index: usize, value: Element) !void {
            if (index >= length) return error.IndexOutOfBounds;
            try Chunks.set(&self.base_view, index, value);
        }

        pub fn setValue(self: *Self, index: usize, value: *const ST.Element.Type) !void {
            const root = try ST.Element.tree.fromValue(self.base_view.pool, value);
            errdefer self.base_view.pool.unref(root);
            const child_view = try ST.Element.TreeView.init(
                self.base_view.allocator,
                self.base_view.pool,
                root,
            );
            try self.set(index, child_view);
        }

        pub fn getAllReadonly(self: *Self, allocator: Allocator) ![]Element {
            // TODO: Implement bulk read-only access after other PRs land.
            _ = self;
            _ = allocator;
            return error.NotImplemented;
        }

        /// Get all element values in a single traversal.
        ///
        /// WARNING: Returns all committed changes. If there are any pending changes,
        /// commit them beforehand.
        ///
        /// Caller owns the returned slice and must free it with the same allocator.
        pub fn getAllReadonlyValues(self: *Self, allocator: Allocator) ![]ST.Element.Type {
            return try Chunks.getAllValues(&self.base_view, allocator, length);
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
    };
}

const UintType = @import("../type/uint.zig").UintType;
const FixedVectorType = @import("../type/vector.zig").FixedVectorType;
const FixedContainerType = @import("../type/container.zig").FixedContainerType;
const ByteVectorType = @import("../type/byte_vector.zig").ByteVectorType;

test "TreeView vector composite element set/get/commit" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    const Uint32 = UintType(32);
    const Inner = FixedContainerType(struct {
        a: Uint32,
        b: ByteVectorType(4),
    });
    const VectorType = FixedVectorType(Inner, 2);

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

    const actual_root = try view.hashTreeRoot();

    var expected: VectorType.Type = .{ v0, replacement };
    var expected_root: [32]u8 = undefined;
    try VectorType.hashTreeRoot(&expected, &expected_root);
    try std.testing.expectEqualSlices(u8, &expected_root, actual_root);

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

    const Inner = FixedContainerType(struct { x: UintType(64) });
    const VectorType = FixedVectorType(Inner, 2);
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

    const Uint32 = UintType(32);
    const InnerVec = FixedVectorType(Uint32, 2);
    const Inner = FixedContainerType(struct {
        id: Uint32,
        vec: InnerVec,
    });
    const VectorType = FixedVectorType(Inner, 2);

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

    const actual_root = try view.hashTreeRoot();

    var expected: VectorType.Type = .{ replacement, v1 };
    var expected_root: [32]u8 = undefined;
    try VectorType.hashTreeRoot(&expected, &expected_root);
    try std.testing.expectEqualSlices(u8, &expected_root, actual_root);
}

test "TreeView vector composite clone isolates updates" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const Uint32 = UintType(32);
    const Inner = FixedContainerType(struct { a: Uint32 });
    const VectorType = FixedVectorType(Inner, 2);

    const original: VectorType.Type = .{ .{ .a = 1 }, .{ .a = 2 } };
    const root = try VectorType.tree.fromValue(&pool, &original);

    var v1 = try VectorType.TreeView.init(allocator, &pool, root);
    defer v1.deinit();

    var v2 = try v1.clone(.{});
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

    const Uint32 = UintType(32);
    const Inner = FixedContainerType(struct { a: Uint32 });
    const VectorType = FixedVectorType(Inner, 2);

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

    var v2 = try v1.clone(.{});
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

    const Uint32 = UintType(32);
    const Inner = FixedContainerType(struct { a: Uint32 });
    const VectorType = FixedVectorType(Inner, 2);

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

    var dropped = try v.clone(.{});
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

    const Uint32 = UintType(32);
    const Inner = FixedContainerType(struct {
        a: Uint32,
    });
    const VectorType = FixedVectorType(Inner, 2);

    const original: VectorType.Type = .{ .{ .a = 1 }, .{ .a = 2 } };
    const root_node = try VectorType.tree.fromValue(&pool, &original);
    var view = try VectorType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    _ = try view.get(0);
    try view.commit();

    try std.testing.expect(view.base_view.data.children_data.count() > 0);

    var cloned_no_cache = try view.clone(.{ .transfer_cache = false });
    defer cloned_no_cache.deinit();

    try std.testing.expect(view.base_view.data.children_data.count() > 0);
    try std.testing.expectEqual(@as(usize, 0), cloned_no_cache.base_view.data.children_data.count());
}

test "TreeView vector composite clone(false) transfers cache and clears source" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    const Uint32 = UintType(32);
    const Inner = FixedContainerType(struct {
        a: Uint32,
    });
    const VectorType = FixedVectorType(Inner, 2);

    const original: VectorType.Type = .{ .{ .a = 1 }, .{ .a = 2 } };
    const root_node = try VectorType.tree.fromValue(&pool, &original);
    var view = try VectorType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    _ = try view.get(0);
    try view.commit();

    try std.testing.expect(view.base_view.data.children_data.count() > 0);

    var cloned = try view.clone(.{});
    defer cloned.deinit();

    try std.testing.expectEqual(@as(usize, 0), view.base_view.data.children_data.count());
    try std.testing.expect(cloned.base_view.data.children_data.count() > 0);
}

// Tests ported from TypeScript ssz packages/ssz/test/unit/byType/vector/tree.test.ts
test "ArrayCompositeTreeView - serialize (ByteVector32 vector)" {
    const allocator = std.testing.allocator;

    const Root32 = ByteVectorType(32);
    const VecRootsType = FixedVectorType(Root32, 4);

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

    const Uint64 = UintType(64);
    const TestContainer = FixedContainerType(struct {
        a: UintType(64),
        b: UintType(64),
    });
    _ = Uint64;
    const VecContainerType = FixedVectorType(TestContainer, 4);

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

    const actual_root = try view.hashTreeRoot();
    // 0xb1a797eb50654748ba239010edccea7b46b55bf740730b700684f48b0c478372
    const expected_root = [_]u8{ 0xb1, 0xa7, 0x97, 0xeb, 0x50, 0x65, 0x47, 0x48, 0xba, 0x23, 0x90, 0x10, 0xed, 0xcc, 0xea, 0x7b, 0x46, 0xb5, 0x5b, 0xf7, 0x40, 0x73, 0x0b, 0x70, 0x06, 0x84, 0xf4, 0x8b, 0x0c, 0x47, 0x83, 0x72 };
    try std.testing.expectEqualSlices(u8, &expected_root, actual_root);
}

test "ArrayCompositeTreeView - get and set" {
    const allocator = std.testing.allocator;

    const Root32 = ByteVectorType(32);
    const VecRootsType = FixedVectorType(Root32, 4);

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
    var bytes0: [Root32.fixed_size]u8 = undefined;
    const bytes0_written = try elem0.serializeIntoBytes(&bytes0);
    try std.testing.expectEqual(bytes0.len, bytes0_written);
    try std.testing.expectEqualSlices(u8, &value[0], &bytes0);

    const new_val = [_]u8{0xff} ** 32;
    const new_node = try Root32.tree.fromValue(&pool, &new_val);
    const new_elem = try Root32.TreeView.init(allocator, &pool, new_node);
    try view.set(1, new_elem);

    var elem1 = try view.get(1);
    var bytes1: [Root32.fixed_size]u8 = undefined;
    const bytes1_written = try elem1.serializeIntoBytes(&bytes1);
    try std.testing.expectEqual(bytes1.len, bytes1_written);
    try std.testing.expectEqualSlices(u8, &new_val, &bytes1);
}
