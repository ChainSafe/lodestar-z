const std = @import("std");
const Allocator = std.mem.Allocator;
const hashing = @import("hashing");
const Depth = hashing.Depth;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const isBasicType = @import("../type/type_kind.zig").isBasicType;

const type_root = @import("../type/root.zig");
const itemsPerChunk = type_root.itemsPerChunk;
const chunkDepth = type_root.chunkDepth;

const BaseTreeView = @import("root.zig").BaseTreeView;
const BasicPackedChunks = @import("chunks.zig").BasicPackedChunks;

/// A specialized tree view for SSZ vector types with basic element types.
/// Elements are packed into chunks (multiple elements per leaf node).
pub fn ArrayBasicTreeView(comptime ST: type) type {
    comptime {
        if (ST.kind != .vector) {
            @compileError("ArrayBasicTreeView can only be used with Vector types");
        }
        if (!@hasDecl(ST, "Element") or !isBasicType(ST.Element)) {
            @compileError("ArrayBasicTreeView can only be used with Vector of basic element types");
        }
    }

    return struct {
        base_view: BaseTreeView,

        pub const SszType = ST;
        pub const Element = ST.Element.Type;
        pub const length = ST.length;

        const Self = @This();

        const base_chunk_depth: Depth = @intCast(ST.chunk_depth);
        const chunk_depth: Depth = chunkDepth(Depth, base_chunk_depth, ST);
        const items_per_chunk: usize = itemsPerChunk(ST.Element);
        const Chunks = BasicPackedChunks(ST, chunk_depth, items_per_chunk);

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !Self {
            return Self{
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

        pub fn get(self: *Self, index: usize) !Element {
            if (index >= length) return error.IndexOutOfBounds;
            return try Chunks.get(&self.base_view, index);
        }

        pub fn set(self: *Self, index: usize, value: Element) !void {
            if (index >= length) return error.IndexOutOfBounds;
            try Chunks.set(&self.base_view, index, value);
        }

        pub fn getAll(self: *Self, allocator: Allocator) ![]Element {
            return try Chunks.getAll(&self.base_view, allocator, length);
        }

        pub fn getAllInto(self: *Self, values: []Element) ![]Element {
            return try Chunks.getAllInto(&self.base_view, length, values);
        }

        /// Serialize the tree view into a provided buffer.
        /// Returns the number of bytes written.
        pub fn serializeIntoBytes(self: *Self, out: []u8) !usize {
            try self.commit();
            return try ST.tree.serializeIntoBytes(self.base_view.data.root, self.base_view.pool, out);
        }

        /// Get the serialized size of this tree view.
        pub fn serializedSize(_: *Self) usize {
            return ST.fixed_size;
        }

        pub fn toValue(self: *Self, _: Allocator, out: *ST.Type) !void {
            try self.commit();
            try ST.tree.toValue(self.base_view.data.root, self.base_view.pool, out);
        }
    };
}

const UintType = @import("../type/uint.zig").UintType;
const FixedVectorType = @import("../type/vector.zig").FixedVectorType;

test "TreeView vector element roundtrip" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 128);
    defer pool.deinit();

    const Uint64 = UintType(64);
    const VectorType = FixedVectorType(Uint64, 4);

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

    const actual_root = try view.hashTreeRoot();

    try std.testing.expectEqualSlices(u8, &expected_root, actual_root);

    var roundtrip: VectorType.Type = undefined;
    try VectorType.tree.toValue(view.base_view.data.root, &pool, &roundtrip);
    try std.testing.expectEqualSlices(u64, &expected, &roundtrip);
}

test "TreeView vector getAll fills provided buffer" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = UintType(32);
    const VectorType = FixedVectorType(Uint32, 8);

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

    const Uint16 = UintType(16);
    const VectorType = FixedVectorType(Uint16, 5);
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

    const Uint32 = UintType(32);
    const VectorType = FixedVectorType(Uint32, 6);
    var values = [_]u32{ 10, 20, 30, 40, 50, 60 };

    const root_node = try VectorType.tree.fromValue(&pool, &values);
    var view = try VectorType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    const first = try view.getAll(allocator);
    defer allocator.free(first);
    try std.testing.expectEqualSlices(u32, values[0..], first);

    try view.set(3, 99);

    try view.commit();
    const second = try view.getAll(allocator);
    defer allocator.free(second);
    values[3] = 99;
    try std.testing.expectEqualSlices(u32, values[0..], second);
}

test "TreeView vector clone isolates subsequent updates" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const Uint16 = UintType(16);
    const Vec4 = FixedVectorType(Uint16, 4);

    const value: Vec4.Type = [_]u16{ 0, 0, 0, 0 };
    const root = try Vec4.tree.fromValue(&pool, &value);

    var v1 = try Vec4.TreeView.init(allocator, &pool, root);
    defer v1.deinit();

    var v2 = try v1.clone(.{});
    defer v2.deinit();

    try v2.set(1, @as(u16, 9));
    try v2.commit();

    try std.testing.expectEqual(@as(u16, 0), try v1.get(1));
    try std.testing.expectEqual(@as(u16, 9), try v2.get(1));
}

test "TreeView vector clone reads committed state" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const Uint16 = UintType(16);
    const Vec4 = FixedVectorType(Uint16, 4);

    const value: Vec4.Type = [_]u16{ 0, 0, 0, 0 };
    const root = try Vec4.tree.fromValue(&pool, &value);

    var v1 = try Vec4.TreeView.init(allocator, &pool, root);
    defer v1.deinit();

    try v1.set(2, @as(u16, 7));
    try v1.commit();

    var v2 = try v1.clone(.{});
    defer v2.deinit();

    try std.testing.expectEqual(@as(u16, 7), try v2.get(2));
}

test "TreeView vector clone drops uncommitted changes" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const Uint16 = UintType(16);
    const Vec4 = FixedVectorType(Uint16, 4);

    const value: Vec4.Type = [_]u16{ 1, 2, 3, 4 };
    const root = try Vec4.tree.fromValue(&pool, &value);

    var v = try Vec4.TreeView.init(allocator, &pool, root);
    defer v.deinit();

    try v.set(0, @as(u16, 9));
    try std.testing.expectEqual(@as(u16, 9), try v.get(0));

    var dropped = try v.clone(.{});
    defer dropped.deinit();

    try std.testing.expectEqual(@as(u16, 1), try v.get(0));
    try std.testing.expectEqual(@as(u16, 1), try dropped.get(0));
}

test "TreeView vector clone(true) does not transfer cache" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const Uint16 = UintType(16);
    const Vec4 = FixedVectorType(Uint16, 4);

    const value: Vec4.Type = [_]u16{ 1, 2, 3, 4 };
    const root = try Vec4.tree.fromValue(&pool, &value);

    var v = try Vec4.TreeView.init(allocator, &pool, root);
    defer v.deinit();

    _ = try v.get(0);
    try std.testing.expect(v.base_view.data.children_nodes.count() > 0);

    var cloned_no_cache = try v.clone(.{ .transfer_cache = false });
    defer cloned_no_cache.deinit();

    try std.testing.expect(v.base_view.data.children_nodes.count() > 0);
    try std.testing.expectEqual(@as(usize, 0), cloned_no_cache.base_view.data.children_nodes.count());
}

test "TreeView vector clone(false) transfers cache and clears source" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const Uint16 = UintType(16);
    const Vec4 = FixedVectorType(Uint16, 4);

    const value: Vec4.Type = [_]u16{ 1, 2, 3, 4 };
    const root = try Vec4.tree.fromValue(&pool, &value);

    var v = try Vec4.TreeView.init(allocator, &pool, root);
    defer v.deinit();

    _ = try v.get(0);
    try std.testing.expect(v.base_view.data.children_nodes.count() > 0);

    var cloned = try v.clone(.{});
    defer cloned.deinit();

    try std.testing.expectEqual(@as(usize, 0), v.base_view.data.children_nodes.count());
    try std.testing.expect(cloned.base_view.data.children_nodes.count() > 0);
}

// Tests ported from TypeScript ssz packages/ssz/test/unit/byType/vector/tree.test.ts
test "ArrayBasicTreeView - serialize (uint64 vector)" {
    const allocator = std.testing.allocator;

    const Uint64 = UintType(64);
    const VecU64Type = FixedVectorType(Uint64, 4);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const TestCase = struct {
        id: []const u8,
        values: [4]u64,
        expected_serialized: []const u8,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "4 values",
            .values = [4]u64{ 100000, 200000, 300000, 400000 },
            // 0xa086010000000000400d030000000000e093040000000000801a060000000000
            .expected_serialized = &[_]u8{ 0xa0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x0d, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x93, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x1a, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00 },
            // For VectorBasic, the root is the same as the serialized bytes (fits in one chunk)
            .expected_root = [_]u8{ 0xa0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x0d, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x93, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x1a, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00 },
        },
    };

    for (test_cases) |tc| {
        const value = tc.values;

        var value_serialized: [VecU64Type.fixed_size]u8 = undefined;
        _ = VecU64Type.serializeIntoBytes(&value, &value_serialized);

        const tree_node = try VecU64Type.tree.fromValue(&pool, &value);
        var view = try VecU64Type.TreeView.init(allocator, &pool, tree_node);
        defer view.deinit();

        var view_serialized: [VecU64Type.fixed_size]u8 = undefined;
        const written = try view.serializeIntoBytes(&view_serialized);
        try std.testing.expectEqual(view_serialized.len, written);

        try std.testing.expectEqualSlices(u8, tc.expected_serialized, &view_serialized);
        try std.testing.expectEqualSlices(u8, &value_serialized, &view_serialized);

        const view_size = view.serializedSize();
        try std.testing.expectEqual(tc.expected_serialized.len, view_size);

        const hash_root = try view.hashTreeRoot();
        try std.testing.expectEqualSlices(u8, &tc.expected_root, hash_root);
    }
}

test "ArrayBasicTreeView - serialize (uint8 vector)" {
    const allocator = std.testing.allocator;

    const Uint8 = UintType(8);
    const VecU8Type = FixedVectorType(Uint8, 8);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const value = [8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };

    var value_serialized: [VecU8Type.fixed_size]u8 = undefined;
    _ = VecU8Type.serializeIntoBytes(&value, &value_serialized);

    const tree_node = try VecU8Type.tree.fromValue(&pool, &value);
    var view = try VecU8Type.TreeView.init(allocator, &pool, tree_node);
    defer view.deinit();

    var view_serialized: [VecU8Type.fixed_size]u8 = undefined;
    const written = try view.serializeIntoBytes(&view_serialized);
    try std.testing.expectEqual(view_serialized.len, written);

    try std.testing.expectEqualSlices(u8, &value, &view_serialized);

    const view_size = view.serializedSize();
    try std.testing.expectEqual(@as(usize, 8), view_size);
}

test "ArrayBasicTreeView - get and set" {
    const allocator = std.testing.allocator;

    const Uint64 = UintType(64);
    const VecU64Type = FixedVectorType(Uint64, 4);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const value = [4]u64{ 100, 200, 300, 400 };
    const tree_node = try VecU64Type.tree.fromValue(&pool, &value);
    var view = try VecU64Type.TreeView.init(allocator, &pool, tree_node);
    defer view.deinit();

    try std.testing.expectEqual(@as(u64, 100), try view.get(0));
    try std.testing.expectEqual(@as(u64, 200), try view.get(1));
    try std.testing.expectEqual(@as(u64, 300), try view.get(2));
    try std.testing.expectEqual(@as(u64, 400), try view.get(3));

    try view.set(1, 999);
    try std.testing.expectEqual(@as(u64, 999), try view.get(1));

    var serialized: [VecU64Type.fixed_size]u8 = undefined;
    const written = try view.serializeIntoBytes(&serialized);
    try std.testing.expectEqual(serialized.len, written);

    const expected = [4]u64{ 100, 999, 300, 400 };
    var expected_serialized: [VecU64Type.fixed_size]u8 = undefined;
    _ = VecU64Type.serializeIntoBytes(&expected, &expected_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &serialized);
}
