const std = @import("std");
const Allocator = std.mem.Allocator;
const hashing = @import("hashing");
const Depth = hashing.Depth;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const isBasicType = @import("../type/type_kind.zig").isBasicType;
const FixedContainerType = @import("../type/container.zig").FixedContainerType;
const UintType = @import("../type/uint.zig").UintType;
const ByteVectorType = @import("../type/byte_vector.zig").ByteVectorType;
const FixedVectorType = @import("../type/vector.zig").FixedVectorType;

const type_root = @import("../type/root.zig");
const chunkDepth = type_root.chunkDepth;

const tree_view_root = @import("root.zig");
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
        /// required fields are delegated to BasicPackedChunks: pool, root
        allocator: Allocator,
        chunks: Chunks,

        pub const SszType = ST;
        pub const Element = *ST.Element.TreeView;
        pub const length = ST.length;

        const Self = @This();

        const base_chunk_depth: Depth = @intCast(ST.chunk_depth);
        const chunk_depth: Depth = chunkDepth(Depth, base_chunk_depth, ST);
        const Chunks = CompositeChunks(ST, chunk_depth);

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !*Self {
            const ptr = try allocator.create(Self);
            try Chunks.init(&ptr.chunks, allocator, pool, root);
            ptr.allocator = allocator;
            return ptr;
        }

        pub fn deinit(self: *Self) void {
            self.chunks.deinit();
            self.allocator.destroy(self);
        }

        pub fn commit(self: *Self) !void {
            try self.chunks.commit();
        }

        pub fn clearCache(self: *Self) void {
            self.chunks.clearCache();
        }

        pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void {
            try self.commit();
            out.* = self.chunks.root.getRoot(self.chunks.pool).*;
        }

        pub fn getRoot(self: *const Self) Node.Id {
            return self.chunks.root;
        }

        pub fn get(self: *Self, index: usize) !Element {
            if (index >= length) return error.IndexOutOfBounds;
            return self.chunks.get(index);
        }

        pub fn getReadonly(self: *Self, index: usize) !Element {
            // TODO: Implement read-only access after other PRs land.
            _ = self;
            _ = index;
            return error.NotImplemented;
        }

        pub fn set(self: *Self, index: usize, value: Element) !void {
            if (index >= length) return error.IndexOutOfBounds;
            try self.chunks.set(index, value);
        }

        pub fn getAllReadonly(self: *Self, allocator: Allocator) ![]Element {
            // TODO: Implement bulk read-only access after other PRs land.
            _ = self;
            _ = allocator;
            return error.NotImplemented;
        }
    };
}

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
    try Inner.tree.toValue(e0_view.getRoot(), &pool, &e0_value);
    try std.testing.expectEqual(@as(u32, 1), e0_value.a);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 1, 1, 1 }, e0_value.b[0..]);

    const replacement: Inner.Type = .{ .a = 9, .b = [_]u8{ 9, 9, 9, 9 } };
    const replacement_root = try Inner.tree.fromValue(&pool, &replacement);
    var replacement_view: ?*Inner.TreeView = try Inner.TreeView.init(allocator, &pool, replacement_root);
    defer if (replacement_view) |v| v.deinit();
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
    try VectorType.tree.toValue(view.getRoot(), &pool, &roundtrip);
    try std.testing.expectEqual(@as(u32, 1), roundtrip[0].a);
    try std.testing.expectEqual(@as(u32, 9), roundtrip[1].a);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 9, 9, 9, 9 }, roundtrip[1].b[0..]);
}
