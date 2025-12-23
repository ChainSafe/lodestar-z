const std = @import("std");
const Allocator = std.mem.Allocator;
const hashing = @import("hashing");
const Depth = hashing.Depth;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const isBasicType = @import("../type/type_kind.zig").isBasicType;
const UintType = @import("../type/uint.zig").UintType;
const FixedVectorType = @import("../type/vector.zig").FixedVectorType;

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
        /// required fields are delegated to BasicPackedChunks: pool, root
        allocator: Allocator,
        chunks: Chunks,

        pub const SszType = ST;
        pub const Element = ST.Element.Type;
        pub const length = ST.length;

        const Self = @This();

        const base_chunk_depth: Depth = @intCast(ST.chunk_depth);
        const chunk_depth: Depth = chunkDepth(Depth, base_chunk_depth, ST);
        const items_per_chunk: usize = itemsPerChunk(ST.Element);
        const Chunks = BasicPackedChunks(ST, chunk_depth, items_per_chunk);

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

        pub fn set(self: *Self, index: usize, value: Element) !void {
            if (index >= length) return error.IndexOutOfBounds;
            try self.chunks.set(index, value);
        }

        pub fn getAll(self: *Self) ![]Element {
            return try self.chunks.getAll(self.allocator, length);
        }

        pub fn getAllInto(self: *Self, values: []Element) ![]Element {
            return try self.chunks.getAllInto(length, values);
        }
    };
}

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

    var actual_root: [32]u8 = undefined;
    try view.hashTreeRoot(&actual_root);

    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);

    var roundtrip: VectorType.Type = undefined;
    try VectorType.tree.toValue(view.getRoot(), &pool, &roundtrip);
    try std.testing.expectEqualSlices(u64, &expected, &roundtrip);
}
