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
        prefetched_chunk_count: ?usize = null,

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
                .prefetched_chunk_count = null,
            };
        }

        pub fn deinit(self: *Self) void {
            self.base_view.deinit();
        }

        pub fn commit(self: *Self) !void {
            try self.base_view.commit();
        }

        pub fn clearCache(self: *Self) void {
            self.base_view.data.clearChildrenNodesCache(self.base_view.pool);
            self.prefetched_chunk_count = null;
            self.base_view.data.changed.clearRetainingCapacity();
        }

        pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void {
            try self.base_view.hashTreeRoot(out);
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
            return try Chunks.getAll(&self.base_view, allocator, length, &self.prefetched_chunk_count);
        }

        pub fn getAllInto(self: *Self, values: []Element) ![]Element {
            return try Chunks.getAllInto(&self.base_view, length, values, &self.prefetched_chunk_count);
        }
    };
}
