const std = @import("std");
const Allocator = std.mem.Allocator;
const hashing = @import("hashing");
const Depth = hashing.Depth;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const isBasicType = @import("../type/type_kind.zig").isBasicType;

const type_root = @import("../type/root.zig");
const BYTES_PER_CHUNK = type_root.BYTES_PER_CHUNK;
const itemsPerChunk = type_root.itemsPerChunk;
const chunkDepth = type_root.chunkDepth;

const BaseTreeView = @import("root.zig").BaseTreeView;
const BasicPackedChunks = @import("chunks.zig").BasicPackedChunks;

/// A specialized tree view for SSZ list types with basic element types.
/// Elements are packed into chunks (multiple elements per leaf node).
pub fn ListBasicTreeView(comptime ST: type) type {
    comptime {
        if (ST.kind != .list) {
            @compileError("ListBasicTreeView can only be used with List types");
        }
        if (!@hasDecl(ST, "Element") or !isBasicType(ST.Element)) {
            @compileError("ListBasicTreeView can only be used with List of basic element types");
        }
    }

    return struct {
        base_view: BaseTreeView,

        pub const SszType = ST;
        pub const Element = ST.Element.Type;

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

        pub fn deinit(self: *Self) void {
            self.base_view.deinit();
        }

        pub fn rootNodeId(self: *const Self) Node.Id {
            return self.base_view.data.root;
        }

        pub fn commit(self: *Self) !void {
            try self.base_view.commit();
        }

        pub fn clearCache(self: *Self) void {
            self.base_view.clearCache();
        }

        pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void {
            try self.commit();
            out.* = self.base_view.data.root.getRoot(self.base_view.pool).*;
        }

        pub fn length(self: *Self) !usize {
            const length_node = try self.base_view.getChildNode(@enumFromInt(3));
            const length_chunk = length_node.getRoot(self.base_view.pool);
            return std.mem.readInt(usize, length_chunk[0..@sizeOf(usize)], .little);
        }

        pub fn get(self: *Self, index: usize) !Element {
            const list_length = try self.length();
            if (index >= list_length) return error.IndexOutOfBounds;
            return try Chunks.get(&self.base_view, index);
        }

        pub fn set(self: *Self, index: usize, value: Element) !void {
            const list_length = try self.length();
            if (index >= list_length) return error.IndexOutOfBounds;
            try Chunks.set(&self.base_view, index, value);
        }

        /// Caller must free the returned slice.
        pub fn getAll(self: *Self, allocator: Allocator) ![]Element {
            const list_length = try self.length();
            return try Chunks.getAll(&self.base_view, allocator, list_length);
        }

        pub fn getAllInto(self: *Self, values: []Element) ![]Element {
            const list_length = try self.length();
            return try Chunks.getAllInto(&self.base_view, list_length, values);
        }

        pub fn push(self: *Self, value: Element) !void {
            const list_length = try self.length();
            if (list_length >= ST.limit) {
                return error.LengthOverLimit;
            }
            try self.updateListLength(list_length + 1);
            try self.set(list_length, value);
        }

        /// Return a new view containing all elements up to and including `index`.
        /// Caller must call `deinit()` on the returned view to avoid memory leaks.
        pub fn sliceTo(self: *Self, index: usize) !Self {
            try self.commit();

            const list_length = try self.length();
            if (list_length == 0 or index >= list_length - 1) {
                return try Self.init(self.base_view.allocator, self.base_view.pool, self.base_view.data.root);
            }

            const new_length = index + 1;
            if (new_length > ST.limit) {
                return error.LengthOverLimit;
            }

            const chunk_index = index / items_per_chunk;
            const chunk_offset = index % items_per_chunk;
            const chunk_node = try Node.Id.getNodeAtDepth(self.base_view.data.root, self.base_view.pool, chunk_depth, chunk_index);

            var chunk_bytes = chunk_node.getRoot(self.base_view.pool).*;
            const keep_bytes = (chunk_offset + 1) * ST.Element.fixed_size;
            if (keep_bytes < BYTES_PER_CHUNK) {
                @memset(chunk_bytes[keep_bytes..], 0);
            }

            var truncated_chunk_node: ?Node.Id = try self.base_view.pool.createLeaf(&chunk_bytes);
            defer if (truncated_chunk_node) |id| self.base_view.pool.unref(id);
            var updated: ?Node.Id = try Node.Id.setNodeAtDepth(
                self.base_view.data.root,
                self.base_view.pool,
                chunk_depth,
                chunk_index,
                truncated_chunk_node.?,
            );
            defer if (updated) |id| self.base_view.pool.unref(id);
            truncated_chunk_node = null;

            var new_root: ?Node.Id = try Node.Id.truncateAfterIndex(updated.?, self.base_view.pool, chunk_depth, chunk_index);
            defer if (new_root) |id| self.base_view.pool.unref(id);
            updated = null;

            var length_node: ?Node.Id = try self.base_view.pool.createLeafFromUint(@intCast(new_length));
            defer if (length_node) |id| self.base_view.pool.unref(id);
            const root_with_length = try Node.Id.setNode(new_root.?, self.base_view.pool, @enumFromInt(3), length_node.?);
            errdefer self.base_view.pool.unref(root_with_length);

            length_node = null;
            new_root = null;

            return try Self.init(self.base_view.allocator, self.base_view.pool, root_with_length);
        }

        fn updateListLength(self: *Self, new_length: usize) !void {
            if (new_length > ST.limit) {
                return error.LengthOverLimit;
            }
            const length_node = try self.base_view.pool.createLeafFromUint(@intCast(new_length));
            errdefer self.base_view.pool.unref(length_node);
            try self.base_view.setChildNode(@enumFromInt(3), length_node);
        }
    };
}
