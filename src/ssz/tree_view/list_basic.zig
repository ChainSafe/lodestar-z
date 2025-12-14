const std = @import("std");
const Allocator = std.mem.Allocator;
const hashing = @import("hashing");
const Depth = hashing.Depth;
const ListLengthUint = hashing.GindexUint;
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
        const list_length_gindex: Gindex = Gindex.fromDepth(1, 1);
        const Chunks = BasicPackedChunks(ST, chunk_depth, items_per_chunk);

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !Self {
            return Self{
                .base_view = try BaseTreeView.init(allocator, pool, root),
            };
        }

        pub fn deinit(self: *Self) void {
            self.base_view.deinit();
        }

        pub fn commit(self: *Self) !void {
            if (self.base_view.data.changed.contains(list_length_gindex)) {
                if (self.base_view.data.list_length) |len| {
                    const length_node = try self.base_view.pool.createLeafFromUint(len);
                    const opt_old = blk: {
                        errdefer self.base_view.pool.unref(length_node);
                        break :blk try self.base_view.data.children_nodes.fetchPut(
                            self.base_view.allocator,
                            list_length_gindex,
                            length_node,
                        );
                    };
                    if (opt_old) |old_entry| {
                        if (old_entry.value.getState(self.base_view.pool).getRefCount() == 0) {
                            self.base_view.pool.unref(old_entry.value);
                        }
                    }
                }
            }

            try self.base_view.commit();
        }

        pub fn clearCache(self: *Self) void {
            self.base_view.data.clearChildrenNodesCache(self.base_view.pool);
            self.base_view.data.prefetched_chunk_count = null;
            self.base_view.data.changed.clearRetainingCapacity();
            self.base_view.data.list_length = null;
        }

        pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void {
            try self.commit();
            out.* = self.base_view.data.root.getRoot(self.base_view.pool).*;
        }

        pub fn getLength(self: *Self) !usize {
            if (self.base_view.data.list_length) |len| {
                return @intCast(len);
            }
            const len = try ST.tree.length(self.base_view.data.root, self.base_view.pool);
            self.base_view.data.list_length = @intCast(len);
            return len;
        }

        pub fn get(self: *Self, index: usize) !Element {
            const len = try self.getLength();
            if (index >= len) return error.IndexOutOfBounds;
            return try Chunks.get(&self.base_view, index);
        }

        pub fn set(self: *Self, index: usize, value: Element) !void {
            const len = try self.getLength();
            if (index >= len) return error.IndexOutOfBounds;
            try Chunks.set(&self.base_view, index, value);
        }

        /// Caller must free the returned slice.
        pub fn getAll(self: *Self, allocator: Allocator) ![]Element {
            const length = try self.getLength();
            return try Chunks.getAll(&self.base_view, allocator, length);
        }

        pub fn getAllInto(self: *Self, values: []Element) ![]Element {
            const length = try self.getLength();
            return try Chunks.getAllInto(&self.base_view, length, values);
        }

        pub fn push(self: *Self, value: Element) !void {
            const length = try self.getLength();
            if (length >= ST.limit) {
                return error.LengthOverLimit;
            }
            try self.updateListLength(length + 1);
            try self.set(length, value);
        }

        /// Return a new view containing all elements up to and including `index`.
        pub fn sliceTo(self: *Self, index: usize) !Self {
            try self.commit();

            const length = try self.getLength();
            if (length == 0 or index >= length - 1) {
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
            const updated = try Node.Id.setNodeAtDepth(self.base_view.data.root, self.base_view.pool, chunk_depth, chunk_index, truncated_chunk_node.?);
            truncated_chunk_node = null;

            var new_root: ?Node.Id = try Node.Id.truncateAfterIndex(updated, self.base_view.pool, chunk_depth, chunk_index);
            defer if (new_root) |id| self.base_view.pool.unref(id);

            var length_node: ?Node.Id = try self.base_view.pool.createLeafFromUint(@intCast(new_length));
            defer if (length_node) |id| self.base_view.pool.unref(id);
            const root_with_length = try Node.Id.setNode(new_root.?, self.base_view.pool, list_length_gindex, length_node.?);
            length_node = null;

            _ = root_with_length.getRoot(self.base_view.pool);

            new_root = root_with_length;
            const result = try Self.init(self.base_view.allocator, self.base_view.pool, root_with_length);
            new_root = null;
            return result;
        }

        fn updateListLength(self: *Self, new_length: usize) !void {
            if (new_length > ST.limit) {
                return error.LengthOverLimit;
            }
            try self.base_view.data.changed.put(self.base_view.allocator, list_length_gindex, {});
            self.base_view.data.list_length = @intCast(new_length);
        }
    };
}
