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

        /// Return a new view containing all elements from `index` to the end.
        /// The caller **must** call `deinit()` on the returned view to avoid memory leaks.
        pub fn sliceFrom(self: *Self, index: usize) !Self {
            try self.commit();

            const list_length = try self.length();

            if (index == 0) {
                return try Self.init(self.base_view.allocator, self.base_view.pool, self.base_view.data.root);
            }

            const target_length = if (index >= list_length) 0 else list_length - index;
            if (target_length == 0) {
                const chunk_root: Node.Id = @enumFromInt(base_chunk_depth);
                var length_node: ?Node.Id = try self.base_view.pool.createLeafFromUint(0);
                defer if (length_node) |id| self.base_view.pool.unref(id);

                const new_root = try self.base_view.pool.createBranch(chunk_root, length_node.?);
                errdefer self.base_view.pool.unref(new_root);
                length_node = null;

                return try Self.init(self.base_view.allocator, self.base_view.pool, new_root);
            }

            const start_chunk_index = index / items_per_chunk;
            const start_offset_in_chunk = index % items_per_chunk;
            const end_chunk_index = (list_length - 1) / items_per_chunk;
            const source_chunk_count = end_chunk_index - start_chunk_index + 1;

            const new_chunk_count = (target_length + items_per_chunk - 1) / items_per_chunk;

            const source_nodes = try self.base_view.allocator.alloc(Node.Id, source_chunk_count);
            defer self.base_view.allocator.free(source_nodes);
            try self.base_view.data.root.getNodesAtDepth(
                self.base_view.pool,
                chunk_depth,
                start_chunk_index,
                source_nodes,
            );

            var chunk_root: ?Node.Id = try self.createChunkRootForSliceFrom(
                index,
                start_chunk_index,
                start_offset_in_chunk,
                list_length,
                target_length,
                new_chunk_count,
                source_nodes,
            );
            defer if (chunk_root) |id| self.base_view.pool.unref(id);

            var length_node: ?Node.Id = try self.base_view.pool.createLeafFromUint(@intCast(target_length));
            defer if (length_node) |id| self.base_view.pool.unref(id);

            const new_root = try self.base_view.pool.createBranch(chunk_root.?, length_node.?);
            errdefer self.base_view.pool.unref(new_root);
            chunk_root = null;
            length_node = null;

            return try Self.init(self.base_view.allocator, self.base_view.pool, new_root);
        }

        fn createChunkRootForSliceFrom(
            self: *Self,
            slice_start_index: usize,
            start_chunk_index: usize,
            start_offset_in_chunk: usize,
            list_length: usize,
            target_length: usize,
            new_chunk_count: usize,
            source_nodes: []const Node.Id,
        ) !Node.Id {
            if (start_offset_in_chunk == 0) {
                return try self.createChunkRootSliceFromAligned(list_length, target_length, new_chunk_count, source_nodes);
            }
            return try self.createChunkRootSliceFromUnaligned(
                slice_start_index,
                start_chunk_index,
                target_length,
                new_chunk_count,
                source_nodes,
            );
        }

        fn createChunkRootSliceFromAligned(
            self: *Self,
            list_length: usize,
            target_length: usize,
            new_chunk_count: usize,
            source_nodes: []const Node.Id,
        ) !Node.Id {
            std.debug.assert(new_chunk_count == source_nodes.len);

            const new_chunk_nodes = try self.base_view.allocator.alloc(Node.Id, new_chunk_count);
            defer self.base_view.allocator.free(new_chunk_nodes);

            var newly_created_last_leaf: ?Node.Id = null;
            errdefer if (newly_created_last_leaf) |id| self.base_view.pool.unref(id);

            for (0..new_chunk_count) |i| {
                if (i < source_nodes.len - 1 or (list_length % items_per_chunk == 0)) {
                    new_chunk_nodes[i] = source_nodes[i];
                    continue;
                }

                const elems_in_last = target_length % items_per_chunk;
                std.debug.assert(elems_in_last != 0);

                var chunk_bytes = source_nodes[i].getRoot(self.base_view.pool).*;
                const keep_bytes = elems_in_last * ST.Element.fixed_size;
                if (keep_bytes < BYTES_PER_CHUNK) {
                    @memset(chunk_bytes[keep_bytes..], 0);
                }

                new_chunk_nodes[i] = try self.base_view.pool.createLeaf(&chunk_bytes);
                newly_created_last_leaf = new_chunk_nodes[i];
            }

            return try Node.fillWithContents(self.base_view.pool, new_chunk_nodes, base_chunk_depth);
        }

        fn createChunkRootSliceFromUnaligned(
            self: *Self,
            slice_start_index: usize,
            start_chunk_index: usize,
            target_length: usize,
            new_chunk_count: usize,
            source_nodes: []const Node.Id,
        ) !Node.Id {
            const new_chunk_nodes = try self.base_view.allocator.alloc(Node.Id, new_chunk_count);
            defer self.base_view.allocator.free(new_chunk_nodes);

            var newly_created_count: usize = 0;
            errdefer for (new_chunk_nodes[0..newly_created_count]) |id| self.base_view.pool.unref(id);

            for (0..new_chunk_count) |new_chunk_idx| {
                var chunk_bytes: [BYTES_PER_CHUNK]u8 = [_]u8{0} ** BYTES_PER_CHUNK;
                const start_elem = new_chunk_idx * items_per_chunk;
                const end_elem = @min(start_elem + items_per_chunk, target_length);

                for (start_elem..end_elem) |elem_idx| {
                    const src_elem_idx = slice_start_index + elem_idx;
                    const src_chunk_idx = src_elem_idx / items_per_chunk - start_chunk_index;
                    const src_offset = src_elem_idx % items_per_chunk;

                    const src_leaf = source_nodes[src_chunk_idx].getRoot(self.base_view.pool);
                    const src_byte_off = src_offset * ST.Element.fixed_size;
                    const dst_offset = (elem_idx - start_elem) * ST.Element.fixed_size;
                    @memcpy(
                        chunk_bytes[dst_offset..][0..ST.Element.fixed_size],
                        src_leaf[src_byte_off..][0..ST.Element.fixed_size],
                    );
                }

                new_chunk_nodes[new_chunk_idx] = try self.base_view.pool.createLeaf(&chunk_bytes);
                newly_created_count += 1;
            }

            return try Node.fillWithContents(self.base_view.pool, new_chunk_nodes, base_chunk_depth);
        }

        fn updateListLength(self: *Self, new_length: usize) !void {
            if (new_length > ST.limit) {
                return error.LengthOverLimit;
            }
            const length_node = try self.base_view.pool.createLeafFromUint(@intCast(new_length));
            errdefer self.base_view.pool.unref(length_node);
            try self.base_view.setChildNode(@enumFromInt(3), length_node);
        }

        /// Serialize the tree view into a provided buffer.
        /// Returns the number of bytes written.
        pub fn serializeIntoBytes(self: *Self, out: []u8) !usize {
            try self.commit();
            return try ST.tree.serializeIntoBytes(self.base_view.allocator, self.base_view.data.root, self.base_view.pool, out);
        }

        /// Get the serialized size of this tree view.
        pub fn serializedSize(self: *Self) !usize {
            try self.commit();
            return try ST.tree.serializedSize(self.base_view.allocator, self.base_view.data.root, self.base_view.pool);
        }
    };
}
