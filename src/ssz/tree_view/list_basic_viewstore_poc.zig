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

const ViewStore = @import("view_store.zig").ViewStore;
const ViewId = @import("view_store.zig").ViewId;

pub fn ListBasicTreeViewViewStorePOC(comptime ST: type) type {
    comptime {
        if (ST.kind != .list) {
            @compileError("ListBasicTreeViewViewStorePOC can only be used with List types");
        }
        if (!@hasDecl(ST, "Element") or !isBasicType(ST.Element)) {
            @compileError("ListBasicTreeViewViewStorePOC can only be used with List of basic element types");
        }
    }

    return struct {
        allocator: Allocator,
        pool: *Node.Pool,
        store: *ViewStore,
        view_id: ViewId,
        owns_store: bool,

        pub const SszType = ST;
        pub const Element = ST.Element.Type;

        const base_chunk_depth: Depth = @intCast(ST.chunk_depth);
        const chunk_depth: Depth = chunkDepth(Depth, base_chunk_depth, ST);
        const items_per_chunk: usize = itemsPerChunk(ST.Element);

        const Self = @This();

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !Self {
            const store = try allocator.create(ViewStore);
            errdefer allocator.destroy(store);

            store.* = ViewStore.init(allocator, pool);
            errdefer store.deinit();

            const view_id = try store.createView(root);
            return .{
                .allocator = allocator,
                .pool = pool,
                .store = store,
                .view_id = view_id,
                .owns_store = true,
            };
        }

        pub fn fromStore(store: *ViewStore, view_id: ViewId) Self {
            return .{
                .allocator = store.allocator,
                .pool = store.pool,
                .store = store,
                .view_id = view_id,
                .owns_store = false,
            };
        }

        pub fn fromStoreWithContext(allocator: Allocator, pool: *Node.Pool, store: *ViewStore, view_id: ViewId) Self {
            _ = allocator;
            _ = pool;
            return fromStore(store, view_id);
        }

        pub fn deinit(self: *Self) void {
            if (!self.owns_store) return;
            self.store.destroyViewRecursive(self.view_id);
            self.store.deinit();
            self.allocator.destroy(self.store);
        }

        pub fn clearCache(self: *Self) void {
            self.store.clearCache(self.view_id);
        }

        pub fn rootNodeId(self: *const Self) Node.Id {
            return self.store.rootNode(self.view_id);
        }

        pub fn commit(self: *Self) !void {
            try self.store.commit(self.view_id);
        }

        pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void {
            try self.commit();
            out.* = self.rootNodeId().getRoot(self.pool).*;
        }

        pub fn length(self: *Self) !usize {
            return try self.getListLengthCachedOrLoad();
        }

        fn getListLengthCachedOrLoad(self: *Self) !usize {
            if (!self.store.isListLengthDirty(self.view_id)) {
                if (self.store.getListLengthCache(self.view_id)) |len| return len;
            }

            const length_node = try self.store.getChildNode(self.view_id, @enumFromInt(3));
            const length_chunk = length_node.getRoot(self.pool);
            const len = std.mem.readInt(usize, length_chunk[0..@sizeOf(usize)], .little);

            self.store.setListLengthCache(self.view_id, len);
            self.store.setListLengthDirty(self.view_id, false);
            return len;
        }

        fn ensureChunksPrefetched(self: *Self, chunk_count: usize) !void {
            if (chunk_count == 0) return;

            var start: usize = 0;
            if (self.store.getPrefetchProgressCount(self.view_id)) |prefetched| {
                if (prefetched >= chunk_count) return;
                start = prefetched;
            }

            const fetch_count = chunk_count - start;
            if (fetch_count == 0) return;

            const nodes = try self.allocator.alloc(Node.Id, fetch_count);
            defer self.allocator.free(nodes);

            try self.rootNodeId().getNodesAtDepth(self.pool, @as(u8, @intCast(chunk_depth)), start, nodes);

            for (nodes, 0..) |node, i| {
                const gindex = Gindex.fromDepth(chunk_depth, start + i);
                try self.store.cacheChildNodeIfAbsent(self.view_id, gindex, node);
            }

            self.store.setPrefetchProgressCount(self.view_id, chunk_count);
        }

        pub fn get(self: *Self, index: usize) !Element {
            const list_length = try self.length();
            if (index >= list_length) return error.IndexOutOfBounds;

            var value: Element = undefined;
            const leaf_node = try self.store.getChildNode(self.view_id, Gindex.fromDepth(chunk_depth, index / items_per_chunk));
            try ST.Element.tree.toValuePacked(leaf_node, self.pool, index, &value);
            return value;
        }

        pub fn set(self: *Self, index: usize, value: Element) !void {
            const list_length = try self.length();
            if (index >= list_length) return error.IndexOutOfBounds;

            const gindex = Gindex.fromDepth(chunk_depth, index / items_per_chunk);
            const leaf_node = try self.store.getChildNode(self.view_id, gindex);
            const new_leaf = try ST.Element.tree.fromValuePacked(leaf_node, self.pool, index, &value);
            try self.store.setChildNode(self.view_id, gindex, new_leaf);
        }

        /// Caller must free the returned slice.
        pub fn getAll(self: *Self, allocator: Allocator) ![]Element {
            const list_length = try self.length();
            const values = try allocator.alloc(Element, list_length);
            errdefer allocator.free(values);
            _ = try self.getAllInto(values);
            return values;
        }

        pub fn getAllInto(self: *Self, values: []Element) ![]Element {
            const list_length = try self.length();
            if (values.len != list_length) return error.InvalidSize;
            if (list_length == 0) return values;

            const len_full_chunks = list_length / items_per_chunk;
            const remainder = list_length % items_per_chunk;
            const chunk_count = len_full_chunks + @intFromBool(remainder != 0);

            try self.ensureChunksPrefetched(chunk_count);

            for (0..len_full_chunks) |chunk_idx| {
                const leaf_node = try self.store.getChildNode(self.view_id, Gindex.fromDepth(chunk_depth, chunk_idx));
                for (0..items_per_chunk) |i| {
                    try ST.Element.tree.toValuePacked(
                        leaf_node,
                        self.pool,
                        i,
                        &values[chunk_idx * items_per_chunk + i],
                    );
                }
            }

            if (remainder > 0) {
                const leaf_node = try self.store.getChildNode(self.view_id, Gindex.fromDepth(chunk_depth, len_full_chunks));
                for (0..remainder) |i| {
                    try ST.Element.tree.toValuePacked(
                        leaf_node,
                        self.pool,
                        i,
                        &values[len_full_chunks * items_per_chunk + i],
                    );
                }
            }

            return values;
        }

        pub fn push(self: *Self, value: Element) !void {
            const list_length = try self.length();
            if (list_length >= ST.limit) return error.LengthOverLimit;
            try self.updateListLength(list_length + 1);
            try self.set(list_length, value);
        }

        /// Return a new view containing all elements up to and including `index`.
        /// The caller must call `deinit()` on the returned view to avoid memory leaks.
        pub fn sliceTo(self: *Self, index: usize) !Self {
            try self.commit();

            const list_length = try self.length();
            if (list_length == 0 or index >= list_length - 1) {
                return try Self.init(self.allocator, self.pool, self.rootNodeId());
            }

            const new_length = index + 1;
            if (new_length > ST.limit) {
                return error.LengthOverLimit;
            }

            const chunk_index = index / items_per_chunk;
            const chunk_offset = index % items_per_chunk;
            const chunk_node = try Node.Id.getNodeAtDepth(self.rootNodeId(), self.pool, chunk_depth, chunk_index);

            var chunk_bytes = chunk_node.getRoot(self.pool).*;
            const keep_bytes = (chunk_offset + 1) * ST.Element.fixed_size;
            if (keep_bytes < BYTES_PER_CHUNK) {
                @memset(chunk_bytes[keep_bytes..], 0);
            }

            var truncated_chunk_node: ?Node.Id = try self.pool.createLeaf(&chunk_bytes);
            defer if (truncated_chunk_node) |id| self.pool.unref(id);

            var updated: ?Node.Id = try Node.Id.setNodeAtDepth(
                self.rootNodeId(),
                self.pool,
                chunk_depth,
                chunk_index,
                truncated_chunk_node.?,
            );
            defer if (updated) |id| self.pool.unref(id);
            truncated_chunk_node = null;

            var new_root: ?Node.Id = try Node.Id.truncateAfterIndex(updated.?, self.pool, chunk_depth, chunk_index);
            defer if (new_root) |id| self.pool.unref(id);
            updated = null;

            var length_node: ?Node.Id = try self.pool.createLeafFromUint(@intCast(new_length));
            defer if (length_node) |id| self.pool.unref(id);
            const root_with_length = try Node.Id.setNode(new_root.?, self.pool, @enumFromInt(3), length_node.?);
            errdefer self.pool.unref(root_with_length);

            length_node = null;
            new_root = null;

            return try Self.init(self.allocator, self.pool, root_with_length);
        }

        fn updateListLength(self: *Self, new_length: usize) !void {
            if (new_length > ST.limit) return error.LengthOverLimit;
            const length_node = try self.pool.createLeafFromUint(@intCast(new_length));
            errdefer self.pool.unref(length_node);

            self.store.setListLengthCache(self.view_id, new_length);
            self.store.setListLengthDirty(self.view_id, false);

            try self.store.setChildNode(self.view_id, @enumFromInt(3), length_node);
        }
    };
}
