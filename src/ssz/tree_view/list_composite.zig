const std = @import("std");
const Allocator = std.mem.Allocator;

const hashing = @import("hashing");
const Depth = hashing.Depth;

const Node = @import("persistent_merkle_tree").Node;

const isBasicType = @import("../type/type_kind.zig").isBasicType;
const isFixedType = @import("../type/type_kind.zig").isFixedType;

const type_root = @import("../type/root.zig");
const chunkDepth = type_root.chunkDepth;

const ViewStore = @import("view_store.zig").ViewStore;
const ViewId = @import("view_store.zig").ViewId;

const CompositeChunks = @import("chunks.zig").CompositeChunks;

pub fn ListCompositeTreeView(comptime ST: type) type {
    comptime {
        if (ST.kind != .list) {
            @compileError("ListCompositeTreeView can only be used with List types");
        }
        if (!@hasDecl(ST, "Element") or isBasicType(ST.Element)) {
            @compileError("ListCompositeTreeView can only be used with List of composite element types");
        }
    }

    return struct {
        allocator: Allocator,
        pool: *Node.Pool,
        store: *ViewStore,
        view_id: ViewId,

        pub const SszType = ST;
        pub const ElementST = ST.Element;

        const base_chunk_depth: Depth = @intCast(ST.chunk_depth);
        const chunk_depth: Depth = chunkDepth(Depth, base_chunk_depth, ST);

        const Chunks = CompositeChunks(ST, chunk_depth);

        const Self = @This();

        pub const ElementView = Chunks.ElementTreeView;

        pub fn init(store: *ViewStore, root: Node.Id) !Self {
            const view_id = try store.createView(root);
            return fromStore(store, view_id);
        }

        pub fn fromStore(store: *ViewStore, view_id: ViewId) Self {
            return .{
                .allocator = store.allocator,
                .pool = store.pool,
                .store = store,
                .view_id = view_id,
            };
        }

        pub fn clone(self: *Self, opts: ViewStore.CloneOpts) !Self {
            const new_id = try self.store.cloneView(self.view_id, opts);
            return fromStore(self.store, new_id);
        }

        pub fn deinit(_: *Self) void {}

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
            const length_node = try self.store.getChildNode(self.view_id, @enumFromInt(3));
            const length_chunk = length_node.getRoot(self.pool);
            return std.mem.readInt(usize, length_chunk[0..@sizeOf(usize)], .little);
        }

        pub fn get(self: *Self, index: usize) !ElementView {
            const list_length = try self.length();
            if (index >= list_length) return error.IndexOutOfBounds;
            return try Chunks.get(self.store, self.view_id, index);
        }

        pub fn set(self: *Self, index: usize, value: ElementView) !void {
            const list_length = try self.length();
            if (index >= list_length) return error.IndexOutOfBounds;
            try Chunks.set(self.store, self.view_id, index, value);
        }

        pub fn push(self: *Self, value: ElementView) !void {
            const list_length = try self.length();
            if (list_length >= ST.limit) {
                return error.LengthOverLimit;
            }

            try self.updateListLength(list_length + 1);
            // Use Chunks.set directly since we've already validated length
            try Chunks.set(self.store, self.view_id, list_length, value);
        }

        /// Return a new view containing all elements up to and including `index`.
        /// The returned view borrows the same `ViewStore` as `self`.
        pub fn sliceTo(self: *Self, index: usize) !Self {
            try self.commit();

            const list_length = try self.length();
            if (list_length == 0 or index >= list_length - 1) {
                return try Self.init(self.store, self.rootNodeId());
            }

            const new_length = index + 1;
            if (new_length > ST.limit) {
                return error.LengthOverLimit;
            }

            var chunk_root: ?Node.Id = try Node.Id.truncateAfterIndex(self.rootNodeId(), self.pool, chunk_depth, index);
            defer if (chunk_root) |id| self.pool.unref(id);

            var length_node: ?Node.Id = try self.pool.createLeafFromUint(@intCast(new_length));
            defer if (length_node) |id| self.pool.unref(id);

            const root_with_length = try Node.Id.setNode(chunk_root.?, self.pool, @enumFromInt(3), length_node.?);
            errdefer self.pool.unref(root_with_length);

            length_node = null;
            chunk_root = null;

            return try Self.init(self.store, root_with_length);
        }

        /// Return a new view containing all elements from `index` to the end.
        /// The returned view borrows the same `ViewStore` as `self`.
        pub fn sliceFrom(self: *Self, index: usize) !Self {
            try self.commit();

            const list_length = try self.length();
            if (index == 0) {
                return try Self.init(self.store, self.rootNodeId());
            }

            const target_length = if (index >= list_length) 0 else list_length - index;

            var chunk_root: ?Node.Id = null;
            defer if (chunk_root) |id| self.pool.unref(id);

            if (target_length == 0) {
                chunk_root = @enumFromInt(base_chunk_depth);
            } else {
                const nodes = try self.allocator.alloc(Node.Id, target_length);
                defer self.allocator.free(nodes);

                try self.rootNodeId().getNodesAtDepth(self.pool, chunk_depth, index, nodes);

                chunk_root = try Node.fillWithContents(self.pool, nodes, base_chunk_depth);
            }

            var length_node: ?Node.Id = try self.pool.createLeafFromUint(@intCast(target_length));
            defer if (length_node) |id| self.pool.unref(id);

            const new_root = try self.pool.createBranch(chunk_root.?, length_node.?);
            errdefer self.pool.unref(new_root);

            length_node = null;
            chunk_root = null;

            return try Self.init(self.store, new_root);
        }

        fn updateListLength(self: *Self, new_length: usize) !void {
            if (new_length > ST.limit) {
                return error.LengthOverLimit;
            }
            const length_node = try self.pool.createLeafFromUint(@intCast(new_length));
            errdefer self.pool.unref(length_node);

            try self.store.setChildNode(self.view_id, @enumFromInt(3), length_node);
        }

        /// Serialize the tree view into a provided buffer.
        /// Returns the number of bytes written.
        pub fn serializeIntoBytes(self: *Self, out: []u8) !usize {
            try self.commit();
            return try ST.tree.serializeIntoBytes(self.allocator, self.store.rootNode(self.view_id), self.pool, out);
        }

        /// Get the serialized size of this tree view.
        pub fn serializedSize(self: *Self) !usize {
            try self.commit();
            return try ST.tree.serializedSize(self.allocator, self.store.rootNode(self.view_id), self.pool);
        }
    };
}
