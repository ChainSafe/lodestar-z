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
const CompositeChunks = @import("chunks.zig").CompositeChunks;
const assertTreeViewType = @import("utils/assert.zig").assertTreeViewType;

/// A specialized tree view for SSZ list types with composite element types.
/// Each element occupies its own subtree.
pub fn ListCompositeTreeView(comptime ST: type) type {
    comptime {
        if (ST.kind != .list) {
            @compileError("ListCompositeTreeView can only be used with List types");
        }
        if (!@hasDecl(ST, "Element") or isBasicType(ST.Element)) {
            @compileError("ListCompositeTreeView can only be used with List of composite element types");
        }
        assertTreeViewType(ST.Element.TreeView);
    }

    const TreeView = struct {
        allocator: Allocator,
        chunks: Chunks,

        pub const SszType = ST;
        pub const Element = *ST.Element.TreeView;

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

        pub fn length(self: *Self) !usize {
            const length_node = try self.chunks.getChildNode(@enumFromInt(3));
            const length_chunk = length_node.getRoot(self.chunks.pool);
            return std.mem.readInt(usize, length_chunk[0..@sizeOf(usize)], .little);
        }

        pub fn get(self: *Self, index: usize) !Element {
            const list_length = try self.length();
            if (index >= list_length) return error.IndexOutOfBounds;
            return self.chunks.get(index);
        }

        pub fn getReadonly(self: *Self, index: usize) !Element {
            // TODO: Implement read-only access after other PRs land.
            _ = self;
            _ = index;
            return error.NotImplemented;
        }

        pub fn set(self: *Self, index: usize, value: Element) !void {
            const list_length = try self.length();
            if (index >= list_length) return error.IndexOutOfBounds;
            try self.chunks.set(index, value);
        }

        pub fn getAllReadonly(self: *Self, allocator: Allocator) ![]Element {
            // TODO: Implement bulk read-only access after other PRs land.
            _ = self;
            _ = allocator;
            return error.NotImplemented;
        }

        /// Appends an element to the end of the list.
        ///
        /// Ownership of the `value` TreeView is transferred to the list view.
        /// The caller must not deinitialize or otherwise use `value` after calling this method,
        /// as it is now owned by the list.
        pub fn push(self: *Self, value: Element) !void {
            const list_length = try self.length();
            if (list_length >= ST.limit) {
                return error.LengthOverLimit;
            }

            try self.updateListLength(list_length + 1);
            try self.set(list_length, value);
        }

        /// Return a new view containing all elements up to and including `index`.
        /// The caller **must** call `deinit()` on the returned view to avoid memory leaks.
        pub fn sliceTo(self: *Self, index: usize) !*Self {
            try self.commit();

            const list_length = try self.length();
            if (list_length == 0 or index >= list_length - 1) {
                return try Self.init(self.allocator, self.chunks.pool, self.chunks.root);
            }

            const new_length = index + 1;
            if (new_length > ST.limit) {
                return error.LengthOverLimit;
            }

            var chunk_root: ?Node.Id = try Node.Id.truncateAfterIndex(self.chunks.root, self.chunks.pool, chunk_depth, index);
            defer if (chunk_root) |id| self.chunks.pool.unref(id);

            var length_node: ?Node.Id = try self.chunks.pool.createLeafFromUint(@intCast(new_length));
            defer if (length_node) |id| self.chunks.pool.unref(id);
            const root_with_length = try Node.Id.setNode(chunk_root.?, self.chunks.pool, @enumFromInt(3), length_node.?);
            errdefer self.chunks.pool.unref(root_with_length);
            length_node = null;
            chunk_root = null;

            return try Self.init(self.allocator, self.chunks.pool, root_with_length);
        }

        /// Return a new view containing all elements from `index` to the end.
        /// The returned view must be deinitialized by the caller using `deinit()` to avoid memory leaks.
        pub fn sliceFrom(self: *Self, index: usize) !*Self {
            try self.commit();

            const list_length = try self.length();
            if (index == 0) {
                return try Self.init(self.allocator, self.chunks.pool, self.chunks.root);
            }

            const target_length = if (index >= list_length) 0 else list_length - index;

            var chunk_root: ?Node.Id = null;
            defer if (chunk_root) |id| self.chunks.pool.unref(id);

            if (target_length == 0) {
                chunk_root = @enumFromInt(base_chunk_depth);
            } else {
                const nodes = try self.allocator.alloc(Node.Id, target_length);
                defer self.allocator.free(nodes);
                try self.chunks.root.getNodesAtDepth(self.chunks.pool, chunk_depth, index, nodes);

                chunk_root = try Node.fillWithContents(self.chunks.pool, nodes, base_chunk_depth);
            }

            var length_node: ?Node.Id = try self.chunks.pool.createLeafFromUint(@intCast(target_length));
            defer if (length_node) |id| self.chunks.pool.unref(id);

            const new_root = try self.chunks.pool.createBranch(chunk_root.?, length_node.?);
            errdefer self.chunks.pool.unref(new_root);
            length_node = null;
            chunk_root = null;

            return try Self.init(self.allocator, self.chunks.pool, new_root);
        }

        fn updateListLength(self: *Self, new_length: usize) !void {
            if (new_length > ST.limit) {
                return error.LengthOverLimit;
            }
            const length_node = try self.chunks.pool.createLeafFromUint(@intCast(new_length));
            errdefer self.chunks.pool.unref(length_node);
            try self.chunks.setChildNode(@enumFromInt(3), length_node);
        }

        /// Serialize the tree view into a provided buffer.
        /// Returns the number of bytes written.
        pub fn serializeIntoBytes(self: *Self, out: []u8) !usize {
            try self.commit();
            return try ST.tree.serializeIntoBytes(self.allocator, self.chunks.root, self.chunks.pool, out);
        }

        /// Get the serialized size of this tree view.
        pub fn serializedSize(self: *Self) !usize {
            try self.commit();
            return try ST.tree.serializedSize(self.allocator, self.chunks.root, self.chunks.pool);
        }
    };

    assertTreeViewType(TreeView);
    return TreeView;
}
