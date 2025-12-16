const std = @import("std");
const Allocator = std.mem.Allocator;
const hashing = @import("hashing");
const Depth = hashing.Depth;
const ListLengthUint = hashing.GindexUint;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const isBasicType = @import("../type/type_kind.zig").isBasicType;

const type_root = @import("../type/root.zig");
const chunkDepth = type_root.chunkDepth;

const tree_view_root = @import("root.zig");
const BaseTreeView = tree_view_root.BaseTreeView;
const CompositeChunks = @import("chunks.zig").CompositeChunks;

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
    }

    return struct {
        base_view: BaseTreeView,
        list_length_cache: ?ListLengthUint = null,

        pub const SszType = ST;
        pub const Element = ST.Element.TreeView;

        const Self = @This();

        const base_chunk_depth: Depth = @intCast(ST.chunk_depth);
        const chunk_depth: Depth = chunkDepth(Depth, base_chunk_depth, ST);
        const list_length_gindex: Gindex = Gindex.fromDepth(1, 1);
        const Chunks = CompositeChunks(ST, chunk_depth);

        const dirty_mask: ListLengthUint = @as(ListLengthUint, 1) << (@bitSizeOf(ListLengthUint) - 1);

        comptime {
            const max_len: usize = (@as(usize, 1) << (@bitSizeOf(ListLengthUint) - 1)) - 1;
            if (ST.limit > max_len) {
                @compileError("ListCompositeTreeView list length does not fit (limit too large for dirty-bit encoding)");
            }
        }

        inline fn isDirtyLength(cached: ListLengthUint) bool {
            return (cached & dirty_mask) != 0;
        }

        inline fn stripDirtyLength(cached: ListLengthUint) ListLengthUint {
            return cached & ~dirty_mask;
        }

        inline fn tagDirtyLength(length_value: ListLengthUint) ListLengthUint {
            std.debug.assert((length_value & dirty_mask) == 0);
            return length_value | dirty_mask;
        }

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !Self {
            return Self{
                .base_view = try BaseTreeView.init(allocator, pool, root),
                .list_length_cache = null,
            };
        }

        pub fn deinit(self: *Self) void {
            self.base_view.deinit();
        }

        pub fn commit(self: *Self) !void {
            try self.base_view.commit();

            if (self.list_length_cache) |cached| {
                if (!isDirtyLength(cached)) return;
                const new_length = stripDirtyLength(cached);
                const root_with_length = blk: {
                    const length_node = try self.base_view.pool.createLeafFromUint(new_length);
                    errdefer self.base_view.pool.unref(length_node);
                    break :blk try Node.Id.setNode(
                        self.base_view.data.root,
                        self.base_view.pool,
                        list_length_gindex,
                        length_node,
                    );
                };
                errdefer self.base_view.pool.unref(root_with_length);

                try self.base_view.pool.ref(root_with_length);
                self.base_view.pool.unref(self.base_view.data.root);
                self.base_view.data.root = root_with_length;

                self.list_length_cache = new_length;
            }
        }

        pub fn clearCache(self: *Self) void {
            self.base_view.data.clearChildrenNodesCache(self.base_view.pool);
            self.base_view.data.clearChildrenDataCache(self.base_view.allocator, self.base_view.pool);
            self.base_view.data.changed.clearRetainingCapacity();
            self.list_length_cache = null;
        }

        pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void {
            try self.commit();
            out.* = self.base_view.data.root.getRoot(self.base_view.pool).*;
        }

        pub fn length(self: *Self) !usize {
            if (self.list_length_cache) |cached_len| {
                return @intCast(stripDirtyLength(cached_len));
            }
            const tree_len = try ST.tree.length(self.base_view.data.root, self.base_view.pool);
            self.list_length_cache = @intCast(tree_len);
            return tree_len;
        }

        pub fn get(self: *Self, index: usize) !Element {
            const list_length = try self.length();
            if (index >= list_length) return error.IndexOutOfBounds;
            return try Chunks.get(&self.base_view, index);
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
            try Chunks.set(&self.base_view, index, value);
        }

        pub fn getAllReadonly(self: *Self, allocator: Allocator) ![]Element {
            // TODO: Implement bulk read-only access after other PRs land.
            _ = self;
            _ = allocator;
            return error.NotImplemented;
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

            var chunk_root: ?Node.Id = try Node.Id.truncateAfterIndex(self.base_view.data.root, self.base_view.pool, chunk_depth, index);
            defer if (chunk_root) |id| self.base_view.pool.unref(id);

            var length_node: ?Node.Id = try self.base_view.pool.createLeafFromUint(@intCast(new_length));
            defer if (length_node) |id| self.base_view.pool.unref(id);
            const root_with_length = try Node.Id.setNode(chunk_root.?, self.base_view.pool, list_length_gindex, length_node.?);
            errdefer self.base_view.pool.unref(root_with_length);
            length_node = null;
            chunk_root = null;

            return try Self.init(self.base_view.allocator, self.base_view.pool, root_with_length);
        }

        /// Return a new view containing all elements from `index` to the end.
        pub fn sliceFrom(self: *Self, index: usize) !Self {
            try self.commit();

            const list_length = try self.length();
            if (index == 0) {
                return try Self.init(self.base_view.allocator, self.base_view.pool, self.base_view.data.root);
            }

            const target_length = if (index >= list_length) 0 else list_length - index;

            var chunk_root: ?Node.Id = null;
            defer if (chunk_root) |id| self.base_view.pool.unref(id);

            if (target_length == 0) {
                chunk_root = @enumFromInt(base_chunk_depth);
            } else {
                const nodes = try self.base_view.allocator.alloc(Node.Id, target_length);
                defer self.base_view.allocator.free(nodes);
                try self.base_view.data.root.getNodesAtDepth(self.base_view.pool, chunk_depth, index, nodes);

                chunk_root = try Node.fillWithContents(self.base_view.pool, nodes, base_chunk_depth);
            }

            var length_node: ?Node.Id = try self.base_view.pool.createLeafFromUint(@intCast(target_length));
            defer if (length_node) |id| self.base_view.pool.unref(id);

            const new_root = try self.base_view.pool.createBranch(chunk_root.?, length_node.?);
            errdefer self.base_view.pool.unref(new_root);
            length_node = null;
            chunk_root = null;

            return try Self.init(self.base_view.allocator, self.base_view.pool, new_root);
        }

        fn updateListLength(self: *Self, new_length: usize) !void {
            if (new_length > ST.limit) {
                return error.LengthOverLimit;
            }
            self.list_length_cache = tagDirtyLength(@intCast(new_length));
        }
    };
}
