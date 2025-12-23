const std = @import("std");
const Allocator = std.mem.Allocator;

const hashing = @import("hashing");
const Depth = hashing.Depth;

const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;

const TypeKind = @import("../type/type_kind.zig").TypeKind;
const isBasicType = @import("../type/type_kind.zig").isBasicType;

const type_root = @import("../type/root.zig");
const chunkDepth = type_root.chunkDepth;

const ViewStore = @import("view_store.zig").ViewStore;
const ViewId = @import("view_store.zig").ViewId;

const ContainerTreeViewViewStorePOC = @import("container_viewstore_poc.zig").ContainerTreeView;
const ArrayBasicTreeViewViewStorePOC = @import("array_basic_viewstore_poc.zig").ArrayBasicTreeViewViewStorePOC;
const ArrayCompositeTreeViewViewStorePOC = @import("array_composite_viewstore_poc.zig").ArrayCompositeTreeViewViewStorePOC;
const ListBasicTreeViewViewStorePOC = @import("list_basic_viewstore_poc.zig").ListBasicTreeViewViewStorePOC;

fn ElementTreeViewViewStorePOC(comptime ElemST: type) type {
    if (comptime ElemST.kind == TypeKind.container) {
        return ContainerTreeViewViewStorePOC(ElemST);
    }

    if (comptime ElemST.kind == TypeKind.vector) {
        if (comptime isBasicType(ElemST.Element)) {
            return ArrayBasicTreeViewViewStorePOC(ElemST);
        }
        return ArrayCompositeTreeViewViewStorePOC(ElemST);
    }

    if (comptime ElemST.kind == TypeKind.list) {
        if (comptime isBasicType(ElemST.Element)) {
            return ListBasicTreeViewViewStorePOC(ElemST);
        }
        return ListCompositeTreeViewViewStorePOC(ElemST);
    }

    @compileError("ListCompositeTreeViewViewStorePOC: element kind not supported yet by DO-1 POC (need a ViewStore-backed view for this element type)");
}

pub fn ListCompositeTreeViewViewStorePOC(comptime ST: type) type {
    comptime {
        if (ST.kind != .list) {
            @compileError("ListCompositeTreeViewViewStorePOC can only be used with List types");
        }
        if (!@hasDecl(ST, "Element") or isBasicType(ST.Element)) {
            @compileError("ListCompositeTreeViewViewStorePOC can only be used with List of composite element types");
        }
    }

    return struct {
        allocator: Allocator,
        pool: *Node.Pool,
        store: *ViewStore,
        view_id: ViewId,
        owns_store: bool,

        pub const SszType = ST;
        pub const ElementST = ST.Element;

        const base_chunk_depth: Depth = @intCast(ST.chunk_depth);
        const chunk_depth: Depth = chunkDepth(Depth, base_chunk_depth, ST);

        const Self = @This();

        pub const ElementView = ElementTreeViewViewStorePOC(ElementST);

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

        pub fn get(self: *Self, index: usize) !ElementView {
            const list_length = try self.length();
            if (index >= list_length) return error.IndexOutOfBounds;
            const child_gindex = Gindex.fromDepth(chunk_depth, index);
            const child_id = try self.store.getOrCreateChildView(self.view_id, child_gindex);
            return ElementView.fromStoreWithContext(self.allocator, self.pool, self.store, child_id);
        }

        pub fn set(self: *Self, index: usize, value: ElementView) !void {
            const list_length = try self.length();
            if (index >= list_length) return error.IndexOutOfBounds;
            const child_gindex = Gindex.fromDepth(chunk_depth, index);

            var v = value;
            defer v.deinit();

            if (v.store == self.store) {
                if (self.store.cachedChildViewId(self.view_id, child_gindex)) |cached_child_id| {
                    if (cached_child_id == v.view_id) {
                        try self.store.markChanged(self.view_id, child_gindex);
                        return;
                    }
                }
            }

            try v.commit();
            const child_root = v.rootNodeId();
            try self.pool.ref(child_root);
            try self.store.setChildNode(self.view_id, child_gindex, child_root);
        }

        pub fn push(self: *Self, value: ElementView) !void {
            const list_length = try self.length();
            if (list_length >= ST.limit) {
                return error.LengthOverLimit;
            }

            try self.updateListLength(list_length + 1);
            try self.set(list_length, value);
        }

        /// Return a new view containing all elements up to and including `index`.
        /// The returned view must be deinitialized by the caller using `deinit()`.
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

            var chunk_root: ?Node.Id = try Node.Id.truncateAfterIndex(self.rootNodeId(), self.pool, chunk_depth, index);
            defer if (chunk_root) |id| self.pool.unref(id);

            var length_node: ?Node.Id = try self.pool.createLeafFromUint(@intCast(new_length));
            defer if (length_node) |id| self.pool.unref(id);

            const root_with_length = try Node.Id.setNode(chunk_root.?, self.pool, @enumFromInt(3), length_node.?);
            errdefer self.pool.unref(root_with_length);

            length_node = null;
            chunk_root = null;

            return try Self.init(self.allocator, self.pool, root_with_length);
        }

        /// Return a new view containing all elements from `index` to the end.
        /// The returned view must be deinitialized by the caller using `deinit()`.
        pub fn sliceFrom(self: *Self, index: usize) !Self {
            try self.commit();

            const list_length = try self.length();
            if (index == 0) {
                return try Self.init(self.allocator, self.pool, self.rootNodeId());
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

            return try Self.init(self.allocator, self.pool, new_root);
        }

        fn updateListLength(self: *Self, new_length: usize) !void {
            if (new_length > ST.limit) {
                return error.LengthOverLimit;
            }
            const length_node = try self.pool.createLeafFromUint(@intCast(new_length));
            errdefer self.pool.unref(length_node);

            self.store.setListLengthCache(self.view_id, new_length);
            self.store.setListLengthDirty(self.view_id, false);

            try self.store.setChildNode(self.view_id, @enumFromInt(3), length_node);
        }
    };
}
