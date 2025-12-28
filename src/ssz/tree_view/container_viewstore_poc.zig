const std = @import("std");
const Allocator = std.mem.Allocator;

const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;

const TypeKind = @import("../type/type_kind.zig").TypeKind;
const isBasicType = @import("../type/type_kind.zig").isBasicType;

const ViewStore = @import("view_store.zig").ViewStore;
const ViewId = @import("view_store.zig").ViewId;

const ArrayBasicTreeViewViewStorePOC = @import("array_basic_viewstore_poc.zig").ArrayBasicTreeViewViewStorePOC;
const ArrayCompositeTreeViewViewStorePOC = @import("array_composite_viewstore_poc.zig").ArrayCompositeTreeViewViewStorePOC;
const ListBasicTreeViewViewStorePOC = @import("list_basic_viewstore_poc.zig").ListBasicTreeViewViewStorePOC;
const ListCompositeTreeViewViewStorePOC = @import("list_composite_viewstore_poc.zig").ListCompositeTreeViewViewStorePOC;

pub fn ContainerTreeView(comptime ST: type) type {
    return struct {
        allocator: Allocator,
        pool: *Node.Pool,
        store: *ViewStore,
        view_id: ViewId,

        pub const SszType = ST;

        const Self = @This();

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

        pub fn deinit(_: *Self) void {}

        pub fn commit(self: *Self) !void {
            try self.store.commit(self.view_id);
        }

        pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void {
            try self.commit();
            out.* = self.store.rootNode(self.view_id).getRoot(self.pool).*;
        }

        pub fn rootNodeId(self: *const Self) Node.Id {
            return self.store.rootNode(self.view_id);
        }

        pub fn Field(comptime field_name: []const u8) type {
            const ChildST = ST.getFieldType(field_name);
            if (comptime isBasicType(ChildST)) {
                return ChildST.Type;
            }

            if (comptime ChildST.kind == TypeKind.container) {
                return ContainerTreeView(ChildST);
            }

            if (comptime ChildST.kind == TypeKind.vector) {
                if (comptime isBasicType(ChildST.Element)) {
                    return ArrayBasicTreeViewViewStorePOC(ChildST);
                }
                return ArrayCompositeTreeViewViewStorePOC(ChildST);
            }

            if (comptime ChildST.kind == TypeKind.list) {
                if (comptime isBasicType(ChildST.Element)) {
                    return ListBasicTreeViewViewStorePOC(ChildST);
                }
                return ListCompositeTreeViewViewStorePOC(ChildST);
            }

            return ChildST.TreeView;
        }

        pub fn get(self: *Self, comptime field_name: []const u8) !Field(field_name) {
            const field_index = comptime ST.getFieldIndex(field_name);
            const ChildST = ST.getFieldType(field_name);
            const child_gindex = Gindex.fromDepth(ST.chunk_depth, field_index);

            if (comptime isBasicType(ChildST)) {
                var value: ChildST.Type = undefined;
                const child_node = try self.store.getChildNode(self.view_id, child_gindex);
                try ChildST.tree.toValue(child_node, self.pool, &value);
                return value;
            }

            if (comptime ChildST.kind == TypeKind.container) {
                const child_id = try self.store.getOrCreateChildView(self.view_id, child_gindex);
                return ContainerTreeView(ChildST).fromStore(self.store, child_id);
            }

            if (comptime ChildST.kind == TypeKind.vector) {
                const child_id = try self.store.getOrCreateChildView(self.view_id, child_gindex);
                if (comptime isBasicType(ChildST.Element)) {
                    return ArrayBasicTreeViewViewStorePOC(ChildST).fromStore(self.store, child_id);
                }
                return ArrayCompositeTreeViewViewStorePOC(ChildST).fromStore(self.store, child_id);
            }

            if (comptime ChildST.kind == TypeKind.list) {
                const child_id = try self.store.getOrCreateChildView(self.view_id, child_gindex);
                if (comptime isBasicType(ChildST.Element)) {
                    return ListBasicTreeViewViewStorePOC(ChildST).fromStore(self.store, child_id);
                }
                return ListCompositeTreeViewViewStorePOC(ChildST).fromStore(self.store, child_id);
            }

            return error.UnsupportedCompositeType;
        }

        pub fn set(self: *Self, comptime field_name: []const u8, value: Field(field_name)) !void {
            const field_index = comptime ST.getFieldIndex(field_name);
            const ChildST = ST.getFieldType(field_name);
            const child_gindex = Gindex.fromDepth(ST.chunk_depth, field_index);

            if (comptime isBasicType(ChildST)) {
                try self.store.setChildNode(
                    self.view_id,
                    child_gindex,
                    try ChildST.tree.fromValue(self.pool, &value),
                );
                return;
            }

            if (comptime ChildST.kind == TypeKind.container) {
                var v = value;
                defer v.deinit();

                if (v.store != self.store) return error.DifferentStore;

                // If the caller is re-setting a borrowed cached child view (from get()), keep the mapping.
                if (self.store.cachedChildViewId(self.view_id, child_gindex)) |cached_child_id| {
                    if (cached_child_id == v.view_id) {
                        try self.store.markChanged(self.view_id, child_gindex);
                        return;
                    }
                }

                try self.store.setChildView(self.view_id, child_gindex, v.view_id);
                return;
            }

            if (comptime ChildST.kind == TypeKind.vector) {
                var v = value;
                defer v.deinit();

                if (v.store != self.store) return error.DifferentStore;

                // If the caller is re-setting a borrowed cached child view (from get()), keep the mapping.
                if (self.store.cachedChildViewId(self.view_id, child_gindex)) |cached_child_id| {
                    if (cached_child_id == v.view_id) {
                        try self.store.markChanged(self.view_id, child_gindex);
                        return;
                    }
                }

                try self.store.setChildView(self.view_id, child_gindex, v.view_id);
                return;
            }

            if (comptime ChildST.kind == TypeKind.list) {
                var v = value;
                defer v.deinit();

                if (v.store != self.store) return error.DifferentStore;

                // If the caller is re-setting a borrowed cached child view (from get()), keep the mapping.
                if (self.store.cachedChildViewId(self.view_id, child_gindex)) |cached_child_id| {
                    if (cached_child_id == v.view_id) {
                        try self.store.markChanged(self.view_id, child_gindex);
                        return;
                    }
                }

                try self.store.setChildView(self.view_id, child_gindex, v.view_id);
                return;
            }

            return error.UnsupportedCompositeType;
        }
    };
}
