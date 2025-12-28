const std = @import("std");

const hashing = @import("hashing");
const Depth = hashing.Depth;

const TypeKind = @import("../type/type_kind.zig").TypeKind;
const isBasicType = @import("../type/type_kind.zig").isBasicType;

const type_root = @import("../type/root.zig");
const chunkDepth = type_root.chunkDepth;

const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const Allocator = std.mem.Allocator;

const ViewStore = @import("view_store.zig").ViewStore;
const ViewId = @import("view_store.zig").ViewId;

const ContainerTreeViewViewStorePOC = @import("container_viewstore_poc.zig").ContainerTreeView;
const ArrayBasicTreeViewViewStorePOC = @import("array_basic_viewstore_poc.zig").ArrayBasicTreeViewViewStorePOC;
const ListBasicTreeViewViewStorePOC = @import("list_basic_viewstore_poc.zig").ListBasicTreeViewViewStorePOC;
const ListCompositeTreeViewViewStorePOC = @import("list_composite_viewstore_poc.zig").ListCompositeTreeViewViewStorePOC;

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

    @compileError("ArrayCompositeTreeViewViewStorePOC: element kind not supported yet by DO-1 POC (need a ViewStore-backed view for this element type)");
}

pub fn ArrayCompositeTreeViewViewStorePOC(comptime ST: type) type {
    comptime {
        if (ST.kind != .vector) {
            @compileError("ArrayCompositeTreeViewViewStorePOC can only be used with Vector types");
        }
        if (!@hasDecl(ST, "Element") or isBasicType(ST.Element)) {
            @compileError("ArrayCompositeTreeViewViewStorePOC can only be used with Vector of composite element types");
        }
    }

    return struct {
        allocator: Allocator,
        pool: *Node.Pool,
        store: *ViewStore,
        view_id: ViewId,

        pub const SszType = ST;
        pub const ElementST = ST.Element;
        pub const length: usize = ST.length;

        const base_chunk_depth: Depth = @intCast(ST.chunk_depth);
        const chunk_depth: Depth = chunkDepth(Depth, base_chunk_depth, ST);

        const Self = @This();

        pub const ElementView = ElementTreeViewViewStorePOC(ElementST);

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

        pub fn clearCache(self: *Self) void {
            self.store.clearCache(self.view_id);
        }

        pub fn rootNodeId(self: *const Self) Node.Id {
            return self.store.rootNode(self.view_id);
        }

        pub fn get(self: *Self, index: usize) !ElementView {
            if (index >= length) return error.IndexOutOfBounds;
            const child_gindex = Gindex.fromDepth(chunk_depth, index);
            const child_id = try self.store.getOrCreateChildView(self.view_id, child_gindex);
            return ElementView.fromStore(self.store, child_id);
        }

        pub fn set(self: *Self, index: usize, value: ElementView) !void {
            if (index >= length) return error.IndexOutOfBounds;
            const child_gindex = Gindex.fromDepth(chunk_depth, index);

            var v = value;
            defer v.deinit();

            if (v.store != self.store) return error.DifferentStore;

            if (self.store.cachedChildViewId(self.view_id, child_gindex)) |cached_child_id| {
                if (cached_child_id == v.view_id) {
                    try self.store.markChanged(self.view_id, child_gindex);
                    return;
                }
            }

            try self.store.setChildView(self.view_id, child_gindex, v.view_id);
        }

        pub fn commit(self: *Self) !void {
            try self.store.commit(self.view_id);
        }

        pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void {
            try self.commit();
            out.* = self.rootNodeId().getRoot(self.pool).*;
        }
    };
}
