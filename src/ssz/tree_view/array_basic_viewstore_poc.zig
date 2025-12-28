const std = @import("std");

const hashing = @import("hashing");
const Depth = hashing.Depth;
const isBasicType = @import("../type/type_kind.zig").isBasicType;

const type_root = @import("../type/root.zig");
const itemsPerChunk = type_root.itemsPerChunk;
const chunkDepth = type_root.chunkDepth;

const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const Allocator = std.mem.Allocator;

const ViewStore = @import("view_store.zig").ViewStore;
const ViewId = @import("view_store.zig").ViewId;

pub fn ArrayBasicTreeViewViewStorePOC(comptime ST: type) type {
    comptime {
        if (ST.kind != .vector) {
            @compileError("ArrayBasicTreeViewViewStorePOC can only be used with Vector types");
        }
        if (!@hasDecl(ST, "Element") or !isBasicType(ST.Element)) {
            @compileError("ArrayBasicTreeViewViewStorePOC can only be used with Vector of basic element types");
        }
    }

    return struct {
        allocator: Allocator,
        pool: *Node.Pool,
        store: *ViewStore,
        view_id: ViewId,

        pub const SszType = ST;
        pub const Element = ST.Element.Type;
        pub const length: usize = ST.length;

        const base_chunk_depth: Depth = @intCast(ST.chunk_depth);
        const chunk_depth: Depth = chunkDepth(Depth, base_chunk_depth, ST);
        const items_per_chunk: usize = itemsPerChunk(ST.Element);
        const leaf_count: usize = (length + items_per_chunk - 1) / items_per_chunk;

        pub fn init(store: *ViewStore, root: Node.Id) !@This() {
            const view_id = try store.createView(root);
            return fromStore(store, view_id);
        }

        pub fn fromStore(store: *ViewStore, view_id: ViewId) @This() {
            return .{
                .allocator = store.allocator,
                .pool = store.pool,
                .store = store,
                .view_id = view_id,
            };
        }

        pub fn deinit(_: *@This()) void {}

        pub fn clearCache(self: *@This()) void {
            self.store.clearCache(self.view_id);
        }

        pub fn rootNodeId(self: *const @This()) Node.Id {
            return self.store.rootNode(self.view_id);
        }

        pub fn get(self: *@This(), index: usize) !Element {
            if (index >= length) return error.IndexOutOfBounds;
            var value: Element = undefined;
            const leaf_node = try self.store.getChildNode(self.view_id, Gindex.fromDepth(chunk_depth, index / items_per_chunk));
            try ST.Element.tree.toValuePacked(leaf_node, self.pool, index, &value);
            return value;
        }

        pub fn set(self: *@This(), index: usize, value: Element) !void {
            if (index >= length) return error.IndexOutOfBounds;
            const gindex = Gindex.fromDepth(chunk_depth, index / items_per_chunk);
            const leaf_node = try self.store.getChildNode(self.view_id, gindex);
            const new_leaf = try ST.Element.tree.fromValuePacked(leaf_node, self.pool, index, &value);
            try self.store.setChildNode(self.view_id, gindex, new_leaf);
        }

        pub fn getAll(self: *@This(), allocator: Allocator) ![]Element {
            const values = try allocator.alloc(Element, length);
            errdefer allocator.free(values);
            _ = try self.getAllInto(values);
            return values;
        }

        pub fn getAllInto(self: *@This(), values: []Element) ![]Element {
            if (values.len != length) return error.InvalidSize;
            if (length == 0) return values;

            const len_full_chunks = length / items_per_chunk;
            const remainder = length % items_per_chunk;

            for (0..len_full_chunks) |chunk_idx| {
                const leaf_node = try self.store.getChildNode(
                    self.view_id,
                    @import("persistent_merkle_tree").Gindex.fromDepth(chunk_depth, chunk_idx),
                );
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
                const leaf_node = try self.store.getChildNode(
                    self.view_id,
                    @import("persistent_merkle_tree").Gindex.fromDepth(chunk_depth, len_full_chunks),
                );
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

        pub fn commit(self: *@This()) !void {
            try self.store.commit(self.view_id);
        }

        pub fn hashTreeRoot(self: *@This(), out: *[32]u8) !void {
            try self.commit();
            out.* = self.rootNodeId().getRoot(self.pool).*;
        }
    };
}
