const std = @import("std");
const Allocator = std.mem.Allocator;

const hashing = @import("hashing");
const Depth = hashing.Depth;

const isBasicType = @import("../type/type_kind.zig").isBasicType;
const isFixedType = @import("../type/type_kind.zig").isFixedType;

const type_root = @import("../type/root.zig");
const chunkDepth = type_root.chunkDepth;

const Node = @import("persistent_merkle_tree").Node;

const ViewStore = @import("view_store.zig").ViewStore;
const ViewId = @import("view_store.zig").ViewId;

const CompositeChunks = @import("chunks.zig").CompositeChunks;

pub fn ArrayCompositeTreeView(comptime ST: type) type {
    comptime {
        if (ST.kind != .vector) {
            @compileError("ArrayCompositeTreeView can only be used with Vector types");
        }
        if (!@hasDecl(ST, "Element") or isBasicType(ST.Element)) {
            @compileError("ArrayCompositeTreeView can only be used with Vector of composite element types");
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

        pub fn get(self: *Self, index: usize) !ElementView {
            if (index >= length) return error.IndexOutOfBounds;
            return try Chunks.get(self.store, self.view_id, index);
        }

        pub fn set(self: *Self, index: usize, value: ElementView) !void {
            if (index >= length) return error.IndexOutOfBounds;
            try Chunks.set(self.store, self.view_id, index, value);
        }

        /// Serialize the tree view into a provided buffer.
        /// Returns the number of bytes written.
        pub fn serializeIntoBytes(self: *Self, out: []u8) !usize {
            try self.commit();
            if (comptime isFixedType(ST)) {
                return try ST.tree.serializeIntoBytes(self.store.rootNode(self.view_id), self.pool, out);
            } else {
                return try ST.tree.serializeIntoBytes(self.allocator, self.store.rootNode(self.view_id), self.pool, out);
            }
        }

        /// Get the serialized size of this tree view.
        pub fn serializedSize(self: *Self) !usize {
            try self.commit();
            if (comptime isFixedType(ST)) {
                return ST.tree.serializedSize(self.store.rootNode(self.view_id), self.pool);
            } else {
                return try ST.tree.serializedSize(self.allocator, self.store.rootNode(self.view_id), self.pool);
            }
        }
    };
}
