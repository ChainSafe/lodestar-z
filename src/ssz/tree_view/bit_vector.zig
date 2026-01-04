const std = @import("std");
const Allocator = std.mem.Allocator;

const hashing = @import("hashing");
const Depth = hashing.Depth;

const Node = @import("persistent_merkle_tree").Node;

const ViewStore = @import("view_store.zig").ViewStore;
const ViewId = @import("view_store.zig").ViewId;
const BitArray = @import("bit_array.zig").BitArray;

pub fn BitVectorTreeView(comptime ST: type) type {
    comptime {
        if (ST.kind != .vector) {
            @compileError("BitVectorTreeView can only be used with Vector types");
        }
        if (!@hasDecl(ST, "Element") or ST.Element.kind != .bool) {
            @compileError("BitVectorTreeView can only be used with BitVector (Vector of bool)");
        }
    }

    return struct {
        allocator: Allocator,
        pool: *Node.Pool,
        store: *ViewStore,
        view_id: ViewId,

        pub const SszType = ST;
        pub const Element = bool;
        pub const length = ST.length;

        const Self = @This();

        const chunk_depth: Depth = @intCast(ST.chunk_depth);
        const BitOps = BitArray(chunk_depth);

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

        pub fn commit(self: *Self) !void {
            try self.store.commit(self.view_id);
        }

        pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void {
            try self.commit();
            out.* = self.store.rootNode(self.view_id).getRoot(self.pool).*;
        }

        pub fn get(self: *Self, index: usize) !Element {
            return BitOps.get(self.store, self.view_id, index, length);
        }

        pub fn set(self: *Self, index: usize, value: Element) !void {
            return BitOps.set(self.store, self.view_id, index, value, length);
        }

        /// Caller must free the returned slice.
        pub fn toBoolArray(self: *Self, allocator: Allocator) ![]bool {
            const values = try allocator.alloc(bool, length);
            errdefer allocator.free(values);
            try self.toBoolArrayInto(values);
            return values;
        }

        pub fn toBoolArrayInto(self: *Self, out: []bool) !void {
            try BitOps.fillBools(self.store, self.view_id, out, length);
        }
    };
}
