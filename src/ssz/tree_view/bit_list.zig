const std = @import("std");
const Allocator = std.mem.Allocator;

const hashing = @import("hashing");
const Depth = hashing.Depth;

const Node = @import("persistent_merkle_tree").Node;

const type_root = @import("../type/root.zig");
const chunkDepth = type_root.chunkDepth;

const ViewStore = @import("view_store.zig").ViewStore;
const ViewId = @import("view_store.zig").ViewId;
const BitArray = @import("bit_array.zig").BitArray;

pub fn BitListTreeView(comptime ST: type) type {
    comptime {
        if (ST.kind != .list) {
            @compileError("BitListTreeView can only be used with List types");
        }
        if (!@hasDecl(ST, "Element") or ST.Element.kind != .bool) {
            @compileError("BitListTreeView can only be used with BitList (List of bool)");
        }
    }

    return struct {
        allocator: Allocator,
        pool: *Node.Pool,
        store: *ViewStore,
        view_id: ViewId,

        pub const SszType = ST;
        pub const Element = bool;

        const Self = @This();

        const base_chunk_depth: Depth = @intCast(ST.chunk_depth);
        const chunk_depth: Depth = chunkDepth(Depth, base_chunk_depth, ST);
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

        fn readLength(self: *Self) !usize {
            const length_node = try self.store.getChildNode(self.view_id, @enumFromInt(3));
            const length_chunk = length_node.getRoot(self.pool);
            return std.mem.readInt(usize, length_chunk[0..@sizeOf(usize)], .little);
        }

        pub fn get(self: *Self, index: usize) !Element {
            const list_length = try self.readLength();
            return BitOps.get(self.store, self.view_id, index, list_length);
        }

        pub fn set(self: *Self, index: usize, value: Element) !void {
            const list_length = try self.readLength();
            return BitOps.set(self.store, self.view_id, index, value, list_length);
        }

        /// Caller must free the returned slice.
        pub fn toBoolArray(self: *Self, allocator: Allocator) ![]bool {
            const list_length = try self.readLength();
            const values = try allocator.alloc(bool, list_length);
            errdefer allocator.free(values);
            try BitOps.fillBools(self.store, self.view_id, values, list_length);
            return values;
        }

        pub fn toBoolArrayInto(self: *Self, out: []bool) !void {
            const list_length = try self.readLength();
            if (out.len != list_length) return error.InvalidSize;
            try BitOps.fillBools(self.store, self.view_id, out, list_length);
        }
    };
}
