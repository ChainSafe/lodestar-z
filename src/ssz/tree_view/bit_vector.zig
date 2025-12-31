const std = @import("std");
const Allocator = std.mem.Allocator;

const hashing = @import("hashing");
const Depth = hashing.Depth;

const Node = @import("persistent_merkle_tree").Node;

const BitArray = @import("bit_array.zig").BitArray;
const assertTreeViewType = @import("utils/assert.zig").assertTreeViewType;

pub fn BitVectorTreeView(comptime ST: type) type {
    comptime {
        if (ST.kind != .vector) {
            @compileError("BitVectorTreeView can only be used with Vector types");
        }
        if (!@hasDecl(ST, "Element") or ST.Element.kind != .bool) {
            @compileError("BitVectorTreeView can only be used with BitVector (Vector of bool)");
        }
    }

    const TreeView = struct {
        allocator: Allocator,
        data: BitOps,

        pub const SszType = ST;
        pub const Element = bool;
        pub const length = ST.length;

        const Self = @This();

        const chunk_depth: Depth = @intCast(ST.chunk_depth);
        const BitOps = BitArray(chunk_depth);

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !*Self {
            const ptr = try allocator.create(Self);
            try BitOps.init(&ptr.data, allocator, pool, root);
            ptr.allocator = allocator;
            return ptr;
        }

        pub fn deinit(self: *Self) void {
            self.data.deinit();
            self.allocator.destroy(self);
        }

        pub fn commit(self: *Self) !void {
            try self.data.commit();
        }

        pub fn clearCache(self: *Self) void {
            self.data.clearCache();
        }

        pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void {
            try self.commit();
            out.* = self.data.root.getRoot(self.data.pool).*;
        }

        pub fn getRoot(self: *const Self) Node.Id {
            return self.data.root;
        }

        pub fn get(self: *Self, index: usize) !Element {
            return try self.data.get(index, length);
        }

        pub fn set(self: *Self, index: usize, value: Element) !void {
            return try self.data.set(index, value, length);
        }

        /// Caller must free the returned slice.
        pub fn toBoolArray(self: *Self, allocator: Allocator) ![]bool {
            const values = try allocator.alloc(bool, length);
            errdefer allocator.free(values);
            try self.toBoolArrayInto(values);
            return values;
        }

        pub fn toBoolArrayInto(self: *Self, out: []bool) !void {
            try self.data.fillBools(out, length);
        }
    };

    assertTreeViewType(TreeView);
    return TreeView;
}
