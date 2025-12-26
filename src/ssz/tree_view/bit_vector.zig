const std = @import("std");
const Allocator = std.mem.Allocator;

const hashing = @import("hashing");
const Depth = hashing.Depth;

const Node = @import("persistent_merkle_tree").Node;

const BaseTreeView = @import("root.zig").BaseTreeView;
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
        base_view: BaseTreeView,

        pub const SszType = ST;
        pub const Element = bool;
        pub const length = ST.length;

        const Self = @This();

        const chunk_depth: Depth = @intCast(ST.chunk_depth);
        const BitOps = BitArray(chunk_depth);

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !Self {
            return Self{ .base_view = try BaseTreeView.init(allocator, pool, root) };
        }

        pub fn deinit(self: *Self) void {
            self.base_view.deinit();
        }

        pub fn commit(self: *Self) !void {
            try self.base_view.commit();
        }

        pub fn clearCache(self: *Self) void {
            self.base_view.clearCache();
        }

        pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void {
            try self.base_view.hashTreeRoot(out);
        }

        pub fn get(self: *Self, index: usize) !Element {
            return BitOps.get(&self.base_view, index, length);
        }

        pub fn set(self: *Self, index: usize, value: Element) !void {
            return BitOps.set(&self.base_view, index, value, length);
        }

        /// Caller must free the returned slice.
        pub fn toBoolArray(self: *Self, allocator: Allocator) ![]bool {
            const values = try allocator.alloc(bool, length);
            errdefer allocator.free(values);
            try self.toBoolArrayInto(values);
            return values;
        }

        pub fn toBoolArrayInto(self: *Self, out: []bool) !void {
            try BitOps.fillBools(&self.base_view, out, length);
        }
    };
}
