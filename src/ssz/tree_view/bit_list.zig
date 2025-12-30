const std = @import("std");
const Allocator = std.mem.Allocator;

const hashing = @import("hashing");
const Depth = hashing.Depth;

const Node = @import("persistent_merkle_tree").Node;

const type_root = @import("../type/root.zig");
const chunkDepth = type_root.chunkDepth;

const BaseTreeView = @import("root.zig").BaseTreeView;
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
        base_view: BaseTreeView,

        pub const SszType = ST;
        pub const Element = bool;

        const Self = @This();

        const base_chunk_depth: Depth = @intCast(ST.chunk_depth);
        const chunk_depth: Depth = chunkDepth(Depth, base_chunk_depth, ST);
        const BitOps = BitArray(chunk_depth);

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !Self {
            return Self{ .base_view = try BaseTreeView.init(allocator, pool, root) };
        }

        pub fn clone(self: *Self, dont_transfer_cache: bool) !Self {
            return Self{ .base_view = try self.base_view.clone(dont_transfer_cache) };
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
            try self.commit();
            out.* = self.base_view.data.root.getRoot(self.base_view.pool).*;
        }

        fn readLength(self: *Self) !usize {
            const length_node = try self.base_view.getChildNode(@enumFromInt(3));
            const length_chunk = length_node.getRoot(self.base_view.pool);
            return std.mem.readInt(usize, length_chunk[0..@sizeOf(usize)], .little);
        }

        pub fn get(self: *Self, index: usize) !Element {
            const list_length = try self.readLength();
            return BitOps.get(&self.base_view, index, list_length);
        }

        pub fn set(self: *Self, index: usize, value: Element) !void {
            const list_length = try self.readLength();
            return BitOps.set(&self.base_view, index, value, list_length);
        }

        /// Caller must free the returned slice.
        pub fn toBoolArray(self: *Self, allocator: Allocator) ![]bool {
            const list_length = try self.readLength();
            const values = try allocator.alloc(bool, list_length);
            errdefer allocator.free(values);
            try BitOps.fillBools(&self.base_view, values, list_length);
            return values;
        }

        pub fn toBoolArrayInto(self: *Self, out: []bool) !void {
            const list_length = try self.readLength();
            if (out.len != list_length) return error.InvalidSize;
            try BitOps.fillBools(&self.base_view, out, list_length);
        }
    };
}
