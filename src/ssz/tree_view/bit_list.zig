const std = @import("std");
const Allocator = std.mem.Allocator;

const hashing = @import("hashing");
const Depth = hashing.Depth;

const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;

const type_root = @import("../type/root.zig");
const chunkDepth = type_root.chunkDepth;

const BaseTreeView = @import("root.zig").BaseTreeView;

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
        const bits_per_chunk: usize = 256;

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
            if (index >= list_length) return error.IndexOutOfBounds;

            const chunk_index = index / bits_per_chunk;
            const bit_in_chunk = index % bits_per_chunk;
            const byte_in_chunk = bit_in_chunk / 8;
            const bit_in_byte: u3 = @intCast(bit_in_chunk % 8);

            const leaf_node = try self.base_view.getChildNode(Gindex.fromDepth(chunk_depth, chunk_index));
            const leaf = leaf_node.getRoot(self.base_view.pool);
            const mask = @as(u8, 1) << bit_in_byte;
            return (leaf[byte_in_chunk] & mask) != 0;
        }

        pub fn set(self: *Self, index: usize, value: Element) !void {
            const list_length = try self.readLength();
            if (index >= list_length) return error.IndexOutOfBounds;

            const chunk_index = index / bits_per_chunk;
            const bit_in_chunk = index % bits_per_chunk;
            const byte_in_chunk = bit_in_chunk / 8;
            const bit_in_byte: u3 = @intCast(bit_in_chunk % 8);

            const gindex = Gindex.fromDepth(chunk_depth, chunk_index);
            const leaf_node = try self.base_view.getChildNode(gindex);
            var leaf_bytes = leaf_node.getRoot(self.base_view.pool).*;

            const mask = @as(u8, 1) << bit_in_byte;
            if (value) {
                leaf_bytes[byte_in_chunk] |= mask;
            } else {
                leaf_bytes[byte_in_chunk] &= ~mask;
            }

            const new_leaf = try self.base_view.pool.createLeaf(&leaf_bytes);
            try self.base_view.setChildNode(gindex, new_leaf);
        }

        /// Caller must free the returned slice.
        pub fn toBoolArray(self: *Self, allocator: Allocator) ![]bool {
            const list_length = try self.readLength();
            const values = try allocator.alloc(bool, list_length);
            errdefer allocator.free(values);
            try self.fillBools(values, list_length);
            return values;
        }

        pub fn toBoolArrayInto(self: *Self, out: []bool) !void {
            const list_length = try self.readLength();
            if (out.len != list_length) return error.InvalidSize;
            try self.fillBools(out, list_length);
        }

        fn fillBools(self: *Self, values: []bool, list_length: usize) !void {
            if (values.len != list_length) return error.InvalidSize;
            if (list_length == 0) return;

            const full_chunks = list_length / bits_per_chunk;
            const remainder_bits = list_length % bits_per_chunk;
            var dest = values;

            for (0..full_chunks) |chunk_idx| {
                const leaf_node = try self.base_view.getChildNode(Gindex.fromDepth(chunk_depth, chunk_idx));
                const leaf = leaf_node.getRoot(self.base_view.pool);

                for (leaf) |b| {
                    inline for (0..8) |j| {
                        dest[j] = (b & (@as(u8, 1) << j)) != 0;
                    }
                    dest = dest[8..];
                }
            }

            if (remainder_bits != 0) {
                const leaf_node = try self.base_view.getChildNode(Gindex.fromDepth(chunk_depth, full_chunks));
                const leaf = leaf_node.getRoot(self.base_view.pool);

                const full_bytes = remainder_bits / 8;
                const tail_bits = remainder_bits % 8;

                for (leaf[0..full_bytes]) |b| {
                    inline for (0..8) |j| {
                        dest[j] = (b & (@as(u8, 1) << j)) != 0;
                    }
                    dest = dest[8..];
                }

                if (tail_bits > 0) {
                    const b = leaf[full_bytes];
                    for (0..tail_bits) |j| {
                        dest[j] = (b & (@as(u8, 1) << @intCast(j))) != 0;
                    }
                }
            }
        }
    };
}
