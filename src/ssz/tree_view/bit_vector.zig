const std = @import("std");
const Allocator = std.mem.Allocator;

const hashing = @import("hashing");
const Depth = hashing.Depth;

const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;

const BaseTreeView = @import("root.zig").BaseTreeView;

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
            try self.base_view.hashTreeRoot(out);
        }

        pub fn get(self: *Self, index: usize) !Element {
            if (index >= length) return error.IndexOutOfBounds;

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
            if (index >= length) return error.IndexOutOfBounds;

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
            const values = try allocator.alloc(bool, length);
            errdefer allocator.free(values);
            try self.toBoolArrayInto(values);
            return values;
        }

        pub fn toBoolArrayInto(self: *Self, out: []bool) !void {
            try self.fillBools(out);
        }

        fn fillBools(self: *Self, values: []bool) !void {
            if (values.len != length) return error.InvalidSize;
            if (length == 0) return;

            const full_chunks = length / bits_per_chunk;
            const remainder_bits = length % bits_per_chunk;
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
