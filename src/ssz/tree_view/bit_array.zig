
const hashing = @import("hashing");
const Depth = hashing.Depth;

const Gindex = @import("persistent_merkle_tree").Gindex;

const BaseTreeView = @import("root.zig").BaseTreeView;

/// Provides common bit array operations for both BitVectorTreeView and BitListTreeView.
pub fn BitArray(comptime chunk_depth: Depth) type {
    return struct {
        const bits_per_chunk: usize = 256;

        pub fn get(base_view: *BaseTreeView, index: usize, len: usize) !bool {
            if (index >= len) return error.IndexOutOfBounds;

            const chunk_index = index / bits_per_chunk;
            const bit_in_chunk = index % bits_per_chunk;
            const byte_in_chunk = bit_in_chunk / 8;
            const bit_in_byte: u3 = @intCast(bit_in_chunk % 8);

            const leaf_node = try base_view.getChildNode(Gindex.fromDepth(chunk_depth, chunk_index));
            const leaf = leaf_node.getRoot(base_view.pool);
            const mask = @as(u8, 1) << bit_in_byte;
            return (leaf[byte_in_chunk] & mask) != 0;
        }

        pub fn set(base_view: *BaseTreeView, index: usize, value: bool, len: usize) !void {
            if (index >= len) return error.IndexOutOfBounds;

            const chunk_index = index / bits_per_chunk;
            const bit_in_chunk = index % bits_per_chunk;
            const byte_in_chunk = bit_in_chunk / 8;
            const bit_in_byte: u3 = @intCast(bit_in_chunk % 8);

            const gindex = Gindex.fromDepth(chunk_depth, chunk_index);
            const leaf_node = try base_view.getChildNode(gindex);
            var leaf_bytes = leaf_node.getRoot(base_view.pool).*;

            const mask = @as(u8, 1) << bit_in_byte;
            if (value) {
                leaf_bytes[byte_in_chunk] |= mask;
            } else {
                leaf_bytes[byte_in_chunk] &= ~mask;
            }

            const new_leaf = try base_view.pool.createLeaf(&leaf_bytes);
            try base_view.setChildNode(gindex, new_leaf);
        }

        pub fn fillBools(base_view: *BaseTreeView, values: []bool, len: usize) !void {
            if (values.len != len) return error.InvalidSize;
            if (len == 0) return;

            const full_chunks = len / bits_per_chunk;
            const remainder_bits = len % bits_per_chunk;
            var dest = values;

            for (0..full_chunks) |chunk_idx| {
                const leaf_node = try base_view.getChildNode(Gindex.fromDepth(chunk_depth, chunk_idx));
                const leaf = leaf_node.getRoot(base_view.pool);

                for (leaf) |b| {
                    inline for (0..8) |j| {
                        dest[j] = (b & (@as(u8, 1) << j)) != 0;
                    }
                    dest = dest[8..];
                }
            }

            if (remainder_bits != 0) {
                const leaf_node = try base_view.getChildNode(Gindex.fromDepth(chunk_depth, full_chunks));
                const leaf = leaf_node.getRoot(base_view.pool);

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
