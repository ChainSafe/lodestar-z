const std = @import("std");
const pmt = @import("persistent_merkle_tree");
const Node = pmt.Node;
const ChunkedLeaf = pmt.ChunkedLeaf;
const Depth = @import("hashing").Depth;

const max_subtrees = @min((@import("hashing").max_depth - 1) / 3, (@bitSizeOf(usize) - 1) / 2) + 1;
const max_chunks = blk: {
    var total: usize = 0;
    for (0..max_subtrees) |i| total += @as(usize, 1) << @intCast(2 * i);
    break :blk total;
};
const zero_bytes: [ChunkedLeaf.K * 32]u8 = @splat(0);

/// Borrows consecutive bytes from stored leaves. Pool mutations invalidate returned slices.
pub const Iterator = struct {
    pool: *Node.Pool,
    spine: Node.Id,
    remaining: usize,
    subtree_remaining: usize = 0,
    subtree_index: usize = 0,
    leaf_offset: Depth = 0,
    iterator: Node.DepthIterator = undefined,

    pub fn init(pool: *Node.Pool, root: Node.Id, count: usize) !Iterator {
        if (count > max_chunks) return error.InvalidSubtreeLength;
        return .{ .pool = pool, .spine = root, .remaining = count };
    }

    pub fn next(self: *Iterator) !?[]const u8 {
        if (self.remaining == 0) {
            if (!std.mem.eql(u8, self.spine.getRoot(self.pool), zero_bytes[0..32])) {
                return error.InvalidTerminatorNode;
            }
            return null;
        }
        if (self.subtree_remaining == 0) {
            const depth: Depth = @intCast(2 * self.subtree_index);
            const capacity = @as(usize, 1) << @intCast(depth);
            self.leaf_offset = if (depth >= ChunkedLeaf.k_log2) ChunkedLeaf.k_log2 else 0;
            const root = if (@intFromEnum(self.spine) == 0)
                @as(Node.Id, @enumFromInt(depth))
            else blk: {
                const left = try self.spine.getLeft(self.pool);
                self.spine = try self.spine.getRight(self.pool);
                break :blk left;
            };
            self.iterator = Node.DepthIterator.init(self.pool, root, depth - self.leaf_offset, 0);
            self.subtree_remaining = @min(capacity, self.remaining);
            self.subtree_index += 1;
        }
        const node = try self.iterator.next();
        const count = @min(@as(usize, 1) << @intCast(self.leaf_offset), self.subtree_remaining);
        self.subtree_remaining -= count;
        self.remaining -= count;
        if (self.pool.nodes.items(.state)[@intFromEnum(node)].kind() == .zero) {
            return zero_bytes[0 .. count * 32];
        }
        if (self.leaf_offset == 0) return node.getRoot(self.pool);
        const chunks = try node.getChunkedLeafChunks(self.pool);
        return @as([*]const u8, @ptrCast(chunks))[0 .. count * 32];
    }
};

pub fn fromValue(comptime Element: type, pool: *Node.Pool, values: []const Element.Type) !Node.Id {
    return build(Element, false, pool, values);
}

pub fn fromBytes(comptime Element: type, pool: *Node.Pool, bytes: []const u8) !Node.Id {
    return build(Element, true, pool, bytes);
}

fn build(comptime Element: type, comptime serialized: bool, pool: *Node.Pool, input: anytype) !Node.Id {
    const len = if (serialized) input.len / Element.fixed_size else input.len;
    const items_per_chunk = 32 / Element.fixed_size;
    const chunk_count = len / items_per_chunk + @intFromBool(len % items_per_chunk != 0);
    if (chunk_count > max_chunks) return error.InputTooLong;

    var roots: [max_subtrees]Node.Id = undefined;
    var root_count: usize = 0;
    errdefer for (roots[0..root_count]) |root| pool.unref(root);
    var item_index: usize = 0;
    for (0..max_subtrees) |subtree_index| {
        if (item_index == len) break;
        const depth: Depth = @intCast(2 * subtree_index);
        const leaf_offset: Depth = if (depth >= ChunkedLeaf.k_log2) ChunkedLeaf.k_log2 else 0;
        const capacity = @as(usize, 1) << @intCast(depth);
        const subtree_chunks = @min(capacity, chunk_count - item_index / items_per_chunk);
        const chunks_per_leaf = @as(usize, 1) << @intCast(leaf_offset);
        const leaf_count = (subtree_chunks + chunks_per_leaf - 1) / chunks_per_leaf;
        var it = Node.FillWithContentsIterator.initWithOffset(pool, depth - leaf_offset, leaf_offset);
        errdefer it.deinit();
        for (0..leaf_count) |_| {
            const count = @min(chunks_per_leaf * items_per_chunk, len - item_index);
            const leaf = if (leaf_offset == 0)
                try pool.createLeaf(&@as([32]u8, @splat(0)))
            else
                try pool.createChunkedLeafEmpty(@intCast((count + items_per_chunk - 1) / items_per_chunk));
            {
                errdefer pool.unref(leaf);
                const bytes: []u8 = if (leaf_offset == 0)
                    &pool.nodes.items(.root)[@intFromEnum(leaf)]
                else
                    @as([*]u8, @ptrCast(&(try leaf.getChunkedLeafPtr(pool)).chunks))[0 .. ChunkedLeaf.K * 32];
                if (serialized) {
                    @memcpy(bytes[0 .. count * Element.fixed_size], input[item_index * Element.fixed_size ..][0 .. count * Element.fixed_size]);
                } else if (comptime @import("type_kind.zig").canMemcpySsz(Element)) {
                    @memcpy(bytes[0 .. count * Element.fixed_size], std.mem.sliceAsBytes(input[item_index..][0..count]));
                } else {
                    for (input[item_index..][0..count], 0..) |*element, i| {
                        _ = Element.serializeIntoBytes(element, bytes[i * Element.fixed_size ..][0..Element.fixed_size]);
                    }
                }
            }
            // append consumes the fresh node even if branch allocation fails.
            try it.append(leaf);
            item_index += count;
        }
        roots[root_count] = try it.finish();
        root_count += 1;
    }
    std.debug.assert(item_index == len);
    var contents: Node.Id = @enumFromInt(0);
    errdefer pool.unref(contents);
    while (root_count > 0) {
        contents = try pool.createBranch(roots[root_count - 1], contents);
        root_count -= 1;
    }
    const length_leaf = try pool.createLeafFromUint(len);
    errdefer pool.unref(length_leaf);
    return pool.createBranch(contents, length_leaf);
}
