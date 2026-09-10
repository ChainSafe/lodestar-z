const std = @import("std");
const hashOne = @import("hashing").hashOne;
const Depth = @import("hashing").Depth;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;

const base_count = 1;
const scaling_factor = 4;

pub fn chunkGindex(chunk_i: usize) Gindex {
    const subtree_i = subtreeIndex(chunk_i);
    var gindex: Gindex.Uint = 1;
    var subtree_starting_index = 0;
    for (0..subtree_i) |i| {
        gindex = gindex * 2 + 1;
        subtree_starting_index += subtreeLength(i);
    }

    gindex *= 2;
    gindex *= try std.math.powi(usize, 2, subtreeDepth(subtree_i));
    gindex += chunk_i - subtree_starting_index;
    return @enumFromInt(gindex);
}

pub fn subtreeIndex(chunk_i: usize) usize {
    var left: usize = chunk_i;
    var subtree_length: usize = base_count;
    var subtree_i: usize = 0;
    while (left > 0) {
        left -|= subtree_length;
        subtree_length *= scaling_factor;
        subtree_i += 1;
    }
    return subtree_i;
}

pub fn subtreeLength(subtree_i: usize) usize {
    return std.math.pow(usize, scaling_factor, subtree_i);
}

pub fn subtreeDepth(subtree_i: usize) Depth {
    return @intCast(subtree_i * std.math.log2_int(usize, scaling_factor));
}

pub fn merkleizeChunksComptime(comptime chunk_count: usize, chunks: *const [chunk_count][32]u8, out: *[32]u8) !void {
    return merkleizeChunksBounded(chunks, out);
}

pub fn merkleizeChunks(_: std.mem.Allocator, chunks: [][32]u8, out: *[32]u8) !void {
    return merkleizeChunksBounded(chunks, out);
}

fn merkleizeChunksBounded(chunks: []const [32]u8, out: *[32]u8) !void {
    const max_subtrees = @min(@import("hashing").max_depth, @bitSizeOf(usize) - 1) / 2 + 1;
    const max_chunks = comptime blk: {
        var count: usize = 0;
        for (0..max_subtrees) |i| count += @as(usize, 1) << @intCast(2 * i);
        break :blk count;
    };
    if (chunks.len > max_chunks) return error.InputTooLong;

    var subtree_roots: [max_subtrees][32]u8 = undefined;
    var subtree_count: usize = 0;
    var start: usize = 0;
    for (0..max_subtrees) |i| {
        if (start == chunks.len) break;
        const subtree_length = @as(usize, 1) << @intCast(2 * i);
        const end = start + @min(subtree_length, chunks.len - start);
        var accumulator = @import("hashing").MerkleAccumulator.init(@intCast(2 * i));
        for (chunks[start..end]) |*chunk| try accumulator.append(chunk);
        try accumulator.finish(&subtree_roots[i]);
        subtree_count += 1;
        start = end;
    }
    std.debug.assert(start == chunks.len);

    out.* = @splat(0);
    while (subtree_count > 0) {
        subtree_count -= 1;
        hashOne(out, &subtree_roots[subtree_count], out);
    }
}

pub fn getNodes(pool: *Node.Pool, root: Node.Id, out: []Node.Id) !void {
    const subtree_count = subtreeIndex(out.len);
    var n = root;
    var l: usize = 0;
    for (0..subtree_count) |subtree_i| {
        const subtree_length = @min(subtreeLength(subtree_i), out.len - l);
        const subtree_depth = subtreeDepth(subtree_i);
        const subtree_root = n.getLeft(pool) catch |err| {
            if (@intFromEnum(n) == 0) {
                for (l..l + subtree_length) |pos| {
                    if (pos < out.len) {
                        out[pos] = @enumFromInt(0);
                    }
                }
                l += subtree_length;
                n = @enumFromInt(0);
                continue;
            }
            return err;
        };
        if (subtree_depth == 0) {
            if (subtree_length != 1) {
                return error.InvalidSubtreeLength;
            }
            out[l] = subtree_root;
        } else {
            try subtree_root.getNodesAtDepth(pool, subtree_depth, 0, out[l .. l + subtree_length]);
        }
        l += subtree_length;
        n = try n.getRight(pool);
    }

    if (!std.mem.eql(u8, &n.getRoot(pool).*, &[_]u8{0} ** 32)) {
        return error.InvalidTerminatorNode;
    }
}

pub fn fillWithContentsComptime(comptime node_count: usize, pool: *Node.Pool, nodes: *const [node_count]Node.Id) !Node.Id {
    const subtree_count = comptime subtreeIndex(node_count);
    var n: Node.Id = @enumFromInt(0);
    errdefer pool.unref(n);

    // Compute subtree starts at comptime
    comptime var subtree_starts: [subtree_count]usize = undefined;
    comptime {
        var pos: usize = 0;
        for (0..subtree_count) |subtree_i| {
            subtree_starts[subtree_i] = pos;
            pos += @min(subtreeLength(subtree_i), node_count - pos);
        }
    }

    // Process subtrees in reverse order
    comptime var i: usize = 0;
    inline while (i < subtree_count) : (i += 1) {
        const subtree_i = subtree_count - 1 - i;
        const st_depth = comptime subtreeDepth(subtree_i);
        const l = comptime subtree_starts[subtree_i];
        const st_length = comptime @min(subtreeLength(subtree_i), node_count - l);

        const subtree_root = try Node.fillWithContents(pool, @constCast(nodes[l..][0..st_length]), st_depth);
        n = try pool.createBranch(subtree_root, n);
    }

    return n;
}

pub fn fillWithContents(allocator: std.mem.Allocator, pool: *Node.Pool, nodes: []Node.Id) !Node.Id {
    const subtree_count = subtreeIndex(nodes.len);
    var n: Node.Id = @enumFromInt(0);
    errdefer pool.unref(n);

    var subtree_starts = std.ArrayList(usize).empty;
    defer subtree_starts.deinit(allocator);
    var pos: usize = 0;
    for (0..subtree_count) |subtree_i| {
        try subtree_starts.append(allocator, pos);
        pos += @min(subtreeLength(subtree_i), nodes.len - pos);
    }

    for (0..subtree_count) |i| {
        const subtree_i = subtree_count - 1 - i;
        const subtree_depth = subtreeDepth(subtree_i);
        const l = subtree_starts.items[subtree_i];
        const subtree_length = @min(subtreeLength(subtree_i), nodes.len - l);

        const subtree_root = try Node.fillWithContents(pool, nodes[l .. l + subtree_length], subtree_depth);
        n = try pool.createBranch(subtree_root, n);
    }

    return n;
}

test {
    _ = @import("progressive_test.zig");
}
