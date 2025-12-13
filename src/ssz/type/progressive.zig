const std = @import("std");
const merkleize = @import("hashing").merkleize;
const mixInAux = @import("hashing").mixInAux;
const hashOne = @import("hashing").hashOne;
const Depth = @import("hashing").Depth;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;

const base_count = 1;
const scaling_factor = 4;

pub fn chunkGindex(chunk_i: usize) Gindex {
    const subtree_i = subtreeIndex(chunk_i);
    var i = subtree_i;
    var gindex: Gindex.Uint = 1;
    var subtree_starting_index = 0;
    while (i > 0) {
        i -= 1;
        gindex *= 2;
        subtree_starting_index += subtreeLength(i);
    }

    gindex += 1;

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

/// Comptime version of merkleizeChunks since we are not using allocator
pub fn merkleizeChunksComptime(comptime chunk_count: usize, chunks: *const [chunk_count][32]u8, out: *[32]u8) !void {
    if (chunk_count == 0) {
        out.* = [_]u8{0} ** 32;
        return;
    }

    const subtree_count = comptime subtreeIndex(chunk_count);
    var subtree_roots: [subtree_count][32]u8 = undefined;

    comptime var c_start: usize = 0;
    comptime var c_subtree_length: usize = base_count;
    inline for (0..subtree_count) |subtree_i| {
        const c_len = chunk_count - c_start;
        const subtree_length = c_subtree_length;
        if (c_len <= subtree_length) {
            var final_subtree_chunks: [subtree_length][32]u8 = undefined;
            @memcpy(final_subtree_chunks[0..c_len], chunks[c_start..][0..c_len]);
            @memset(final_subtree_chunks[c_len..], [_]u8{0} ** 32);

            const depth = comptime subtreeDepth(subtree_i);
            if (depth == 0) {
                subtree_roots[subtree_i] = final_subtree_chunks[0];
            } else {
                try merkleize(@ptrCast(&final_subtree_chunks), depth, &subtree_roots[subtree_i]);
            }
        } else {
            const depth = comptime subtreeDepth(subtree_i);
            if (depth == 0) {
                subtree_roots[subtree_i] = chunks[c_start];
            } else {
                try merkleize(@ptrCast(chunks[c_start..][0..subtree_length]), depth, &subtree_roots[subtree_i]);
            }
            c_start += subtree_length;
            c_subtree_length *= scaling_factor;
        }
    }

    out.* = [_]u8{0} ** 32;
    comptime var st_i = subtree_count;
    inline while (st_i > 0) {
        st_i -= 1;
        hashOne(out, out, &subtree_roots[st_i]);
    }
}

pub fn merkleizeChunks(allocator: std.mem.Allocator, chunks: [][32]u8, out: *[32]u8) !void {
    if (chunks.len == 0) {
        out.* = [_]u8{0} ** 32;
        return;
    }

    const subtree_count = subtreeIndex(chunks.len);
    const subtree_roots = try allocator.alloc([32]u8, subtree_count);
    defer allocator.free(subtree_roots);

    var c = chunks;
    var subtree_length: usize = base_count;
    for (0..subtree_count) |subtree_i| {
        if (c.len <= subtree_length) {
            const final_subtree_chunks = try allocator.alloc([32]u8, subtree_length);
            defer allocator.free(final_subtree_chunks);

            @memcpy(final_subtree_chunks[0..c.len], c);
            @memset(final_subtree_chunks[c.len..], [_]u8{0} ** 32);

            const depth = subtreeDepth(subtree_i);
            if (depth == 0) {
                subtree_roots[subtree_i] = final_subtree_chunks[0];
            } else {
                try merkleize(@ptrCast(final_subtree_chunks), depth, &subtree_roots[subtree_i]);
            }
        } else {
            const depth = subtreeDepth(subtree_i);
            if (depth == 0) {
                subtree_roots[subtree_i] = c[0];
            } else {
                try merkleize(@ptrCast(c[0..subtree_length]), depth, &subtree_roots[subtree_i]);
            }

            c = c[subtree_length..];
            subtree_length *= scaling_factor;
        }
    }
    out.* = [_]u8{0} ** 32;
    var subtree_i = subtree_count;
    while (subtree_i > 0) {
        subtree_i -= 1;
        hashOne(
            out,
            out,
            &subtree_roots[subtree_i],
        );
    }
}

pub fn getNodes(pool: *Node.Pool, root: Node.Id, out: []Node.Id) !void {
    const subtree_count = subtreeIndex(out.len);
    var n = root;
    var l: usize = 0;
    for (0..subtree_count) |subtree_i| {
        const subtree_length = @min(subtreeLength(subtree_i), out.len - l);
        const subtree_depth = subtreeDepth(subtree_i);
        const subtree_root = n.getRight(pool) catch |err| {
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
        n = try n.getLeft(pool);
    }

    if (!std.mem.eql(u8, &n.getRoot(pool).*, &[_]u8{0} ** 32)) {
        return error.InvalidTerminatorNode;
    }
}

pub fn fillWithContentsComptime(comptime node_count: usize, pool: *Node.Pool, nodes: *const [node_count]Node.Id) !Node.Id {
    const subtree_count = comptime subtreeIndex(node_count);
    var n: Node.Id = @enumFromInt(0);

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
        n = try pool.createBranch(n, subtree_root);
    }

    return n;
}

pub fn fillWithContents(allocator: std.mem.Allocator, pool: *Node.Pool, nodes: []Node.Id) !Node.Id {
    const subtree_count = subtreeIndex(nodes.len);
    var n: Node.Id = @enumFromInt(0);

    var subtree_starts = std.ArrayList(usize).init(allocator);
    defer subtree_starts.deinit();
    var pos: usize = 0;
    for (0..subtree_count) |subtree_i| {
        try subtree_starts.append(pos);
        pos += @min(subtreeLength(subtree_i), nodes.len - pos);
    }

    for (0..subtree_count) |i| {
        const subtree_i = subtree_count - 1 - i;
        const subtree_depth = subtreeDepth(subtree_i);
        const l = subtree_starts.items[subtree_i];
        const subtree_length = @min(subtreeLength(subtree_i), nodes.len - l);

        const subtree_root = try Node.fillWithContents(pool, nodes[l .. l + subtree_length], subtree_depth);
        n = try pool.createBranch(n, subtree_root);
    }

    return n;
}
