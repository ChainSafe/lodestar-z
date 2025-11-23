const std = @import("std");
const Allocator = std.mem.Allocator;

const GindexUint = @import("hashing").GindexUint;
const Node = @import("Node.zig");
const Gindex = @import("gindex.zig").Gindex;

const root_gindex_value: GindexUint = 1;

pub const Error = error{
    /// Allocator or pool could not reserve enough memory.
    OutOfMemory,
    /// Provided generalized index is not part of the binary tree (must be >= 1).
    InvalidGindex,
    /// Witness list length does not match the gindex path length.
    InvalidWitnessLength,
};

pub const SingleProof = struct {
    leaf: [32]u8,
    witnesses: [][32]u8,

    pub fn deinit(self: *SingleProof, allocator: Allocator) void {
        allocator.free(self.witnesses);
        self.* = undefined;
    }
};

/// Produces a single Merkle proof for the node at `gindex`.
pub fn createSingleProof(
    allocator: Allocator,
    pool: *Node.Pool,
    root: Node.Id,
    gindex: Gindex,
) (Node.Error || Error)!SingleProof {
    if (@intFromEnum(gindex) < root_gindex_value) {
        return error.InvalidGindex;
    }

    const path_len = gindex.pathLen();
    var witnesses = try allocator.alloc([32]u8, path_len);
    errdefer allocator.free(witnesses);

    if (path_len == 0) {
        return SingleProof{
            .leaf = root.getRoot(pool).*,
            .witnesses = witnesses,
        };
    }

    var node_id = root;
    var path = gindex.toPath();

    for (0..path_len) |depth_idx| {
        const witness_index = path_len - 1 - depth_idx;

        if (path.left()) {
            const right_id = try node_id.getRight(pool);
            witnesses[witness_index] = right_id.getRoot(pool).*;
            node_id = try node_id.getLeft(pool);
        } else {
            const left_id = try node_id.getLeft(pool);
            witnesses[witness_index] = left_id.getRoot(pool).*;
            node_id = try node_id.getRight(pool);
        }

        path.next();
    }

    return SingleProof{
        .leaf = node_id.getRoot(pool).*,
        .witnesses = witnesses,
    };
}

/// Build a fresh node tree from a single Merkle proof.
pub fn createNodeFromSingleProof(
    pool: *Node.Pool,
    gindex: Gindex,
    leaf: [32]u8,
    witnesses: []const [32]u8,
) (Node.Error || Error)!Node.Id {
    if (@intFromEnum(gindex) < root_gindex_value) {
        return error.InvalidGindex;
    }

    const path_len = gindex.pathLen();
    if (witnesses.len != path_len) {
        return error.InvalidWitnessLength;
    }

    var node_id = try pool.createLeaf(&leaf);
    errdefer pool.unref(node_id);
    var index_value: GindexUint = @intFromEnum(gindex);

    for (witnesses) |witness| {
        const sibling_id = try pool.createLeaf(&witness);
        errdefer pool.unref(sibling_id);

        node_id = try if ((index_value & 1) == 0)
            pool.createBranchTransfer(node_id, sibling_id)
        else
            pool.createBranchTransfer(sibling_id, node_id);

        index_value >>= 1;
    }

    return node_id;
}
