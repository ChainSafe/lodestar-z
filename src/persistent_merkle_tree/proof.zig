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

pub const ProofType = enum {
    single,
    compactMulti,

    pub fn toString(self: ProofType) []const u8 {
        return switch (self) {
            .single => "single",
            .compactMulti => "compactMulti",
        };
    }
};

/// Input for creating a single proof
pub const SingleProofInput = struct {
    gindex: Gindex,
};

/// Input for creating a compact multi proof
pub const CompactMultiProofInput = struct {
    descriptor: []const u8,
};

pub const ProofInput = union(ProofType) {
    single: SingleProofInput,
    compactMulti: CompactMultiProofInput,
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
            pool.createBranch(node_id, sibling_id)
        else
            pool.createBranch(sibling_id, node_id);

        index_value >>= 1;
    }

    // Raise the reference count so callers own the result.
    try pool.ref(node_id);
    return node_id;
}

/// Creates a proof based on the input type.
pub fn createProof(
    allocator: Allocator,
    pool: *Node.Pool,
    root: Node.Id,
    input: ProofInput,
) (Node.Error || Error)!Proof {
    switch (input) {
        .single => |single_input| {
            const single_proof = try createSingleProof(allocator, pool, root, single_input.gindex);
            return Proof{
                .single = .{
                    .gindex = single_input.gindex,
                    .leaf = single_proof.leaf,
                    .witnesses = single_proof.witnesses,
                },
            };
        },
        .compactMulti => |compact_input| {
            const leaves = try createCompactMultiProof(allocator, pool, root, compact_input.descriptor);
            return Proof{
                .compactMulti = .{
                    .leaves = leaves,
                    .descriptor = compact_input.descriptor,
                },
            };
        },
    }
}

/// Compact multi-proof result
pub const CompactMultiProof = struct {
    leaves: [][32]u8,
    descriptor: []u8,

    pub fn deinit(self: *CompactMultiProof, allocator: Allocator) void {
        allocator.free(self.leaves);
        allocator.free(self.descriptor);
        self.* = undefined;
    }
};

pub const Proof = union(ProofType) {
    single: struct {
        gindex: Gindex,
        leaf: [32]u8,
        witnesses: [][32]u8,
    },
    compactMulti: struct {
        leaves: [][32]u8,
        descriptor: []const u8,
    },

    pub fn deinit(self: *Proof, allocator: Allocator) void {
        switch (self.*) {
            .single => |*s| allocator.free(s.witnesses),
            .compactMulti => |*c| allocator.free(c.leaves),
        }
        self.* = undefined;
    }
};

/// Convert gindex to bitstring
fn convertGindexToBitstring(allocator: Allocator, gindex: Gindex) ![]const u8 {
    const value = @intFromEnum(gindex);
    if (value < 1) return error.InvalidGindex;

    return std.fmt.allocPrint(allocator, "{b}", .{value});
}

/// Compute proof bitstrings (path and branch) for a gindex bitstring
/// Matches computeProofBitstrings from util.ts
fn computeProofBitstrings(allocator: Allocator, bitstring: []const u8) !struct { path: std.StringHashMap(void), branch: std.StringHashMap(void) } {
    var path = std.StringHashMap(void).init(allocator);
    errdefer path.deinit();
    var branch = std.StringHashMap(void).init(allocator);
    errdefer branch.deinit();

    var g = bitstring;
    while (g.len > 1) {
        // Add current to path
        const path_key = try allocator.dupe(u8, g);
        try path.put(path_key, {});

        // Get last bit and parent (remove last bit)
        const last_bit = g[g.len - 1];
        const parent = g[0 .. g.len - 1];

        const sibling_bit: u8 = if (last_bit == '0') '1' else '0';
        const sibling = try allocator.alloc(u8, parent.len + 1);
        @memcpy(sibling[0..parent.len], parent);
        sibling[parent.len] = sibling_bit;
        try branch.put(sibling, {});

        // Move to parent
        g = parent;
    }

    return .{ .path = path, .branch = branch };
}

/// Add string to HashMap (Set) if not already present
fn addToSet(set: *std.StringHashMap(void), allocator: Allocator, value: []const u8) !void {
    if (!set.contains(value)) {
        const key = try allocator.dupe(u8, value);
        try set.put(key, {});
    }
}

/// Free all keys in a HashMap and deinit
fn freeSetKeys(set: *std.StringHashMap(void), allocator: Allocator) void {
    var iter = set.keyIterator();
    while (iter.next()) |key| {
        allocator.free(key.*);
    }
    set.deinit();
}

/// Compute descriptor from gindices
/// See https://github.com/ethereum/consensus-specs/blob/dev/ssz/merkle-proofs.md
pub fn computeDescriptor(allocator: Allocator, gindices: []const Gindex) ![]u8 {
    if (gindices.len == 0) return &[_]u8{};

    var proof_bitstrings = std.StringHashMap(void).init(allocator);
    defer freeSetKeys(&proof_bitstrings, allocator);

    var path_bitstrings = std.StringHashMap(void).init(allocator);
    defer freeSetKeys(&path_bitstrings, allocator);

    // Collect all proof and path bitstrings
    for (gindices) |gindex| {
        const leaf_bitstring = try convertGindexToBitstring(allocator, gindex);
        defer allocator.free(leaf_bitstring);

        try addToSet(&proof_bitstrings, allocator, leaf_bitstring);

        var proof_result = try computeProofBitstrings(allocator, leaf_bitstring);
        defer freeSetKeys(&proof_result.path, allocator);
        defer freeSetKeys(&proof_result.branch, allocator);

        // Remove leaf from path
        if (proof_result.path.fetchRemove(leaf_bitstring)) |removed| {
            allocator.free(removed.key);
        }

        // Add path indices to path_bitstrings
        var path_iter = proof_result.path.keyIterator();
        while (path_iter.next()) |key| {
            try addToSet(&path_bitstrings, allocator, key.*);
        }

        // Add branch indices to proof_bitstrings
        var branch_iter = proof_result.branch.keyIterator();
        while (branch_iter.next()) |key| {
            try addToSet(&proof_bitstrings, allocator, key.*);
        }
    }

    // Remove all path bitstrings from proof bitstrings
    var path_iter = path_bitstrings.keyIterator();
    while (path_iter.next()) |key| {
        if (proof_bitstrings.fetchRemove(key.*)) |removed| {
            allocator.free(removed.key);
        }
    }

    // Sort bitstrings lexicographically
    var sorted_list = std.ArrayList([]const u8).init(allocator);
    defer sorted_list.deinit();

    var proof_iter = proof_bitstrings.keyIterator();
    while (proof_iter.next()) |key| {
        try sorted_list.append(key.*);
    }

    const bitstringLessThan = struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan;

    std.sort.pdq([]const u8, sorted_list.items, {}, bitstringLessThan);

    // Convert gindex bitstrings into descriptor bitstring
    var descriptor_bitstring = std.ArrayList(u8).init(allocator);
    defer descriptor_bitstring.deinit();

    for (sorted_list.items) |gindex_bitstring| {
        // Find the rightmost '1' bit
        var i: usize = 0;
        while (i < gindex_bitstring.len) : (i += 1) {
            const rev_idx = gindex_bitstring.len - 1 - i;
            if (gindex_bitstring[rev_idx] == '1') {
                for (0..i) |_| {
                    try descriptor_bitstring.append('0');
                }
                try descriptor_bitstring.append('1');
                break;
            }
        }
    }

    // Byte-align by padding with zeros
    const remainder = descriptor_bitstring.items.len % 8;
    if (remainder != 0) {
        const padding = 8 - remainder;
        for (0..padding) |_| {
            try descriptor_bitstring.append('0');
        }
    }

    // Convert bitstring to bytes
    const byte_len = descriptor_bitstring.items.len / 8;
    var descriptor = try allocator.alloc(u8, byte_len);
    errdefer allocator.free(descriptor);

    for (0..byte_len) |i| {
        var byte: u8 = 0;
        for (0..8) |bit_idx| {
            const char = descriptor_bitstring.items[i * 8 + bit_idx];
            if (char == '1') {
                byte |= @as(u8, 0x80) >> @intCast(bit_idx);
            }
        }
        descriptor[i] = byte;
    }

    return descriptor;
}

/// Get a bit from a byte array at the given bit index
fn getBit(bitlist: []const u8, bit_index: usize) bool {
    const byte_idx = bit_index / 8;
    const bit_idx = @as(u3, @intCast(bit_index % 8));
    const byte = bitlist[byte_idx];
    return (byte & (@as(u8, 0x80) >> bit_idx)) != 0;
}

/// Convert descriptor bytes to bitlist
pub fn descriptorToBitlist(allocator: Allocator, descriptor: []const u8) ![]bool {
    var bools = std.ArrayList(bool).init(allocator);
    errdefer bools.deinit();

    const max_bit_length = descriptor.len * 8;
    var count0: usize = 0;
    var count1: usize = 0;

    var i: usize = 0;
    while (i < max_bit_length) : (i += 1) {
        const bit = getBit(descriptor, i);
        try bools.append(bit);

        if (bit) {
            count1 += 1;
        } else {
            count0 += 1;
        }

        if (count1 > count0) {
            i += 1;
            // Verify remaining bits are all zero (padding)
            if (i + 7 < max_bit_length) {
                return error.InvalidWitnessLength;
            }
            while (i < max_bit_length) : (i += 1) {
                if (getBit(descriptor, i)) {
                    return error.InvalidWitnessLength;
                }
            }
            return bools.toOwnedSlice();
        }
    }

    return error.InvalidWitnessLength;
}

/// Recursively extract leaves from node using bitlist
fn nodeToCompactMultiProof(
    allocator: Allocator,
    pool: *Node.Pool,
    node_id: Node.Id,
    bitlist: []const bool,
    bit_index: usize,
) (Node.Error || Error)![][32]u8 {
    // If bit is 1, this node is a leaf in the proof
    if (bitlist[bit_index]) {
        const leaves = try allocator.alloc([32]u8, 1);
        leaves[0] = node_id.getRoot(pool).*;
        return leaves;
    }

    // Otherwise, recurse into children
    const left_id = try node_id.getLeft(pool);
    const left = try nodeToCompactMultiProof(allocator, pool, left_id, bitlist, bit_index + 1);
    defer allocator.free(left);

    const right_id = try node_id.getRight(pool);
    const right = try nodeToCompactMultiProof(allocator, pool, right_id, bitlist, bit_index + left.len * 2);
    defer allocator.free(right);

    const result = try allocator.alloc([32]u8, left.len + right.len);
    @memcpy(result[0..left.len], left);
    @memcpy(result[left.len..], right);
    return result;
}

/// Creates a compact multiproof for the given descriptor.
pub fn createCompactMultiProof(
    allocator: Allocator,
    pool: *Node.Pool,
    root: Node.Id,
    descriptor: []const u8,
) (Node.Error || Error)![][32]u8 {
    const bitlist = try descriptorToBitlist(allocator, descriptor);
    defer allocator.free(bitlist);

    return nodeToCompactMultiProof(allocator, pool, root, bitlist, 0);
}

/// Pointer to track position in bitlist and leaves during reconstruction
const MultiProofPointer = struct {
    bit_index: usize,
    leaf_index: usize,
};

/// Recursively build a node from a bitlist and leaves
fn compactMultiProofToNode(
    pool: *Node.Pool,
    bitlist: []const bool,
    leaves: [][32]u8,
    pointer: *MultiProofPointer,
) Node.Error!Node.Id {
    if (bitlist[pointer.bit_index]) {
        pointer.bit_index += 1;
        const leaf = try pool.createLeaf(&leaves[pointer.leaf_index]);
        pointer.leaf_index += 1;
        return leaf;
    }

    pointer.bit_index += 1;
    const left = try compactMultiProofToNode(pool, bitlist, leaves, pointer);
    const right = try compactMultiProofToNode(pool, bitlist, leaves, pointer);
    return pool.createBranch(left, right);
}

/// Create a Node from a compact multiproof
pub fn createNodeFromCompactMultiProof(
    pool: *Node.Pool,
    leaves: [][32]u8,
    descriptor: []const u8,
) (Node.Error || Error)!Node.Id {
    var arena = std.heap.ArenaAllocator.init(pool.allocator);
    defer arena.deinit();
    const temp_allocator = arena.allocator();

    const bitlist = try descriptorToBitlist(temp_allocator, descriptor);

    if (bitlist.len != leaves.len * 2 - 1) {
        return error.InvalidWitnessLength;
    }

    var pointer = MultiProofPointer{ .bit_index = 0, .leaf_index = 0 };
    const node = try compactMultiProofToNode(pool, bitlist, leaves, &pointer);

    try pool.ref(node);
    return node;
}
