///! Merkle node backed by a memory pool
const std = @import("std");
const Allocator = std.mem.Allocator;

const hashOne = @import("hashing").hashOne;
const getZeroHash = @import("hashing").getZeroHash;
const max_depth = @import("hashing").max_depth;
const Depth = @import("hashing").Depth;
const proof = @import("proof.zig");
const Gindex = @import("gindex.zig").Gindex;

hash: [32]u8,
left: Id,
right: Id,
state: State,

const Node = @This();

pub const Error = error{
    /// Attempt to access a child of a node that is not a branch node.
    InvalidNode,
    /// Attempt to use a length beyond the tree's length at a given depth.
    InvalidLength,
    // Attempt to increment the reference count of a node that has reached the maximum reference count.
    RefCountOverflow,
    // Out of memory
    OutOfMemory,
};

/// An enum which manages `node_type`, `ref_count`, and `next_free`.
/// Used by the Pool to manage the free list (single-linked-list) and reference count.
///
/// The high bit is used to indicate if the node is free or not.
/// If the high bit is set, the `next_free` is stored in the next 31 bits.
///
/// `[1, next_free]`
///
/// If the high bit is not set, the next two bits determine the `node_type`
/// The following 29 bits are used for the `ref_count`.
///
/// `[0, node_type, ref_count]`
pub const State = enum(u32) {
    _,

    pub const free: State = @enumFromInt(0x80000000);

    pub const max_next_free = 0x7FFFFFFF;

    // four types of nodes
    const node_type = 0x60000000;
    pub const zero: State = @enumFromInt(0x00000000);
    pub const leaf: State = @enumFromInt(0x20000000);
    pub const branch_lazy: State = @enumFromInt(0x40000000);
    pub const branch_computed: State = @enumFromInt(0x60000000);

    pub const max_ref_count = 0x1FFFFFFF;

    pub inline fn isFree(node: State) bool {
        return @intFromEnum(node) & @intFromEnum(free) != 0;
    }

    pub inline fn initNextFree(next_free: Id) State {
        return @enumFromInt(@intFromEnum(free) | @intFromEnum(next_free));
    }

    pub inline fn getNextFree(node: State) Id {
        return @enumFromInt(@intFromEnum(node) & max_next_free);
    }

    pub inline fn isZero(node: State) bool {
        return @intFromEnum(node) & node_type == @intFromEnum(zero);
    }

    pub inline fn isLeaf(node: State) bool {
        return @intFromEnum(node) & node_type == @intFromEnum(leaf);
    }

    pub inline fn isBranch(node: State) bool {
        return @intFromEnum(node) & @intFromEnum(branch_lazy) != 0;
    }

    pub inline fn isBranchLazy(node: State) bool {
        return @intFromEnum(node) & node_type == @intFromEnum(branch_lazy);
    }

    pub inline fn isBranchComputed(node: State) bool {
        return @intFromEnum(node) & node_type == @intFromEnum(branch_computed);
    }

    pub inline fn setBranchComputed(node: *State) void {
        node.* = @enumFromInt(@intFromEnum(node.*) | @intFromEnum(branch_computed));
    }

    pub inline fn initRefCount(node: State, should_ref: bool) State {
        return @enumFromInt(@intFromEnum(node) | @intFromBool(should_ref));
    }

    pub inline fn getRefCount(node: State) u32 {
        return @intFromEnum(node) & max_ref_count;
    }

    pub inline fn incRefCount(node: *State) Error!u32 {
        const ref_count = node.getRefCount();
        if (ref_count == max_ref_count) {
            return error.RefCountOverflow;
        }
        node.* = @enumFromInt(@intFromEnum(node.*) + 1);
        return ref_count + 1;
    }

    pub inline fn decRefCount(node: *State) u32 {
        const ref_count = node.getRefCount();
        if (ref_count == 0) {
            return 0;
        }
        node.* = @enumFromInt(@intFromEnum(node.*) - 1);
        return ref_count - 1;
    }
};

/// Stores nodes in a memory pool
pub const Pool = struct {
    allocator: Allocator,
    nodes: std.MultiArrayList(Node).Slice,
    next_free_node: Id,

    pub const free_bit: u32 = 0x80000000;
    pub const max_ref_count: u32 = 0x7FFFFFFF;

    /// Initializes the memory pool with `pool_size` + `zero_hash_max_depth` items.
    pub fn init(allocator: Allocator, pool_size: u32) Error!Pool {
        var pool: Pool = .{
            .allocator = allocator,
            .nodes = undefined,
            .next_free_node = @enumFromInt(max_depth),
        };

        if (pool_size + max_depth >= free_bit) {
            return error.OutOfMemory;
        }

        var nodes = std.MultiArrayList(Node).empty;
        try nodes.resize(allocator, pool_size + max_depth);
        nodes.len = max_depth;

        pool.nodes = nodes.slice();

        // Populate zero hashes (at index 0 to zero_hash_max_depth - 1)
        for (0..max_depth) |i| {
            pool.nodes.set(@intCast(i), Node{
                .hash = getZeroHash(@intCast(i)).*,
                .left = if (i == 0) undefined else @enumFromInt(i - 1),
                .right = if (i == 0) undefined else @enumFromInt(i - 1),
                .state = .zero,
            });
        }

        try pool.preheat(pool_size);

        return pool;
    }

    pub fn deinit(self: *Pool) void {
        self.nodes.deinit(self.allocator);
        self.* = undefined;
    }

    /// Preheats the memory pool by pre-allocating `size` items.
    /// This allows up to `size` active allocations before an
    /// `OutOfMemory` error might happen when calling `create*()`.
    pub fn preheat(self: *Pool, additional_size: u32) Allocator.Error!void {
        const size = self.nodes.len;
        const new_size = size + additional_size;

        if (new_size >= free_bit) {
            return error.OutOfMemory;
        }

        var nodes = self.nodes.toMultiArrayList();
        try nodes.resize(self.allocator, new_size);
        self.nodes = nodes.slice();

        const states = self.nodes.items(.state);

        for (size..new_size) |i| {
            states[i] = State.initNextFree(@enumFromInt(@as(u32, @intCast(i + 1))));
        }
    }

    /// Assumes that self.next_free_node is in bounds and will not allocate
    /// Assumes that the caller will initialize the Id's state / ref count
    inline fn createUnsafe(self: *Pool, states: []State) Id {
        // pop from the free list
        const n: Id = self.next_free_node;
        // mask away the free bit
        self.next_free_node = states[@intFromEnum(n)].getNextFree();
        return n;
    }

    fn create(self: *Pool) Allocator.Error!Id {
        std.debug.assert(@intFromEnum(self.next_free_node) <= self.nodes.len);

        if (@intFromEnum(self.next_free_node) == self.nodes.len) {
            try self.preheat(1);
        }
        return self.createUnsafe(self.nodes.items(.state));
    }

    /// Returns the number of nodes currently in use (not free)
    pub fn getNodesInUse(self: *Pool) usize {
        var count: usize = 0;
        const states = self.nodes.items(.state);
        for (states) |state| {
            if (!state.isFree()) {
                count += 1;
            }
        }
        return count;
    }

    pub fn createLeaf(self: *Pool, hash: *const [32]u8, should_ref: bool) Allocator.Error!Id {
        const node_id = try self.create();

        self.nodes.items(.hash)[@intFromEnum(node_id)] = hash.*;
        self.nodes.items(.state)[@intFromEnum(node_id)] = State.leaf.initRefCount(should_ref);

        return node_id;
    }

    pub fn createLeafFromUint(self: *Pool, uint: u256, should_ref: bool) Allocator.Error!Id {
        var hash: [32]u8 = undefined;
        std.mem.writeInt(u256, &hash, uint, .little);
        return self.createLeaf(&hash, should_ref);
    }

    pub fn createBranch(self: *Pool, left_id: Id, right_id: Id, should_ref: bool) Error!Id {
        std.debug.assert(@intFromEnum(left_id) < self.nodes.len);
        std.debug.assert(@intFromEnum(right_id) < self.nodes.len);

        const node_id = try self.create();

        const states = self.nodes.items(.state);

        std.debug.assert(!states[@intFromEnum(left_id)].isFree());
        std.debug.assert(!states[@intFromEnum(right_id)].isFree());

        self.nodes.items(.left)[@intFromEnum(node_id)] = left_id;
        self.nodes.items(.right)[@intFromEnum(node_id)] = right_id;
        states[@intFromEnum(node_id)] = State.branch_lazy.initRefCount(should_ref);

        try self.refUnsafe(left_id, states);
        try self.refUnsafe(right_id, states);

        return node_id;
    }

    /// Allocates nodes into the pool.
    ///
    /// Note: Only the first node (`out[0]`) is pre-refed.
    ///
    /// Nodes allocated here are expected to be attached via `rebind`
    /// Return true if pool had to allocate more memory, false otherwise
    pub fn alloc(self: *Pool, out: []Id) Allocator.Error!bool {
        var states = self.nodes.items(.state);
        var allocated: bool = false;
        for (0..out.len) |i| {
            std.debug.assert(@intFromEnum(self.next_free_node) <= self.nodes.len);
            if (@intFromEnum(self.next_free_node) == self.nodes.len) {
                const remaining = out.len - i;
                try self.preheat(@intCast(remaining));
                // TODO how to handle failing to resize here
                // errdefer self.free(out[0..i]);

                states = self.nodes.items(.state);
                allocated = true;
            }
            out[i] = self.createUnsafe(states);
            states[@intFromEnum(out[i])] = State.branch_lazy.initRefCount(i == 0);
        }
        return allocated;
    }

    /// Unrefs nodes from the pool.
    pub fn free(self: *Pool, out: []Id) void {
        for (out) |node_id| {
            self.unref(node_id);
        }
    }

    /// Rebinds nodes in the pool.
    ///
    /// It is assumed that `out` nodes have been freshly allocated and are not referenced elsewhere.
    pub fn rebind(self: *Pool, out: []Id, left_ids: []Id, right_ids: []Id) Error!void {
        std.debug.assert(out.len == left_ids.len);
        std.debug.assert(out.len == right_ids.len);

        const lefts = self.nodes.items(.left);
        const rights = self.nodes.items(.right);
        const states = self.nodes.items(.state);

        for (0..out.len) |i| {
            std.debug.assert(@intFromEnum(out[i]) < self.nodes.len);

            lefts[@intFromEnum(out[i])] = left_ids[i];
            rights[@intFromEnum(out[i])] = right_ids[i];

            try self.refUnsafe(left_ids[i], states);
            try self.refUnsafe(right_ids[i], states);
        }
    }

    pub fn ref(self: *Pool, node_id: Id) Error!void {
        // Check if the node is in bounds
        if (@intFromEnum(node_id) >= self.nodes.len) {
            return;
        }

        const states = self.nodes.items(.state);

        // Check if the node is free
        if (states[@intFromEnum(node_id)].isFree()) {
            return;
        }

        try self.refUnsafe(node_id, states);
    }

    // Assumes `node_id` to be in bounds and not free
    fn refUnsafe(self: *Pool, node_id: Id, states: []Node.State) Error!void {
        _ = self;

        if (states[@intFromEnum(node_id)].isZero()) {
            return;
        }

        _ = try states[@intFromEnum(node_id)].incRefCount();
    }

    pub fn unref(self: *Pool, node_id: Id) void {
        const states = self.nodes.items(.state);
        const lefts = self.nodes.items(.left);
        const rights = self.nodes.items(.right);

        var stack: [max_depth]Id = undefined;
        var current: ?Id = node_id;
        var sp: Depth = 0;
        while (true) {
            const id = current orelse {
                if (sp == 0) {
                    break;
                }
                sp -= 1;
                current = stack[sp];
                continue;
            };

            // Continue if the the node is out of bounds or free or a zero node
            if (@intFromEnum(id) >= self.nodes.len or states[@intFromEnum(id)].isFree() or states[@intFromEnum(id)].isZero()) {
                current = null;
                continue;
            }

            // Decrement the reference count
            const ref_count = states[@intFromEnum(id)].decRefCount();

            // If the reference count is not zero, continue
            if (ref_count != 0) {
                current = null;
                continue;
            }

            // If the node is a branch, push its children onto the stack
            if (states[@intFromEnum(id)].isBranch()) {
                stack[sp] = rights[@intFromEnum(id)];
                sp += 1;
                current = lefts[@intFromEnum(id)];
            } else {
                current = null;
            }

            // Return the node to the free list
            states[@intFromEnum(id)] = State.initNextFree(self.next_free_node);
            self.next_free_node = id;
        }
    }
};

/// A handle which uniquely identifies the node
///
/// This handle only has meaning in the context of a `Pool`.
pub const Id = enum(u32) {
    _,

    /// Returns true if navigation to the child node is not possible
    pub inline fn noChild(node_id: Id, state: State) bool {
        return state.isLeaf() or @intFromEnum(node_id) == 0;
    }

    /// Returns the root hash of the tree, computing any lazy branches as needed.
    pub fn getRoot(node_id: Id, pool: *Pool) *const [32]u8 {
        const state = &pool.nodes.items(.state)[@intFromEnum(node_id)];
        const hash = &pool.nodes.items(.hash)[@intFromEnum(node_id)];

        if (state.isBranchLazy()) {
            const left = pool.nodes.items(.left)[@intFromEnum(node_id)].getRoot(pool);
            const right = pool.nodes.items(.right)[@intFromEnum(node_id)].getRoot(pool);
            hashOne(hash, left, right);
            state.setBranchComputed();
        }
        return hash;
    }

    pub fn getLeft(node_id: Id, pool: *Pool) Error!Id {
        const state = pool.nodes.items(.state)[@intFromEnum(node_id)];
        if (node_id.noChild(state)) {
            return Error.InvalidNode;
        }

        return pool.nodes.items(.left)[@intFromEnum(node_id)];
    }

    pub fn getRight(node_id: Id, pool: *Pool) Error!Id {
        const state = pool.nodes.items(.state)[@intFromEnum(node_id)];
        if (node_id.noChild(state)) {
            return Error.InvalidNode;
        }

        return pool.nodes.items(.right)[@intFromEnum(node_id)];
    }

    pub fn getState(node_id: Id, pool: *Pool) State {
        return pool.nodes.items(.state)[@intFromEnum(node_id)];
    }

    pub fn getNode(root_node: Id, pool: *Pool, gindex: Gindex) Error!Id {
        if (@intFromEnum(gindex) <= 1) {
            return root_node;
        }

        const path_len = gindex.pathLen();
        var path = gindex.toPath();

        const states = pool.nodes.items(.state);
        const lefts = pool.nodes.items(.left);
        const rights = pool.nodes.items(.right);

        var node_id: Id = root_node;
        for (0..path_len) |_| {
            if (node_id.noChild(states[@intFromEnum(node_id)])) {
                return Error.InvalidNode;
            }
            if (path.left()) {
                node_id = lefts[@intFromEnum(node_id)];
            } else {
                node_id = rights[@intFromEnum(node_id)];
            }
            path.next();
        }

        return node_id;
    }

    pub fn getNodeAtDepth(root_node: Id, pool: *Pool, depth: Depth, index: usize) Error!Id {
        return try root_node.getNode(
            pool,
            Gindex.fromDepth(depth, index),
        );
    }

    pub fn setNode(root_node: Id, pool: *Pool, gindex: Gindex, node_id: Id) Error!Id {
        if (@intFromEnum(gindex) <= 1) {
            return node_id;
        }

        const path_len = gindex.pathLen();
        var path = gindex.toPath();

        var path_lefts_buf: [max_depth]Id = undefined;
        var path_rights_buf: [max_depth]Id = undefined;
        var path_parents_buf: [max_depth]Id = undefined;

        const path_lefts = path_lefts_buf[0..path_len];
        const path_rights = path_rights_buf[0..path_len];
        const path_parents = path_parents_buf[0..path_len];

        _ = try pool.alloc(path_parents);
        errdefer pool.free(path_parents);

        const states = pool.nodes.items(.state);
        const lefts = pool.nodes.items(.left);
        const rights = pool.nodes.items(.right);

        var id = root_node;

        for (0..path_len - 1) |i| {
            if (id.noChild(states[@intFromEnum(id)])) {
                return Error.InvalidNode;
            }
            if (path.left()) {
                path_lefts[i] = path_parents[i + 1];
                path_rights[i] = rights[@intFromEnum(id)];
                id = lefts[@intFromEnum(id)];
            } else {
                path_lefts[i] = lefts[@intFromEnum(id)];
                path_rights[i] = path_parents[i + 1];
                id = rights[@intFromEnum(id)];
            }
            path.next();
        }

        // final layer
        if (id.noChild(states[@intFromEnum(id)])) {
            return Error.InvalidNode;
        }
        if (path.left()) {
            path_lefts[path_len - 1] = node_id;
            path_rights[path_len - 1] = rights[@intFromEnum(id)];
        } else {
            path_lefts[path_len - 1] = lefts[@intFromEnum(id)];
            path_rights[path_len - 1] = node_id;
        }

        try pool.rebind(
            path_parents,
            path_lefts,
            path_rights,
        );

        return path_parents[0];
    }

    pub fn setNodeAtDepth(root_node: Id, pool: *Pool, depth: Depth, index: usize, node_id: Id) Error!Id {
        return try root_node.setNode(
            pool,
            Gindex.fromDepth(depth, index),
            node_id,
        );
    }

    /// Get multiple nodes in a single traversal
    ///
    /// Stores `out.len` nodes at the specified `depth`, starting from `start_index`.
    pub fn getNodesAtDepth(root_node: Id, pool: *Pool, depth: Depth, start_index: usize, out: []Id) Error!void {
        std.debug.assert(out.len > 0);

        const base_gindex = Gindex.fromDepth(depth, 0);

        if (@intFromEnum(base_gindex) <= 1) {
            out[0] = root_node;
            return;
        }

        const path_len = base_gindex.pathLen();
        var parents_buf: [max_depth]Id = undefined;

        var node_id = root_node;
        var diffi = depth;

        const states = pool.nodes.items(.state);
        const lefts = pool.nodes.items(.left);
        const rights = pool.nodes.items(.right);

        // For each index specified
        for (0..out.len) |i| {
            // Calculate the gindex bits for the current index
            const index = start_index + i;
            const gindex: Gindex = @enumFromInt(@as(Gindex.Uint, @intCast(@intFromEnum(base_gindex) | index)));
            const d = path_len - diffi;

            var path = gindex.toPath();
            path.nextN(d);

            // Navigate down (from the depth diff) to the current index, populating parents
            for (d..path_len) |bit_i| {
                if (node_id.noChild(states[@intFromEnum(node_id)])) {
                    return Error.InvalidNode;
                }
                parents_buf[bit_i] = node_id;
                if (path.left()) {
                    node_id = lefts[@intFromEnum(node_id)];
                } else {
                    node_id = rights[@intFromEnum(node_id)];
                }
                path.next();
            }

            // Populate the output
            out[i] = node_id;

            // Calculate the depth diff to navigate from current index to the next
            // This is always gt 0 (unless an index is repeated)
            diffi = if (i == out.len - 1)
                depth
            else
                @intCast(@bitSizeOf(Gindex) - @clz(index ^ index + 1));

            // Navigate upwards depth diff times
            node_id = parents_buf[path_len - diffi];
        }
    }

    /// Set multiple nodes in batch, editing and traversing nodes strictly once.
    /// - indexes MUST be sorted in ascending order beforehand.
    /// - All indexes must be at the exact same depth.
    /// - Depth must be > 0, if 0 just replace the root node.
    pub fn setNodesAtDepth(root_node: Id, pool: *Pool, depth: Depth, indices: []const usize, nodes: []Id) Error!Id {
        std.debug.assert(nodes.len == indices.len);
        if (indices.len == 0) {
            return root_node;
        }

        const base_gindex = Gindex.fromDepth(depth, 0);

        if (@intFromEnum(base_gindex) <= 1) {
            return nodes[0];
        }

        const path_len = base_gindex.pathLen();

        var path_parents_buf: [max_depth]Id = undefined;
        // at each level, there is at most 1 unfinalized parent per traversal
        // "unfinalized" means it may or may not be part of the new tree
        var unfinalized_parents_buf: [max_depth]?Id = undefined;
        var path_lefts_buf: [max_depth]Id = undefined;
        var path_rights_buf: [max_depth]Id = undefined;
        // right_move means it's part of the new tree, it happens when we traverse right
        var right_move: [max_depth]bool = undefined;

        const path_parents = path_parents_buf[0..path_len];
        const path_lefts = path_lefts_buf[0..path_len];
        const path_rights = path_rights_buf[0..path_len];

        var node_id = root_node;
        errdefer {
            // at any points, node_id is the root of the in-progress new tree
            if (node_id != root_node) pool.unref(node_id);
            // orphaned nodes were unrefed along the way through unfinalized_parents_buf
            // path_parents may or maynot be part of the in-progress new tree, there is no issue to double unref()
            pool.free(path_parents);
        }

        // The shared depth between the previous and current index
        // This is initialized as 0 since the first index has no previous index
        var d_offset: Depth = 0;

        var states = pool.nodes.items(.state);
        var lefts = pool.nodes.items(.left);
        var rights = pool.nodes.items(.right);

        // For each index specified, maintain/update path_lefts and path_rights from root (depth 0) all the way to path_len
        // but only allocate and update path_parents from the next shared depth to path_len
        for (0..indices.len) |i| {
            // Calculate the gindex bits for the current index
            const index = indices[i];
            const gindex: Gindex = @enumFromInt(@as(Gindex.Uint, @intCast(@intFromEnum(base_gindex) | index)));

            // Calculate the depth offset to navigate from current index to the next
            const next_d_offset = if (i == indices.len - 1)
                // 0 because there is no next index, it also means node_id is now the new root
                0
            else
                path_len - @as(Depth, @intCast(@bitSizeOf(usize) - @clz(index ^ indices[i + 1])));
            if (try pool.alloc(path_parents[next_d_offset..path_len])) {
                states = pool.nodes.items(.state);
                lefts = pool.nodes.items(.left);
                rights = pool.nodes.items(.right);
            }

            var path = gindex.toPath();

            // Navigate down (to the depth offset), attaching any new updates
            // d_offset is the shared depth between the previous and current index so we can reuse path_lefts and path_rights up that point
            // but update them to the path_parents to rebind starting from next_d_offset if needed
            if (d_offset > next_d_offset) {
                path.nextN(next_d_offset);
                for (next_d_offset..d_offset) |bit_i| {
                    if (path.left()) {
                        path_lefts[bit_i] = path_parents[bit_i + 1];
                        right_move[bit_i] = false;
                        // move left, unfinalized
                        unfinalized_parents_buf[bit_i] = path_parents[bit_i];
                    } else {
                        path_rights[bit_i] = path_parents[bit_i + 1];
                        right_move[bit_i] = true;
                    }
                    path.next();
                }
            } else {
                path.nextN(d_offset);
            }

            // right move at d_offset, make all unfinalized parents at lower levels as finalized
            if (path.right()) {
                for (d_offset + 1..path_len) |bit_i| {
                    unfinalized_parents_buf[bit_i] = null;
                }
            }

            // Navigate down (from the depth offset) to the current index, populating parents
            for (d_offset..path_len - 1) |bit_i| {
                if (node_id.noChild(states[@intFromEnum(node_id)])) {
                    return Error.InvalidNode;
                }

                if (path.left()) {
                    path_lefts[bit_i] = path_parents[bit_i + 1];
                    path_rights[bit_i] = rights[@intFromEnum(node_id)];
                    node_id = lefts[@intFromEnum(node_id)];
                    right_move[bit_i] = false;
                    unfinalized_parents_buf[bit_i] = path_parents[bit_i];
                } else {
                    path_lefts[bit_i] = lefts[@intFromEnum(node_id)];
                    path_rights[bit_i] = path_parents[bit_i + 1];
                    node_id = rights[@intFromEnum(node_id)];
                    right_move[bit_i] = true;
                }
                path.next();
            }
            // final layer
            if (node_id.noChild(states[@intFromEnum(node_id)])) {
                return Error.InvalidNode;
            }
            if (path.left()) {
                path_lefts[path_len - 1] = nodes[i];
                path_rights[path_len - 1] = rights[@intFromEnum(node_id)];
                right_move[path_len - 1] = false;
                unfinalized_parents_buf[path_len - 1] = path_parents[path_len - 1];
            } else {
                path_lefts[path_len - 1] = lefts[@intFromEnum(node_id)];
                path_rights[path_len - 1] = nodes[i];
                right_move[path_len - 1] = true;
            }

            // Rebind upwards depth diff times
            try pool.rebind(
                path_parents[next_d_offset..path_len],
                path_lefts[next_d_offset..path_len],
                path_rights[next_d_offset..path_len],
            );

            // unref prev parents if it's not part of the new tree
            // can only unref after the rebind
            for (next_d_offset..path_len) |bit_i| {
                if (right_move[bit_i] and unfinalized_parents_buf[bit_i] != null) {
                    pool.unref(unfinalized_parents_buf[bit_i].?);
                    unfinalized_parents_buf[bit_i] = null;
                }
            }
            node_id = path_parents[next_d_offset];
            d_offset = next_d_offset;
        }

        return node_id;
    }

    /// Set multiple nodes in batch, editing and traversing nodes strictly once.
    /// - gindexes MUST be sorted in ascending order beforehand.
    pub fn setNodes(root_node: Id, pool: *Pool, gindices: []const Gindex, nodes: []Id) Error!Id {
        std.debug.assert(nodes.len == gindices.len);
        if (gindices.len == 0) {
            return root_node;
        }

        const base_gindex = gindices[0];
        if (@intFromEnum(base_gindex) <= 1) {
            return nodes[0];
        }

        const path_len = base_gindex.pathLen();

        var path_parents_buf: [max_depth]Id = undefined;
        // at each level, there is at most 1 unfinalized parent per traversal
        // "unfinalized" means it may or may not be part of the new tree
        var unfinalized_parents_buf: [max_depth]?Id = undefined;
        var path_lefts_buf: [max_depth]Id = undefined;
        var path_rights_buf: [max_depth]Id = undefined;
        // right_move means it's part of the new tree, it happens when we traverse right
        var right_move: [max_depth]bool = undefined;

        var node_id = root_node;
        errdefer {
            // at any points, node_id is the root of the in-progress new tree
            if (node_id != root_node) pool.unref(node_id);
            // orphaned nodes were unrefed along the way through unfinalized_parents_buf
            // path_parents_buf may or maynot be part of the in-progress new tree, there is no issue to double unref()
            pool.free(&path_parents_buf);
        }

        // The shared depth between the previous and current index
        // This is initialized as 0 since the first index has no previous index
        var d_offset: Depth = 0;

        var states = pool.nodes.items(.state);
        var lefts = pool.nodes.items(.left);
        var rights = pool.nodes.items(.right);

        // For each index specified, maintain/update path_lefts and path_rights from root (depth 0) all the way to path_len
        // but only allocate and update path_parents from the next shared depth to path_len
        for (0..gindices.len) |i| {
            // Calculate the gindex bits for the current index
            const gindex = gindices[i];

            // Calculate the depth offset to navigate from current index to the next
            const next_d_offset = if (i == gindices.len - 1)
                // 0 because there is no next gindex, it also means node_id is now the new root
                0
            else
                path_len - @as(Depth, @intCast(@bitSizeOf(usize) - @clz(@intFromEnum(gindex) ^ @intFromEnum(gindices[i + 1]))));

            if (try pool.alloc(path_parents_buf[next_d_offset..path_len])) {
                states = pool.nodes.items(.state);
                lefts = pool.nodes.items(.left);
                rights = pool.nodes.items(.right);
            }

            var path = gindex.toPath();

            // Navigate down (to the depth offset), attaching any new updates
            // d_offset is the shared depth between the previous and current index so we can reuse path_lefts and path_rights up that point
            // but update them to the path_parents to rebind starting from next_d_offset if needed
            if (d_offset > next_d_offset) {
                path.nextN(next_d_offset);
                for (next_d_offset..d_offset) |bit_i| {
                    if (path.left()) {
                        path_lefts_buf[bit_i] = path_parents_buf[bit_i + 1];
                        right_move[bit_i] = false;
                        // move left, unfinalized
                        unfinalized_parents_buf[bit_i] = path_parents_buf[bit_i];
                    } else {
                        path_rights_buf[bit_i] = path_parents_buf[bit_i + 1];
                        right_move[bit_i] = true;
                    }
                    path.next();
                }
            } else {
                path.nextN(d_offset);
            }

            // right move at d_offset, make all unfinalized parents at lower levels as finalized
            if (path.right()) {
                for (d_offset + 1..path_len) |bit_i| {
                    unfinalized_parents_buf[bit_i] = null;
                }
            }

            // Navigate down (from the depth offset) to the current index, populating parents
            for (d_offset..path_len - 1) |bit_i| {
                if (node_id.noChild(states[@intFromEnum(node_id)])) {
                    return Error.InvalidNode;
                }

                if (path.left()) {
                    path_lefts_buf[bit_i] = path_parents_buf[bit_i + 1];
                    path_rights_buf[bit_i] = rights[@intFromEnum(node_id)];
                    node_id = lefts[@intFromEnum(node_id)];
                    right_move[bit_i] = false;
                    unfinalized_parents_buf[bit_i] = path_parents_buf[bit_i];
                } else {
                    path_lefts_buf[bit_i] = lefts[@intFromEnum(node_id)];
                    path_rights_buf[bit_i] = path_parents_buf[bit_i + 1];
                    node_id = rights[@intFromEnum(node_id)];
                    right_move[bit_i] = true;
                }
                path.next();
            }
            // final layer
            if (node_id.noChild(states[@intFromEnum(node_id)])) {
                return Error.InvalidNode;
            }
            if (path.left()) {
                path_lefts_buf[path_len - 1] = nodes[i];
                path_rights_buf[path_len - 1] = rights[@intFromEnum(node_id)];
                right_move[path_len - 1] = false;
                unfinalized_parents_buf[path_len - 1] = path_parents_buf[path_len - 1];
            } else {
                path_lefts_buf[path_len - 1] = lefts[@intFromEnum(node_id)];
                path_rights_buf[path_len - 1] = nodes[i];
                right_move[path_len - 1] = true;
            }

            // Rebind upwards depth diff times
            try pool.rebind(
                path_parents_buf[next_d_offset..path_len],
                path_lefts_buf[next_d_offset..path_len],
                path_rights_buf[next_d_offset..path_len],
            );
            // unref prev parents if it's not part of the new tree
            // can only unref after the rebind
            for (next_d_offset..path_len) |bit_i| {
                if (right_move[bit_i] and unfinalized_parents_buf[bit_i] != null) {
                    pool.unref(unfinalized_parents_buf[bit_i].?);
                    unfinalized_parents_buf[bit_i] = null;
                }
            }

            node_id = path_parents_buf[next_d_offset];
            d_offset = next_d_offset;
        }

        return node_id;
    }
};

/// Fill a view to the specified depth, returning the new root node id.
pub fn fillToDepth(pool: *Pool, bottom: Id, depth: Depth, should_ref: bool) Error!Id {
    var d = depth;
    var node = bottom;
    while (d > 0) : (d -= 1) {
        node = try pool.createBranch(node, node, false);
    }

    if (should_ref) {
        try pool.ref(node);
    }
    return node;
}

/// Fill a view to the specified length and depth, returning the new root node id.
pub fn fillToLength(pool: *Pool, leaf: Id, depth: Depth, length: usize, should_ref: bool) Error!Id {
    const max_length = @as(Gindex.Uint, 1) << depth;
    if (length > max_length) {
        return Error.InvalidLength;
    }

    // fill a full view to the specified depth
    var node_id = try fillToDepth(pool, leaf, depth, should_ref);

    // if the requested length is the same as the max length, return the node
    if (length == max_length) {
        return node_id;
    }

    // otherwise, traverse down to the specified length
    const gindex: Gindex = @enumFromInt(max_length | length);
    const path_len = gindex.pathLen();
    var path = gindex.toPath();

    var parents_buf: [max_depth]Id = undefined;
    var lefts_buf: [max_depth]Id = undefined;
    var rights_buf: [max_depth]Id = undefined;

    const path_parents = parents_buf[0..path_len];
    const path_lefts = lefts_buf[0..path_len];
    const path_rights = rights_buf[0..path_len];

    const states = pool.nodes.items(.state);
    const lefts = pool.nodes.items(.left);
    const rights = pool.nodes.items(.right);

    for (0..path_len - 1) |i| {
        if (node_id.noChild(states[@intFromEnum(node_id)])) {
            return Error.InvalidNode;
        }
        if (path.left()) {
            path_lefts[i] = path_parents[i + 1];
            path_rights[i] = rights[@intFromEnum(node_id)];
            node_id = lefts[@intFromEnum(node_id)];
        } else {
            path_lefts[i] = lefts[@intFromEnum(node_id)];
            path_rights[i] = path_parents[i + 1];
            node_id = rights[@intFromEnum(node_id)];
        }
        path.next();
    }

    // and rebind with zero(0)
    if (path.left()) {
        path_lefts[path_len - 1] = @enumFromInt(0);
        path_rights[path_len - 1] = rights[@intFromEnum(node_id)];
    } else {
        path_lefts[path_len - 1] = lefts[@intFromEnum(node_id)];
        path_rights[path_len - 1] = @enumFromInt(0);
    }

    // and rebind with zero(0)
    try pool.rebind(
        path_parents,
        path_lefts,
        path_rights,
    );

    if (should_ref) {
        try pool.ref(path_parents[0]);
    }
    return path_parents[0];
}

/// Fill a view with the specified contents, returning the new root node id.
///
/// Note: contents is mutated
pub fn fillWithContents(pool: *Pool, contents: []Id, depth: Depth, should_ref: bool) !Id {
    if (contents.len == 0) {
        return @enumFromInt(depth);
    }
    const max_length = @as(Gindex.Uint, 1) << depth;
    if (contents.len > max_length) {
        return Error.InvalidLength;
    }

    var d = depth;
    var count = contents.len;
    while (d > 0) : (d -= 1) {
        var i: usize = 0;
        while (i < count - 1) : (i += 2) {
            contents[i / 2] = try pool.createBranch(contents[i], contents[i + 1], false);
        }

        // if the count is odd, we need to add a zero node
        if (i != count) {
            contents[i / 2] = try pool.createBranch(contents[i], @enumFromInt(depth - d), false);
        }

        count = (count + 1) / 2;
    }

    if (should_ref) {
        try pool.ref(contents[0]);
    }
    return contents[0];
}
