//! Merkle node backed by a memory pool.
//!
//! Nodes are stored as a tagged union:
//!   - `free`: an entry on the free list, carrying the next free `Id`.
//!   - `zero`: a precomputed zero-hash sentinel (one per depth).
//!   - `leaf`: a 32-byte leaf hash.
//!   - `branch`: a parent with two children and an optional cached root
//!     (`null` = lazy, `some` = computed).
//!
//! Reference counts live in a parallel SoA column (`ref_count`) inside a
//! `MultiArrayList(NodeWithMeta).Slice`. This keeps unref scans cache-friendly.
const std = @import("std");
const Allocator = std.mem.Allocator;

const hashOne = @import("hashing").hashOne;
const getZeroHash = @import("hashing").getZeroHash;
const max_depth = @import("hashing").max_depth;
const Depth = @import("hashing").Depth;
const Gindex = @import("gindex.zig").Gindex;
const Slab = @import("slab.zig");

pub const Error = error{
    /// Attempt to access a child of a node that is not a branch node.
    InvalidNode,
    /// Attempt to use a length beyond the tree's length at a given depth.
    InvalidLength,
    /// Attempt to increment the reference count beyond `max_ref_count`.
    RefCountOverflow,
    /// Out of memory.
    OutOfMemory,
};

/// Maximum reference count a node may hold.
///
/// We reserve `maxInt(u32)` as a sentinel so that comparisons (`rc == max`)
/// stay simple and a saturated value remains representable.
pub const max_ref_count: u32 = std.math.maxInt(u32) - 1;

/// Tagged union representation of a node in the pool.
pub const Node = union(enum) {
    /// Slot is on the free list. Carries the index of the next free slot.
    free: struct { next_free: Id },
    /// Precomputed zero-hash node. Never freed, never ref-counted.
    zero: struct { root: [32]u8 },
    /// Leaf containing a 32-byte hash payload.
    leaf: struct { root: [32]u8 },
    /// Internal branch with two children. `root == lazy_sentinel` means
    /// lazy (uncomputed); any other value means cached.
    branch: struct { left: Id, right: Id, root: [32]u8 },
    /// Chunked-leaf slab. `storage` points to a heap-allocated
    /// `Slab.Storage` (chunks + len, ref-counted through the Pool's
    /// slab-Node ref count, mirroring Lighthouse's `Arc<PackedLeaf>`).
    /// `root` is the cached merkleized slab subtree root; `lazy_sentinel`
    /// means lazy.
    slab: struct {
        storage: *Slab.Storage,
        root: [32]u8,
    },
};

/// Sentinel value for a lazy (uncomputed) `root` field on `branch` and
/// `slab` variants. We use all-`0xFF` because cryptographic SHA-256 outputs
/// are extremely unlikely to equal this value (~1 in 2^256), avoiding the
/// 1-byte tag overhead an `?[32]u8` Optional would add and the resulting
/// padding that inflates the union to 48 bytes.
pub const lazy_sentinel: [32]u8 = [_]u8{0xFF} ** 32;

/// Parallel-array element holding a node alongside its reference count.
///
/// Stored in a `MultiArrayList`, so `node` and `ref_count` end up in
/// separate columns — `unref` walks the ref_count column without touching
/// the union payload column.
pub const NodeWithMeta = struct {
    node: Node,
    ref_count: u32,
};

/// Pair of child Ids. Always defined when `noChild` is false.
const Children = struct { left: Id, right: Id };

/// Resolve the (left, right) child Ids for a navigable node.
///
/// For branch nodes the children come from the union payload. For zero
/// nodes (depth >= 1) the children are synthesised: `zero(d).left = zero(d).right = zero(d-1)`,
/// matching the legacy free-form left/right columns that pre-stored these refs.
inline fn childrenOf(node_id: Id, n: Node) Children {
    return switch (n) {
        .branch => |b| .{ .left = b.left, .right = b.right },
        .zero => blk: {
            const idx = @intFromEnum(node_id);
            std.debug.assert(idx >= 1);
            const prev: Id = @enumFromInt(idx - 1);
            break :blk .{ .left = prev, .right = prev };
        },
        // `noChild` guards prevent reaching here for these variants.
        .leaf, .free => unreachable,
        // Slabs are terminal — they have no Id-children.
        .slab => unreachable,
    };
}

/// A handle which uniquely identifies the node within a `Pool`.
pub const Id = enum(u32) {
    _,

    /// Returns true if navigation to a child node is impossible at `node`.
    ///
    /// Matches legacy semantics: leaves and `Id(0)` (the depth-0 zero
    /// sentinel) have no navigable children. Zero nodes at depth >= 1
    /// remain navigable — both children point to `zero(d-1)`.
    pub inline fn noChild(node_id: Id, n: Node) bool {
        return switch (n) {
            .leaf => true,
            // `Id(0)` is the depth-0 zero sentinel: nothing below it.
            .zero => @intFromEnum(node_id) == 0,
            // Branches always have children.
            .branch => @intFromEnum(node_id) == 0,
            // Free slots are not user-visible nodes.
            .free => true,
            // Slabs are terminal: their chunks are not Id-children.
            .slab => true,
        };
    }

    /// Returns the root hash, computing any lazy branch nodes on demand.
    pub fn getRoot(node_id: Id, pool: *Pool) *const [32]u8 {
        const nodes = pool.nodes.items(.node);
        const idx = @intFromEnum(node_id);
        // `nodes[idx]` is an lvalue into the column slice; this pointer stays
        // valid for the lifetime of the column slice (no allocation occurs
        // during getRoot).
        const node_ptr: *Node = &nodes[idx];
        switch (node_ptr.*) {
            .zero => return &node_ptr.zero.root,
            .leaf => return &node_ptr.leaf.root,
            // Defense-in-depth: `unreachable` would be UB-eliminated under
            // ReleaseFast; if a stale Id reaches here, the switch dispatch
            // would silently misroute to another arm and read the slot's
            // bytes (next_free Id + stale payload) as a valid variant —
            // typically manifesting as a SEGV deep inside the .slab arm.
            // A `@panic` cannot be elided and surfaces the UAF directly.
            .free => @panic("getRoot called on .free slot — use-after-free"),
            .branch => {
                if (!std.mem.eql(u8, &node_ptr.branch.root, &lazy_sentinel)) {
                    return &node_ptr.branch.root;
                }
                const left_id = node_ptr.branch.left;
                const right_id = node_ptr.branch.right;
                const left_root = left_id.getRoot(pool);
                const right_root = right_id.getRoot(pool);
                var hash: [32]u8 = undefined;
                hashOne(&hash, left_root, right_root);
                node_ptr.branch.root = hash;
                return &node_ptr.branch.root;
            },
            .slab => {
                if (!std.mem.eql(u8, &node_ptr.slab.root, &lazy_sentinel)) {
                    return &node_ptr.slab.root;
                }
                var hash: [32]u8 = undefined;
                Slab.computeRoot(node_ptr.slab.storage, &hash);
                node_ptr.slab.root = hash;
                return &node_ptr.slab.root;
            },
        }
    }

    pub fn getLeft(node_id: Id, pool: *Pool) Error!Id {
        const node = pool.nodes.items(.node)[@intFromEnum(node_id)];
        if (node_id.noChild(node)) return Error.InvalidNode;
        return childrenOf(node_id, node).left;
    }

    pub fn getRight(node_id: Id, pool: *Pool) Error!Id {
        const node = pool.nodes.items(.node)[@intFromEnum(node_id)];
        if (node_id.noChild(node)) return Error.InvalidNode;
        return childrenOf(node_id, node).right;
    }

    /// Returns a read-only pointer to the slab's K-chunk array. Returns
    /// `Error.InvalidNode` if the node is not a slab variant.
    pub fn getSlabChunks(node_id: Id, pool: *Pool) Error!*align(64) const [Slab.K][32]u8 {
        const node = pool.nodes.items(.node)[@intFromEnum(node_id)];
        return switch (node) {
            .slab => |s| &s.storage.chunks,
            else => Error.InvalidNode,
        };
    }

    /// Returns the slab's `len` (number of valid chunks, `<= K`). Returns
    /// `Error.InvalidNode` if the node is not a slab variant.
    pub fn getSlabLen(node_id: Id, pool: *Pool) Error!u16 {
        const node = pool.nodes.items(.node)[@intFromEnum(node_id)];
        return switch (node) {
            .slab => |s| s.storage.len,
            else => Error.InvalidNode,
        };
    }

    /// Returns a new slab `Id` with `chunk` at `intra_index`; the receiver slab
    /// is unchanged. Heap Storage is cloned. The returned slab has `root: null`
    /// (lazy). Returns `Error.InvalidNode` if the receiver is not a slab variant.
    pub fn setSlabChunk(node_id: Id, pool: *Pool, intra_index: u16, chunk: *const [32]u8) Error!Id {
        std.debug.assert(intra_index < Slab.K);

        const old_storage = blk: {
            const node = pool.nodes.items(.node)[@intFromEnum(node_id)];
            break :blk switch (node) {
                .slab => |s| s.storage,
                else => return Error.InvalidNode,
            };
        };

        const new_storage = try Slab.allocZero(pool.allocator);
        errdefer Slab.destroy(pool.allocator, new_storage);

        new_storage.chunks = old_storage.chunks;
        new_storage.len = old_storage.len;
        new_storage.chunks[intra_index] = chunk.*;

        const new_id = try pool.create();
        // Re-fetch the node column after pool.create() — preheat may have
        // realloc'd and invalidated any earlier slice we held.
        pool.nodes.items(.node)[@intFromEnum(new_id)] = .{ .slab = .{
            .storage = new_storage,
            .root = lazy_sentinel,
        } };
        pool.nodes.items(.ref_count)[@intFromEnum(new_id)] = 0;
        return new_id;
    }

    /// Returns a new slab `Id` with each `intra_indices[i]` chunk replaced by
    /// `new_chunks[i]`. Heap Storage cloned once; all updates applied in-place
    /// in the new Storage. Returns `Error.InvalidNode` if the receiver is not
    /// a slab variant. `intra_indices` and `new_chunks` must have equal length.
    pub fn setSlabChunks(
        node_id: Id,
        pool: *Pool,
        intra_indices: []const u16,
        new_chunks: []const *const [32]u8,
    ) Error!Id {
        std.debug.assert(intra_indices.len == new_chunks.len);

        const old_storage = blk: {
            const node = pool.nodes.items(.node)[@intFromEnum(node_id)];
            break :blk switch (node) {
                .slab => |s| s.storage,
                else => return Error.InvalidNode,
            };
        };

        const new_storage = try Slab.allocZero(pool.allocator);
        errdefer Slab.destroy(pool.allocator, new_storage);

        new_storage.chunks = old_storage.chunks;
        new_storage.len = old_storage.len;

        for (intra_indices, new_chunks) |idx, ptr| {
            std.debug.assert(idx < Slab.K);
            new_storage.chunks[idx] = ptr.*;
        }

        const new_id = try pool.create();
        pool.nodes.items(.node)[@intFromEnum(new_id)] = .{ .slab = .{
            .storage = new_storage,
            .root = lazy_sentinel,
        } };
        pool.nodes.items(.ref_count)[@intFromEnum(new_id)] = 0;
        return new_id;
    }

    /// Lightweight read-only view over a slot's tag and ref count.
    /// Preserves the legacy `state.isFoo()` predicate API.
    pub fn getState(node_id: Id, pool: *Pool) StateView {
        return .{ .pool = pool, .id = node_id };
    }

    pub fn getNode(root_node: Id, pool: *Pool, gindex: Gindex) Error!Id {
        if (@intFromEnum(gindex) <= 1) {
            return root_node;
        }

        const path_len = gindex.pathLen();
        var path = gindex.toPath();

        const nodes = pool.nodes.items(.node);

        var node_id: Id = root_node;
        for (0..path_len) |_| {
            const n = nodes[@intFromEnum(node_id)];
            if (node_id.noChild(n)) {
                return Error.InvalidNode;
            }
            const c = childrenOf(node_id, n);
            if (path.left()) {
                node_id = c.left;
            } else {
                node_id = c.right;
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

        const nodes = pool.nodes.items(.node);

        var id = root_node;

        for (0..path_len - 1) |i| {
            const n = nodes[@intFromEnum(id)];
            if (id.noChild(n)) {
                return Error.InvalidNode;
            }
            const c = childrenOf(id, n);
            if (path.left()) {
                path_lefts[i] = path_parents[i + 1];
                path_rights[i] = c.right;
                id = c.left;
            } else {
                path_lefts[i] = c.left;
                path_rights[i] = path_parents[i + 1];
                id = c.right;
            }
            path.next();
        }

        // final layer
        {
            const n = nodes[@intFromEnum(id)];
            if (id.noChild(n)) {
                return Error.InvalidNode;
            }
            const c = childrenOf(id, n);
            if (path.left()) {
                path_lefts[path_len - 1] = node_id;
                path_rights[path_len - 1] = c.right;
            } else {
                path_lefts[path_len - 1] = c.left;
                path_rights[path_len - 1] = node_id;
            }
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

    /// Get multiple nodes in a single traversal.
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

        const nodes = pool.nodes.items(.node);

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
                const n = nodes[@intFromEnum(node_id)];
                if (node_id.noChild(n)) {
                    return Error.InvalidNode;
                }
                const c = childrenOf(node_id, n);
                parents_buf[bit_i] = node_id;
                if (path.left()) {
                    node_id = c.left;
                } else {
                    node_id = c.right;
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
    pub fn setNodesAtDepth(root_node: Id, pool: *Pool, depth: Depth, indices: []const usize, nodes_in: []Id) Error!Id {
        std.debug.assert(nodes_in.len == indices.len);
        if (indices.len == 0) {
            return root_node;
        }

        const base_gindex = Gindex.fromDepth(depth, 0);

        if (@intFromEnum(base_gindex) <= 1) {
            return nodes_in[0];
        }

        const path_len = base_gindex.pathLen();

        var path_parents_buf: [max_depth]Id = undefined;
        // at each level, there is at most 1 unfinalized parent per traversal
        // "unfinalized" means it may or may not be part of the new tree.
        // MUST start as all-null so iteration 0's post-rebind unref loop
        // does not read garbage Optional bytes and call `pool.unref` on
        // an arbitrary Id (use-after-free).
        var unfinalized_parents_buf: [max_depth]?Id = [_]?Id{null} ** max_depth;
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

        var nodes_slice = pool.nodes.items(.node);

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
                nodes_slice = pool.nodes.items(.node);
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
                const n = nodes_slice[@intFromEnum(node_id)];
                if (node_id.noChild(n)) {
                    return Error.InvalidNode;
                }
                const c = childrenOf(node_id, n);

                if (path.left()) {
                    path_lefts[bit_i] = path_parents[bit_i + 1];
                    path_rights[bit_i] = c.right;
                    node_id = c.left;
                    right_move[bit_i] = false;
                    unfinalized_parents_buf[bit_i] = path_parents[bit_i];
                } else {
                    path_lefts[bit_i] = c.left;
                    path_rights[bit_i] = path_parents[bit_i + 1];
                    node_id = c.right;
                    right_move[bit_i] = true;
                }
                path.next();
            }
            // final layer
            {
                const n = nodes_slice[@intFromEnum(node_id)];
                if (node_id.noChild(n)) {
                    return Error.InvalidNode;
                }
                const c = childrenOf(node_id, n);
                if (path.left()) {
                    path_lefts[path_len - 1] = nodes_in[i];
                    path_rights[path_len - 1] = c.right;
                    right_move[path_len - 1] = false;
                    unfinalized_parents_buf[path_len - 1] = path_parents[path_len - 1];
                } else {
                    path_lefts[path_len - 1] = c.left;
                    path_rights[path_len - 1] = nodes_in[i];
                    right_move[path_len - 1] = true;
                }
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
            // unref may have grown the pool indirectly via subsequent calls; the
            // node_id we read above is preserved by value, but `nodes_slice`
            // may be stale if any allocation happened. Refresh defensively.
            nodes_slice = pool.nodes.items(.node);
        }

        return node_id;
    }

    /// Zeroes every node strictly to the right of `index` at the provided `depth`.
    pub fn truncateAfterIndex(root_node: Id, pool: *Pool, depth: Depth, index: usize) Error!Id {
        if (depth == 0) {
            return root_node;
        }

        const max_length = @as(Gindex.Uint, 1) << depth;
        if (index >= max_length - 1) {
            if (index >= max_length) {
                return Error.InvalidLength;
            }
            return root_node;
        }

        const path_len = @as(usize, depth);

        var path_lefts_buf: [max_depth]Id = undefined;
        var path_rights_buf: [max_depth]Id = undefined;
        var path_parents_buf: [max_depth]Id = undefined;

        const path_lefts = path_lefts_buf[0..path_len];
        const path_rights = path_rights_buf[0..path_len];
        const path_parents = path_parents_buf[0..path_len];

        _ = try pool.alloc(path_parents);
        errdefer pool.free(path_parents);

        const nodes = pool.nodes.items(.node);

        var node_id = root_node;

        for (0..path_len - 1) |i| {
            const n = nodes[@intFromEnum(node_id)];
            if (node_id.noChild(n)) {
                return Error.InvalidNode;
            }
            const c = childrenOf(node_id, n);

            const depthi = path_len - i - 1;
            const go_left = isLeftIndex(depthi, index);
            if (go_left) {
                path_lefts[i] = path_parents[i + 1];
                const zero_depth: Depth = @intCast(depthi);
                path_rights[i] = @enumFromInt(zero_depth);
                node_id = c.left;
            } else {
                path_lefts[i] = c.left;
                path_rights[i] = path_parents[i + 1];
                node_id = c.right;
            }
        }

        {
            const n = nodes[@intFromEnum(node_id)];
            if (node_id.noChild(n)) {
                return Error.InvalidNode;
            }
            const c = childrenOf(node_id, n);

            const go_left_last = isLeftIndex(0, index);
            if (go_left_last) {
                path_lefts[path_len - 1] = c.left;
                path_rights[path_len - 1] = @enumFromInt(0);
            } else {
                path_lefts[path_len - 1] = c.left;
                path_rights[path_len - 1] = c.right;
            }
        }

        try pool.rebind(path_parents, path_lefts, path_rights);
        return path_parents[0];
    }

    inline fn isLeftIndex(depthi: usize, index: usize) bool {
        const mask: usize = @as(usize, 1) << @intCast(depthi);
        return (index & mask) == 0;
    }

    /// Set multiple nodes in batch, editing and traversing nodes strictly once.
    /// - gindexes MUST be sorted in ascending order beforehand.
    pub fn setNodes(root_node: Id, pool: *Pool, gindices: []const Gindex, nodes_in: []Id) Error!Id {
        std.debug.assert(nodes_in.len == gindices.len);
        if (gindices.len == 0) {
            return root_node;
        }

        const base_gindex = gindices[0];
        if (@intFromEnum(base_gindex) <= 1) {
            return nodes_in[0];
        }

        const path_len = base_gindex.pathLen();

        var path_parents_buf: [max_depth]Id = undefined;
        // at each level, there is at most 1 unfinalized parent per traversal
        // "unfinalized" means it may or may not be part of the new tree.
        // MUST start as all-null so iteration 0's post-rebind unref loop
        // does not read garbage Optional bytes and call `pool.unref` on
        // an arbitrary Id (use-after-free).
        var unfinalized_parents_buf: [max_depth]?Id = [_]?Id{null} ** max_depth;
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

        var nodes_slice = pool.nodes.items(.node);

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
                nodes_slice = pool.nodes.items(.node);
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
                const n = nodes_slice[@intFromEnum(node_id)];
                if (node_id.noChild(n)) {
                    return Error.InvalidNode;
                }
                const c = childrenOf(node_id, n);

                if (path.left()) {
                    path_lefts_buf[bit_i] = path_parents_buf[bit_i + 1];
                    path_rights_buf[bit_i] = c.right;
                    node_id = c.left;
                    right_move[bit_i] = false;
                    unfinalized_parents_buf[bit_i] = path_parents_buf[bit_i];
                } else {
                    path_lefts_buf[bit_i] = c.left;
                    path_rights_buf[bit_i] = path_parents_buf[bit_i + 1];
                    node_id = c.right;
                    right_move[bit_i] = true;
                }
                path.next();
            }
            // final layer
            {
                const n = nodes_slice[@intFromEnum(node_id)];
                if (node_id.noChild(n)) {
                    return Error.InvalidNode;
                }
                const c = childrenOf(node_id, n);
                if (path.left()) {
                    path_lefts_buf[path_len - 1] = nodes_in[i];
                    path_rights_buf[path_len - 1] = c.right;
                    right_move[path_len - 1] = false;
                    unfinalized_parents_buf[path_len - 1] = path_parents_buf[path_len - 1];
                } else {
                    path_lefts_buf[path_len - 1] = c.left;
                    path_rights_buf[path_len - 1] = nodes_in[i];
                    right_move[path_len - 1] = true;
                }
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
            // Refresh slice after potential pool growth via rebind/unref paths.
            nodes_slice = pool.nodes.items(.node);
        }

        return node_id;
    }

    /// Set multiple nodes in batch where gindices may be at different depths.
    ///
    /// This groups updates by `gindex.pathLen()` (i.e. depth) and applies each group via `setNodes()`.
    /// - gindices MUST be sorted in ascending order beforehand.
    pub fn setNodesGrouped(root_node: Id, pool: *Pool, gindices: []const Gindex, nodes: []Id) Error!Id {
        std.debug.assert(nodes.len == gindices.len);
        if (gindices.len == 0) {
            return root_node;
        }

        var node_id = root_node;
        var start: usize = 0;
        while (start < gindices.len) {
            const depth = gindices[start].pathLen();
            var end: usize = start + 1;
            while (end < gindices.len and gindices[end].pathLen() == depth) : (end += 1) {}

            const prev = node_id;
            const next = try Id.setNodes(prev, pool, gindices[start..end], nodes[start..end]);
            if (prev != root_node and prev != next) {
                pool.unref(prev);
            }
            node_id = next;
            start = end;
        }

        return node_id;
    }
};

/// Read-only adapter that mimics the legacy `State` predicate API.
///
/// The previous bit-packed `State` enum exposed `isFree`, `isLeaf`, etc. so
/// callers could write `id.getState(p).isLeaf()`. With the union refactor the
/// state lives in the union tag (and ref count in a parallel column), but
/// callers still want the predicate-style API; `StateView` keeps the old
/// surface working without a separate enum copy.
pub const StateView = struct {
    pool: *Pool,
    id: Id,

    pub fn isFree(s: StateView) bool {
        return s.pool.nodes.items(.node)[@intFromEnum(s.id)] == .free;
    }
    pub fn isZero(s: StateView) bool {
        return s.pool.nodes.items(.node)[@intFromEnum(s.id)] == .zero;
    }
    pub fn isLeaf(s: StateView) bool {
        return s.pool.nodes.items(.node)[@intFromEnum(s.id)] == .leaf;
    }
    pub fn isBranch(s: StateView) bool {
        return s.pool.nodes.items(.node)[@intFromEnum(s.id)] == .branch;
    }
    pub fn isSlab(s: StateView) bool {
        return s.pool.nodes.items(.node)[@intFromEnum(s.id)] == .slab;
    }
    pub fn isBranchLazy(s: StateView) bool {
        return switch (s.pool.nodes.items(.node)[@intFromEnum(s.id)]) {
            .branch => |b| std.mem.eql(u8, &b.root, &lazy_sentinel),
            else => false,
        };
    }
    pub fn isBranchComputed(s: StateView) bool {
        return switch (s.pool.nodes.items(.node)[@intFromEnum(s.id)]) {
            .branch => |b| !std.mem.eql(u8, &b.root, &lazy_sentinel),
            else => false,
        };
    }
    pub fn getRefCount(s: StateView) u32 {
        return s.pool.nodes.items(.ref_count)[@intFromEnum(s.id)];
    }
    pub fn getNextFree(s: StateView) Id {
        return switch (s.pool.nodes.items(.node)[@intFromEnum(s.id)]) {
            .free => |f| f.next_free,
            else => unreachable,
        };
    }
};

/// Stores nodes in a memory pool, with reference counting and a free list.
pub const Pool = struct {
    allocator: Allocator,
    nodes: std.MultiArrayList(NodeWithMeta).Slice,
    next_free_node: Id,

    /// Initializes the memory pool with `pool_size` + `max_depth` slots. The
    /// first `max_depth` slots are reserved for the precomputed zero-hash
    /// sentinels; user allocations live in the remaining slots.
    pub fn init(allocator: Allocator, pool_size: u32) Error!Pool {
        var pool: Pool = .{
            .allocator = allocator,
            .nodes = undefined,
            .next_free_node = @enumFromInt(max_depth),
        };

        var list = std.MultiArrayList(NodeWithMeta).empty;
        try list.resize(allocator, pool_size + max_depth);
        list.len = pool_size + max_depth;
        pool.nodes = list.slice();

        // Pre-populate zero-hash sentinels at indices 0..max_depth-1.
        // These are never freed and never ref-counted.
        for (0..max_depth) |i| {
            pool.nodes.set(@intCast(i), .{
                .node = .{ .zero = .{ .root = getZeroHash(@intCast(i)).* } },
                .ref_count = 0,
            });
        }

        // Initialize the free list across the user slots.
        const node_col = pool.nodes.items(.node);
        const rc_col = pool.nodes.items(.ref_count);
        for (max_depth..pool.nodes.len) |i| {
            const next: Id = @enumFromInt(@as(u32, @intCast(i + 1)));
            node_col[i] = .{ .free = .{ .next_free = next } };
            rc_col[i] = 0;
        }

        return pool;
    }

    pub fn deinit(self: *Pool) void {
        var list = self.nodes.toMultiArrayList();
        list.deinit(self.allocator);
        self.* = undefined;
    }

    /// Preheat the memory pool by extending the backing storage by
    /// `additional_size` slots and threading them onto the free list.
    pub fn preheat(self: *Pool, additional_size: u32) Allocator.Error!void {
        const size = self.nodes.len;
        const new_size = size + additional_size;

        var list = self.nodes.toMultiArrayList();
        try list.resize(self.allocator, new_size);
        self.nodes = list.slice();

        const node_col = self.nodes.items(.node);
        const rc_col = self.nodes.items(.ref_count);
        for (size..new_size) |i| {
            const next: Id = @enumFromInt(@as(u32, @intCast(i + 1)));
            node_col[i] = .{ .free = .{ .next_free = next } };
            rc_col[i] = 0;
        }
    }

    /// Returns the number of nodes currently in use (not free).
    pub fn getNodesInUse(self: *Pool) usize {
        var count: usize = 0;
        for (self.nodes.items(.node)) |n| {
            if (n != .free) count += 1;
        }
        return count;
    }

    /// Pop the next free slot from the free list. Caller must initialise the
    /// returned slot.
    inline fn createUnsafe(self: *Pool) Id {
        const n: Id = self.next_free_node;
        const node_col = self.nodes.items(.node);
        std.debug.assert(node_col[@intFromEnum(n)] == .free);
        self.next_free_node = node_col[@intFromEnum(n)].free.next_free;
        return n;
    }

    fn create(self: *Pool) Allocator.Error!Id {
        std.debug.assert(@intFromEnum(self.next_free_node) <= self.nodes.len);
        if (@intFromEnum(self.next_free_node) >= self.nodes.len) {
            try self.preheat(1);
        }
        return self.createUnsafe();
    }

    pub fn createLeaf(self: *Pool, hash: *const [32]u8) Allocator.Error!Id {
        const node_id = try self.create();
        self.nodes.items(.node)[@intFromEnum(node_id)] = .{ .leaf = .{ .root = hash.* } };
        self.nodes.items(.ref_count)[@intFromEnum(node_id)] = 0;
        return node_id;
    }

    pub fn createLeafFromUint(self: *Pool, uint: u256) Allocator.Error!Id {
        var hash: [32]u8 = undefined;
        std.mem.writeInt(u256, &hash, uint, .little);
        return self.createLeaf(&hash);
    }

    pub fn createBranch(self: *Pool, left_id: Id, right_id: Id) Error!Id {
        std.debug.assert(@intFromEnum(left_id) < self.nodes.len);
        std.debug.assert(@intFromEnum(right_id) < self.nodes.len);

        const node_id = try self.create();
        const node_col = self.nodes.items(.node);
        std.debug.assert(node_col[@intFromEnum(left_id)] != .free);
        std.debug.assert(node_col[@intFromEnum(right_id)] != .free);
        node_col[@intFromEnum(node_id)] = .{ .branch = .{
            .left = left_id,
            .right = right_id,
            .root = lazy_sentinel,
        } };
        self.nodes.items(.ref_count)[@intFromEnum(node_id)] = 0;
        try self.refUnsafe(left_id);
        try self.refUnsafe(right_id);
        return node_id;
    }

    /// Creates a slab Node owning a heap-allocated `Slab.Storage` initialized
    /// from `chunks`. `len` is the count of valid chunks (`<= K`); the caller
    /// is responsible for ensuring chunks at indices `>= len` are zero-bytes
    /// (the Storage invariant). The returned Node has `root: null` (lazy);
    /// `Id.getRoot` will compute and cache it on first access.
    pub fn createSlab(self: *Pool, chunks: *align(64) const [Slab.K][32]u8, len: u16) Error!Id {
        std.debug.assert(len <= Slab.K);
        const storage = try Slab.allocZero(self.allocator);
        errdefer Slab.destroy(self.allocator, storage);

        storage.chunks = chunks.*;
        storage.len = len;

        const node_id = try self.create();
        self.nodes.items(.node)[@intFromEnum(node_id)] = .{ .slab = .{
            .storage = storage,
            .root = lazy_sentinel,
        } };
        self.nodes.items(.ref_count)[@intFromEnum(node_id)] = 0;
        return node_id;
    }

    /// Allocates nodes into the pool.
    ///
    /// All nodes are allocated with refcount=0.
    /// Nodes allocated here are expected to be attached via `rebind`.
    /// Returns true if pool had to allocate more memory, false otherwise.
    pub fn alloc(self: *Pool, out: []Id) Allocator.Error!bool {
        var allocated: bool = false;
        for (0..out.len) |i| {
            std.debug.assert(@intFromEnum(self.next_free_node) <= self.nodes.len);
            if (@intFromEnum(self.next_free_node) >= self.nodes.len) {
                const remaining = out.len - i;
                try self.preheat(@intCast(remaining));
                allocated = true;
            }
            out[i] = self.createUnsafe();

            // Initialize as a lazy branch with zero(0) children so that any
            // errdefer-driven cleanup walks safely. Caller is expected to
            // overwrite via `rebind`.
            self.nodes.items(.node)[@intFromEnum(out[i])] = .{ .branch = .{
                .left = @enumFromInt(0),
                .right = @enumFromInt(0),
                .root = lazy_sentinel,
            } };
            self.nodes.items(.ref_count)[@intFromEnum(out[i])] = 0;
        }
        return allocated;
    }

    /// Unrefs each node in `out`.
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

        const node_col = self.nodes.items(.node);

        for (0..out.len) |i| {
            std.debug.assert(@intFromEnum(out[i]) < self.nodes.len);

            node_col[@intFromEnum(out[i])] = .{ .branch = .{
                .left = left_ids[i],
                .right = right_ids[i],
                .root = lazy_sentinel,
            } };

            try self.refUnsafe(left_ids[i]);
            try self.refUnsafe(right_ids[i]);
        }
    }

    pub fn ref(self: *Pool, node_id: Id) Error!void {
        // Out of bounds: silently no-op (matches legacy behavior).
        if (@intFromEnum(node_id) >= self.nodes.len) {
            return;
        }
        // Free slot: silently no-op (matches legacy behavior).
        if (self.nodes.items(.node)[@intFromEnum(node_id)] == .free) {
            return;
        }
        try self.refUnsafe(node_id);
    }

    /// Increment the reference count. Assumes `node_id` is in bounds and not free.
    fn refUnsafe(self: *Pool, node_id: Id) Error!void {
        // Zero nodes are sentinels and not ref counted.
        if (self.nodes.items(.node)[@intFromEnum(node_id)] == .zero) {
            return;
        }
        const rc = &self.nodes.items(.ref_count)[@intFromEnum(node_id)];
        if (rc.* == max_ref_count) {
            return Error.RefCountOverflow;
        }
        rc.* += 1;
    }

    pub fn unref(self: *Pool, node_id: Id) void {
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

            // Continue if the node is out of bounds.
            if (@intFromEnum(id) >= self.nodes.len) {
                current = null;
                continue;
            }

            const node_col = self.nodes.items(.node);
            const n = node_col[@intFromEnum(id)];

            // Already-freed node: bug in ref counting. Match legacy: just continue.
            if (n == .free) {
                current = null;
                continue;
            }
            // Zero nodes are not ref counted; nothing to do.
            if (n == .zero) {
                current = null;
                continue;
            }

            // Decrement the reference count, saturating at zero.
            //
            // Legacy semantics (mirrored): `decRefCount` clamped at zero and
            // still returned 0, which caused the caller to walk into the
            // free-the-slot path. So a node already at rc==0 (freshly created
            // and never additionally ref'd) still gets freed on unref.
            const rcs = self.nodes.items(.ref_count);
            const rc_ptr = &rcs[@intFromEnum(id)];
            const new_rc: u32 = if (rc_ptr.* == 0) 0 else rc_ptr.* - 1;
            rc_ptr.* = new_rc;

            if (new_rc != 0) {
                current = null;
                continue;
            }

            // Reached zero: traverse children before freeing the slot.
            switch (n) {
                .branch => |b| {
                    stack[sp] = b.right;
                    sp += 1;
                    current = b.left;
                },
                .slab => |s| {
                    // Free the heap-allocated Storage owned by this slab Node.
                    Slab.destroy(self.allocator, s.storage);
                    current = null;
                },
                else => {
                    current = null;
                },
            }
            // Return the node to the free list.
            node_col[@intFromEnum(id)] = .{ .free = .{ .next_free = self.next_free_node } };
            self.next_free_node = id;
        }
    }
};

/// Fill a view to the specified depth, returning the new root node id.
pub fn fillToDepth(pool: *Pool, bottom: Id, depth: Depth) Error!Id {
    var d = depth;
    var node = bottom;
    while (d > 0) : (d -= 1) {
        node = try pool.createBranch(node, node);
    }

    return node;
}

/// Fill a view to the specified length and depth, returning the new root node id.
pub fn fillToLength(pool: *Pool, leaf: Id, depth: Depth, length: usize) Error!Id {
    const max_length = @as(Gindex.Uint, 1) << depth;
    if (length > max_length) {
        return Error.InvalidLength;
    }

    // fill a full view to the specified depth
    var node_id = try fillToDepth(pool, leaf, depth);

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

    const nodes = pool.nodes.items(.node);

    for (0..path_len - 1) |i| {
        const n = nodes[@intFromEnum(node_id)];
        if (node_id.noChild(n)) {
            return Error.InvalidNode;
        }
        const c = childrenOf(node_id, n);
        if (path.left()) {
            path_lefts[i] = path_parents[i + 1];
            path_rights[i] = c.right;
            node_id = c.left;
        } else {
            path_lefts[i] = c.left;
            path_rights[i] = path_parents[i + 1];
            node_id = c.right;
        }
        path.next();
    }

    // and rebind with zero(0)
    {
        const n = nodes[@intFromEnum(node_id)];
        if (node_id.noChild(n)) return Error.InvalidNode;
        const c = childrenOf(node_id, n);
        if (path.left()) {
            path_lefts[path_len - 1] = @enumFromInt(0);
            path_rights[path_len - 1] = c.right;
        } else {
            path_lefts[path_len - 1] = c.left;
            path_rights[path_len - 1] = @enumFromInt(0);
        }
    }

    // and rebind with zero(0)
    try pool.rebind(
        path_parents,
        path_lefts,
        path_rights,
    );

    return path_parents[0];
}

/// Fill a view with the specified contents, returning the new root node id.
///
/// Note: contents is mutated.
pub fn fillWithContents(pool: *Pool, contents: []Id, depth: Depth) !Id {
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
            contents[i / 2] = try pool.createBranch(contents[i], contents[i + 1]);
        }

        // if the count is odd, we need to add a zero node
        if (i != count) {
            contents[i / 2] = try pool.createBranch(contents[i], @enumFromInt(depth - d));
        }

        count = (count + 1) / 2;
    }

    return contents[0];
}

/// Iterator to traverse all nodes at a specific depth.
/// Use this instead of `getNodesAtDepth` when memory usage is a concern.
pub const DepthIterator = struct {
    pool: *Pool,
    node_id: Id,
    parents_buf: [max_depth]Id,
    diffi: Depth,
    base_gindex: Gindex,
    index: usize,

    /// Initialize a depth iterator starting from `start_index` at the specified `depth`.
    ///
    /// There is no `deinit` function since the iterator does not allocate any resources.
    pub fn init(pool: *Pool, root_node: Id, depth: Depth, start_index: usize) DepthIterator {
        return .{
            .pool = pool,
            .node_id = root_node,
            .parents_buf = undefined,
            .diffi = depth,
            .base_gindex = Gindex.fromDepth(depth, 0),
            .index = start_index,
        };
    }

    pub fn next(self: *DepthIterator) Error!Id {
        const path_len = self.base_gindex.pathLen();
        // Depth 0: only the root exists; yield once then finish.
        if (@intFromEnum(self.base_gindex) <= 1) {
            if (self.index != 0) return Error.InvalidLength;
            self.index = 1;
            return self.node_id;
        }

        const max_length: Gindex.Uint = @intFromEnum(self.base_gindex);
        if (self.index >= max_length) return Error.InvalidLength;

        const nodes = self.pool.nodes.items(.node);

        // Compute gindex for current index at the requested depth.
        const gindex = Gindex.fromUint(@intCast(@intFromEnum(self.base_gindex) | self.index));

        // diffi: how many levels we can reuse from previous traversal (initialized to depth by caller state)
        const d = path_len - self.diffi;

        var path = gindex.toPath();
        path.nextN(d);

        var node_id = self.node_id;

        // Navigate down from the shared prefix (d) to the target, updating parents.
        for (d..path_len) |bit_i| {
            const n = nodes[@intFromEnum(node_id)];
            if (node_id.noChild(n)) {
                return Error.InvalidNode;
            }
            const c = childrenOf(node_id, n);
            self.parents_buf[bit_i] = node_id;
            node_id = if (path.left()) c.left else c.right;
            path.next();
        }

        // Yield current node.
        const out_id = node_id;

        // Prepare state for next index.
        const index = self.index;
        self.index += 1;

        if (self.index >= max_length) {
            // No next element; iterator is done after this yield.
            return out_id;
        }

        // Same "depth diff" computation as getNodesAtDepth (underflow-safe: only used when there is a next index).
        self.diffi = @intCast(@bitSizeOf(Gindex) - @clz(index ^ (index + 1)));
        self.node_id = self.parents_buf[path_len - self.diffi];

        return out_id;
    }
};

/// Incrementally build a tree by appending leaves, filling missing right siblings with zero-nodes.
/// Matches the behavior of `fillWithContents`, but optimized for incremental appends.
pub const FillWithContentsIterator = struct {
    pool: *Pool,
    depth: Depth,
    /// Absolute depth, in chunks, of each appended Id. For depth-0 leaves
    /// (chunks) this is 0. For slab Ids it is `Slab.k_log2`. Zero fillers
    /// emitted by `finish()` for missing right siblings at iterator level L
    /// must therefore be at absolute depth `L + leaf_offset`.
    leaf_offset: Depth,
    // At each level i, holds either null or the unpaired left node at that level.
    lefts: [max_depth]?Id,

    /// Initialize an iterator where each appended Id is a depth-0 leaf
    /// (a chunk). Equivalent to `initWithOffset(pool, depth, 0)`.
    pub fn init(pool: *Pool, depth: Depth) FillWithContentsIterator {
        return initWithOffset(pool, depth, 0);
    }

    /// Initialize an iterator where each appended Id is a depth-`leaf_offset`
    /// subtree (e.g. a slab Id is a depth-`Slab.k_log2` subtree of K chunks).
    /// Zero fillers in `finish()` use `@enumFromInt(level + leaf_offset)`
    /// so the resulting tree's root is correct under standard SSZ
    /// merkleization at absolute depth `depth + leaf_offset`.
    pub fn initWithOffset(pool: *Pool, depth: Depth, leaf_offset: Depth) FillWithContentsIterator {
        return .{
            .pool = pool,
            .depth = depth,
            .leaf_offset = leaf_offset,
            .lefts = [_]?Id{null} ** max_depth,
        };
    }

    /// Clean up references held by the iterator.
    ///
    /// This only needs to be called if the iterator is abandoned before `finish` is called.
    pub fn deinit(self: *FillWithContentsIterator) void {
        for (self.lefts) |left| {
            if (left) |node_id| {
                self.pool.unref(node_id);
            }
        }
    }

    /// Append a leaf (or subtree root at leaf level). Builds branches incrementally.
    pub fn append(self: *FillWithContentsIterator, node_id: Id) Error!void {
        // Bounds check
        if (self.lefts[self.depth] != null) {
            return Error.InvalidLength;
        }

        var carry = node_id;
        for (0..self.depth) |level| {
            if (self.lefts[level]) |left| {
                self.lefts[level] = null;
                carry = try self.pool.createBranch(left, carry);
            } else {
                self.lefts[level] = carry;
                return;
            }
        }
        // Only reaches here if the tree is full
        self.lefts[self.depth] = carry;
    }

    /// Finalize the tree, returning the root node. Uses zero-nodes to pad missing right siblings.
    pub fn finish(self: *FillWithContentsIterator) Error!Id {
        if (self.lefts[self.depth]) |root| {
            return root;
        }

        // Initial carry = zero subtree at absolute depth `depth + leaf_offset`.
        var carry: Id = @enumFromInt(@as(u32, self.depth) + @as(u32, self.leaf_offset));
        var start_level: usize = self.depth;

        // Find the lowest non-null as starting carry. Its absolute depth is
        // `level + leaf_offset` because each appended Id sits at depth `leaf_offset`.
        for (0..self.depth) |level| {
            if (self.lefts[level] != null) {
                carry = @enumFromInt(@as(u32, @intCast(level)) + @as(u32, self.leaf_offset));
                start_level = level;
                break;
            }
        }

        // Starting from the lowest non-null, build upwards with zero-nodes.
        // A missing right sibling at iterator level `level` is a zero subtree
        // at absolute depth `level + leaf_offset`.
        for (start_level..self.depth) |level| {
            if (self.lefts[level]) |left| {
                self.lefts[level] = null;
                carry = try self.pool.createBranch(left, carry);
            } else {
                carry = try self.pool.createBranch(carry, @enumFromInt(@as(u32, @intCast(level)) + @as(u32, self.leaf_offset)));
            }
        }
        return carry;
    }
};
