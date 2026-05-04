//! Merkle node backed by a memory pool.
//!
//! Nodes are stored as a flat struct of independent fields (no tagged union)
//! so that `MultiArrayList` splits each field into its own dense SoA column.
//! Variants are distinguished by `kind`:
//!   - `free`: an entry on the free list. `left` carries the next free `Id`.
//!   - `zero`: a precomputed zero-hash sentinel. `root` holds the precomputed
//!     hash. Children are synthesised from the slot index (depth-1 zero).
//!   - `leaf`: a 32-byte leaf hash held in `root`.
//!   - `branch`: parent with two children (`left`, `right`) and a cached root
//!     in `root` (`lazy_sentinel` = uncomputed; any other value = computed).
//!   - `slab`: chunked-leaf payload. `cache` is a `*Slab.Storage` pointer cast
//!     to `*anyopaque`; `root` caches the slab subtree root (`lazy_sentinel`
//!     means lazy).
//!
//! Why flat fields? `getNodesAtDepth` is the dominant navigation hotspot. The
//! union layout forced every visit to touch the full 48 B payload (1.3 nodes /
//! cache-line). With flat columns the navigation loop reads only `kind` (1 B)
//! and one child Id (4 B) per visit — recovering ~16 nodes / cache-line on the
//! hot path while leaving payload columns untouched.
//!
//! Reference counts live in their own column (`ref_count`). `unref` scans
//! `ref_count` and `kind` without touching `root`/`cache` until the slot
//! actually drops to zero.
const std = @import("std");
const Allocator = std.mem.Allocator;

const hashOne = @import("hashing").hashOne;
const getZeroHash = @import("hashing").getZeroHash;
const max_depth = @import("hashing").max_depth;
const Depth = @import("hashing").Depth;
const Gindex = @import("gindex.zig").Gindex;
const Slab = @import("slab.zig");

// Flat node fields (file-as-struct). Each field becomes a dedicated SoA
// column inside `MultiArrayList(@This())`.
//
// `kind` + `ref_count` are packed into a single `state: State` u32:
//   - bit 31 set   → free slot;  bits 0..30 = next-free Id
//   - bit 31 clear → in-use;     bits 28..30 = kind, bits 0..27 = ref_count
left: Id,
right: Id,
root: [32]u8,
cache: ?*anyopaque,
state: State,

const Node = @This();

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

/// Maximum reference count an in-use node may hold.
///
/// `State` packs ref_count into 28 bits, so the saturating sentinel is the
/// largest 28-bit value.
pub const max_ref_count: u32 = State.rc_mask;

/// Variant tag exposed to callers. The encoded form lives inside `State`'s
/// 3-bit kind field; `.free` is encoded as `state.isFree()` (the high bit)
/// rather than as a 3-bit value, so the in-use kinds occupy values 1..5
/// and the 3-bit slot stores `tag - 1`.
pub const NodeKind = enum(u8) {
    free = 0,
    zero = 1,
    leaf = 2,
    branch = 3,
    slab = 4,
    branch_struct = 5,
};

/// Packed `[ free_bit | kind:3 | ref_count:28 ]` (in-use) or
/// `[ free_bit | next_free:31 ]` (free).
pub const State = enum(u32) {
    _,

    pub const free_bit: u32 = 0x8000_0000;
    pub const next_free_mask: u32 = 0x7FFF_FFFF;
    pub const kind_shift: u5 = 28;
    pub const kind_field_mask: u32 = 0x7000_0000;
    pub const rc_mask: u32 = 0x0FFF_FFFF;

    pub inline fn isFree(s: State) bool {
        return @intFromEnum(s) & free_bit != 0;
    }

    /// Branch-free decode: free → NodeKind(0)=.free, in-use → NodeKind(enc+1).
    pub inline fn kind(s: State) NodeKind {
        const raw = @intFromEnum(s);
        const is_in_use: u32 = @intFromBool((raw & free_bit) == 0);
        const enc: u32 = (raw & kind_field_mask) >> kind_shift;
        return @enumFromInt(@as(u8, @intCast(is_in_use * (enc + 1))));
    }

    pub inline fn refCount(s: State) u32 {
        std.debug.assert(!s.isFree());
        return @intFromEnum(s) & rc_mask;
    }

    pub inline fn nextFree(s: State) Id {
        std.debug.assert(s.isFree());
        return @enumFromInt(@intFromEnum(s) & next_free_mask);
    }

    pub inline fn initFree(next: Id) State {
        std.debug.assert(@intFromEnum(next) <= next_free_mask);
        return @enumFromInt(free_bit | @intFromEnum(next));
    }

    pub inline fn initInUse(k: NodeKind, rc: u32) State {
        std.debug.assert(k != .free);
        std.debug.assert(rc <= rc_mask);
        const enc: u32 = (@as(u32, @intFromEnum(k)) - 1) << kind_shift;
        return @enumFromInt(enc | rc);
    }

    /// Replaces the kind tag while preserving the ref count.
    pub inline fn setKind(s: *State, k: NodeKind) void {
        std.debug.assert(!s.isFree());
        std.debug.assert(k != .free);
        const enc: u32 = (@as(u32, @intFromEnum(k)) - 1) << kind_shift;
        s.* = @enumFromInt((@intFromEnum(s.*) & rc_mask) | enc);
    }

    pub inline fn incRefCount(s: *State) Error!u32 {
        std.debug.assert(!s.isFree());
        const rc = s.refCount();
        if (rc == rc_mask) return Error.RefCountOverflow;
        s.* = @enumFromInt(@intFromEnum(s.*) + 1);
        return rc + 1;
    }

    pub inline fn decRefCount(s: *State) u32 {
        std.debug.assert(!s.isFree());
        const rc = s.refCount();
        if (rc == 0) return 0;
        s.* = @enumFromInt(@intFromEnum(s.*) - 1);
        return rc - 1;
    }
};

/// Vtable + struct pointer that backs every `.branch_struct` Node.
///
/// The Pool owns this allocation. `ptr` is an opaque-typed pointer to a
/// caller-supplied wrapped struct that implements the required methods:
///   - `init(allocator, *const T) Error!*const T` — clone the struct into the pool
///   - `deinit(allocator) void` — free the cloned struct
///   - `getRoot(out: *[32]u8) void` — compute the merkle root from cached fields
///   - `toTree(pool: *Pool) Error!Id` — materialize a temporary, fully-navigable
///     PMT subtree from the cached struct so that proof traversal can walk
///     into the container's interior. The returned Id is owned by the caller
///     (typically created with refcount=0 by the underlying field-tree
///     constructors); the proof code wraps it with `pool.unref` on cleanup.
pub const BranchStructRef = struct {
    ptr: *anyopaque,
    get_root: *const fn (ptr: *const anyopaque, out: *[32]u8) void,
    to_tree: *const fn (ptr: *const anyopaque, pool: *Pool) Error!Id,
    deinit: *const fn (ptr: *anyopaque, allocator: Allocator) void,
};

/// Sentinel value for a lazy (uncomputed) `root` field on `branch` and
/// `slab` variants. We use all-`0xFF` because cryptographic SHA-256 outputs
/// are extremely unlikely to equal this value (~1 in 2^256), avoiding the
/// 1-byte tag overhead an `?[32]u8` Optional would add.
pub const lazy_sentinel: [32]u8 = [_]u8{0xFF} ** 32;

/// Pair of child Ids. Always defined when `noChild` is false.
const Children = struct { left: Id, right: Id };

/// Resolve the (left, right) child Ids for a navigable node.
///
/// For branch nodes the children come directly from the `left`/`right`
/// columns. For zero nodes (depth >= 1) the children are synthesised:
/// `zero(d).left = zero(d).right = zero(d-1)`.
inline fn childrenOf(
    node_id: Id,
    kind: NodeKind,
    lefts: []const Id,
    rights: []const Id,
) Children {
    const idx = @intFromEnum(node_id);
    return switch (kind) {
        .branch => .{ .left = lefts[idx], .right = rights[idx] },
        .zero => blk: {
            std.debug.assert(idx >= 1);
            const prev: Id = @enumFromInt(idx - 1);
            break :blk .{ .left = prev, .right = prev };
        },
        // `noChild` guards prevent reaching here for these variants.
        .leaf, .free => unreachable,
        // Slabs are terminal — they have no Id-children.
        .slab => unreachable,
        // Branch-struct nodes are terminal — they have no Id-children.
        .branch_struct => unreachable,
    };
}

/// Inline helper: returns true if navigation to a child is impossible.
inline fn noChildKind(node_id: Id, kind: NodeKind) bool {
    return switch (kind) {
        .leaf => true,
        // `Id(0)` is the depth-0 zero sentinel: nothing below it.
        .zero => @intFromEnum(node_id) == 0,
        // Branches always have children, except the synthetic `Id(0)` slot.
        .branch => @intFromEnum(node_id) == 0,
        // Free slots are not user-visible nodes.
        .free => true,
        // Slabs are terminal: their chunks are not Id-children.
        .slab => true,
        // Branch-struct nodes are terminal: their fields live inside the
        // wrapped struct, not as separate Id-children.
        .branch_struct => true,
    };
}

/// Read the slab Storage pointer for a slot known to be `.slab`.
inline fn slabStorage(cache_col: []const ?*anyopaque, idx: u32) *Slab.Storage {
    const raw = cache_col[idx].?;
    return @ptrCast(@alignCast(raw));
}

/// Read the BranchStructRef for a slot known to be `.branch_struct`.
inline fn branchStructRef(cache_col: []const ?*anyopaque, idx: u32) *BranchStructRef {
    const raw = cache_col[idx].?;
    return @ptrCast(@alignCast(raw));
}

/// A handle which uniquely identifies the node within a `Pool`.
pub const Id = enum(u32) {
    _,

    /// Returns true if navigation to a child node is impossible at `node`.
    ///
    /// Matches legacy semantics: leaves and `Id(0)` (the depth-0 zero
    /// sentinel) have no navigable children. Zero nodes at depth >= 1
    /// remain navigable — both children point to `zero(d-1)`.
    pub inline fn noChild(node_id: Id, kind: NodeKind) bool {
        return noChildKind(node_id, kind);
    }

    /// Returns the root hash, computing any lazy branch nodes on demand.
    pub fn getRoot(node_id: Id, pool: *Pool) *const [32]u8 {
        const idx = @intFromEnum(node_id);
        const states = pool.nodes.items(.state);
        const roots = pool.nodes.items(.root);
        const kind = states[idx].kind();

        switch (kind) {
            .zero, .leaf => return &roots[idx],
            // Defense-in-depth: `unreachable` would be UB-eliminated under
            // ReleaseFast; if a stale Id reaches here, the switch dispatch
            // would silently misroute to another arm and read the slot's
            // bytes as a valid variant — typically manifesting as a SEGV deep
            // inside the .slab arm. A `@panic` cannot be elided and surfaces
            // the UAF directly.
            .free => @panic("getRoot called on .free slot — use-after-free"),
            .branch => {
                if (!std.mem.eql(u8, &roots[idx], &lazy_sentinel)) {
                    return &roots[idx];
                }
                const lefts = pool.nodes.items(.left);
                const rights = pool.nodes.items(.right);
                const left_id = lefts[idx];
                const right_id = rights[idx];
                const left_root = left_id.getRoot(pool);
                const right_root = right_id.getRoot(pool);
                var hash: [32]u8 = undefined;
                hashOne(&hash, left_root, right_root);
                roots[idx] = hash;
                return &roots[idx];
            },
            .slab => {
                if (!std.mem.eql(u8, &roots[idx], &lazy_sentinel)) {
                    return &roots[idx];
                }
                const cache_col = pool.nodes.items(.cache);
                const storage = slabStorage(cache_col, idx);
                var hash: [32]u8 = undefined;
                Slab.computeRoot(storage, &hash);
                roots[idx] = hash;
                return &roots[idx];
            },
            .branch_struct => {
                if (!std.mem.eql(u8, &roots[idx], &lazy_sentinel)) {
                    return &roots[idx];
                }
                const cache_col = pool.nodes.items(.cache);
                const ref_ptr = branchStructRef(cache_col, idx);
                var hash: [32]u8 = undefined;
                ref_ptr.get_root(ref_ptr.ptr, &hash);
                roots[idx] = hash;
                return &roots[idx];
            },
        }
    }

    pub fn getLeft(node_id: Id, pool: *Pool) Error!Id {
        const idx = @intFromEnum(node_id);
        const kind = pool.nodes.items(.state)[idx].kind();
        if (noChildKind(node_id, kind)) return Error.InvalidNode;
        return childrenOf(
            node_id,
            kind,
            pool.nodes.items(.left),
            pool.nodes.items(.right),
        ).left;
    }

    pub fn getRight(node_id: Id, pool: *Pool) Error!Id {
        const idx = @intFromEnum(node_id);
        const kind = pool.nodes.items(.state)[idx].kind();
        if (noChildKind(node_id, kind)) return Error.InvalidNode;
        return childrenOf(
            node_id,
            kind,
            pool.nodes.items(.left),
            pool.nodes.items(.right),
        ).right;
    }

    /// Returns a read-only pointer to the slab's K-chunk array. Returns
    /// `Error.InvalidNode` if the node is not a slab variant.
    pub fn getSlabChunks(node_id: Id, pool: *Pool) Error!*align(64) const [Slab.K][32]u8 {
        const idx = @intFromEnum(node_id);
        if (pool.nodes.items(.state)[idx].kind() != .slab) return Error.InvalidNode;
        return &slabStorage(pool.nodes.items(.cache), idx).chunks;
    }

    /// Returns the slab's `len` (number of valid chunks, `<= K`). Returns
    /// `Error.InvalidNode` if the node is not a slab variant.
    pub fn getSlabLen(node_id: Id, pool: *Pool) Error!u16 {
        const idx = @intFromEnum(node_id);
        if (pool.nodes.items(.state)[idx].kind() != .slab) return Error.InvalidNode;
        return slabStorage(pool.nodes.items(.cache), idx).len;
    }

    /// Returns a new slab `Id` with `chunk` at `intra_index`; the receiver slab
    /// is unchanged. Heap Storage is cloned. The returned slab has a lazy root.
    /// Returns `Error.InvalidNode` if the receiver is not a slab variant.
    pub fn setSlabChunk(node_id: Id, pool: *Pool, intra_index: u16, chunk: *const [32]u8) Error!Id {
        std.debug.assert(intra_index < Slab.K);

        const idx = @intFromEnum(node_id);
        if (pool.nodes.items(.state)[idx].kind() != .slab) return Error.InvalidNode;
        const old_storage = slabStorage(pool.nodes.items(.cache), idx);

        const new_storage = try Slab.allocZero(pool.allocator);
        errdefer Slab.destroy(pool.allocator, new_storage);

        new_storage.chunks = old_storage.chunks;
        new_storage.len = old_storage.len;
        new_storage.chunks[intra_index] = chunk.*;

        const new_id = try pool.create();
        // Re-fetch column slices after pool.create() — preheat may have
        // realloc'd and invalidated any earlier slice we held.
        const new_idx = @intFromEnum(new_id);
        pool.nodes.items(.state)[new_idx] = State.initInUse(.slab, 0);
        pool.nodes.items(.cache)[new_idx] = @ptrCast(new_storage);
        pool.nodes.items(.root)[new_idx] = lazy_sentinel;
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

        const idx = @intFromEnum(node_id);
        if (pool.nodes.items(.state)[idx].kind() != .slab) return Error.InvalidNode;
        const old_storage = slabStorage(pool.nodes.items(.cache), idx);

        const new_storage = try Slab.allocZero(pool.allocator);
        errdefer Slab.destroy(pool.allocator, new_storage);

        new_storage.chunks = old_storage.chunks;
        new_storage.len = old_storage.len;

        for (intra_indices, new_chunks) |i, ptr| {
            std.debug.assert(i < Slab.K);
            new_storage.chunks[i] = ptr.*;
        }

        const new_id = try pool.create();
        const new_idx = @intFromEnum(new_id);
        pool.nodes.items(.state)[new_idx] = State.initInUse(.slab, 0);
        pool.nodes.items(.cache)[new_idx] = @ptrCast(new_storage);
        pool.nodes.items(.root)[new_idx] = lazy_sentinel;
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

        const states = pool.nodes.items(.state);
        const lefts = pool.nodes.items(.left);
        const rights = pool.nodes.items(.right);

        var node_id: Id = root_node;
        for (0..path_len) |_| {
            const idx = @intFromEnum(node_id);
            const k = states[idx].kind();
            if (noChildKind(node_id, k)) {
                return Error.InvalidNode;
            }
            const c = childrenOf(node_id, k, lefts, rights);
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

        const states = pool.nodes.items(.state);
        const lefts = pool.nodes.items(.left);
        const rights = pool.nodes.items(.right);

        var id = root_node;

        for (0..path_len - 1) |i| {
            const idx = @intFromEnum(id);
            const k = states[idx].kind();
            if (noChildKind(id, k)) {
                return Error.InvalidNode;
            }
            const c = childrenOf(id, k, lefts, rights);
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
            const idx = @intFromEnum(id);
            const k = states[idx].kind();
            if (noChildKind(id, k)) {
                return Error.InvalidNode;
            }
            const c = childrenOf(id, k, lefts, rights);
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

        // Hot navigation loop reads only `kinds` (1 B/visit) and one of
        // `lefts`/`rights` (4 B/visit). Bind once outside the index loop —
        // no allocations occur inside.
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
                const idx = @intFromEnum(node_id);
                const k = states[idx].kind();
                if (noChildKind(node_id, k)) {
                    return Error.InvalidNode;
                }
                const c = childrenOf(node_id, k, lefts, rights);
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

        // Bind navigation columns once. Refresh after any allocation that
        // could grow the underlying MAL (alloc/rebind/unref-driven preheat).
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
                const idx = @intFromEnum(node_id);
                const k = states[idx].kind();
                if (noChildKind(node_id, k)) {
                    return Error.InvalidNode;
                }
                const c = childrenOf(node_id, k, lefts, rights);

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
                const idx = @intFromEnum(node_id);
                const k = states[idx].kind();
                if (noChildKind(node_id, k)) {
                    return Error.InvalidNode;
                }
                const c = childrenOf(node_id, k, lefts, rights);
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
            // node_id we read above is preserved by value, but the column slices
            // may be stale if any allocation happened. Refresh defensively.
            states = pool.nodes.items(.state);
            lefts = pool.nodes.items(.left);
            rights = pool.nodes.items(.right);
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

        const states = pool.nodes.items(.state);
        const lefts = pool.nodes.items(.left);
        const rights = pool.nodes.items(.right);

        var node_id = root_node;

        for (0..path_len - 1) |i| {
            const idx = @intFromEnum(node_id);
            const k = states[idx].kind();
            if (noChildKind(node_id, k)) {
                return Error.InvalidNode;
            }
            const c = childrenOf(node_id, k, lefts, rights);

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
            const idx = @intFromEnum(node_id);
            const k = states[idx].kind();
            if (noChildKind(node_id, k)) {
                return Error.InvalidNode;
            }
            const c = childrenOf(node_id, k, lefts, rights);

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
                const idx = @intFromEnum(node_id);
                const k = states[idx].kind();
                if (noChildKind(node_id, k)) {
                    return Error.InvalidNode;
                }
                const c = childrenOf(node_id, k, lefts, rights);

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
                const idx = @intFromEnum(node_id);
                const k = states[idx].kind();
                if (noChildKind(node_id, k)) {
                    return Error.InvalidNode;
                }
                const c = childrenOf(node_id, k, lefts, rights);
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
            // Refresh slices after potential pool growth via rebind/unref paths.
            states = pool.nodes.items(.state);
            lefts = pool.nodes.items(.left);
            rights = pool.nodes.items(.right);
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
/// callers could write `id.getState(p).isLeaf()`. With the flat-column refactor
/// the variant tag lives in the `kind` column (and ref count in its own
/// column); `StateView` keeps the old surface working by reading those columns
/// directly.
pub const StateView = struct {
    pool: *Pool,
    id: Id,

    inline fn kind(s: StateView) NodeKind {
        return s.pool.nodes.items(.state)[@intFromEnum(s.id)].kind();
    }

    pub fn isFree(s: StateView) bool {
        return s.kind() == .free;
    }
    pub fn isZero(s: StateView) bool {
        return s.kind() == .zero;
    }
    pub fn isLeaf(s: StateView) bool {
        return s.kind() == .leaf;
    }
    pub fn isBranch(s: StateView) bool {
        return s.kind() == .branch;
    }
    pub fn isSlab(s: StateView) bool {
        return s.kind() == .slab;
    }
    pub fn isBranchStruct(s: StateView) bool {
        return s.kind() == .branch_struct;
    }
    pub fn isBranchLazy(s: StateView) bool {
        if (s.kind() != .branch) return false;
        return std.mem.eql(u8, &s.pool.nodes.items(.root)[@intFromEnum(s.id)], &lazy_sentinel);
    }
    pub fn isBranchComputed(s: StateView) bool {
        if (s.kind() != .branch) return false;
        return !std.mem.eql(u8, &s.pool.nodes.items(.root)[@intFromEnum(s.id)], &lazy_sentinel);
    }
    pub fn getRefCount(s: StateView) u32 {
        return s.pool.nodes.items(.state)[@intFromEnum(s.id)].refCount();
    }
    pub fn getNextFree(s: StateView) Id {
        return s.pool.nodes.items(.state)[@intFromEnum(s.id)].nextFree();
    }
};

/// Stores nodes in a memory pool, with reference counting and a free list.
pub const Pool = struct {
    allocator: Allocator,
    nodes: std.MultiArrayList(Node).Slice,
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

        var list = std.MultiArrayList(Node).empty;
        try list.resize(allocator, pool_size + max_depth);
        list.len = pool_size + max_depth;
        pool.nodes = list.slice();

        // Pre-populate zero-hash sentinels at indices 0..max_depth-1.
        // These are never freed and never ref-counted.
        for (0..max_depth) |i| {
            pool.nodes.set(@intCast(i), .{
                .left = @enumFromInt(0),
                .right = @enumFromInt(0),
                .root = getZeroHash(@intCast(i)).*,
                .cache = null,
                .state = State.initInUse(.zero, 0),
            });
        }

        // Initialize the free list across the user slots. `state` carries
        // kind=free + next_free link in the low 31 bits; `cache` must be
        // null so no future path dereferences a stale pointer; other fields
        // can stay undefined.
        const state_col = pool.nodes.items(.state);
        const cache_col = pool.nodes.items(.cache);
        for (max_depth..pool.nodes.len) |i| {
            const next: Id = @enumFromInt(@as(u32, @intCast(i + 1)));
            state_col[i] = State.initFree(next);
            cache_col[i] = null;
        }

        return pool;
    }

    pub fn deinit(self: *Pool) void {
        // Release heap payloads owned by `.slab` and `.branch_struct` slots.
        // The MultiArrayList only owns its own column buffers; cache pointers
        // are heap-allocated separately and become unreachable when callers
        // tear down the pool without first unref'ing every root.
        const states = self.nodes.items(.state);
        const caches = self.nodes.items(.cache);
        for (states, caches) |s, cache_opt| {
            const ptr = cache_opt orelse continue;
            if (s.isFree()) continue;
            switch (s.kind()) {
                .slab => Slab.destroy(
                    self.allocator,
                    @as(*Slab.Storage, @ptrCast(@alignCast(ptr))),
                ),
                .branch_struct => {
                    const struct_ref: *BranchStructRef = @ptrCast(@alignCast(ptr));
                    struct_ref.deinit(struct_ref.ptr, self.allocator);
                    self.allocator.destroy(struct_ref);
                },
                else => {},
            }
        }
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

        const state_col = self.nodes.items(.state);
        const cache_col = self.nodes.items(.cache);
        for (size..new_size) |i| {
            const next: Id = @enumFromInt(@as(u32, @intCast(i + 1)));
            state_col[i] = State.initFree(next);
            cache_col[i] = null;
        }
    }

    /// Returns the number of nodes currently in use (not free).
    pub fn getNodesInUse(self: *Pool) usize {
        var count: usize = 0;
        for (self.nodes.items(.state)) |s| {
            if (!s.isFree()) count += 1;
        }
        return count;
    }

    /// Pop the next free slot from the free list. Caller must initialise the
    /// returned slot.
    inline fn createUnsafe(self: *Pool) Id {
        const n: Id = self.next_free_node;
        const idx = @intFromEnum(n);
        const state_col = self.nodes.items(.state);
        std.debug.assert(state_col[idx].isFree());
        self.next_free_node = state_col[idx].nextFree();
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
        const idx = @intFromEnum(node_id);
        self.nodes.items(.state)[idx] = State.initInUse(.leaf, 0);
        self.nodes.items(.root)[idx] = hash.*;
        self.nodes.items(.cache)[idx] = null;
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
        const idx = @intFromEnum(node_id);
        const states = self.nodes.items(.state);
        std.debug.assert(!states[@intFromEnum(left_id)].isFree());
        std.debug.assert(!states[@intFromEnum(right_id)].isFree());
        states[idx] = State.initInUse(.branch, 0);
        self.nodes.items(.left)[idx] = left_id;
        self.nodes.items(.right)[idx] = right_id;
        self.nodes.items(.root)[idx] = lazy_sentinel;
        self.nodes.items(.cache)[idx] = null;
        try self.refUnsafe(left_id);
        try self.refUnsafe(right_id);
        return node_id;
    }

    /// Creates a slab Node owning a heap-allocated `Slab.Storage` initialized
    /// from `chunks`. `len` is the count of valid chunks (`<= K`); the caller
    /// is responsible for ensuring chunks at indices `>= len` are zero-bytes
    /// (the Storage invariant). The returned Node has a lazy root;
    /// `Id.getRoot` will compute and cache it on first access.
    pub fn createSlab(self: *Pool, chunks: *align(64) const [Slab.K][32]u8, len: u16) Error!Id {
        std.debug.assert(len <= Slab.K);
        const storage = try Slab.allocZero(self.allocator);
        errdefer Slab.destroy(self.allocator, storage);

        storage.chunks = chunks.*;
        storage.len = len;

        const node_id = try self.create();
        const idx = @intFromEnum(node_id);
        self.nodes.items(.state)[idx] = State.initInUse(.slab, 0);
        self.nodes.items(.cache)[idx] = @ptrCast(storage);
        self.nodes.items(.root)[idx] = lazy_sentinel;
        return node_id;
    }

    /// Create a `.branch_struct` Node holding a cloned `T` instance.
    ///
    /// `T` must implement:
    ///   - `pub fn init(allocator: Allocator, *const T) Error!*const T`
    ///   - `pub fn deinit(*T, allocator: Allocator) void`
    ///   - `pub fn getRoot(*const T, out: *[32]u8) void`
    ///
    /// The Pool clones `ptr` (so the caller retains ownership of its copy) and
    /// owns the resulting `BranchStructRef`. The returned Node has a lazy root;
    /// `Id.getRoot` computes and caches it on first access.
    pub fn createBranchStruct(self: *Pool, comptime T: type, ptr: *const T) Error!Id {
        // Clone the struct into the Pool's allocator.
        const cloned = try T.init(self.allocator, ptr);
        errdefer @constCast(cloned).deinit(self.allocator);

        const ref_ptr = try self.allocator.create(BranchStructRef);
        errdefer self.allocator.destroy(ref_ptr);

        ref_ptr.* = .{
            .ptr = @ptrCast(@constCast(cloned)),
            .get_root = struct {
                fn call(erased: *const anyopaque, out: *[32]u8) void {
                    const typed: *const T = @ptrCast(@alignCast(erased));
                    T.getRoot(typed, out);
                }
            }.call,
            .to_tree = struct {
                fn call(erased: *const anyopaque, p: *Pool) Error!Id {
                    const typed: *const T = @ptrCast(@alignCast(erased));
                    return try T.toTree(typed, p);
                }
            }.call,
            .deinit = struct {
                fn call(erased: *anyopaque, allocator: Allocator) void {
                    const typed: *T = @ptrCast(@alignCast(erased));
                    T.deinit(typed, allocator);
                }
            }.call,
        };

        const node_id = try self.create();
        const idx = @intFromEnum(node_id);
        self.nodes.items(.state)[idx] = State.initInUse(.branch_struct, 0);
        // `left`/`right` unused — set to Id(0) for safety (a benign bit pattern
        // matching `noChild` semantics).
        self.nodes.items(.left)[idx] = @enumFromInt(0);
        self.nodes.items(.right)[idx] = @enumFromInt(0);
        self.nodes.items(.cache)[idx] = @ptrCast(ref_ptr);
        self.nodes.items(.root)[idx] = lazy_sentinel;
        return node_id;
    }

    /// Returns a read-only pointer to the wrapped struct held by a
    /// `.branch_struct` Node. Returns `Error.InvalidNode` if the slot is not
    /// a branch-struct variant.
    pub fn getStructPtr(self: *Pool, node_id: Id, comptime T: type) Error!*const T {
        const idx = @intFromEnum(node_id);
        if (self.nodes.items(.state)[idx].kind() != .branch_struct) {
            return Error.InvalidNode;
        }
        const ref_ptr = branchStructRef(self.nodes.items(.cache), idx);
        return @ptrCast(@alignCast(ref_ptr.ptr));
    }

    /// Materializes a temporary, fully-navigable PMT subtree from a
    /// `.branch_struct` slot's wrapped struct. The returned Id has refcount
    /// matching the underlying field-tree constructors (typically 0 — caller
    /// is responsible for `unref`'ing it once the temporary tree is no longer
    /// needed). Returns `Error.InvalidNode` if the slot is not a branch-struct
    /// variant.
    pub fn materializeBranchStruct(self: *Pool, node_id: Id) Error!Id {
        const idx = @intFromEnum(node_id);
        if (self.nodes.items(.state)[idx].kind() != .branch_struct) {
            return Error.InvalidNode;
        }
        const ref_ptr = branchStructRef(self.nodes.items(.cache), idx);
        return try ref_ptr.to_tree(ref_ptr.ptr, self);
    }

    /// Materializes a temporary, fully-navigable PMT subtree from a `.slab`
    /// slot's K packed chunks. The slab represents a depth-`Slab.k_log2`
    /// subtree of leaves; this builds it explicitly so that proof traversal
    /// can walk into individual chunks. Trailing zero subtrees fill the slab
    /// to full K. The returned Id has refcount=0; caller is responsible for
    /// `unref`'ing it. Returns `Error.InvalidNode` if the slot is not a slab.
    pub fn materializeSlab(self: *Pool, node_id: Id) Error!Id {
        const idx = @intFromEnum(node_id);
        if (self.nodes.items(.state)[idx].kind() != .slab) {
            return Error.InvalidNode;
        }
        const storage = slabStorage(self.nodes.items(.cache), idx);

        // Build a depth-k_log2 perfect tree spanning all K chunks. We always
        // emit K leaves (even those at indices >= storage.len, which are
        // guaranteed to be zero-bytes by the Storage invariant) so that the
        // resulting subtree's root matches the slab's `computeRoot` exactly.
        var it = FillWithContentsIterator.init(self, Slab.k_log2);
        errdefer it.deinit();
        for (0..Slab.K) |i| {
            const leaf = try self.createLeaf(&storage.chunks[i]);
            try it.append(leaf);
        }
        return try it.finish();
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
            const idx = @intFromEnum(out[i]);
            self.nodes.items(.state)[idx] = State.initInUse(.branch, 0);
            self.nodes.items(.left)[idx] = @enumFromInt(0);
            self.nodes.items(.right)[idx] = @enumFromInt(0);
            self.nodes.items(.root)[idx] = lazy_sentinel;
            self.nodes.items(.cache)[idx] = null;
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

        const state_col = self.nodes.items(.state);
        const left_col = self.nodes.items(.left);
        const right_col = self.nodes.items(.right);
        const root_col = self.nodes.items(.root);
        const cache_col = self.nodes.items(.cache);

        for (0..out.len) |i| {
            const idx = @intFromEnum(out[i]);
            std.debug.assert(idx < self.nodes.len);

            // Preserve existing ref count: a previous iteration in this
            // same rebind() call may have already ref'd this slot.
            state_col[idx].setKind(.branch);
            left_col[idx] = left_ids[i];
            right_col[idx] = right_ids[i];
            root_col[idx] = lazy_sentinel;
            cache_col[idx] = null;

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
        if (self.nodes.items(.state)[@intFromEnum(node_id)].kind() == .free) {
            return;
        }
        try self.refUnsafe(node_id);
    }

    /// Increment the reference count. Assumes `node_id` is in bounds and not free.
    fn refUnsafe(self: *Pool, node_id: Id) Error!void {
        const s = &self.nodes.items(.state)[@intFromEnum(node_id)];
        // Zero nodes are sentinels and not ref counted.
        if (s.kind() == .zero) return;
        _ = try s.incRefCount();
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

            const states = self.nodes.items(.state);
            const k = states[@intFromEnum(id)].kind();

            // Already-freed node: bug in ref counting. Match legacy: just continue.
            if (k == .free) {
                current = null;
                continue;
            }
            // Zero nodes are not ref counted; nothing to do.
            if (k == .zero) {
                current = null;
                continue;
            }

            // Decrement the reference count, saturating at zero. A node at
            // rc==0 (freshly created and never additionally ref'd) still
            // gets freed on unref (legacy semantics preserved by decRefCount).
            const new_rc = states[@intFromEnum(id)].decRefCount();

            if (new_rc != 0) {
                current = null;
                continue;
            }

            // Reached zero: traverse children before freeing the slot.
            switch (k) {
                .branch => {
                    stack[sp] = self.nodes.items(.right)[@intFromEnum(id)];
                    sp += 1;
                    current = self.nodes.items(.left)[@intFromEnum(id)];
                },
                .slab => {
                    // Free the heap-allocated Storage owned by this slab Node.
                    const storage = slabStorage(self.nodes.items(.cache), @intFromEnum(id));
                    Slab.destroy(self.allocator, storage);
                    self.nodes.items(.cache)[@intFromEnum(id)] = null;
                    current = null;
                },
                .branch_struct => {
                    // Free the wrapped struct + the BranchStructRef heap-allocation
                    // owned by this slot.
                    const ref_ptr = branchStructRef(self.nodes.items(.cache), @intFromEnum(id));
                    ref_ptr.deinit(ref_ptr.ptr, self.allocator);
                    self.allocator.destroy(ref_ptr);
                    self.nodes.items(.cache)[@intFromEnum(id)] = null;
                    current = null;
                },
                else => {
                    current = null;
                },
            }
            // Return the node to the free list. Free-list link is encoded
            // in `state` (the State.initFree representation).
            states[@intFromEnum(id)] = State.initFree(self.next_free_node);
            self.nodes.items(.cache)[@intFromEnum(id)] = null;
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

    const states = pool.nodes.items(.state);
    const lefts = pool.nodes.items(.left);
    const rights = pool.nodes.items(.right);

    for (0..path_len - 1) |i| {
        const idx = @intFromEnum(node_id);
        const k = states[idx].kind();
        if (noChildKind(node_id, k)) {
            return Error.InvalidNode;
        }
        const c = childrenOf(node_id, k, lefts, rights);
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
        const idx = @intFromEnum(node_id);
        const k = states[idx].kind();
        if (noChildKind(node_id, k)) return Error.InvalidNode;
        const c = childrenOf(node_id, k, lefts, rights);
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

        const states = self.pool.nodes.items(.state);
        const lefts = self.pool.nodes.items(.left);
        const rights = self.pool.nodes.items(.right);

        // Compute gindex for current index at the requested depth.
        const gindex = Gindex.fromUint(@intCast(@intFromEnum(self.base_gindex) | self.index));

        // diffi: how many levels we can reuse from previous traversal (initialized to depth by caller state)
        const d = path_len - self.diffi;

        var path = gindex.toPath();
        path.nextN(d);

        var node_id = self.node_id;

        // Navigate down from the shared prefix (d) to the target, updating parents.
        for (d..path_len) |bit_i| {
            const idx = @intFromEnum(node_id);
            const k = states[idx].kind();
            if (noChildKind(node_id, k)) {
                return Error.InvalidNode;
            }
            const c = childrenOf(node_id, k, lefts, rights);
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
