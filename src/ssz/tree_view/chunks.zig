const std = @import("std");
const Allocator = std.mem.Allocator;

const hashing = @import("hashing");
const Depth = hashing.Depth;

const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;

const isFixedType = @import("../type/type_kind.zig").isFixedType;

const tree_view_root = @import("root.zig");
const TreeViewState = @import("utils/tree_view_state.zig").TreeViewState;
const CloneOpts = @import("utils/clone_opts.zig").CloneOpts;

/// Shared helpers for basic element types packed into chunks.
///
/// `use_slab` selects between two leaf layouts:
///   * false (default) — one chunk per leaf, navigated by Node.Id.
///   * true — slab-leaf navigation: the bottom `Slab.k_log2` levels of the
///     tree are folded into a single Slab Node, addressed at `slab_depth =
///     chunk_depth - Slab.k_log2`. get/set/getAllInto read and CoW-write
///     chunk bytes through `Id.getSlabChunks` / `Id.setSlabChunk`.
pub fn BasicPackedChunks(
    comptime ST: type,
    comptime chunk_depth: Depth,
    comptime items_per_chunk: usize,
    comptime use_slab: bool,
) type {
    return struct {
        state: TreeViewState,

        pub const Element = ST.Element.Type;

        const Self = @This();

        // Slab-related comptime constants. Only meaningful when `use_slab = true`.
        // The `else` placeholders keep the symbols valid in non-slab instantiations
        // without referencing the Slab module.
        const Slab = if (use_slab) @import("persistent_merkle_tree").Slab else struct {};
        const slab_depth: Depth = if (use_slab) chunk_depth - Slab.k_log2 else 0;

        pub fn init(self: *Self, allocator: Allocator, pool: *Node.Pool, root: Node.Id) !void {
            try self.state.init(allocator, pool, root);
        }

        pub fn clone(self: *Self, opts: CloneOpts, out: *Self) !void {
            try self.state.clone(opts, &out.state);
        }

        pub fn deinit(self: *Self) void {
            self.state.deinit();
        }

        pub fn commit(self: *Self) !void {
            try self.state.commitNodes();
        }

        pub fn clearCache(self: *Self) void {
            self.state.clearCache();
        }

        pub fn get(self: *Self, index: usize) !Element {
            var value: Element = undefined;
            if (comptime use_slab) {
                const chunk_idx = index / items_per_chunk;
                const slab_idx = chunk_idx / Slab.K;
                const intra_chunk = chunk_idx % Slab.K;
                const slab_id = try self.state.getChildNode(Gindex.fromDepth(slab_depth, slab_idx));
                // Navigation may land on a zero sentinel when the tree was built
                // empty or sparsely (early-return path in tree.fromValue, or
                // slab_idx beyond filled slabs). A zero subtree at the slab
                // boundary is semantically an all-zero slab; the decoded value
                // is therefore the element's zero value.
                if (self.state.pool.nodes.items(.node)[@intFromEnum(slab_id)] == .zero) {
                    return std.mem.zeroes(Element);
                }
                const chunks = try slab_id.getSlabChunks(self.state.pool);
                ST.Element.tree.toValuePackedFromBytes(&chunks[intra_chunk], index, &value);
            } else {
                const child_node = try self.state.getChildNode(Gindex.fromDepth(chunk_depth, index / items_per_chunk));
                try ST.Element.tree.toValuePacked(child_node, self.state.pool, index, &value);
            }
            return value;
        }

        pub fn set(self: *Self, index: usize, value: Element) !void {
            if (comptime use_slab) {
                const chunk_idx = index / items_per_chunk;
                const slab_idx = chunk_idx / Slab.K;
                const intra_chunk = chunk_idx % Slab.K;
                const intra_chunk_u16: u16 = @intCast(intra_chunk);
                const gindex = Gindex.fromDepth(slab_depth, slab_idx);

                const existing_id = try self.state.getChildNode(gindex);
                const node_col = self.state.pool.nodes.items(.node);
                const existing_variant = node_col[@intFromEnum(existing_id)];

                // Path 1: navigation landed on a zero sentinel (sparse tree).
                // Materialize a fresh zero-filled slab and mutate it in place
                // (rc=0 ⇒ exclusively owned by us). Then setChildNode publishes
                // it to the cache and `changed` set.
                if (existing_variant == .zero) {
                    var zero_buf: [Slab.K][32]u8 align(64) = [_][32]u8{[_]u8{0} ** 32} ** Slab.K;
                    const fresh_id = try self.state.pool.createSlab(&zero_buf, 0);
                    const fresh_node = &node_col[@intFromEnum(fresh_id)];
                    ST.Element.tree.fromValuePackedIntoChunk(&fresh_node.slab.storage.chunks[intra_chunk], index, &value);
                    fresh_node.slab.root = Node.lazy_sentinel;
                    try self.state.setChildNode(gindex, fresh_id);
                    return;
                }

                // Path 2: existing slab is `transient` — exclusively owned by
                // this TreeView (rc==0, only the children_nodes cache holds it).
                // This is the steady state after the first write produces a
                // CoW slab. Mutate in place: byte-write into the heap chunks,
                // accumulate dirty bits, invalidate the cached slab root.
                // The gindex was already added to `changed` by the prior
                // setChildNode call that produced this transient slab, so we
                // do NOT call setChildNode again (which would unref-then-store
                // the same Id and free our slab).
                const ref_counts = self.state.pool.nodes.items(.ref_count);
                if (ref_counts[@intFromEnum(existing_id)] == 0) {
                    const node_ptr = &node_col[@intFromEnum(existing_id)];
                    ST.Element.tree.fromValuePackedIntoChunk(&node_ptr.slab.storage.chunks[intra_chunk], index, &value);
                    node_ptr.slab.root = Node.lazy_sentinel;
                    return;
                }

                // Path 3: shared slab (rc >= 1 — owned by the persistent tree).
                // Must CoW: produce a fresh slab via setSlabChunk and publish
                // it. From this point onward subsequent writes hit Path 2.
                var new_chunk: [32]u8 = existing_variant.slab.storage.chunks[intra_chunk];
                ST.Element.tree.fromValuePackedIntoChunk(&new_chunk, index, &value);
                const new_slab_id = try existing_id.setSlabChunk(self.state.pool, intra_chunk_u16, &new_chunk);
                try self.state.setChildNode(gindex, new_slab_id);
            } else {
                const gindex = Gindex.fromDepth(chunk_depth, index / items_per_chunk);
                const child_node = try self.state.getChildNode(gindex);
                const new_node = try ST.Element.tree.fromValuePacked(child_node, self.state.pool, index, &value);
                try self.state.setChildNode(gindex, new_node);
            }
        }

        pub fn getAll(
            self: *Self,
            allocator: Allocator,
            len: usize,
        ) ![]Element {
            const values = try allocator.alloc(Element, len);
            errdefer allocator.free(values);
            return try self.getAllInto(len, values);
        }

        pub fn getAllInto(
            self: *Self,
            len: usize,
            values: []Element,
        ) ![]Element {
            if (values.len != len) return error.InvalidSize;
            if (len == 0) return values;

            if (comptime use_slab) {
                const chunk_count = (len + items_per_chunk - 1) / items_per_chunk;
                const slab_count = (chunk_count + Slab.K - 1) / Slab.K;
                const slab_ids = try self.state.allocator.alloc(Node.Id, slab_count);
                defer self.state.allocator.free(slab_ids);
                try self.state.root.getNodesAtDepth(self.state.pool, slab_depth, 0, slab_ids);

                var item_idx: usize = 0;
                outer: for (slab_ids) |sid| {
                    // Slab boundary may be a zero sentinel for sparsely-filled
                    // trees (e.g. an empty list grown via push, or slab slots
                    // beyond the materialized range). A zero subtree is
                    // semantically all-zero chunks; emit zero values without
                    // touching the (non-existent) slab payload.
                    if (self.state.pool.nodes.items(.node)[@intFromEnum(sid)] == .zero) {
                        const items_in_slab = @min(Slab.K * items_per_chunk, len - item_idx);
                        @memset(values[item_idx..][0..items_in_slab], std.mem.zeroes(Element));
                        item_idx += items_in_slab;
                        if (item_idx >= len) break :outer;
                        continue;
                    }
                    const chunks_ptr = try sid.getSlabChunks(self.state.pool);
                    for (0..Slab.K) |intra_chunk| {
                        if (item_idx >= len) break :outer;
                        const items_in_chunk = @min(items_per_chunk, len - item_idx);
                        for (0..items_in_chunk) |i| {
                            ST.Element.tree.toValuePackedFromBytes(
                                &chunks_ptr[intra_chunk],
                                item_idx + i,
                                &values[item_idx + i],
                            );
                        }
                        item_idx += items_in_chunk;
                    }
                }
                return values;
            }

            const len_full_chunks = len / items_per_chunk;
            const remainder = len % items_per_chunk;
            const chunk_count = len_full_chunks + @intFromBool(remainder != 0);

            try self.populateAllNodes(chunk_count);

            for (0..len_full_chunks) |chunk_idx| {
                const leaf_node = try self.state.getChildNode(Gindex.fromDepth(chunk_depth, chunk_idx));
                for (0..items_per_chunk) |i| {
                    try ST.Element.tree.toValuePacked(
                        leaf_node,
                        self.state.pool,
                        i,
                        &values[chunk_idx * items_per_chunk + i],
                    );
                }
            }

            if (remainder > 0) {
                const leaf_node = try self.state.getChildNode(Gindex.fromDepth(chunk_depth, len_full_chunks));
                for (0..remainder) |i| {
                    try ST.Element.tree.toValuePacked(
                        leaf_node,
                        self.state.pool,
                        i,
                        &values[len_full_chunks * items_per_chunk + i],
                    );
                }
            }

            return values;
        }

        fn populateAllNodes(self: *Self, chunk_count: usize) !void {
            // Slab path doesn't pre-populate per-chunk Ids; getAllInto walks slabs
            // directly. No-op to keep external API stable.
            if (comptime use_slab) return;

            if (chunk_count == 0) return;

            const nodes = try self.state.allocator.alloc(Node.Id, chunk_count);
            defer self.state.allocator.free(nodes);

            try self.state.root.getNodesAtDepth(self.state.pool, chunk_depth, 0, nodes);

            for (nodes, 0..) |node, chunk_idx| {
                const gindex = Gindex.fromDepth(chunk_depth, chunk_idx);
                const gop = try self.state.children_nodes.getOrPut(self.state.allocator, gindex);
                if (!gop.found_existing) {
                    gop.value_ptr.* = node;
                }
            }
        }

        pub fn getChildNode(self: *Self, gindex: Gindex) !Node.Id {
            return self.state.getChildNode(gindex);
        }

        pub fn setChildNode(self: *Self, gindex: Gindex, node: Node.Id) !void {
            try self.state.setChildNode(gindex, node);
        }

        pub fn getLength(self: *Self) !usize {
            const length_node = try self.state.getChildNode(@enumFromInt(3));
            const length_chunk = length_node.getRoot(self.state.pool);
            return std.mem.readInt(usize, length_chunk[0..@sizeOf(usize)], .little);
        }

        pub fn setLength(self: *Self, length: usize) !void {
            const length_node = try self.state.pool.createLeafFromUint(@intCast(length));
            errdefer self.state.pool.unref(length_node);
            try self.state.setChildNode(@enumFromInt(3), length_node);
        }
    };
}

/// Shared helpers for composite element types, where each element occupies its own subtree.
pub fn CompositeChunks(
    comptime ST: type,
    comptime chunk_depth: Depth,
) type {
    return struct {
        state: TreeViewState,

        /// cached data for faster access of already-visited children
        children_data: std.AutoHashMapUnmanaged(Gindex, ElementPtr),

        const Element = ST.Element.TreeView;
        pub const ElementPtr = *Element;

        const Self = @This();

        pub fn init(self: *Self, allocator: Allocator, pool: *Node.Pool, root: Node.Id) !void {
            try self.state.init(allocator, pool, root);
            self.children_data = .empty;
        }

        pub fn clone(self: *Self, opts: CloneOpts, out: *Self) !void {
            if (!opts.transfer_cache) {
                try self.state.clone(opts, &out.state);
                out.children_data = .empty;
                return;
            }

            // Transfer children_data, removing uncommitted entries.
            out.children_data = self.children_data;
            {
                const changed_keys = self.state.changed.keys();
                for (changed_keys) |gindex| {
                    if (out.children_data.fetchRemove(gindex)) |entry| {
                        entry.value.deinit();
                    }
                }
            }
            // changed_keys borrow is now out of scope.

            // Clone state (transfers children_nodes, clears self caches).
            try self.state.clone(opts, &out.state);
            self.children_data = .empty;
        }

        /// Deinitialize the Data and free all associated resources.
        /// This also deinits all child Data recursively.
        pub fn deinit(self: *Self) void {
            const allocator = self.state.allocator;
            self.clearChildrenDataCache();
            self.children_data.deinit(allocator);
            self.state.deinit();
        }

        pub fn commit(self: *Self) !void {
            if (self.state.changed.count() == 0) {
                return;
            }

            // Flush child views into children_nodes so commitNodes can handle them uniformly.
            for (self.state.changed.keys()) |gindex| {
                if (self.children_data.get(gindex)) |child_ptr| {
                    try child_ptr.commit();
                    const gop = try self.state.children_nodes.getOrPut(self.state.allocator, gindex);
                    gop.value_ptr.* = child_ptr.getRoot();
                }
            }

            try self.state.commitNodes();
        }

        pub fn clearCache(self: *Self) void {
            self.state.clearCache();
            self.clearChildrenDataCache();
        }

        pub fn get(self: *Self, index: usize) !ElementPtr {
            const gindex = Gindex.fromDepth(chunk_depth, index);
            // Always mark as changed - the child may have been previously cached
            // via getReadonly() without being tracked in changed.
            try self.state.changed.put(self.state.allocator, gindex, {});
            const gop = try self.children_data.getOrPut(self.state.allocator, gindex);
            if (gop.found_existing) {
                return gop.value_ptr.*;
            }
            const child_node = try self.state.getChildNode(gindex);
            const child_ptr = try Element.init(self.state.allocator, self.state.pool, child_node);
            gop.value_ptr.* = child_ptr;
            return child_ptr;
        }

        pub fn set(self: *Self, index: usize, value: ElementPtr) !void {
            const gindex = Gindex.fromDepth(chunk_depth, index);
            try self.state.changed.put(self.state.allocator, gindex, {});
            const opt_old_data = try self.children_data.fetchPut(
                self.state.allocator,
                gindex,
                value,
            );
            if (opt_old_data) |old_data_value| {
                var child_ptr: ElementPtr = @constCast(&old_data_value.value.*);
                if (child_ptr != value) {
                    child_ptr.deinit();
                }
            }
        }

        /// Get a child view without tracking changes (read-only access).
        pub fn getReadonly(self: *Self, index: usize) !ElementPtr {
            const gindex = Gindex.fromDepth(chunk_depth, index);
            if (self.children_data.get(gindex)) |child_ptr| {
                return child_ptr;
            }
            const child_node = try self.state.getChildNode(gindex);
            const child_ptr = try Element.init(self.state.allocator, self.state.pool, child_node);
            try self.children_data.put(self.state.allocator, gindex, child_ptr);
            // Do NOT add to self.state.changed (read-only)
            return child_ptr;
        }

        /// Get all child views without tracking changes (read-only).
        pub fn getAllReadonly(self: *Self, allocator: Allocator, len: usize) ![]ElementPtr {
            const views = try allocator.alloc(ElementPtr, len);
            errdefer allocator.free(views);
            for (0..len) |i| {
                views[i] = try self.getReadonly(i);
            }
            return views;
        }

        pub const Value = ST.Element.Type;

        /// Get a child value as an SSZ value type.
        pub fn getValue(self: *Self, allocator: Allocator, index: usize, out: *Value) !void {
            var child_view = try self.getReadonly(index);
            if (comptime isFixedType(ST.Element)) {
                try child_view.toValue(undefined, out);
            } else {
                try child_view.toValue(allocator, out);
            }
        }

        /// Set a child from an SSZ value type.
        pub fn setValue(self: *Self, index: usize, value: *const Value) !void {
            const root = try ST.Element.tree.fromValue(self.state.pool, value);
            errdefer self.state.pool.unref(root);
            const child_view = try Element.init(self.state.allocator, self.state.pool, root);
            errdefer child_view.deinit();
            try self.set(index, child_view);
        }

        /// Get all element values in a single traversal.
        /// Caller owns the returned slice and must free it with the same allocator.
        pub fn getAllValues(self: *Self, allocator: Allocator, len: usize) ![]Value {
            const values = try allocator.alloc(Value, len);
            errdefer allocator.free(values);
            return try self.getAllValuesInto(allocator, values);
        }

        /// Fills `values` with all element values.
        pub fn getAllValuesInto(self: *Self, allocator: Allocator, values: []Value) ![]Value {
            const len = values.len;
            if (len == 0) return values;

            if (self.state.changed.count() != 0) {
                return error.MustCommitBeforeBulkRead;
            }

            const nodes = try allocator.alloc(Node.Id, len);
            defer allocator.free(nodes);

            try self.state.root.getNodesAtDepth(self.state.pool, chunk_depth, 0, nodes);

            for (nodes, 0..) |node, i| {
                if (comptime @hasDecl(ST.Element, "deinit")) {
                    errdefer {
                        for (values[0..i]) |*v| {
                            ST.Element.deinit(allocator, v);
                        }
                    }
                }
                if (comptime isFixedType(ST.Element)) {
                    try ST.Element.tree.toValue(node, self.state.pool, &values[i]);
                } else {
                    // Initialize value to default before toValue for variable types
                    // (e.g. BitList fields need initialized ArrayListUnmanaged)
                    if (comptime @hasDecl(ST.Element, "default_value")) {
                        values[i] = ST.Element.default_value;
                    } else {
                        values[i] = std.mem.zeroes(Value);
                    }
                    try ST.Element.tree.toValue(allocator, node, self.state.pool, &values[i]);
                }
            }

            return values;
        }

        pub fn getChildNode(self: *Self, gindex: Gindex) !Node.Id {
            return self.state.getChildNode(gindex);
        }

        pub fn setChildNode(self: *Self, gindex: Gindex, node: Node.Id) !void {
            try self.state.setChildNode(gindex, node);
        }

        pub fn getLength(self: *Self) !usize {
            const length_node = try self.state.getChildNode(@enumFromInt(3));
            const length_chunk = length_node.getRoot(self.state.pool);
            return std.mem.readInt(usize, length_chunk[0..@sizeOf(usize)], .little);
        }

        pub fn setLength(self: *Self, length: usize) !void {
            const length_node = try self.state.pool.createLeafFromUint(@intCast(length));
            errdefer self.state.pool.unref(length_node);
            try self.state.setChildNode(@enumFromInt(3), length_node);
        }

        fn clearChildrenDataCache(self: *Self) void {
            var value_iter = self.children_data.valueIterator();
            while (value_iter.next()) |child_ptr| {
                child_ptr.*.deinit();
            }
            self.children_data.clearRetainingCapacity();
        }
    };
}
