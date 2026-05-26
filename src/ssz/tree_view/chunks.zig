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
pub fn BasicPackedChunks(
    comptime ST: type,
    comptime chunk_depth: Depth,
    comptime items_per_chunk: usize,
) type {
    return struct {
        state: TreeViewState,

        pub const Element = ST.Element.Type;

        const Self = @This();

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
            const child_node = try self.state.getChildNode(Gindex.fromDepth(chunk_depth, index / items_per_chunk));
            try ST.Element.tree.toValuePacked(child_node, self.state.pool, index, &value);
            return value;
        }

        pub fn set(self: *Self, index: usize, value: Element) !void {
            const gindex = Gindex.fromDepth(chunk_depth, index / items_per_chunk);
            const child_node = try self.state.getChildNode(gindex);
            const new_node = try ST.Element.tree.fromValuePacked(child_node, self.state.pool, index, &value);
            try self.state.setChildNode(gindex, new_node);
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

        /// Clone, optionally moving the child-view cache to `out`. With `transfer_cache = true`,
        /// any pointer from an earlier get()/getReadonly() is invalidated — cached `changed`
        /// children get deinited (and get() counts as a change even on a read).
        pub fn clone(self: *Self, opts: CloneOpts, out: *Self) !void {
            if (!opts.transfer_cache) {
                try self.state.clone(opts, &out.state);
                out.children_data = .empty;
                return;
            }

            // Drop uncommitted (changed) cached children from self's own map first, in place, so a
            // failure in the fallible state clone below leaves self valid (just with fewer cached
            // entries) instead of referencing a half-modified map.
            {
                const changed_keys = self.state.changed.keys();
                for (changed_keys) |gindex| {
                    if (self.children_data.fetchRemove(gindex)) |entry| {
                        entry.value.deinit();
                    }
                }
            }

            // Clone state (transfers children_nodes, clears self's state caches). Fallible.
            try self.state.clone(opts, &out.state);

            // Hand the trimmed cache to out and clear self (infallible).
            out.children_data = self.children_data;
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

            // Reserve first so storing each committed root can't fail. Otherwise a getOrPut OOM
            // after a child already committed would leave a stale entry pointing at its freed root.
            try self.state.children_nodes.ensureUnusedCapacity(self.state.allocator, @intCast(self.state.changed.count()));

            // Flush child views into children_nodes so commitNodes can handle them uniformly.
            for (self.state.changed.keys()) |gindex| {
                if (self.children_data.get(gindex)) |child_ptr| {
                    try child_ptr.commit();
                    self.state.children_nodes.putAssumeCapacity(gindex, child_ptr.getRoot());
                }
            }

            try self.state.commitNodes();
        }

        pub fn clearCache(self: *Self) void {
            self.state.clearCache();
            self.clearChildrenDataCache();
        }

        /// Returns a borrowed child view owned by this cache. A later set() on the same index or a
        /// clone(transfer_cache) invalidates it — re-get() after either, and don't deinit it.
        pub fn get(self: *Self, index: usize) !ElementPtr {
            const gindex = Gindex.fromDepth(chunk_depth, index);
            // Always mark as changed - the child may have been previously cached
            // via getReadonly() without being tracked in changed.
            try self.state.changed.put(self.state.allocator, gindex, {});
            const gop = try self.children_data.getOrPut(self.state.allocator, gindex);
            if (gop.found_existing) {
                return gop.value_ptr.*;
            }
            // getOrPut added an entry with an undefined value; drop it if we fail before filling
            // it, otherwise a later deinit would deref the garbage pointer.
            errdefer _ = self.children_data.remove(gindex);
            const child_node = try self.state.getChildNode(gindex);
            const child_ptr = try Element.init(self.state.allocator, self.state.pool, child_node);
            gop.value_ptr.* = child_ptr;
            return child_ptr;
        }

        /// Takes ownership of `value` (and deinits it if a reservation fails). Deinits whatever
        /// child was cached for `index`, so any earlier get()/getReadonly() of it is now invalid.
        /// Pass a view you own — never a get()/getReadonly() pointer for this same index, or a
        /// failed set would deinit a view the cache still holds (double-free).
        pub fn set(self: *Self, index: usize, value: ElementPtr) !void {
            const gindex = Gindex.fromDepth(chunk_depth, index);
            // Reserve before storing so neither store can fail. A failure mid-store would drop
            // `value` (we own it now, the caller won't free it) or leave `changed` and
            // `children_data` out of sync.
            {
                errdefer value.deinit();
                try self.state.changed.ensureUnusedCapacity(self.state.allocator, 1);
                try self.children_data.ensureUnusedCapacity(self.state.allocator, 1);
            }
            self.state.changed.putAssumeCapacity(gindex, {});
            const opt_old_data = self.children_data.fetchPutAssumeCapacity(gindex, value);
            if (opt_old_data) |old_data_value| {
                var child_ptr: ElementPtr = @constCast(&old_data_value.value.*);
                if (child_ptr != value) {
                    child_ptr.deinit();
                }
            }
        }

        /// Like get() but doesn't mark the index changed. Same borrow rules: a later set() on this
        /// index or clone(transfer_cache) invalidates the pointer; don't deinit it.
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
            // Free `root` only if init fails. Once init succeeds, `set` owns `child_view` on every
            // path, so we must not deinit it here; that would double-free if set later fails.
            const child_view = Element.init(self.state.allocator, self.state.pool, root) catch |err| {
                self.state.pool.unref(root);
                return err;
            };
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
