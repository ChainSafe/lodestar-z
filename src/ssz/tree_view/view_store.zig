const std = @import("std");
const Allocator = std.mem.Allocator;

const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;

/// ViewStore: centralized state/ownership for a tree of mutable SSZ views.
pub const ViewId = u32;

const ViewState = struct {
    alive: bool = false,
    root: Node.Id = undefined,
    children_nodes: std.AutoHashMapUnmanaged(Gindex, Node.Id) = .empty,
    children_views: std.AutoHashMapUnmanaged(Gindex, ViewId) = .empty,
    changed: std.AutoArrayHashMapUnmanaged(Gindex, void) = .empty,

    fn deinit(self: *ViewState, allocator: Allocator, pool: *Node.Pool, store: *ViewStore) void {
        if (!self.alive) return;

        var child_iter = self.children_views.valueIterator();
        while (child_iter.next()) |child_id_ptr| {
            store.destroyViewRecursive(child_id_ptr.*);
        }
        self.children_views.deinit(allocator);

        self.clearChildrenNodesCache(pool);
        self.children_nodes.deinit(allocator);

        self.changed.deinit(allocator);

        pool.unref(self.root);
        self.alive = false;
    }

    fn clearChildrenNodesCache(self: *ViewState, pool: *Node.Pool) void {
        var value_iter = self.children_nodes.valueIterator();
        while (value_iter.next()) |node_id_ptr| {
            const node_id = node_id_ptr.*;
            // Only unref temp nodes (refcount 0). Tree-owned nodes already have a refcount.
            if (node_id.getState(pool).getRefCount() == 0) {
                pool.unref(node_id);
            }
        }
        self.children_nodes.clearRetainingCapacity();
    }
};

pub const ViewStore = struct {
    allocator: Allocator,
    pool: *Node.Pool,

    views: std.ArrayListUnmanaged(ViewState) = .{},
    free_ids: std.ArrayListUnmanaged(ViewId) = .{},

    prefetch_progress_count: std.ArrayListUnmanaged(?usize) = .{},

    list_length_cache: std.ArrayListUnmanaged(?usize) = .{},

    list_length_dirty: std.ArrayListUnmanaged(bool) = .{},

    pub fn init(allocator: Allocator, pool: *Node.Pool) ViewStore {
        return .{
            .allocator = allocator,
            .pool = pool,
        };
    }

    pub fn deinit(self: *ViewStore) void {
        for (self.views.items, 0..) |*view, i| {
            _ = i;
            view.deinit(self.allocator, self.pool, self);
        }
        self.views.deinit(self.allocator);
        self.free_ids.deinit(self.allocator);
        self.prefetch_progress_count.deinit(self.allocator);
        self.list_length_cache.deinit(self.allocator);
        self.list_length_dirty.deinit(self.allocator);
    }

    pub fn createView(self: *ViewStore, root: Node.Id) !ViewId {
        try self.pool.ref(root);

        if (self.free_ids.items.len > 0) {
            const id = self.free_ids.pop().?;
            const idx: usize = @intCast(id);
            const state = &self.views.items[idx];
            state.* = .{
                .alive = true,
                .root = root,
                .children_nodes = .empty,
                .children_views = .empty,
                .changed = .empty,
            };

            if (idx < self.prefetch_progress_count.items.len) {
                self.prefetch_progress_count.items[idx] = null;
            }
            if (idx < self.list_length_cache.items.len) {
                self.list_length_cache.items[idx] = null;
            }
            if (idx < self.list_length_dirty.items.len) {
                self.list_length_dirty.items[idx] = true;
            }
            return id;
        }

        try self.views.append(self.allocator, .{
            .alive = true,
            .root = root,
            .children_nodes = .empty,
            .children_views = .empty,
            .changed = .empty,
        });

        try self.prefetch_progress_count.append(self.allocator, null);
        try self.list_length_cache.append(self.allocator, null);
        try self.list_length_dirty.append(self.allocator, true);

        return @intCast(self.views.items.len - 1);
    }

    pub fn destroyViewRecursive(self: *ViewStore, id: ViewId) void {
        const idx: usize = @intCast(id);
        if (idx >= self.views.items.len) return;
        if (!self.views.items[idx].alive) return;

        self.views.items[idx].deinit(self.allocator, self.pool, self);
        if (idx < self.prefetch_progress_count.items.len) {
            self.prefetch_progress_count.items[idx] = null;
        }
        if (idx < self.list_length_cache.items.len) {
            self.list_length_cache.items[idx] = null;
        }
        if (idx < self.list_length_dirty.items.len) {
            self.list_length_dirty.items[idx] = true;
        }
        self.free_ids.append(self.allocator, id) catch {};
    }

    fn getState(self: *ViewStore, id: ViewId) *ViewState {
        const idx: usize = @intCast(id);
        std.debug.assert(idx < self.views.items.len);
        const state = &self.views.items[idx];
        std.debug.assert(state.alive);
        return state;
    }

    pub fn rootNode(self: *ViewStore, id: ViewId) Node.Id {
        return self.getState(id).root;
    }

    pub fn cachedChildViewId(self: *ViewStore, id: ViewId, gindex: Gindex) ?ViewId {
        return self.getState(id).children_views.get(gindex);
    }

    pub fn clearCache(self: *ViewStore, id: ViewId) void {
        var state = self.getState(id);
        state.clearChildrenNodesCache(self.pool);
        // For now, we do not clear children_views recursively here; callers can decide.
        state.changed.clearRetainingCapacity();
        self.invalidatePrefetchProgress(id);
        self.invalidateListLengthCache(id);
    }

    pub fn getChildNode(self: *ViewStore, id: ViewId, gindex: Gindex) !Node.Id {
        var state = self.getState(id);

        const gop = try state.children_nodes.getOrPut(self.allocator, gindex);
        if (gop.found_existing) {
            return gop.value_ptr.*;
        }

        const child_node = try state.root.getNode(self.pool, gindex);
        gop.value_ptr.* = child_node;
        return child_node;
    }

    pub fn setChildNode(self: *ViewStore, id: ViewId, gindex: Gindex, node: Node.Id) !void {
        var state = self.getState(id);

        // Replacing a child subtree rooted at gindex invalidates any cached child view at that gindex.
        if (state.children_views.fetchRemove(gindex)) |entry| {
            self.destroyViewRecursive(entry.value);
        }

        try state.changed.put(self.allocator, gindex, {});

        const opt_old_node = try state.children_nodes.fetchPut(self.allocator, gindex, node);
        if (opt_old_node) |old_node| {
            if (old_node.value.getState(self.pool).getRefCount() == 0) {
                self.pool.unref(old_node.value);
            }
        }
    }

    pub fn markChanged(self: *ViewStore, id: ViewId, gindex: Gindex) !void {
        var state = self.getState(id);
        try state.changed.put(self.allocator, gindex, {});
    }

    pub fn cacheChildNodeIfAbsent(self: *ViewStore, id: ViewId, gindex: Gindex, node: Node.Id) !void {
        var state = self.getState(id);
        const gop = try state.children_nodes.getOrPut(self.allocator, gindex);
        if (!gop.found_existing) {
            gop.value_ptr.* = node;
        }
    }

    pub fn invalidatePrefetchProgress(self: *ViewStore, id: ViewId) void {
        const idx: usize = @intCast(id);
        if (idx >= self.prefetch_progress_count.items.len) return;
        self.prefetch_progress_count.items[idx] = null;
    }

    pub fn getPrefetchProgressCount(self: *ViewStore, id: ViewId) ?usize {
        const idx: usize = @intCast(id);
        if (idx >= self.prefetch_progress_count.items.len) return null;
        return self.prefetch_progress_count.items[idx];
    }

    pub fn setPrefetchProgressCount(self: *ViewStore, id: ViewId, value: ?usize) void {
        const idx: usize = @intCast(id);
        if (idx >= self.prefetch_progress_count.items.len) return;
        self.prefetch_progress_count.items[idx] = value;
    }

    pub fn invalidateListLengthCache(self: *ViewStore, id: ViewId) void {
        const idx: usize = @intCast(id);
        if (idx >= self.list_length_cache.items.len) return;
        self.list_length_cache.items[idx] = null;
        if (idx < self.list_length_dirty.items.len) {
            self.list_length_dirty.items[idx] = true;
        }
    }

    pub fn getListLengthCache(self: *ViewStore, id: ViewId) ?usize {
        const idx: usize = @intCast(id);
        if (idx >= self.list_length_cache.items.len) return null;
        return self.list_length_cache.items[idx];
    }

    pub fn setListLengthCache(self: *ViewStore, id: ViewId, value: ?usize) void {
        const idx: usize = @intCast(id);
        if (idx >= self.list_length_cache.items.len) return;
        self.list_length_cache.items[idx] = value;
    }

    pub fn isListLengthDirty(self: *ViewStore, id: ViewId) bool {
        const idx: usize = @intCast(id);
        if (idx >= self.list_length_dirty.items.len) return true;
        return self.list_length_dirty.items[idx];
    }

    pub fn setListLengthDirty(self: *ViewStore, id: ViewId, dirty: bool) void {
        const idx: usize = @intCast(id);
        if (idx >= self.list_length_dirty.items.len) return;
        self.list_length_dirty.items[idx] = dirty;
    }

    pub fn getOrCreateChildView(self: *ViewStore, id: ViewId, gindex: Gindex) !ViewId {
        var state = self.getState(id);

        if (state.children_views.get(gindex)) |existing_child_id| {
            // Mirror current BaseTreeView behavior: treat child access as potentially mutable.
            try state.changed.put(self.allocator, gindex, {});
            return existing_child_id;
        }

        const child_node = try self.getChildNode(id, gindex);
        const child_id = try self.createView(child_node);
        errdefer self.destroyViewRecursive(child_id);

        // createView() may reallocate the underlying views buffer; re-fetch the state pointer.
        state = self.getState(id);
        try state.children_views.put(self.allocator, gindex, child_id);
        try state.changed.put(self.allocator, gindex, {});
        return child_id;
    }

    pub fn commit(self: *ViewStore, id: ViewId) !void {
        var state = self.getState(id);
        if (state.changed.count() == 0) return;

        const nodes = try self.allocator.alloc(Node.Id, state.changed.count());
        defer self.allocator.free(nodes);

        const gindices = state.changed.keys();
        Gindex.sortAsc(gindices);

        for (gindices, 0..) |gindex, i| {
            if (state.children_views.get(gindex)) |child_id| {
                try self.commit(child_id);
                nodes[i] = self.rootNode(child_id);
            } else if (state.children_nodes.get(gindex)) |child_node| {
                nodes[i] = child_node;
            } else {
                return error.ChildNotFound;
            }
        }

        const new_root = try state.root.setNodesGrouped(self.pool, gindices, nodes);
        try self.pool.ref(new_root);
        self.pool.unref(state.root);
        state.root = new_root;

        state.changed.clearRetainingCapacity();
    }
};
