const std = @import("std");
const Allocator = std.mem.Allocator;

const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;

/// ViewStore: centralized state/ownership for a tree of mutable SSZ views.
pub const ViewId = u32;

const ViewState = struct {
    root: Node.Id = undefined,
    children_nodes: std.AutoHashMapUnmanaged(Gindex, Node.Id) = .empty,
    children_views: std.AutoHashMapUnmanaged(Gindex, ViewId) = .empty,
    changed: std.AutoArrayHashMapUnmanaged(Gindex, void) = .empty,

    fn deinit(self: *ViewState, allocator: Allocator, pool: *Node.Pool) void {
        self.children_views.deinit(allocator);

        self.clearChildrenNodesCache(pool);
        self.children_nodes.deinit(allocator);

        self.changed.deinit(allocator);

        pool.unref(self.root);
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

    pub fn init(allocator: Allocator, pool: *Node.Pool) ViewStore {
        return .{
            .allocator = allocator,
            .pool = pool,
        };
    }

    pub fn deinit(self: *ViewStore) void {
        for (self.views.items) |*view| {
            view.deinit(self.allocator, self.pool);
        }
        self.views.deinit(self.allocator);
    }

    pub fn createView(self: *ViewStore, root: Node.Id) !ViewId {
        try self.pool.ref(root);

        try self.views.append(self.allocator, .{
            .root = root,
            .children_nodes = .empty,
            .children_views = .empty,
            .changed = .empty,
        });

        return @intCast(self.views.items.len - 1);
    }

    fn destroyLastView(self: *ViewStore, id: ViewId) void {
        const idx: usize = @intCast(id);
        std.debug.assert(idx + 1 == self.views.items.len);
        var state = self.views.pop().?;
        state.deinit(self.allocator, self.pool);
    }

    fn getState(self: *ViewStore, id: ViewId) *ViewState {
        const idx: usize = @intCast(id);
        std.debug.assert(idx < self.views.items.len);
        const state = &self.views.items[idx];
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
        _ = state.children_views.fetchRemove(gindex);

        try state.changed.put(self.allocator, gindex, {});

        const opt_old_node = try state.children_nodes.fetchPut(self.allocator, gindex, node);
        if (opt_old_node) |old_node| {
            if (old_node.value.getState(self.pool).getRefCount() == 0) {
                self.pool.unref(old_node.value);
            }
        }
    }

    pub fn setChildView(self: *ViewStore, id: ViewId, gindex: Gindex, child_id: ViewId) !void {
        // Ensure child_id is in-bounds (same store).
        _ = self.getState(child_id);

        var state = self.getState(id);

        // Switching to a child view invalidates any cached child node at that gindex.
        if (state.children_nodes.fetchRemove(gindex)) |old_node| {
            if (old_node.value.getState(self.pool).getRefCount() == 0) {
                self.pool.unref(old_node.value);
            }
        }

        try state.children_views.put(self.allocator, gindex, child_id);
        try state.changed.put(self.allocator, gindex, {});
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

    pub fn getOrCreateChildView(self: *ViewStore, id: ViewId, gindex: Gindex) !ViewId {
        var state = self.getState(id);

        if (state.children_views.get(gindex)) |existing_child_id| {
            try state.changed.put(self.allocator, gindex, {});
            return existing_child_id;
        }

        const child_node = try self.getChildNode(id, gindex);
        const child_id = try self.createView(child_node);
        errdefer self.destroyLastView(child_id);

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
