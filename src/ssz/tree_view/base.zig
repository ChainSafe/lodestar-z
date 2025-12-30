const std = @import("std");
const Allocator = std.mem.Allocator;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;

/// Represents the internal state of a tree view.
///
/// This struct manages the root node of the tree, caches child nodes and sub-data for efficient access,
/// and tracks which child indices have been modified since the last commit.
///
/// It enables fast (re)access of children and batched updates to the merkle tree structure.
pub const TreeViewData = struct {
    root: Node.Id,

    /// cached nodes for faster access of already-visited children
    children_nodes: std.AutoHashMapUnmanaged(Gindex, Node.Id),

    /// cached data for faster access of already-visited children
    children_data: std.AutoHashMapUnmanaged(Gindex, TreeViewData),

    /// whether the corresponding child node/data has changed since the last update of the root
    changed: std.AutoArrayHashMapUnmanaged(Gindex, void),

    pub fn init(pool: *Node.Pool, root: Node.Id) !TreeViewData {
        try pool.ref(root);
        return TreeViewData{
            .root = root,
            .children_nodes = .empty,
            .children_data = .empty,
            .changed = .empty,
        };
    }

    /// Deinitialize the Data and free all associated resources.
    /// This also deinits all child Data recursively.
    pub fn deinit(self: *TreeViewData, allocator: Allocator, pool: *Node.Pool) void {
        pool.unref(self.root);
        self.clearChildrenNodesCache(pool);
        self.children_nodes.deinit(allocator);
        self.clearChildrenDataCache(allocator, pool);
        self.children_data.deinit(allocator);
        self.changed.deinit(allocator);
    }

    pub fn clearChildrenNodesCache(self: *TreeViewData, pool: *Node.Pool) void {
        var value_iter = self.children_nodes.valueIterator();
        while (value_iter.next()) |node_id_ptr| {
            const node_id = node_id_ptr.*;
            if (node_id.getState(pool).getRefCount() == 0) {
                pool.unref(node_id);
            }
        }
        self.children_nodes.clearRetainingCapacity();
    }

    pub fn clearChildrenDataCache(self: *TreeViewData, allocator: Allocator, pool: *Node.Pool) void {
        var value_iter = self.children_data.valueIterator();
        while (value_iter.next()) |child_data| {
            child_data.deinit(allocator, pool);
        }
        self.children_data.clearRetainingCapacity();
    }

    pub fn commit(self: *TreeViewData, allocator: Allocator, pool: *Node.Pool) !void {
        if (self.changed.count() == 0) {
            return;
        }

        const nodes = try allocator.alloc(Node.Id, self.changed.count());
        defer allocator.free(nodes);

        const gindices = self.changed.keys();
        Gindex.sortAsc(gindices);

        for (gindices, 0..) |gindex, i| {
            if (self.children_data.getPtr(gindex)) |child_data| {
                try child_data.commit(allocator, pool);
                nodes[i] = child_data.root;
            } else if (self.children_nodes.get(gindex)) |child_node| {
                nodes[i] = child_node;
            } else {
                return error.ChildNotFound;
            }
        }

        const new_root = try self.root.setNodesGrouped(pool, gindices, nodes);
        try pool.ref(new_root);
        pool.unref(self.root);
        self.root = new_root;

        self.changed.clearRetainingCapacity();
    }
};

/// Provides the foundational implementation for tree views.
///
/// `BaseTreeView` manages and owns a `TreeViewData` struct,
/// enabling fast (re)access of children and batched updates to the merkle tree structure.
///
/// It supports operations such as get/set of child nodes and data, committing changes, computing hash tree roots.
///
/// This struct serves as the base for specialized tree views like `ContainerTreeView` and array/list tree views.
pub const BaseTreeView = struct {
    allocator: Allocator,
    pool: *Node.Pool,
    data: TreeViewData,

    pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !BaseTreeView {
        return BaseTreeView{
            .allocator = allocator,
            .pool = pool,
            .data = try TreeViewData.init(pool, root),
        };
    }

    /// Create a new, independent BaseTreeView referencing the same current root node.
    ///
    /// - `dont_transfer_cache = false`: transfers *safe* cache entries from `self` into the clone.
    ///   This is a best-effort transfer: only cache entries that are not marked as changed are moved.
    ///   After transferring, this instance is reset to a committed-only state by clearing its caches.
    /// - `dont_transfer_cache = true`: clone starts with an empty cache; this instance keeps its caches.
    ///
    /// Notes:
    /// - Any uncommitted changes in this instance are not included in the clone. Call `commit()` first if needed.
    pub fn clone(self: *BaseTreeView, dont_transfer_cache: bool) !BaseTreeView {
        var out = try BaseTreeView.init(self.allocator, self.pool, self.data.root);
        if (dont_transfer_cache) {
            return out;
        }

        try self.transferSafeCache(&out);
        self.clearCache();
        return out;
    }

    fn transferSafeCache(self: *BaseTreeView, out: *BaseTreeView) !void {
        var safe_node_keys = std.ArrayList(Gindex).init(self.allocator);
        defer safe_node_keys.deinit();

        var nodes_it = self.data.children_nodes.iterator();
        while (nodes_it.next()) |entry| {
            const gindex = entry.key_ptr.*;
            if (!self.data.changed.contains(gindex)) {
                try safe_node_keys.append(gindex);
            }
        }

        for (safe_node_keys.items) |gindex| {
            const removed = self.data.children_nodes.fetchRemove(gindex) orelse continue;
            try out.data.children_nodes.put(self.allocator, gindex, removed.value);
        }

        var safe_data_keys = std.ArrayList(Gindex).init(self.allocator);
        defer safe_data_keys.deinit();

        var data_it = self.data.children_data.iterator();
        while (data_it.next()) |entry| {
            const gindex = entry.key_ptr.*;
            if (!self.data.changed.contains(gindex)) {
                try safe_data_keys.append(gindex);
            }
        }

        for (safe_data_keys.items) |gindex| {
            const removed = self.data.children_data.fetchRemove(gindex) orelse continue;
            try out.data.children_data.put(self.allocator, gindex, removed.value);
        }
    }

    pub fn deinit(self: *BaseTreeView) void {
        self.data.deinit(self.allocator, self.pool);
    }

    pub fn commit(self: *BaseTreeView) !void {
        try self.data.commit(self.allocator, self.pool);
    }

    pub fn clearCache(self: *BaseTreeView) void {
        self.data.clearChildrenNodesCache(self.pool);
        self.data.clearChildrenDataCache(self.allocator, self.pool);
        self.data.changed.clearRetainingCapacity();
    }

    pub fn hashTreeRoot(self: *BaseTreeView, out: *[32]u8) !void {
        try self.commit();
        out.* = self.data.root.getRoot(self.pool).*;
    }

    pub fn getChildNode(self: *BaseTreeView, gindex: Gindex) !Node.Id {
        const gop = try self.data.children_nodes.getOrPut(self.allocator, gindex);
        if (gop.found_existing) {
            return gop.value_ptr.*;
        }
        const child_node = try self.data.root.getNode(self.pool, gindex);
        gop.value_ptr.* = child_node;
        return child_node;
    }

    pub fn setChildNode(self: *BaseTreeView, gindex: Gindex, node: Node.Id) !void {
        try self.data.changed.put(self.allocator, gindex, {});
        const opt_old_node = try self.data.children_nodes.fetchPut(
            self.allocator,
            gindex,
            node,
        );
        if (opt_old_node) |old_node| {
            // Multiple set() calls before commit() leave our previous temp nodes cached with refcount 0.
            // Tree-owned nodes already have a refcount, so skip unref in that case.
            if (old_node.value.getState(self.pool).getRefCount() == 0) {
                self.pool.unref(old_node.value);
            }
        }
    }

    pub fn getChildData(self: *BaseTreeView, gindex: Gindex) !TreeViewData {
        const gop = try self.data.children_data.getOrPut(self.allocator, gindex);
        if (gop.found_existing) {
            return gop.value_ptr.*;
        }
        const child_node = try self.getChildNode(gindex);
        const child_data = try TreeViewData.init(self.pool, child_node);
        gop.value_ptr.* = child_data;

        // TODO only update changed if the subview is mutable
        try self.data.changed.put(self.allocator, gindex, {});
        return child_data;
    }

    pub fn setChildData(self: *BaseTreeView, gindex: Gindex, child_data: TreeViewData) !void {
        try self.data.changed.put(self.allocator, gindex, {});
        const opt_old_data = try self.data.children_data.fetchPut(
            self.allocator,
            gindex,
            child_data,
        );
        if (opt_old_data) |old_data_value| {
            var old_data = @constCast(&old_data_value.value);
            old_data.deinit(self.allocator, self.pool);
        }
    }
};
