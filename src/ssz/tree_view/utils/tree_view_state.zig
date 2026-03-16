const std = @import("std");
const Allocator = std.mem.Allocator;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const CloneOpts = @import("clone_opts.zig").CloneOpts;

/// Common state for tree views that use runtime gindex-based child caching.
///
/// Used by list, array, bitvector, and bitlist views (chunk-based).
/// NOT used by ContainerTreeView (which uses comptime field-indexed tuples).
pub const TreeViewState = struct {
    allocator: Allocator,
    pool: *Node.Pool,
    root: Node.Id,

    /// cached nodes for faster access of already-visited children
    children_nodes: std.AutoHashMapUnmanaged(Gindex, Node.Id),

    /// whether the corresponding child node/data has changed since the last update of the root
    changed: std.AutoArrayHashMapUnmanaged(Gindex, void),

    pub fn init(self: *TreeViewState, allocator: Allocator, pool: *Node.Pool, root: Node.Id) !void {
        try pool.ref(root);
        self.* = .{
            .allocator = allocator,
            .pool = pool,
            .root = root,
            .children_nodes = .empty,
            .changed = .empty,
        };
    }

    pub fn deinit(self: *TreeViewState) void {
        self.pool.unref(self.root);
        self.clearChildrenNodesCache();
        self.children_nodes.deinit(self.allocator);
        self.changed.deinit(self.allocator);
    }

    pub fn getChildNode(self: *TreeViewState, gindex: Gindex) !Node.Id {
        const gop = try self.children_nodes.getOrPut(self.allocator, gindex);
        if (gop.found_existing) {
            return gop.value_ptr.*;
        }
        const child_node = try self.root.getNode(self.pool, gindex);
        gop.value_ptr.* = child_node;
        return child_node;
    }

    pub fn setChildNode(self: *TreeViewState, gindex: Gindex, node: Node.Id) !void {
        try self.changed.put(self.allocator, gindex, {});
        const opt_old_node = try self.children_nodes.fetchPut(
            self.allocator,
            gindex,
            node,
        );
        if (opt_old_node) |old_node| {
            if (old_node.value.getState(self.pool).getRefCount() == 0) {
                self.pool.unref(old_node.value);
            }
        }
    }

    pub fn commitNodes(self: *TreeViewState) !void {
        if (self.changed.count() == 0) {
            return;
        }

        const nodes = try self.allocator.alloc(Node.Id, self.changed.count());
        defer self.allocator.free(nodes);

        const gindices = self.changed.keys();
        Gindex.sortAsc(gindices);

        for (gindices, 0..) |gindex, i| {
            if (self.children_nodes.get(gindex)) |child_node| {
                nodes[i] = child_node;
            } else {
                return error.ChildNotFound;
            }
        }

        const new_root = try self.root.setNodesGrouped(self.pool, gindices, nodes);
        try self.pool.ref(new_root);
        self.pool.unref(self.root);
        self.root = new_root;

        self.changed.clearRetainingCapacity();
    }

    pub fn clearChildrenNodesCache(self: *TreeViewState) void {
        var value_iter = self.children_nodes.valueIterator();
        while (value_iter.next()) |node_id_ptr| {
            const node_id = node_id_ptr.*;
            if (node_id.getState(self.pool).getRefCount() == 0) {
                self.pool.unref(node_id);
            }
        }
        self.children_nodes.clearRetainingCapacity();
    }

    pub fn clearCache(self: *TreeViewState) void {
        self.clearChildrenNodesCache();
        self.changed.clearRetainingCapacity();
    }

    pub fn getLength(self: *TreeViewState) !usize {
        const length_node = try self.getChildNode(@enumFromInt(3));
        const length_chunk = length_node.getRoot(self.pool);
        return std.mem.readInt(usize, length_chunk[0..@sizeOf(usize)], .little);
    }

    pub fn setLength(self: *TreeViewState, length: usize) !void {
        const length_node = try self.pool.createLeafFromUint(@intCast(length));
        errdefer self.pool.unref(length_node);
        try self.setChildNode(@enumFromInt(3), length_node);
    }

    pub fn clone(self: *TreeViewState, opts: CloneOpts, out: *TreeViewState) !void {
        try out.init(self.allocator, self.pool, self.root);

        if (!opts.transfer_cache) {
            return;
        }

        out.children_nodes = self.children_nodes;

        for (self.changed.keys()) |gindex| {
            _ = out.children_nodes.remove(gindex);
        }

        self.children_nodes = .empty;
        self.changed.clearRetainingCapacity();
    }
};
