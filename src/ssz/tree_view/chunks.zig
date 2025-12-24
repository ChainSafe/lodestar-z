const std = @import("std");
const Allocator = std.mem.Allocator;

const hashing = @import("hashing");
const Depth = hashing.Depth;

const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;

const tree_view_root = @import("root.zig");

/// Shared helpers for basic element types packed into chunks.
pub fn BasicPackedChunks(
    comptime ST: type,
    comptime chunk_depth: Depth,
    comptime items_per_chunk: usize,
) type {
    return struct {
        /// required fields
        allocator: Allocator,
        pool: *Node.Pool,
        root: Node.Id,

        /// cached nodes for faster access of already-visited children
        children_nodes: std.AutoHashMapUnmanaged(Gindex, Node.Id),

        /// whether the corresponding child node/data has changed since the last update of the root
        changed: std.AutoArrayHashMapUnmanaged(Gindex, void),

        pub const Element = ST.Element.Type;

        const Self = @This();

        pub fn init(self: *Self, allocator: Allocator, pool: *Node.Pool, root: Node.Id) !void {
            try pool.ref(root);
            errdefer pool.unref(root);
            self.* = .{
                .allocator = allocator,
                .pool = pool,
                .root = root,
                .children_nodes = .empty,
                .changed = .empty,
            };
        }

        pub fn deinit(self: *Self) void {
            self.pool.unref(self.root);
            self.clearChildrenNodesCache();
            self.children_nodes.deinit(self.allocator);
            self.changed.deinit(self.allocator);
        }

        pub fn commit(self: *Self) !void {
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

        pub fn get(self: *Self, index: usize) !Element {
            var value: Element = undefined;
            const child_node = try self.getChildNode(Gindex.fromDepth(chunk_depth, index / items_per_chunk));
            try ST.Element.tree.toValuePacked(child_node, self.pool, index, &value);
            return value;
        }

        pub fn set(self: *Self, index: usize, value: Element) !void {
            const gindex = Gindex.fromDepth(chunk_depth, index / items_per_chunk);
            try self.changed.put(self.allocator, gindex, {});
            const child_node = try self.getChildNode(gindex);
            const opt_old_node = try self.children_nodes.fetchPut(
                self.allocator,
                gindex,
                try ST.Element.tree.fromValuePacked(child_node, self.pool, index, &value),
            );
            if (opt_old_node) |old_node| {
                if (old_node.value.getState(self.pool).getRefCount() == 0) {
                    self.pool.unref(old_node.value);
                }
            }
        }

        pub fn getAll(
            self: *Self,
            allocator: Allocator,
            len: usize,
        ) ![]Element {
            const values = try allocator.alloc(Element, len);
            errdefer allocator.free(values);
            return try getAllInto(self, len, values);
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

            try populateAllNodes(self, chunk_count);

            for (0..len_full_chunks) |chunk_idx| {
                const leaf_node = try self.getChildNode(Gindex.fromDepth(chunk_depth, chunk_idx));
                for (0..items_per_chunk) |i| {
                    try ST.Element.tree.toValuePacked(
                        leaf_node,
                        self.pool,
                        i,
                        &values[chunk_idx * items_per_chunk + i],
                    );
                }
            }

            if (remainder > 0) {
                const leaf_node = try self.getChildNode(Gindex.fromDepth(chunk_depth, len_full_chunks));
                for (0..remainder) |i| {
                    try ST.Element.tree.toValuePacked(
                        leaf_node,
                        self.pool,
                        i,
                        &values[len_full_chunks * items_per_chunk + i],
                    );
                }
            }

            return values;
        }

        fn populateAllNodes(self: *Self, chunk_count: usize) !void {
            if (chunk_count == 0) return;

            const nodes = try self.allocator.alloc(Node.Id, chunk_count);
            defer self.allocator.free(nodes);

            try self.root.getNodesAtDepth(self.pool, chunk_depth, 0, nodes);

            for (nodes, 0..) |node, chunk_idx| {
                const gindex = Gindex.fromDepth(chunk_depth, chunk_idx);
                const gop = try self.children_nodes.getOrPut(self.allocator, gindex);
                if (!gop.found_existing) {
                    gop.value_ptr.* = node;
                }
            }
        }

        pub fn getChildNode(self: *Self, gindex: Gindex) !Node.Id {
            return getChildNodeOrTraverse(self, gindex);
        }

        fn setChildNode(self: *Self, gindex: Gindex, node: Node.Id) !void {
            try setChildNodeUnrefOld(self, gindex, node);
        }

        pub fn clearChildrenNodesCache(self: *Self) void {
            clearChildrenNodesAndUnref(self, self.pool);
        }
    };
}

/// Shared helpers for composite element types, where each element occupies its own subtree.
pub fn CompositeChunks(
    comptime ST: type,
    comptime chunk_depth: Depth,
) type {
    return struct {
        /// required fields
        allocator: Allocator,
        pool: *Node.Pool,
        root: Node.Id,

        /// cached nodes for faster access of already-visited children
        children_nodes: std.AutoHashMapUnmanaged(Gindex, Node.Id),

        /// cached data for faster access of already-visited children
        children_data: std.AutoHashMapUnmanaged(Gindex, ElementPtr),

        /// whether the corresponding child node/data has changed since the last update of the root
        changed: std.AutoArrayHashMapUnmanaged(Gindex, void),

        const Element = ST.Element.TreeView;
        pub const ElementPtr = *Element;

        const Self = @This();

        pub fn init(self: *Self, allocator: Allocator, pool: *Node.Pool, root: Node.Id) !void {
            try pool.ref(root);
            errdefer pool.unref(root);
            self.* = .{
                .allocator = allocator,
                .pool = pool,
                .root = root,
                .children_nodes = .empty,
                .children_data = .empty,
                .changed = .empty,
            };
        }

        /// Deinitialize the Data and free all associated resources.
        /// This also deinits all child Data recursively.
        pub fn deinit(self: *Self) void {
            self.pool.unref(self.root);
            self.clearChildrenNodesCache();
            self.children_nodes.deinit(self.allocator);
            self.clearChildrenDataCache();
            self.children_data.deinit(self.allocator);
            self.changed.deinit(self.allocator);
        }

        pub fn commit(self: *Self) !void {
            if (self.changed.count() == 0) {
                return;
            }

            const nodes = try self.allocator.alloc(Node.Id, self.changed.count());
            defer self.allocator.free(nodes);

            const gindices = self.changed.keys();
            Gindex.sortAsc(gindices);

            for (gindices, 0..) |gindex, i| {
                if (self.children_data.get(gindex)) |child_ptr| {
                    // TODO: compare with child_nodes to avoid unnecessary rebind
                    try child_ptr.commit();
                    nodes[i] = child_ptr.getRoot();
                } else if (self.children_nodes.get(gindex)) |child_node| {
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

        pub fn get(self: *Self, index: usize) !ElementPtr {
            const gindex = Gindex.fromDepth(chunk_depth, index);
            const gop = try self.children_data.getOrPut(self.allocator, gindex);
            if (gop.found_existing) {
                return gop.value_ptr.*;
            }
            const child_node = try self.getChildNode(gindex);
            const child_ptr = try Element.init(self.allocator, self.pool, child_node);
            gop.value_ptr.* = child_ptr;

            // TODO only update changed if the subview is mutable
            try self.changed.put(self.allocator, gindex, {});
            return child_ptr;
        }

        pub fn set(self: *Self, index: usize, value: ElementPtr) !void {
            const gindex = Gindex.fromDepth(chunk_depth, index);
            try self.changed.put(self.allocator, gindex, {});
            const opt_old_data = try self.children_data.fetchPut(
                self.allocator,
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

        pub fn getChildNode(self: *Self, gindex: Gindex) !Node.Id {
            return getChildNodeOrTraverse(self, gindex);
        }

        pub fn setChildNode(self: *Self, gindex: Gindex, node: Node.Id) !void {
            try setChildNodeUnrefOld(self, gindex, node);
        }

        pub fn clearChildrenNodesCache(self: *Self) void {
            clearChildrenNodesAndUnref(self, self.pool);
        }

        pub fn clearChildrenDataCache(self: *Self) void {
            var value_iter = self.children_data.valueIterator();
            while (value_iter.next()) |child_ptr| {
                child_ptr.*.deinit();
            }
            self.children_data.clearRetainingCapacity();
        }
    };
}

/// common functions for both BasicPackedChunks and CompositeChunks to deal with children_nodes
pub fn getChildNodeOrTraverse(self: anytype, gindex: Gindex) !Node.Id {
    const gop = try self.children_nodes.getOrPut(self.allocator, gindex);
    if (gop.found_existing) {
        return gop.value_ptr.*;
    }
    const child_node = try self.root.getNode(self.pool, gindex);
    gop.value_ptr.* = child_node;
    return child_node;
}

fn setChildNodeUnrefOld(self: anytype, gindex: Gindex, node: Node.Id) !void {
    try self.changed.put(self.allocator, gindex, {});
    const opt_old_node = try self.children_nodes.fetchPut(
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

pub fn clearChildrenNodesAndUnref(self: anytype, pool: *Node.Pool) void {
    var value_iter = self.children_nodes.valueIterator();
    while (value_iter.next()) |node_id_ptr| {
        const node_id = node_id_ptr.*;
        if (node_id.getState(pool).getRefCount() == 0) {
            pool.unref(node_id);
        }
    }
    self.children_nodes.clearRetainingCapacity();
}
