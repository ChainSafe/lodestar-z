const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;

pub const ChildNodesUtils = struct {
    /// common functions for TreeViews deal with children_nodes
    pub fn getChildNodeOrTraverse(self: anytype, gindex: Gindex) !Node.Id {
        const gop = try self.children_nodes.getOrPut(self.allocator, gindex);
        if (gop.found_existing) {
            return gop.value_ptr.*;
        }
        const child_node = try self.root.getNode(self.pool, gindex);
        gop.value_ptr.* = child_node;
        return child_node;
    }

    pub fn setChildNodeUnrefOld(self: anytype, gindex: Gindex, node: Node.Id) !void {
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

    pub const Change = struct {
        /// common functions for TreeViews deal with children_nodes + changed
        pub fn commit(self: anytype) !void {
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
    };
};
