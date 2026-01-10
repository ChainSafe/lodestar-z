const std = @import("std");
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const CloneOpts = @import("clone_opts.zig").CloneOpts;

/// Common functions for `TreeView`s dealing with `children_nodes`.
pub const ChildNodes = struct {
    pub fn getChildNode(self: anytype, gindex: Gindex) !Node.Id {
        const gop = try self.children_nodes.getOrPut(self.allocator, gindex);
        if (gop.found_existing) {
            return gop.value_ptr.*;
        }
        const child_node = try self.root.getNode(self.pool, gindex);
        gop.value_ptr.* = child_node;
        return child_node;
    }

    pub fn setChildNode(self: anytype, gindex: Gindex, node: Node.Id) !void {
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

    pub fn clearChildrenNodesCache(self: anytype, pool: *Node.Pool) void {
        var value_iter = self.children_nodes.valueIterator();
        while (value_iter.next()) |node_id_ptr| {
            const node_id = node_id_ptr.*;
            if (node_id.getState(pool).getRefCount() == 0) {
                pool.unref(node_id);
            }
        }
        self.children_nodes.clearRetainingCapacity();
    }

    pub fn getLength(self: anytype) !usize {
        const length_node = try getChildNode(self, @enumFromInt(3));
        const length_chunk = length_node.getRoot(self.pool);
        return std.mem.readInt(usize, length_chunk[0..@sizeOf(usize)], .little);
    }

    pub fn setLength(self: anytype, length: usize) !void {
        const length_node = try self.pool.createLeafFromUint(@intCast(length));
        errdefer self.pool.unref(length_node);
        try self.setChildNode(@enumFromInt(3), length_node);
    }

    /// Common functions for TreeViews deal with `children_nodes` + `changed`
    pub const Change = struct {
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

        pub fn clone(comptime T: type, self: *T, opts: CloneOpts, out: *T) !void {
            try T.init(out, self.allocator, self.pool, self.root);

            if (!opts.transfer_cache) {
                return;
            }

            out.children_nodes = self.children_nodes;

            var nodes_it = out.children_nodes.iterator();
            while (nodes_it.next()) |entry| {
                const gindex = entry.key_ptr.*;
                if (self.changed.contains(gindex)) {
                    _ = out.children_nodes.remove(gindex);
                }
            }

            // clear self's caches
            self.children_nodes = .empty;
            self.changed.clearRetainingCapacity();
        }
    };
};
