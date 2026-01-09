const std = @import("std");
const Allocator = std.mem.Allocator;

const hashing = @import("hashing");
const Depth = hashing.Depth;

const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;

const isFixedType = @import("../type/type_kind.zig").isFixedType;

const tree_view_root = @import("root.zig");
const BaseTreeView = tree_view_root.BaseTreeView;
const TreeViewData = tree_view_root.TreeViewData;

/// Shared helpers for basic element types packed into chunks.
pub fn BasicPackedChunks(
    comptime ST: type,
    comptime chunk_depth: Depth,
    comptime items_per_chunk: usize,
) type {
    return struct {
        pub const Element = ST.Element.Type;

        pub fn get(base_view: *BaseTreeView, index: usize) !Element {
            var value: Element = undefined;
            const child_node = try base_view.getChildNode(Gindex.fromDepth(chunk_depth, index / items_per_chunk));
            try ST.Element.tree.toValuePacked(child_node, base_view.pool, index, &value);
            return value;
        }

        pub fn set(base_view: *BaseTreeView, index: usize, value: Element) !void {
            const gindex = Gindex.fromDepth(chunk_depth, index / items_per_chunk);
            try base_view.data.changed.put(base_view.allocator, gindex, {});
            const child_node = try base_view.getChildNode(gindex);
            const opt_old_node = try base_view.data.children_nodes.fetchPut(
                base_view.allocator,
                gindex,
                try ST.Element.tree.fromValuePacked(child_node, base_view.pool, index, &value),
            );
            if (opt_old_node) |old_node| {
                if (old_node.value.getState(base_view.pool).getRefCount() == 0) {
                    base_view.pool.unref(old_node.value);
                }
            }
        }

        pub fn getAll(
            base_view: *BaseTreeView,
            allocator: Allocator,
            len: usize,
        ) ![]Element {
            const values = try allocator.alloc(Element, len);
            errdefer allocator.free(values);
            return try getAllInto(base_view, len, values);
        }

        pub fn getAllInto(
            base_view: *BaseTreeView,
            len: usize,
            values: []Element,
        ) ![]Element {
            if (values.len != len) return error.InvalidSize;
            if (len == 0) return values;

            if (base_view.data.changed.count() != 0) {
                return error.MustCommitBeforeBulkRead;
            }

            const len_full_chunks = len / items_per_chunk;
            const remainder = len % items_per_chunk;
            const chunk_count = len_full_chunks + @intFromBool(remainder != 0);

            try populateAllNodes(base_view, chunk_count);

            for (0..len_full_chunks) |chunk_idx| {
                const leaf_node = try base_view.getChildNode(Gindex.fromDepth(chunk_depth, chunk_idx));
                for (0..items_per_chunk) |i| {
                    try ST.Element.tree.toValuePacked(
                        leaf_node,
                        base_view.pool,
                        i,
                        &values[chunk_idx * items_per_chunk + i],
                    );
                }
            }

            if (remainder > 0) {
                const leaf_node = try base_view.getChildNode(Gindex.fromDepth(chunk_depth, len_full_chunks));
                for (0..remainder) |i| {
                    try ST.Element.tree.toValuePacked(
                        leaf_node,
                        base_view.pool,
                        i,
                        &values[len_full_chunks * items_per_chunk + i],
                    );
                }
            }

            return values;
        }

        fn populateAllNodes(base_view: *BaseTreeView, chunk_count: usize) !void {
            if (chunk_count == 0) return;

            const nodes = try base_view.allocator.alloc(Node.Id, chunk_count);
            defer base_view.allocator.free(nodes);

            try base_view.data.root.getNodesAtDepth(base_view.pool, chunk_depth, 0, nodes);

            for (nodes, 0..) |node, chunk_idx| {
                const gindex = Gindex.fromDepth(chunk_depth, chunk_idx);
                const gop = try base_view.data.children_nodes.getOrPut(base_view.allocator, gindex);
                if (!gop.found_existing) {
                    gop.value_ptr.* = node;
                }
            }
        }
    };
}

/// Shared helpers for composite element types, where each element occupies its own subtree.
pub fn CompositeChunks(
    comptime ST: type,
    comptime chunk_depth: Depth,
) type {
    return struct {
        pub const Element = ST.Element.TreeView;
        pub const Value = ST.Element.Type;

        pub fn get(base_view: *BaseTreeView, index: usize) !Element {
            const child_data = try base_view.getChildData(Gindex.fromDepth(chunk_depth, index));
            return .{
                .base_view = .{
                    .allocator = base_view.allocator,
                    .pool = base_view.pool,
                    .data = child_data,
                },
            };
        }

        pub fn set(base_view: *BaseTreeView, index: usize, value: Element) !void {
            const gindex = Gindex.fromDepth(chunk_depth, index);
            try base_view.setChildData(gindex, value.base_view.data);
        }

        /// Get all element values in a single traversal.
        ///
        /// WARNING: Returns all committed changes. If there are any pending changes,
        /// commit them beforehand.
        ///
        /// Caller owns the returned slice and must free it with the same allocator.
        pub fn getAllValues(
            base_view: *BaseTreeView,
            allocator: Allocator,
            len: usize,
        ) ![]Value {
            const values = try allocator.alloc(Value, len);
            errdefer allocator.free(values);
            _ = try getAllValuesInto(base_view, allocator, values);
            return values;
        }

        /// Fills `values` with all element values in a single traversal.
        /// `values.len` determines the number of elements read.
        pub fn getAllValuesInto(
            base_view: *BaseTreeView,
            allocator: Allocator,
            values: []Value,
        ) ![]Value {
            const len = values.len;
            if (len == 0) return values;

            if (base_view.data.changed.count() != 0) {
                return error.MustCommitBeforeBulkRead;
            }

            const nodes = try allocator.alloc(Node.Id, len);
            defer allocator.free(nodes);

            try base_view.data.root.getNodesAtDepth(base_view.pool, chunk_depth, 0, nodes);

            for (nodes, 0..) |node, i| {
                if (comptime isFixedType(ST.Element)) {
                    try ST.Element.tree.toValue(node, base_view.pool, &values[i]);
                } else {
                    try ST.Element.tree.toValue(allocator, node, base_view.pool, &values[i]);
                }
            }

            return values;
        }
    };
}
