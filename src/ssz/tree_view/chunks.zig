const std = @import("std");
const Allocator = std.mem.Allocator;

const hashing = @import("hashing");
const Depth = hashing.Depth;

const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;

const ViewStore = @import("view_store.zig").ViewStore;
const ViewId = @import("view_store.zig").ViewId;

/// Common logic for setting a composite child view.
/// Used by container, array_composite, list_composite, and CompositeChunks.
pub fn setChildViewValue(
    store: *ViewStore,
    parent_view_id: ViewId,
    child_gindex: Gindex,
    child_view: anytype,
) !void {
    var v = child_view;
    defer v.deinit();

    if (v.store != store) return error.DifferentStore;

    if (store.cachedChildViewId(parent_view_id, child_gindex)) |cached_child_id| {
        if (cached_child_id == v.view_id) {
            try store.markChanged(parent_view_id, child_gindex);
            return;
        }
    }

    try store.setChildView(parent_view_id, child_gindex, v.view_id);
}

/// Shared helpers for basic element types packed into chunks.
/// Works with ViewStore-based tree views.
pub fn BasicPackedChunks(
    comptime ST: type,
    comptime chunk_depth: Depth,
    comptime items_per_chunk: usize,
) type {
    return struct {
        pub const Element = ST.Element.Type;

        pub fn get(store: *ViewStore, view_id: ViewId, index: usize) !Element {
            var value: Element = undefined;
            const leaf_node = try store.getChildNode(view_id, Gindex.fromDepth(chunk_depth, index / items_per_chunk));
            try ST.Element.tree.toValuePacked(leaf_node, store.pool, index, &value);
            return value;
        }

        pub fn set(store: *ViewStore, view_id: ViewId, index: usize, value: Element) !void {
            const gindex = Gindex.fromDepth(chunk_depth, index / items_per_chunk);
            const leaf_node = try store.getChildNode(view_id, gindex);
            const new_leaf = try ST.Element.tree.fromValuePacked(leaf_node, store.pool, index, &value);
            try store.setChildNode(view_id, gindex, new_leaf);
        }

        pub fn getAll(store: *ViewStore, view_id: ViewId, allocator: Allocator, len: usize) ![]Element {
            const values = try allocator.alloc(Element, len);
            errdefer allocator.free(values);
            return try getAllInto(store, view_id, len, values);
        }

        pub fn getAllInto(store: *ViewStore, view_id: ViewId, len: usize, values: []Element) ![]Element {
            if (values.len != len) return error.InvalidSize;
            if (len == 0) return values;

            const len_full_chunks = len / items_per_chunk;
            const remainder = len % items_per_chunk;
            const chunk_count = len_full_chunks + @intFromBool(remainder != 0);

            // Batch-fetch all leaf nodes at once for better performance
            try populateAllNodes(store, view_id, chunk_count);

            for (0..len_full_chunks) |chunk_idx| {
                const leaf_node = try store.getChildNode(view_id, Gindex.fromDepth(chunk_depth, chunk_idx));
                for (0..items_per_chunk) |i| {
                    try ST.Element.tree.toValuePacked(
                        leaf_node,
                        store.pool,
                        i,
                        &values[chunk_idx * items_per_chunk + i],
                    );
                }
            }

            if (remainder > 0) {
                const leaf_node = try store.getChildNode(view_id, Gindex.fromDepth(chunk_depth, len_full_chunks));
                for (0..remainder) |i| {
                    try ST.Element.tree.toValuePacked(
                        leaf_node,
                        store.pool,
                        i,
                        &values[len_full_chunks * items_per_chunk + i],
                    );
                }
            }

            return values;
        }

        /// Pre-populate the ViewStore's cache with all leaf nodes at once.
        /// This is more efficient than fetching nodes one-by-one.
        fn populateAllNodes(store: *ViewStore, view_id: ViewId, chunk_count: usize) !void {
            if (chunk_count == 0) return;

            const nodes = try store.allocator.alloc(Node.Id, chunk_count);
            defer store.allocator.free(nodes);

            const root = store.rootNode(view_id);
            try root.getNodesAtDepth(store.pool, chunk_depth, 0, nodes);

            for (nodes, 0..) |node, chunk_idx| {
                const gindex = Gindex.fromDepth(chunk_depth, chunk_idx);
                try store.cacheChildNodeIfAbsent(view_id, gindex, node);
            }
        }
    };
}

/// Shared helpers for composite element types, where each element occupies its own subtree.
/// Works with ViewStore-based tree views.
pub fn CompositeChunks(
    comptime ST: type,
    comptime chunk_depth: Depth,
) type {
    return struct {
        // Use ST.Element.TreeView directly instead of TreeViewFor to avoid import cycle
        pub const ElementTreeView = ST.Element.TreeView;

        pub fn get(store: *ViewStore, view_id: ViewId, index: usize) !ElementTreeView {
            const gindex = Gindex.fromDepth(chunk_depth, index);
            const child_view_id = try store.getOrCreateChildView(view_id, gindex);
            return ElementTreeView.fromStore(store, child_view_id);
        }

        pub fn set(store: *ViewStore, view_id: ViewId, index: usize, child_view: ElementTreeView) !void {
            const gindex = Gindex.fromDepth(chunk_depth, index);
            try setChildViewValue(store, view_id, gindex, child_view);
        }
    };
}
