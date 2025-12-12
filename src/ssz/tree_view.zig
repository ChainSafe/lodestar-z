const std = @import("std");
const Allocator = std.mem.Allocator;
const Depth = @import("hashing").Depth;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const isBasicType = @import("type/type_kind.zig").isBasicType;
const BYTES_PER_CHUNK = @import("type/root.zig").BYTES_PER_CHUNK;

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
        self.children_nodes.deinit(allocator);
        var value_iter = self.children_data.valueIterator();
        while (value_iter.next()) |child_data| {
            child_data.deinit(allocator, pool);
        }
        self.children_data.deinit(allocator);
        self.changed.deinit(allocator);
    }

    pub fn commit(self: *TreeViewData, allocator: Allocator, pool: *Node.Pool) !void {
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

        const new_root = try self.root.setNodes(pool, gindices, nodes);
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
/// This struct serves as the base for specialized tree views like `ContainerTreeView` and `ArrayTreeView`.
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

    pub fn deinit(self: *BaseTreeView) void {
        self.data.deinit(self.allocator, self.pool);
    }

    pub fn commit(self: *BaseTreeView) !void {
        try self.data.commit(self.allocator, self.pool);
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

    pub fn setChildData(self: *BaseTreeView, gindex: Gindex, data: TreeViewData) !void {
        try self.data.changed.put(self.allocator, gindex, {});
        const opt_old_data = try self.data.children_data.fetchPut(
            self.allocator,
            gindex,
            data,
        );
        if (opt_old_data) |old_data_value| {
            var old_data = @constCast(&old_data_value.value);
            old_data.deinit(self.allocator, self.pool);
        }
    }
};

/// A specialized tree view for SSZ container types, enabling efficient access and modification of container fields, given a backing merkle tree.
///
/// This struct wraps a `BaseTreeView` and provides methods to get and set fields by name.
///
/// For basic-type fields, it returns or accepts values directly; for complex fields, it returns or accepts corresponding tree views.
pub fn ContainerTreeView(comptime ST: type) type {
    return struct {
        base_view: BaseTreeView,

        const Self = @This();

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !Self {
            return .{
                .base_view = try BaseTreeView.init(allocator, pool, root),
            };
        }

        pub fn deinit(self: *Self) void {
            self.base_view.deinit();
        }

        pub fn commit(self: *Self) !void {
            try self.base_view.commit();
        }

        pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void {
            try self.base_view.hashTreeRoot(out);
        }

        pub fn Field(comptime field_name: []const u8) type {
            const ChildST = ST.getFieldType(field_name);
            if (comptime isBasicType(ChildST)) {
                return ChildST.Type;
            } else {
                return ChildST.TreeView;
            }
        }

        /// Get a field by name. If the field is a basic type, returns the value directly.
        /// Caller borrows a copy of the value so there is no need to deinit it.
        pub fn get(self: *Self, comptime field_name: []const u8) !Field(field_name) {
            const field_index = comptime ST.getFieldIndex(field_name);
            const ChildST = ST.getFieldType(field_name);
            const child_gindex = Gindex.fromDepth(ST.chunk_depth, field_index);
            if (comptime isBasicType(ChildST)) {
                var value: ChildST.Type = undefined;
                const child_node = try self.base_view.getChildNode(child_gindex);
                try ChildST.tree.toValue(child_node, self.base_view.pool, &value);
                return value;
            } else {
                const child_data = try self.base_view.getChildData(child_gindex);

                return .{
                    .base_view = .{
                        .allocator = self.base_view.allocator,
                        .pool = self.base_view.pool,
                        .data = child_data,
                    },
                };
            }
        }

        /// Set a field by name. If the field is a basic type, pass the value directly.
        /// If the field is a complex type, pass a TreeView of the corresponding type.
        /// The caller transfers ownership of the `value` TreeView to this parent view.
        /// The existing TreeView, if any, will be deinited by this function.
        pub fn set(self: *Self, comptime field_name: []const u8, value: Field(field_name)) !void {
            const field_index = comptime ST.getFieldIndex(field_name);
            const ChildST = ST.getFieldType(field_name);
            const child_gindex = Gindex.fromDepth(ST.chunk_depth, field_index);
            if (comptime isBasicType(ChildST)) {
                try self.base_view.setChildNode(
                    child_gindex,
                    try ChildST.tree.fromValue(
                        self.base_view.pool,
                        &value,
                    ),
                );
            } else {
                try self.base_view.setChildData(child_gindex, value.base_view.data);
            }
        }
    };
}

/// A specialized tree view for SSZ list and vector types, enabling efficient access and modification of array elements, given a backing merkle tree.
///
/// This struct wraps a `BaseTreeView` and provides methods to get and set elements by index.
///
/// For basic-type elements, it returns or accepts values directly; for complex elements, it returns or accepts corresponding tree views.
pub fn ArrayTreeView(comptime ST: type) type {
    return struct {
        base_view: BaseTreeView,

        const Self = @This();

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !Self {
            return .{
                .base_view = try BaseTreeView.init(allocator, pool, root),
            };
        }

        pub fn deinit(self: *Self) void {
            self.base_view.deinit();
        }

        pub fn commit(self: *Self) !void {
            try self.base_view.commit();
        }

        pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void {
            try self.base_view.hashTreeRoot(out);
        }

        pub const Element: type = if (isBasicType(ST.Element))
            ST.Element.Type
        else
            ST.Element.TreeView;

        inline fn elementChildGindex(index: usize) Gindex {
            return Gindex.fromDepth(
                // Lists mix in their length at one extra depth level.
                ST.chunk_depth + if (ST.kind == .list) 1 else 0,
                if (comptime isBasicType(ST.Element)) blk: {
                    const per_chunk = BYTES_PER_CHUNK / ST.Element.fixed_size;
                    break :blk index / per_chunk;
                } else index,
            );
        }

        /// Get an element by index. If the element is a basic type, returns the value directly.
        /// Caller borrows a copy of the value so there is no need to deinit it.
        pub fn get(self: *Self, index: usize) !Element {
            const child_gindex = elementChildGindex(index);
            if (comptime isBasicType(ST.Element)) {
                var value: ST.Element.Type = undefined;
                const child_node = try self.base_view.getChildNode(child_gindex);
                try ST.Element.tree.toValuePacked(child_node, self.base_view.pool, index, &value);
                return value;
            } else {
                const child_data = try self.base_view.getChildData(child_gindex);

                return .{
                    .base_view = .{
                        .allocator = self.base_view.allocator,
                        .pool = self.base_view.pool,
                        .data = child_data,
                    },
                };
            }
        }

        /// Set an element by index. If the element is a basic type, pass the value directly.
        /// If the element is a complex type, pass a TreeView of the corresponding type.
        /// The caller transfers ownership of the `value` TreeView to this parent view.
        /// The existing TreeView, if any, will be deinited by this function.
        pub fn set(self: *Self, index: usize, value: Element) !void {
            const child_gindex = elementChildGindex(index);
            if (comptime isBasicType(ST.Element)) {
                const child_node = try self.base_view.getChildNode(child_gindex);
                try self.base_view.setChildNode(
                    child_gindex,
                    try ST.Element.tree.fromValuePacked(
                        child_node,
                        self.base_view.pool,
                        index,
                        &value,
                    ),
                );
            } else {
                try self.base_view.setChildData(child_gindex, value.base_view.data);
            }
        }
    };
}
