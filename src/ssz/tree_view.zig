const std = @import("std");
const Allocator = std.mem.Allocator;
const hashing = @import("hashing");
const Depth = hashing.Depth;
const ListLengthUint = hashing.GindexUint;
const list_length_unset = hashing.max_depth;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const isBasicType = @import("type/type_kind.zig").isBasicType;

const type_root = @import("type/root.zig");
const BYTES_PER_CHUNK = type_root.BYTES_PER_CHUNK;
const itemsPerChunk = type_root.itemsPerChunk;
const chunkDepth = type_root.chunkDepth;

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

        const new_root = try self.root.setNodesGrouped(pool, gindices, nodes);
        try pool.ref(new_root);
        pool.unref(self.root);
        self.root = new_root;

        self.changed.clearRetainingCapacity();
    }
};

/// Extended tree view data for array (vector) types.
/// Composes TreeViewData and adds array-specific caching fields.
pub const ArrayTreeViewData = struct {
    base: TreeViewData,

    /// Number of chunk nodes (starting from index 0) that have been prefetched into the cache.
    prefetched_chunk_count: usize,

    pub fn init(pool: *Node.Pool, root: Node.Id) !ArrayTreeViewData {
        return ArrayTreeViewData{
            .base = try TreeViewData.init(pool, root),
            .prefetched_chunk_count = 0,
        };
    }

    pub fn deinit(self: *ArrayTreeViewData, allocator: Allocator, pool: *Node.Pool) void {
        self.base.deinit(allocator, pool);
    }

    pub fn commit(self: *ArrayTreeViewData, allocator: Allocator, pool: *Node.Pool) !void {
        try self.base.commit(allocator, pool);
    }
};

/// Extended tree view data for list types.
/// Composes ArrayTreeViewData and adds list-specific length field.
pub const ListTreeViewData = struct {
    base: ArrayTreeViewData,

    /// Cached length for list views. `list_length_unset` marks the value as invalid/unpopulated, so
    /// the next `getLength()` fetches from the tree before returning a concrete length.
    list_length: ListLengthUint,

    pub fn init(pool: *Node.Pool, root: Node.Id) !ListTreeViewData {
        return ListTreeViewData{
            .base = try ArrayTreeViewData.init(pool, root),
            .list_length = list_length_unset,
        };
    }

    pub fn deinit(self: *ListTreeViewData, allocator: Allocator, pool: *Node.Pool) void {
        self.base.deinit(allocator, pool);
    }

    pub fn commit(self: *ListTreeViewData, allocator: Allocator, pool: *Node.Pool) !void {
        try self.base.commit(allocator, pool);
    }
};

/// Provides the foundational implementation for tree views.
///
/// `BaseTreeView` is a generic struct that manages a `DataType` (one of `TreeViewData`, `ArrayTreeViewData`, or `ListTreeViewData`),
/// enabling fast (re)access of children and batched updates to the merkle tree structure.
///
/// It supports operations such as get/set of child nodes and data, committing changes, computing hash tree roots.
///
/// This struct serves as the base for specialized tree views like `ContainerTreeView` and `ArrayTreeView`.
pub fn BaseTreeView(comptime DataType: type) type {
    return struct {
        allocator: Allocator,
        pool: *Node.Pool,
        data: DataType,

        const Self = @This();

        /// Get a pointer to the base TreeViewData.
        pub fn base(self: *Self) *TreeViewData {
            if (DataType == TreeViewData) {
                return &self.data;
            } else if (DataType == ArrayTreeViewData) {
                return &self.data.base;
            } else if (DataType == ListTreeViewData) {
                return &self.data.base.base;
            } else {
                @compileError("Unsupported DataType for BaseTreeView");
            }
        }

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !Self {
            return Self{
                .allocator = allocator,
                .pool = pool,
                .data = try DataType.init(pool, root),
            };
        }

        pub fn deinit(self: *Self) void {
            self.data.deinit(self.allocator, self.pool);
        }

        pub fn commit(self: *Self) !void {
            try self.data.commit(self.allocator, self.pool);
        }

        pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void {
            try self.commit();
            out.* = self.base().root.getRoot(self.pool).*;
        }

        pub fn getChildNode(self: *Self, gindex: Gindex) !Node.Id {
            const b = self.base();
            const gop = try b.children_nodes.getOrPut(self.allocator, gindex);
            if (gop.found_existing) {
                return gop.value_ptr.*;
            }
            const child_node = try b.root.getNode(self.pool, gindex);
            gop.value_ptr.* = child_node;
            return child_node;
        }

        pub fn setChildNode(self: *Self, gindex: Gindex, node: Node.Id) !void {
            const b = self.base();
            try b.changed.put(self.allocator, gindex, {});
            const opt_old_node = try b.children_nodes.fetchPut(
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

        pub fn getChildData(self: *Self, gindex: Gindex) !TreeViewData {
            const b = self.base();
            const gop = try b.children_data.getOrPut(self.allocator, gindex);
            if (gop.found_existing) {
                return gop.value_ptr.*;
            }
            const child_node = try self.getChildNode(gindex);
            const child_data = try TreeViewData.init(self.pool, child_node);
            gop.value_ptr.* = child_data;

            // TODO only update changed if the subview is mutable
            try b.changed.put(self.allocator, gindex, {});
            return child_data;
        }

        pub fn setChildData(self: *Self, gindex: Gindex, child_data: TreeViewData) !void {
            const b = self.base();
            try b.changed.put(self.allocator, gindex, {});
            const opt_old_data = try b.children_data.fetchPut(
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
}

/// A specialized tree view for SSZ container types, enabling efficient access and modification of container fields, given a backing merkle tree.
///
/// This struct wraps a `BaseTreeView(TreeViewData)` and provides methods to get and set fields by name.
///
/// For basic-type fields, it returns or accepts values directly; for complex fields, it returns or accepts corresponding tree views.
pub fn ContainerTreeView(comptime ST: type) type {
    return struct {
        base_view: BaseTreeView(TreeViewData),

        pub const SszType = ST;

        const Self = @This();

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !Self {
            return .{
                .base_view = try BaseTreeView(TreeViewData).init(allocator, pool, root),
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

/// A specialized tree view for SSZ vector types, enabling efficient access and modification of array elements, given a backing merkle tree.
///
/// This struct wraps a `BaseTreeView(ArrayTreeViewData)` and provides methods to get and set elements by index.
///
/// For basic-type elements, it returns or accepts values directly; for complex elements, it returns or accepts corresponding tree views.
pub fn ArrayTreeView(comptime ST: type) type {
    return struct {
        base_view: BaseTreeView(ArrayTreeViewData),

        pub const SszType = ST;

        const Self = @This();

        const base_chunk_depth: Depth = @intCast(ST.chunk_depth);
        const chunk_depth: Depth = chunkDepth(Depth, base_chunk_depth, ST);

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !Self {
            return .{
                .base_view = try BaseTreeView(ArrayTreeViewData).init(allocator, pool, root),
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

        /// Get the length of the array. For Vector returns compile-time constant.
        pub fn getLength(self: *Self) !usize {
            _ = self;
            comptime {
                if (ST.kind != .vector) {
                    @compileError("ArrayTreeView.getLength can only be used with Vector types. For List, use ListArrayTreeView");
                }
            }
            return ST.length;
        }

        pub const Element: type = if (isBasicType(ST.Element))
            ST.Element.Type
        else
            ST.Element.TreeView;

        inline fn elementChildGindex(index: usize) Gindex {
            return Gindex.fromDepth(
                chunk_depth,
                if (comptime isBasicType(ST.Element)) blk: {
                    const per_chunk = itemsPerChunk(ST.Element);
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
            const b = self.base_view.base();
            try b.changed.put(self.base_view.allocator, child_gindex, {});
            if (comptime isBasicType(ST.Element)) {
                const child_node = try self.base_view.getChildNode(child_gindex);
                const opt_old_node = try b.children_nodes.fetchPut(
                    self.base_view.allocator,
                    child_gindex,
                    try ST.Element.tree.fromValuePacked(
                        child_node,
                        self.base_view.pool,
                        index,
                        &value,
                    ),
                );
                if (opt_old_node) |old_node| {
                    if (old_node.value.getState(self.base_view.pool).getRefCount() == 0) {
                        self.base_view.pool.unref(old_node.value);
                    }
                }
            } else {
                const opt_old_data = try b.children_data.fetchPut(
                    self.base_view.allocator,
                    child_gindex,
                    value.base_view.data,
                );
                if (opt_old_data) |old_data_value| {
                    var data_ptr: *TreeViewData = @constCast(&old_data_value.value);
                    data_ptr.deinit(self.base_view.allocator, self.base_view.pool);
                }
            }
        }

        /// Prefetch up to `chunk_count` chunk leaves into the cache so repeated reads from
        /// basic arrays avoid re-traversing the tree.
        fn ensureChunkPrefetch(self: *Self, chunk_count: usize, items_per_chunk_arg: usize) !void {
            comptime {
                if (!(@hasDecl(ST, "Element") and isBasicType(ST.Element))) {
                    @compileError("ensureChunkPrefetch can only be used with basic element types");
                }
            }

            if (chunk_count == 0) return;
            if (self.base_view.data.prefetched_chunk_count >= chunk_count) return;

            const start_index = self.base_view.data.prefetched_chunk_count;
            const remaining = chunk_count - start_index;

            const nodes = try self.base_view.allocator.alloc(Node.Id, remaining);
            defer self.base_view.allocator.free(nodes);

            const b = self.base_view.base();
            try b.root.getNodesAtDepth(self.base_view.pool, chunk_depth, start_index, nodes);

            for (nodes, 0..) |node, offset| {
                const chunk_idx = start_index + offset;
                const gindex = elementChildGindex(chunk_idx * items_per_chunk_arg);
                const gop = try b.children_nodes.getOrPut(self.base_view.allocator, gindex);
                if (!gop.found_existing) {
                    gop.value_ptr.* = node;
                }
            }

            self.base_view.data.prefetched_chunk_count = chunk_count;
        }

        /// Allocate and return all elements as an array. Only available for basic array types (Vector of basic types).
        /// Returns a slice that must be freed by the caller.
        pub fn getAllAlloc(self: *Self, allocator: Allocator) ![]ST.Element.Type {
            comptime {
                if (!(@hasDecl(ST, "Element") and isBasicType(ST.Element))) {
                    @compileError("getAllAlloc can only be used with basic element types");
                }
            }

            const length = try self.getLength();
            const values = try allocator.alloc(ST.Element.Type, length);
            errdefer allocator.free(values);

            return try self.getAll(values);
        }

        /// Populate a caller-provided buffer with all elements and return it.
        pub fn getAll(self: *Self, values: []ST.Element.Type) ![]ST.Element.Type {
            comptime {
                if (!(@hasDecl(ST, "Element") and isBasicType(ST.Element))) {
                    @compileError("getAll can only be used with basic element types");
                }
            }

            const length = try self.getLength();
            if (values.len != length) {
                return error.InvalidSize;
            }

            if (length == 0) {
                return values;
            }

            const items_per_chunk_val = itemsPerChunk(ST.Element);
            const len_full_chunks = length / items_per_chunk_val;
            const remainder = length % items_per_chunk_val;
            const chunk_count = len_full_chunks + @intFromBool(remainder != 0);

            if (chunk_count > 0) {
                try self.ensureChunkPrefetch(chunk_count, items_per_chunk_val);
            }

            try self.populateElementsFromChunks(values, items_per_chunk_val, len_full_chunks, remainder);
            return values;
        }

        fn populateElementsFromChunks(
            self: *Self,
            dest: []ST.Element.Type,
            items_per_chunk_arg: usize,
            len_full_chunks: usize,
            remainder: usize,
        ) !void {
            for (0..len_full_chunks) |chunk_idx| {
                const chunk_gindex = elementChildGindex(chunk_idx * items_per_chunk_arg);
                const leaf_node = try self.base_view.getChildNode(chunk_gindex);

                for (0..items_per_chunk_arg) |i| {
                    try ST.Element.tree.toValuePacked(
                        leaf_node,
                        self.base_view.pool,
                        i,
                        &dest[chunk_idx * items_per_chunk_arg + i],
                    );
                }
            }

            if (remainder > 0) {
                const chunk_gindex = elementChildGindex(len_full_chunks * items_per_chunk_arg);
                const leaf_node = try self.base_view.getChildNode(chunk_gindex);

                for (0..remainder) |i| {
                    try ST.Element.tree.toValuePacked(
                        leaf_node,
                        self.base_view.pool,
                        i,
                        &dest[len_full_chunks * items_per_chunk_arg + i],
                    );
                }
            }
        }
    };
}

/// A specialized tree view for SSZ list types, enabling efficient access and modification of list elements, given a backing merkle tree.
///
/// This struct wraps a `BaseTreeView(ListTreeViewData)` and provides additional methods for list-specific operations like `push`, `sliceTo`, `sliceFrom`.
///
/// For basic-type elements, it returns or accepts values directly; for complex elements, it returns or accepts corresponding tree views.
pub fn ListArrayTreeView(comptime ST: type) type {
    comptime {
        if (ST.kind != .list) {
            @compileError("ListArrayTreeView can only be used with List types");
        }
    }

    return struct {
        base_view: BaseTreeView(ListTreeViewData),

        pub const SszType = ST;

        const Self = @This();

        const base_chunk_depth: Depth = @intCast(ST.chunk_depth);
        const chunk_depth: Depth = chunkDepth(Depth, base_chunk_depth, ST);

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !Self {
            return .{
                .base_view = try BaseTreeView(ListTreeViewData).init(allocator, pool, root),
            };
        }

        pub fn deinit(self: *Self) void {
            self.base_view.deinit();
        }

        pub fn commit(self: *Self) !void {
            const gindex = listLengthGindex();
            const b = self.base_view.base();
            if (b.changed.contains(gindex)) {
                const length_node = try self.base_view.pool.createLeafFromUint(self.base_view.data.list_length);
                const opt_old = blk: {
                    errdefer self.base_view.pool.unref(length_node);
                    break :blk try b.children_nodes.fetchPut(self.base_view.allocator, gindex, length_node);
                };
                if (opt_old) |old_entry| {
                    if (old_entry.value.getState(self.base_view.pool).getRefCount() == 0) {
                        self.base_view.pool.unref(old_entry.value);
                    }
                }
            }
            try b.commit(self.base_view.allocator, self.base_view.pool);
        }

        pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void {
            try self.commit();
            out.* = self.base_view.base().root.getRoot(self.base_view.pool).*;
        }

        /// Get the length of the list. Reads from tree if not cached.
        pub fn getLength(self: *Self) !usize {
            if (self.base_view.data.list_length != list_length_unset) {
                return @intCast(self.base_view.data.list_length);
            }
            const len = try ST.tree.length(self.base_view.base().root, self.base_view.pool);
            self.base_view.data.list_length = @intCast(len);
            return len;
        }

        pub const Element: type = if (isBasicType(ST.Element))
            ST.Element.Type
        else
            ST.Element.TreeView;

        inline fn elementChildGindex(index: usize) Gindex {
            return Gindex.fromDepth(
                chunk_depth,
                if (comptime isBasicType(ST.Element)) blk: {
                    const per_chunk = itemsPerChunk(ST.Element);
                    break :blk index / per_chunk;
                } else index,
            );
        }

        inline fn listLengthGindex() Gindex {
            return Gindex.fromDepth(1, 1);
        }

        fn updateListLength(self: *Self, new_length: usize) !void {
            if (new_length > ST.limit) {
                return error.LengthOverLimit;
            }

            // Only update the cached length and mark as changed.
            // The actual length node is created lazily in commit().
            try self.base_view.base().changed.put(self.base_view.allocator, listLengthGindex(), {});
            self.base_view.data.list_length = @intCast(new_length);
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
            const b = self.base_view.base();
            try b.changed.put(self.base_view.allocator, child_gindex, {});
            if (comptime isBasicType(ST.Element)) {
                const child_node = try self.base_view.getChildNode(child_gindex);
                const opt_old_node = try b.children_nodes.fetchPut(
                    self.base_view.allocator,
                    child_gindex,
                    try ST.Element.tree.fromValuePacked(
                        child_node,
                        self.base_view.pool,
                        index,
                        &value,
                    ),
                );
                if (opt_old_node) |old_node| {
                    if (old_node.value.getState(self.base_view.pool).getRefCount() == 0) {
                        self.base_view.pool.unref(old_node.value);
                    }
                }
            } else {
                const opt_old_data = try b.children_data.fetchPut(
                    self.base_view.allocator,
                    child_gindex,
                    value.base_view.data,
                );
                if (opt_old_data) |old_data_value| {
                    var data_ptr: *TreeViewData = @constCast(&old_data_value.value);
                    data_ptr.deinit(self.base_view.allocator, self.base_view.pool);
                }
            }
        }

        /// Prefetch up to `chunk_count` chunk leaves into the cache so repeated reads from
        /// basic arrays avoid re-traversing the tree.
        fn ensureChunkPrefetch(self: *Self, chunk_count: usize, items_per_chunk_arg: usize) !void {
            comptime {
                if (!(@hasDecl(ST, "Element") and isBasicType(ST.Element))) {
                    @compileError("ensureChunkPrefetch can only be used with basic element types");
                }
            }

            if (chunk_count == 0) return;
            if (self.base_view.data.base.prefetched_chunk_count >= chunk_count) return;

            const start_index = self.base_view.data.base.prefetched_chunk_count;
            const remaining = chunk_count - start_index;

            const nodes = try self.base_view.allocator.alloc(Node.Id, remaining);
            defer self.base_view.allocator.free(nodes);

            const b = self.base_view.base();
            try b.root.getNodesAtDepth(self.base_view.pool, chunk_depth, start_index, nodes);

            for (nodes, 0..) |node, offset| {
                const chunk_idx = start_index + offset;
                const gindex = elementChildGindex(chunk_idx * items_per_chunk_arg);
                const gop = try b.children_nodes.getOrPut(self.base_view.allocator, gindex);
                if (!gop.found_existing) {
                    gop.value_ptr.* = node;
                }
            }

            self.base_view.data.base.prefetched_chunk_count = chunk_count;
        }

        /// Allocate and return all elements as an array. Only available for basic list types (List of basic types).
        /// Returns a slice that must be freed by the caller.
        pub fn getAllAlloc(self: *Self, allocator: Allocator) ![]ST.Element.Type {
            comptime {
                if (!(@hasDecl(ST, "Element") and isBasicType(ST.Element))) {
                    @compileError("getAllAlloc can only be used with basic element types");
                }
            }

            const length = try self.getLength();
            const values = try allocator.alloc(ST.Element.Type, length);
            errdefer allocator.free(values);

            return try self.getAll(values);
        }

        /// Populate a caller-provided buffer with all elements and return it.
        pub fn getAll(self: *Self, values: []ST.Element.Type) ![]ST.Element.Type {
            comptime {
                if (!(@hasDecl(ST, "Element") and isBasicType(ST.Element))) {
                    @compileError("getAll can only be used with basic element types");
                }
            }

            const length = try self.getLength();
            if (values.len != length) {
                return error.InvalidSize;
            }

            if (length == 0) {
                return values;
            }

            const items_per_chunk_val = itemsPerChunk(ST.Element);
            const len_full_chunks = length / items_per_chunk_val;
            const remainder = length % items_per_chunk_val;
            const chunk_count = len_full_chunks + @intFromBool(remainder != 0);

            if (chunk_count > 0) {
                try self.ensureChunkPrefetch(chunk_count, items_per_chunk_val);
            }

            try self.populateElementsFromChunks(values, items_per_chunk_val, len_full_chunks, remainder);
            return values;
        }

        fn populateElementsFromChunks(
            self: *Self,
            dest: []ST.Element.Type,
            items_per_chunk_arg: usize,
            len_full_chunks: usize,
            remainder: usize,
        ) !void {
            for (0..len_full_chunks) |chunk_idx| {
                const chunk_gindex = elementChildGindex(chunk_idx * items_per_chunk_arg);
                const leaf_node = try self.base_view.getChildNode(chunk_gindex);

                for (0..items_per_chunk_arg) |i| {
                    try ST.Element.tree.toValuePacked(
                        leaf_node,
                        self.base_view.pool,
                        i,
                        &dest[chunk_idx * items_per_chunk_arg + i],
                    );
                }
            }

            if (remainder > 0) {
                const chunk_gindex = elementChildGindex(len_full_chunks * items_per_chunk_arg);
                const leaf_node = try self.base_view.getChildNode(chunk_gindex);

                for (0..remainder) |i| {
                    try ST.Element.tree.toValuePacked(
                        leaf_node,
                        self.base_view.pool,
                        i,
                        &dest[len_full_chunks * items_per_chunk_arg + i],
                    );
                }
            }
        }

        /// Append an element to the end of the list, updating the cached length.
        pub fn push(self: *Self, value: Element) !void {
            const length = try self.getLength();
            if (length >= ST.limit) {
                return error.LengthOverLimit;
            }

            try self.set(length, value);
            try self.updateListLength(length + 1);
        }

        /// Return a new view containing all elements up to and including `index`.
        /// Only available for list views.
        pub fn sliceTo(self: *Self, index: usize) !Self {
            try self.commit();

            const length = try self.getLength();
            const b = self.base_view.base();
            if (length == 0 or index >= length - 1) {
                return try Self.init(self.base_view.allocator, self.base_view.pool, b.root);
            }

            const new_length = index + 1;
            if (new_length > ST.limit) {
                return error.LengthOverLimit;
            }

            var new_root: ?Node.Id = null;
            defer if (new_root) |id| self.base_view.pool.unref(id);
            if (comptime @hasDecl(ST, "Element") and isBasicType(ST.Element)) {
                const items_per_chunk_val = itemsPerChunk(ST.Element);
                const chunk_index = index / items_per_chunk_val;
                const chunk_offset = index % items_per_chunk_val;
                const chunk_node = try Node.Id.getNodeAtDepth(b.root, self.base_view.pool, chunk_depth, chunk_index);

                var chunk_bytes = chunk_node.getRoot(self.base_view.pool).*;
                const keep_bytes = (chunk_offset + 1) * ST.Element.fixed_size;
                if (keep_bytes < BYTES_PER_CHUNK) {
                    @memset(chunk_bytes[keep_bytes..], 0);
                }

                var truncated_chunk_node: ?Node.Id = try self.base_view.pool.createLeaf(&chunk_bytes);
                defer if (truncated_chunk_node) |id| self.base_view.pool.unref(id);
                const updated = try Node.Id.setNodeAtDepth(b.root, self.base_view.pool, chunk_depth, chunk_index, truncated_chunk_node.?);
                truncated_chunk_node = null;
                new_root = try Node.Id.truncateAfterIndex(updated, self.base_view.pool, chunk_depth, chunk_index);
            } else {
                new_root = try Node.Id.truncateAfterIndex(b.root, self.base_view.pool, chunk_depth, index);
            }

            var length_node: ?Node.Id = try self.base_view.pool.createLeafFromUint(@intCast(new_length));
            defer if (length_node) |id| self.base_view.pool.unref(id);
            const with_length = try Node.Id.setNode(new_root.?, self.base_view.pool, listLengthGindex(), length_node.?);
            length_node = null;

            // Ensure the truncated tree has all branch hashes computed before handing it out.
            _ = with_length.getRoot(self.base_view.pool);

            new_root = with_length;
            const new_base_view = try BaseTreeView(ListTreeViewData).init(self.base_view.allocator, self.base_view.pool, with_length);
            new_root = null;
            return Self{
                .base_view = new_base_view,
            };
        }

        /// Return a new view containing all elements from `index` to the end.
        /// Only available for list views of composite types.
        /// Basic list slicing would require per-element extraction and repacking since multiple elements are tightly packed within each chunk.
        pub fn sliceFrom(self: *Self, index: usize) !Self {
            comptime {
                if (@hasDecl(ST, "Element") and isBasicType(ST.Element)) {
                    @compileError("sliceFrom can only be used with List of composite types");
                }
            }

            try self.commit();

            const length = try self.getLength();
            const b = self.base_view.base();
            if (index == 0) {
                return try Self.init(self.base_view.allocator, self.base_view.pool, b.root);
            }

            const target_length = if (index >= length) 0 else length - index;

            var chunk_root: ?Node.Id = null;
            defer if (chunk_root) |id| self.base_view.pool.unref(id);

            if (target_length == 0) {
                chunk_root = @enumFromInt(base_chunk_depth);
            } else {
                const nodes = try self.base_view.allocator.alloc(Node.Id, target_length);
                defer self.base_view.allocator.free(nodes);
                try b.root.getNodesAtDepth(self.base_view.pool, chunk_depth, index, nodes);

                chunk_root = try Node.fillWithContents(self.base_view.pool, nodes, base_chunk_depth);
            }

            var length_node: ?Node.Id = try self.base_view.pool.createLeafFromUint(@intCast(target_length));
            defer if (length_node) |id| self.base_view.pool.unref(id);

            const new_root = try self.base_view.pool.createBranch(chunk_root.?, length_node.?);
            length_node = null;
            chunk_root = null;

            var root_handle: ?Node.Id = new_root;
            defer if (root_handle) |id| self.base_view.pool.unref(id);
            const new_base_view = try BaseTreeView(ListTreeViewData).init(self.base_view.allocator, self.base_view.pool, new_root);
            root_handle = null;
            return Self{
                .base_view = new_base_view,
            };
        }
    };
}
