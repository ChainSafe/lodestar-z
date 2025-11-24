const std = @import("std");
const math = std.math;
const hashing = @import("hashing");
const Depth = hashing.Depth;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const isBasicType = @import("type/type_kind.zig").isBasicType;
const TypeKind = @import("type/type_kind.zig").TypeKind;
const type_root = @import("type/root.zig");
const BYTES_PER_CHUNK = type_root.BYTES_PER_CHUNK;
const itemsPerChunk = type_root.itemsPerChunk;
const chunkCount = type_root.chunkCount;
const chunkDepth = type_root.chunkDepth;
const ListLengthUint = hashing.GindexUint;
// A sentinel value indicating that the list length cache is unset.
const list_length_unset = hashing.max_depth;

pub const Data = struct {
    root: Node.Id,

    /// cached nodes for faster access of already-visited children
    children_nodes: std.AutoHashMap(Gindex, Node.Id),

    /// cached data for faster access of already-visited children
    children_data: std.AutoHashMap(Gindex, Data),

    /// whether the corresponding child node/data has changed since the last update of the root
    changed: std.AutoArrayHashMap(Gindex, void),

    /// Number of chunk nodes (starting from index 0) that have been prefetched into the cache.
    /// Only used for basic array views.
    prefetched_chunk_count: usize,

    /// Cached length for list views. `list_length_unset` marks the value as invalid/unpopulated, so
    /// the next `getLength()` fetches from the tree before returning a concrete length.
    list_length: ListLengthUint,

    pub fn init(allocator: std.mem.Allocator, pool: *Node.Pool, root: Node.Id) !Data {
        try pool.ref(root);
        return Data{
            .root = root,
            .children_nodes = std.AutoHashMap(Gindex, Node.Id).init(allocator),
            .children_data = std.AutoHashMap(Gindex, Data).init(allocator),
            .changed = std.AutoArrayHashMap(Gindex, void).init(allocator),
            .prefetched_chunk_count = 0,
            .list_length = list_length_unset,
        };
    }

    /// Deinitialize the Data and free all associated resources.
    /// This also deinits all child Data recursively.
    pub fn deinit(self: *Data, pool: *Node.Pool) void {
        pool.unref(self.root);
        self.children_nodes.deinit();
        var value_iter = self.children_data.valueIterator();
        while (value_iter.next()) |child_data| {
            child_data.deinit(pool);
        }
        self.children_data.deinit();
        self.changed.deinit();
    }

    pub fn commit(self: *Data, allocator: std.mem.Allocator, pool: *Node.Pool) !void {
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
        self.list_length = list_length_unset;
    }
};

/// A treeview provides a view into a merkle tree of a given SSZ type.
/// It maintains and takes ownership recursively of a Data struct, which caches nodes and child Data.
pub fn TreeView(comptime ST: type) type {
    comptime {
        if (isBasicType(ST)) {
            @compileError("TreeView cannot be used with basic types");
        }
    }
    return struct {
        allocator: std.mem.Allocator,
        pool: *Node.Pool,
        data: Data,
        pub const SszType: type = ST;

        const Self = @This();

        /// Which variant this TreeView is
        const is_container_view = ST.kind == TypeKind.container;
        const is_list_view = ST.kind == TypeKind.list;
        const is_vector_view = ST.kind == TypeKind.vector;
        const is_array_view = is_list_view or is_vector_view;
        const is_basic_array_view = is_array_view and @hasDecl(ST, "Element") and isBasicType(ST.Element);

        pub fn init(allocator: std.mem.Allocator, pool: *Node.Pool, root: Node.Id) !Self {
            return Self{
                .allocator = allocator,
                .pool = pool,
                .data = try Data.init(allocator, pool, root),
            };
        }

        pub fn deinit(self: *Self) void {
            self.data.deinit(self.pool);
        }

        pub fn commit(self: *Self) !void {
            try self.data.commit(self.allocator, self.pool);
        }

        pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void {
            try self.commit();
            out.* = self.data.root.getRoot(self.pool).*;
        }

        /// Get (and cache) the length of the list. Only available for List types.
        pub fn getLength(self: *Self) !usize {
            if (comptime !is_list_view) {
                @compileError("getLength can only be used with List types");
            }
            if (self.data.list_length != list_length_unset) {
                return @intCast(self.data.list_length);
            }
            const len = try ST.tree.length(self.data.root, self.pool);
            self.data.list_length = @intCast(len);
            return len;
        }

        fn getChildNode(self: *Self, gindex: Gindex) !Node.Id {
            const gop = try self.data.children_nodes.getOrPut(gindex);
            if (gop.found_existing) {
                return gop.value_ptr.*;
            }
            const child_node = try self.data.root.getNode(self.pool, gindex);
            gop.value_ptr.* = child_node;
            return child_node;
        }

        fn getChildData(self: *Self, gindex: Gindex) !Data {
            const gop = try self.data.children_data.getOrPut(gindex);
            if (gop.found_existing) {
                return gop.value_ptr.*;
            }
            const child_node = try self.getChildNode(gindex);
            const child_data = try Data.init(self.allocator, self.pool, child_node);
            gop.value_ptr.* = child_data;
            return child_data;
        }

        /// Prefetch up to `chunk_count` chunk leaves into the cache so repeated reads from
        /// basic arrays avoid re-traversing the tree.
        fn ensureChunkPrefetch(self: *Self, chunk_count: usize, items_per_chunk: usize) !void {
            comptime {
                if (!is_basic_array_view) {
                    @compileError("ensureChunkPrefetch can only be used with basic array views");
                }
            }

            if (chunk_count == 0) return;
            if (self.data.prefetched_chunk_count >= chunk_count) return;

            const start_index = self.data.prefetched_chunk_count;
            const remaining = chunk_count - start_index;

            const base_chunk_depth: Depth = @intCast(ST.chunk_depth);
            const chunk_depth: Depth = chunkDepth(Depth, base_chunk_depth, is_list_view);

            const nodes = try self.allocator.alloc(Node.Id, remaining);
            defer self.allocator.free(nodes);

            try self.data.root.getNodesAtDepth(self.pool, chunk_depth, start_index, nodes);

            for (nodes, 0..) |node, offset| {
                const chunk_idx = start_index + offset;
                const gindex = elementChildGindex(chunk_idx * items_per_chunk);
                const gop = try self.data.children_nodes.getOrPut(gindex);
                if (!gop.found_existing) {
                    gop.value_ptr.* = node;
                }
            }

            self.data.prefetched_chunk_count = chunk_count;
        }

        pub const Element: type = if (isBasicType(ST.Element))
            ST.Element.Type
        else
            TreeView(ST.Element);

        inline fn elementChildGindex(index: usize) Gindex {
            const base_chunk_depth: Depth = @intCast(ST.chunk_depth);
            return Gindex.fromDepth(
                // Lists mix in their length at one extra depth level.
                chunkDepth(Depth, base_chunk_depth, is_list_view),
                if (comptime isBasicType(ST.Element)) blk: {
                    const per_chunk = itemsPerChunk(ST.Element);
                    break :blk index / per_chunk;
                } else index,
            );
        }

        inline fn listLengthGindex() Gindex {
            comptime {
                if (!is_list_view) {
                    @compileError("listLengthGindex can only be used with List types");
                }
            }
            return Gindex.fromDepth(1, 1);
        }

        fn updateListLength(self: *Self, new_length: usize) !void {
            comptime {
                if (!is_list_view) {
                    @compileError("updateListLength can only be used with List types");
                }
            }
            if (new_length > ST.limit) {
                return error.LengthOverLimit;
            }

            const length_node = try self.pool.createLeafFromUint(@intCast(new_length), false);
            var inserted = false;
            defer if (!inserted) self.pool.unref(length_node); // only drop if we never attach it to the tree

            const gindex = listLengthGindex();
            const opt_old = try self.data.children_nodes.fetchPut(gindex, length_node);
            inserted = true;
            if (opt_old) |old_entry| {
                // Multiple local mutations before commit() leave our cloned nodes with
                // refcount 0. Only free those; tree-owned nodes keep a positive refcount.
                if (old_entry.value.getState(self.pool).getRefCount() == 0) {
                    self.pool.unref(old_entry.value);
                }
            }

            try self.data.changed.put(gindex, {});
            self.data.list_length = @intCast(new_length);

            if (comptime is_basic_array_view) {
                const chunk_count = chunkCount(new_length, ST.Element);
                // If the list shrank, discard prefetched chunks that fall beyond the new length
                if (self.data.prefetched_chunk_count > chunk_count) {
                    self.data.prefetched_chunk_count = chunk_count;
                }
            }
        }

        /// Get an element by index. If the element is a basic type, returns the value directly.
        /// Caller borrows a copy of the value so there is no need to deinit it.
        pub fn getElement(self: *Self, index: usize) !Element {
            if (ST.kind != .vector and ST.kind != .list) {
                @compileError("getElement can only be used with vector or list types");
            }
            const child_gindex = elementChildGindex(index);
            if (comptime isBasicType(ST.Element)) {
                var value: ST.Element.Type = undefined;
                const child_node = try self.getChildNode(child_gindex);
                try ST.Element.tree.toValuePacked(child_node, self.pool, index, &value);
                return value;
            } else {
                const child_data = try self.getChildData(child_gindex);

                // TODO only update changed if the subview is mutable
                try self.data.changed.put(child_gindex, {});

                return TreeView(ST.Element){
                    .allocator = self.allocator,
                    .pool = self.pool,
                    .data = child_data,
                };
            }
        }

        /// Allocate and return all elements as an array. Only available for basic array types (Vector/List of basic types).
        /// Returns a slice that must be freed by the caller.
        pub fn getAllElementsAlloc(self: *Self, allocator: std.mem.Allocator) ![]ST.Element.Type {
            if (!comptime is_basic_array_view) {
                @compileError("getAllElementsAlloc can only be used with Vector/List of basic types");
            }

            const length = if (comptime is_list_view) try self.getLength() else ST.length;
            const values = try allocator.alloc(ST.Element.Type, length);
            errdefer allocator.free(values);

            return try self.getAllElements(values);
        }

        /// Populate a caller-provided buffer with all elements and return it.
        pub fn getAllElements(self: *Self, values: []ST.Element.Type) ![]ST.Element.Type {
            if (!comptime is_basic_array_view) {
                @compileError("getAllElements can only be used with Vector/List of basic types");
            }

            const length = if (comptime is_list_view) try self.getLength() else ST.length;
            if (values.len != length) {
                return error.InvalidSize;
            }

            if (length == 0) {
                return values;
            }

            const items_per_chunk = itemsPerChunk(ST.Element);
            const len_full_chunks = length / items_per_chunk;
            const remainder = length % items_per_chunk;
            const chunk_count = len_full_chunks + @intFromBool(remainder != 0);

            if (chunk_count > 0) {
                try self.ensureChunkPrefetch(chunk_count, items_per_chunk);
            }

            try self.populateElementsFromChunks(values, items_per_chunk, len_full_chunks, remainder);
            return values;
        }

        fn populateElementsFromChunks(
            self: *Self,
            dest: []ST.Element.Type,
            items_per_chunk: usize,
            len_full_chunks: usize,
            remainder: usize,
        ) !void {
            for (0..len_full_chunks) |chunk_idx| {
                const chunk_gindex = elementChildGindex(chunk_idx * items_per_chunk);
                const leaf_node = try self.getChildNode(chunk_gindex);

                for (0..items_per_chunk) |i| {
                    try ST.Element.tree.toValuePacked(
                        leaf_node,
                        self.pool,
                        i,
                        &dest[chunk_idx * items_per_chunk + i],
                    );
                }
            }

            if (remainder > 0) {
                const chunk_gindex = elementChildGindex(len_full_chunks * items_per_chunk);
                const leaf_node = try self.getChildNode(chunk_gindex);

                for (0..remainder) |i| {
                    try ST.Element.tree.toValuePacked(
                        leaf_node,
                        self.pool,
                        i,
                        &dest[len_full_chunks * items_per_chunk + i],
                    );
                }
            }
        }

        /// Set an element by index. If the element is a basic type, pass the value directly.
        /// If the element is a complex type, pass a TreeView of the corresponding type.
        /// The caller transfers ownership of the `value` TreeView to this parent view.
        /// The existing TreeView, if any, will be deinited by this function.
        pub fn setElement(self: *Self, index: usize, value: Element) !void {
            if (ST.kind != .vector and ST.kind != .list) {
                @compileError("setElement can only be used with vector or list types");
            }
            const child_gindex = elementChildGindex(index);
            try self.data.changed.put(child_gindex, {});
            if (comptime isBasicType(ST.Element)) {
                const child_node = try self.getChildNode(child_gindex);
                const opt_old_node = try self.data.children_nodes.fetchPut(
                    child_gindex,
                    try ST.Element.tree.fromValuePacked(
                        child_node,
                        self.pool,
                        index,
                        &value,
                    ),
                );
                if (opt_old_node) |old_node| {
                    // Multiple set() calls before commit() leave our previous temp nodes cached with refcount 0.
                    // Tree-owned nodes already have a refcount, so skip unref in that case.
                    if (old_node.value.getState(self.pool).getRefCount() == 0) {
                        self.pool.unref(old_node.value);
                    }
                }
            } else {
                const opt_old_data = try self.data.children_data.fetchPut(
                    child_gindex,
                    value.data,
                );
                if (opt_old_data) |old_data_value| {
                    var data: *Data = @constCast(&old_data_value.value);
                    data.deinit(self.pool);
                }
            }
        }

        /// Append an element to the end of the list, updating the cached length.
        pub fn push(self: *Self, value: Element) !void {
            if (comptime !is_list_view) {
                @compileError("push can only be used with List types");
            }

            const length = try self.getLength();
            if (length >= ST.limit) {
                return error.LengthOverLimit;
            }

            try self.setElement(length, value);
            try self.updateListLength(length + 1);
        }

        /// Return a new view containing all elements up to and including `index`.
        /// Only available for list views.
        pub fn sliceTo(self: *Self, index: usize) !Self {
            comptime {
                if (!is_list_view) {
                    @compileError("sliceTo can only be used with List types");
                }
            }

            try self.commit();

            const length = try self.getLength();
            if (length == 0 or index >= length - 1) {
                return try Self.init(self.allocator, self.pool, self.data.root);
            }

            const new_length = index + 1;
            if (new_length > ST.limit) {
                return error.LengthOverLimit;
            }
            const base_chunk_depth: Depth = @intCast(ST.chunk_depth);
            const chunk_depth: Depth = chunkDepth(Depth, base_chunk_depth, is_list_view);

            var new_root: Node.Id = undefined;
            var new_root_owned = false;
            errdefer if (new_root_owned) self.pool.unref(new_root);
            if (comptime is_basic_array_view) {
                const items_per_chunk = itemsPerChunk(ST.Element);
                const chunk_index = index / items_per_chunk;
                const chunk_offset = index % items_per_chunk;
                const chunk_node = try Node.Id.getNodeAtDepth(self.data.root, self.pool, chunk_depth, chunk_index);

                var chunk_bytes = chunk_node.getRoot(self.pool).*;
                const keep_bytes = (chunk_offset + 1) * ST.Element.fixed_size;
                if (keep_bytes < BYTES_PER_CHUNK) {
                    @memset(chunk_bytes[keep_bytes..], 0);
                }

                const truncated_chunk_node = try self.pool.createLeaf(&chunk_bytes, false);
                var chunk_inserted = false;
                // Drop the temporary truncated chunk leaf unless we swap it into the tree
                defer if (!chunk_inserted) self.pool.unref(truncated_chunk_node);

                new_root = try Node.Id.setNodeAtDepth(self.data.root, self.pool, chunk_depth, chunk_index, truncated_chunk_node);
                chunk_inserted = true;
                new_root_owned = true;

                new_root = try Node.Id.truncateAfterIndex(new_root, self.pool, chunk_depth, chunk_index);
            } else {
                new_root = try Node.Id.truncateAfterIndex(self.data.root, self.pool, chunk_depth, index);
                new_root_owned = true;
            }

            const length_node = try self.pool.createLeafFromUint(@intCast(new_length), false);
            var length_inserted = false;
            // Drop the temporary length leaf unless we attach it to the new branch
            defer if (!length_inserted) self.pool.unref(length_node);
            new_root = try Node.Id.setNode(new_root, self.pool, listLengthGindex(), length_node);
            length_inserted = true;

            const new_data = try Data.init(self.allocator, self.pool, new_root);
            new_root_owned = false;
            return Self{
                .allocator = self.allocator,
                .pool = self.pool,
                .data = new_data,
            };
        }

        /// Return a new view containing all elements from `index` to the end.
        /// Only available for list views of composite types.
        /// Basic list slicing would require per-element extraction and repacking since multiple elements are tightly packed within each chunk.
        pub fn sliceFrom(self: *Self, index: usize) !Self {
            comptime {
                if (!is_list_view or is_basic_array_view) {
                    @compileError("sliceFrom can only be used with List of composite types");
                }
            }

            try self.commit();

            const length = try self.getLength();
            if (index == 0) {
                return try Self.init(self.allocator, self.pool, self.data.root);
            }

            const base_chunk_depth: Depth = @intCast(ST.chunk_depth);
            const chunk_depth: Depth = chunkDepth(Depth, base_chunk_depth, is_list_view);
            const target_length = if (index >= length) 0 else length - index;

            var chunk_root_inserted = target_length == 0;
            var chunk_root: ?Node.Id = null;
            // Only release the chunk root when (a) we actually built a temporary subtree and
            // (b) the new branch never adopted it.
            defer if (chunk_root != null and !chunk_root_inserted) self.pool.unref(chunk_root.?);

            if (target_length == 0) {
                chunk_root = @enumFromInt(base_chunk_depth);
            } else {
                const nodes = try self.allocator.alloc(Node.Id, target_length);
                defer self.allocator.free(nodes);
                try self.data.root.getNodesAtDepth(self.pool, chunk_depth, index, nodes);

                chunk_root = try Node.fillWithContents(self.pool, nodes, base_chunk_depth, false);
            }

            const length_node = try self.pool.createLeafFromUint(@intCast(target_length), false);
            var length_inserted = false;
            // Drop the temporary length leaf unless we attach it to the new branch
            defer if (!length_inserted) self.pool.unref(length_node);

            const new_root = try self.pool.createBranch(chunk_root.?, length_node, false);
            length_inserted = true;
            chunk_root_inserted = true;

            errdefer self.pool.unref(new_root);
            const new_data = try Data.init(self.allocator, self.pool, new_root);
            return Self{
                .allocator = self.allocator,
                .pool = self.pool,
                .data = new_data,
            };
        }

        pub fn Field(comptime field_name: []const u8) type {
            const ChildST = ST.getFieldType(field_name);
            if (comptime isBasicType(ChildST)) {
                return ChildST.Type;
            } else {
                return TreeView(ChildST);
            }
        }

        /// Get a field by name. If the field is a basic type, returns the value directly.
        /// Caller borrows a copy of the value so there is no need to deinit it.
        pub fn getField(self: *Self, comptime field_name: []const u8) !Field(field_name) {
            if (comptime ST.kind != .container) {
                @compileError("getField can only be used with container types");
            }
            const field_index = comptime ST.getFieldIndex(field_name);
            const ChildST = ST.getFieldType(field_name);
            const child_gindex = Gindex.fromDepth(ST.chunk_depth, field_index);
            if (comptime isBasicType(ChildST)) {
                var value: ChildST.Type = undefined;
                const child_node = try self.getChildNode(child_gindex);
                try ChildST.tree.toValue(child_node, self.pool, &value);
                return value;
            } else {
                const child_data = try self.getChildData(child_gindex);

                // TODO only update changed if the subview is mutable
                try self.data.changed.put(child_gindex, {});

                return TreeView(ChildST){
                    .allocator = self.allocator,
                    .pool = self.pool,
                    .data = child_data,
                };
            }
        }

        /// Set a field by name. If the field is a basic type, pass the value directly.
        /// If the field is a complex type, pass a TreeView of the corresponding type.
        /// The caller transfers ownership of the `value` TreeView to this parent view.
        /// The existing TreeView, if any, will be deinited by this function.
        pub fn setField(self: *Self, comptime field_name: []const u8, value: Field(field_name)) !void {
            if (comptime ST.kind != .container) {
                @compileError("setField can only be used with container types");
            }
            const field_index = comptime ST.getFieldIndex(field_name);
            const ChildST = ST.getFieldType(field_name);
            const child_gindex = Gindex.fromDepth(ST.chunk_depth, field_index);
            try self.data.changed.put(child_gindex, {});
            if (comptime isBasicType(ChildST)) {
                const opt_old_node = try self.data.children_nodes.fetchPut(
                    child_gindex,
                    try ChildST.tree.fromValue(
                        self.pool,
                        &value,
                    ),
                );
                if (opt_old_node) |old_node| {
                    // Multiple set() calls before commit() leave our previous temp nodes cached with refcount 0.
                    // Tree-owned nodes already have a refcount, so skip unref in that case.
                    if (old_node.value.getState(self.pool).getRefCount() == 0) {
                        self.pool.unref(old_node.value);
                    }
                }
            } else {
                const opt_old_data = try self.data.children_data.fetchPut(
                    child_gindex,
                    value.data,
                );
                if (opt_old_data) |old_data_value| {
                    var data: *Data = @constCast(&old_data_value.value);
                    data.deinit(self.pool);
                }
            }
        }
    };
}
