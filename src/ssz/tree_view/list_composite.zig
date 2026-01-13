const std = @import("std");
const Allocator = std.mem.Allocator;
const hashing = @import("hashing");
const Depth = hashing.Depth;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const isBasicType = @import("../type/type_kind.zig").isBasicType;
const isFixedType = @import("../type/type_kind.zig").isFixedType;

const type_root = @import("../type/root.zig");
const chunkDepth = type_root.chunkDepth;

const tree_view_root = @import("root.zig");
const BaseTreeView = tree_view_root.BaseTreeView;
const CompositeChunks = @import("chunks.zig").CompositeChunks;

/// A specialized tree view for SSZ list types with composite element types.
/// Each element occupies its own subtree.
pub fn ListCompositeTreeView(comptime ST: type) type {
    comptime {
        if (ST.kind != .list) {
            @compileError("ListCompositeTreeView can only be used with List types");
        }
        if (!@hasDecl(ST, "Element") or isBasicType(ST.Element)) {
            @compileError("ListCompositeTreeView can only be used with List of composite element types");
        }
    }

    return struct {
        base_view: BaseTreeView,

        pub const SszType = ST;
        pub const Element = ST.Element.TreeView;

        const Self = @This();

        const base_chunk_depth: Depth = @intCast(ST.chunk_depth);
        const chunk_depth: Depth = chunkDepth(Depth, base_chunk_depth, ST);
        const Chunks = CompositeChunks(ST, chunk_depth);

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !Self {
            return Self{
                .base_view = try BaseTreeView.init(allocator, pool, root),
            };
        }

        pub fn clone(self: *Self, opts: BaseTreeView.CloneOpts) !Self {
            return Self{ .base_view = try self.base_view.clone(opts) };
        }

        pub fn deinit(self: *Self) void {
            self.base_view.deinit();
        }

        pub fn commit(self: *Self) !void {
            try self.base_view.commit();
        }

        pub fn clearCache(self: *Self) void {
            self.base_view.clearCache();
        }

        /// Return the root hash of the tree.
        /// The returned array is owned by the internal pool and must not be modified.
        pub fn hashTreeRoot(self: *Self) !*const [32]u8 {
            return try self.base_view.hashTreeRoot();
        }

        pub fn length(self: *Self) !usize {
            const length_node = try self.base_view.getChildNode(@enumFromInt(3));
            const length_chunk = length_node.getRoot(self.base_view.pool);
            return std.mem.readInt(usize, length_chunk[0..@sizeOf(usize)], .little);
        }

        pub fn setLength(self: *Self, new_length: usize) !void {
            try self.updateListLength(new_length);
        }

        pub fn getRoot(self: *Self, index: usize) !*const [32]u8 {
            const field_node = try self.base_view.getChildNode(Gindex.fromDepth(chunk_depth, index));
            return field_node.getRoot(self.base_view.pool);
        }

        pub fn get(self: *Self, index: usize) !Element {
            const list_length = try self.length();
            if (index >= list_length) return error.IndexOutOfBounds;
            return try Chunks.get(&self.base_view, index);
        }

        pub fn getValue(self: *Self, allocator: Allocator, index: usize) !ST.Element.Type {
            var child_view = try self.get(index);
            var out = ST.Element.default_value;
            try child_view.toValue(allocator, &out);
            return out;
        }

        pub fn getReadonly(self: *Self, index: usize) !Element {
            // TODO: Implement read-only access after other PRs land.
            _ = self;
            _ = index;
            return error.NotImplemented;
        }

        pub fn set(self: *Self, index: usize, value: Element) !void {
            const list_length = try self.length();
            if (index >= list_length) return error.IndexOutOfBounds;
            try Chunks.set(&self.base_view, index, value);
        }

        pub fn setValue(self: *Self, index: usize, value: *const ST.Element.Type) !void {
            const root = try ST.Element.tree.fromValue(self.base_view.pool, value);
            errdefer self.base_view.pool.unref(root);
            const child_view = try ST.Element.TreeView.init(
                self.base_view.allocator,
                self.base_view.pool,
                root,
            );
            try self.set(index, child_view);
        }

        pub fn getAllReadonly(self: *Self, allocator: Allocator) ![]Element {
            // TODO: Implement bulk read-only access after other PRs land.
            _ = self;
            _ = allocator;
            return error.NotImplemented;
        }

        /// Get all element values in a single traversal.
        ///
        /// WARNING: Returns all committed changes. If there are any pending changes,
        /// commit them beforehand.
        ///
        /// Caller owns the returned slice and must free it with the same allocator.
        pub fn getAllReadonlyValues(self: *Self, allocator: Allocator) ![]ST.Element.Type {
            const list_length = try self.length();
            return try Chunks.getAllValues(&self.base_view, allocator, list_length);
        }

        /// Appends an element to the end of the list.
        ///
        /// Ownership of the `value` TreeView is transferred to the list view.
        /// The caller must not deinitialize or otherwise use `value` after calling this method,
        /// as it is now owned by the list.
        pub fn push(self: *Self, value: Element) !void {
            const list_length = try self.length();
            if (list_length >= ST.limit) {
                return error.LengthOverLimit;
            }

            try self.updateListLength(list_length + 1);
            try self.set(list_length, value);
        }

        pub fn pushValue(self: *Self, value: *const ST.Element.Type) !void {
            const root = try ST.Element.tree.fromValue(self.base_view.pool, value);
            errdefer self.base_view.pool.unref(root);
            var child_view = try ST.Element.TreeView.init(
                self.base_view.allocator,
                self.base_view.pool,
                root,
            );
            errdefer child_view.deinit();
            try self.push(child_view);
        }

        /// Return a new view containing all elements up to and including `index`.
        /// The caller **must** call `deinit()` on the returned view to avoid memory leaks.
        pub fn sliceTo(self: *Self, index: usize) !Self {
            try self.commit();

            const list_length = try self.length();
            if (list_length == 0 or index >= list_length - 1) {
                return try Self.init(self.base_view.allocator, self.base_view.pool, self.base_view.data.root);
            }

            const new_length = index + 1;
            if (new_length > ST.limit) {
                return error.LengthOverLimit;
            }

            var chunk_root: ?Node.Id = try Node.Id.truncateAfterIndex(self.base_view.data.root, self.base_view.pool, chunk_depth, index);
            defer if (chunk_root) |id| self.base_view.pool.unref(id);

            var length_node: ?Node.Id = try self.base_view.pool.createLeafFromUint(@intCast(new_length));
            defer if (length_node) |id| self.base_view.pool.unref(id);
            const root_with_length = try Node.Id.setNode(chunk_root.?, self.base_view.pool, @enumFromInt(3), length_node.?);
            errdefer self.base_view.pool.unref(root_with_length);
            length_node = null;
            chunk_root = null;

            return try Self.init(self.base_view.allocator, self.base_view.pool, root_with_length);
        }

        /// Return a new view containing all elements from `index` to the end.
        /// The returned view must be deinitialized by the caller using `deinit()` to avoid memory leaks.
        pub fn sliceFrom(self: *Self, index: usize) !Self {
            try self.commit();

            const list_length = try self.length();
            if (index == 0) {
                return try Self.init(self.base_view.allocator, self.base_view.pool, self.base_view.data.root);
            }

            const target_length = if (index >= list_length) 0 else list_length - index;

            var chunk_root: ?Node.Id = null;
            defer if (chunk_root) |id| self.base_view.pool.unref(id);

            if (target_length == 0) {
                chunk_root = @enumFromInt(base_chunk_depth);
            } else {
                const nodes = try self.base_view.allocator.alloc(Node.Id, target_length);
                defer self.base_view.allocator.free(nodes);
                try self.base_view.data.root.getNodesAtDepth(self.base_view.pool, chunk_depth, index, nodes);

                chunk_root = try Node.fillWithContents(self.base_view.pool, nodes, base_chunk_depth);
            }

            var length_node: ?Node.Id = try self.base_view.pool.createLeafFromUint(@intCast(target_length));
            defer if (length_node) |id| self.base_view.pool.unref(id);

            const new_root = try self.base_view.pool.createBranch(chunk_root.?, length_node.?);
            errdefer self.base_view.pool.unref(new_root);
            length_node = null;
            chunk_root = null;

            return try Self.init(self.base_view.allocator, self.base_view.pool, new_root);
        }

        fn updateListLength(self: *Self, new_length: usize) !void {
            if (new_length > ST.limit) {
                return error.LengthOverLimit;
            }
            const length_node = try self.base_view.pool.createLeafFromUint(@intCast(new_length));
            errdefer self.base_view.pool.unref(length_node);
            try self.base_view.setChildNode(@enumFromInt(3), length_node);
        }

        /// Serialize the tree view into a provided buffer.
        /// Returns the number of bytes written.
        pub fn serializeIntoBytes(self: *Self, out: []u8) !usize {
            try self.commit();
            return try ST.tree.serializeIntoBytes(self.base_view.data.root, self.base_view.pool, out);
        }

        /// Get the serialized size of this tree view.
        pub fn serializedSize(self: *Self) !usize {
            try self.commit();
            return try ST.tree.serializedSize(self.base_view.data.root, self.base_view.pool);
        }

        pub fn fromValue(allocator: Allocator, pool: *Node.Pool, value: *const ST.Type) !Self {
            const root = try ST.tree.fromValue(pool, value);
            return try Self.init(allocator, pool, root);
        }

        pub fn toValue(self: *Self, allocator: Allocator, out: *ST.Type) !void {
            try self.commit();
            try ST.tree.toValue(allocator, self.base_view.data.root, self.base_view.pool, out);
        }

        /// Get a read-only iterator over the elements of the list.
        /// This only iterates over committed elements.
        /// It is up to the caller to ensure that the iterator doesn't run past the end of the list.
        pub inline fn iteratorReadonly(self: *const Self, start_index: usize) ReadonlyIterator {
            return ReadonlyIterator.init(self, start_index);
        }

        /// Get a read-only iterator over the elements of the list.
        /// This only iterates over committed elements.
        /// It is up to the caller to ensure that the iterator doesn't run past the end of the list.
        pub const ReadonlyIterator = struct {
            tree_view: *const Self,
            depth_iterator: Node.DepthIterator,

            pub fn init(tree_view: *const Self, start_index: usize) ReadonlyIterator {
                return .{
                    .tree_view = tree_view,
                    .depth_iterator = Node.DepthIterator.init(
                        tree_view.base_view.pool,
                        tree_view.base_view.data.root,
                        ST.chunk_depth + 1,
                        start_index,
                    ),
                };
            }

            /// Return the next element of the iterator as a TreeView.
            /// Caller owns the returned TreeView.
            pub fn next(self: *ReadonlyIterator) !Element {
                const node = try self.depth_iterator.next();
                return try ST.Element.TreeView.init(
                    self.tree_view.base_view.allocator,
                    self.tree_view.base_view.pool,
                    node,
                );
            }

            /// Return the next element of the iterator as a value.
            /// Caller owns the returned value.
            pub fn nextValue(self: *ReadonlyIterator, allocator: Allocator) !ST.Element.Type {
                const node = try self.depth_iterator.next();
                var out = ST.Element.default_value;
                if (comptime isFixedType(ST.Element)) {
                    try ST.Element.tree.toValue(node, self.tree_view.base_view.pool, &out);
                } else {
                    try ST.Element.tree.toValue(allocator, node, self.tree_view.base_view.pool, &out);
                }

                return out;
            }
        };
    };
}

const FixedContainerType = @import("../type/container.zig").FixedContainerType;
const VariableContainerType = @import("../type/container.zig").VariableContainerType;
const UintType = @import("../type/uint.zig").UintType;
const ByteVectorType = @import("../type/byte_vector.zig").ByteVectorType;
const ByteListType = @import("../type/byte_list.zig").ByteListType;
const FixedListType = @import("../type/list.zig").FixedListType;
const VariableListType = @import("../type/list.zig").VariableListType;
const FixedVectorType = @import("../type/vector.zig").FixedVectorType;

const Checkpoint = FixedContainerType(struct {
    epoch: UintType(64),
    root: ByteVectorType(32),
});

test "TreeView composite list sliceTo truncates elements" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    const ListType = FixedListType(Checkpoint, 16);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);

    const checkpoints = [_]Checkpoint.Type{
        .{ .epoch = 1, .root = [_]u8{1} ** 32 },
        .{ .epoch = 2, .root = [_]u8{2} ** 32 },
        .{ .epoch = 3, .root = [_]u8{3} ** 32 },
        .{ .epoch = 4, .root = [_]u8{4} ** 32 },
    };
    try list.appendSlice(allocator, &checkpoints);

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    var sliced = try view.sliceTo(1);
    defer sliced.deinit();

    try std.testing.expectEqual(@as(usize, 2), try sliced.length());

    var roundtrip: ListType.Type = .empty;
    defer roundtrip.deinit(allocator);
    try ListType.tree.toValue(allocator, sliced.base_view.data.root, &pool, &roundtrip);

    try std.testing.expectEqual(@as(usize, 2), roundtrip.items.len);
    try std.testing.expectEqual(checkpoints[0].epoch, roundtrip.items[0].epoch);
    try std.testing.expectEqual(checkpoints[1].epoch, roundtrip.items[1].epoch);
}

test "TreeView composite list sliceFrom returns suffix" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    const ListType = FixedListType(Checkpoint, 16);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);

    const checkpoints = [_]Checkpoint.Type{
        .{ .epoch = 5, .root = [_]u8{5} ** 32 },
        .{ .epoch = 6, .root = [_]u8{6} ** 32 },
        .{ .epoch = 7, .root = [_]u8{7} ** 32 },
        .{ .epoch = 8, .root = [_]u8{8} ** 32 },
    };
    try list.appendSlice(allocator, &checkpoints);

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    var suffix = try view.sliceFrom(2);
    defer suffix.deinit();

    try std.testing.expectEqual(@as(usize, 2), try suffix.length());

    var roundtrip: ListType.Type = .empty;
    defer roundtrip.deinit(allocator);
    try ListType.tree.toValue(allocator, suffix.base_view.data.root, &pool, &roundtrip);

    try std.testing.expectEqual(@as(usize, 2), roundtrip.items.len);
    try std.testing.expectEqual(checkpoints[2].epoch, roundtrip.items[0].epoch);
    try std.testing.expectEqual(checkpoints[3].epoch, roundtrip.items[1].epoch);

    var empty_suffix = try view.sliceFrom(10);
    defer empty_suffix.deinit();
    try std.testing.expectEqual(@as(usize, 0), try empty_suffix.length());
}

// Refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/listComposite/tree.test.ts#L209-L229
test "TreeView composite list sliceFrom handles boundary conditions" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const ListType = FixedListType(Checkpoint, 1024);
    const list_length = 16;

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);

    var values: [list_length]Checkpoint.Type = undefined;
    for (&values, 0..) |*value, idx| {
        value.* = Checkpoint.Type{
            .epoch = @intCast(idx),
            .root = [_]u8{@as(u8, @intCast(idx))} ** 32,
        };
    }
    try list.appendSlice(allocator, values[0..list_length]);

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    const min_index: i32 = -@as(i32, list_length) - 1;
    const max_index: i32 = @as(i32, list_length) + 1;
    const signed_len = std.math.cast(i32, list_length) orelse @panic("slice length exceeds i32 range");

    var i = min_index;
    while (i < max_index) : (i += 1) {
        var start_i32 = i;
        if (start_i32 < 0) {
            start_i32 = signed_len + start_i32;
        }
        start_i32 = std.math.clamp(start_i32, 0, signed_len);
        const start_index: usize = @intCast(start_i32);
        const expected_len = list_length - start_index;

        {
            var sliced = try view.sliceFrom(start_index);
            defer sliced.deinit();

            try std.testing.expectEqual(expected_len, try sliced.length());

            var actual: ListType.Type = .empty;
            defer actual.deinit(allocator);
            try ListType.tree.toValue(allocator, sliced.base_view.data.root, &pool, &actual);

            var expected: ListType.Type = .empty;
            defer expected.deinit(allocator);
            try expected.appendSlice(allocator, values[start_index..list_length]);

            try std.testing.expectEqual(expected_len, actual.items.len);
            try std.testing.expectEqual(expected_len, expected.items.len);

            for (expected.items, 0..) |item, idx_item| {
                try std.testing.expectEqual(item.epoch, actual.items[idx_item].epoch);
                try std.testing.expectEqualSlices(u8, &item.root, &actual.items[idx_item].root);
            }

            const expected_node = try ListType.tree.fromValue(&pool, &expected);
            var expected_root: [32]u8 = expected_node.getRoot(&pool).*;
            defer pool.unref(expected_node);

            const actual_root = try sliced.hashTreeRoot();
            try std.testing.expectEqualSlices(u8, &expected_root, actual_root);
        }
    }
}

test "TreeView composite list push appends element" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    const ListType = FixedListType(Checkpoint, 8);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);

    const first = Checkpoint.Type{ .epoch = 9, .root = [_]u8{9} ** 32 };
    try list.append(allocator, first);

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    const next_checkpoint = Checkpoint.Type{ .epoch = 10, .root = [_]u8{10} ** 32 };
    const next_node = try Checkpoint.tree.fromValue(&pool, &next_checkpoint);
    var element_view = try Checkpoint.TreeView.init(allocator, &pool, next_node);
    var transferred = false;
    defer if (!transferred) element_view.deinit();

    try view.push(element_view);
    transferred = true;

    try std.testing.expectEqual(@as(usize, 2), try view.length());

    try view.commit();

    var roundtrip: ListType.Type = .empty;
    defer roundtrip.deinit(allocator);
    try ListType.tree.toValue(allocator, view.base_view.data.root, &pool, &roundtrip);

    try std.testing.expectEqual(@as(usize, 2), roundtrip.items.len);
    try std.testing.expectEqual(next_checkpoint.epoch, roundtrip.items[1].epoch);
}

test "TreeView composite list clone isolates updates" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const ListType = FixedListType(Checkpoint, 16);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.append(allocator, .{ .epoch = 1, .root = [_]u8{1} ** 32 });

    const root = try ListType.tree.fromValue(&pool, &list);
    var v1 = try ListType.TreeView.init(allocator, &pool, root);
    defer v1.deinit();

    var v2 = try v1.clone(.{});
    defer v2.deinit();

    const replacement = Checkpoint.Type{ .epoch = 9, .root = [_]u8{9} ** 32 };
    const replacement_root = try Checkpoint.tree.fromValue(&pool, &replacement);
    var replacement_view: ?Checkpoint.TreeView = try Checkpoint.TreeView.init(allocator, &pool, replacement_root);
    defer if (replacement_view) |*v| v.deinit();
    try v2.set(0, replacement_view.?);
    replacement_view = null;
    try v2.commit();

    const v1_e0 = try v1.get(0);
    var v1_e0_value: Checkpoint.Type = undefined;
    try Checkpoint.tree.toValue(v1_e0.base_view.data.root, &pool, &v1_e0_value);

    const v2_e0 = try v2.get(0);
    var v2_e0_value: Checkpoint.Type = undefined;
    try Checkpoint.tree.toValue(v2_e0.base_view.data.root, &pool, &v2_e0_value);

    try std.testing.expectEqual(@as(u64, 1), v1_e0_value.epoch);
    try std.testing.expectEqual(@as(u64, 9), v2_e0_value.epoch);
}

test "TreeView composite list clone reads committed state" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const ListType = FixedListType(Checkpoint, 16);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.append(allocator, .{ .epoch = 1, .root = [_]u8{1} ** 32 });

    const root = try ListType.tree.fromValue(&pool, &list);
    var v1 = try ListType.TreeView.init(allocator, &pool, root);
    defer v1.deinit();

    const replacement = Checkpoint.Type{ .epoch = 9, .root = [_]u8{9} ** 32 };
    const replacement_root = try Checkpoint.tree.fromValue(&pool, &replacement);
    var replacement_view: ?Checkpoint.TreeView = try Checkpoint.TreeView.init(allocator, &pool, replacement_root);
    defer if (replacement_view) |*v| v.deinit();
    try v1.set(0, replacement_view.?);
    replacement_view = null;
    try v1.commit();

    var v2 = try v1.clone(.{});
    defer v2.deinit();

    const v2_e0 = try v2.get(0);
    var v2_e0_value: Checkpoint.Type = undefined;
    try Checkpoint.tree.toValue(v2_e0.base_view.data.root, &pool, &v2_e0_value);

    try std.testing.expectEqual(@as(u64, 9), v2_e0_value.epoch);
}

test "TreeView composite list clone drops uncommitted changes" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const ListType = FixedListType(Checkpoint, 16);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.append(allocator, .{ .epoch = 1, .root = [_]u8{1} ** 32 });

    const root = try ListType.tree.fromValue(&pool, &list);
    var v = try ListType.TreeView.init(allocator, &pool, root);
    defer v.deinit();

    const replacement = Checkpoint.Type{ .epoch = 9, .root = [_]u8{9} ** 32 };
    const replacement_root = try Checkpoint.tree.fromValue(&pool, &replacement);
    var replacement_view: ?Checkpoint.TreeView = try Checkpoint.TreeView.init(allocator, &pool, replacement_root);
    defer if (replacement_view) |*v0| v0.deinit();
    try v.set(0, replacement_view.?);
    replacement_view = null;

    const v_e0_before = try v.get(0);
    var v_e0_before_value: Checkpoint.Type = undefined;
    try Checkpoint.tree.toValue(v_e0_before.base_view.data.root, &pool, &v_e0_before_value);
    try std.testing.expectEqual(@as(u64, 9), v_e0_before_value.epoch);

    var dropped = try v.clone(.{});
    defer dropped.deinit();

    const v_e0_after = try v.get(0);
    var v_e0_after_value: Checkpoint.Type = undefined;
    try Checkpoint.tree.toValue(v_e0_after.base_view.data.root, &pool, &v_e0_after_value);

    const dropped_e0 = try dropped.get(0);
    var dropped_e0_value: Checkpoint.Type = undefined;
    try Checkpoint.tree.toValue(dropped_e0.base_view.data.root, &pool, &dropped_e0_value);

    try std.testing.expectEqual(@as(u64, 1), v_e0_after_value.epoch);
    try std.testing.expectEqual(@as(u64, 1), dropped_e0_value.epoch);
}

test "TreeView composite list clone(true) does not transfer cache" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    const ListType = FixedListType(Checkpoint, 16);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.append(allocator, .{ .epoch = 1, .root = [_]u8{1} ** 32 });

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    _ = try view.get(0);
    try view.commit();

    try std.testing.expect(view.base_view.data.children_data.count() > 0);

    var cloned_no_cache = try view.clone(.{ .transfer_cache = false });
    defer cloned_no_cache.deinit();

    try std.testing.expect(view.base_view.data.children_data.count() > 0);
    try std.testing.expectEqual(@as(usize, 0), cloned_no_cache.base_view.data.children_data.count());
}

test "TreeView composite list clone(false) transfers cache and clears source" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    const ListType = FixedListType(Checkpoint, 16);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.append(allocator, .{ .epoch = 1, .root = [_]u8{1} ** 32 });

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    _ = try view.get(0);
    try view.commit();

    try std.testing.expect(view.base_view.data.children_data.count() > 0);

    var cloned = try view.clone(.{});
    defer cloned.deinit();

    try std.testing.expectEqual(@as(usize, 0), view.base_view.data.children_data.count());
    try std.testing.expect(cloned.base_view.data.children_data.count() > 0);
}

test "TreeView list of list commits inner length updates" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const Uint32 = UintType(32);
    const Bytes = ByteListType(32);
    const Numbers = FixedListType(Uint32, 8);
    const Vec2 = FixedVectorType(Uint32, 2);
    const InnerElement = VariableContainerType(struct {
        id: Uint32,
        payload: Bytes,
        numbers: Numbers,
        vec: Vec2,
    });
    const InnerListType = VariableListType(InnerElement, 16);
    const OuterListType = VariableListType(InnerListType, 8);

    var outer_value: OuterListType.Type = .empty;
    defer OuterListType.deinit(allocator, &outer_value);
    const outer_root = try OuterListType.tree.fromValue(&pool, &outer_value);
    var outer_view = try OuterListType.TreeView.init(allocator, &pool, outer_root);
    defer outer_view.deinit();

    var inner_value: InnerListType.Type = .empty;
    defer InnerListType.deinit(allocator, &inner_value);
    const inner_root = try InnerListType.tree.fromValue(&pool, &inner_value);
    var inner_view = try InnerListType.TreeView.init(allocator, &pool, inner_root);
    var transferred = false;
    defer if (!transferred) inner_view.deinit();

    var e1_value: InnerElement.Type = InnerElement.default_value;
    defer InnerElement.deinit(allocator, &e1_value);
    const e1_root = try InnerElement.tree.fromValue(&pool, &e1_value);
    var e1_view: ?InnerElement.TreeView = try InnerElement.TreeView.init(allocator, &pool, e1_root);
    defer if (e1_view) |*view| view.deinit();
    const e1 = &e1_view.?;

    try e1.set("id", @as(u32, 11));

    // payload: ByteListType (list_basic) -> push + set + getAll + getAllInto
    var payload_value: Bytes.Type = Bytes.default_value;
    defer payload_value.deinit(allocator);
    const payload_root = try Bytes.tree.fromValue(&pool, &payload_value);
    var payload_view: ?Bytes.TreeView = try Bytes.TreeView.init(allocator, &pool, payload_root);
    defer if (payload_view) |*view| view.deinit();
    const payload = &payload_view.?;

    try payload.push(@as(u8, 0xAA));
    try payload.push(@as(u8, 0xAB));
    try payload.set(1, @as(u8, 0xAC));
    try payload.commit();
    {
        const all = try payload.getAll(allocator);
        defer allocator.free(all);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xAC }, all);

        var buf: [2]u8 = undefined;
        _ = try payload.getAllInto(buf[0..]);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xAC }, buf[0..]);
    }

    try e1.set("payload", payload_view.?);
    payload_view = null;

    var numbers_value: Numbers.Type = .empty;
    defer numbers_value.deinit(allocator);
    const numbers_root = try Numbers.tree.fromValue(&pool, &numbers_value);
    var numbers_view: ?Numbers.TreeView = try Numbers.TreeView.init(allocator, &pool, numbers_root);
    defer if (numbers_view) |*view| view.deinit();
    const numbers = &numbers_view.?;

    try numbers.push(@as(u32, 1));
    try numbers.push(@as(u32, 2));
    try numbers.set(0, @as(u32, 3));
    try numbers.commit();
    {
        const all = try numbers.getAll(allocator);
        defer allocator.free(all);
        try std.testing.expectEqual(@as(usize, 2), all.len);
        try std.testing.expectEqual(@as(u32, 3), all[0]);
        try std.testing.expectEqual(@as(u32, 2), all[1]);

        var buf: [2]u32 = undefined;
        _ = try numbers.getAllInto(buf[0..]);
        try std.testing.expectEqual(@as(u32, 3), buf[0]);
        try std.testing.expectEqual(@as(u32, 2), buf[1]);
    }

    try e1.set("numbers", numbers_view.?);
    numbers_view = null;

    var vec_value: Vec2.Type = [_]u32{ 0, 0 };
    const vec_root = try Vec2.tree.fromValue(&pool, &vec_value);
    var vec_view: ?Vec2.TreeView = try Vec2.TreeView.init(allocator, &pool, vec_root);
    defer if (vec_view) |*view| view.deinit();
    const vec = &vec_view.?;

    try vec.set(0, @as(u32, 9));
    try vec.set(1, @as(u32, 10));
    try vec.commit();
    {
        const all = try vec.getAll(allocator);
        defer allocator.free(all);
        try std.testing.expectEqual(@as(usize, 2), all.len);
        try std.testing.expectEqual(@as(u32, 9), all[0]);
        try std.testing.expectEqual(@as(u32, 10), all[1]);

        var buf: [2]u32 = undefined;
        _ = try vec.getAllInto(buf[0..]);
        try std.testing.expectEqual(@as(u32, 9), buf[0]);
        try std.testing.expectEqual(@as(u32, 10), buf[1]);
    }

    try e1.set("vec", vec_view.?);
    vec_view = null;

    try inner_view.push(e1_view.?);
    e1_view = null;

    var e2_value: InnerElement.Type = InnerElement.default_value;
    defer InnerElement.deinit(allocator, &e2_value);
    const e2_root = try InnerElement.tree.fromValue(&pool, &e2_value);
    var e2_view: ?InnerElement.TreeView = try InnerElement.TreeView.init(allocator, &pool, e2_root);
    defer if (e2_view) |*view| view.deinit();
    const e2 = &e2_view.?;

    try e2.set("id", @as(u32, 22));

    var e2_payload_value: Bytes.Type = Bytes.default_value;
    defer e2_payload_value.deinit(allocator);
    const e2_payload_root = try Bytes.tree.fromValue(&pool, &e2_payload_value);
    var e2_payload_view: ?Bytes.TreeView = try Bytes.TreeView.init(allocator, &pool, e2_payload_root);
    defer if (e2_payload_view) |*view| view.deinit();
    const e2_payload = &e2_payload_view.?;
    try e2_payload.push(@as(u8, 0xBB));
    try e2.set("payload", e2_payload_view.?);
    e2_payload_view = null;

    try inner_view.push(e2_view.?);
    e2_view = null;

    {
        var e3_value: InnerElement.Type = InnerElement.default_value;
        defer InnerElement.deinit(allocator, &e3_value);
        const e3_root = try InnerElement.tree.fromValue(&pool, &e3_value);
        var e3_view: ?InnerElement.TreeView = try InnerElement.TreeView.init(allocator, &pool, e3_root);
        defer if (e3_view) |*view| view.deinit();
        const e3 = &e3_view.?;
        try e3.set("id", @as(u32, 33));
        try inner_view.set(1, e3_view.?);
        e3_view = null;
    }

    try std.testing.expectEqual(@as(usize, 2), try inner_view.length());

    try outer_view.push(inner_view);
    transferred = true;

    try outer_view.commit();

    // Roundtrip and verify nested lengths and values.
    var roundtrip: OuterListType.Type = .empty;
    defer OuterListType.deinit(allocator, &roundtrip);
    try OuterListType.tree.toValue(allocator, outer_view.base_view.data.root, &pool, &roundtrip);

    try std.testing.expectEqual(@as(usize, 1), roundtrip.items.len);
    try std.testing.expectEqual(@as(usize, 2), roundtrip.items[0].items.len);
    try std.testing.expectEqual(@as(u32, 11), roundtrip.items[0].items[0].id);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xAC }, roundtrip.items[0].items[0].payload.items);
    try std.testing.expectEqual(@as(usize, 2), roundtrip.items[0].items[0].numbers.items.len);
    try std.testing.expectEqual(@as(u32, 3), roundtrip.items[0].items[0].numbers.items[0]);
    try std.testing.expectEqual(@as(u32, 2), roundtrip.items[0].items[0].numbers.items[1]);
    try std.testing.expectEqual(@as(u32, 9), roundtrip.items[0].items[0].vec[0]);
    try std.testing.expectEqual(@as(u32, 10), roundtrip.items[0].items[0].vec[1]);

    try std.testing.expectEqual(@as(u32, 33), roundtrip.items[0].items[1].id);
}

// Refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/listComposite/tree.test.ts#L182-L207
test "TreeView composite list sliceTo matches incremental snapshots" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 2048);
    defer pool.deinit();

    const ListType = FixedListType(Checkpoint, 1024);
    const total_values: usize = 16;

    var values: [total_values]Checkpoint.Type = undefined;
    for (&values, 0..) |*value, idx| {
        value.* = Checkpoint.Type{
            .epoch = @intCast(idx + 1),
            .root = [_]u8{@as(u8, @intCast(idx + 1))} ** 32,
        };
    }

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, values[0..]);

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    try view.commit();

    var i: usize = 0;
    while (i < total_values) : (i += 1) {
        var sliced = try view.sliceTo(i);
        defer sliced.deinit();

        const expected_len = i + 1;
        try std.testing.expectEqual(expected_len, try sliced.length());

        var actual: ListType.Type = .empty;
        defer actual.deinit(allocator);
        try ListType.tree.toValue(allocator, sliced.base_view.data.root, &pool, &actual);

        var expected: ListType.Type = .empty;
        defer expected.deinit(allocator);
        try expected.appendSlice(allocator, values[0..expected_len]);

        try std.testing.expectEqual(expected_len, actual.items.len);
        for (expected.items, 0..) |item, idx_item| {
            try std.testing.expectEqual(item.epoch, actual.items[idx_item].epoch);
            try std.testing.expectEqualSlices(u8, &item.root, &actual.items[idx_item].root);
        }

        var expected_root: [32]u8 = undefined;
        try ListType.hashTreeRoot(allocator, &expected, &expected_root);

        const actual_root = try sliced.hashTreeRoot();
        try std.testing.expectEqualSlices(u8, &expected_root, actual_root);

        const serialized_len = ListType.serializedSize(&expected);
        const expected_bytes = try allocator.alloc(u8, serialized_len);
        defer allocator.free(expected_bytes);
        const actual_bytes = try allocator.alloc(u8, serialized_len);
        defer allocator.free(actual_bytes);

        _ = ListType.serializeIntoBytes(&expected, expected_bytes);
        _ = ListType.serializeIntoBytes(&actual, actual_bytes);

        try std.testing.expectEqualSlices(u8, expected_bytes, actual_bytes);
    }
}

// Refer to https://github.com/ChainSafe/ssz/blob/f5ed0b457333749b5c3f49fa5eafa096a725f033/packages/ssz/test/unit/byType/listComposite/tree.test.ts
test "ListCompositeTreeView - serialize (ByteVector32 list)" {
    const allocator = std.testing.allocator;

    const Root32 = ByteVectorType(32);
    const ListRootsType = FixedListType(Root32, 128);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const TestCase = struct {
        id: []const u8,
        values: []const [32]u8,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty",
            .values = &[_][32]u8{},
            // 0x96559674a79656e540871e1f39c9b91e152aa8cddb71493e754827c4cc809d57
            .expected_root = [_]u8{ 0x96, 0x55, 0x96, 0x74, 0xa7, 0x96, 0x56, 0xe5, 0x40, 0x87, 0x1e, 0x1f, 0x39, 0xc9, 0xb9, 0x1e, 0x15, 0x2a, 0xa8, 0xcd, 0xdb, 0x71, 0x49, 0x3e, 0x75, 0x48, 0x27, 0xc4, 0xcc, 0x80, 0x9d, 0x57 },
        },
        .{
            .id = "2 roots",
            .values = &[_][32]u8{
                [_]u8{0xdd} ** 32,
                [_]u8{0xee} ** 32,
            },
            // 0x0cb947377e177f774719ead8d210af9c6461f41baf5b4082f86a3911454831b8
            .expected_root = [_]u8{ 0x0c, 0xb9, 0x47, 0x37, 0x7e, 0x17, 0x7f, 0x77, 0x47, 0x19, 0xea, 0xd8, 0xd2, 0x10, 0xaf, 0x9c, 0x64, 0x61, 0xf4, 0x1b, 0xaf, 0x5b, 0x40, 0x82, 0xf8, 0x6a, 0x39, 0x11, 0x45, 0x48, 0x31, 0xb8 },
        },
    };

    for (test_cases) |tc| {
        var value: ListRootsType.Type = ListRootsType.default_value;
        defer value.deinit(allocator);
        for (tc.values) |v| {
            try value.append(allocator, v);
        }

        const value_serialized = try allocator.alloc(u8, ListRootsType.serializedSize(&value));
        defer allocator.free(value_serialized);
        _ = ListRootsType.serializeIntoBytes(&value, value_serialized);

        const tree_node = try ListRootsType.tree.fromValue(&pool, &value);
        var view = try ListRootsType.TreeView.init(allocator, &pool, tree_node);
        defer view.deinit();

        const view_size = try view.serializedSize();
        const view_serialized = try allocator.alloc(u8, view_size);
        defer allocator.free(view_serialized);
        const written = try view.serializeIntoBytes(view_serialized);
        try std.testing.expectEqual(view_size, written);

        try std.testing.expectEqualSlices(u8, value_serialized, view_serialized);
        try std.testing.expectEqual(value_serialized.len, view_size);

        const hash_root = try view.hashTreeRoot();
        try std.testing.expectEqualSlices(u8, &tc.expected_root, hash_root);
    }
}

test "ListCompositeTreeView - serialize (Container list)" {
    const allocator = std.testing.allocator;

    const Uint64 = UintType(64);
    const TestContainer = FixedContainerType(struct {
        a: UintType(64),
        b: UintType(64),
    });
    _ = Uint64;
    const ListContainerType = FixedListType(TestContainer, 128);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const TestCase = struct {
        id: []const u8,
        values: []const TestContainer.Type,
        expected_serialized: []const u8,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty",
            .values = &[_]TestContainer.Type{},
            .expected_serialized = &[_]u8{},
            // 0x96559674a79656e540871e1f39c9b91e152aa8cddb71493e754827c4cc809d57
            .expected_root = [_]u8{ 0x96, 0x55, 0x96, 0x74, 0xa7, 0x96, 0x56, 0xe5, 0x40, 0x87, 0x1e, 0x1f, 0x39, 0xc9, 0xb9, 0x1e, 0x15, 0x2a, 0xa8, 0xcd, 0xdb, 0x71, 0x49, 0x3e, 0x75, 0x48, 0x27, 0xc4, 0xcc, 0x80, 0x9d, 0x57 },
        },
        .{
            .id = "2 values",
            .values = &[_]TestContainer.Type{
                .{ .a = 0, .b = 0 },
                .{ .a = 123456, .b = 654321 },
            },
            // 0x0000000000000000000000000000000040e2010000000000f1fb090000000000
            .expected_serialized = &[_]u8{
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x40, 0xe2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1, 0xfb, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
            },
            // 0x8ff94c10d39ffa84aa937e2a077239c2742cb425a2a161744a3e9876eb3c7210
            .expected_root = [_]u8{ 0x8f, 0xf9, 0x4c, 0x10, 0xd3, 0x9f, 0xfa, 0x84, 0xaa, 0x93, 0x7e, 0x2a, 0x07, 0x72, 0x39, 0xc2, 0x74, 0x2c, 0xb4, 0x25, 0xa2, 0xa1, 0x61, 0x74, 0x4a, 0x3e, 0x98, 0x76, 0xeb, 0x3c, 0x72, 0x10 },
        },
    };

    for (test_cases) |tc| {
        var value: ListContainerType.Type = ListContainerType.default_value;
        defer value.deinit(allocator);

        for (tc.values) |v| {
            try value.append(allocator, v);
        }

        const value_serialized = try allocator.alloc(u8, ListContainerType.serializedSize(&value));
        defer allocator.free(value_serialized);
        _ = ListContainerType.serializeIntoBytes(&value, value_serialized);

        const tree_node = try ListContainerType.tree.fromValue(&pool, &value);
        var view = try ListContainerType.TreeView.init(allocator, &pool, tree_node);
        defer view.deinit();

        const view_size = try view.serializedSize();
        const view_serialized = try allocator.alloc(u8, view_size);
        defer allocator.free(view_serialized);
        const written = try view.serializeIntoBytes(view_serialized);
        try std.testing.expectEqual(view_size, written);

        try std.testing.expectEqualSlices(u8, tc.expected_serialized, view_serialized);
        try std.testing.expectEqualSlices(u8, value_serialized, view_serialized);

        const hash_root = try view.hashTreeRoot();
        try std.testing.expectEqualSlices(u8, &tc.expected_root, hash_root);
    }
}

test "ListCompositeTreeView - push and serialize" {
    const allocator = std.testing.allocator;

    const Root32 = ByteVectorType(32);
    const ListRootsType = FixedListType(Root32, 128);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    var value: ListRootsType.Type = ListRootsType.default_value;
    defer value.deinit(allocator);

    const tree_node = try ListRootsType.tree.fromValue(&pool, &value);
    var view = try ListRootsType.TreeView.init(allocator, &pool, tree_node);
    defer view.deinit();

    const val1 = [_]u8{0xdd} ** 32;
    const node1 = try Root32.tree.fromValue(&pool, &val1);
    const elem_view1 = try Root32.TreeView.init(allocator, &pool, node1);
    try view.push(elem_view1);

    const val2 = [_]u8{0xee} ** 32;
    const node2 = try Root32.tree.fromValue(&pool, &val2);
    const elem_view2 = try Root32.TreeView.init(allocator, &pool, node2);
    try view.push(elem_view2);

    const len = try view.length();
    try std.testing.expectEqual(@as(usize, 2), len);

    const size = try view.serializedSize();
    const serialized = try allocator.alloc(u8, size);
    defer allocator.free(serialized);
    const written = try view.serializeIntoBytes(serialized);
    try std.testing.expectEqual(size, written);

    try std.testing.expectEqual(@as(usize, 64), serialized.len);
    try std.testing.expectEqualSlices(u8, &val1, serialized[0..32]);
    try std.testing.expectEqualSlices(u8, &val2, serialized[32..64]);

    const expected_root = [_]u8{ 0x0c, 0xb9, 0x47, 0x37, 0x7e, 0x17, 0x7f, 0x77, 0x47, 0x19, 0xea, 0xd8, 0xd2, 0x10, 0xaf, 0x9c, 0x64, 0x61, 0xf4, 0x1b, 0xaf, 0x5b, 0x40, 0x82, 0xf8, 0x6a, 0x39, 0x11, 0x45, 0x48, 0x31, 0xb8 };
    const hash_root = try view.hashTreeRoot();
    try std.testing.expectEqualSlices(u8, &expected_root, hash_root);
}

test "ListCompositeTreeView - ReadonlyIterator" {
    const allocator = std.testing.allocator;

    const Root32 = ByteVectorType(32);
    const ListRootsType = FixedListType(Root32, 128);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    var value: ListRootsType.Type = ListRootsType.default_value;
    defer value.deinit(allocator);

    const data = [_][32]u8{
        [_]u8{0xaa} ** 32,
        [_]u8{0xbb} ** 32,
        [_]u8{0xcc} ** 32,
        [_]u8{0xdd} ** 32,
        [_]u8{0xee} ** 32,
        [_]u8{0xff} ** 32,
    };
    for (data) |d| {
        try value.append(allocator, d);
    }

    const tree_node = try ListRootsType.tree.fromValue(&pool, &value);
    var view = try ListRootsType.TreeView.init(allocator, &pool, tree_node);
    defer view.deinit();

    var iter = view.iteratorReadonly(0);

    for (data) |expected| {
        var elem = try iter.next();
        defer elem.deinit();
        var elem_value: [32]u8 = undefined;

        try Root32.tree.toValue(elem.base_view.data.root, &pool, &elem_value);
        try std.testing.expectEqualSlices(u8, &expected, &elem_value);
    }

    iter = view.iteratorReadonly(0);
    for (data) |expected| {
        const elem_value = try iter.nextValue(undefined);

        try std.testing.expectEqualSlices(u8, &expected, &elem_value);
    }
}
