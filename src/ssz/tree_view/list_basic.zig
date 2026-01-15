const std = @import("std");
const Allocator = std.mem.Allocator;
const hashing = @import("hashing");
const Depth = hashing.Depth;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const isBasicType = @import("../type/type_kind.zig").isBasicType;

const type_root = @import("../type/root.zig");
const BYTES_PER_CHUNK = type_root.BYTES_PER_CHUNK;
const itemsPerChunk = type_root.itemsPerChunk;
const chunkDepth = type_root.chunkDepth;

const BasicPackedChunks = @import("chunks.zig").BasicPackedChunks;
const assertTreeViewType = @import("utils/assert.zig").assertTreeViewType;
const CloneOpts = @import("utils/clone_opts.zig").CloneOpts;

/// A specialized tree view for SSZ list types with basic element types.
/// Elements are packed into chunks (multiple elements per leaf node).
pub fn ListBasicTreeView(comptime ST: type) type {
    comptime {
        if (ST.kind != .list) {
            @compileError("ListBasicTreeView can only be used with List types");
        }
        if (!@hasDecl(ST, "Element") or !isBasicType(ST.Element)) {
            @compileError("ListBasicTreeView can only be used with List of basic element types");
        }
    }

    const TreeView = struct {
        allocator: Allocator,
        chunks: Chunks,
        // the original length, before any modifications
        _orig_len: usize,
        // the current length, may differ from original until committed
        _len: usize,

        pub const SszType = ST;
        pub const Element = ST.Element.Type;

        const Self = @This();

        const base_chunk_depth: Depth = @intCast(ST.chunk_depth);
        const chunk_depth: Depth = chunkDepth(Depth, base_chunk_depth, ST);
        const items_per_chunk: usize = itemsPerChunk(ST.Element);
        const Chunks = BasicPackedChunks(ST, chunk_depth, items_per_chunk);

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !*Self {
            const ptr = try allocator.create(Self);
            errdefer allocator.destroy(ptr);

            try Chunks.init(&ptr.chunks, allocator, pool, root);
            ptr.allocator = allocator;
            ptr._orig_len = try ptr.chunks.getLength();
            ptr._len = ptr._orig_len;
            return ptr;
        }

        pub fn clone(self: *Self, opts: CloneOpts) !*Self {
            const ptr = try self.allocator.create(Self);
            errdefer self.allocator.destroy(ptr);

            try self.chunks.clone(opts, &ptr.chunks);
            ptr.allocator = self.allocator;
            ptr._orig_len = self._orig_len;
            ptr._len = self._len;
            return ptr;
        }

        pub fn deinit(self: *Self) void {
            self.chunks.deinit();
            self.allocator.destroy(self);
        }

        pub fn commit(self: *Self) !void {
            try self.updateListLength();
            try self.chunks.commit();
            self._orig_len = self._len;
        }

        pub fn clearCache(self: *Self) void {
            self.chunks.clearCache();
        }

        pub fn hashTreeRoot(self: *Self, out: *[32]u8) !void {
            try self.commit();
            out.* = self.chunks.root.getRoot(self.chunks.pool).*;
        }

        pub fn getRoot(self: *const Self) Node.Id {
            return self.chunks.root;
        }

        pub fn length(self: *const Self) !usize {
            return self._len;
        }

        pub fn get(self: *Self, index: usize) !Element {
            const list_length = try self.length();
            if (index >= list_length) return error.IndexOutOfBounds;
            return self.chunks.get(index);
        }

        pub fn set(self: *Self, index: usize, value: Element) !void {
            const list_length = try self.length();
            if (index >= list_length) return error.IndexOutOfBounds;
            try self.chunks.set(index, value);
        }

        /// Caller must free the returned slice.
        pub fn getAll(self: *Self) ![]Element {
            const list_length = try self.length();
            return try self.chunks.getAll(self.allocator, list_length);
        }

        pub fn getAllInto(self: *Self, values: []Element) ![]Element {
            const list_length = try self.length();
            return self.chunks.getAllInto(list_length, values);
        }

        pub fn push(self: *Self, value: Element) !void {
            const list_length = try self.length();
            if (list_length >= ST.limit) {
                return error.LengthOverLimit;
            }
            self._len += 1;
            try self.set(list_length, value);
        }

        /// Return a new view containing all elements up to and including `index`.
        /// Caller must call `deinit()` on the returned view to avoid memory leaks.
        pub fn sliceTo(self: *Self, index: usize) !*Self {
            try self.commit();

            const list_length = try self.length();
            if (list_length == 0 or index >= list_length - 1) {
                return try Self.init(self.allocator, self.chunks.pool, self.chunks.root);
            }

            const new_length = index + 1;
            if (new_length > ST.limit) {
                return error.LengthOverLimit;
            }

            const chunk_index = index / items_per_chunk;
            const chunk_offset = index % items_per_chunk;
            const chunk_node = try Node.Id.getNodeAtDepth(self.chunks.root, self.chunks.pool, chunk_depth, chunk_index);

            var chunk_bytes = chunk_node.getRoot(self.chunks.pool).*;
            const keep_bytes = (chunk_offset + 1) * ST.Element.fixed_size;
            if (keep_bytes < BYTES_PER_CHUNK) {
                @memset(chunk_bytes[keep_bytes..], 0);
            }

            var truncated_chunk_node: ?Node.Id = try self.chunks.pool.createLeaf(&chunk_bytes);
            defer if (truncated_chunk_node) |id| self.chunks.pool.unref(id);
            var updated: ?Node.Id = try Node.Id.setNodeAtDepth(
                self.chunks.root,
                self.chunks.pool,
                chunk_depth,
                chunk_index,
                truncated_chunk_node.?,
            );
            defer if (updated) |id| self.chunks.pool.unref(id);
            truncated_chunk_node = null;

            var new_root: ?Node.Id = try Node.Id.truncateAfterIndex(updated.?, self.chunks.pool, chunk_depth, chunk_index);
            defer if (new_root) |id| self.chunks.pool.unref(id);
            updated = null;

            var length_node: ?Node.Id = try self.chunks.pool.createLeafFromUint(@intCast(new_length));
            defer if (length_node) |id| self.chunks.pool.unref(id);
            const root_with_length = try Node.Id.setNode(new_root.?, self.chunks.pool, @enumFromInt(3), length_node.?);
            errdefer self.chunks.pool.unref(root_with_length);

            length_node = null;
            new_root = null;

            return try Self.init(self.allocator, self.chunks.pool, root_with_length);
        }

        /// Serialize the tree view into a provided buffer.
        /// Returns the number of bytes written.
        pub fn serializeIntoBytes(self: *Self, out: []u8) !usize {
            try self.commit();
            return try ST.tree.serializeIntoBytes(self.chunks.root, self.chunks.pool, out);
        }

        /// Get the serialized size of this tree view.
        pub fn serializedSize(self: *Self) !usize {
            try self.commit();
            return try ST.tree.serializedSize(self.chunks.root, self.chunks.pool);
        }

        fn updateListLength(self: *Self) !void {
            if (self._len == self._orig_len) {
                return;
            }

            std.debug.assert(self._len <= ST.limit);
            try self.chunks.setLength(self._len);
        }
    };

    assertTreeViewType(TreeView);
    return TreeView;
}

const UintType = @import("../type/uint.zig").UintType;
const FixedListType = @import("../type/list.zig").FixedListType;
test "TreeView list element roundtrip" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 16);

    const base_values = [_]u32{ 5, 15, 25, 35, 45 };

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &base_values);

    var expected_list: ListType.Type = .empty;
    defer expected_list.deinit(allocator);
    try expected_list.appendSlice(allocator, &base_values);

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    try std.testing.expectEqual(@as(u32, 5), try view.get(0));
    try std.testing.expectEqual(@as(u32, 45), try view.get(4));

    try view.set(2, 99);
    try view.set(4, 123);

    try view.commit();

    expected_list.items[2] = 99;
    expected_list.items[4] = 123;

    var expected_root: [32]u8 = undefined;
    try ListType.hashTreeRoot(allocator, &expected_list, &expected_root);

    var actual_root: [32]u8 = undefined;
    try view.hashTreeRoot(&actual_root);

    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);

    var roundtrip: ListType.Type = .empty;
    defer roundtrip.deinit(allocator);
    try ListType.tree.toValue(allocator, view.getRoot(), &pool, &roundtrip);
    try std.testing.expectEqual(roundtrip.items.len, expected_list.items.len);
    try std.testing.expectEqualSlices(u32, expected_list.items, roundtrip.items);
}

test "TreeView list push updates cached length" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 16);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &[_]u32{ 1, 2, 3 });

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    try std.testing.expectEqual(@as(usize, 3), try view.length());

    try view.push(@as(u32, 55));

    try std.testing.expectEqual(@as(usize, 4), try view.length());
    try std.testing.expectEqual(@as(u32, 55), try view.get(3));

    try view.commit();

    try std.testing.expectEqual(@as(usize, 4), try view.length());

    var expected: ListType.Type = .empty;
    defer expected.deinit(allocator);
    try expected.appendSlice(allocator, &[_]u32{ 1, 2, 3, 55 });

    var expected_root: [32]u8 = undefined;
    try ListType.hashTreeRoot(allocator, &expected, &expected_root);

    var actual_root: [32]u8 = undefined;
    try view.hashTreeRoot(&actual_root);

    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

test "TreeView list getAllAlloc handles zero length" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();

    const Uint8 = UintType(8);
    const ListType = FixedListType(Uint8, 4);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    const filled = try view.getAll();
    defer allocator.free(filled);

    try std.testing.expectEqual(@as(usize, 0), filled.len);
}

test "TreeView list getAllAlloc spans multiple chunks" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    const Uint16 = UintType(16);
    const ListType = FixedListType(Uint16, 64);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);

    var values: [20]u16 = undefined;
    for (&values, 0..) |*val, idx| {
        val.* = @intCast((idx * 3 + 1) % 17);
    }
    try list.appendSlice(allocator, &values);

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    const filled = try view.getAll();
    defer allocator.free(filled);

    try std.testing.expectEqualSlices(u16, values[0..], filled);
}

test "TreeView list push batches before commit" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 16);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &[_]u32{ 1, 2, 3, 4 });

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    try view.push(@as(u32, 5));
    try view.push(@as(u32, 6));
    try view.push(@as(u32, 7));
    try view.push(@as(u32, 8));
    try view.push(@as(u32, 9));

    try std.testing.expectEqual(@as(usize, 9), try view.length());
    try std.testing.expectEqual(@as(u32, 9), try view.get(8));

    try view.commit();

    try std.testing.expectEqual(@as(usize, 9), try view.length());
    try std.testing.expectEqual(@as(u32, 9), try view.get(8));

    var expected: ListType.Type = .empty;
    defer expected.deinit(allocator);
    try expected.appendSlice(allocator, &[_]u32{ 1, 2, 3, 4, 5, 6, 7, 8, 9 });

    var expected_root: [32]u8 = undefined;
    try ListType.hashTreeRoot(allocator, &expected, &expected_root);
    var actual_root: [32]u8 = undefined;
    try view.hashTreeRoot(&actual_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

test "TreeView list push across chunk boundary resets prefetch" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 32);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &[_]u32{ 0, 1, 2, 3, 4, 5, 6, 7 });

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    const initial = try view.getAll();
    defer allocator.free(initial);
    try std.testing.expectEqual(@as(usize, 8), initial.len);

    try view.push(@as(u32, 8));
    try view.push(@as(u32, 9));

    try std.testing.expectEqual(@as(usize, 10), try view.length());
    try std.testing.expectEqual(@as(u32, 9), try view.get(9));

    const filled = try view.getAll();
    defer allocator.free(filled);
    var expected: [10]u32 = [_]u32{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    try std.testing.expectEqualSlices(u32, expected[0..], filled);
}

test "TreeView list push enforces limit" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 2);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &[_]u32{ 1, 2 });

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    try std.testing.expectError(error.LengthOverLimit, view.push(@as(u32, 3)));
    try std.testing.expectEqual(@as(usize, 2), try view.length());
}

test "TreeView list basic clone isolates updates" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 16);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &[_]u32{ 1, 2, 3 });

    const root = try ListType.tree.fromValue(&pool, &list);
    var v1 = try ListType.TreeView.init(allocator, &pool, root);
    defer v1.deinit();

    var v2 = try v1.clone(.{});
    defer v2.deinit();

    try v2.set(1, @as(u32, 99));
    try v2.commit();

    try std.testing.expectEqual(@as(u32, 2), try v1.get(1));
    try std.testing.expectEqual(@as(u32, 99), try v2.get(1));
}

test "TreeView list basic clone reads committed state" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 16);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &[_]u32{ 1, 2, 3 });

    const root = try ListType.tree.fromValue(&pool, &list);
    var v1 = try ListType.TreeView.init(allocator, &pool, root);
    defer v1.deinit();

    try v1.set(0, @as(u32, 7));
    try v1.commit();

    var v2 = try v1.clone(.{});
    defer v2.deinit();

    try std.testing.expectEqual(@as(u32, 7), try v2.get(0));
}

test "TreeView list basic clone drops uncommitted changes" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 16);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &[_]u32{ 1, 2, 3 });

    const root = try ListType.tree.fromValue(&pool, &list);
    var v = try ListType.TreeView.init(allocator, &pool, root);
    defer v.deinit();

    try v.set(0, @as(u32, 7));
    try std.testing.expectEqual(@as(u32, 7), try v.get(0));

    var dropped = try v.clone(.{});
    defer dropped.deinit();

    try std.testing.expectEqual(@as(u32, 1), try v.get(0));
    try std.testing.expectEqual(@as(u32, 1), try dropped.get(0));
}

test "TreeView list basic clone(true) does not transfer cache" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 16);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &[_]u32{ 1, 2, 3 });

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    _ = try view.get(0);
    try std.testing.expect(view.chunks.children_nodes.count() > 0);

    var cloned_no_cache = try view.clone(.{ .transfer_cache = false });
    defer cloned_no_cache.deinit();

    try std.testing.expect(view.chunks.children_nodes.count() > 0);
    try std.testing.expectEqual(@as(usize, 0), cloned_no_cache.chunks.children_nodes.count());
}

test "TreeView list basic clone(false) transfers cache and clears source" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 16);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &[_]u32{ 1, 2, 3 });

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    _ = try view.get(0);
    try std.testing.expect(view.chunks.children_nodes.count() > 0);

    var cloned = try view.clone(.{});
    defer cloned.deinit();

    try std.testing.expectEqual(@as(usize, 0), view.chunks.children_nodes.count());
    try std.testing.expect(cloned.chunks.children_nodes.count() > 0);
}

// Refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/listBasic/tree.test.ts#L180-L203
test "TreeView basic list getAll reflects pushes" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const list_limit = 32;
    const Uint64 = UintType(64);
    const ListType = FixedListType(Uint64, list_limit);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    var expected: [list_limit]u64 = undefined;
    for (&expected, 0..) |*slot, idx| {
        slot.* = @intCast(idx);
    }

    for (expected, 0..) |value, idx| {
        try view.push(value);
        try std.testing.expectEqual(value, try view.get(idx));
    }

    try std.testing.expectError(error.LengthOverLimit, view.push(@intCast(list_limit)));

    for (expected, 0..) |value, idx| {
        try std.testing.expectEqual(value, try view.get(idx));
    }

    try view.commit();
    const filled = try view.getAll();
    defer allocator.free(filled);
    try std.testing.expectEqualSlices(u64, expected[0..], filled);
}

test "TreeView list sliceTo returns original when truncation unnecessary" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 16);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &[_]u32{ 4, 5, 6, 7 });

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    try view.commit();

    var sliced = try view.sliceTo(100);
    defer sliced.deinit();

    try std.testing.expectEqual(try view.length(), try sliced.length());

    var expected_root: [32]u8 = undefined;
    try ListType.hashTreeRoot(allocator, &list, &expected_root);

    var actual_root: [32]u8 = undefined;
    try sliced.hashTreeRoot(&actual_root);

    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

// Refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/listBasic/tree.test.ts#L219-L247
test "TreeView basic list sliceTo matches incremental snapshots" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 2048);
    defer pool.deinit();

    const Uint64 = UintType(64);
    const ListType = FixedListType(Uint64, 1024);
    const total_values: usize = 16;

    var base_values: [total_values]u64 = undefined;
    for (&base_values, 0..) |*value, idx| {
        value.* = @intCast(idx);
    }

    var empty_list: ListType.Type = .empty;
    defer empty_list.deinit(allocator);
    const root_node = try ListType.tree.fromValue(&pool, &empty_list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    for (base_values) |value| {
        try view.push(value);
    }
    try view.commit();

    for (base_values, 0..) |_, idx| {
        var sliced = try view.sliceTo(idx);
        defer sliced.deinit();

        const expected_len = idx + 1;
        try std.testing.expectEqual(expected_len, try sliced.length());

        var expected: ListType.Type = .empty;
        defer expected.deinit(allocator);
        try expected.appendSlice(allocator, base_values[0..expected_len]);

        var actual: ListType.Type = .empty;
        defer actual.deinit(allocator);
        try ListType.tree.toValue(allocator, sliced.getRoot(), &pool, &actual);

        try std.testing.expectEqual(expected_len, actual.items.len);
        try std.testing.expectEqualSlices(u64, expected.items, actual.items);

        const serialized_len = ListType.serializedSize(&expected);
        const expected_bytes = try allocator.alloc(u8, serialized_len);
        defer allocator.free(expected_bytes);
        const actual_bytes = try allocator.alloc(u8, serialized_len);
        defer allocator.free(actual_bytes);

        _ = ListType.serializeIntoBytes(&expected, expected_bytes);
        _ = ListType.serializeIntoBytes(&actual, actual_bytes);
        try std.testing.expectEqualSlices(u8, expected_bytes, actual_bytes);

        var expected_root: [32]u8 = undefined;
        try ListType.hashTreeRoot(allocator, &expected, &expected_root);

        var actual_root: [32]u8 = undefined;
        try sliced.hashTreeRoot(&actual_root);

        try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
    }
}

test "TreeView list sliceTo truncates tail elements" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 32);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);

    const values = [_]u32{ 10, 20, 30, 40, 50 };
    try list.appendSlice(allocator, &values);

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    try view.commit();

    var sliced = try view.sliceTo(2);
    defer sliced.deinit();

    try std.testing.expectEqual(@as(usize, 3), try sliced.length());

    const filled = try sliced.getAll();
    defer allocator.free(filled);

    try std.testing.expectEqualSlices(u32, values[0..3], filled);

    var expected: ListType.Type = .empty;
    defer expected.deinit(allocator);
    try expected.appendSlice(allocator, values[0..3]);

    var expected_root: [32]u8 = undefined;
    try ListType.hashTreeRoot(allocator, &expected, &expected_root);

    var actual_root: [32]u8 = undefined;
    try sliced.hashTreeRoot(&actual_root);

    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

// Tests ported from TypeScript ssz packages/ssz/test/unit/byType/listBasic/tree.test.ts
test "ListBasicTreeView - serialize (uint8 list)" {
    const allocator = std.testing.allocator;

    const Uint8 = UintType(8);
    const ListU8Type = FixedListType(Uint8, 128);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const TestCase = struct {
        id: []const u8,
        values: []const u8,
        expected_serialized: []const u8,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty",
            .values = &[_]u8{},
            .expected_serialized = &[_]u8{},
            .expected_root = [_]u8{ 0x28, 0xba, 0x18, 0x34, 0xa3, 0xa7, 0xb6, 0x57, 0x46, 0x0c, 0xe7, 0x9f, 0xa3, 0xa1, 0xd9, 0x09, 0xab, 0x88, 0x28, 0xfd, 0x55, 0x76, 0x59, 0xd4, 0xd0, 0x55, 0x4a, 0x9b, 0xdb, 0xc0, 0xec, 0x30 },
        },
        .{
            .id = "4 values",
            .values = &[_]u8{ 1, 2, 3, 4 },
            .expected_serialized = &[_]u8{ 0x01, 0x02, 0x03, 0x04 },
            .expected_root = [_]u8{ 0xba, 0xc5, 0x11, 0xd1, 0xf6, 0x41, 0xd6, 0xb8, 0x82, 0x32, 0x00, 0xbb, 0x4b, 0x3c, 0xce, 0xd3, 0xbd, 0x47, 0x20, 0x70, 0x1f, 0x18, 0x57, 0x1d, 0xff, 0x35, 0xa5, 0xd2, 0xa4, 0x01, 0x90, 0xfa },
        },
    };

    for (test_cases) |tc| {
        var value: ListU8Type.Type = ListU8Type.default_value;
        defer value.deinit(allocator);
        for (tc.values) |v| {
            try value.append(allocator, v);
        }

        const value_serialized = try allocator.alloc(u8, ListU8Type.serializedSize(&value));
        defer allocator.free(value_serialized);
        _ = ListU8Type.serializeIntoBytes(&value, value_serialized);

        const tree_node = try ListU8Type.tree.fromValue(&pool, &value);
        var view = try ListU8Type.TreeView.init(allocator, &pool, tree_node);
        defer view.deinit();

        const view_size = try view.serializedSize();
        const view_serialized = try allocator.alloc(u8, view_size);
        defer allocator.free(view_serialized);
        const written = try view.serializeIntoBytes(view_serialized);
        try std.testing.expectEqual(view_size, written);

        try std.testing.expectEqualSlices(u8, tc.expected_serialized, view_serialized);
        try std.testing.expectEqualSlices(u8, value_serialized, view_serialized);

        try std.testing.expectEqual(tc.expected_serialized.len, view_size);

        var hash_root: [32]u8 = undefined;
        try view.hashTreeRoot(&hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "ListBasicTreeView - serialize (uint64 list)" {
    const allocator = std.testing.allocator;

    const Uint64 = UintType(64);
    const ListU64Type = FixedListType(Uint64, 128);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const TestCase = struct {
        id: []const u8,
        values: []const u64,
        expected_serialized: []const u8,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty",
            .values = &[_]u64{},
            .expected_serialized = &[_]u8{},
            .expected_root = [_]u8{ 0x52, 0xe2, 0x64, 0x7a, 0xbc, 0x3d, 0x0c, 0x9d, 0x3b, 0xe0, 0x38, 0x7f, 0x3f, 0x0d, 0x92, 0x54, 0x22, 0xc7, 0xa4, 0xe9, 0x8c, 0xf4, 0x48, 0x90, 0x66, 0xf0, 0xf4, 0x32, 0x81, 0xa8, 0x99, 0xf3 },
        },
        .{
            .id = "4 values",
            .values = &[_]u64{ 100000, 200000, 300000, 400000 },
            // 0xa086010000000000400d030000000000e093040000000000801a060000000000
            .expected_serialized = &[_]u8{ 0xa0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x0d, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x93, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x1a, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00 },
            .expected_root = [_]u8{ 0xd1, 0xda, 0xef, 0x21, 0x55, 0x02, 0xb7, 0x74, 0x6e, 0x5f, 0xf3, 0xe8, 0x83, 0x3e, 0x39, 0x9c, 0xb2, 0x49, 0xab, 0x3f, 0x81, 0xd8, 0x24, 0xbe, 0x60, 0xe1, 0x74, 0xff, 0x56, 0x33, 0xc1, 0xbf },
        },
    };

    for (test_cases) |tc| {
        var value: ListU64Type.Type = ListU64Type.default_value;
        defer value.deinit(allocator);
        for (tc.values) |v| {
            try value.append(allocator, v);
        }

        const value_serialized = try allocator.alloc(u8, ListU64Type.serializedSize(&value));
        defer allocator.free(value_serialized);
        _ = ListU64Type.serializeIntoBytes(&value, value_serialized);

        const tree_node = try ListU64Type.tree.fromValue(&pool, &value);
        var view = try ListU64Type.TreeView.init(allocator, &pool, tree_node);
        defer view.deinit();

        const view_size = try view.serializedSize();
        const view_serialized = try allocator.alloc(u8, view_size);
        defer allocator.free(view_serialized);
        const written = try view.serializeIntoBytes(view_serialized);
        try std.testing.expectEqual(view_size, written);

        try std.testing.expectEqualSlices(u8, tc.expected_serialized, view_serialized);
        try std.testing.expectEqualSlices(u8, value_serialized, view_serialized);

        try std.testing.expectEqual(tc.expected_serialized.len, view_size);

        var hash_root: [32]u8 = undefined;
        try view.hashTreeRoot(&hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "ListBasicTreeView - push and serialize" {
    const allocator = std.testing.allocator;

    const Uint8 = UintType(8);
    const ListU8Type = FixedListType(Uint8, 128);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    var value: ListU8Type.Type = ListU8Type.default_value;
    defer value.deinit(allocator);

    const tree_node = try ListU8Type.tree.fromValue(&pool, &value);
    var view = try ListU8Type.TreeView.init(allocator, &pool, tree_node);
    defer view.deinit();

    try view.push(1);
    try view.push(2);
    try view.push(3);
    try view.push(4);

    const size = try view.serializedSize();
    const serialized = try allocator.alloc(u8, size);
    defer allocator.free(serialized);
    const written = try view.serializeIntoBytes(serialized);
    try std.testing.expectEqual(size, written);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, serialized);

    const len = try view.length();
    try std.testing.expectEqual(@as(usize, 4), len);

    var hash_root: [32]u8 = undefined;
    try view.hashTreeRoot(&hash_root);
    const expected_root = [_]u8{ 0xba, 0xc5, 0x11, 0xd1, 0xf6, 0x41, 0xd6, 0xb8, 0x82, 0x32, 0x00, 0xbb, 0x4b, 0x3c, 0xce, 0xd3, 0xbd, 0x47, 0x20, 0x70, 0x1f, 0x18, 0x57, 0x1d, 0xff, 0x35, 0xa5, 0xd2, 0xa4, 0x01, 0x90, 0xfa };
    try std.testing.expectEqualSlices(u8, &expected_root, &hash_root);
}

test "ListBasicTreeView - sliceTo and serialize" {
    const allocator = std.testing.allocator;

    const Uint8 = UintType(8);
    const ListU8Type = FixedListType(Uint8, 128);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    var value: ListU8Type.Type = ListU8Type.default_value;
    defer value.deinit(allocator);
    try value.append(allocator, 1);
    try value.append(allocator, 2);
    try value.append(allocator, 3);
    try value.append(allocator, 4);

    const tree_node = try ListU8Type.tree.fromValue(&pool, &value);
    var view = try ListU8Type.TreeView.init(allocator, &pool, tree_node);
    defer view.deinit();

    var sliced = try view.sliceTo(1);
    defer sliced.deinit();

    const size = try sliced.serializedSize();
    const serialized = try allocator.alloc(u8, size);
    defer allocator.free(serialized);
    const written = try sliced.serializeIntoBytes(serialized);
    try std.testing.expectEqual(size, written);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2 }, serialized);
    try std.testing.expectEqual(@as(usize, 2), try sliced.length());
}
