const std = @import("std");
const Allocator = std.mem.Allocator;
const hashing = @import("hashing");
const Depth = hashing.Depth;
const Node = @import("persistent_merkle_tree").Node;
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
        const Chunks = BasicPackedChunks(ST, chunk_depth, items_per_chunk, ST.opts.chunked_leaf);

        // Mirrors `chunks.zig`'s ChunkedLeaf bindings; only meaningful when
        // `ST.opts.chunked_leaf = true`. The empty-struct placeholder keeps
        // symbols valid in non-chunked_leaf instantiations.
        const ChunkedLeaf = if (ST.opts.chunked_leaf) @import("persistent_merkle_tree").ChunkedLeaf else struct {};
        const chunked_leaf_depth: Depth = if (ST.opts.chunked_leaf) chunk_depth - ChunkedLeaf.k_log2 else 0;

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

        pub fn hashTreeRootInto(self: *Self, out: *[32]u8) !void {
            try self.commit();
            out.* = self.chunks.state.root.getRoot(self.chunks.state.pool).*;
        }

        pub fn hashTreeRoot(self: *Self) !*const [32]u8 {
            try self.commit();
            return self.chunks.state.root.getRoot(self.chunks.state.pool);
        }

        pub fn fromValue(allocator: Allocator, pool: *Node.Pool, value: *const ST.Type) !*Self {
            const root = try ST.tree.fromValue(pool, value);
            errdefer pool.unref(root);
            return try Self.init(allocator, pool, root);
        }

        pub fn toValue(self: *Self, allocator: Allocator, out: *ST.Type) !void {
            try self.commit();
            try ST.tree.toValue(allocator, self.chunks.state.root, self.chunks.state.pool, out);
        }

        pub fn setLength(self: *Self, new_length: usize) !void {
            self._len = new_length;
        }

        pub fn iteratorReadonly(self: *const Self, start_index: usize) ReadonlyIterator {
            return ReadonlyIterator.init(self, start_index);
        }

        pub const ReadonlyIterator = struct {
            tree_view: *const Self,
            depth_iterator: Node.DepthIterator,
            elem_index: usize,
            // Non-chunked_leaf state: cached current chunk Node.Id; cleared
            // when we cross a chunk boundary so the next call fetches anew.
            elem_node: ?Node.Id,
            // Chunked_leaf state: cached chunks pointer of the current
            // ChunkedLeaf, plus a flag for the all-zero (sparse) case where
            // no payload exists. Cleared when we cross a chunked_leaf
            // boundary so the next call fetches the next ChunkedLeaf.
            current_chunks: ?*align(64) const [if (ST.opts.chunked_leaf) ChunkedLeaf.K else 1][32]u8,
            current_is_zero: bool,
            last_chunked_leaf_idx: ?usize,

            pub fn init(tree_view: *const Self, start_index: usize) ReadonlyIterator {
                if (comptime ST.opts.chunked_leaf) {
                    const start_chunk = start_index / items_per_chunk;
                    const start_chunked_leaf = start_chunk / ChunkedLeaf.K;
                    return .{
                        .tree_view = tree_view,
                        .depth_iterator = Node.DepthIterator.init(
                            tree_view.chunks.state.pool,
                            tree_view.chunks.state.root,
                            chunked_leaf_depth,
                            start_chunked_leaf,
                        ),
                        .elem_index = start_index,
                        .elem_node = null,
                        .current_chunks = null,
                        .current_is_zero = false,
                        .last_chunked_leaf_idx = null,
                    };
                } else {
                    return .{
                        .tree_view = tree_view,
                        .depth_iterator = Node.DepthIterator.init(
                            tree_view.chunks.state.pool,
                            tree_view.chunks.state.root,
                            ST.chunk_depth + 1,
                            ST.chunkIndex(start_index),
                        ),
                        .elem_index = start_index,
                        .elem_node = null,
                        .current_chunks = null,
                        .current_is_zero = false,
                        .last_chunked_leaf_idx = null,
                    };
                }
            }

            pub fn next(self: *ReadonlyIterator) !Element {
                const elem_index = self.elem_index;
                const pool = self.tree_view.chunks.state.pool;

                if (comptime ST.opts.chunked_leaf) {
                    const chunk_idx = elem_index / items_per_chunk;
                    const chunked_leaf_idx = chunk_idx / ChunkedLeaf.K;
                    const intra_chunk = chunk_idx % ChunkedLeaf.K;

                    // Fetch ChunkedLeaf if first call or just crossed a
                    // chunked_leaf boundary.
                    if (self.last_chunked_leaf_idx == null or self.last_chunked_leaf_idx.? != chunked_leaf_idx) {
                        const sid = try self.depth_iterator.next();
                        if (pool.nodes.items(.state)[@intFromEnum(sid)].kind() == .zero) {
                            self.current_chunks = null;
                            self.current_is_zero = true;
                        } else {
                            self.current_chunks = try sid.getChunkedLeafChunks(pool);
                            self.current_is_zero = false;
                        }
                        self.last_chunked_leaf_idx = chunked_leaf_idx;
                    }

                    var value: Element = undefined;
                    if (self.current_is_zero) {
                        value = std.mem.zeroes(Element);
                    } else {
                        ST.Element.tree.toValuePackedFromBytes(
                            &self.current_chunks.?[intra_chunk],
                            elem_index,
                            &value,
                        );
                    }
                    self.elem_index += 1;
                    return value;
                }

                const n = if (self.elem_node) |node|
                    node
                else
                    try self.depth_iterator.next();
                self.elem_node = n;
                var value: Element = undefined;
                try ST.Element.tree.toValuePacked(n, pool, elem_index, &value);
                self.elem_index += 1;
                if (self.elem_index % items_per_chunk == 0) {
                    self.elem_node = null;
                }
                return value;
            }
        };

        pub fn getRoot(self: *const Self) Node.Id {
            return self.chunks.state.root;
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

        /// Caller must free the returned slice with the same allocator.
        pub fn getAll(self: *Self, allocator: ?Allocator) ![]Element {
            const list_length = try self.length();
            return try self.chunks.getAll(allocator orelse self.allocator, list_length);
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
                return try Self.init(self.allocator, self.chunks.state.pool, self.chunks.state.root);
            }

            const new_length = index + 1;
            if (new_length > ST.limit) {
                return error.LengthOverLimit;
            }

            const pool = self.chunks.state.pool;
            const chunk_index = index / items_per_chunk;
            const chunk_offset = index % items_per_chunk;
            const keep_bytes = (chunk_offset + 1) * ST.Element.fixed_size;

            if (comptime ST.opts.chunked_leaf) {
                const chunked_leaf_idx = chunk_index / ChunkedLeaf.K;
                const intra_chunk: u16 = @intCast(chunk_index % ChunkedLeaf.K);

                const boundary_id = try Node.Id.getNodeAtDepth(self.chunks.state.root, pool, chunked_leaf_depth, chunked_leaf_idx);
                const boundary_kind = pool.nodes.items(.state)[@intFromEnum(boundary_id)].kind();

                // The truncate step zeroes chunked_leaves > chunked_leaf_idx
                // and uses ZeroHash[depthi + k_log2] sentinels (each "leaf"
                // at chunked_leaf_depth represents a depth-`k_log2` subtree).
                // The length leaf at gindex 3 ends up zeroed by the same
                // call and is re-installed via setNode below.
                //
                // Two paths for the boundary itself:
                //   1. `.chunked_leaf` — materialize a trimmed copy
                //      (chunks before `intra_chunk` preserved, byte-mask in
                //      chunk[intra_chunk], chunks after zeroed) and install
                //      it via setNodeAtDepth before truncating.
                //   2. `.zero` — boundary is already an all-zero subtree.
                //      The trimmed slice's elements at this position are
                //      all zero by construction (slice extends sparse list
                //      with zeros), so leaving the existing zero sentinel
                //      gives the same merkle root. Skip the materialization
                //      and feed root straight into truncate.
                const truncate_input: Node.Id = blk: {
                    if (boundary_kind == .zero) {
                        break :blk self.chunks.state.root;
                    }
                    if (boundary_kind != .chunked_leaf) {
                        return error.InvalidNode;
                    }

                    var trimmed_chunked_leaf: ?Node.Id = try pool.createChunkedLeafEmpty(intra_chunk + 1);
                    defer if (trimmed_chunked_leaf) |id| pool.unref(id);
                    {
                        const old_chunks = try boundary_id.getChunkedLeafChunks(pool);
                        const new_storage = try trimmed_chunked_leaf.?.getChunkedLeafPtr(pool);
                        @memcpy(new_storage.chunks[0 .. intra_chunk + 1], old_chunks[0 .. intra_chunk + 1]);
                        if (keep_bytes < BYTES_PER_CHUNK) {
                            @memset(new_storage.chunks[intra_chunk][keep_bytes..], 0);
                        }
                    }

                    const updated = try Node.Id.setNodeAtDepth(
                        self.chunks.state.root,
                        pool,
                        chunked_leaf_depth,
                        chunked_leaf_idx,
                        trimmed_chunked_leaf.?,
                    );
                    trimmed_chunked_leaf = null;
                    break :blk updated;
                };
                // `truncate_input` is either `self.chunks.state.root` (no
                // extra ref) or a new tree from `setNodeAtDepth` (rc=0
                // owned by us). In both cases passing to truncate consumes
                // logically — truncate produces `new_root` and the input
                // is unref'd via the defer below if it was owned.
                const owned_truncate_input = boundary_kind != .zero;

                var truncate_input_handle: ?Node.Id = if (owned_truncate_input) truncate_input else null;
                defer if (truncate_input_handle) |id| pool.unref(id);

                var new_root: ?Node.Id = try Node.Id.truncateAfterIndexWithLeafOffset(truncate_input, pool, chunked_leaf_depth, chunked_leaf_idx, ChunkedLeaf.k_log2);
                defer if (new_root) |id| pool.unref(id);
                truncate_input_handle = null;

                var length_node: ?Node.Id = try pool.createLeafFromUint(@intCast(new_length));
                defer if (length_node) |id| pool.unref(id);
                const root_with_length = try Node.Id.setNode(new_root.?, pool, @enumFromInt(3), length_node.?);
                errdefer pool.unref(root_with_length);

                length_node = null;
                new_root = null;

                return try Self.init(self.allocator, pool, root_with_length);
            }

            const chunk_node = try Node.Id.getNodeAtDepth(self.chunks.state.root, pool, chunk_depth, chunk_index);

            var chunk_bytes = chunk_node.getRoot(pool).*;
            if (keep_bytes < BYTES_PER_CHUNK) {
                @memset(chunk_bytes[keep_bytes..], 0);
            }

            var truncated_chunk_node: ?Node.Id = try pool.createLeaf(&chunk_bytes);
            defer if (truncated_chunk_node) |id| pool.unref(id);
            var updated: ?Node.Id = try Node.Id.setNodeAtDepth(
                self.chunks.state.root,
                pool,
                chunk_depth,
                chunk_index,
                truncated_chunk_node.?,
            );
            defer if (updated) |id| pool.unref(id);
            truncated_chunk_node = null;

            var new_root: ?Node.Id = try Node.Id.truncateAfterIndex(updated.?, pool, chunk_depth, chunk_index);
            defer if (new_root) |id| pool.unref(id);
            updated = null;

            var length_node: ?Node.Id = try pool.createLeafFromUint(@intCast(new_length));
            defer if (length_node) |id| pool.unref(id);
            const root_with_length = try Node.Id.setNode(new_root.?, pool, @enumFromInt(3), length_node.?);
            errdefer pool.unref(root_with_length);

            length_node = null;
            new_root = null;

            return try Self.init(self.allocator, pool, root_with_length);
        }

        /// Serialize the tree view into a provided buffer.
        /// Returns the number of bytes written.
        pub fn serializeIntoBytes(self: *Self, out: []u8) !usize {
            try self.commit();
            return try ST.tree.serializeIntoBytes(self.chunks.state.root, self.chunks.state.pool, out);
        }

        /// Get the serialized size of this tree view.
        pub fn serializedSize(self: *Self) !usize {
            try self.commit();
            return try ST.tree.serializedSize(self.chunks.state.root, self.chunks.state.pool);
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
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 });
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 16, .{});

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
    try view.hashTreeRootInto(&actual_root);

    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);

    var roundtrip: ListType.Type = .empty;
    defer roundtrip.deinit(allocator);
    try ListType.tree.toValue(allocator, view.getRoot(), &pool, &roundtrip);
    try std.testing.expectEqual(roundtrip.items.len, expected_list.items.len);
    try std.testing.expectEqualSlices(u32, expected_list.items, roundtrip.items);
}

test "TreeView list push updates cached length" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 });
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 16, .{});

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
    try view.hashTreeRootInto(&actual_root);

    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

test "TreeView list getAllAlloc handles zero length" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 64 });
    defer pool.deinit();

    const Uint8 = UintType(8);
    const ListType = FixedListType(Uint8, 4, .{});

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    const filled = try view.getAll(null);
    defer allocator.free(filled);

    try std.testing.expectEqual(@as(usize, 0), filled.len);
}

test "TreeView list getAllAlloc spans multiple chunks" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 512 });
    defer pool.deinit();

    const Uint16 = UintType(16);
    const ListType = FixedListType(Uint16, 64, .{});

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

    const filled = try view.getAll(null);
    defer allocator.free(filled);

    try std.testing.expectEqualSlices(u16, values[0..], filled);
}

test "TreeView list push batches before commit" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 });
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 16, .{});

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
    try view.hashTreeRootInto(&actual_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

test "TreeView list push across chunk boundary resets prefetch" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 });
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 32, .{});

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &[_]u32{ 0, 1, 2, 3, 4, 5, 6, 7 });

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    const initial = try view.getAll(null);
    defer allocator.free(initial);
    try std.testing.expectEqual(@as(usize, 8), initial.len);

    try view.push(@as(u32, 8));
    try view.push(@as(u32, 9));

    try std.testing.expectEqual(@as(usize, 10), try view.length());
    try std.testing.expectEqual(@as(u32, 9), try view.get(9));

    const filled = try view.getAll(null);
    defer allocator.free(filled);
    var expected: [10]u32 = [_]u32{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    try std.testing.expectEqualSlices(u32, expected[0..], filled);
}

test "TreeView list push enforces limit" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 });
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 2, .{});

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
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 16, .{});

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
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 16, .{});

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
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 16, .{});

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

test "TreeView list basic clone(false) does not transfer cache" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 });
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 16, .{});

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &[_]u32{ 1, 2, 3 });

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    _ = try view.get(0);
    try std.testing.expect(view.chunks.state.children_nodes.count() > 0);

    var cloned_no_cache = try view.clone(.{ .transfer_cache = false });
    defer cloned_no_cache.deinit();

    try std.testing.expect(view.chunks.state.children_nodes.count() > 0);
    try std.testing.expectEqual(@as(usize, 0), cloned_no_cache.chunks.state.children_nodes.count());
}

test "TreeView list basic clone(true) transfers cache and clears source" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 });
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 16, .{});

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &[_]u32{ 1, 2, 3 });

    const root_node = try ListType.tree.fromValue(&pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    _ = try view.get(0);
    try std.testing.expect(view.chunks.state.children_nodes.count() > 0);

    var cloned = try view.clone(.{});
    defer cloned.deinit();

    try std.testing.expectEqual(@as(usize, 0), view.chunks.state.children_nodes.count());
    try std.testing.expect(cloned.chunks.state.children_nodes.count() > 0);
}

// Refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/listBasic/tree.test.ts#L180-L203
test "TreeView basic list getAll reflects pushes" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 });
    defer pool.deinit();

    const list_limit = 32;
    const Uint64 = UintType(64);
    const ListType = FixedListType(Uint64, list_limit, .{});

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
    const filled = try view.getAll(null);
    defer allocator.free(filled);
    try std.testing.expectEqualSlices(u64, expected[0..], filled);
}

test "TreeView list sliceTo returns original when truncation unnecessary" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 });
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 16, .{});

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
    try sliced.hashTreeRootInto(&actual_root);

    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

// Refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/listBasic/tree.test.ts#L219-L247
test "TreeView basic list sliceTo matches incremental snapshots" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 2048 });
    defer pool.deinit();

    const Uint64 = UintType(64);
    const ListType = FixedListType(Uint64, 1024, .{});
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
        try sliced.hashTreeRootInto(&actual_root);

        try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
    }
}

test "TreeView list sliceTo truncates tail elements" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 });
    defer pool.deinit();

    const Uint32 = UintType(32);
    const ListType = FixedListType(Uint32, 32, .{});

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

    const filled = try sliced.getAll(null);
    defer allocator.free(filled);

    try std.testing.expectEqualSlices(u32, values[0..3], filled);

    var expected: ListType.Type = .empty;
    defer expected.deinit(allocator);
    try expected.appendSlice(allocator, values[0..3]);

    var expected_root: [32]u8 = undefined;
    try ListType.hashTreeRoot(allocator, &expected, &expected_root);

    var actual_root: [32]u8 = undefined;
    try sliced.hashTreeRootInto(&actual_root);

    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

// Tests ported from TypeScript ssz packages/ssz/test/unit/byType/listBasic/tree.test.ts
test "ListBasicTreeView - serialize (uint8 list)" {
    const allocator = std.testing.allocator;

    const Uint8 = UintType(8);
    const ListU8Type = FixedListType(Uint8, 128, .{});

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
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
        try view.hashTreeRootInto(&hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "ListBasicTreeView - serialize (uint64 list)" {
    const allocator = std.testing.allocator;

    const Uint64 = UintType(64);
    const ListU64Type = FixedListType(Uint64, 128, .{});

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
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
        try view.hashTreeRootInto(&hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "ListBasicTreeView - push and serialize" {
    const allocator = std.testing.allocator;

    const Uint8 = UintType(8);
    const ListU8Type = FixedListType(Uint8, 128, .{});

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
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
    try view.hashTreeRootInto(&hash_root);
    const expected_root = [_]u8{ 0xba, 0xc5, 0x11, 0xd1, 0xf6, 0x41, 0xd6, 0xb8, 0x82, 0x32, 0x00, 0xbb, 0x4b, 0x3c, 0xce, 0xd3, 0xbd, 0x47, 0x20, 0x70, 0x1f, 0x18, 0x57, 0x1d, 0xff, 0x35, 0xa5, 0xd2, 0xa4, 0x01, 0x90, 0xfa };
    try std.testing.expectEqualSlices(u8, &expected_root, &hash_root);
}

test "ListBasicTreeView - sliceTo and serialize" {
    const allocator = std.testing.allocator;

    const Uint8 = UintType(8);
    const ListU8Type = FixedListType(Uint8, 128, .{});

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
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

// chunked_leaf-mode tests for iteratorReadonly and sliceTo. The non-chunked_leaf
// path is covered by the tests above; here we cross ChunkedLeaf boundaries
// and intra-chunk offsets, and verify the merkle root matches the leaf-path
// equivalent.
//
// File-level alias so tests can reference `ChunkedLeafType.K` / `ChunkedLeafType.k_log2`
// without colliding with the inner-struct binding in `ListBasicTreeView`.
const ChunkedLeafType = @import("persistent_merkle_tree").ChunkedLeaf;

test "ListBasicTreeView chunked_leaf: iteratorReadonly within first chunked_leaf" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 4096 });
    defer pool.deinit();

    const ListT = FixedListType(UintType(64), 1 << 20, .{ .chunked_leaf = true });
    const item_count: usize = 100;

    var src: ListT.Type = .empty;
    defer src.deinit(allocator);
    for (0..item_count) |i| try src.append(allocator, @as(u64, @intCast(i * 7 + 3)));

    const root_id = try ListT.tree.fromValue(&pool, &src);
    var view = try ListT.TreeView.init(allocator, &pool, root_id);
    defer view.deinit();

    var it = view.iteratorReadonly(0);
    for (0..item_count) |i| {
        const got = try it.next();
        try std.testing.expectEqual(src.items[i], got);
    }
}

test "ListBasicTreeView chunked_leaf: iteratorReadonly across chunked_leaf boundary" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 4096 });
    defer pool.deinit();

    const ListT = FixedListType(UintType(64), 1 << 20, .{ .chunked_leaf = true });
    // Cross 3 ChunkedLeaves: 2 full + 1 partial. items_per_chunk=4 for u64,
    // K=1024 chunks/chunked_leaf -> 4096 items per ChunkedLeaf.
    const item_count: usize = 2 * 4096 + 17;

    var src: ListT.Type = .empty;
    defer src.deinit(allocator);
    try src.ensureTotalCapacity(allocator, item_count);
    for (0..item_count) |i| try src.append(allocator, @as(u64, @intCast(i * 31 + 1)));

    const root_id = try ListT.tree.fromValue(&pool, &src);
    var view = try ListT.TreeView.init(allocator, &pool, root_id);
    defer view.deinit();

    var it = view.iteratorReadonly(0);
    for (0..item_count) |i| {
        const got = try it.next();
        try std.testing.expectEqual(src.items[i], got);
    }
}

test "ListBasicTreeView chunked_leaf: iteratorReadonly with start_index mid-chunked_leaf" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 4096 });
    defer pool.deinit();

    const ListT = FixedListType(UintType(64), 1 << 20, .{ .chunked_leaf = true });
    const item_count: usize = 5000;

    var src: ListT.Type = .empty;
    defer src.deinit(allocator);
    try src.ensureTotalCapacity(allocator, item_count);
    for (0..item_count) |i| try src.append(allocator, @as(u64, @intCast(i * 13 + 5)));

    const root_id = try ListT.tree.fromValue(&pool, &src);
    var view = try ListT.TreeView.init(allocator, &pool, root_id);
    defer view.deinit();

    // Start in the second ChunkedLeaf (index >= 4096) and at non-chunk boundary.
    const start: usize = 4500;
    var it = view.iteratorReadonly(start);
    for (start..item_count) |i| {
        const got = try it.next();
        try std.testing.expectEqual(src.items[i], got);
    }
}

test "ListBasicTreeView chunked_leaf: iteratorReadonly on sparsely grown list" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 4096 });
    defer pool.deinit();

    const ListT = FixedListType(UintType(64), 1 << 20, .{ .chunked_leaf = true });
    // Grow from empty via push so initial chunked_leaves are zero sentinels
    // until they get materialized. After pushing N elements, only the
    // ChunkedLeaves up to ceil(N / (K * items_per_chunk)) are real.
    const item_count: usize = 6000;

    var empty: ListT.Type = .empty;
    defer empty.deinit(allocator);
    const root_id = try ListT.tree.fromValue(&pool, &empty);
    var view = try ListT.TreeView.init(allocator, &pool, root_id);
    defer view.deinit();

    for (0..item_count) |i| {
        try view.push(@as(u64, @intCast(i + 1)));
    }
    try view.commit();

    var it = view.iteratorReadonly(0);
    for (0..item_count) |i| {
        const got = try it.next();
        try std.testing.expectEqual(@as(u64, @intCast(i + 1)), got);
    }
}

test "ListBasicTreeView chunked_leaf: sliceTo within first chunked_leaf" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 4096 });
    defer pool.deinit();

    const ListT = FixedListType(UintType(64), 1 << 20, .{ .chunked_leaf = true });
    const ListTLeaf = FixedListType(UintType(64), 1 << 20, .{});

    const item_count: usize = 50;

    var src: ListT.Type = .empty;
    defer src.deinit(allocator);
    for (0..item_count) |i| try src.append(allocator, @as(u64, @intCast(i + 100)));

    const root_id = try ListT.tree.fromValue(&pool, &src);
    var view = try ListT.TreeView.init(allocator, &pool, root_id);
    defer view.deinit();

    const cut: usize = 17;
    var sliced = try view.sliceTo(cut);
    defer sliced.deinit();

    try std.testing.expectEqual(@as(usize, cut + 1), try sliced.length());

    // Element-level equality.
    for (0..cut + 1) |i| {
        try std.testing.expectEqual(src.items[i], try sliced.get(i));
    }

    // Root matches the non-chunked_leaf reference at the same length.
    var ref: ListTLeaf.Type = .empty;
    defer ref.deinit(allocator);
    try ref.appendSlice(allocator, src.items[0 .. cut + 1]);
    var expected_root: [32]u8 = undefined;
    try ListTLeaf.hashTreeRoot(allocator, &ref, &expected_root);

    var actual_root: [32]u8 = undefined;
    try sliced.hashTreeRootInto(&actual_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

test "ListBasicTreeView chunked_leaf: sliceTo at chunked_leaf boundary" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 4096 });
    defer pool.deinit();

    const ListT = FixedListType(UintType(64), 1 << 20, .{ .chunked_leaf = true });
    const ListTLeaf = FixedListType(UintType(64), 1 << 20, .{});
    const item_count: usize = 2 * 4096 + 100;

    var src: ListT.Type = .empty;
    defer src.deinit(allocator);
    try src.ensureTotalCapacity(allocator, item_count);
    for (0..item_count) |i| try src.append(allocator, @as(u64, @intCast(i * 11 + 7)));

    const root_id = try ListT.tree.fromValue(&pool, &src);
    var view = try ListT.TreeView.init(allocator, &pool, root_id);
    defer view.deinit();

    // Cut at the last index of the first ChunkedLeaf (4095). Boundary
    // exercises intra_chunk = K-1 and all chunks past it are zeroed.
    const cut: usize = 4095;
    var sliced = try view.sliceTo(cut);
    defer sliced.deinit();

    try std.testing.expectEqual(@as(usize, cut + 1), try sliced.length());

    var ref: ListTLeaf.Type = .empty;
    defer ref.deinit(allocator);
    try ref.appendSlice(allocator, src.items[0 .. cut + 1]);

    var expected_root: [32]u8 = undefined;
    try ListTLeaf.hashTreeRoot(allocator, &ref, &expected_root);
    var actual_root: [32]u8 = undefined;
    try sliced.hashTreeRootInto(&actual_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

test "ListBasicTreeView chunked_leaf: sliceTo across chunked_leaf boundary" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 4096 });
    defer pool.deinit();

    const ListT = FixedListType(UintType(64), 1 << 20, .{ .chunked_leaf = true });
    const ListTLeaf = FixedListType(UintType(64), 1 << 20, .{});
    const item_count: usize = 3 * 4096 + 50;

    var src: ListT.Type = .empty;
    defer src.deinit(allocator);
    try src.ensureTotalCapacity(allocator, item_count);
    for (0..item_count) |i| try src.append(allocator, @as(u64, @intCast(i * 23 + 9)));

    const root_id = try ListT.tree.fromValue(&pool, &src);
    var view = try ListT.TreeView.init(allocator, &pool, root_id);
    defer view.deinit();

    // Cut in the middle of the second ChunkedLeaf.
    const cut: usize = 4096 + 1234;
    var sliced = try view.sliceTo(cut);
    defer sliced.deinit();

    try std.testing.expectEqual(@as(usize, cut + 1), try sliced.length());

    // toValue round-trip.
    var dst: ListT.Type = .empty;
    defer dst.deinit(allocator);
    try ListT.tree.toValue(allocator, sliced.getRoot(), &pool, &dst);
    try std.testing.expectEqual(@as(usize, cut + 1), dst.items.len);
    try std.testing.expectEqualSlices(u64, src.items[0 .. cut + 1], dst.items);

    // Root matches reference.
    var ref: ListTLeaf.Type = .empty;
    defer ref.deinit(allocator);
    try ref.appendSlice(allocator, src.items[0 .. cut + 1]);
    var expected_root: [32]u8 = undefined;
    try ListTLeaf.hashTreeRoot(allocator, &ref, &expected_root);
    var actual_root: [32]u8 = undefined;
    try sliced.hashTreeRootInto(&actual_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

test "ListBasicTreeView chunked_leaf: sliceTo returns clone when index >= length-1" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 4096 });
    defer pool.deinit();

    const ListT = FixedListType(UintType(64), 1 << 20, .{ .chunked_leaf = true });
    const item_count: usize = 100;

    var src: ListT.Type = .empty;
    defer src.deinit(allocator);
    for (0..item_count) |i| try src.append(allocator, @as(u64, @intCast(i)));

    const root_id = try ListT.tree.fromValue(&pool, &src);
    var view = try ListT.TreeView.init(allocator, &pool, root_id);
    defer view.deinit();

    var sliced = try view.sliceTo(item_count - 1);
    defer sliced.deinit();

    try std.testing.expectEqual(item_count, try sliced.length());
    try std.testing.expectEqualSlices(u8, view.getRoot().getRoot(&pool), sliced.getRoot().getRoot(&pool));
}

// Build a list root manually with chunked_leaf 0 real and chunked_leaf 1 forced to a
// zero sentinel; length spans into chunked_leaf 1. Used to exercise defensive
// `.zero` branches in iteratorReadonly and sliceTo that aren't reachable via
// `fromValue` / `push` (those materialize on first write).
fn buildChunkedLeafListWithZeroBoundary(
    pool: *Node.Pool,
    cl0_chunks: *align(64) const [ChunkedLeafType.K][32]u8,
    list_length: usize,
    chunked_leaf_subtree_depth: Depth,
) !Node.Id {
    const cl0_id = try pool.createChunkedLeaf(cl0_chunks, ChunkedLeafType.K);

    // Build chunks subtree: only append chunked_leaf 0; finish() pads remaining
    // positions at chunked_leaf level with ZeroHash[k_log2] sentinels.
    var fc_it = Node.FillWithContentsIterator.initWithOffset(pool, chunked_leaf_subtree_depth, ChunkedLeafType.k_log2);
    errdefer fc_it.deinit();
    try fc_it.append(cl0_id);
    const chunks_root = try fc_it.finish();
    errdefer pool.unref(chunks_root);

    // Mix in length: list_root = hash(chunks_root, length_leaf).
    const length_leaf = try pool.createLeafFromUint(@intCast(list_length));
    errdefer pool.unref(length_leaf);

    var list_it = Node.FillWithContentsIterator.init(pool, 1);
    errdefer list_it.deinit();
    try list_it.append(chunks_root);
    try list_it.append(length_leaf);
    return try list_it.finish();
}

test "ListBasicTreeView chunked_leaf: iteratorReadonly handles zero-sentinel chunked_leaf" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 4096 });
    defer pool.deinit();

    const ListT = FixedListType(UintType(64), 1 << 20, .{ .chunked_leaf = true });

    // Fill chunked_leaf 0 with deterministic non-zero u64 data: chunk i has u256 = i + 1.
    var raw: [ChunkedLeafType.K][32]u8 align(64) = undefined;
    @memset(std.mem.asBytes(&raw), 0);
    for (0..ChunkedLeafType.K) |i| {
        std.mem.writeInt(u256, &raw[i], @as(u256, @intCast(i + 1)), .little);
    }

    // length spans into chunked_leaf 1 (zero sentinel) — last 100 items live in
    // the sparse region where iteratorReadonly hits its `.zero` branch.
    const items_in_cl0: usize = ChunkedLeafType.K * 4; // 4096 (items_per_chunk = 4 for u64)
    const items_in_cl1: usize = 100;
    const item_count = items_in_cl0 + items_in_cl1;
    const chunked_leaf_subtree_depth: Depth = @intCast(ListT.chunk_depth - ChunkedLeafType.k_log2);

    const list_root = try buildChunkedLeafListWithZeroBoundary(&pool, &raw, item_count, chunked_leaf_subtree_depth);
    var view = try ListT.TreeView.init(allocator, &pool, list_root);
    defer view.deinit();

    try std.testing.expectEqual(item_count, try view.length());

    var it = view.iteratorReadonly(0);

    // First chunked_leaf: real data. Each chunk holds u256 (chunk_idx + 1) = 4
    // little-endian u64s, so item j in chunk c has value = (c+1) >> (j%4 * 64).
    for (0..items_in_cl0) |item_idx| {
        const got = try it.next();
        const chunk_idx = item_idx / 4;
        const u64_idx = item_idx % 4;
        const u256_val: u256 = @intCast(chunk_idx + 1);
        const expected: u64 = @truncate(u256_val >> @intCast(u64_idx * 64));
        try std.testing.expectEqual(expected, got);
    }

    // Crossed into chunked_leaf 1 — zero sentinel. Iterator's `.zero` branch
    // should yield zero values without dereferencing payload.
    for (0..items_in_cl1) |_| {
        const got = try it.next();
        try std.testing.expectEqual(@as(u64, 0), got);
    }
}

test "ListBasicTreeView chunked_leaf: sliceTo handles zero-sentinel boundary" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 4096 });
    defer pool.deinit();

    const ListT = FixedListType(UintType(64), 1 << 20, .{ .chunked_leaf = true });
    const ListTLeaf = FixedListType(UintType(64), 1 << 20, .{});

    var raw: [ChunkedLeafType.K][32]u8 align(64) = undefined;
    @memset(std.mem.asBytes(&raw), 0);
    for (0..ChunkedLeafType.K) |i| {
        std.mem.writeInt(u256, &raw[i], @as(u256, @intCast(i * 7 + 13)), .little);
    }

    const items_in_cl0: usize = ChunkedLeafType.K * 4;
    const items_in_cl1: usize = 200;
    const item_count = items_in_cl0 + items_in_cl1;
    const chunked_leaf_subtree_depth: Depth = @intCast(ListT.chunk_depth - ChunkedLeafType.k_log2);

    const list_root = try buildChunkedLeafListWithZeroBoundary(&pool, &raw, item_count, chunked_leaf_subtree_depth);
    var view = try ListT.TreeView.init(allocator, &pool, list_root);
    defer view.deinit();

    // Cut at index 4150 — boundary chunked_leaf is the zero-sentinel chunked_leaf 1.
    const cut: usize = items_in_cl0 + 50;
    var sliced = try view.sliceTo(cut);
    defer sliced.deinit();

    try std.testing.expectEqual(@as(usize, cut + 1), try sliced.length());

    // The first 4096 items come from chunked_leaf 0 (real data); items 4096..cut
    // come from the zero sentinel (zeros).
    var ref_items = try allocator.alloc(u64, cut + 1);
    defer allocator.free(ref_items);
    for (0..items_in_cl0) |item_idx| {
        const chunk_idx = item_idx / 4;
        const u64_idx = item_idx % 4;
        const u256_val: u256 = @intCast(chunk_idx * 7 + 13);
        ref_items[item_idx] = @truncate(u256_val >> @intCast(u64_idx * 64));
    }
    @memset(ref_items[items_in_cl0..], 0);

    var ref: ListTLeaf.Type = .empty;
    defer ref.deinit(allocator);
    try ref.appendSlice(allocator, ref_items);

    var expected_root: [32]u8 = undefined;
    try ListTLeaf.hashTreeRoot(allocator, &ref, &expected_root);

    var actual_root: [32]u8 = undefined;
    try sliced.hashTreeRootInto(&actual_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}
