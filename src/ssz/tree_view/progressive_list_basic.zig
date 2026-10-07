const std = @import("std");
const Allocator = std.mem.Allocator;
const hashing = @import("hashing");
const Depth = hashing.Depth;
const pmt = @import("persistent_merkle_tree");
const Node = pmt.Node;
const ChunkedLeaf = pmt.ChunkedLeaf;
const Gindex = pmt.Gindex;
const isBasicType = @import("../type/type_kind.zig").isBasicType;
const progressive = @import("../type/progressive.zig");
const TreeViewState = @import("utils/tree_view_state.zig").TreeViewState;
const CloneOpts = @import("utils/clone_opts.zig").CloneOpts;
const assertTreeViewType = @import("utils/assert.zig").assertTreeViewType;

/// Packed basic elements with deferred writes over progressive subtrees of 1, 4, 16, ... chunks.
pub fn ProgressiveListBasicTreeView(comptime ST: type) type {
    comptime {
        if (ST.kind != .progressive_list or !isBasicType(ST.Element)) {
            @compileError(
                "ProgressiveListBasicTreeView requires a progressive list of basic elements",
            );
        }
    }

    const TreeView = struct {
        allocator: Allocator,
        state: TreeViewState,
        _orig_len: usize,
        _len: usize,
        cached_chunk: ?struct { position: Position, node: Node.Id, dirty: bool },

        pub const SszType = ST;
        pub const Element = ST.Element.Type;

        const Self = @This();
        const items_per_chunk = 32 / ST.Element.fixed_size;
        const use_chunked_leaf = ST.opts.chunked_leaf;
        const length_gindex: Gindex = @enumFromInt(3);
        pub const max_length: usize = @intCast(@min(
            @as(u128, progressive.max_tree_chunks) * items_per_chunk,
            std.math.maxInt(usize) / ST.Element.fixed_size,
        ));

        pub fn init(allocator: Allocator, pool: *Node.Pool, root: Node.Id) !*Self {
            const len = try ST.tree.length(root, pool);
            if (len > max_length) return error.LengthOverLimit;

            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);

            try self.state.init(allocator, pool, root);
            self.allocator = allocator;
            self._orig_len = len;
            self._len = len;
            self.cached_chunk = null;
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.state.deinit();
            self.allocator.destroy(self);
        }

        /// Clones the committed root. Cache transfer also discards the source's pending writes.
        pub fn clone(self: *Self, opts: CloneOpts) !*Self {
            const copy = try self.allocator.create(Self);
            errdefer self.allocator.destroy(copy);

            try self.state.clone(opts, &copy.state);
            copy.allocator = self.allocator;
            copy._orig_len = self._orig_len;
            copy._len = self._orig_len;
            copy.cached_chunk = null;
            if (opts.transfer_cache) {
                self._len = self._orig_len;
                self.cached_chunk = null;
            }
            return copy;
        }

        /// Discards pending writes and growth, retaining the cache allocations.
        pub fn clearCache(self: *Self) void {
            self.state.clearCache();
            self._len = self._orig_len;
            self.cached_chunk = null;
        }

        pub fn fromValue(allocator: Allocator, pool: *Node.Pool, value: *const ST.Type) !*Self {
            if (value.items.len > max_length) return error.LengthOverLimit;
            const root = try ST.tree.fromValue(pool, value);
            errdefer pool.unref(root);
            return Self.init(allocator, pool, root);
        }

        pub fn deserialize(allocator: Allocator, pool: *Node.Pool, bytes: []const u8) !*Self {
            const root = try ST.tree.deserializeFromBytes(pool, bytes);
            errdefer pool.unref(root);
            return Self.init(allocator, pool, root);
        }

        pub fn getRoot(self: *const Self) Node.Id {
            return self.state.root;
        }

        pub fn length(self: *const Self) !usize {
            return self._len;
        }

        /// Extends with zeros. Use sliceTo to shrink and clear the truncated contents.
        pub fn growTo(self: *Self, new_length: usize) !void {
            if (new_length < self._len) return error.InvalidLength;
            if (new_length > max_length) return error.LengthOverLimit;
            self._len = new_length;
        }

        pub fn get(self: *Self, index: usize) !Element {
            if (index >= self._len) return error.IndexOutOfBounds;
            const chunk_index = index / items_per_chunk;
            const position = self.positionForChunk(chunk_index);
            const node = try self.getChunk(position);
            var value: Element = undefined;
            if (position.leaf_offset != 0) {
                if (node.getState(self.state.pool).isZero()) return std.mem.zeroes(Element);
                const chunks = try node.getChunkedLeafChunks(self.state.pool);
                ST.Element.tree.toValuePackedFromBytes(
                    &chunks[chunk_index - position.start],
                    index % items_per_chunk,
                    &value,
                );
            } else {
                try ST.Element.tree.toValuePacked(
                    node,
                    self.state.pool,
                    index % items_per_chunk,
                    &value,
                );
            }
            return value;
        }

        pub fn set(self: *Self, index: usize, value: Element) !void {
            if (index >= self._len) return error.IndexOutOfBounds;
            const chunk_index = index / items_per_chunk;
            const position = self.positionForChunk(chunk_index);
            const gindex = position.gindex;
            const node = try self.getChunk(position);
            if (position.leaf_offset != 0) {
                const valid_chunks: u16 = @intCast(@min(
                    ChunkedLeaf.K,
                    chunkCount(self._len) - position.start,
                ));
                if (self.cached_chunk.?.dirty) {
                    try node.editChunkedLeaf(
                        self.state.pool,
                        @intCast(chunk_index - position.start),
                        valid_chunks,
                        Element,
                        index % items_per_chunk,
                        &value,
                        ST.Element.tree.fromValuePackedIntoChunk,
                    );
                } else {
                    // Growth can address a new subtree before commit installs its zero scaffold.
                    try self.state.children_nodes.put(self.allocator, gindex, node);
                    try self.state.editChunkedLeaf(
                        gindex,
                        @intCast(chunk_index - position.start),
                        valid_chunks,
                        Element,
                        index % items_per_chunk,
                        &value,
                        ST.Element.tree.fromValuePackedIntoChunk,
                    );
                    self.cached_chunk = .{
                        .position = position,
                        .node = self.state.children_nodes.get(gindex).?,
                        .dirty = true,
                    };
                }
                return;
            }
            if (self.cached_chunk.?.dirty) {
                std.debug.assert(node.getState(self.state.pool).isLeaf());
                std.debug.assert(node.getState(self.state.pool).refCount() == 0);
                ST.Element.tree.fromValuePackedIntoChunk(
                    &self.state.pool.nodes.items(.root)[@intFromEnum(node)],
                    index % items_per_chunk,
                    &value,
                );
                return;
            }

            const replacement = try ST.Element.tree.fromValuePacked(
                node,
                self.state.pool,
                index % items_per_chunk,
                &value,
            );
            errdefer self.state.pool.unref(replacement);

            try self.state.setChildNode(gindex, replacement);
            self.cached_chunk = .{ .position = position, .node = replacement, .dirty = true };
        }

        pub fn push(self: *Self, value: Element) !void {
            if (self._len == max_length) return error.LengthOverLimit;
            const index = self._len;
            self._len += 1;
            errdefer self._len -= 1;
            try self.set(index, value);
        }

        /// On failure, the committed root stays unchanged and pending writes remain valid.
        pub fn commit(self: *Self) !void {
            const pool = self.state.pool;
            if (self._len != self._orig_len) {
                const length_node = try pool.createLeafFromUint(self._len);
                errdefer pool.unref(length_node);
                try self.state.setChildNode(length_gindex, length_node);
            }

            const old_count = subtreeCount(chunkCount(self._orig_len));
            const new_count = subtreeCount(chunkCount(self._len));
            if (old_count == new_count) {
                try self.state.commitNodes();
            } else {
                std.debug.assert(new_count > old_count);
                var tail: Node.Id = @enumFromInt(0);
                defer pool.unref(tail);
                var i = new_count;
                while (i > old_count) {
                    i -= 1;
                    tail = try pool.createBranch(@enumFromInt(2 * i), tail);
                }
                // Retain the scaffold while setNode may partially build and reclaim ancestors.
                try pool.ref(tail);
                const expanded = try self.state.root.setNode(pool, spineGindex(old_count), tail);
                try pool.ref(expanded);

                const original = self.state.root;
                self.state.root = expanded;
                errdefer {
                    pool.unref(self.state.root);
                    self.state.root = original;
                }
                try self.state.commitNodes();
                pool.unref(original);
            }
            self._orig_len = self._len;
            self.cached_chunk = null;
        }

        pub fn getAll(self: *Self, allocator: ?Allocator) ![]Element {
            const alloc = allocator orelse self.allocator;
            const values = try alloc.alloc(Element, self._len);
            errdefer alloc.free(values);
            return self.getAllInto(values);
        }

        pub fn getAllInto(self: *Self, values: []Element) ![]Element {
            if (values.len != self._len) return error.InvalidSize;
            var chunks = ChunkIterator.init(self, 0);
            var index: usize = 0;
            while (index < values.len) {
                const block = try chunks.next();
                const count = @min(block.count * items_per_chunk, values.len - index);
                const pool = self.state.pool;
                if (block.node.getState(pool).isZero()) {
                    @memset(values[index..][0..count], std.mem.zeroes(Element));
                } else {
                    const bytes: []const u8 = if (block.leaf_offset != 0)
                        std.mem.asBytes(try block.node.getChunkedLeafChunks(pool))
                    else
                        block.node.getRoot(pool);
                    ST.tree.toValuesPackedFromBytes(bytes, values[index..][0..count]);
                }
                index += count;
            }
            return values;
        }

        /// Reads committed elements. Commit before creating the iterator; do not mutate the view
        /// or pool while iterating, since the iterator borrows packed bytes.
        pub fn iteratorReadonly(self: *const Self, start_index: usize) ReadonlyIterator {
            std.debug.assert(self.state.changed.count() == 0);
            std.debug.assert(self._len == self._orig_len);
            return .{
                .chunks = ChunkIterator.init(self, start_index / items_per_chunk),
                .index = start_index,
            };
        }

        pub const ReadonlyIterator = struct {
            chunks: ChunkIterator,
            index: usize,
            block: ?Block = null,
            bytes: []const u8 = undefined,

            pub fn next(self: *ReadonlyIterator) !Element {
                if (self.index >= self.chunks.view._orig_len) return error.InvalidLength;
                const pool = self.chunks.view.state.pool;
                const block = self.block orelse blk: {
                    const next_block = try self.chunks.next();
                    self.bytes = if (next_block.node.getState(pool).isZero())
                        &progressive.zero_leaf_bytes
                    else if (next_block.leaf_offset != 0)
                        std.mem.asBytes(try next_block.node.getChunkedLeafChunks(pool))
                    else
                        next_block.node.getRoot(pool);
                    self.block = next_block;
                    break :blk next_block;
                };
                var value: Element = undefined;
                const offset = (self.index / items_per_chunk - block.start) * 32;
                ST.Element.tree.toValuePackedFromBytes(
                    self.bytes[offset..][0..32],
                    self.index % items_per_chunk,
                    &value,
                );
                self.index += 1;
                if (self.index / items_per_chunk >= block.start + block.count) self.block = null;
                return value;
            }
        };

        const Block = struct {
            node: Node.Id,
            start: usize,
            count: usize,
            leaf_offset: Depth,
        };

        const ChunkIterator = struct {
            view: *const Self,
            index: usize,
            subtree_end: usize = 0,
            gindex: Gindex = @enumFromInt(0),
            leaf_offset: Depth = 0,
            iterator: Node.DepthIterator = undefined,

            fn init(view: *const Self, start_index: usize) ChunkIterator {
                return .{ .view = view, .index = start_index };
            }

            fn next(self: *ChunkIterator) !Block {
                const pool = self.view.state.pool;
                if (self.index >= self.subtree_end) {
                    const subtree = subtreeIndex(self.index);
                    const start = subtreeStart(subtree);
                    const depth: Depth = @intCast(2 * subtree);
                    self.leaf_offset = leafOffset(subtree);
                    const position = Position.init(self.index);
                    const root = if (subtree < subtreeCount(chunkCount(self.view._orig_len)))
                        try self.view.state.root.getNode(pool, subtreeGindex(subtree))
                    else
                        @as(Node.Id, @enumFromInt(depth));
                    self.iterator = Node.DepthIterator.init(
                        pool,
                        root,
                        depth - self.leaf_offset,
                        (self.index - start) >> self.leaf_offset,
                    );
                    self.subtree_end = start + (@as(usize, 1) << depth);
                    self.gindex = position.gindex;
                    self.index = position.start;
                }
                const committed = try self.iterator.next();
                const node = if (self.view.state.changed.count() == 0)
                    committed
                else
                    self.view.state.children_nodes.get(self.gindex) orelse committed;
                const block: Block = .{
                    .node = node,
                    .start = self.index,
                    .count = @as(usize, 1) << self.leaf_offset,
                    .leaf_offset = self.leaf_offset,
                };
                self.index += block.count;
                self.gindex = @enumFromInt(@intFromEnum(self.gindex) + 1);
                return block;
            }
        };

        /// Returns a separately owned view containing elements through index, inclusive.
        pub fn sliceTo(self: *Self, index: usize) !*Self {
            try self.commit();
            if (self._len == 0 or index >= self._len - 1) {
                return Self.init(self.allocator, self.state.pool, self.state.root);
            }
            const pool = self.state.pool;
            const chunk_index = index / items_per_chunk;
            const subtree = subtreeIndex(chunk_index);
            const leaf_offset = leafOffset(subtree);
            const depth: Depth = @intCast(2 * subtree - leaf_offset);
            const offset = (chunk_index - subtreeStart(subtree)) >> leaf_offset;
            var prefixes: [progressive.max_tree_subtrees]Node.Id = undefined;
            var spine = try self.state.root.getLeft(pool);
            for (0..subtree) |i| {
                prefixes[i] = try spine.getLeft(pool);
                spine = try spine.getRight(pool);
            }
            const root = try spine.getLeft(pool);
            const boundary = try root.getNodeAtDepth(pool, depth, offset);
            const keep_bytes = (index % items_per_chunk + 1) * ST.Element.fixed_size;
            const leaf = if (leaf_offset == 0) blk: {
                var bytes = boundary.getRoot(pool).*;
                @memset(bytes[keep_bytes..], 0);
                break :blk try pool.createLeaf(&bytes);
            } else if (boundary.getState(pool).isZero()) boundary else blk: {
                const intra_chunk = (chunk_index - subtreeStart(subtree)) % ChunkedLeaf.K;
                const trimmed_leaf = try pool.createChunkedLeafEmpty(@intCast(intra_chunk + 1));
                errdefer pool.unref(trimmed_leaf);
                const old_chunks = try boundary.getChunkedLeafChunks(pool);
                const storage = try trimmed_leaf.getChunkedLeafPtr(pool);
                @memcpy(storage.chunks[0 .. intra_chunk + 1], old_chunks[0 .. intra_chunk + 1]);
                @memset(storage.chunks[intra_chunk][keep_bytes..], 0);
                break :blk trimmed_leaf;
            };
            try pool.ref(leaf);
            defer pool.unref(leaf);

            const updated = try root.setNodeAtDepth(pool, depth, offset, leaf);
            try pool.ref(updated);
            defer pool.unref(updated);

            const trimmed = try updated.truncateAfterIndexWithLeafOffset(
                pool,
                depth,
                offset,
                leaf_offset,
            );
            try pool.ref(trimmed);
            defer pool.unref(trimmed);

            const sliced = blk: {
                var contents = try pool.createBranch(trimmed, @enumFromInt(0));
                errdefer pool.unref(contents);

                var i = subtree;
                while (i > 0) {
                    i -= 1;
                    contents = try pool.createBranch(prefixes[i], contents);
                }

                const length_node = try pool.createLeafFromUint(index + 1);
                errdefer pool.unref(length_node);

                break :blk try pool.createBranch(contents, length_node);
            };
            errdefer pool.unref(sliced);

            return Self.init(self.allocator, pool, sliced);
        }

        /// Fills `out` in place. The caller initializes `out` with `allocator` and keeps
        /// ownership; on error only its allocation stays valid.
        pub fn toValue(self: *Self, allocator: Allocator, out: *ST.Type) !void {
            try self.commit();
            try out.resize(allocator, self._len);
            _ = try self.getAllInto(out.items);
        }

        pub fn hashTreeRoot(self: *Self) !*const [32]u8 {
            try self.commit();
            return self.state.root.getRoot(self.state.pool);
        }

        pub fn hashTreeRootInto(self: *Self, out: *[32]u8) !void {
            out.* = (try self.hashTreeRoot()).*;
        }

        pub fn serializedSize(self: *Self) !usize {
            return self._len * ST.Element.fixed_size;
        }

        pub fn serializeIntoBytes(self: *Self, out: []u8) !usize {
            try self.commit();
            return ST.tree.serializeIntoBytes(self.state.root, self.state.pool, out);
        }

        inline fn getChunk(self: *Self, position: Position) !Node.Id {
            if (self.cached_chunk) |cached| {
                if (cached.position.start == position.start) return cached.node;
            }
            const gindex = position.gindex;
            const node = self.state.children_nodes.get(gindex) orelse
                if (position.start >= chunkCount(self._orig_len))
                    @as(Node.Id, @enumFromInt(position.leaf_offset))
                else
                    try self.state.getChildNode(gindex);
            self.cached_chunk = .{
                .position = position,
                .node = node,
                .dirty = self.state.changed.contains(gindex),
            };
            return node;
        }

        inline fn positionForChunk(self: *const Self, index: usize) Position {
            if (self.cached_chunk) |cached| {
                const position = cached.position;
                if (index >= position.start and
                    index - position.start < (@as(usize, 1) << position.leaf_offset))
                {
                    return position;
                }
            }
            return Position.init(index);
        }

        fn chunkCount(len: usize) usize {
            return len / items_per_chunk + @intFromBool(len % items_per_chunk != 0);
        }

        fn subtreeIndex(chunk_index: usize) usize {
            return std.math.log2_int(usize, 3 * chunk_index + 1) / 2;
        }

        fn subtreeStart(index: usize) usize {
            return ((@as(usize, 1) << @intCast(2 * index)) - 1) / 3;
        }

        fn subtreeCount(count: usize) usize {
            return if (count == 0) 0 else subtreeIndex(count - 1) + 1;
        }

        fn spineGindex(index: usize) Gindex {
            return @enumFromInt((@as(Gindex.Uint, 3) << @intCast(index)) - 1);
        }

        fn subtreeGindex(index: usize) Gindex {
            return @enumFromInt(@intFromEnum(spineGindex(index)) * 2);
        }

        fn leafOffset(subtree: usize) Depth {
            return if (use_chunked_leaf and 2 * subtree >= ChunkedLeaf.k_log2)
                ChunkedLeaf.k_log2
            else
                0;
        }

        const Position = struct {
            start: usize,
            leaf_offset: Depth,
            gindex: Gindex,

            inline fn init(index: usize) Position {
                const subtree = subtreeIndex(index);
                const start = subtreeStart(subtree);
                const leaf_offset = leafOffset(subtree);
                const leaf_index = (index - start) >> leaf_offset;
                const prefix = @intFromEnum(subtreeGindex(subtree)) <<
                    @intCast(2 * subtree - leaf_offset);
                return .{
                    .start = start + (leaf_index << leaf_offset),
                    .leaf_offset = leaf_offset,
                    .gindex = @enumFromInt(prefix + leaf_index),
                };
            }
        };
    };

    assertTreeViewType(TreeView);
    return TreeView;
}

test {
    _ = @import("progressive_list_basic_test.zig");
}
