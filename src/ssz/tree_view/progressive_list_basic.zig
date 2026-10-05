const std = @import("std");
const Allocator = std.mem.Allocator;
const hashing = @import("hashing");
const Depth = hashing.Depth;
const pmt = @import("persistent_merkle_tree");
const Node = pmt.Node;
const Gindex = pmt.Gindex;
const isBasicType = @import("../type/type_kind.zig").isBasicType;
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
        cached_chunk: ?struct { index: usize, node: Node.Id, dirty: bool },

        pub const SszType = ST;
        pub const Element = ST.Element.Type;

        const Self = @This();
        const items_per_chunk = 32 / ST.Element.fixed_size;
        // A chunk in subtree i has path length 3*i + 2 from the list root.
        const max_subtrees = @min((hashing.max_depth - 2) / 3, (@bitSizeOf(usize) - 1) / 2) + 1;
        const max_chunks = blk: {
            var total: usize = 0;
            for (0..max_subtrees) |i| total += @as(usize, 1) << @intCast(2 * i);
            break :blk total;
        };
        pub const max_length: usize = @intCast(@min(
            @as(u128, max_chunks) * items_per_chunk,
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
            const node = try self.getChunk(index / items_per_chunk);
            var value: Element = undefined;
            try ST.Element.tree.toValuePacked(
                node,
                self.state.pool,
                index % items_per_chunk,
                &value,
            );
            return value;
        }

        pub fn set(self: *Self, index: usize, value: Element) !void {
            if (index >= self._len) return error.IndexOutOfBounds;
            const chunk_index = index / items_per_chunk;
            const gindex = chunkGindex(chunk_index);
            const node = try self.getChunk(chunk_index);
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
            self.cached_chunk = .{ .index = chunk_index, .node = replacement, .dirty = true };
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
                try self.state.setChildNode(@enumFromInt(3), length_node);
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
                var published = false;
                defer {
                    if (published) {
                        pool.unref(original);
                    } else {
                        pool.unref(self.state.root);
                        self.state.root = original;
                    }
                }
                try self.state.commitNodes();
                published = true;
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
                const node = try chunks.next();
                const count = @min(items_per_chunk, values.len - index);
                const bytes = node.getRoot(self.state.pool);
                for (0..count) |i| {
                    ST.Element.tree.toValuePackedFromBytes(bytes, i, &values[index + i]);
                }
                index += count;
            }
            return values;
        }

        /// Reads committed elements. Call commit before creating an iterator over pending writes.
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
            node: ?Node.Id = null,

            pub fn next(self: *ReadonlyIterator) !Element {
                if (self.index >= self.chunks.view._orig_len) return error.InvalidLength;
                const node = self.node orelse try self.chunks.next();
                self.node = node;
                var value: Element = undefined;
                try ST.Element.tree.toValuePacked(
                    node,
                    self.chunks.view.state.pool,
                    self.index % items_per_chunk,
                    &value,
                );
                self.index += 1;
                if (self.index % items_per_chunk == 0) self.node = null;
                return value;
            }
        };

        const ChunkIterator = struct {
            view: *const Self,
            index: usize,
            subtree_end: usize = 0,
            gindex: Gindex = @enumFromInt(0),
            iterator: Node.DepthIterator = undefined,

            fn init(view: *const Self, start_index: usize) ChunkIterator {
                return .{ .view = view, .index = start_index };
            }

            fn next(self: *ChunkIterator) !Node.Id {
                const pool = self.view.state.pool;
                if (self.index >= self.subtree_end) {
                    const subtree = subtreeIndex(self.index);
                    const start = subtreeStart(subtree);
                    const depth: Depth = @intCast(2 * subtree);
                    const root = if (subtree < subtreeCount(chunkCount(self.view._orig_len)))
                        try self.view.state.root.getNode(pool, subtreeGindex(subtree))
                    else
                        @as(Node.Id, @enumFromInt(depth));
                    self.iterator = Node.DepthIterator.init(pool, root, depth, self.index - start);
                    self.subtree_end = start + (@as(usize, 1) << depth);
                    self.gindex = chunkGindex(self.index);
                }
                const committed = try self.iterator.next();
                const node = if (self.view.state.changed.count() == 0)
                    committed
                else
                    self.view.state.children_nodes.get(self.gindex) orelse committed;
                self.index += 1;
                self.gindex = @enumFromInt(@intFromEnum(self.gindex) + 1);
                return node;
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
            const depth: Depth = @intCast(2 * subtree);
            const offset = chunk_index - subtreeStart(subtree);
            var prefixes: [max_subtrees]Node.Id = undefined;
            var spine = try self.state.root.getLeft(pool);
            for (0..subtree) |i| {
                prefixes[i] = try spine.getLeft(pool);
                spine = try spine.getRight(pool);
            }
            const root = try spine.getLeft(pool);
            const boundary = try root.getNodeAtDepth(pool, depth, offset);
            var bytes = boundary.getRoot(pool).*;
            @memset(bytes[(index % items_per_chunk + 1) * ST.Element.fixed_size ..], 0);

            const leaf = try pool.createLeaf(&bytes);
            try pool.ref(leaf);
            defer pool.unref(leaf);

            const updated = try root.setNodeAtDepth(pool, depth, offset, leaf);
            try pool.ref(updated);
            defer pool.unref(updated);

            const trimmed = try updated.truncateAfterIndex(pool, depth, offset);
            try pool.ref(trimmed);
            defer pool.unref(trimmed);

            var contents = try pool.createBranch(trimmed, @enumFromInt(0));
            defer pool.unref(contents);

            var i = subtree;
            while (i > 0) {
                i -= 1;
                contents = try pool.createBranch(prefixes[i], contents);
            }

            var length_node: ?Node.Id = try pool.createLeafFromUint(index + 1);
            defer if (length_node) |node| pool.unref(node);

            const sliced = try pool.createBranch(contents, length_node.?);
            // The new root owns contents; its initialization must clean up that root on failure.
            contents = @enumFromInt(0);
            length_node = null;
            errdefer pool.unref(sliced);
            return Self.init(self.allocator, pool, sliced);
        }

        /// Replaces an initialized, caller-owned value only on success; use its owning allocator.
        pub fn toValue(self: *Self, allocator: Allocator, out: *ST.Type) !void {
            try self.commit();
            var replacement: ST.Type = .empty;
            errdefer replacement.deinit(allocator);
            try replacement.resize(allocator, self._len);
            _ = try self.getAllInto(replacement.items);
            out.deinit(allocator);
            out.* = replacement;
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

        fn getChunk(self: *Self, index: usize) !Node.Id {
            if (self.cached_chunk) |cached| {
                if (cached.index == index) return cached.node;
            }
            const gindex = chunkGindex(index);
            const node = self.state.children_nodes.get(gindex) orelse
                if (index >= chunkCount(self._orig_len))
                    @as(Node.Id, @enumFromInt(0))
                else
                    try self.state.getChildNode(gindex);
            self.cached_chunk = .{
                .index = index,
                .node = node,
                .dirty = self.state.changed.contains(gindex),
            };
            return node;
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

        fn chunkGindex(index: usize) Gindex {
            const subtree = subtreeIndex(index);
            const prefix = @intFromEnum(subtreeGindex(subtree)) << @intCast(2 * subtree);
            return @enumFromInt(prefix + index - subtreeStart(subtree));
        }
    };

    assertTreeViewType(TreeView);
    return TreeView;
}

test {
    _ = @import("progressive_list_basic_test.zig");
}
