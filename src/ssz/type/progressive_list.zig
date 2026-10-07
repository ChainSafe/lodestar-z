const std = @import("std");
const TypeKind = @import("type_kind.zig").TypeKind;
const isBasicType = @import("type_kind.zig").isBasicType;
const isFixedType = @import("type_kind.zig").isFixedType;
const canMemcpySsz = @import("type_kind.zig").canMemcpySsz;
const VariableElementIterator = @import("variable_element_iterator.zig").VariableElementIterator;
const mixInLength = @import("hashing").mixInLength;
const Depth = @import("hashing").Depth;
const Node = @import("persistent_merkle_tree").Node;
const ChunkedLeaf = @import("persistent_merkle_tree").ChunkedLeaf;
const progressive = @import("progressive.zig");
const TypeOpts = @import("list.zig").TypeOpts;

pub fn FixedProgressiveListType(comptime ST: type) type {
    return FixedProgressiveListTypeWithOptions(ST, .{});
}

/// Chunked storage applies within subtrees of at least ChunkedLeaf.K chunks, preserving SSZ roots.
pub fn FixedProgressiveListTypeWithOptions(comptime ST: type, comptime _opts: TypeOpts) type {
    comptime {
        if (!isFixedType(ST)) {
            @compileError("ST must be fixed type");
        }
        if (_opts.chunked_leaf and !isBasicType(ST)) {
            @compileError("chunked_leaf requires basic elements");
        }
    }

    return struct {
        const Self = @This();
        pub const kind = TypeKind.progressive_list;
        pub const Element: type = ST;
        pub const opts = _opts;
        const use_chunked_leaf = opts.chunked_leaf;
        const items_per_chunk = 32 / Element.fixed_size;
        pub const Type: type = std.ArrayList(Element.Type);
        pub const min_size: usize = 0;
        pub const max_size: usize = std.math.maxInt(usize);

        pub const default_value: Type = Type.empty;

        pub const TreeView = if (isBasicType(Element))
            @import("../tree_view/progressive_list_basic.zig").ProgressiveListBasicTreeView(Self)
        else
            void;

        pub fn equals(a: *const Type, b: *const Type) bool {
            if (a.items.len != b.items.len) return false;
            for (a.items, b.items) |a_elem, b_elem| {
                if (!Element.equals(&a_elem, &b_elem)) return false;
            }
            return true;
        }

        pub fn deinit(allocator: std.mem.Allocator, value: *Type) void {
            value.deinit(allocator);
        }

        pub fn chunkCount(value: *const Type) usize {
            return chunkCountForLength(value.items.len);
        }

        fn chunkCountForLength(len: usize) usize {
            if (comptime isBasicType(Element)) {
                return len / items_per_chunk + @intFromBool(len % items_per_chunk != 0);
            } else return len;
        }

        pub fn hashTreeRoot(_: std.mem.Allocator, value: *const Type, out: *[32]u8) !void {
            var accumulator = try progressive.MerkleAccumulator.init(chunkCount(value));
            if (comptime isBasicType(Element)) {
                var index: usize = 0;
                while (index < value.items.len) {
                    var chunk: [32]u8 = @splat(0);
                    const count = @min(items_per_chunk, value.items.len - index);
                    for (value.items[index..][0..count], 0..) |*element, i| {
                        _ = Element.serializeIntoBytes(element, chunk[i * Element.fixed_size ..][0..Element.fixed_size]);
                    }
                    try accumulator.append(&chunk);
                    index += count;
                }
            } else {
                for (value.items) |*element| {
                    var chunk: [32]u8 = undefined;
                    try Element.hashTreeRoot(element, &chunk);
                    try accumulator.append(&chunk);
                }
            }
            try accumulator.finish(out);
            mixInLength(value.items.len, out);
        }

        pub fn serializedSize(value: *const Type) usize {
            return value.items.len * Element.fixed_size;
        }

        pub fn serializeIntoBytes(value: *const Type, out: []u8) usize {
            var i: usize = 0;
            for (value.items) |element| {
                i += Element.serializeIntoBytes(&element, out[i..]);
            }
            return i;
        }

        pub fn deserializeFromBytes(allocator: std.mem.Allocator, data: []const u8, out: *Type) !void {
            if (data.len % Element.fixed_size != 0) {
                return error.InvalidSSZ;
            }

            const len = data.len / Element.fixed_size;

            var replacement: Type = .empty;
            errdefer replacement.deinit(allocator);
            try replacement.resize(allocator, len);
            @memset(replacement.items, Element.default_value);
            for (0..len) |i| {
                try Element.deserializeFromBytes(
                    data[i * Element.fixed_size .. (i + 1) * Element.fixed_size],
                    &replacement.items[i],
                );
            }

            deinit(allocator, out);
            out.* = replacement;
        }

        pub fn serializeIntoJson(_: std.mem.Allocator, writer: anytype, in: *const Type) !void {
            try writer.beginArray();
            for (in.items) |element| {
                try Element.serializeIntoJson(writer, &element);
            }
            try writer.endArray();
        }

        pub fn deserializeFromJson(allocator: std.mem.Allocator, source: *std.json.Scanner, out: *Type) !void {
            switch (try source.next()) {
                .array_begin => {},
                else => return error.InvalidJson,
            }

            var replacement: Type = .empty;
            errdefer replacement.deinit(allocator);
            while ((try source.peekNextTokenType()) != .array_end) {
                try replacement.append(allocator, Element.default_value);
                try Element.deserializeFromJson(source, &replacement.items[replacement.items.len - 1]);
            }
            _ = try source.next();

            deinit(allocator, out);
            out.* = replacement;
        }

        pub const serialized = struct {
            pub fn validate(data: []const u8) !void {
                const len = std.math.divExact(usize, data.len, Element.fixed_size) catch {
                    return error.InvalidSSZ;
                };

                for (0..len) |i| {
                    try Element.serialized.validate(data[i * Element.fixed_size .. (i + 1) * Element.fixed_size]);
                }
            }

            pub fn length(data: []const u8) !usize {
                const len = std.math.divExact(usize, data.len, Element.fixed_size) catch {
                    return error.InvalidSSZ;
                };
                return len;
            }

            pub fn hashTreeRoot(_: std.mem.Allocator, data: []const u8, out: *[32]u8) !void {
                const len = try length(data);
                var accumulator = try progressive.MerkleAccumulator.init(chunkCountForLength(len));
                if (comptime isBasicType(Element)) {
                    var offset: usize = 0;
                    while (offset < data.len) {
                        var chunk: [32]u8 = @splat(0);
                        const count = @min(32, data.len - offset);
                        @memcpy(chunk[0..count], data[offset..][0..count]);
                        try accumulator.append(&chunk);
                        offset += count;
                    }
                } else {
                    for (0..len) |i| {
                        var chunk: [32]u8 = undefined;
                        try Element.serialized.hashTreeRoot(data[i * Element.fixed_size ..][0..Element.fixed_size], &chunk);
                        try accumulator.append(&chunk);
                    }
                }
                try accumulator.finish(out);
                mixInLength(len, out);
            }
        };

        pub const tree = struct {
            pub fn length(node: Node.Id, pool: *Node.Pool) !usize {
                const right = try node.getRight(pool);
                const hash = right.getRoot(pool);

                const len_u256 = std.mem.readInt(u256, hash[0..32], .little);
                const len = @as(usize, @intCast(@min(len_u256, std.math.maxInt(usize))));

                return len;
            }

            /// Decodes `values.len` packed elements from `bytes`, which start on a chunk boundary.
            pub fn toValuesPackedFromBytes(bytes: []const u8, values: []Element.Type) void {
                comptime std.debug.assert(isBasicType(Element));
                std.debug.assert(bytes.len % 32 == 0);
                std.debug.assert(bytes.len >= values.len * Element.fixed_size);
                if (comptime canMemcpySsz(Element)) {
                    const size = values.len * Element.fixed_size;
                    @memcpy(std.mem.sliceAsBytes(values), bytes[0..size]);
                } else if (comptime Element.kind == .bool) {
                    for (values, bytes[0..values.len]) |*value, byte| value.* = byte != 0;
                } else {
                    for (values, 0..) |*value, i| {
                        const chunk = bytes[i / items_per_chunk * 32 ..][0..32];
                        Element.tree.toValuePackedFromBytes(chunk, i, value);
                    }
                }
            }

            /// Fills `out` in place. The caller initializes `out` with `allocator` and keeps
            /// ownership; on error only its allocation stays valid.
            pub fn toValue(allocator: std.mem.Allocator, node: Node.Id, pool: *Node.Pool, out: *Type) !void {
                if (comptime use_chunked_leaf) {
                    const len = try length(node, pool);
                    var it = try progressive.NodeIterator.initChunkedLeaf(
                        pool,
                        try node.getLeft(pool),
                        chunkCountForLength(len),
                    );
                    try out.resize(allocator, len);
                    var index: usize = 0;
                    while (try it.nextBytes()) |bytes| {
                        const count = @min(bytes.len / Element.fixed_size, len - index);
                        toValuesPackedFromBytes(bytes, out.items[index..][0..count]);
                        index += count;
                    }
                    std.debug.assert(index == len);
                    return;
                }
                const len = try length(node, pool);
                const chunk_count = chunkCountForLength(len);
                if (chunk_count > progressive.max_tree_chunks) return error.InvalidSubtreeLength;

                if (chunk_count == 0) {
                    try out.resize(allocator, 0);
                    return;
                }

                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);

                const contents_node = try node.getLeft(pool);
                try progressive.getNodes(pool, contents_node, nodes);

                try out.resize(allocator, len);
                @memset(out.items, Element.default_value);
                if (comptime isBasicType(Element)) {
                    for (0..len) |i| {
                        const chunk_index = (i * Element.fixed_size) / 32;
                        const element_index = i % (32 / Element.fixed_size);
                        try Element.tree.toValuePacked(
                            nodes[chunk_index],
                            pool,
                            element_index,
                            &out.items[i],
                        );
                    }
                } else {
                    for (0..len) |i| {
                        try Element.tree.toValue(
                            nodes[i],
                            pool,
                            &out.items[i],
                        );
                    }
                }
            }

            pub fn serializedSize(node: Node.Id, pool: *Node.Pool) !usize {
                return std.math.mul(usize, try length(node, pool), Element.fixed_size);
            }

            pub fn serializeIntoBytes(node: Node.Id, pool: *Node.Pool, out: []u8) !usize {
                const len = try length(node, pool);
                const size = try std.math.mul(usize, len, Element.fixed_size);
                if (out.len < size) return error.InvalidSize;
                const chunk_count = chunkCountForLength(len);
                if (comptime use_chunked_leaf) {
                    var it = try progressive.NodeIterator.initChunkedLeaf(
                        pool,
                        try node.getLeft(pool),
                        chunk_count,
                    );
                    var offset: usize = 0;
                    while (try it.nextBytes()) |bytes| {
                        const count = @min(bytes.len, size - offset);
                        @memcpy(out[offset..][0..count], bytes[0..count]);
                        offset += count;
                    }
                    std.debug.assert(offset == size);
                    return size;
                }
                var it = try progressive.NodeIterator.init(pool, try node.getLeft(pool), chunk_count);
                var offset: usize = 0;
                while (try it.next()) |chunk| {
                    if (comptime isBasicType(Element)) {
                        const byte_count = @min(32, size - offset);
                        @memcpy(out[offset..][0..byte_count], chunk.getRoot(pool)[0..byte_count]);
                        offset += byte_count;
                    } else {
                        offset += try Element.tree.serializeIntoBytes(chunk, pool, out[offset..][0..Element.fixed_size]);
                    }
                }
                std.debug.assert(offset == size);
                return size;
            }

            pub fn deserializeFromBytes(pool: *Node.Pool, data: []const u8) !Node.Id {
                if (comptime use_chunked_leaf) {
                    try serialized.validate(data);
                    return buildChunkedLeaf(true, pool, data);
                }
                const allocator = pool.allocator;
                var value = Self.default_value;
                defer Self.deinit(allocator, &value);

                try Self.deserializeFromBytes(allocator, data, &value);
                return fromValue(pool, &value);
            }

            fn buildChunkedLeaf(
                comptime from_bytes: bool,
                pool: *Node.Pool,
                input: if (from_bytes) []const u8 else []const Element.Type,
            ) !Node.Id {
                const len = if (from_bytes) input.len / Element.fixed_size else input.len;
                const chunk_count = chunkCountForLength(len);
                if (chunk_count > progressive.max_tree_chunks) return error.InputTooLong;

                var roots: [progressive.max_tree_subtrees]Node.Id = undefined;
                var root_count: usize = 0;
                errdefer for (roots[0..root_count]) |root| pool.unref(root);

                var item_index: usize = 0;
                for (0..progressive.max_tree_subtrees) |subtree_index| {
                    if (item_index == len) break;
                    const depth: Depth = @intCast(2 * subtree_index);
                    const leaf_offset: Depth =
                        if (depth >= ChunkedLeaf.k_log2) ChunkedLeaf.k_log2 else 0;
                    const capacity = @as(usize, 1) << @intCast(depth);
                    const chunks_done = item_index / items_per_chunk;
                    const subtree_chunks = @min(capacity, chunk_count - chunks_done);
                    const chunks_per_leaf = @as(usize, 1) << @intCast(leaf_offset);
                    const leaf_count = (subtree_chunks + chunks_per_leaf - 1) / chunks_per_leaf;

                    var it = Node.FillWithContentsIterator.initWithOffset(
                        pool,
                        depth - leaf_offset,
                        leaf_offset,
                    );
                    errdefer it.deinit();

                    for (0..leaf_count) |_| {
                        const count = @min(chunks_per_leaf * items_per_chunk, len - item_index);
                        const size = count * Element.fixed_size;
                        const leaf_chunks = (count + items_per_chunk - 1) / items_per_chunk;
                        const leaf = if (leaf_offset == 0)
                            try pool.createLeaf(&@as([32]u8, @splat(0)))
                        else
                            try pool.createChunkedLeafEmpty(@intCast(leaf_chunks));
                        {
                            errdefer pool.unref(leaf);
                            const bytes: []u8 = if (leaf_offset == 0)
                                &pool.nodes.items(.root)[@intFromEnum(leaf)]
                            else
                                std.mem.asBytes(&(try leaf.getChunkedLeafPtr(pool)).chunks);
                            const out = bytes[0..size];
                            if (from_bytes) {
                                @memcpy(out, input[item_index * Element.fixed_size ..][0..size]);
                            } else if (comptime canMemcpySsz(Element)) {
                                @memcpy(out, std.mem.sliceAsBytes(input[item_index..][0..count]));
                            } else {
                                for (input[item_index..][0..count], 0..) |*element, i| {
                                    _ = Element.serializeIntoBytes(
                                        element,
                                        out[i * Element.fixed_size ..][0..Element.fixed_size],
                                    );
                                }
                            }
                        }
                        // append consumes the fresh node even if branch allocation fails.
                        try it.append(leaf);
                        item_index += count;
                    }
                    roots[root_count] = try it.finish();
                    root_count += 1;
                }
                std.debug.assert(item_index == len);

                var contents: Node.Id = @enumFromInt(0);
                errdefer pool.unref(contents);

                while (root_count > 0) {
                    contents = try pool.createBranch(roots[root_count - 1], contents);
                    root_count -= 1;
                }

                const length_leaf = try pool.createLeafFromUint(len);
                errdefer pool.unref(length_leaf);

                return pool.createBranch(contents, length_leaf);
            }

            pub fn fromValue(pool: *Node.Pool, value: *const Type) !Node.Id {
                if (comptime use_chunked_leaf) {
                    return buildChunkedLeaf(false, pool, value.items);
                }
                const allocator = pool.allocator;
                const len = value.items.len;
                const chunk_count = chunkCount(value);

                if (chunk_count == 0) {
                    const length_leaf = try pool.createLeafFromUint(0);
                    errdefer pool.unref(length_leaf);

                    return try pool.createBranch(@enumFromInt(0), length_leaf);
                }

                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);
                @memset(nodes, @as(Node.Id, @enumFromInt(0)));
                var content_owns_nodes = false;
                errdefer if (!content_owns_nodes) pool.free(nodes);
                if (comptime isBasicType(Element)) {
                    var next: usize = 0;

                    for (0..chunk_count) |i| {
                        var leaf_buf = [_]u8{0} ** 32;

                        const remaining = len - next;
                        const to_write = @min(remaining, items_per_chunk);

                        for (0..to_write) |j| {
                            const dst_off = j * Element.fixed_size;
                            const dst_slice = leaf_buf[dst_off .. dst_off + Element.fixed_size];
                            _ = Element.serializeIntoBytes(&value.items[next + j], dst_slice);
                        }
                        next += to_write;

                        nodes[i] = try pool.createLeaf(&leaf_buf);
                    }
                } else {
                    for (0..chunk_count) |i| {
                        nodes[i] = try Element.tree.fromValue(pool, &value.items[i]);
                    }
                }

                const contents_tree = try progressive.fillWithContents(allocator, pool, nodes);
                content_owns_nodes = true;
                errdefer pool.unref(contents_tree);

                const length_leaf = try pool.createLeafFromUint(len);
                errdefer pool.unref(length_leaf);

                const result = try pool.createBranch(
                    contents_tree,
                    length_leaf,
                );
                return result;
            }
        };
    };
}

pub fn VariableProgressiveListType(comptime ST: type) type {
    comptime {
        if (isFixedType(ST)) {
            @compileError("ST must not be fixed type");
        }
    }
    return struct {
        const Self = @This();
        pub const kind = TypeKind.progressive_list;
        pub const Element: type = ST;
        pub const Type: type = std.ArrayList(Element.Type);
        pub const min_size: usize = 0;
        pub const max_size: usize = std.math.maxInt(usize);

        pub const default_value: Type = Type.empty;

        pub fn equals(a: *const Type, b: *const Type) bool {
            if (a.items.len != b.items.len) return false;
            for (a.items, b.items) |a_elem, b_elem| {
                if (!Element.equals(&a_elem, &b_elem)) return false;
            }
            return true;
        }

        pub fn deinit(allocator: std.mem.Allocator, value: *Type) void {
            for (value.items) |*element| {
                Element.deinit(allocator, element);
            }
            value.deinit(allocator);
        }

        pub fn chunkCount(value: *const Type) usize {
            return value.items.len;
        }

        pub fn hashTreeRoot(allocator: std.mem.Allocator, value: *const Type, out: *[32]u8) !void {
            var accumulator = try progressive.MerkleAccumulator.init(value.items.len);
            for (value.items) |*element| {
                var chunk: [32]u8 = undefined;
                try Element.hashTreeRoot(allocator, element, &chunk);
                try accumulator.append(&chunk);
            }
            try accumulator.finish(out);
            mixInLength(value.items.len, out);
        }

        pub fn serializedSize(value: *const Type) usize {
            var size: usize = value.items.len * 4;
            for (value.items) |element| {
                size += Element.serializedSize(&element);
            }
            return size;
        }

        pub fn serializeIntoBytes(value: *const Type, out: []u8) usize {
            var variable_index = value.items.len * 4;
            for (value.items, 0..) |element, i| {
                std.mem.writeInt(u32, out[i * 4 ..][0..4], @intCast(variable_index), .little);
                variable_index += Element.serializeIntoBytes(&element, out[variable_index..]);
            }
            return variable_index;
        }

        pub fn deserializeFromBytes(allocator: std.mem.Allocator, data: []const u8, out: *Type) !void {
            var elements = try VariableElementIterator(Self).init(data);
            const len = elements.len;

            var replacement: Type = .empty;
            errdefer deinit(allocator, &replacement);
            try replacement.resize(allocator, len);
            @memset(replacement.items, Element.default_value);

            var i: usize = 0;
            while (try elements.next()) |element_bytes| : (i += 1) {
                try Element.deserializeFromBytes(
                    allocator,
                    element_bytes,
                    &replacement.items[i],
                );
            }
            std.debug.assert(i == len);

            deinit(allocator, out);
            out.* = replacement;
        }

        pub const serialized = struct {
            pub fn validate(data: []const u8) !void {
                var elements = try VariableElementIterator(Self).init(data);
                while (try elements.next()) |element_bytes| {
                    try Element.serialized.validate(element_bytes);
                }
            }

            pub fn length(data: []const u8) !usize {
                const elements = try VariableElementIterator(Self).init(data);
                return elements.len;
            }

            pub fn hashTreeRoot(allocator: std.mem.Allocator, data: []const u8, out: *[32]u8) !void {
                var elements = try VariableElementIterator(Self).init(data);
                var accumulator = try progressive.MerkleAccumulator.init(elements.len);
                while (try elements.next()) |element_bytes| {
                    var chunk: [32]u8 = undefined;
                    try Element.serialized.hashTreeRoot(allocator, element_bytes, &chunk);
                    try accumulator.append(&chunk);
                }
                try accumulator.finish(out);
                mixInLength(elements.len, out);
            }
        };

        pub const tree = struct {
            pub fn length(node: Node.Id, pool: *Node.Pool) !usize {
                const right = try node.getRight(pool);
                const hash = right.getRoot(pool);

                const len_u256 = std.mem.readInt(u256, hash[0..32], .little);
                const len = @as(usize, @intCast(@min(len_u256, std.math.maxInt(usize))));

                return len;
            }

            pub fn toValue(allocator: std.mem.Allocator, node: Node.Id, pool: *Node.Pool, out: *Type) !void {
                const len = try length(node, pool);
                const chunk_count = len;
                var replacement: Type = .empty;
                errdefer deinit(allocator, &replacement);
                if (chunk_count == 0) {
                    deinit(allocator, out);
                    out.* = replacement;
                    return;
                }

                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);

                try progressive.getNodes(pool, try node.getLeft(pool), nodes);

                try replacement.resize(allocator, len);
                @memset(replacement.items, Element.default_value);
                for (0..len) |i| {
                    try Element.tree.toValue(
                        allocator,
                        nodes[i],
                        pool,
                        &replacement.items[i],
                    );
                }

                deinit(allocator, out);
                out.* = replacement;
            }

            pub fn serializedSize(node: Node.Id, pool: *Node.Pool) !usize {
                const allocator = pool.allocator;
                var value = Self.default_value;
                defer Self.deinit(allocator, &value);

                try toValue(allocator, node, pool, &value);
                return Self.serializedSize(&value);
            }

            pub fn serializeIntoBytes(node: Node.Id, pool: *Node.Pool, out: []u8) !usize {
                const allocator = pool.allocator;
                var value = Self.default_value;
                defer Self.deinit(allocator, &value);

                try toValue(allocator, node, pool, &value);
                return Self.serializeIntoBytes(&value, out);
            }

            pub fn deserializeFromBytes(pool: *Node.Pool, data: []const u8) !Node.Id {
                const allocator = pool.allocator;
                var value = Self.default_value;
                defer Self.deinit(allocator, &value);

                try Self.deserializeFromBytes(allocator, data, &value);
                return fromValue(pool, &value);
            }

            pub fn fromValue(pool: *Node.Pool, value: *const Type) !Node.Id {
                const allocator = pool.allocator;
                const len = value.items.len;
                const chunk_count = len;
                if (chunk_count == 0) {
                    const length_leaf = try pool.createLeafFromUint(0);
                    errdefer pool.unref(length_leaf);

                    return try pool.createBranch(@enumFromInt(0), length_leaf);
                }

                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);
                @memset(nodes, @as(Node.Id, @enumFromInt(0)));
                var content_owns_nodes = false;
                errdefer if (!content_owns_nodes) pool.free(nodes);
                for (0..chunk_count) |i| {
                    nodes[i] = try Element.tree.fromValue(pool, &value.items[i]);
                }

                const contents_tree = try progressive.fillWithContents(allocator, pool, nodes);
                content_owns_nodes = true;
                errdefer pool.unref(contents_tree);

                const length_leaf = try pool.createLeafFromUint(len);
                errdefer pool.unref(length_leaf);

                return try pool.createBranch(contents_tree, length_leaf);
            }
        };

        pub fn serializeIntoJson(allocator: std.mem.Allocator, writer: anytype, in: *const Type) !void {
            try writer.beginArray();
            for (in.items) |element| {
                try Element.serializeIntoJson(allocator, writer, &element);
            }
            try writer.endArray();
        }

        pub fn deserializeFromJson(allocator: std.mem.Allocator, source: *std.json.Scanner, out: *Type) !void {
            switch (try source.next()) {
                .array_begin => {},
                else => return error.InvalidJson,
            }

            var replacement: Type = .empty;
            errdefer deinit(allocator, &replacement);
            while ((try source.peekNextTokenType()) != .array_end) {
                try replacement.append(allocator, Element.default_value);
                try Element.deserializeFromJson(
                    allocator,
                    source,
                    &replacement.items[replacement.items.len - 1],
                );
            }
            _ = try source.next();

            deinit(allocator, out);
            out.* = replacement;
        }
    };
}

test {
    _ = @import("progressive_list_test.zig");
}
