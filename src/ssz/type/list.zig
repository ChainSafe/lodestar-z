const std = @import("std");
const expectEqualRootsAlloc = @import("test_utils.zig").expectEqualRootsAlloc;
const expectEqualSerializedAlloc = @import("test_utils.zig").expectEqualSerializedAlloc;
const TypeKind = @import("type_kind.zig").TypeKind;
const isBasicType = @import("type_kind.zig").isBasicType;
const isFixedType = @import("type_kind.zig").isFixedType;
const OffsetIterator = @import("offsets.zig").OffsetIterator;
const merkleize = @import("hashing").merkleize;
const mixInLength = @import("hashing").mixInLength;
const maxChunksToDepth = @import("hashing").maxChunksToDepth;
const Node = @import("persistent_merkle_tree").Node;
const tree_view = @import("../tree_view/root.zig");
const ListBasicTreeView = tree_view.ListBasicTreeView;
const ListCompositeTreeView = tree_view.ListCompositeTreeView;

pub fn FixedListType(comptime ST: type, comptime _limit: comptime_int) type {
    comptime {
        if (!isFixedType(ST)) {
            @compileError("ST must be fixed type");
        }
        if (_limit <= 0) {
            @compileError("limit must be greater than 0");
        }
    }
    return struct {
        pub const kind = TypeKind.list;
        pub const Element: type = ST;
        pub const limit: usize = _limit;
        pub const Type: type = std.ArrayListUnmanaged(Element.Type);
        pub const TreeView: type = if (isBasicType(Element))
            ListBasicTreeView(@This())
        else
            ListCompositeTreeView(@This());
        pub const min_size: usize = 0;
        pub const max_size: usize = Element.fixed_size * limit;
        pub const max_chunk_count: usize = if (isBasicType(Element)) std.math.divCeil(usize, max_size, 32) catch unreachable else limit;
        pub const chunk_depth: u8 = maxChunksToDepth(max_chunk_count);

        pub const default_value: Type = Type.empty;

        pub fn equals(a: *const Type, b: *const Type) bool {
            if (a.items.len != b.items.len) {
                return false;
            }
            for (a.items, b.items) |a_elem, b_elem| {
                if (!Element.equals(&a_elem, &b_elem)) {
                    return false;
                }
            }
            return true;
        }

        pub fn deinit(allocator: std.mem.Allocator, value: *Type) void {
            value.deinit(allocator);
        }

        pub fn chunkIndex(index: usize) usize {
            if (comptime isBasicType(Element)) {
                return (index * Element.fixed_size) / 32;
            } else return index;
        }

        pub fn chunkCount(value: *const Type) usize {
            if (comptime isBasicType(Element)) {
                return (Element.fixed_size * value.items.len + 31) / 32;
            } else return value.items.len;
        }

        pub fn hashTreeRoot(allocator: std.mem.Allocator, value: *const Type, out: *[32]u8) !void {
            const chunks = try allocator.alloc([32]u8, (chunkCount(value) + 1) / 2 * 2);
            defer allocator.free(chunks);

            @memset(chunks, [_]u8{0} ** 32);

            if (comptime isBasicType(Element)) {
                _ = serializeIntoBytes(value, @ptrCast(chunks));
            } else {
                for (value.items, 0..) |element, i| {
                    try Element.hashTreeRoot(&element, &chunks[i]);
                }
            }
            try merkleize(@ptrCast(chunks), chunk_depth, out);
            mixInLength(value.items.len, out);
        }

        /// Clones the underlying `ArrayList`.
        ///
        /// Caller owns the memory.
        pub fn clone(allocator: std.mem.Allocator, value: *const Type, out: *Type) !void {
            try out.resize(allocator, value.items.len);

            for (value.items, 0..) |v, i| {
                try Element.clone(&v, &out.items[i]);
            }
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
            const len = try std.math.divExact(usize, data.len, Element.fixed_size);
            if (len > limit) {
                return error.gtLimit;
            }

            try out.resize(allocator, len);
            @memset(out.items[0..len], Element.default_value);
            for (0..len) |i| {
                try Element.deserializeFromBytes(
                    data[i * Element.fixed_size .. (i + 1) * Element.fixed_size],
                    &out.items[i],
                );
            }
        }

        pub fn serializeIntoJson(_: std.mem.Allocator, writer: anytype, in: *const Type) !void {
            try writer.beginArray();
            for (in.items) |element| {
                try Element.serializeIntoJson(writer, &element);
            }
            try writer.endArray();
        }

        pub fn deserializeFromJson(allocator: std.mem.Allocator, source: *std.json.Scanner, out: *Type) !void {
            // start array token "["
            switch (try source.next()) {
                .array_begin => {},
                else => return error.InvalidJson,
            }

            for (0..limit + 1) |i| {
                switch (try source.peekNextTokenType()) {
                    .array_end => {
                        _ = try source.next();
                        return;
                    },
                    else => {},
                }

                _ = try out.addOne(allocator);
                out.items[i] = Element.default_value;
                try Element.deserializeFromJson(source, &out.items[i]);
            }
            return error.invalidLength;
        }

        pub const serialized = struct {
            pub fn validate(data: []const u8) !void {
                const len = try std.math.divExact(usize, data.len, Element.fixed_size);
                if (len > limit) {
                    return error.gtLimit;
                }
                for (0..len) |i| {
                    try Element.serialized.validate(data[i * Element.fixed_size .. (i + 1) * Element.fixed_size]);
                }
            }

            pub fn length(data: []const u8) !usize {
                const len = try std.math.divExact(usize, data.len, Element.fixed_size);
                if (len > limit) {
                    return error.gtLimit;
                }
                return len;
            }

            pub fn hashTreeRoot(allocator: std.mem.Allocator, data: []const u8, out: *[32]u8) !void {
                const len = try length(data);

                const chunk_count = if (comptime isBasicType(Element))
                    (Element.fixed_size * len + 31) / 32
                else
                    len;
                const chunks = try allocator.alloc([32]u8, (chunk_count + 1) / 2 * 2);
                defer allocator.free(chunks);

                @memset(chunks, [_]u8{0} ** 32);

                if (comptime isBasicType(Element)) {
                    @memcpy(@as([]u8, @ptrCast(chunks))[0..data.len], data);
                } else {
                    for (0..len) |i| {
                        try Element.serialized.hashTreeRoot(
                            data[i * Element.fixed_size .. (i + 1) * Element.fixed_size],
                            &chunks[i],
                        );
                    }
                }
                try merkleize(@ptrCast(chunks), chunk_depth, out);
                mixInLength(len, out);
            }
        };

        pub const tree = struct {
            pub fn deserializeFromBytes(pool: *Node.Pool, data: []const u8) !Node.Id {
                const len = try std.math.divExact(usize, data.len, Element.fixed_size);
                if (len > limit) {
                    return error.gtLimit;
                }

                const chunk_count = if (comptime isBasicType(Element))
                    (Element.fixed_size * len + 31) / 32
                else
                    len;

                if (chunk_count == 0) {
                    return try pool.createBranch(
                        @enumFromInt(chunk_depth),
                        @enumFromInt(0),
                    );
                }

                var it = Node.FillWithContentsIterator.init(pool, chunk_depth);
                errdefer it.deinit();

                if (comptime isBasicType(Element)) {
                    for (0..chunk_count - 1) |i| {
                        var chunk: [32]u8 = undefined;
                        @memcpy(chunk[0..32], data[i * 32 ..][0..32]);
                        try it.append(try pool.createLeaf(&chunk));
                    }
                    {
                        // last chunk may be partial
                        var chunk = [_]u8{0} ** 32;
                        const i = chunk_count - 1;
                        const remaining_bytes = (len * Element.fixed_size) - i * 32;
                        @memcpy(chunk[0..remaining_bytes], data[i * 32 ..][0..remaining_bytes]);
                        try it.append(try pool.createLeaf(&chunk));
                    }
                } else {
                    for (0..len) |i| {
                        const elem_bytes = data[i * Element.fixed_size .. (i + 1) * Element.fixed_size];
                        try it.append(try Element.tree.deserializeFromBytes(pool, elem_bytes));
                    }
                }

                const content_root = try it.finish();
                errdefer pool.unref(content_root);
                const len_mixin = try pool.createLeafFromUint(len);
                errdefer pool.unref(len_mixin);

                return try pool.createBranch(content_root, len_mixin);
            }

            pub fn length(node: Node.Id, pool: *Node.Pool) !usize {
                const right = try node.getRight(pool);
                const hash = right.getRoot(pool);
                return std.mem.readInt(usize, hash[0..8], .little);
            }

            pub fn toValue(allocator: std.mem.Allocator, node: Node.Id, pool: *Node.Pool, out: *Type) !void {
                const len = try length(node, pool);
                const chunk_count = if (comptime isBasicType(Element))
                    (Element.fixed_size * len + 31) / 32
                else
                    len;

                if (chunk_count == 0) {
                    try out.resize(allocator, 0);
                    return;
                }

                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);

                try node.getNodesAtDepth(pool, chunk_depth + 1, 0, nodes);

                try out.resize(allocator, len);
                @memset(out.items, Element.default_value);
                if (comptime isBasicType(Element)) {
                    // tightly packed list
                    for (0..len) |i| {
                        try Element.tree.toValuePacked(
                            nodes[i * Element.fixed_size / 32],
                            pool,
                            i,
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

            pub fn fromValue(pool: *Node.Pool, value: *const Type) !Node.Id {
                const len = value.items.len;
                const chunk_count = chunkCount(value);
                if (chunk_count == 0) {
                    return try pool.createBranch(
                        @enumFromInt(chunk_depth),
                        @enumFromInt(0),
                    );
                }

                var it = Node.FillWithContentsIterator.init(pool, chunk_depth);
                errdefer it.deinit();

                if (comptime isBasicType(Element)) {
                    const items_per_chunk = 32 / Element.fixed_size;
                    var next: usize = 0; // index in value.items

                    for (0..chunk_count) |_| {
                        var leaf_buf = [_]u8{0} ** 32;

                        // how many items still remain to be packed into this chunk?
                        const remaining = len - next;
                        const to_write = @min(remaining, items_per_chunk);

                        // serialise exactly to_write elements into the 32‑byte buffer
                        for (0..to_write) |j| {
                            const dst_off = j * Element.fixed_size;
                            const dst_slice = leaf_buf[dst_off .. dst_off + Element.fixed_size];
                            _ = Element.serializeIntoBytes(&value.items[next + j], dst_slice);
                        }
                        next += to_write;

                        try it.append(try pool.createLeaf(&leaf_buf));
                    }
                } else {
                    for (0..chunk_count) |i| {
                        try it.append(try Element.tree.fromValue(pool, &value.items[i]));
                    }
                }

                const content_root = try it.finish();
                errdefer pool.unref(content_root);
                const len_mixin = try pool.createLeafFromUint(len);
                errdefer pool.unref(len_mixin);

                return try pool.createBranch(content_root, len_mixin);
            }

            pub fn serializeIntoBytes(node: Node.Id, pool: *Node.Pool, out: []u8) !usize {
                const len = try length(node, pool);
                if (len == 0) {
                    return 0;
                }

                const chunk_count = if (comptime isBasicType(Element))
                    (Element.fixed_size * len + 31) / 32
                else
                    len;

                var it = Node.DepthIterator.init(pool, node, chunk_depth + 1, 0);

                if (comptime isBasicType(Element)) {
                    const serialized_size = len * Element.fixed_size;
                    for (0..chunk_count) |i| {
                        const start_idx = i * 32;
                        const remaining_bytes = serialized_size - start_idx;
                        const bytes_to_copy = @min(remaining_bytes, 32);
                        if (bytes_to_copy > 0) {
                            @memcpy(out[start_idx..][0..bytes_to_copy], (try it.next()).getRoot(pool)[0..bytes_to_copy]);
                        }
                    }
                    return serialized_size;
                } else {
                    var offset: usize = 0;
                    for (0..len) |_| {
                        offset += try Element.tree.serializeIntoBytes((try it.next()), pool, out[offset..]);
                    }
                    return offset;
                }
            }

            pub fn serializedSize(node: Node.Id, pool: *Node.Pool) !usize {
                const len = try length(node, pool);
                return len * Element.fixed_size;
            }
        };
    };
}

pub fn VariableListType(comptime ST: type, comptime _limit: comptime_int) type {
    comptime {
        if (isFixedType(ST)) {
            @compileError("ST must not be fixed type");
        }
        if (_limit <= 0) {
            @compileError("limit must be greater than 0");
        }
    }
    return struct {
        const Self = @This();
        pub const kind = TypeKind.list;
        pub const Element: type = ST;
        pub const limit: usize = _limit;
        pub const Type: type = std.ArrayListUnmanaged(Element.Type);
        pub const TreeView: type = if (isBasicType(Element))
            ListBasicTreeView(@This())
        else
            ListCompositeTreeView(@This());
        pub const min_size: usize = 0;
        pub const max_size: usize = Element.max_size * limit + 4 * limit;
        pub const max_chunk_count: usize = limit;
        pub const chunk_depth: u8 = maxChunksToDepth(max_chunk_count);

        pub const default_value: Type = Type.empty;

        pub fn equals(a: *const Type, b: *const Type) bool {
            if (a.items.len != b.items.len) {
                return false;
            }
            for (a.items, b.items) |a_elem, b_elem| {
                if (!Element.equals(&a_elem, &b_elem)) {
                    return false;
                }
            }
            return true;
        }

        pub fn deinit(allocator: std.mem.Allocator, value: *Type) void {
            for (value.items) |*element| {
                Element.deinit(allocator, element);
            }
            value.deinit(allocator);
        }

        /// Clones the underlying `ArrayList`.
        ///
        /// Caller owns the memory.
        pub fn clone(allocator: std.mem.Allocator, value: *const Type, out: *Type) !void {
            try out.resize(allocator, value.items.len);
            for (0..value.items.len) |i|
                try Element.clone(allocator, &value.items[i], &out.items[i]);
        }

        pub fn chunkCount(value: *const Type) usize {
            return value.items.len;
        }

        pub fn hashTreeRoot(allocator: std.mem.Allocator, value: *const Type, out: *[32]u8) !void {
            const chunks = try allocator.alloc([32]u8, (chunkCount(value) + 1) / 2 * 2);
            defer allocator.free(chunks);

            @memset(chunks, [_]u8{0} ** 32);

            for (value.items, 0..) |element, i| {
                try Element.hashTreeRoot(allocator, &element, &chunks[i]);
            }
            try merkleize(@ptrCast(chunks), chunk_depth, out);
            mixInLength(value.items.len, out);
        }

        pub fn serializedSize(value: *const Type) usize {
            // offsets size
            var size: usize = value.items.len * 4;
            // element sizes
            for (value.items) |element| {
                size += Element.serializedSize(&element);
            }
            return size;
        }

        pub fn serializeIntoBytes(value: *const Type, out: []u8) usize {
            var variable_index = value.items.len * 4;
            for (value.items, 0..) |element, i| {
                // write offset
                std.mem.writeInt(u32, out[i * 4 ..][0..4], @intCast(variable_index), .little);
                // write element data
                variable_index += Element.serializeIntoBytes(&element, out[variable_index..]);
            }
            return variable_index;
        }

        pub fn serializeIntoJson(allocator: std.mem.Allocator, writer: anytype, in: *const Type) !void {
            try writer.beginArray();
            for (in.items) |element| {
                try Element.serializeIntoJson(allocator, writer, &element);
            }
            try writer.endArray();
        }

        pub fn deserializeFromBytes(allocator: std.mem.Allocator, data: []const u8, out: *Type) !void {
            const offsets = try readVariableOffsets(allocator, data);
            defer allocator.free(offsets);

            const len = offsets.len - 1;

            try out.resize(allocator, len);
            @memset(out.items[0..len], Element.default_value);
            for (0..len) |i| {
                try Element.deserializeFromBytes(
                    allocator,
                    data[offsets[i]..offsets[i + 1]],
                    &out.items[i],
                );
            }
        }

        pub fn readVariableOffsets(allocator: std.mem.Allocator, data: []const u8) ![]u32 {
            var iterator = OffsetIterator(Self).init(data);
            const first_offset = if (data.len == 0) 0 else try iterator.next();
            const len = first_offset / 4;

            const offsets = try allocator.alloc(u32, len + 1);

            offsets[0] = first_offset;
            while (iterator.pos < len) {
                offsets[iterator.pos] = try iterator.next();
            }
            offsets[len] = @intCast(data.len);

            return offsets;
        }

        pub const serialized = struct {
            pub fn validate(data: []const u8) !void {
                var iterator = OffsetIterator(Self).init(data);
                if (data.len == 0) return;
                const first_offset = try iterator.next();
                const len = first_offset / 4;

                var curr_offset = first_offset;
                var prev_offset = first_offset;
                while (iterator.pos < len) {
                    prev_offset = curr_offset;
                    curr_offset = try iterator.next();

                    try Element.serialized.validate(data[prev_offset..curr_offset]);
                }
                try Element.serialized.validate(data[curr_offset..data.len]);
            }

            pub fn length(data: []const u8) !usize {
                if (data.len == 0) {
                    return 0;
                }
                var iterator = OffsetIterator(Self).init(data);
                return try iterator.firstOffset() / 4;
            }

            pub fn hashTreeRoot(allocator: std.mem.Allocator, data: []const u8, out: *[32]u8) !void {
                const len = try length(data);
                const chunk_count = len;

                const chunks = try allocator.alloc([32]u8, (chunk_count + 1) / 2 * 2);
                defer allocator.free(chunks);
                @memset(chunks, [_]u8{0} ** 32);

                const offsets = try readVariableOffsets(allocator, data);
                defer allocator.free(offsets);

                for (0..len) |i| {
                    try Element.serialized.hashTreeRoot(
                        allocator,
                        data[offsets[i]..offsets[i + 1]],
                        &chunks[i],
                    );
                }
                try merkleize(@ptrCast(chunks), chunk_depth, out);
                mixInLength(len, out);
            }
        };

        pub const tree = struct {
            pub fn deserializeFromBytes(pool: *Node.Pool, data: []const u8) !Node.Id {
                var iterator = OffsetIterator(Self).init(data);
                const first_offset = if (data.len == 0) 0 else try iterator.next();
                const len = first_offset / 4;

                if (len > limit) {
                    return error.gtLimit;
                }

                const chunk_count = len;
                if (chunk_count == 0) {
                    return try pool.createBranch(
                        @enumFromInt(chunk_depth),
                        @enumFromInt(0),
                    );
                }

                var it = Node.FillWithContentsIterator.init(pool, chunk_depth);
                errdefer it.deinit();

                var offset = first_offset;
                for (0..len - 1) |_| {
                    const next_offset = try iterator.next();
                    const elem_bytes = data[offset..next_offset];
                    offset = next_offset;
                    try it.append(try Element.tree.deserializeFromBytes(pool, elem_bytes));
                }
                {
                    const elem_bytes = data[offset..data.len];
                    try it.append(try Element.tree.deserializeFromBytes(pool, elem_bytes));
                }

                const content_root = try it.finish();
                errdefer pool.unref(content_root);
                const len_mixin = try pool.createLeafFromUint(len);
                errdefer pool.unref(len_mixin);

                return try pool.createBranch(content_root, len_mixin);
            }

            pub fn length(node: Node.Id, pool: *Node.Pool) !usize {
                const right = try node.getRight(pool);
                const hash = right.getRoot(pool);
                return std.mem.readInt(usize, hash[0..8], .little);
            }

            pub fn toValue(allocator: std.mem.Allocator, node: Node.Id, pool: *Node.Pool, out: *Type) !void {
                const len = try length(node, pool);
                const chunk_count = len;
                if (chunk_count == 0) {
                    try out.resize(allocator, 0);
                    return;
                }

                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);

                try node.getNodesAtDepth(pool, chunk_depth + 1, 0, nodes);

                try out.resize(allocator, len);
                @memset(out.items, Element.default_value);
                for (0..len) |i| {
                    try Element.tree.toValue(
                        allocator,
                        nodes[i],
                        pool,
                        &out.items[i],
                    );
                }
            }

            pub fn fromValue(pool: *Node.Pool, value: *const Type) !Node.Id {
                const len = value.items.len;
                const chunk_count = len;
                if (chunk_count == 0) {
                    return try pool.createBranch(
                        @enumFromInt(chunk_depth),
                        @enumFromInt(0),
                    );
                }

                var it = Node.FillWithContentsIterator.init(pool, chunk_depth);
                errdefer it.deinit();

                for (0..chunk_count) |i| {
                    try it.append(try Element.tree.fromValue(pool, &value.items[i]));
                }

                const content_root = try it.finish();
                errdefer pool.unref(content_root);
                const len_mixin = try pool.createLeafFromUint(len);
                errdefer pool.unref(len_mixin);

                return try pool.createBranch(content_root, len_mixin);
            }

            pub fn serializeIntoBytes(node: Node.Id, pool: *Node.Pool, out: []u8) !usize {
                const len = try length(node, pool);
                if (len == 0) {
                    return 0;
                }

                var it = Node.DepthIterator.init(pool, node, chunk_depth + 1, 0);

                const fixed_end = len * 4;
                var variable_index = fixed_end;

                for (0..len) |i| {
                    std.mem.writeInt(u32, out[i * 4 ..][0..4], @intCast(variable_index), .little);
                    variable_index += try Element.tree.serializeIntoBytes((try it.next()), pool, out[variable_index..]);
                }

                return variable_index;
            }

            pub fn serializedSize(node: Node.Id, pool: *Node.Pool) !usize {
                const len = try length(node, pool);
                if (len == 0) {
                    return 0;
                }

                var it = Node.DepthIterator.init(pool, node, chunk_depth + 1, 0);

                var total_size: usize = len * 4; // Offsets
                for (0..len) |_| {
                    total_size += try Element.tree.serializedSize((try it.next()), pool);
                }
                return total_size;
            }
        };

        pub fn deserializeFromJson(allocator: std.mem.Allocator, source: *std.json.Scanner, out: *Type) !void {
            // start array token "["
            switch (try source.next()) {
                .array_begin => {},
                else => return error.InvalidJson,
            }

            for (0..limit + 1) |i| {
                switch (try source.peekNextTokenType()) {
                    .array_end => {
                        _ = try source.next();
                        return;
                    },
                    else => {},
                }

                _ = try out.addOne(allocator);
                out.items[i] = Element.default_value;
                try Element.deserializeFromJson(allocator, source, &out.items[i]);
            }
            return error.invalidLength;
        }
    };
}

const UintType = @import("uint.zig").UintType;
const BoolType = @import("bool.zig").BoolType;
const ByteVectorType = @import("byte_vector.zig").ByteVectorType;
const FixedContainerType = @import("container.zig").FixedContainerType;

test "ListType - sanity" {
    const allocator = std.testing.allocator;

    // create a fixed list type and instance and round-trip serialize
    const Bytes = FixedListType(UintType(8), 32);

    var b: Bytes.Type = Bytes.default_value;
    defer b.deinit(allocator);
    try b.append(allocator, 5);

    const b_buf = try allocator.alloc(u8, Bytes.serializedSize(&b));
    defer allocator.free(b_buf);

    _ = Bytes.serializeIntoBytes(&b, b_buf);
    try Bytes.deserializeFromBytes(allocator, b_buf, &b);

    // create a variable list type and instance and round-trip serialize
    const BytesBytes = VariableListType(Bytes, 32);
    var bb: BytesBytes.Type = BytesBytes.default_value;
    defer bb.deinit(allocator);
    const b2: Bytes.Type = Bytes.default_value;
    try bb.append(allocator, b2);

    const bb_buf = try allocator.alloc(u8, BytesBytes.serializedSize(&bb));
    defer allocator.free(bb_buf);

    _ = BytesBytes.serializeIntoBytes(&bb, bb_buf);
    try BytesBytes.deserializeFromBytes(allocator, bb_buf, &bb);
}

test "clone" {
    const allocator = std.testing.allocator;
    const BytesFixed = FixedListType(UintType(8), 32);
    const BytesVariable = VariableListType(BytesFixed, 32);

    var b: BytesFixed.Type = BytesFixed.default_value;
    defer b.deinit(allocator);
    try b.append(allocator, 5);
    var cloned: BytesFixed.Type = BytesFixed.default_value;
    try BytesFixed.clone(allocator, &b, &cloned);
    defer cloned.deinit(allocator);
    try std.testing.expect(&b != &cloned);
    try std.testing.expect(std.mem.eql(u8, b.items[0..], cloned.items[0..]));
    try expectEqualRootsAlloc(BytesFixed, allocator, b, cloned);
    try expectEqualSerializedAlloc(BytesFixed, allocator, b, cloned);

    var bv: BytesVariable.Type = BytesVariable.default_value;
    defer bv.deinit(allocator);
    const bb: BytesFixed.Type = BytesFixed.default_value;
    try bv.append(allocator, bb);
    var cloned_v: BytesVariable.Type = BytesVariable.default_value;
    try BytesVariable.clone(allocator, &bv, &cloned_v);
    defer cloned_v.deinit(allocator);
    try std.testing.expect(&bv != &cloned_v);
    try expectEqualRootsAlloc(BytesVariable, allocator, bv, cloned_v);
    try expectEqualSerializedAlloc(BytesVariable, allocator, bv, cloned_v);
    // TODO(bing): Equals test
}

// Tests ported from TypeScript ssz packages/ssz/test/unit/byType/listBasic/valid.test.ts
test "FixedListType - tree roundtrip (ListBasic uint8)" {
    const allocator = std.testing.allocator;

    const ListU8 = FixedListType(UintType(8), 128);

    const TestCase = struct {
        id: []const u8,
        values: []const u8,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty",
            .values = &[_]u8{},
            // 0x28ba1834a3a7b657460ce79fa3a1d909ab8828fd557659d4d0554a9bdbc0ec30
            .expected_root = [_]u8{ 0x28, 0xba, 0x18, 0x34, 0xa3, 0xa7, 0xb6, 0x57, 0x46, 0x0c, 0xe7, 0x9f, 0xa3, 0xa1, 0xd9, 0x09, 0xab, 0x88, 0x28, 0xfd, 0x55, 0x76, 0x59, 0xd4, 0xd0, 0x55, 0x4a, 0x9b, 0xdb, 0xc0, 0xec, 0x30 },
        },
        .{
            .id = "4 values",
            .values = &[_]u8{ 1, 2, 3, 4 },
            // 0xbac511d1f641d6b8823200bb4b3cced3bd4720701f18571dff35a5d2a40190fa
            .expected_root = [_]u8{ 0xba, 0xc5, 0x11, 0xd1, 0xf6, 0x41, 0xd6, 0xb8, 0x82, 0x32, 0x00, 0xbb, 0x4b, 0x3c, 0xce, 0xd3, 0xbd, 0x47, 0x20, 0x70, 0x1f, 0x18, 0x57, 0x1d, 0xff, 0x35, 0xa5, 0xd2, 0xa4, 0x01, 0x90, 0xfa },
        },
    };

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    for (test_cases) |tc| {
        var value: ListU8.Type = ListU8.default_value;
        defer value.deinit(allocator);
        for (tc.values) |v| {
            try value.append(allocator, v);
        }

        const serialized = try allocator.alloc(u8, ListU8.serializedSize(&value));
        defer allocator.free(serialized);
        _ = ListU8.serializeIntoBytes(&value, serialized);

        const tree_node = try ListU8.tree.fromValue(&pool, &value);

        var value_from_tree: ListU8.Type = ListU8.default_value;
        defer value_from_tree.deinit(allocator);
        try ListU8.tree.toValue(allocator, tree_node, &pool, &value_from_tree);

        try std.testing.expectEqual(value.items.len, value_from_tree.items.len);
        try std.testing.expectEqualSlices(u8, value.items, value_from_tree.items);

        const tree_size = try ListU8.tree.serializedSize(tree_node, &pool);
        try std.testing.expectEqual(serialized.len, tree_size);

        const tree_serialized = try allocator.alloc(u8, tree_size);
        defer allocator.free(tree_serialized);
        _ = try ListU8.tree.serializeIntoBytes(tree_node, &pool, tree_serialized);
        try std.testing.expectEqualSlices(u8, serialized, tree_serialized);

        var hash_root: [32]u8 = undefined;
        try ListU8.hashTreeRoot(allocator, &value, &hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "FixedListType - tree roundtrip (ListBasic uint64)" {
    const allocator = std.testing.allocator;

    const ListU64 = FixedListType(UintType(64), 128);

    const TestCase = struct {
        id: []const u8,
        values: []const u64,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty",
            .values = &[_]u64{},
            // 0x52e2647abc3d0c9d3be0387f3f0d925422c7a4e98cf4489066f0f43281a899f3
            .expected_root = [_]u8{ 0x52, 0xe2, 0x64, 0x7a, 0xbc, 0x3d, 0x0c, 0x9d, 0x3b, 0xe0, 0x38, 0x7f, 0x3f, 0x0d, 0x92, 0x54, 0x22, 0xc7, 0xa4, 0xe9, 0x8c, 0xf4, 0x48, 0x90, 0x66, 0xf0, 0xf4, 0x32, 0x81, 0xa8, 0x99, 0xf3 },
        },
        .{
            .id = "4 values",
            .values = &[_]u64{ 100000, 200000, 300000, 400000 },
            // 0xd1daef215502b7746e5ff3e8833e399cb249ab3f81d824be60e174ff5633c1bf
            .expected_root = [_]u8{ 0xd1, 0xda, 0xef, 0x21, 0x55, 0x02, 0xb7, 0x74, 0x6e, 0x5f, 0xf3, 0xe8, 0x83, 0x3e, 0x39, 0x9c, 0xb2, 0x49, 0xab, 0x3f, 0x81, 0xd8, 0x24, 0xbe, 0x60, 0xe1, 0x74, 0xff, 0x56, 0x33, 0xc1, 0xbf },
        },
        .{
            .id = "8 values",
            .values = &[_]u64{ 100000, 200000, 300000, 400000, 100000, 200000, 300000, 400000 },
            // 0xb55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1
            .expected_root = [_]u8{ 0xb5, 0x5b, 0x85, 0x92, 0xbc, 0xac, 0x47, 0x59, 0x06, 0x63, 0x14, 0x81, 0xbb, 0xc7, 0x46, 0xbc, 0xa7, 0x33, 0x9d, 0x04, 0xab, 0x10, 0x85, 0xe8, 0x48, 0x84, 0xa7, 0x00, 0xc0, 0x3d, 0xe4, 0xb1 },
        },
    };

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    for (test_cases) |tc| {
        var value: ListU64.Type = ListU64.default_value;
        defer value.deinit(allocator);
        for (tc.values) |v| {
            try value.append(allocator, v);
        }

        const serialized = try allocator.alloc(u8, ListU64.serializedSize(&value));
        defer allocator.free(serialized);
        _ = ListU64.serializeIntoBytes(&value, serialized);

        const tree_node = try ListU64.tree.fromValue(&pool, &value);

        var value_from_tree: ListU64.Type = ListU64.default_value;
        defer value_from_tree.deinit(allocator);
        try ListU64.tree.toValue(allocator, tree_node, &pool, &value_from_tree);

        try std.testing.expectEqual(value.items.len, value_from_tree.items.len);
        try std.testing.expectEqualSlices(u64, value.items, value_from_tree.items);

        const tree_size = try ListU64.tree.serializedSize(tree_node, &pool);
        const tree_serialized = try allocator.alloc(u8, tree_size);
        defer allocator.free(tree_serialized);
        _ = try ListU64.tree.serializeIntoBytes(tree_node, &pool, tree_serialized);
        try std.testing.expectEqualSlices(u8, serialized, tree_serialized);

        var hash_root: [32]u8 = undefined;
        try ListU64.hashTreeRoot(allocator, &value, &hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "FixedListType - serializeIntoBytes (ListComposite ByteVector32 - empty)" {
    const allocator = std.testing.allocator;
    const ByteVector32 = ByteVectorType(32);
    const ListBV32 = FixedListType(ByteVector32, 128);

    var value: ListBV32.Type = ListBV32.default_value;

    const expected_serialized = [_]u8{};
    const expected_root = [_]u8{ 0x96, 0x55, 0x96, 0x74, 0xa7, 0x96, 0x56, 0xe5, 0x40, 0x87, 0x1e, 0x1f, 0x39, 0xc9, 0xb9, 0x1e, 0x15, 0x2a, 0xa8, 0xcd, 0xdb, 0x71, 0x49, 0x3e, 0x75, 0x48, 0x27, 0xc4, 0xcc, 0x80, 0x9d, 0x57 };

    const size = ListBV32.serializedSize(&value);
    try std.testing.expectEqual(@as(usize, 0), size);
    const serialized = try allocator.alloc(u8, size);
    defer allocator.free(serialized);
    const written = ListBV32.serializeIntoBytes(&value, serialized);
    try std.testing.expectEqual(@as(usize, 0), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, serialized);

    var root: [32]u8 = undefined;
    try ListBV32.hashTreeRoot(allocator, &value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try ListBV32.tree.fromValue(&pool, &value);
    const tree_size = try ListBV32.tree.serializedSize(node, &pool);
    try std.testing.expectEqual(@as(usize, 0), tree_size);
    const tree_serialized = try allocator.alloc(u8, tree_size);
    defer allocator.free(tree_serialized);
    _ = try ListBV32.tree.serializeIntoBytes(node, &pool, tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, tree_serialized);
}

test "FixedListType - serializeIntoBytes (ListComposite ByteVector32 - 2 roots)" {
    const allocator = std.testing.allocator;
    const ByteVector32 = ByteVectorType(32);
    const ListBV32 = FixedListType(ByteVector32, 128);

    var value: ListBV32.Type = ListBV32.default_value;
    defer value.deinit(allocator);
    // [0xdddd...dd, 0xeeee...ee]
    try value.append(allocator, [_]u8{0xdd} ** 32);
    try value.append(allocator, [_]u8{0xee} ** 32);

    // 0xddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
    const expected_serialized = [_]u8{0xdd} ** 32 ++ [_]u8{0xee} ** 32;
    const expected_root = [_]u8{ 0x0c, 0xb9, 0x47, 0x37, 0x7e, 0x17, 0x7f, 0x77, 0x47, 0x19, 0xea, 0xd8, 0xd2, 0x10, 0xaf, 0x9c, 0x64, 0x61, 0xf4, 0x1b, 0xaf, 0x5b, 0x40, 0x82, 0xf8, 0x6a, 0x39, 0x11, 0x45, 0x48, 0x31, 0xb8 };

    const size = ListBV32.serializedSize(&value);
    try std.testing.expectEqual(@as(usize, 64), size);
    const serialized = try allocator.alloc(u8, size);
    defer allocator.free(serialized);
    const written = ListBV32.serializeIntoBytes(&value, serialized);
    try std.testing.expectEqual(@as(usize, 64), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, serialized);

    var root: [32]u8 = undefined;
    try ListBV32.hashTreeRoot(allocator, &value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try ListBV32.tree.fromValue(&pool, &value);
    const tree_size = try ListBV32.tree.serializedSize(node, &pool);
    try std.testing.expectEqual(@as(usize, 64), tree_size);
    const tree_serialized = try allocator.alloc(u8, tree_size);
    defer allocator.free(tree_serialized);
    _ = try ListBV32.tree.serializeIntoBytes(node, &pool, tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, tree_serialized);
}

test "FixedListType - serializeIntoBytes (ListComposite Container - empty)" {
    const allocator = std.testing.allocator;
    const Container = FixedContainerType(struct {
        a: UintType(64),
        b: UintType(64),
    });
    const ListContainer = FixedListType(Container, 128);

    var value: ListContainer.Type = ListContainer.default_value;

    const expected_serialized = [_]u8{};
    const expected_root = [_]u8{ 0x96, 0x55, 0x96, 0x74, 0xa7, 0x96, 0x56, 0xe5, 0x40, 0x87, 0x1e, 0x1f, 0x39, 0xc9, 0xb9, 0x1e, 0x15, 0x2a, 0xa8, 0xcd, 0xdb, 0x71, 0x49, 0x3e, 0x75, 0x48, 0x27, 0xc4, 0xcc, 0x80, 0x9d, 0x57 };

    const size = ListContainer.serializedSize(&value);
    try std.testing.expectEqual(@as(usize, 0), size);
    const serialized = try allocator.alloc(u8, size);
    defer allocator.free(serialized);
    const written = ListContainer.serializeIntoBytes(&value, serialized);
    try std.testing.expectEqual(@as(usize, 0), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, serialized);

    var root: [32]u8 = undefined;
    try ListContainer.hashTreeRoot(allocator, &value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try ListContainer.tree.fromValue(&pool, &value);
    const tree_size = try ListContainer.tree.serializedSize(node, &pool);
    try std.testing.expectEqual(@as(usize, 0), tree_size);
    const tree_serialized = try allocator.alloc(u8, tree_size);
    defer allocator.free(tree_serialized);
    _ = try ListContainer.tree.serializeIntoBytes(node, &pool, tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, tree_serialized);
}

test "FixedListType - serializeIntoBytes (ListComposite Container - 2 values)" {
    const allocator = std.testing.allocator;
    const Container = FixedContainerType(struct {
        a: UintType(64),
        b: UintType(64),
    });
    const ListContainer = FixedListType(Container, 128);

    var value: ListContainer.Type = ListContainer.default_value;
    defer value.deinit(allocator);
    // [{a: 0, b: 0}, {a: 123456, b: 654321}]
    try value.append(allocator, .{ .a = 0, .b = 0 });
    try value.append(allocator, .{ .a = 123456, .b = 654321 });

    // 0x0000000000000000000000000000000040e2010000000000f1fb090000000000
    const expected_serialized = [_]u8{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // a = 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // b = 0
        0x40, 0xe2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // a = 123456
        0xf1, 0xfb, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, // b = 654321
    };
    const expected_root = [_]u8{ 0x8f, 0xf9, 0x4c, 0x10, 0xd3, 0x9f, 0xfa, 0x84, 0xaa, 0x93, 0x7e, 0x2a, 0x07, 0x72, 0x39, 0xc2, 0x74, 0x2c, 0xb4, 0x25, 0xa2, 0xa1, 0x61, 0x74, 0x4a, 0x3e, 0x98, 0x76, 0xeb, 0x3c, 0x72, 0x10 };

    const size = ListContainer.serializedSize(&value);
    try std.testing.expectEqual(@as(usize, 32), size);
    const serialized = try allocator.alloc(u8, size);
    defer allocator.free(serialized);
    const written = ListContainer.serializeIntoBytes(&value, serialized);
    try std.testing.expectEqual(@as(usize, 32), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, serialized);

    var root: [32]u8 = undefined;
    try ListContainer.hashTreeRoot(allocator, &value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try ListContainer.tree.fromValue(&pool, &value);
    const tree_size = try ListContainer.tree.serializedSize(node, &pool);
    try std.testing.expectEqual(@as(usize, 32), tree_size);
    const tree_serialized = try allocator.alloc(u8, tree_size);
    defer allocator.free(tree_serialized);
    _ = try ListContainer.tree.serializeIntoBytes(node, &pool, tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, tree_serialized);
}

test "VariableListType - serializeIntoBytes (List<List<uint16>> - empty)" {
    const allocator = std.testing.allocator;
    const InnerList = FixedListType(UintType(16), 2);
    const OuterList = VariableListType(InnerList, 2);

    var value: OuterList.Type = OuterList.default_value;

    // empty list
    const expected_serialized = [_]u8{};
    const expected_root = [_]u8{ 0x7a, 0x05, 0x01, 0xf5, 0x95, 0x7b, 0xdf, 0x9c, 0xb3, 0xa8, 0xff, 0x49, 0x66, 0xf0, 0x22, 0x65, 0xf9, 0x68, 0x65, 0x8b, 0x7a, 0x9c, 0x62, 0x64, 0x2c, 0xba, 0x11, 0x65, 0xe8, 0x66, 0x42, 0xf5 };

    const size = OuterList.serializedSize(&value);
    try std.testing.expectEqual(@as(usize, 0), size);
    const serialized = try allocator.alloc(u8, size);
    defer allocator.free(serialized);
    const written = OuterList.serializeIntoBytes(&value, serialized);
    try std.testing.expectEqual(@as(usize, 0), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, serialized);

    var root: [32]u8 = undefined;
    try OuterList.hashTreeRoot(allocator, &value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try OuterList.tree.fromValue(&pool, &value);
    const tree_size = try OuterList.tree.serializedSize(node, &pool);
    try std.testing.expectEqual(@as(usize, 0), tree_size);
    const tree_serialized = try allocator.alloc(u8, tree_size);
    defer allocator.free(tree_serialized);
    _ = try OuterList.tree.serializeIntoBytes(node, &pool, tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, tree_serialized);
}

test "VariableListType - serializeIntoBytes (List<List<uint16>> - 2 full values)" {
    const allocator = std.testing.allocator;
    const InnerList = FixedListType(UintType(16), 2);
    const OuterList = VariableListType(InnerList, 2);

    var value: OuterList.Type = OuterList.default_value;
    defer OuterList.deinit(allocator, &value);
    // [[1, 2], [3, 4]]
    var inner1: InnerList.Type = InnerList.default_value;
    try inner1.appendSlice(allocator, &[_]u16{ 1, 2 });
    var inner2: InnerList.Type = InnerList.default_value;
    try inner2.appendSlice(allocator, &[_]u16{ 3, 4 });
    try value.append(allocator, inner1);
    try value.append(allocator, inner2);

    // 0x080000000c0000000100020003000400
    const expected_serialized = [_]u8{
        0x08, 0x00, 0x00, 0x00, // offset to inner1 (8)
        0x0c, 0x00, 0x00, 0x00, // offset to inner2 (12)
        0x01, 0x00, // 1
        0x02, 0x00, // 2
        0x03, 0x00, // 3
        0x04, 0x00, // 4
    };
    const expected_root = [_]u8{ 0x58, 0x14, 0x0d, 0x48, 0xf9, 0xc2, 0x45, 0x45, 0xc1, 0xe3, 0xa5, 0x0f, 0x1e, 0xbc, 0xca, 0x85, 0xfd, 0x40, 0x43, 0x3c, 0x98, 0x59, 0xc0, 0xac, 0x34, 0x34, 0x2f, 0xc8, 0xe0, 0xa8, 0x00, 0xb8 };

    const size = OuterList.serializedSize(&value);
    try std.testing.expectEqual(@as(usize, 16), size);
    const serialized = try allocator.alloc(u8, size);
    defer allocator.free(serialized);
    const written = OuterList.serializeIntoBytes(&value, serialized);
    try std.testing.expectEqual(@as(usize, 16), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, serialized);

    var root: [32]u8 = undefined;
    try OuterList.hashTreeRoot(allocator, &value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try OuterList.tree.fromValue(&pool, &value);
    const tree_size = try OuterList.tree.serializedSize(node, &pool);
    try std.testing.expectEqual(@as(usize, 16), tree_size);
    const tree_serialized = try allocator.alloc(u8, tree_size);
    defer allocator.free(tree_serialized);
    _ = try OuterList.tree.serializeIntoBytes(node, &pool, tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, tree_serialized);
}

test "VariableListType - serializeIntoBytes (List<List<uint16>> - 2 empty values)" {
    const allocator = std.testing.allocator;
    const InnerList = FixedListType(UintType(16), 2);
    const OuterList = VariableListType(InnerList, 2);

    var value: OuterList.Type = OuterList.default_value;
    defer OuterList.deinit(allocator, &value);
    // [[], []]
    const inner1: InnerList.Type = InnerList.default_value;
    const inner2: InnerList.Type = InnerList.default_value;
    try value.append(allocator, inner1);
    try value.append(allocator, inner2);

    // 0x0800000008000000
    const expected_serialized = [_]u8{
        0x08, 0x00, 0x00, 0x00, // offset to inner1 (8)
        0x08, 0x00, 0x00, 0x00, // offset to inner2 (8) - same offset since inner1 is empty
    };
    const expected_root = [_]u8{ 0xe8, 0x39, 0xa2, 0x27, 0x14, 0xbd, 0xa0, 0x59, 0x23, 0xb6, 0x11, 0xd0, 0x7b, 0xe9, 0x3b, 0x4d, 0x70, 0x70, 0x27, 0xd2, 0x9f, 0xd9, 0xee, 0xf7, 0xaa, 0x86, 0x4e, 0xd5, 0x87, 0xe4, 0x62, 0xec };

    const size = OuterList.serializedSize(&value);
    try std.testing.expectEqual(@as(usize, 8), size);
    const serialized = try allocator.alloc(u8, size);
    defer allocator.free(serialized);
    const written = OuterList.serializeIntoBytes(&value, serialized);
    try std.testing.expectEqual(@as(usize, 8), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, serialized);

    var root: [32]u8 = undefined;
    try OuterList.hashTreeRoot(allocator, &value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try OuterList.tree.fromValue(&pool, &value);
    const tree_size = try OuterList.tree.serializedSize(node, &pool);
    try std.testing.expectEqual(@as(usize, 8), tree_size);
    const tree_serialized = try allocator.alloc(u8, tree_size);
    defer allocator.free(tree_serialized);
    _ = try OuterList.tree.serializeIntoBytes(node, &pool, tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, tree_serialized);
}

test "FixedListType - tree.deserializeFromBytes (ListBasic uint8)" {
    const allocator = std.testing.allocator;

    const ListU8 = FixedListType(UintType(8), 128);

    const TestCase = struct {
        id: []const u8,
        serialized: []const u8,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty",
            .serialized = &[_]u8{},
            // 0x28ba1834a3a7b657460ce79fa3a1d909ab8828fd557659d4d0554a9bdbc0ec30
            .expected_root = [_]u8{ 0x28, 0xba, 0x18, 0x34, 0xa3, 0xa7, 0xb6, 0x57, 0x46, 0x0c, 0xe7, 0x9f, 0xa3, 0xa1, 0xd9, 0x09, 0xab, 0x88, 0x28, 0xfd, 0x55, 0x76, 0x59, 0xd4, 0xd0, 0x55, 0x4a, 0x9b, 0xdb, 0xc0, 0xec, 0x30 },
        },
        .{
            .id = "4 values",
            .serialized = &[_]u8{ 0x01, 0x02, 0x03, 0x04 },
            // 0xbac511d1f641d6b8823200bb4b3cced3bd4720701f18571dff35a5d2a40190fa
            .expected_root = [_]u8{ 0xba, 0xc5, 0x11, 0xd1, 0xf6, 0x41, 0xd6, 0xb8, 0x82, 0x32, 0x00, 0xbb, 0x4b, 0x3c, 0xce, 0xd3, 0xbd, 0x47, 0x20, 0x70, 0x1f, 0x18, 0x57, 0x1d, 0xff, 0x35, 0xa5, 0xd2, 0xa4, 0x01, 0x90, 0xfa },
        },
    };

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    for (test_cases) |tc| {
        const tree_node = try ListU8.tree.deserializeFromBytes(&pool, tc.serialized);

        var value_from_tree: ListU8.Type = ListU8.default_value;
        defer value_from_tree.deinit(allocator);
        try ListU8.tree.toValue(allocator, tree_node, &pool, &value_from_tree);

        try std.testing.expectEqual(tc.serialized.len, value_from_tree.items.len);
        try std.testing.expectEqualSlices(u8, tc.serialized, value_from_tree.items);

        const tree_size = try ListU8.tree.serializedSize(tree_node, &pool);
        try std.testing.expectEqual(tc.serialized.len, tree_size);
        const tree_serialized = try allocator.alloc(u8, tree_size);
        defer allocator.free(tree_serialized);
        _ = try ListU8.tree.serializeIntoBytes(tree_node, &pool, tree_serialized);
        try std.testing.expectEqualSlices(u8, tc.serialized, tree_serialized);

        var hash_root: [32]u8 = undefined;
        try ListU8.hashTreeRoot(allocator, &value_from_tree, &hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "FixedListType - tree.deserializeFromBytes (ListBasic uint64)" {
    const allocator = std.testing.allocator;

    const ListU64 = FixedListType(UintType(64), 128);

    const TestCase = struct {
        id: []const u8,
        serialized: []const u8,
        expected_values: []const u64,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty",
            .serialized = &[_]u8{},
            .expected_values = &[_]u64{},
            // 0x52e2647abc3d0c9d3be0387f3f0d925422c7a4e98cf4489066f0f43281a899f3
            .expected_root = [_]u8{ 0x52, 0xe2, 0x64, 0x7a, 0xbc, 0x3d, 0x0c, 0x9d, 0x3b, 0xe0, 0x38, 0x7f, 0x3f, 0x0d, 0x92, 0x54, 0x22, 0xc7, 0xa4, 0xe9, 0x8c, 0xf4, 0x48, 0x90, 0x66, 0xf0, 0xf4, 0x32, 0x81, 0xa8, 0x99, 0xf3 },
        },
        .{
            .id = "4 values",
            // 0xa086010000000000400d030000000000e093040000000000801a060000000000
            .serialized = &[_]u8{
                0xa0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // 100000
                0x40, 0x0d, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, // 200000
                0xe0, 0x93, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // 300000
                0x80, 0x1a, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, // 400000
            },
            .expected_values = &[_]u64{ 100000, 200000, 300000, 400000 },
            // 0xd1daef215502b7746e5ff3e8833e399cb249ab3f81d824be60e174ff5633c1bf
            .expected_root = [_]u8{ 0xd1, 0xda, 0xef, 0x21, 0x55, 0x02, 0xb7, 0x74, 0x6e, 0x5f, 0xf3, 0xe8, 0x83, 0x3e, 0x39, 0x9c, 0xb2, 0x49, 0xab, 0x3f, 0x81, 0xd8, 0x24, 0xbe, 0x60, 0xe1, 0x74, 0xff, 0x56, 0x33, 0xc1, 0xbf },
        },
        .{
            .id = "8 values",
            // 0xa086010000000000400d030000000000e093040000000000801a060000000000a086010000000000400d030000000000e093040000000000801a060000000000
            .serialized = &[_]u8{
                0xa0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // 100000
                0x40, 0x0d, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, // 200000
                0xe0, 0x93, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // 300000
                0x80, 0x1a, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, // 400000
                0xa0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // 100000
                0x40, 0x0d, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, // 200000
                0xe0, 0x93, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // 300000
                0x80, 0x1a, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, // 400000
            },
            .expected_values = &[_]u64{ 100000, 200000, 300000, 400000, 100000, 200000, 300000, 400000 },
            // 0xb55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1
            .expected_root = [_]u8{ 0xb5, 0x5b, 0x85, 0x92, 0xbc, 0xac, 0x47, 0x59, 0x06, 0x63, 0x14, 0x81, 0xbb, 0xc7, 0x46, 0xbc, 0xa7, 0x33, 0x9d, 0x04, 0xab, 0x10, 0x85, 0xe8, 0x48, 0x84, 0xa7, 0x00, 0xc0, 0x3d, 0xe4, 0xb1 },
        },
    };

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    for (test_cases) |tc| {
        const tree_node = try ListU64.tree.deserializeFromBytes(&pool, tc.serialized);

        var value_from_tree: ListU64.Type = ListU64.default_value;
        defer value_from_tree.deinit(allocator);
        try ListU64.tree.toValue(allocator, tree_node, &pool, &value_from_tree);

        try std.testing.expectEqual(tc.expected_values.len, value_from_tree.items.len);
        try std.testing.expectEqualSlices(u64, tc.expected_values, value_from_tree.items);

        const tree_size = try ListU64.tree.serializedSize(tree_node, &pool);
        try std.testing.expectEqual(tc.serialized.len, tree_size);
        const tree_serialized = try allocator.alloc(u8, tree_size);
        defer allocator.free(tree_serialized);
        _ = try ListU64.tree.serializeIntoBytes(tree_node, &pool, tree_serialized);
        try std.testing.expectEqualSlices(u8, tc.serialized, tree_serialized);

        var hash_root: [32]u8 = undefined;
        try ListU64.hashTreeRoot(allocator, &value_from_tree, &hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "FixedListType - tree.deserializeFromBytes (ListComposite ByteVector32)" {
    const allocator = std.testing.allocator;
    const ByteVector32 = ByteVectorType(32);
    const ListBV32 = FixedListType(ByteVector32, 128);

    const TestCase = struct {
        id: []const u8,
        serialized: []const u8,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty",
            .serialized = &[_]u8{},
            // 0x96559674a79656e540871e1f39c9b91e152aa8cddb71493e754827c4cc809d57
            .expected_root = [_]u8{ 0x96, 0x55, 0x96, 0x74, 0xa7, 0x96, 0x56, 0xe5, 0x40, 0x87, 0x1e, 0x1f, 0x39, 0xc9, 0xb9, 0x1e, 0x15, 0x2a, 0xa8, 0xcd, 0xdb, 0x71, 0x49, 0x3e, 0x75, 0x48, 0x27, 0xc4, 0xcc, 0x80, 0x9d, 0x57 },
        },
        .{
            .id = "2 roots",
            // 0xddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
            .serialized = &([_]u8{0xdd} ** 32 ++ [_]u8{0xee} ** 32),
            // 0x0cb947377e177f774719ead8d210af9c6461f41baf5b4082f86a3911454831b8
            .expected_root = [_]u8{ 0x0c, 0xb9, 0x47, 0x37, 0x7e, 0x17, 0x7f, 0x77, 0x47, 0x19, 0xea, 0xd8, 0xd2, 0x10, 0xaf, 0x9c, 0x64, 0x61, 0xf4, 0x1b, 0xaf, 0x5b, 0x40, 0x82, 0xf8, 0x6a, 0x39, 0x11, 0x45, 0x48, 0x31, 0xb8 },
        },
    };

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    for (test_cases) |tc| {
        const tree_node = try ListBV32.tree.deserializeFromBytes(&pool, tc.serialized);

        var value_from_tree: ListBV32.Type = ListBV32.default_value;
        defer value_from_tree.deinit(allocator);
        try ListBV32.tree.toValue(allocator, tree_node, &pool, &value_from_tree);

        try std.testing.expectEqual(tc.serialized.len / 32, value_from_tree.items.len);

        const tree_size = try ListBV32.tree.serializedSize(tree_node, &pool);
        try std.testing.expectEqual(tc.serialized.len, tree_size);
        const tree_serialized = try allocator.alloc(u8, tree_size);
        defer allocator.free(tree_serialized);
        _ = try ListBV32.tree.serializeIntoBytes(tree_node, &pool, tree_serialized);
        try std.testing.expectEqualSlices(u8, tc.serialized, tree_serialized);

        var hash_root: [32]u8 = undefined;
        try ListBV32.hashTreeRoot(allocator, &value_from_tree, &hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "FixedListType - tree.deserializeFromBytes (ListComposite Container)" {
    const allocator = std.testing.allocator;
    const Container = FixedContainerType(struct {
        a: UintType(64),
        b: UintType(64),
    });
    const ListContainer = FixedListType(Container, 128);

    const TestCase = struct {
        id: []const u8,
        serialized: []const u8,
        expected_values: []const Container.Type,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty",
            .serialized = &[_]u8{},
            .expected_values = &[_]Container.Type{},
            // 0x96559674a79656e540871e1f39c9b91e152aa8cddb71493e754827c4cc809d57
            .expected_root = [_]u8{ 0x96, 0x55, 0x96, 0x74, 0xa7, 0x96, 0x56, 0xe5, 0x40, 0x87, 0x1e, 0x1f, 0x39, 0xc9, 0xb9, 0x1e, 0x15, 0x2a, 0xa8, 0xcd, 0xdb, 0x71, 0x49, 0x3e, 0x75, 0x48, 0x27, 0xc4, 0xcc, 0x80, 0x9d, 0x57 },
        },
        .{
            .id = "2 values",
            // 0x0000000000000000000000000000000040e2010000000000f1fb090000000000
            .serialized = &[_]u8{
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // a = 0
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // b = 0
                0x40, 0xe2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // a = 123456
                0xf1, 0xfb, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, // b = 654321
            },
            .expected_values = &[_]Container.Type{
                .{ .a = 0, .b = 0 },
                .{ .a = 123456, .b = 654321 },
            },
            // 0x8ff94c10d39ffa84aa937e2a077239c2742cb425a2a161744a3e9876eb3c7210
            .expected_root = [_]u8{ 0x8f, 0xf9, 0x4c, 0x10, 0xd3, 0x9f, 0xfa, 0x84, 0xaa, 0x93, 0x7e, 0x2a, 0x07, 0x72, 0x39, 0xc2, 0x74, 0x2c, 0xb4, 0x25, 0xa2, 0xa1, 0x61, 0x74, 0x4a, 0x3e, 0x98, 0x76, 0xeb, 0x3c, 0x72, 0x10 },
        },
    };

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    for (test_cases) |tc| {
        const tree_node = try ListContainer.tree.deserializeFromBytes(&pool, tc.serialized);

        var value_from_tree: ListContainer.Type = ListContainer.default_value;
        defer value_from_tree.deinit(allocator);
        try ListContainer.tree.toValue(allocator, tree_node, &pool, &value_from_tree);

        try std.testing.expectEqual(tc.expected_values.len, value_from_tree.items.len);
        for (tc.expected_values, 0..) |expected, i| {
            try std.testing.expectEqual(expected.a, value_from_tree.items[i].a);
            try std.testing.expectEqual(expected.b, value_from_tree.items[i].b);
        }

        const tree_size = try ListContainer.tree.serializedSize(tree_node, &pool);
        try std.testing.expectEqual(tc.serialized.len, tree_size);
        const tree_serialized = try allocator.alloc(u8, tree_size);
        defer allocator.free(tree_serialized);
        _ = try ListContainer.tree.serializeIntoBytes(tree_node, &pool, tree_serialized);
        try std.testing.expectEqualSlices(u8, tc.serialized, tree_serialized);

        var hash_root: [32]u8 = undefined;
        try ListContainer.hashTreeRoot(allocator, &value_from_tree, &hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "VariableListType - tree.deserializeFromBytes (List<List<uint16>>)" {
    const allocator = std.testing.allocator;
    const InnerList = FixedListType(UintType(16), 2);
    const OuterList = VariableListType(InnerList, 2);

    const TestCase = struct {
        id: []const u8,
        serialized: []const u8,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty",
            .serialized = &[_]u8{},
            // 0x7a0501f5957bdf9cb3a8ff4966f02265f968658b7a9c62642cba1165e86642f5
            .expected_root = [_]u8{ 0x7a, 0x05, 0x01, 0xf5, 0x95, 0x7b, 0xdf, 0x9c, 0xb3, 0xa8, 0xff, 0x49, 0x66, 0xf0, 0x22, 0x65, 0xf9, 0x68, 0x65, 0x8b, 0x7a, 0x9c, 0x62, 0x64, 0x2c, 0xba, 0x11, 0x65, 0xe8, 0x66, 0x42, 0xf5 },
        },
        .{
            .id = "2 full values",
            // 0x080000000c0000000100020003000400
            .serialized = &[_]u8{
                0x08, 0x00, 0x00, 0x00, // offset to inner1 (8)
                0x0c, 0x00, 0x00, 0x00, // offset to inner2 (12)
                0x01, 0x00, // 1
                0x02, 0x00, // 2
                0x03, 0x00, // 3
                0x04, 0x00, // 4
            },
            // 0x58140d48f9c24545c1e3a50f1ebcca85fd40433c9859c0ac34342fc8e0a800b8
            .expected_root = [_]u8{ 0x58, 0x14, 0x0d, 0x48, 0xf9, 0xc2, 0x45, 0x45, 0xc1, 0xe3, 0xa5, 0x0f, 0x1e, 0xbc, 0xca, 0x85, 0xfd, 0x40, 0x43, 0x3c, 0x98, 0x59, 0xc0, 0xac, 0x34, 0x34, 0x2f, 0xc8, 0xe0, 0xa8, 0x00, 0xb8 },
        },
        .{
            .id = "2 empty values",
            // 0x0800000008000000
            .serialized = &[_]u8{
                0x08, 0x00, 0x00, 0x00, // offset to inner1 (8)
                0x08, 0x00, 0x00, 0x00, // offset to inner2 (8) - same offset since inner1 is empty
            },
            // 0xe839a22714bda05923b611d07be93b4d707027d29fd9eef7aa864ed587e462ec
            .expected_root = [_]u8{ 0xe8, 0x39, 0xa2, 0x27, 0x14, 0xbd, 0xa0, 0x59, 0x23, 0xb6, 0x11, 0xd0, 0x7b, 0xe9, 0x3b, 0x4d, 0x70, 0x70, 0x27, 0xd2, 0x9f, 0xd9, 0xee, 0xf7, 0xaa, 0x86, 0x4e, 0xd5, 0x87, 0xe4, 0x62, 0xec },
        },
    };

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    for (test_cases) |tc| {
        const tree_node = try OuterList.tree.deserializeFromBytes(&pool, tc.serialized);

        var value_from_tree: OuterList.Type = OuterList.default_value;
        defer OuterList.deinit(allocator, &value_from_tree);
        try OuterList.tree.toValue(allocator, tree_node, &pool, &value_from_tree);

        const tree_size = try OuterList.tree.serializedSize(tree_node, &pool);
        try std.testing.expectEqual(tc.serialized.len, tree_size);
        const tree_serialized = try allocator.alloc(u8, tree_size);
        defer allocator.free(tree_serialized);
        _ = try OuterList.tree.serializeIntoBytes(tree_node, &pool, tree_serialized);
        try std.testing.expectEqualSlices(u8, tc.serialized, tree_serialized);

        var hash_root: [32]u8 = undefined;
        try OuterList.hashTreeRoot(allocator, &value_from_tree, &hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

const TypeTestCase = @import("test_utils.zig").TypeTestCase;
const testCases = [_]TypeTestCase{
    .{ .id = "empty", .serializedHex = "0x", .json = "[]", .rootHex = "0x52e2647abc3d0c9d3be0387f3f0d925422c7a4e98cf4489066f0f43281a899f3" },
    .{ .id = "4 values", .serializedHex = "0xa086010000000000400d030000000000e093040000000000801a060000000000a086010000000000400d030000000000e093040000000000801a060000000000", .json = 
    \\["100000","200000","300000","400000","100000","200000","300000","400000"]
    , .rootHex = "0xb55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1" },
    .{
        .id = "8 values",
        .serializedHex = "0xa086010000000000400d030000000000e093040000000000801a060000000000a086010000000000400d030000000000e093040000000000801a060000000000",
        .json =
        \\["100000","200000","300000","400000","100000","200000","300000","400000"]
        ,
        .rootHex = "0xb55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1",
    },
};

test "valid test for ListBasicType" {
    const allocator = std.testing.allocator;

    // uint of 8 bytes = u64
    const Uint = UintType(64);
    const List = FixedListType(Uint, 128);

    const TypeTest = @import("test_utils.zig").typeTest(List);

    for (testCases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}

test "FixedListType equals" {
    const allocator = std.testing.allocator;
    const List = FixedListType(UintType(8), 32);

    var a: List.Type = List.Type.empty;
    var b: List.Type = List.Type.empty;
    var c: List.Type = List.Type.empty;

    defer a.deinit(allocator);
    defer b.deinit(allocator);
    defer c.deinit(allocator);

    try a.appendSlice(allocator, &[_]u8{ 1, 2, 3 });
    try b.appendSlice(allocator, &[_]u8{ 1, 2, 3 });
    try c.appendSlice(allocator, &[_]u8{ 1, 2 });

    try std.testing.expect(List.equals(&a, &b));
    try std.testing.expect(!List.equals(&a, &c));
}

test "ListCompositeType of Root" {
    const test_cases = [_]TypeTestCase{
        // refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/listComposite/valid.test.ts#L23
        .{
            .id = "2 roots",
            .serializedHex = "0xddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            .json =
            \\["0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"]
            ,
            .rootHex = "0x0cb947377e177f774719ead8d210af9c6461f41baf5b4082f86a3911454831b8",
        },
    };

    const allocator = std.testing.allocator;
    const ByteVector = ByteVectorType(32);
    const List = FixedListType(ByteVector, 128);

    const TypeTest = @import("test_utils.zig").typeTest(List);

    for (test_cases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}

test "ListCompositeType of Container" {
    const test_cases = [_]TypeTestCase{
        // refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/listComposite/valid.test.ts#L46
        .{
            .id = "2 values",
            .serializedHex = "0x0000000000000000000000000000000040e2010000000000f1fb090000000000",
            .json =
            \\[{"a":"0","b":"0"},{"a":"123456","b":"654321"}]
            ,
            .rootHex = "0x8ff94c10d39ffa84aa937e2a077239c2742cb425a2a161744a3e9876eb3c7210",
        },
    };

    const allocator = std.testing.allocator;
    const Uint = UintType(64);
    const Container = FixedContainerType(struct {
        a: Uint,
        b: Uint,
    });
    const List = FixedListType(Container, 128);

    const TypeTest = @import("test_utils.zig").typeTest(List);

    for (test_cases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}

test "VariableListType of FixedList" {
    // refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/listComposite/valid.test.ts#L59
    const test_cases = [_]TypeTestCase{
        .{
            .id = "empty",
            .serializedHex = "0x",
            .json =
            \\[]
            ,
            .rootHex = "0x7a0501f5957bdf9cb3a8ff4966f02265f968658b7a9c62642cba1165e86642f5",
        },
        .{
            .id = "2 full values",
            .serializedHex = "0x080000000c0000000100020003000400",
            .json =
            \\[["1","2"],["3","4"]]
            ,
            .rootHex = "0x58140d48f9c24545c1e3a50f1ebcca85fd40433c9859c0ac34342fc8e0a800b8",
        },
        .{
            .id = "2 empty values",
            .serializedHex = "0x0800000008000000",
            .json =
            \\[[],[]]
            ,
            .rootHex = "0xe839a22714bda05923b611d07be93b4d707027d29fd9eef7aa864ed587e462ec",
        },
    };

    const allocator = std.testing.allocator;
    const FixedList = FixedListType(UintType(16), 2);
    const List = VariableListType(FixedList, 2);

    const TypeTest = @import("test_utils.zig").typeTest(List);

    for (test_cases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}
