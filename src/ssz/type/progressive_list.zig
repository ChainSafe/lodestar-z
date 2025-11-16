const std = @import("std");
const TypeKind = @import("type_kind.zig").TypeKind;
const isBasicType = @import("type_kind.zig").isBasicType;
const isFixedType = @import("type_kind.zig").isFixedType;
const OffsetIterator = @import("offsets.zig").OffsetIterator;
const mixInLength = @import("hashing").mixInLength;
const maxChunksToDepth = @import("hashing").maxChunksToDepth;
const Depth = @import("hashing").Depth;
const Node = @import("persistent_merkle_tree").Node;
const progressive = @import("progressive.zig");

pub fn FixedProgressiveListType(comptime ST: type) type {
    comptime {
        if (!isFixedType(ST)) {
            @compileError("ST must be fixed type");
        }
    }

    return struct {
        pub const kind = TypeKind.progressive_list;
        pub const Element: type = ST;
        pub const Type: type = std.ArrayListUnmanaged(Element.Type);
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
            value.deinit(allocator);
        }

        pub fn chunkCount(value: *const Type) usize {
            if (comptime isBasicType(Element)) {
                return (Element.fixed_size * value.items.len + 31) / 32;
            } else return value.items.len;
        }

        pub fn hashTreeRoot(allocator: std.mem.Allocator, value: *const Type, out: *[32]u8) !void {
            const chunks = try allocator.alloc([32]u8, chunkCount(value));
            defer allocator.free(chunks);

            @memset(chunks, [_]u8{0} ** 32);

            if (comptime isBasicType(Element)) {
                _ = serializeIntoBytes(value, @ptrCast(chunks));
            } else {
                for (value.items, 0..) |element, i| {
                    try Element.hashTreeRoot(&element, &chunks[i]);
                }
            }

            try progressive.merkleizeChunks(allocator, chunks, out);
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
            switch (try source.next()) {
                .array_begin => {},
                else => return error.InvalidJson,
            }

            var i: usize = 0;
            while (true) : (i += 1) {
                switch (try source.peekNextTokenType()) {
                    .array_end => {
                        _ = try source.next();
                        return;
                    },
                    else => {},
                }

                try out.append(allocator, Element.default_value);
                try Element.deserializeFromJson(source, &out.items[i]);
            }
            return error.invalidLength;
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

            pub fn hashTreeRoot(allocator: std.mem.Allocator, data: []const u8, out: *[32]u8) !void {
                const len = try length(data);

                const chunk_count = if (comptime isBasicType(Element))
                    (Element.fixed_size * len + 31) / 32
                else
                    len;
                const chunks = try allocator.alloc([32]u8, chunk_count);
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

                try progressive.merkleizeChunks(allocator, chunks, out);
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
                try out.resize(allocator, len);
                @memset(out.items, Element.default_value);

                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);

                const contents_node = try node.getLeft(pool);
                try progressive.getNodes(pool, contents_node, nodes);

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

            pub fn fromValue(allocator: std.mem.Allocator, pool: *Node.Pool, value: *const Type) !Node.Id {
                const len = value.items.len;
                const chunk_count = chunkCount(value);

                if (chunk_count == 0) {
                    return try pool.createBranch(
                        @enumFromInt(0),
                        try pool.createLeafFromUint(0, false),
                        false,
                    );
                }

                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);
                if (comptime isBasicType(Element)) {
                    const items_per_chunk = 32 / Element.fixed_size;
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

                        nodes[i] = try pool.createLeaf(&leaf_buf, false);
                    }
                } else {
                    for (0..chunk_count) |i| {
                        nodes[i] = try Element.tree.fromValue(pool, &value.items[i]);
                    }
                }

                const contents_tree = try progressive.fillWithContents(allocator, pool, nodes, false);
                const length_leaf = try pool.createLeafFromUint(len, false);
                const result = try pool.createBranch(
                    contents_tree,
                    length_leaf,
                    false,
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
        pub const Type: type = std.ArrayListUnmanaged(Element.Type);
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
            const chunks = try allocator.alloc([32]u8, chunkCount(value));
            defer allocator.free(chunks);

            @memset(chunks, [_]u8{0} ** 32);

            for (value.items, 0..) |element, i| {
                try Element.hashTreeRoot(allocator, &element, &chunks[i]);
            }
            try progressive.merkleizeChunks(allocator, chunks, out);
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

                const chunks = try allocator.alloc([32]u8, chunk_count);
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
                try progressive.merkleizeChunks(allocator, chunks, out);
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

            pub fn toValue(allocator: std.mem.Allocator, node: Node.Id, pool: *Node.Pool, out: *Type) !void {
                const len = try length(node, pool);
                const chunk_count = len;
                if (chunk_count == 0) {
                    try out.resize(allocator, 0);
                    return;
                }

                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);

                try progressive.getNodes(pool, try node.getLeft(pool), nodes);

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

            pub fn fromValue(allocator: std.mem.Allocator, pool: *Node.Pool, value: *const Type) !Node.Id {
                const len = value.items.len;
                const chunk_count = len;
                if (chunk_count == 0) {
                    return try pool.createBranch(
                        @enumFromInt(0),
                        try pool.createLeafFromUint(0, false),
                        false,
                    );
                }

                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);
                for (0..chunk_count) |i| {
                    nodes[i] = try Element.tree.fromValue(allocator, pool, &value.items[i]);
                }

                return try pool.createBranch(
                    try progressive.fillWithContents(allocator, pool, nodes, false),
                    try pool.createLeafFromUint(len, false),
                    false,
                );
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

            var i: usize = 0;
            while (true) : (i += 1) {
                switch (try source.peekNextTokenType()) {
                    .array_end => {
                        _ = try source.next();
                        return;
                    },
                    else => {},
                }

                try out.append(allocator, Element.default_value);
                try Element.deserializeFromJson(allocator, source, &out.items[i]);
            }
            return error.invalidLength;
        }
    };
}

const UintType = @import("uint.zig").UintType;
const BoolType = @import("bool.zig").BoolType;

test "ListType - sanity" {
    const allocator = std.testing.allocator;

    const Bytes = FixedProgressiveListType(UintType(8));

    var b: Bytes.Type = Bytes.default_value;
    defer b.deinit(allocator);
    try b.append(allocator, 5);

    const b_buf = try allocator.alloc(u8, Bytes.serializedSize(&b));
    defer allocator.free(b_buf);

    _ = Bytes.serializeIntoBytes(&b, b_buf);
    try Bytes.deserializeFromBytes(allocator, b_buf, &b);

    const BytesBytes = VariableProgressiveListType(Bytes);
    var b2: BytesBytes.Type = BytesBytes.default_value;
    defer b2.deinit(allocator);
    const b_elem: Bytes.Type = Bytes.default_value;
    try b2.append(allocator, b_elem);

    const b2_buf = try allocator.alloc(u8, BytesBytes.serializedSize(&b2));
    defer allocator.free(b2_buf);

    _ = BytesBytes.serializeIntoBytes(&b2, b2_buf);
    try BytesBytes.deserializeFromBytes(allocator, b2_buf, &b2);
}
