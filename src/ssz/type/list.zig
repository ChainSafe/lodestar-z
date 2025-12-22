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

            pub fn fromValue(allocator: std.mem.Allocator, pool: *Node.Pool, value: *const Type) !Node.Id {
                const len = value.items.len;
                const chunk_count = chunkCount(value);
                if (chunk_count == 0) {
                    return try pool.createBranch(
                        @enumFromInt(chunk_depth),
                        @enumFromInt(0),
                    );
                }

                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);
                if (comptime isBasicType(Element)) {
                    const items_per_chunk = 32 / Element.fixed_size;
                    var next: usize = 0; // index in value.items

                    for (0..chunk_count) |i| {
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

                        nodes[i] = try pool.createLeaf(&leaf_buf);
                    }
                } else {
                    for (0..chunk_count) |i| {
                        nodes[i] = try Element.tree.fromValue(pool, &value.items[i]);
                    }
                }
                return try pool.createBranch(
                    try Node.fillWithContents(pool, nodes, chunk_depth),
                    try pool.createLeafFromUint(len),
                );
            }

            pub fn serializeIntoBytes(allocator: std.mem.Allocator, node: Node.Id, pool: *Node.Pool, out: []u8) !usize {
                const len = try length(node, pool);
                if (len == 0) {
                    return 0;
                }

                const chunk_count = if (comptime isBasicType(Element))
                    (Element.fixed_size * len + 31) / 32
                else
                    len;

                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);
                try node.getNodesAtDepth(pool, chunk_depth + 1, 0, nodes);

                if (comptime isBasicType(Element)) {
                    const serialized_size = len * Element.fixed_size;
                    for (0..chunk_count) |i| {
                        const start_idx = i * 32;
                        const remaining_bytes = serialized_size - start_idx;
                        const bytes_to_copy = @min(remaining_bytes, 32);
                        if (bytes_to_copy > 0) {
                            @memcpy(out[start_idx..][0..bytes_to_copy], nodes[i].getRoot(pool)[0..bytes_to_copy]);
                        }
                    }
                    return serialized_size;
                } else {
                    var offset: usize = 0;
                    for (0..len) |i| {
                        offset += try Element.tree.serializeIntoBytes(nodes[i], pool, out[offset..]);
                    }
                    return offset;
                }
            }

            pub fn serializedSize(allocator: std.mem.Allocator, node: Node.Id, pool: *Node.Pool) !usize {
                const len = try length(node, pool);
                if (comptime isBasicType(Element)) {
                    return len * Element.fixed_size;
                } else {
                    const chunk_count = len;
                    if (chunk_count == 0) {
                        return 0;
                    }

                    const nodes = try allocator.alloc(Node.Id, chunk_count);
                    defer allocator.free(nodes);
                    try node.getNodesAtDepth(pool, chunk_depth + 1, 0, nodes);

                    var total_size: usize = 0;
                    for (0..len) |i| {
                        total_size += Element.tree.serializedSize(nodes[i], pool);
                    }
                    return total_size;
                }
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

            pub fn fromValue(allocator: std.mem.Allocator, pool: *Node.Pool, value: *const Type) !Node.Id {
                const len = value.items.len;
                const chunk_count = len;
                if (chunk_count == 0) {
                    return try pool.createBranch(
                        @enumFromInt(chunk_depth),
                        @enumFromInt(0),
                    );
                }

                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);
                for (0..chunk_count) |i| {
                    nodes[i] = try Element.tree.fromValue(allocator, pool, &value.items[i]);
                }
                return try pool.createBranch(
                    try Node.fillWithContents(pool, nodes, chunk_depth),
                    try pool.createLeafFromUint(len),
                );
            }

            pub fn serializeIntoBytes(allocator: std.mem.Allocator, node: Node.Id, pool: *Node.Pool, out: []u8) !usize {
                const len = try length(node, pool);
                if (len == 0) {
                    return 0;
                }

                const chunk_count = len;

                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);
                try node.getNodesAtDepth(pool, chunk_depth + 1, 0, nodes);

                const fixed_end = len * 4;
                var variable_index = fixed_end;

                for (0..len) |i| {
                    std.mem.writeInt(u32, out[i * 4 ..][0..4], @intCast(variable_index), .little);
                    variable_index += try Element.tree.serializeIntoBytes(allocator, nodes[i], pool, out[variable_index..]);
                }

                return variable_index;
            }

            pub fn serializedSize(allocator: std.mem.Allocator, node: Node.Id, pool: *Node.Pool) !usize {
                const len = try length(node, pool);
                if (len == 0) {
                    return 0;
                }

                const chunk_count = len;
                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);
                try node.getNodesAtDepth(pool, chunk_depth + 1, 0, nodes);

                var total_size: usize = len * 4; // Offsets
                for (0..len) |i| {
                    total_size += try Element.tree.serializedSize(allocator, nodes[i], pool);
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

        const tree_node = try ListU8.tree.fromValue(allocator, &pool, &value);

        var value_from_tree: ListU8.Type = ListU8.default_value;
        defer value_from_tree.deinit(allocator);
        try ListU8.tree.toValue(allocator, tree_node, &pool, &value_from_tree);

        try std.testing.expectEqual(value.items.len, value_from_tree.items.len);
        try std.testing.expectEqualSlices(u8, value.items, value_from_tree.items);

        const tree_size = try ListU8.tree.serializedSize(allocator, tree_node, &pool);
        try std.testing.expectEqual(serialized.len, tree_size);

        const tree_serialized = try allocator.alloc(u8, tree_size);
        defer allocator.free(tree_serialized);
        _ = try ListU8.tree.serializeIntoBytes(allocator, tree_node, &pool, tree_serialized);
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

        const tree_node = try ListU64.tree.fromValue(allocator, &pool, &value);

        var value_from_tree: ListU64.Type = ListU64.default_value;
        defer value_from_tree.deinit(allocator);
        try ListU64.tree.toValue(allocator, tree_node, &pool, &value_from_tree);

        try std.testing.expectEqual(value.items.len, value_from_tree.items.len);
        try std.testing.expectEqualSlices(u64, value.items, value_from_tree.items);

        const tree_size = try ListU64.tree.serializedSize(allocator, tree_node, &pool);
        const tree_serialized = try allocator.alloc(u8, tree_size);
        defer allocator.free(tree_serialized);
        _ = try ListU64.tree.serializeIntoBytes(allocator, tree_node, &pool, tree_serialized);
        try std.testing.expectEqualSlices(u8, serialized, tree_serialized);

        var hash_root: [32]u8 = undefined;
        try ListU64.hashTreeRoot(allocator, &value, &hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}
