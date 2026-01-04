const std = @import("std");
const expectEqualRoots = @import("test_utils.zig").expectEqualRoots;
const expectEqualRootsAlloc = @import("test_utils.zig").expectEqualRootsAlloc;
const expectEqualSerializedAlloc = @import("test_utils.zig").expectEqualSerializedAlloc;
const expectEqualSerialized = @import("test_utils.zig").expectEqualSerialized;
const TypeKind = @import("type_kind.zig").TypeKind;
const isBasicType = @import("type_kind.zig").isBasicType;
const isFixedType = @import("type_kind.zig").isFixedType;
const OffsetIterator = @import("offsets.zig").OffsetIterator;
const merkleize = @import("hashing").merkleize;
const maxChunksToDepth = @import("hashing").maxChunksToDepth;
const Node = @import("persistent_merkle_tree").Node;
const tree_view = @import("../tree_view/root.zig");
const ArrayBasicTreeView = tree_view.ArrayBasicTreeView;
const ArrayCompositeTreeView = tree_view.ArrayCompositeTreeView;

pub fn FixedVectorType(comptime ST: type, comptime _length: comptime_int) type {
    comptime {
        if (!isFixedType(ST)) {
            @compileError("ST must be fixed type");
        }
        if (_length <= 0) {
            @compileError("length must be greater than 0");
        }
    }
    return struct {
        pub const kind = TypeKind.vector;
        pub const Element: type = ST;
        pub const length: usize = _length;
        pub const Type: type = [length]Element.Type;
        pub const TreeView: type = if (isBasicType(Element))
            ArrayBasicTreeView(@This())
        else
            ArrayCompositeTreeView(@This());
        pub const fixed_size: usize = Element.fixed_size * length;
        pub const chunk_count: usize = if (isBasicType(Element)) std.math.divCeil(usize, fixed_size, 32) catch unreachable else length;
        pub const chunk_depth: u8 = maxChunksToDepth(chunk_count);

        pub const default_value: Type = [_]Element.Type{Element.default_value} ** length;

        pub fn equals(a: *const Type, b: *const Type) bool {
            for (a, b) |a_elem, b_elem| {
                if (!Element.equals(&a_elem, &b_elem)) {
                    return false;
                }
            }
            return true;
        }

        pub fn hashTreeRoot(value: *const Type, out: *[32]u8) !void {
            var chunks = [_][32]u8{[_]u8{0} ** 32} ** ((chunk_count + 1) / 2 * 2);
            if (comptime isBasicType(Element)) {
                _ = serializeIntoBytes(value, @ptrCast(&chunks));
            } else {
                for (value, 0..) |element, i| {
                    try Element.hashTreeRoot(&element, &chunks[i]);
                }
            }
            try merkleize(@ptrCast(&chunks), chunk_depth, out);
        }

        pub fn clone(value: *const Type, out: *Type) !void {
            out.* = value.*;
        }

        pub fn serializeIntoBytes(value: *const Type, out: []u8) usize {
            var i: usize = 0;
            for (value) |element| {
                i += Element.serializeIntoBytes(&element, out[i..]);
            }
            return i;
        }

        pub fn deserializeFromBytes(data: []const u8, out: *Type) !void {
            if (data.len != fixed_size) {
                return error.InvalidSize;
            }

            for (0..length) |i| {
                try Element.deserializeFromBytes(
                    data[i * Element.fixed_size .. (i + 1) * Element.fixed_size],
                    &out[i],
                );
            }
        }

        pub const serialized = struct {
            pub fn validate(data: []const u8) !void {
                if (data.len != fixed_size) {
                    return error.InvalidSize;
                }
                for (0..length) |i| {
                    try Element.serialized.validate(data[i * Element.fixed_size .. (i + 1) * Element.fixed_size]);
                }
            }

            pub fn hashTreeRoot(data: []const u8, out: *[32]u8) !void {
                var chunks = [_][32]u8{[_]u8{0} ** 32} ** ((chunk_count + 1) / 2 * 2);
                if (comptime isBasicType(Element)) {
                    @memcpy(@as([]u8, @ptrCast(&chunks))[0..fixed_size], data);
                } else {
                    for (0..length) |i| {
                        try Element.serialized.hashTreeRoot(
                            data[i * Element.fixed_size .. (i + 1) * Element.fixed_size],
                            &chunks[i],
                        );
                    }
                }
                try merkleize(@ptrCast(&chunks), chunk_depth, out);
            }
        };

        pub const tree = struct {
            pub fn deserializeFromBytes(pool: *Node.Pool, data: []const u8) !Node.Id {
                if (data.len != fixed_size) {
                    return error.InvalidSize;
                }

                var nodes: [chunk_count]Node.Id = undefined;

                if (comptime isBasicType(Element)) {
                    var chunks: [chunk_count][32]u8 = [_][32]u8{[_]u8{0} ** 32} ** chunk_count;
                    const chunk_bytes: []u8 = @ptrCast(&chunks);
                    @memcpy(chunk_bytes[0..fixed_size], data[0..fixed_size]);

                    for (&chunks, 0..) |*chunk, i| {
                        nodes[i] = try pool.createLeaf(chunk);
                    }
                } else {
                    for (0..length) |i| {
                        const elem_bytes = data[i * Element.fixed_size .. (i + 1) * Element.fixed_size];
                        nodes[i] = try Element.tree.deserializeFromBytes(pool, elem_bytes);
                    }
                }

                return try Node.fillWithContents(pool, &nodes, chunk_depth);
            }

            pub fn toValue(node: Node.Id, pool: *Node.Pool, out: *Type) !void {
                var nodes: [chunk_count]Node.Id = undefined;

                try node.getNodesAtDepth(pool, chunk_depth, 0, &nodes);

                if (comptime isBasicType(Element)) {
                    // tightly packed list
                    for (0..length) |i| {
                        try Element.tree.toValuePacked(
                            nodes[i * Element.fixed_size / 32],
                            pool,
                            i,
                            &out[i],
                        );
                    }
                } else {
                    for (0..length) |i| {
                        try Element.tree.toValue(
                            nodes[i],
                            pool,
                            &out[i],
                        );
                    }
                }
            }

            pub fn fromValue(pool: *Node.Pool, value: *const Type) !Node.Id {
                var nodes: [chunk_count]Node.Id = undefined;

                if (comptime isBasicType(Element)) {
                    const items_per_chunk = 32 / Element.fixed_size;
                    var l: usize = 0;
                    for (0..chunk_count) |i| {
                        var leaf_buf = [_]u8{0} ** 32;
                        for (0..items_per_chunk) |j| {
                            _ = Element.serializeIntoBytes(&value[l], leaf_buf[j * Element.fixed_size ..]);
                            l += 1;
                            if (l >= length) break;
                        }
                        nodes[i] = try pool.createLeaf(&leaf_buf);
                    }
                } else {
                    for (0..chunk_count) |i| {
                        nodes[i] = try Element.tree.fromValue(pool, &value[i]);
                    }
                }
                return try Node.fillWithContents(pool, &nodes, chunk_depth);
            }

            pub fn serializeIntoBytes(node: Node.Id, pool: *Node.Pool, out: []u8) !usize {
                var nodes: [chunk_count]Node.Id = undefined;
                try node.getNodesAtDepth(pool, chunk_depth, 0, &nodes);

                if (comptime isBasicType(Element)) {
                    for (0..chunk_count) |i| {
                        const start_idx = i * 32;
                        const remaining_bytes = fixed_size - start_idx;
                        const bytes_to_copy = @min(remaining_bytes, 32);
                        if (bytes_to_copy > 0) {
                            @memcpy(out[start_idx..][0..bytes_to_copy], nodes[i].getRoot(pool)[0..bytes_to_copy]);
                        }
                    }
                } else {
                    var offset: usize = 0;
                    for (0..length) |i| {
                        offset += try Element.tree.serializeIntoBytes(nodes[i], pool, out[offset..]);
                    }
                }
                return fixed_size;
            }

            pub fn serializedSize(_: Node.Id, _: *Node.Pool) usize {
                return fixed_size;
            }
        };

        pub fn serializeIntoJson(writer: anytype, in: *const Type) !void {
            try writer.beginArray();
            for (in) |element| {
                try Element.serializeIntoJson(writer, &element);
            }
            try writer.endArray();
        }

        pub fn deserializeFromJson(source: *std.json.Scanner, out: *Type) !void {
            // start array token "["
            switch (try source.next()) {
                .array_begin => {},
                else => return error.InvalidJson,
            }

            for (0..length) |i| {
                try Element.deserializeFromJson(source, &out[i]);
            }

            // end array token "]"
            switch (try source.next()) {
                .array_end => {},
                else => return error.InvalidJson,
            }
        }

        pub fn defaultTreeView(allocator: std.mem.Allocator, pool: *Node.Pool) !TreeView {
            const root = try tree.fromValue(pool, &default_value);
            return try TreeView.init(allocator, pool, root);
        }
    };
}

pub fn VariableVectorType(comptime ST: type, comptime _length: comptime_int) type {
    comptime {
        if (isFixedType(ST)) {
            @compileError("ST must not be fixed type");
        }
        if (_length <= 0) {
            @compileError("length must be greater than 0");
        }
    }
    return struct {
        pub const kind = TypeKind.vector;
        pub const Element: type = ST;
        pub const length: usize = _length;
        pub const Type: type = [length]Element.Type;
        pub const TreeView: type = if (isBasicType(Element))
            ArrayBasicTreeView(@This())
        else
            ArrayCompositeTreeView(@This());
        pub const min_size: usize = Element.min_size * length + 4 * length;
        pub const max_size: usize = Element.max_size * length + 4 * length;
        pub const chunk_count: usize = length;
        pub const chunk_depth: u8 = maxChunksToDepth(chunk_count);

        pub const default_value: Type = [_]Element.Type{Element.default_value} ** length;

        pub fn equals(a: *const Type, b: *const Type) bool {
            for (a, b) |a_elem, b_elem| {
                if (!Element.equals(&a_elem, &b_elem)) {
                    return false;
                }
            }
            return true;
        }

        pub fn deinit(allocator: std.mem.Allocator, value: *Type) void {
            for (0..length) |i| {
                Element.deinit(allocator, &value[i]);
            }
        }

        pub fn hashTreeRoot(allocator: std.mem.Allocator, value: *const Type, out: *[32]u8) !void {
            var chunks = [_][32]u8{[_]u8{0} ** 32} ** ((chunk_count + 1) / 2 * 2);
            for (value, 0..) |element, i| {
                try Element.hashTreeRoot(allocator, &element, &chunks[i]);
            }
            try merkleize(@ptrCast(&chunks), chunk_depth, out);
        }

        pub fn clone(allocator: std.mem.Allocator, value: *const Type, out: *Type) !void {
            for (0..length) |i| try Element.clone(allocator, &value[i], &out[i]);
        }

        pub fn serializedSize(value: *const Type) usize {
            var size: usize = 0;
            for (value) |*element| {
                size += 4 + Element.serializedSize(element);
            }
            return size;
        }

        pub fn serializeIntoBytes(value: *const Type, out: []u8) usize {
            var variable_index = length * 4;
            for (value, 0..) |element, i| {
                // write offset
                std.mem.writeInt(u32, out[i * 4 ..][0..4], @intCast(variable_index), .little);
                // write element data
                variable_index += Element.serializeIntoBytes(&element, out[variable_index..]);
            }
            return variable_index;
        }

        pub fn deserializeFromBytes(allocator: std.mem.Allocator, data: []const u8, out: *Type) !void {
            if (data.len > max_size or data.len < min_size) {
                return error.InvalidSize;
            }

            const offsets = try readVariableOffsets(data);
            for (0..length) |i| {
                try Element.deserializeFromBytes(allocator, data[offsets[i]..offsets[i + 1]], &out[i]);
            }
        }

        pub fn readVariableOffsets(data: []const u8) ![length + 1]usize {
            var iterator = OffsetIterator(@This()).init(data);
            var offsets: [length + 1]usize = undefined;
            for (0..length) |i| {
                offsets[i] = try iterator.next();
            }
            offsets[length] = data.len;

            return offsets;
        }

        pub const serialized = struct {
            pub fn validate(data: []const u8) !void {
                if (data.len > max_size or data.len < min_size) {
                    return error.InvalidSize;
                }

                const offsets = try readVariableOffsets(data);
                for (0..length) |i| {
                    try Element.serialized.validate(data[offsets[i]..offsets[i + 1]]);
                }
            }

            pub fn hashTreeRoot(allocator: std.mem.Allocator, data: []const u8, out: *[32]u8) !void {
                var chunks = [_][32]u8{[_]u8{0} ** 32} ** ((chunk_count + 1) / 2 * 2);
                const offsets = try readVariableOffsets(data);
                for (0..length) |i| {
                    try Element.serialized.hashTreeRoot(allocator, data[offsets[i]..offsets[i + 1]], &chunks[i]);
                }
                try merkleize(@ptrCast(&chunks), chunk_depth, out);
            }
        };

        pub const tree = struct {
            pub fn deserializeFromBytes(allocator: std.mem.Allocator, pool: *Node.Pool, data: []const u8) !Node.Id {
                if (data.len > max_size or data.len < min_size) {
                    return error.InvalidSize;
                }

                const offsets = try readVariableOffsets(data);
                var nodes: [chunk_count]Node.Id = undefined;
                for (0..length) |i| {
                    const elem_bytes = data[offsets[i]..offsets[i + 1]];
                    nodes[i] = try Element.tree.deserializeFromBytes(allocator, pool, elem_bytes);
                }

                return try Node.fillWithContents(pool, &nodes, chunk_depth);
            }

            pub fn toValue(allocator: std.mem.Allocator, node: Node.Id, pool: *Node.Pool, out: *Type) !void {
                var nodes: [chunk_count]Node.Id = undefined;

                try node.getNodesAtDepth(pool, chunk_depth, 0, &nodes);

                for (0..length) |i| {
                    try Element.tree.toValue(
                        allocator,
                        nodes[i],
                        pool,
                        &out[i],
                    );
                }
            }

            pub fn fromValue(allocator: std.mem.Allocator, pool: *Node.Pool, value: *const Type) !Node.Id {
                var nodes: [chunk_count]Node.Id = undefined;

                for (0..chunk_count) |i| {
                    nodes[i] = try Element.tree.fromValue(allocator, pool, &value[i]);
                }
                return try Node.fillWithContents(pool, &nodes, chunk_depth);
            }

            pub fn serializeIntoBytes(allocator: std.mem.Allocator, node: Node.Id, pool: *Node.Pool, out: []u8) !usize {
                var nodes: [chunk_count]Node.Id = undefined;
                try node.getNodesAtDepth(pool, chunk_depth, 0, &nodes);

                const fixed_end = length * 4;
                var variable_index = fixed_end;

                for (0..length) |i| {
                    std.mem.writeInt(u32, out[i * 4 ..][0..4], @intCast(variable_index), .little);
                    variable_index += try Element.tree.serializeIntoBytes(allocator, nodes[i], pool, out[variable_index..]);
                }

                return variable_index;
            }

            pub fn serializedSize(allocator: std.mem.Allocator, node: Node.Id, pool: *Node.Pool) !usize {
                var nodes: [chunk_count]Node.Id = undefined;
                try node.getNodesAtDepth(pool, chunk_depth, 0, &nodes);

                var total_size: usize = length * 4; // Offsets
                for (0..length) |i| {
                    total_size += try Element.tree.serializedSize(allocator, nodes[i], pool);
                }
                return total_size;
            }
        };

        pub fn serializeIntoJson(allocator: std.mem.Allocator, writer: anytype, in: *const Type) !void {
            try writer.beginArray();
            for (in) |element| {
                try Element.serializeIntoJson(allocator, writer, &element);
            }
            try writer.endArray();
        }

        pub fn deserializeFromJson(allocator: std.mem.Allocator, source: *std.json.Scanner, out: *Type) !void {
            // start array token "["
            switch (try source.next()) {
                .array_begin => {},
                else => return error.InvalidJson,
            }

            for (0..length) |i| {
                try Element.deserializeFromJson(allocator, source, &out[i]);
            }

            // end array token "]"
            switch (try source.next()) {
                .array_end => {},
                else => return error.InvalidJson,
            }
        }

        pub fn defaultTreeView(allocator: std.mem.Allocator, pool: *Node.Pool) !TreeView {
            const root = try tree.fromValue(allocator, pool, &default_value);
            return try TreeView.init(allocator, pool, root);
        }
    };
}

const UintType = @import("uint.zig").UintType;
const BoolType = @import("bool.zig").BoolType;
const BitListType = @import("bit_list.zig").BitListType;
const ByteVectorType = @import("byte_vector.zig").ByteVectorType;
const FixedContainerType = @import("container.zig").FixedContainerType;
const FixedListType = @import("list.zig").FixedListType;

test "vector - sanity" {
    // create a fixed vector type and instance and round-trip serialize
    const Bytes32 = FixedVectorType(UintType(8), 32);

    var b0: Bytes32.Type = undefined;
    var b0_buf: [Bytes32.fixed_size]u8 = undefined;
    _ = Bytes32.serializeIntoBytes(&b0, &b0_buf);
    try Bytes32.deserializeFromBytes(&b0_buf, &b0);
}

test "clone" {
    const allocator = std.testing.allocator;
    const BoolVectorFixed = FixedVectorType(BoolType(), 8);
    var bvf: BoolVectorFixed.Type = BoolVectorFixed.default_value;

    var cloned: BoolVectorFixed.Type = undefined;
    try BoolVectorFixed.clone(&bvf, &cloned);
    try expectEqualRoots(BoolVectorFixed, bvf, cloned);
    try expectEqualSerialized(BoolVectorFixed, bvf, cloned);

    try std.testing.expect(&bvf != &cloned);
    try std.testing.expect(std.mem.eql(bool, bvf[0..], cloned[0..]));

    const limit = 16;
    const BitList = BitListType(limit);
    const bl = BitList.default_value;
    const BoolVectorVariable = VariableVectorType(BitList, 8);
    var bvv: BoolVectorVariable.Type = BoolVectorVariable.default_value;
    bvv[0] = bl;

    var cloned_v: BoolVectorVariable.Type = undefined;
    try BoolVectorVariable.clone(allocator, &bvv, &cloned_v);
    try std.testing.expect(&bvv != &cloned_v);
    try expectEqualRootsAlloc(BoolVectorVariable, allocator, bvv, cloned_v);
    try expectEqualSerializedAlloc(BoolVectorVariable, allocator, bvv, cloned_v);
}

// Refer to https://github.com/ChainSafe/ssz/blob/f5ed0b457333749b5c3f49fa5eafa096a725f033/packages/ssz/test/unit/byType/vector/valid.test.ts#L15-L85
test "FixedVectorType - serializeIntoBytes (VectorBasic uint64 - 4 values)" {
    const allocator = std.testing.allocator;
    const VectorU64 = FixedVectorType(UintType(64), 4);

    const value: VectorU64.Type = [_]u64{ 100000, 200000, 300000, 400000 };

    // 0xa086010000000000400d030000000000e093040000000000801a060000000000
    const expected_serialized = [_]u8{
        0xa0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // 100000
        0x40, 0x0d, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, // 200000
        0xe0, 0x93, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // 300000
        0x80, 0x1a, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, // 400000
    };
    const expected_root = expected_serialized;

    var serialized: [VectorU64.fixed_size]u8 = undefined;
    const written = VectorU64.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 32), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &serialized);

    var root: [32]u8 = undefined;
    try VectorU64.hashTreeRoot(&value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try VectorU64.tree.fromValue(&pool, &value);
    var tree_serialized: [VectorU64.fixed_size]u8 = undefined;
    _ = try VectorU64.tree.serializeIntoBytes(node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &tree_serialized);
}

test "FixedVectorType - serializeIntoBytes (VectorComposite ByteVector32 - 4 roots)" {
    const allocator = std.testing.allocator;
    const ByteVector32 = ByteVectorType(32);
    const VectorBV32 = FixedVectorType(ByteVector32, 4);

    const value: VectorBV32.Type = [_][32]u8{
        [_]u8{0xbb} ** 32,
        [_]u8{0xcc} ** 32,
        [_]u8{0xdd} ** 32,
        [_]u8{0xee} ** 32,
    };

    const expected_serialized = [_]u8{0xbb} ** 32 ++ [_]u8{0xcc} ** 32 ++ [_]u8{0xdd} ** 32 ++ [_]u8{0xee} ** 32;
    const expected_root = [_]u8{ 0x56, 0x01, 0x9b, 0xaf, 0xbc, 0x63, 0x46, 0x1b, 0x73, 0xe2, 0x1c, 0x6e, 0xae, 0x0c, 0x62, 0xe8, 0xd5, 0xb8, 0xe0, 0x5c, 0xb0, 0xac, 0x06, 0x57, 0x77, 0xdc, 0x23, 0x8f, 0xcf, 0x96, 0x04, 0xe6 };

    var serialized: [VectorBV32.fixed_size]u8 = undefined;
    const written = VectorBV32.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 128), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &serialized);

    var root: [32]u8 = undefined;
    try VectorBV32.hashTreeRoot(&value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try VectorBV32.tree.fromValue(&pool, &value);
    var tree_serialized: [VectorBV32.fixed_size]u8 = undefined;
    _ = try VectorBV32.tree.serializeIntoBytes(node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &tree_serialized);
}

test "FixedVectorType - serializeIntoBytes (VectorComposite Container - 4 arrays)" {
    const allocator = std.testing.allocator;
    const Container = FixedContainerType(struct {
        a: UintType(64),
        b: UintType(64),
    });
    const VectorContainer = FixedVectorType(Container, 4);

    const value: VectorContainer.Type = [_]Container.Type{
        .{ .a = 0, .b = 0 },
        .{ .a = 123456, .b = 654321 },
        .{ .a = 234567, .b = 765432 },
        .{ .a = 345678, .b = 876543 },
    };

    // 0x0000000000000000000000000000000040e2010000000000f1fb0900000000004794030000000000f8ad0b00000000004e46050000000000ff5f0d0000000000
    const expected_serialized = [_]u8{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // a=0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // b=0
        0x40, 0xe2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // a=123456
        0xf1, 0xfb, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, // b=654321
        0x47, 0x94, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, // a=234567
        0xf8, 0xad, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, // b=765432
        0x4e, 0x46, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, // a=345678
        0xff, 0x5f, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, // b=876543
    };
    const expected_root = [_]u8{ 0xb1, 0xa7, 0x97, 0xeb, 0x50, 0x65, 0x47, 0x48, 0xba, 0x23, 0x90, 0x10, 0xed, 0xcc, 0xea, 0x7b, 0x46, 0xb5, 0x5b, 0xf7, 0x40, 0x73, 0x0b, 0x70, 0x06, 0x84, 0xf4, 0x8b, 0x0c, 0x47, 0x83, 0x72 };

    var serialized: [VectorContainer.fixed_size]u8 = undefined;
    const written = VectorContainer.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 64), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &serialized);

    var root: [32]u8 = undefined;
    try VectorContainer.hashTreeRoot(&value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try VectorContainer.tree.fromValue(&pool, &value);
    var tree_serialized: [VectorContainer.fixed_size]u8 = undefined;
    _ = try VectorContainer.tree.serializeIntoBytes(node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &tree_serialized);
}

test "VariableVectorType - serializeIntoBytes (VectorComposite ListBasic - [[1,2],[5,6]])" {
    const allocator = std.testing.allocator;
    const ListU64 = FixedListType(UintType(64), 8);
    const VectorList = VariableVectorType(ListU64, 2);

    var value: VectorList.Type = VectorList.default_value;
    // [[1,2],[5,6]]
    try value[0].appendSlice(allocator, &[_]u64{ 1, 2 });
    try value[1].appendSlice(allocator, &[_]u64{ 5, 6 });
    defer VectorList.deinit(allocator, &value);

    // 0x08000000180000000100000000000000020000000000000005000000000000000600000000000000
    const expected_serialized = [_]u8{
        0x08, 0x00, 0x00, 0x00, // offset to first list = 8
        0x18, 0x00, 0x00, 0x00, // offset to second list = 24
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 2
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 5
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 6
    };
    const expected_root = [_]u8{ 0x00, 0x14, 0xc4, 0x85, 0xce, 0x39, 0xc8, 0x07, 0x1f, 0x69, 0x63, 0x15, 0x66, 0xb1, 0xd1, 0xad, 0x51, 0xe2, 0xb0, 0xb5, 0xab, 0xc3, 0xc7, 0xa2, 0x99, 0xa6, 0xfa, 0xc1, 0xab, 0xce, 0x9e, 0x49 };

    const size = VectorList.serializedSize(&value);
    try std.testing.expectEqual(@as(usize, 40), size);
    const serialized = try allocator.alloc(u8, size);
    defer allocator.free(serialized);
    const written = VectorList.serializeIntoBytes(&value, serialized);
    try std.testing.expectEqual(@as(usize, 40), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, serialized);

    var root: [32]u8 = undefined;
    try VectorList.hashTreeRoot(allocator, &value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try VectorList.tree.fromValue(allocator, &pool, &value);
    const tree_size = try VectorList.tree.serializedSize(allocator, node, &pool);
    try std.testing.expectEqual(@as(usize, 40), tree_size);
    const tree_serialized = try allocator.alloc(u8, tree_size);
    defer allocator.free(tree_serialized);
    _ = try VectorList.tree.serializeIntoBytes(allocator, node, &pool, tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, tree_serialized);
}

test "FixedVectorType - tree.deserializeFromBytes (VectorBasic uint64)" {
    const allocator = std.testing.allocator;
    const VectorU64 = FixedVectorType(UintType(64), 4);

    // 0xa086010000000000400d030000000000e093040000000000801a060000000000
    const serialized = [_]u8{
        0xa0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // 100000
        0x40, 0x0d, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, // 200000
        0xe0, 0x93, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // 300000
        0x80, 0x1a, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, // 400000
    };
    const expected_values = [_]u64{ 100000, 200000, 300000, 400000 };
    const expected_root = serialized; // For VectorBasic with 4 uint64 values, root equals serialized

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const tree_node = try VectorU64.tree.deserializeFromBytes(&pool, &serialized);

    var value_from_tree: VectorU64.Type = undefined;
    try VectorU64.tree.toValue(tree_node, &pool, &value_from_tree);

    try std.testing.expectEqualSlices(u64, &expected_values, &value_from_tree);

    var tree_serialized: [VectorU64.fixed_size]u8 = undefined;
    _ = try VectorU64.tree.serializeIntoBytes(tree_node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &serialized, &tree_serialized);

    var hash_root: [32]u8 = undefined;
    try VectorU64.hashTreeRoot(&value_from_tree, &hash_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &hash_root);
}

test "FixedVectorType - tree.deserializeFromBytes (VectorComposite ByteVector32)" {
    const allocator = std.testing.allocator;
    const ByteVector32 = ByteVectorType(32);
    const VectorBV32 = FixedVectorType(ByteVector32, 4);

    // 0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
    const serialized = [_]u8{0xbb} ** 32 ++ [_]u8{0xcc} ** 32 ++ [_]u8{0xdd} ** 32 ++ [_]u8{0xee} ** 32;
    const expected_values = [_][32]u8{
        [_]u8{0xbb} ** 32,
        [_]u8{0xcc} ** 32,
        [_]u8{0xdd} ** 32,
        [_]u8{0xee} ** 32,
    };
    // 0x56019bafbc63461b73e21c6eae0c62e8d5b8e05cb0ac065777dc238fcf9604e6
    const expected_root = [_]u8{ 0x56, 0x01, 0x9b, 0xaf, 0xbc, 0x63, 0x46, 0x1b, 0x73, 0xe2, 0x1c, 0x6e, 0xae, 0x0c, 0x62, 0xe8, 0xd5, 0xb8, 0xe0, 0x5c, 0xb0, 0xac, 0x06, 0x57, 0x77, 0xdc, 0x23, 0x8f, 0xcf, 0x96, 0x04, 0xe6 };

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const tree_node = try VectorBV32.tree.deserializeFromBytes(&pool, &serialized);

    var value_from_tree: VectorBV32.Type = undefined;
    try VectorBV32.tree.toValue(tree_node, &pool, &value_from_tree);

    for (expected_values, 0..) |expected, i| {
        try std.testing.expectEqualSlices(u8, &expected, &value_from_tree[i]);
    }

    var tree_serialized: [VectorBV32.fixed_size]u8 = undefined;
    _ = try VectorBV32.tree.serializeIntoBytes(tree_node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &serialized, &tree_serialized);

    var hash_root: [32]u8 = undefined;
    try VectorBV32.hashTreeRoot(&value_from_tree, &hash_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &hash_root);
}

test "FixedVectorType - tree.deserializeFromBytes (VectorComposite Container)" {
    const allocator = std.testing.allocator;
    const Container = FixedContainerType(struct {
        a: UintType(64),
        b: UintType(64),
    });
    const VectorContainer = FixedVectorType(Container, 4);

    // 0x0000000000000000000000000000000040e2010000000000f1fb0900000000004794030000000000f8ad0b00000000004e46050000000000ff5f0d0000000000
    const serialized = [_]u8{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // a=0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // b=0
        0x40, 0xe2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // a=123456
        0xf1, 0xfb, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, // b=654321
        0x47, 0x94, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, // a=234567
        0xf8, 0xad, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, // b=765432
        0x4e, 0x46, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, // a=345678
        0xff, 0x5f, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, // b=876543
    };
    const expected_values = [_]Container.Type{
        .{ .a = 0, .b = 0 },
        .{ .a = 123456, .b = 654321 },
        .{ .a = 234567, .b = 765432 },
        .{ .a = 345678, .b = 876543 },
    };
    // 0xb1a797eb50654748ba239010edccea7b46b55bf740730b700684f48b0c478372
    const expected_root = [_]u8{ 0xb1, 0xa7, 0x97, 0xeb, 0x50, 0x65, 0x47, 0x48, 0xba, 0x23, 0x90, 0x10, 0xed, 0xcc, 0xea, 0x7b, 0x46, 0xb5, 0x5b, 0xf7, 0x40, 0x73, 0x0b, 0x70, 0x06, 0x84, 0xf4, 0x8b, 0x0c, 0x47, 0x83, 0x72 };

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const tree_node = try VectorContainer.tree.deserializeFromBytes(&pool, &serialized);

    var value_from_tree: VectorContainer.Type = undefined;
    try VectorContainer.tree.toValue(tree_node, &pool, &value_from_tree);

    for (expected_values, 0..) |expected, i| {
        try std.testing.expectEqual(expected.a, value_from_tree[i].a);
        try std.testing.expectEqual(expected.b, value_from_tree[i].b);
    }

    var tree_serialized: [VectorContainer.fixed_size]u8 = undefined;
    _ = try VectorContainer.tree.serializeIntoBytes(tree_node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &serialized, &tree_serialized);

    var hash_root: [32]u8 = undefined;
    try VectorContainer.hashTreeRoot(&value_from_tree, &hash_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &hash_root);
}

test "VariableVectorType - tree.deserializeFromBytes (VectorComposite ListBasic)" {
    const allocator = std.testing.allocator;
    const ListU64 = FixedListType(UintType(64), 8);
    const VectorList = VariableVectorType(ListU64, 2);

    // 0x08000000180000000100000000000000020000000000000005000000000000000600000000000000
    const serialized = [_]u8{
        0x08, 0x00, 0x00, 0x00, // offset to first list = 8
        0x18, 0x00, 0x00, 0x00, // offset to second list = 24
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 2
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 5
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 6
    };
    // 0x0014c485ce39c8071f69631566b1d1ad51e2b0b5abc3c7a299a6fac1abce9e49
    const expected_root = [_]u8{ 0x00, 0x14, 0xc4, 0x85, 0xce, 0x39, 0xc8, 0x07, 0x1f, 0x69, 0x63, 0x15, 0x66, 0xb1, 0xd1, 0xad, 0x51, 0xe2, 0xb0, 0xb5, 0xab, 0xc3, 0xc7, 0xa2, 0x99, 0xa6, 0xfa, 0xc1, 0xab, 0xce, 0x9e, 0x49 };

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const tree_node = try VectorList.tree.deserializeFromBytes(allocator, &pool, &serialized);

    var value_from_tree: VectorList.Type = VectorList.default_value;
    defer VectorList.deinit(allocator, &value_from_tree);
    try VectorList.tree.toValue(allocator, tree_node, &pool, &value_from_tree);

    try std.testing.expectEqual(@as(usize, 2), value_from_tree[0].items.len);
    try std.testing.expectEqual(@as(u64, 1), value_from_tree[0].items[0]);
    try std.testing.expectEqual(@as(u64, 2), value_from_tree[0].items[1]);
    try std.testing.expectEqual(@as(usize, 2), value_from_tree[1].items.len);
    try std.testing.expectEqual(@as(u64, 5), value_from_tree[1].items[0]);
    try std.testing.expectEqual(@as(u64, 6), value_from_tree[1].items[1]);

    const tree_size = try VectorList.tree.serializedSize(allocator, tree_node, &pool);
    try std.testing.expectEqual(@as(usize, 40), tree_size);
    const tree_serialized = try allocator.alloc(u8, tree_size);
    defer allocator.free(tree_serialized);
    _ = try VectorList.tree.serializeIntoBytes(allocator, tree_node, &pool, tree_serialized);
    try std.testing.expectEqualSlices(u8, &serialized, tree_serialized);

    var hash_root: [32]u8 = undefined;
    try VectorList.hashTreeRoot(allocator, &value_from_tree, &hash_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &hash_root);
}
