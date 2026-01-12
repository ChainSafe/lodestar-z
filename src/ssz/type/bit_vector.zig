const std = @import("std");
const expectEqualRoots = @import("test_utils.zig").expectEqualRoots;
const expectEqualSerialized = @import("test_utils.zig").expectEqualSerialized;
const merkleize = @import("hashing").merkleize;
const TypeKind = @import("type_kind.zig").TypeKind;
const BoolType = @import("bool.zig").BoolType;
const hexToBytes = @import("hex").hexToBytes;
const hexLenFromBytes = @import("hex").hexLenFromBytes;
const bytesToHex = @import("hex").bytesToHex;
const maxChunksToDepth = @import("hashing").maxChunksToDepth;
const getZeroHash = @import("hashing").getZeroHash;
const Node = @import("persistent_merkle_tree").Node;
const BitVectorTreeView = @import("../tree_view/root.zig").BitVectorTreeView;

pub fn isBitVectorType(ST: type) bool {
    return ST == BitVectorType(ST.length);
}

pub fn BitVectorType(comptime _length: comptime_int) type {
    if (_length <= 0) @compileError("length must be greater than 0");

    return struct {
        pub const kind = TypeKind.vector;
        pub const Element: type = BoolType();
        pub const length: usize = _length;
        pub const byte_length = std.math.divCeil(usize, length, 8) catch unreachable;
        pub const Type: type = @This();
        pub const TreeView: type = BitVectorTreeView(@This());
        pub const fixed_size: usize = byte_length;
        pub const chunk_count: usize = std.math.divCeil(usize, fixed_size, 32) catch unreachable;
        pub const chunk_depth: u8 = maxChunksToDepth(chunk_count);

        data: [byte_length]u8,

        pub const default_value: Type = Type.empty;

        pub const default_root: [32]u8 = getZeroHash(chunk_depth).*;

        pub const empty: @This() = .{
            .data = [_]u8{0} ** byte_length,
        };

        pub fn equals(self: *const @This(), other: *const @This()) bool {
            return std.mem.eql(u8, &self.data, &other.data);
        }

        pub fn fromBoolArray(bools: [length]bool) !@This() {
            var bv = empty;
            for (bools, 0..) |bit, i| {
                try bv.set(i, bit);
            }
            return bv;
        }

        pub fn toBoolArray(self: *const @This(), out: *[length]bool) void {
            for (0..length) |i| {
                out[i] = self.get(i) catch unreachable;
            }
        }

        pub fn getTrueBitIndexes(self: *const @This(), out: []usize) !usize {
            if (out.len < length) {
                return error.InvalidSize;
            }
            var true_bit_count: usize = 0;

            for (0..byte_length) |i_byte| {
                var b = self.data[i_byte];

                while (b != 0) {
                    const lsb: usize = @as(u8, @ctz(b));
                    const bit_index = i_byte * 8 + lsb;
                    out[true_bit_count] = bit_index;
                    true_bit_count += 1;
                    b &= b - 1;
                }
            }

            return true_bit_count;
        }

        pub fn getSingleTrueBit(self: *const @This()) ?usize {
            var found_index: ?usize = null;

            for (0..byte_length) |i_byte| {
                var b = self.data[i_byte];

                while (b != 0) {
                    if (found_index != null) {
                        return null; // more than one true bit found
                    }
                    const lsb: usize = @as(u8, @ctz(b));
                    const bit_index = i_byte * 8 + lsb;
                    found_index = bit_index;

                    b &= b - 1;
                }
            }
            return found_index;
        }

        pub fn get(self: *const @This(), bit_index: usize) !bool {
            if (bit_index >= length) {
                return error.OutOfRange;
            }

            const byte_idx = bit_index / 8;
            const offset_in_byte: u3 = @intCast(bit_index % 8);
            const mask = @as(u8, 1) << offset_in_byte;
            return (self.data[byte_idx] & mask) == mask;
        }

        /// Set bit value at index `bit_index`
        pub fn set(self: *@This(), bit_index: usize, bit: bool) !void {
            if (bit_index >= length) {
                return error.OutOfRange;
            }

            const byte_index = bit_index / 8;
            const offset_in_byte: u3 = @intCast(bit_index % 8);
            const mask = @as(u8, 1) << offset_in_byte;
            var byte = self.data[byte_index];
            if (bit) {
                // For bit in byte, 1,0 OR 1 = 1
                // byte 100110
                // mask 010000
                // res  110110
                byte |= mask;
                self.data[byte_index] = byte;
            } else {
                // For bit in byte, 1,0 OR 1 = 0
                if ((byte & mask) == mask) {
                    // byte 110110
                    // mask 010000
                    // res  100110
                    byte ^= mask;
                    self.data[byte_index] = byte;
                } else {
                    // Ok, bit is already 0
                }
            }
        }

        /// Allocates and returns an `ArrayList` of indices where the bit at the index of `self` is set to `true`.
        ///
        /// Caller must call `deinit` on the returned list
        pub fn intersectValues(
            self: *const @This(),
            comptime T: type,
            allocator: std.mem.Allocator,
            values: *const [length]T,
        ) !std.ArrayList(T) {
            var indices = try std.ArrayList(T).initCapacity(allocator, byte_length * 8);

            for (0..byte_length) |i_byte| {
                var b = self.data[i_byte];
                // Kernighan's algorithm to count the set bits instead of going through 0..8 for every byte
                while (b != 0) {
                    const lsb: usize = @as(u8, @ctz(b)); // Get the index of least significant bit
                    const bit_index = i_byte * 8 + lsb;
                    indices.appendAssumeCapacity(values[bit_index]);
                    // The `b - 1` flips the bits starting from `lsb` index
                    // And `&` will reset the last bit at `lsb` index
                    b &= b - 1;
                }
            }
            return indices;
        }

        pub fn hashTreeRoot(value: *const Type, out: *[32]u8) !void {
            var chunks = [_][32]u8{[_]u8{0} ** 32} ** ((chunk_count + 1) / 2 * 2);
            _ = serializeIntoBytes(value, @ptrCast(&chunks));
            try merkleize(@ptrCast(&chunks), chunk_depth, out);
        }

        pub fn clone(value: *const Type, out: *Type) !void {
            out.* = value.*;
        }

        pub fn serializeIntoBytes(value: *const Type, out: []u8) usize {
            @memcpy(out[0..byte_length], &value.data);
            return byte_length;
        }

        pub fn deserializeFromBytes(data: []const u8, out: *Type) !void {
            try serialized.validate(data);

            @memcpy(&out.data, data[0..fixed_size]);
        }

        pub const serialized = struct {
            pub fn validate(data: []const u8) !void {
                if (data.len != fixed_size) {
                    return error.invalidLength;
                }

                // ensure trailing zeros for non-byte-aligned lengths
                if (length % 8 != 0 and @clz(data[fixed_size - 1]) < 8 - length % 8) {
                    return error.trailingData;
                }
            }

            pub fn hashTreeRoot(data: []const u8, out: *[32]u8) !void {
                var chunks = [_][32]u8{[_]u8{0} ** 32} ** ((chunk_count + 1) / 2 * 2);
                @memcpy(@as([]u8, @ptrCast(&chunks))[0..fixed_size], data);
                try merkleize(@ptrCast(&chunks), chunk_depth, out);
            }
        };

        pub const tree = struct {
            pub fn default(_: *Node.Pool) !Node.Id {
                return @enumFromInt(chunk_depth);
            }

            pub fn deserializeFromBytes(pool: *Node.Pool, data: []const u8) !Node.Id {
                try serialized.validate(data);

                var chunks: [chunk_count][32]u8 = [_][32]u8{[_]u8{0} ** 32} ** chunk_count;
                const chunk_bytes: []u8 = @ptrCast(&chunks);
                @memcpy(chunk_bytes[0..byte_length], data[0..byte_length]);

                var nodes: [chunk_count]Node.Id = undefined;
                for (&chunks, 0..) |*chunk, i| {
                    nodes[i] = try pool.createLeaf(chunk);
                }

                return try Node.fillWithContents(pool, &nodes, chunk_depth);
            }

            pub fn toValue(node: Node.Id, pool: *Node.Pool, out: *Type) !void {
                var nodes: [chunk_count]Node.Id = undefined;

                try node.getNodesAtDepth(pool, chunk_depth, 0, &nodes);

                for (0..chunk_count) |i| {
                    const start_idx = i * 32;
                    const remaining_bytes = byte_length - start_idx;

                    // Determine how many bytes to copy for this chunk
                    const bytes_to_copy = @min(remaining_bytes, 32);

                    // Copy data if there are bytes to copy
                    if (bytes_to_copy > 0) {
                        @memcpy(out.data[start_idx..][0..bytes_to_copy], nodes[i].getRoot(pool)[0..bytes_to_copy]);
                    }
                }
            }

            pub fn fromValue(pool: *Node.Pool, value: *const Type) !Node.Id {
                var nodes: [chunk_count]Node.Id = undefined;
                for (0..chunk_count) |i| {
                    var leaf_buf = [_]u8{0} ** 32;
                    const start_idx = i * 32;
                    const remaining_bytes = byte_length - start_idx;

                    // Determine how many bytes to copy for this chunk
                    const bytes_to_copy = @min(remaining_bytes, 32);

                    // Copy data if there are bytes to copy
                    if (bytes_to_copy > 0) {
                        @memcpy(leaf_buf[0..bytes_to_copy], value.data[start_idx..][0..bytes_to_copy]);
                    }

                    nodes[i] = try pool.createLeaf(&leaf_buf);
                }

                return try Node.fillWithContents(pool, &nodes, chunk_depth);
            }

            pub fn serializeIntoBytes(node: Node.Id, pool: *Node.Pool, out: []u8) !usize {
                var nodes: [chunk_count]Node.Id = undefined;
                try node.getNodesAtDepth(pool, chunk_depth, 0, &nodes);

                for (0..chunk_count) |i| {
                    const start_idx = i * 32;
                    const remaining_bytes = byte_length - start_idx;
                    const bytes_to_copy = @min(remaining_bytes, 32);
                    if (bytes_to_copy > 0) {
                        @memcpy(out[start_idx..][0..bytes_to_copy], nodes[i].getRoot(pool)[0..bytes_to_copy]);
                    }
                }
                return fixed_size;
            }
        };

        pub fn serializeIntoJson(writer: anytype, in: *const Type) !void {
            const bytes = in.*.data;
            var byte_str: [2 + 2 * byte_length]u8 = undefined;

            _ = try bytesToHex(&byte_str, &bytes);
            try writer.print("\"{s}\"", .{byte_str});
        }

        pub fn deserializeFromJson(source: *std.json.Scanner, out: *Type) !void {
            const hex_bytes = switch (try source.next()) {
                .string => |v| v,
                else => return error.InvalidJson,
            };
            const written = try hexToBytes(&out.data, hex_bytes);
            if (written.len != fixed_size) {
                return error.invalidLength;
            }
            // ensure trailing zeros for non-byte-aligned lengths
            if (length % 8 != 0 and @clz(out.data[fixed_size - 1]) < 8 - length % 8) {
                return error.trailingData;
            }
        }
    };
}

test "BitVectorType - sanity" {
    const length = 44;
    const Bits = BitVectorType(length);
    var b: Bits = .default_value;
    try b.set(0, true);
    try b.set(length - 1, true);

    try std.testing.expectEqual(true, try b.get(0));

    for (1..length - 1) |i| {
        try std.testing.expectEqual(false, try b.get(i));
    }
    try std.testing.expectEqual(true, try b.get(length - 1));

    var b_buf: [Bits.fixed_size]u8 = undefined;
    _ = Bits.serializeIntoBytes(&b, &b_buf);
    try Bits.deserializeFromBytes(&b_buf, &b);
}

test "BitVectorType - sanity with bools" {
    const Bits = BitVectorType(16);
    const expected_bools = [_]bool{ true, false, true, true, false, true, false, true, true, false, true, true, false, false, true, false };
    const expected_true_bit_indexes = [_]usize{ 0, 2, 3, 5, 7, 8, 10, 11, 14 };
    var b: Bits = try Bits.fromBoolArray(expected_bools);

    var actual_bools: [Bits.length]bool = undefined;
    b.toBoolArray(&actual_bools);

    try std.testing.expectEqualSlices(bool, &expected_bools, &actual_bools);

    var true_bit_indexes: [Bits.length]usize = undefined;
    const true_bit_count = try b.getTrueBitIndexes(true_bit_indexes[0..]);

    try std.testing.expectEqualSlices(usize, &expected_true_bit_indexes, true_bit_indexes[0..true_bit_count]);

    const expected_single_bool = [_]bool{ false, false, false, false, false, false, false, false, false, false, false, true, false, false, false, false };
    var b_single_bool: Bits = try Bits.fromBoolArray(expected_single_bool);

    try std.testing.expectEqual(b_single_bool.getSingleTrueBit(), 11);
}

test "BitVectorType - intersectValues" {
    const TestCase = struct { expected: []const u8, bit_len: usize };
    const test_cases = [_]TestCase{
        .{ .expected = &[_]u8{}, .bit_len = 16 },
        .{ .expected = &[_]u8{3}, .bit_len = 16 },
        .{ .expected = &[_]u8{ 0, 5, 6, 10, 14 }, .bit_len = 16 },
        .{ .expected = &[_]u8{ 0, 5, 6, 10, 14 }, .bit_len = 15 },
    };

    const allocator = std.testing.allocator;
    const Bits = BitVectorType(16);

    for (test_cases) |tc| {
        var b: Bits = .default_value;

        for (tc.expected) |i| try b.set(i, true);

        var values: [16]u8 = undefined;
        for (0..tc.bit_len) |i| values[i] = @intCast(i);

        var actual = try b.intersectValues(u8, allocator, &values);
        defer actual.deinit();
        try std.testing.expectEqualSlices(u8, tc.expected, actual.items);
    }
}

test "clone" {
    const length = 44;
    const Bits = BitVectorType(length);
    var b: Bits = .default_value;
    try b.set(0, true);
    try b.set(length - 1, true);

    var cloned: Bits = undefined;
    try Bits.clone(&b, &cloned);
    try std.testing.expect(&b != &cloned);
    try std.testing.expect(std.mem.eql(u8, b.data[0..], cloned.data[0..]));

    try expectEqualRoots(Bits, b, cloned);
    try expectEqualSerialized(Bits, b, cloned);
}

// Refer to https://github.com/ChainSafe/ssz/blob/f5ed0b457333749b5c3f49fa5eafa096a725f033/packages/ssz/test/unit/byType/bitVector/valid.test.ts#L4-L21
test "BitVectorType - tree roundtrip 128 bits" {
    const allocator = std.testing.allocator;

    const Bits = BitVectorType(128);

    const TestCase = struct {
        id: []const u8,
        serialized: [16]u8,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty (one bit set)",
            .serialized = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
            // root is padded serialized (16 bytes -> 32 bytes)
            .expected_root = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        },
        .{
            .id = "some value",
            .serialized = [_]u8{ 0xb5, 0x5b, 0x85, 0x92, 0xbc, 0xac, 0x47, 0x59, 0x06, 0x63, 0x14, 0x81, 0xbb, 0xc7, 0x46, 0xbc },
            .expected_root = [_]u8{ 0xb5, 0x5b, 0x85, 0x92, 0xbc, 0xac, 0x47, 0x59, 0x06, 0x63, 0x14, 0x81, 0xbb, 0xc7, 0x46, 0xbc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        },
    };

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    for (test_cases) |tc| {
        var value: Bits = undefined;
        try Bits.deserializeFromBytes(&tc.serialized, &value);

        const tree_node = try Bits.tree.fromValue(&pool, &value);

        var value_from_tree: Bits = undefined;
        try Bits.tree.toValue(tree_node, &pool, &value_from_tree);

        try std.testing.expect(Bits.equals(&value, &value_from_tree));

        const tree_size = Bits.fixed_size;
        try std.testing.expectEqual(tc.serialized.len, tree_size);

        var tree_serialized: [Bits.fixed_size]u8 = undefined;
        _ = try Bits.tree.serializeIntoBytes(tree_node, &pool, &tree_serialized);
        try std.testing.expectEqualSlices(u8, &tc.serialized, &tree_serialized);

        var hash_root: [32]u8 = undefined;
        try Bits.hashTreeRoot(&value, &hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

// Refer to https://github.com/ChainSafe/ssz/blob/f5ed0b457333749b5c3f49fa5eafa096a725f033/packages/ssz/test/unit/byType/bitVector/valid.test.ts#L23-L42
test "BitVectorType - tree roundtrip 512 bits" {
    const allocator = std.testing.allocator;

    const Bits = BitVectorType(512);

    const TestCase = struct {
        id: []const u8,
        serialized: [64]u8,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty (one bit set)",
            // 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
            .serialized = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
            // 0x90f4b39548df55ad6187a1d20d731ecee78c545b94afd16f42ef7592d99cd365
            .expected_root = [_]u8{ 0x90, 0xf4, 0xb3, 0x95, 0x48, 0xdf, 0x55, 0xad, 0x61, 0x87, 0xa1, 0xd2, 0x0d, 0x73, 0x1e, 0xce, 0xe7, 0x8c, 0x54, 0x5b, 0x94, 0xaf, 0xd1, 0x6f, 0x42, 0xef, 0x75, 0x92, 0xd9, 0x9c, 0xd3, 0x65 },
        },
        .{
            .id = "some value",
            // 0xb55b8592bcac475906631481bbc746bccb647cbb184136609574cacb2958b55bb55b8592bcac475906631481bbc746bccb647cbb184136609574cacb2958b55b
            .serialized = [_]u8{ 0xb5, 0x5b, 0x85, 0x92, 0xbc, 0xac, 0x47, 0x59, 0x06, 0x63, 0x14, 0x81, 0xbb, 0xc7, 0x46, 0xbc, 0xcb, 0x64, 0x7c, 0xbb, 0x18, 0x41, 0x36, 0x60, 0x95, 0x74, 0xca, 0xcb, 0x29, 0x58, 0xb5, 0x5b, 0xb5, 0x5b, 0x85, 0x92, 0xbc, 0xac, 0x47, 0x59, 0x06, 0x63, 0x14, 0x81, 0xbb, 0xc7, 0x46, 0xbc, 0xcb, 0x64, 0x7c, 0xbb, 0x18, 0x41, 0x36, 0x60, 0x95, 0x74, 0xca, 0xcb, 0x29, 0x58, 0xb5, 0x5b },
            // 0xf5619a9b3c6831a68fdbd1b30b69843c778b9d36ed1ff6831339ba0f723dbea0
            .expected_root = [_]u8{ 0xf5, 0x61, 0x9a, 0x9b, 0x3c, 0x68, 0x31, 0xa6, 0x8f, 0xdb, 0xd1, 0xb3, 0x0b, 0x69, 0x84, 0x3c, 0x77, 0x8b, 0x9d, 0x36, 0xed, 0x1f, 0xf6, 0x83, 0x13, 0x39, 0xba, 0x0f, 0x72, 0x3d, 0xbe, 0xa0 },
        },
    };

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    for (test_cases) |tc| {
        var value: Bits = undefined;
        try Bits.deserializeFromBytes(&tc.serialized, &value);

        const tree_node = try Bits.tree.fromValue(&pool, &value);

        var value_from_tree: Bits = undefined;
        try Bits.tree.toValue(tree_node, &pool, &value_from_tree);

        try std.testing.expect(Bits.equals(&value, &value_from_tree));

        const tree_size = Bits.fixed_size;
        try std.testing.expectEqual(tc.serialized.len, tree_size);

        var tree_serialized: [Bits.fixed_size]u8 = undefined;
        _ = try Bits.tree.serializeIntoBytes(tree_node, &pool, &tree_serialized);
        try std.testing.expectEqualSlices(u8, &tc.serialized, &tree_serialized);

        var hash_root: [32]u8 = undefined;
        try Bits.hashTreeRoot(&value, &hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "BitVectorType - tree.deserializeFromBytes 128 bits" {
    const allocator = std.testing.allocator;

    const Bits = BitVectorType(128);

    const TestCase = struct {
        id: []const u8,
        serialized: [16]u8,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty (one bit set)",
            .serialized = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
            .expected_root = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        },
        .{
            .id = "some value",
            .serialized = [_]u8{ 0xb5, 0x5b, 0x85, 0x92, 0xbc, 0xac, 0x47, 0x59, 0x06, 0x63, 0x14, 0x81, 0xbb, 0xc7, 0x46, 0xbc },
            .expected_root = [_]u8{ 0xb5, 0x5b, 0x85, 0x92, 0xbc, 0xac, 0x47, 0x59, 0x06, 0x63, 0x14, 0x81, 0xbb, 0xc7, 0x46, 0xbc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        },
    };

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    for (test_cases) |tc| {
        const tree_node = try Bits.tree.deserializeFromBytes(&pool, &tc.serialized);

        const node_root = tree_node.getRoot(&pool);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, node_root);

        var value_from_tree: Bits = undefined;
        try Bits.tree.toValue(tree_node, &pool, &value_from_tree);

        var tree_serialized: [Bits.fixed_size]u8 = undefined;
        _ = try Bits.tree.serializeIntoBytes(tree_node, &pool, &tree_serialized);
        try std.testing.expectEqualSlices(u8, &tc.serialized, &tree_serialized);

        var hash_root: [32]u8 = undefined;
        try Bits.hashTreeRoot(&value_from_tree, &hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

const TypeTestCase = @import("test_utils.zig").TypeTestCase;
test "BitVectorType of 128 bits" {
    const testCases = [_]TypeTestCase{
        .{
            .id = "empty",
            .serializedHex = "0x00000000000000000000000000000001",
            .json =
            \\"0x00000000000000000000000000000001"
            ,
            .rootHex = "0x0000000000000000000000000000000100000000000000000000000000000000",
        },
        .{
            .id = "some value",
            .serializedHex = "0xb55b8592bcac475906631481bbc746bc",
            .json =
            \\"0xb55b8592bcac475906631481bbc746bc"
            ,
            .rootHex = "0xb55b8592bcac475906631481bbc746bc00000000000000000000000000000000",
        },
    };

    const allocator = std.testing.allocator;
    const BV = BitVectorType(128);
    const TypeTest = @import("test_utils.zig").typeTest(BV);

    for (testCases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}

test "BitVectorType of 512 bits" {
    const testCases = [_]TypeTestCase{
        .{
            .id = "empty",
            .serializedHex = "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
            .json =
            \\"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"
            ,
            .rootHex = "0x90f4b39548df55ad6187a1d20d731ecee78c545b94afd16f42ef7592d99cd365",
        },
        .{
            .id = "some value",
            .serializedHex = "0xb55b8592bcac475906631481bbc746bccb647cbb184136609574cacb2958b55bb55b8592bcac475906631481bbc746bccb647cbb184136609574cacb2958b55b",
            .json =
            \\"0xb55b8592bcac475906631481bbc746bccb647cbb184136609574cacb2958b55bb55b8592bcac475906631481bbc746bccb647cbb184136609574cacb2958b55b"
            ,
            .rootHex = "0xf5619a9b3c6831a68fdbd1b30b69843c778b9d36ed1ff6831339ba0f723dbea0",
        },
    };

    const allocator = std.testing.allocator;
    const BV = BitVectorType(512);
    const TypeTest = @import("test_utils.zig").typeTest(BV);

    for (testCases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}

test "BitVectorType equals" {
    const BV = BitVectorType(16);

    var a = BV.Type.empty;
    var b = BV.Type.empty;
    var c = BV.Type.empty;

    try a.set(0, true);
    try a.set(5, true);
    try a.set(15, true);

    try b.set(0, true);
    try b.set(5, true);
    try b.set(15, true);

    try c.set(0, true);
    try c.set(5, true);
    try c.set(14, true);

    try std.testing.expect(BV.equals(&a, &b));
    try std.testing.expect(!BV.equals(&a, &c));
}

test "BitVectorType - default_root" {
    const Bits128 = BitVectorType(128);
    var expected_root: [32]u8 = undefined;
    try Bits128.hashTreeRoot(&Bits128.default_value, &expected_root);
    try std.testing.expectEqualSlices(u8, &Bits128.default_root, &expected_root);

    const Bits513 = BitVectorType(513);
    try Bits513.hashTreeRoot(&Bits513.default_value, &expected_root);
    try std.testing.expectEqualSlices(u8, &Bits513.default_root, &expected_root);

    var pool = try Node.Pool.init(std.testing.allocator, 1024);
    defer pool.deinit();

    const node_128 = try Bits128.tree.default(&pool);
    try std.testing.expectEqualSlices(u8, &Bits128.default_root, node_128.getRoot(&pool));

    const node_513 = try Bits513.tree.default(&pool);
    try std.testing.expectEqualSlices(u8, &Bits513.default_root, node_513.getRoot(&pool));
}
