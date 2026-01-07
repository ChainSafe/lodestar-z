const std = @import("std");
const expectEqualRoots = @import("test_utils.zig").expectEqualRoots;
const expectEqualSerialized = @import("test_utils.zig").expectEqualSerialized;
const TypeKind = @import("type_kind.zig").TypeKind;
const UintType = @import("uint.zig").UintType;
const hexToBytes = @import("hex").hexToBytes;
const hexByteLen = @import("hex").hexByteLen;
const hexLenFromBytes = @import("hex").hexLenFromBytes;
const bytesToHex = @import("hex").bytesToHex;
const merkleize = @import("hashing").merkleize;
const maxChunksToDepth = @import("hashing").maxChunksToDepth;
const Depth = @import("hashing").Depth;
const Node = @import("persistent_merkle_tree").Node;
const ArrayBasicTreeView = @import("../tree_view/root.zig").ArrayBasicTreeView;

pub fn isByteVectorType(ST: type) bool {
    return ST.kind == .vector and ST.Element.kind == .uint and ST.Element.fixed_size == 1 and ST == ByteVectorType(ST.length);
}

pub fn ByteVectorType(comptime _length: comptime_int) type {
    comptime {
        if (_length <= 0) {
            @compileError("length must be greater than 0");
        }
    }
    return struct {
        pub const kind = TypeKind.vector;
        pub const Element: type = UintType(8);
        pub const length: usize = _length;
        pub const Type: type = [length]Element.Type;
        pub const TreeView: type = ArrayBasicTreeView(@This());
        pub const fixed_size: usize = Element.fixed_size * length;
        pub const chunk_count: usize = std.math.divCeil(usize, fixed_size, 32) catch unreachable;
        pub const chunk_depth: Depth = maxChunksToDepth(chunk_count);

        pub const default_value: Type = [_]Element.Type{Element.default_value} ** length;

        pub fn equals(a: *const Type, b: *const Type) bool {
            return std.mem.eql(u8, a, b);
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
            @memcpy(out[0..fixed_size], value);
            return length;
        }

        pub fn deserializeFromBytes(data: []const u8, out: *Type) !void {
            if (data.len != fixed_size) {
                return error.InvalidSize;
            }

            @memcpy(out, data[0..fixed_size]);
        }

        pub const serialized = struct {
            pub fn validate(data: []const u8) !void {
                if (data.len != fixed_size) {
                    return error.InvalidSize;
                }
            }

            pub fn hashTreeRoot(data: []const u8, out: *[32]u8) !void {
                var chunks = [_][32]u8{[_]u8{0} ** 32} ** ((chunk_count + 1) / 2 * 2);
                @memcpy(@as([]u8, @ptrCast(&chunks))[0..fixed_size], data);
                try merkleize(@ptrCast(&chunks), chunk_depth, out);
            }
        };

        pub const tree = struct {
            pub fn deserializeFromBytes(pool: *Node.Pool, data: []const u8) !Node.Id {
                if (data.len != fixed_size) {
                    return error.InvalidSize;
                }

                var chunks: [chunk_count][32]u8 = [_][32]u8{[_]u8{0} ** 32} ** chunk_count;
                const chunk_bytes: []u8 = @ptrCast(&chunks);
                @memcpy(chunk_bytes[0..length], data[0..length]);

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
                    const remaining_bytes = length - start_idx;

                    // Determine how many bytes to copy for this chunk
                    const bytes_to_copy = @min(remaining_bytes, 32);

                    // Copy data if there are bytes to copy
                    if (bytes_to_copy > 0) {
                        @memcpy(out[start_idx..][0..bytes_to_copy], nodes[i].getRoot(pool)[0..bytes_to_copy]);
                    }
                }
            }

            pub fn fromValue(pool: *Node.Pool, value: *const Type) !Node.Id {
                var nodes: [chunk_count]Node.Id = undefined;
                for (0..chunk_count) |i| {
                    var leaf_buf = [_]u8{0} ** 32;
                    const start_idx = i * 32;
                    const remaining_bytes = length - start_idx;

                    // Determine how many bytes to copy for this chunk
                    const bytes_to_copy = @min(remaining_bytes, 32);

                    // Copy data if there are bytes to copy
                    if (bytes_to_copy > 0) {
                        @memcpy(leaf_buf[0..bytes_to_copy], value[start_idx..][0..bytes_to_copy]);
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
                    const remaining_bytes = length - start_idx;
                    const bytes_to_copy = @min(remaining_bytes, 32);
                    if (bytes_to_copy > 0) {
                        @memcpy(out[start_idx..][0..bytes_to_copy], nodes[i].getRoot(pool)[0..bytes_to_copy]);
                    }
                }
                return fixed_size;
            }
        };

        pub fn serializeIntoJson(writer: anytype, in: *const Type) !void {
            var byte_str: [2 + 2 * fixed_size]u8 = undefined;

            _ = try bytesToHex(&byte_str, in);
            try writer.print("\"{s}\"", .{byte_str});
        }

        pub fn deserializeFromJson(source: *std.json.Scanner, out: *Type) !void {
            const hex_bytes = switch (try source.next()) {
                .string => |v| v,
                else => return error.InvalidJson,
            };

            if (hexByteLen(hex_bytes) != length) {
                return error.InvalidJson;
            }
            _ = try hexToBytes(out, hex_bytes);
        }
    };
}

test "clone" {
    const length = 44;
    const Bytes = ByteVectorType(length);

    var b = [_]u8{1} ** length;
    var cloned: [44]u8 = undefined;
    try Bytes.clone(&b, &cloned);
    try std.testing.expect(&b != &cloned);
    try std.testing.expect(std.mem.eql(u8, b[0..], cloned[0..]));
    try expectEqualRoots(Bytes, b, cloned);
    try expectEqualSerialized(Bytes, b, cloned);
}

// Refer to https://github.com/ChainSafe/ssz/blob/f5ed0b457333749b5c3f49fa5eafa096a725f033/packages/ssz/test/unit/byType/byteVector/valid.test.ts#L4-L61
test "ByteVectorType(4) - serializeIntoBytes (zero)" {
    const allocator = std.testing.allocator;
    const ByteVector4 = ByteVectorType(4);

    const value = [_]u8{ 0x00, 0x00, 0x00, 0x00 };

    var serialized: [4]u8 = undefined;
    const size = ByteVector4.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 4), size);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x00, 0x00 }, &serialized);

    var root: [32]u8 = undefined;
    try ByteVector4.hashTreeRoot(&value, &root);
    // 0x0000000000000000000000000000000000000000000000000000000000000000
    const expected_root = [_]u8{0x00} ** 32;
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 32);
    defer pool.deinit();
    const tree_node = try ByteVector4.tree.fromValue(&pool, &value);
    var tree_serialized: [4]u8 = undefined;
    _ = try ByteVector4.tree.serializeIntoBytes(tree_node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &serialized, &tree_serialized);
}

test "ByteVectorType(4) - serializeIntoBytes (some value)" {
    const allocator = std.testing.allocator;
    const ByteVector4 = ByteVectorType(4);

    // 0x0cb94737
    const value = [_]u8{ 0x0c, 0xb9, 0x47, 0x37 };

    var serialized: [4]u8 = undefined;
    const size = ByteVector4.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 4), size);
    try std.testing.expectEqualSlices(u8, &value, &serialized);

    var root: [32]u8 = undefined;
    try ByteVector4.hashTreeRoot(&value, &root);
    // 0x0cb9473700000000000000000000000000000000000000000000000000000000
    const expected_root = [_]u8{ 0x0c, 0xb9, 0x47, 0x37 } ++ [_]u8{0x00} ** 28;
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 32);
    defer pool.deinit();
    const tree_node = try ByteVector4.tree.fromValue(&pool, &value);
    var tree_serialized: [4]u8 = undefined;
    _ = try ByteVector4.tree.serializeIntoBytes(tree_node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &serialized, &tree_serialized);
}

test "ByteVectorType(32) - serializeIntoBytes (zero)" {
    const allocator = std.testing.allocator;
    const ByteVector32 = ByteVectorType(32);

    const value = [_]u8{0x00} ** 32;

    var serialized: [32]u8 = undefined;
    const size = ByteVector32.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 32), size);
    try std.testing.expectEqualSlices(u8, &value, &serialized);

    var root: [32]u8 = undefined;
    try ByteVector32.hashTreeRoot(&value, &root);
    // 0x0000000000000000000000000000000000000000000000000000000000000000
    const expected_root = [_]u8{0x00} ** 32;
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 32);
    defer pool.deinit();
    const tree_node = try ByteVector32.tree.fromValue(&pool, &value);
    var tree_serialized: [32]u8 = undefined;
    _ = try ByteVector32.tree.serializeIntoBytes(tree_node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &serialized, &tree_serialized);
}

test "ByteVectorType(32) - serializeIntoBytes (some value)" {
    const allocator = std.testing.allocator;
    const ByteVector32 = ByteVectorType(32);

    // 0x0cb947377e177f774719ead8d210af9c6461f41baf5b4082f86a3911454831b8
    const value = [_]u8{ 0x0c, 0xb9, 0x47, 0x37, 0x7e, 0x17, 0x7f, 0x77, 0x47, 0x19, 0xea, 0xd8, 0xd2, 0x10, 0xaf, 0x9c, 0x64, 0x61, 0xf4, 0x1b, 0xaf, 0x5b, 0x40, 0x82, 0xf8, 0x6a, 0x39, 0x11, 0x45, 0x48, 0x31, 0xb8 };

    var serialized: [32]u8 = undefined;
    const size = ByteVector32.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 32), size);
    try std.testing.expectEqualSlices(u8, &value, &serialized);

    var root: [32]u8 = undefined;
    try ByteVector32.hashTreeRoot(&value, &root);
    // root equals the value itself for 32-byte vector
    try std.testing.expectEqualSlices(u8, &value, &root);

    var pool = try Node.Pool.init(allocator, 32);
    defer pool.deinit();
    const tree_node = try ByteVector32.tree.fromValue(&pool, &value);
    var tree_serialized: [32]u8 = undefined;
    _ = try ByteVector32.tree.serializeIntoBytes(tree_node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &serialized, &tree_serialized);
}

test "ByteVectorType(96) - serializeIntoBytes (zero)" {
    const allocator = std.testing.allocator;
    const ByteVector96 = ByteVectorType(96);

    const value = [_]u8{0x00} ** 96;

    var serialized: [96]u8 = undefined;
    const size = ByteVector96.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 96), size);
    try std.testing.expectEqualSlices(u8, &value, &serialized);

    var root: [32]u8 = undefined;
    try ByteVector96.hashTreeRoot(&value, &root);
    // 0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71
    const expected_root = [_]u8{ 0xdb, 0x56, 0x11, 0x4e, 0x00, 0xfd, 0xd4, 0xc1, 0xf8, 0x5c, 0x89, 0x2b, 0xf3, 0x5a, 0xc9, 0xa8, 0x92, 0x89, 0xaa, 0xec, 0xb1, 0xeb, 0xd0, 0xa9, 0x6c, 0xde, 0x60, 0x6a, 0x74, 0x8b, 0x5d, 0x71 };
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();
    const tree_node = try ByteVector96.tree.fromValue(&pool, &value);
    var tree_serialized: [96]u8 = undefined;
    _ = try ByteVector96.tree.serializeIntoBytes(tree_node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &serialized, &tree_serialized);
}

test "ByteVectorType(96) - serializeIntoBytes (some value)" {
    const allocator = std.testing.allocator;
    const ByteVector96 = ByteVectorType(96);

    // 0xb55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1 repeated 3 times
    const chunk = [_]u8{ 0xb5, 0x5b, 0x85, 0x92, 0xbc, 0xac, 0x47, 0x59, 0x06, 0x63, 0x14, 0x81, 0xbb, 0xc7, 0x46, 0xbc, 0xa7, 0x33, 0x9d, 0x04, 0xab, 0x10, 0x85, 0xe8, 0x48, 0x84, 0xa7, 0x00, 0xc0, 0x3d, 0xe4, 0xb1 };
    const value = chunk ++ chunk ++ chunk;

    var serialized: [96]u8 = undefined;
    const size = ByteVector96.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 96), size);
    try std.testing.expectEqualSlices(u8, &value, &serialized);

    var root: [32]u8 = undefined;
    try ByteVector96.hashTreeRoot(&value, &root);
    // 0x032eecca637b67fd922e0e421b4be9c22948719ba02c6d03eb2c61cfdc4cb3e3
    const expected_root = [_]u8{ 0x03, 0x2e, 0xec, 0xca, 0x63, 0x7b, 0x67, 0xfd, 0x92, 0x2e, 0x0e, 0x42, 0x1b, 0x4b, 0xe9, 0xc2, 0x29, 0x48, 0x71, 0x9b, 0xa0, 0x2c, 0x6d, 0x03, 0xeb, 0x2c, 0x61, 0xcf, 0xdc, 0x4c, 0xb3, 0xe3 };
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();
    const tree_node = try ByteVector96.tree.fromValue(&pool, &value);
    var tree_serialized: [96]u8 = undefined;
    _ = try ByteVector96.tree.serializeIntoBytes(tree_node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &serialized, &tree_serialized);
}

test "ByteVectorType(32) - tree.deserializeFromBytes" {
    const allocator = std.testing.allocator;
    const ByteVector32 = ByteVectorType(32);

    const TestCase = struct {
        id: []const u8,
        serialized: [32]u8,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "zero",
            .serialized = [_]u8{0x00} ** 32,
            .expected_root = [_]u8{0x00} ** 32,
        },
        .{
            .id = "some value",
            .serialized = [_]u8{ 0x0c, 0xb9, 0x47, 0x37, 0x7e, 0x17, 0x7f, 0x77, 0x47, 0x19, 0xea, 0xd8, 0xd2, 0x10, 0xaf, 0x9c, 0x64, 0x61, 0xf4, 0x1b, 0xaf, 0x5b, 0x40, 0x82, 0xf8, 0x6a, 0x39, 0x11, 0x45, 0x48, 0x31, 0xb8 },
            .expected_root = [_]u8{ 0x0c, 0xb9, 0x47, 0x37, 0x7e, 0x17, 0x7f, 0x77, 0x47, 0x19, 0xea, 0xd8, 0xd2, 0x10, 0xaf, 0x9c, 0x64, 0x61, 0xf4, 0x1b, 0xaf, 0x5b, 0x40, 0x82, 0xf8, 0x6a, 0x39, 0x11, 0x45, 0x48, 0x31, 0xb8 },
        },
    };

    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();

    for (test_cases) |tc| {
        const tree_node = try ByteVector32.tree.deserializeFromBytes(&pool, &tc.serialized);

        const node_root = tree_node.getRoot(&pool);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, node_root);

        var value_from_tree: ByteVector32.Type = undefined;
        try ByteVector32.tree.toValue(tree_node, &pool, &value_from_tree);

        var tree_serialized: [32]u8 = undefined;
        _ = try ByteVector32.tree.serializeIntoBytes(tree_node, &pool, &tree_serialized);
        try std.testing.expectEqualSlices(u8, &tc.serialized, &tree_serialized);

        var hash_root: [32]u8 = undefined;
        try ByteVector32.hashTreeRoot(&value_from_tree, &hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "ByteVectorType(96) - tree.deserializeFromBytes" {
    const allocator = std.testing.allocator;
    const ByteVector96 = ByteVectorType(96);

    // 0xb55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1 repeated 3 times
    const chunk = [_]u8{ 0xb5, 0x5b, 0x85, 0x92, 0xbc, 0xac, 0x47, 0x59, 0x06, 0x63, 0x14, 0x81, 0xbb, 0xc7, 0x46, 0xbc, 0xa7, 0x33, 0x9d, 0x04, 0xab, 0x10, 0x85, 0xe8, 0x48, 0x84, 0xa7, 0x00, 0xc0, 0x3d, 0xe4, 0xb1 };
    const serialized = chunk ++ chunk ++ chunk;
    // 0x032eecca637b67fd922e0e421b4be9c22948719ba02c6d03eb2c61cfdc4cb3e3
    const expected_root = [_]u8{ 0x03, 0x2e, 0xec, 0xca, 0x63, 0x7b, 0x67, 0xfd, 0x92, 0x2e, 0x0e, 0x42, 0x1b, 0x4b, 0xe9, 0xc2, 0x29, 0x48, 0x71, 0x9b, 0xa0, 0x2c, 0x6d, 0x03, 0xeb, 0x2c, 0x61, 0xcf, 0xdc, 0x4c, 0xb3, 0xe3 };

    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();

    const tree_node = try ByteVector96.tree.deserializeFromBytes(&pool, &serialized);

    const node_root = tree_node.getRoot(&pool);
    try std.testing.expectEqualSlices(u8, &expected_root, node_root);

    var value_from_tree: ByteVector96.Type = undefined;
    try ByteVector96.tree.toValue(tree_node, &pool, &value_from_tree);

    var tree_serialized: [96]u8 = undefined;
    _ = try ByteVector96.tree.serializeIntoBytes(tree_node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &serialized, &tree_serialized);

    var hash_root: [32]u8 = undefined;
    try ByteVector96.hashTreeRoot(&value_from_tree, &hash_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &hash_root);
}
