const std = @import("std");
const expectEqualRootsAlloc = @import("test_utils.zig").expectEqualRootsAlloc;
const expectEqualSerializedAlloc = @import("test_utils.zig").expectEqualSerializedAlloc;
const TypeKind = @import("type_kind.zig").TypeKind;
const UintType = @import("uint.zig").UintType;
const hexToBytes = @import("hex").hexToBytes;
const hexByteLen = @import("hex").hexByteLen;
const hexLenFromBytes = @import("hex").hexLenFromBytes;
const bytesToHex = @import("hex").bytesToHex;
const merkleize = @import("hashing").merkleize;
const mixInLength = @import("hashing").mixInLength;
const maxChunksToDepth = @import("hashing").maxChunksToDepth;
const Node = @import("persistent_merkle_tree").Node;
const ListBasicTreeView = @import("../tree_view/root.zig").ListBasicTreeView;

pub fn isByteListType(ST: type) bool {
    return ST.kind == .list and ST.Element.kind == .uint and ST.Element.fixed_size == 1 and ST == ByteListType(ST.limit);
}

pub fn ByteListType(comptime _limit: comptime_int) type {
    comptime {
        if (_limit <= 0) {
            @compileError("limit must be greater than 0");
        }
    }
    return struct {
        pub const kind = TypeKind.list;
        pub const Element: type = UintType(8);
        pub const limit: usize = _limit;
        pub const Type: type = std.ArrayListUnmanaged(Element.Type);
        pub const TreeView: type = ListBasicTreeView(@This());
        pub const min_size: usize = 0;
        pub const max_size: usize = Element.fixed_size * limit;
        pub const max_chunk_count: usize = std.math.divCeil(usize, max_size, 32) catch unreachable;
        pub const chunk_depth: u8 = maxChunksToDepth(max_chunk_count);

        pub const default_value: Type = Type.empty;

        pub fn equals(a: *const Type, b: *const Type) bool {
            return std.mem.eql(u8, a.items, b.items);
        }

        pub fn deinit(allocator: std.mem.Allocator, value: *Type) void {
            value.deinit(allocator);
        }

        pub fn chunkCount(value: *const Type) usize {
            return (value.items.len + 31) / 32;
        }

        pub fn hashTreeRoot(allocator: std.mem.Allocator, value: *const Type, out: *[32]u8) !void {
            const chunks = try allocator.alloc([32]u8, (chunkCount(value) + 1) / 2 * 2);
            defer allocator.free(chunks);

            @memset(chunks, [_]u8{0} ** 32);

            _ = serializeIntoBytes(value, @ptrCast(chunks));

            try merkleize(@ptrCast(chunks), chunk_depth, out);
            mixInLength(value.items.len, out);
        }

        /// Clones the underlying `ArrayList`.
        ///
        /// Caller owns the memory.
        pub fn clone(allocator: std.mem.Allocator, value: *const Type, out: *Type) !void {
            out.* = try value.clone(allocator);
        }

        pub fn serializedSize(value: *const Type) usize {
            return value.items.len * Element.fixed_size;
        }

        pub fn serializeIntoBytes(value: *const Type, out: []u8) usize {
            @memcpy(out[0..value.items.len], value.items);
            return value.items.len;
        }

        pub const serialized = struct {
            pub fn validate(data: []const u8) !void {
                if (data.len > limit) {
                    return error.gtLimit;
                }
            }

            pub fn length(data: []const u8) !usize {
                if (data.len > limit) {
                    return error.gtLimit;
                }
                return data.len;
            }

            pub fn hashTreeRoot(allocator: std.mem.Allocator, data: []const u8, out: *[32]u8) !void {
                const len = try length(data);
                const chunk_count = (len + 31) / 32;
                const chunks = try allocator.alloc([32]u8, (chunk_count + 1) / 2 * 2);
                defer allocator.free(chunks);

                @memset(chunks, [_]u8{0} ** 32);
                @memcpy(@as([]u8, @ptrCast(chunks))[0..data.len], data);

                try merkleize(@ptrCast(chunks), chunk_depth, out);
                mixInLength(len, out);
            }
        };

        pub const tree = struct {
            pub fn deserializeFromBytes(allocator: std.mem.Allocator, pool: *Node.Pool, data: []const u8) !Node.Id {
                if (data.len > limit) {
                    return error.gtLimit;
                }

                const len: usize = data.len;
                const chunk_count = (len + 31) / 32;
                if (chunk_count == 0) {
                    return try pool.createBranch(
                        @enumFromInt(chunk_depth),
                        @enumFromInt(0),
                    );
                }

                const chunks = try allocator.alloc([32]u8, chunk_count);
                defer allocator.free(chunks);
                @memset(chunks, [_]u8{0} ** 32);

                const chunk_bytes: []u8 = @ptrCast(chunks);
                @memcpy(chunk_bytes[0..len], data[0..len]);

                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);
                for (chunks, 0..) |*chunk, i| {
                    nodes[i] = try pool.createLeaf(chunk);
                }

                return try pool.createBranch(
                    try Node.fillWithContents(pool, nodes, chunk_depth),
                    try pool.createLeafFromUint(len),
                );
            }

            pub fn length(node: Node.Id, pool: *Node.Pool) !usize {
                const right = try node.getRight(pool);
                const hash = right.getRoot(pool);
                return std.mem.readInt(usize, hash[0..8], .little);
            }

            pub fn toValue(allocator: std.mem.Allocator, node: Node.Id, pool: *Node.Pool, out: *Type) !void {
                const len = try length(node, pool);
                const chunk_count = (len + 31) / 32;
                if (chunk_count == 0) {
                    try out.resize(allocator, 0);
                    return;
                }

                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);
                try node.getNodesAtDepth(pool, chunk_depth + 1, 0, nodes);

                try out.resize(allocator, len);
                for (0..chunk_count) |i| {
                    const start_idx = i * 32;
                    const remaining_bytes = len - start_idx;

                    // Determine how many bytes to copy for this chunk
                    const bytes_to_copy = @min(remaining_bytes, 32);

                    // Copy data if there are bytes to copy
                    if (bytes_to_copy > 0) {
                        @memcpy(out.items[start_idx..][0..bytes_to_copy], nodes[i].getRoot(pool)[0..bytes_to_copy]);
                    }
                }
            }

            pub fn fromValue(allocator: std.mem.Allocator, pool: *Node.Pool, value: *const Type) !Node.Id {
                const chunk_count = chunkCount(value);
                if (chunk_count == 0) {
                    return try pool.createBranch(
                        @enumFromInt(chunk_depth),
                        @enumFromInt(0),
                    );
                }

                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);
                for (0..chunk_count) |i| {
                    var leaf_buf = [_]u8{0} ** 32;
                    const start_idx = i * 32;
                    const remaining_bytes = value.items.len - start_idx;

                    // Determine how many bytes to copy for this chunk
                    const bytes_to_copy = @min(remaining_bytes, 32);

                    // Copy data if there are bytes to copy
                    if (bytes_to_copy > 0) {
                        @memcpy(leaf_buf[0..bytes_to_copy], value.items[start_idx..][0..bytes_to_copy]);
                    }

                    nodes[i] = try pool.createLeaf(&leaf_buf);
                }
                return try pool.createBranch(
                    try Node.fillWithContents(pool, nodes[0..chunk_count], chunk_depth),
                    try pool.createLeafFromUint(value.items.len),
                );
            }

            pub fn serializeIntoBytes(allocator: std.mem.Allocator, node: Node.Id, pool: *Node.Pool, out: []u8) !usize {
                const len = try length(node, pool);
                const chunk_count = (len + 31) / 32;
                if (chunk_count == 0) {
                    return 0;
                }

                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);
                try node.getNodesAtDepth(pool, chunk_depth + 1, 0, nodes);

                for (0..chunk_count) |i| {
                    const start_idx = i * 32;
                    const remaining_bytes = len - start_idx;
                    const bytes_to_copy = @min(remaining_bytes, 32);
                    if (bytes_to_copy > 0) {
                        @memcpy(out[start_idx..][0..bytes_to_copy], nodes[i].getRoot(pool)[0..bytes_to_copy]);
                    }
                }
                return len;
            }

            pub fn serializedSize(node: Node.Id, pool: *Node.Pool) !usize {
                return try length(node, pool);
            }
        };

        pub fn deserializeFromBytes(allocator: std.mem.Allocator, data: []const u8, out: *Type) !void {
            if (data.len > limit) {
                return error.invalidLength;
            }

            try out.resize(allocator, data.len);
            @memcpy(out.items, data);
        }

        pub fn serializeIntoJson(allocator: std.mem.Allocator, writer: anytype, in: *const Type) !void {
            const byte_str = try allocator.alloc(u8, hexLenFromBytes(in.*.items));
            defer allocator.free(byte_str);

            _ = try bytesToHex(byte_str, in.*.items);
            try writer.print("\"{s}\"", .{byte_str});
        }

        pub fn deserializeFromJson(allocator: std.mem.Allocator, source: *std.json.Scanner, out: *Type) !void {
            const hex_bytes = switch (try source.next()) {
                .string => |v| v,
                else => return error.InvalidJson,
            };

            const hex_bytes_len = hexByteLen(hex_bytes);
            if (hex_bytes_len > limit) {
                return error.InvalidJson;
            }

            try out.resize(allocator, hex_bytes_len);
            _ = try hexToBytes(out.items, hex_bytes);
        }
    };
}
test "clone" {
    const allocator = std.testing.allocator;

    const length = 44;
    const Bits = ByteListType(length);
    var b = Bits.default_value;
    defer b.deinit(allocator);
    try b.append(allocator, 5);

    var cloned: Bits.Type = undefined;
    defer cloned.deinit(allocator);
    try Bits.clone(allocator, &b, &cloned);
    try std.testing.expect(&b != &cloned);
    try std.testing.expect(std.mem.eql(u8, b.items, cloned.items));
    try expectEqualRootsAlloc(Bits, allocator, b, cloned);
    try expectEqualSerializedAlloc(Bits, allocator, b, cloned);
}

// Refer to https://github.com/ChainSafe/ssz/blob/f5ed0b457333749b5c3f49fa5eafa096a725f033/packages/ssz/test/unit/byType/byteList/valid.test.ts#L26-L77
test "ByteListType - serializeIntoBytes (empty)" {
    const allocator = std.testing.allocator;
    const ByteList256 = ByteListType(256);

    var value = ByteList256.default_value;
    defer value.deinit(allocator);

    const size = ByteList256.serializedSize(&value);
    try std.testing.expectEqual(@as(usize, 0), size);

    var root: [32]u8 = undefined;
    try ByteList256.hashTreeRoot(allocator, &value, &root);
    // 0xe8e527e84f666163a90ef900e013f56b0a4d020148b2224057b719f351b003a6
    const expected_root = [_]u8{ 0xe8, 0xe5, 0x27, 0xe8, 0x4f, 0x66, 0x61, 0x63, 0xa9, 0x0e, 0xf9, 0x00, 0xe0, 0x13, 0xf5, 0x6b, 0x0a, 0x4d, 0x02, 0x01, 0x48, 0xb2, 0x22, 0x40, 0x57, 0xb7, 0x19, 0xf3, 0x51, 0xb0, 0x03, 0xa6 };
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();
    const tree_node = try ByteList256.tree.fromValue(allocator, &pool, &value);
    const tree_size = try ByteList256.tree.serializedSize(tree_node, &pool);
    try std.testing.expectEqual(@as(usize, 0), tree_size);
}

test "ByteListType - serializeIntoBytes (4 bytes zero)" {
    const allocator = std.testing.allocator;
    const ByteList256 = ByteListType(256);

    var value = ByteList256.default_value;
    defer value.deinit(allocator);
    try value.appendSlice(allocator, &[_]u8{ 0x00, 0x00, 0x00, 0x00 });

    var serialized: [4]u8 = undefined;
    const size = ByteList256.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 4), size);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x00, 0x00 }, &serialized);

    var root: [32]u8 = undefined;
    try ByteList256.hashTreeRoot(allocator, &value, &root);
    // 0xa39babe565305429771fc596a639d6e05b2d0304297986cdd2ef388c1936885e
    const expected_root = [_]u8{ 0xa3, 0x9b, 0xab, 0xe5, 0x65, 0x30, 0x54, 0x29, 0x77, 0x1f, 0xc5, 0x96, 0xa6, 0x39, 0xd6, 0xe0, 0x5b, 0x2d, 0x03, 0x04, 0x29, 0x79, 0x86, 0xcd, 0xd2, 0xef, 0x38, 0x8c, 0x19, 0x36, 0x88, 0x5e };
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();
    const tree_node = try ByteList256.tree.fromValue(allocator, &pool, &value);
    var tree_serialized: [4]u8 = undefined;
    _ = try ByteList256.tree.serializeIntoBytes(allocator, tree_node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &serialized, &tree_serialized);
}

test "ByteListType - serializeIntoBytes (4 bytes some value)" {
    const allocator = std.testing.allocator;
    const ByteList256 = ByteListType(256);

    var value = ByteList256.default_value;
    defer value.deinit(allocator);
    // 0x0cb94737
    try value.appendSlice(allocator, &[_]u8{ 0x0c, 0xb9, 0x47, 0x37 });

    var serialized: [4]u8 = undefined;
    const size = ByteList256.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 4), size);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x0c, 0xb9, 0x47, 0x37 }, &serialized);

    var root: [32]u8 = undefined;
    try ByteList256.hashTreeRoot(allocator, &value, &root);
    // 0x2e14da116ecbec4c8d693656fb5b69bb0ea9e84ecdd15aba7be1c008633f2885
    const expected_root = [_]u8{ 0x2e, 0x14, 0xda, 0x11, 0x6e, 0xcb, 0xec, 0x4c, 0x8d, 0x69, 0x36, 0x56, 0xfb, 0x5b, 0x69, 0xbb, 0x0e, 0xa9, 0xe8, 0x4e, 0xcd, 0xd1, 0x5a, 0xba, 0x7b, 0xe1, 0xc0, 0x08, 0x63, 0x3f, 0x28, 0x85 };
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();
    const tree_node = try ByteList256.tree.fromValue(allocator, &pool, &value);
    var tree_serialized: [4]u8 = undefined;
    _ = try ByteList256.tree.serializeIntoBytes(allocator, tree_node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &serialized, &tree_serialized);
}

test "ByteListType - serializeIntoBytes (32 bytes zero)" {
    const allocator = std.testing.allocator;
    const ByteList256 = ByteListType(256);

    var value = ByteList256.default_value;
    defer value.deinit(allocator);
    try value.appendSlice(allocator, &([_]u8{0x00} ** 32));

    var serialized: [32]u8 = undefined;
    const size = ByteList256.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 32), size);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x00} ** 32), &serialized);

    var root: [32]u8 = undefined;
    try ByteList256.hashTreeRoot(allocator, &value, &root);
    // 0xbae146b221eca758702e29b45ee7f7dc3eea17d119dd0a3094481e3f94706c96
    const expected_root = [_]u8{ 0xba, 0xe1, 0x46, 0xb2, 0x21, 0xec, 0xa7, 0x58, 0x70, 0x2e, 0x29, 0xb4, 0x5e, 0xe7, 0xf7, 0xdc, 0x3e, 0xea, 0x17, 0xd1, 0x19, 0xdd, 0x0a, 0x30, 0x94, 0x48, 0x1e, 0x3f, 0x94, 0x70, 0x6c, 0x96 };
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();
    const tree_node = try ByteList256.tree.fromValue(allocator, &pool, &value);
    var tree_serialized: [32]u8 = undefined;
    _ = try ByteList256.tree.serializeIntoBytes(allocator, tree_node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &serialized, &tree_serialized);
}

test "ByteListType - serializeIntoBytes (32 bytes some value)" {
    const allocator = std.testing.allocator;
    const ByteList256 = ByteListType(256);

    var value = ByteList256.default_value;
    defer value.deinit(allocator);
    // 0x0cb947377e177f774719ead8d210af9c6461f41baf5b4082f86a3911454831b8
    const data = [_]u8{ 0x0c, 0xb9, 0x47, 0x37, 0x7e, 0x17, 0x7f, 0x77, 0x47, 0x19, 0xea, 0xd8, 0xd2, 0x10, 0xaf, 0x9c, 0x64, 0x61, 0xf4, 0x1b, 0xaf, 0x5b, 0x40, 0x82, 0xf8, 0x6a, 0x39, 0x11, 0x45, 0x48, 0x31, 0xb8 };
    try value.appendSlice(allocator, &data);

    var serialized: [32]u8 = undefined;
    const size = ByteList256.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 32), size);
    try std.testing.expectEqualSlices(u8, &data, &serialized);

    var root: [32]u8 = undefined;
    try ByteList256.hashTreeRoot(allocator, &value, &root);
    // 0x50425dbd7a34b50b20916e965ce5c060abe6516ac71bb00a4afebe5d5c4568b8
    const expected_root = [_]u8{ 0x50, 0x42, 0x5d, 0xbd, 0x7a, 0x34, 0xb5, 0x0b, 0x20, 0x91, 0x6e, 0x96, 0x5c, 0xe5, 0xc0, 0x60, 0xab, 0xe6, 0x51, 0x6a, 0xc7, 0x1b, 0xb0, 0x0a, 0x4a, 0xfe, 0xbe, 0x5d, 0x5c, 0x45, 0x68, 0xb8 };
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();
    const tree_node = try ByteList256.tree.fromValue(allocator, &pool, &value);
    var tree_serialized: [32]u8 = undefined;
    _ = try ByteList256.tree.serializeIntoBytes(allocator, tree_node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &serialized, &tree_serialized);
}

test "ByteListType - serializeIntoBytes (96 bytes some value)" {
    const allocator = std.testing.allocator;
    const ByteList256 = ByteListType(256);

    var value = ByteList256.default_value;
    defer value.deinit(allocator);
    // 0xb55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1 repeated 3 times
    const chunk = [_]u8{ 0xb5, 0x5b, 0x85, 0x92, 0xbc, 0xac, 0x47, 0x59, 0x06, 0x63, 0x14, 0x81, 0xbb, 0xc7, 0x46, 0xbc, 0xa7, 0x33, 0x9d, 0x04, 0xab, 0x10, 0x85, 0xe8, 0x48, 0x84, 0xa7, 0x00, 0xc0, 0x3d, 0xe4, 0xb1 };
    try value.appendSlice(allocator, &chunk);
    try value.appendSlice(allocator, &chunk);
    try value.appendSlice(allocator, &chunk);

    var serialized: [96]u8 = undefined;
    const size = ByteList256.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 96), size);
    try std.testing.expectEqualSlices(u8, &chunk, serialized[0..32]);
    try std.testing.expectEqualSlices(u8, &chunk, serialized[32..64]);
    try std.testing.expectEqualSlices(u8, &chunk, serialized[64..96]);

    var root: [32]u8 = undefined;
    try ByteList256.hashTreeRoot(allocator, &value, &root);
    // 0x5d3ae4b886c241ffe8dc7ae1b5f0e2fb9b682e1eac2ddea292ef02cc179e6903
    const expected_root = [_]u8{ 0x5d, 0x3a, 0xe4, 0xb8, 0x86, 0xc2, 0x41, 0xff, 0xe8, 0xdc, 0x7a, 0xe1, 0xb5, 0xf0, 0xe2, 0xfb, 0x9b, 0x68, 0x2e, 0x1e, 0xac, 0x2d, 0xde, 0xa2, 0x92, 0xef, 0x02, 0xcc, 0x17, 0x9e, 0x69, 0x03 };
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();
    const tree_node = try ByteList256.tree.fromValue(allocator, &pool, &value);
    var tree_serialized: [96]u8 = undefined;
    _ = try ByteList256.tree.serializeIntoBytes(allocator, tree_node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &serialized, &tree_serialized);
}

test "ByteListType - tree.deserializeFromBytes (32 bytes)" {
    const allocator = std.testing.allocator;
    const ByteList256 = ByteListType(256);

    // 0x0cb947377e177f774719ead8d210af9c6461f41baf5b4082f86a3911454831b8
    const serialized = [_]u8{ 0x0c, 0xb9, 0x47, 0x37, 0x7e, 0x17, 0x7f, 0x77, 0x47, 0x19, 0xea, 0xd8, 0xd2, 0x10, 0xaf, 0x9c, 0x64, 0x61, 0xf4, 0x1b, 0xaf, 0x5b, 0x40, 0x82, 0xf8, 0x6a, 0x39, 0x11, 0x45, 0x48, 0x31, 0xb8 };
    // 0x50425dbd7a34b50b20916e965ce5c060abe6516ac71bb00a4afebe5d5c4568b8
    const expected_root = [_]u8{ 0x50, 0x42, 0x5d, 0xbd, 0x7a, 0x34, 0xb5, 0x0b, 0x20, 0x91, 0x6e, 0x96, 0x5c, 0xe5, 0xc0, 0x60, 0xab, 0xe6, 0x51, 0x6a, 0xc7, 0x1b, 0xb0, 0x0a, 0x4a, 0xfe, 0xbe, 0x5d, 0x5c, 0x45, 0x68, 0xb8 };

    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();

    const tree_node = try ByteList256.tree.deserializeFromBytes(allocator, &pool, &serialized);

    const node_root = tree_node.getRoot(&pool);
    try std.testing.expectEqualSlices(u8, &expected_root, node_root);

    var value_from_tree: ByteList256.Type = ByteList256.default_value;
    defer value_from_tree.deinit(allocator);
    try ByteList256.tree.toValue(allocator, tree_node, &pool, &value_from_tree);

    var tree_serialized: [32]u8 = undefined;
    _ = try ByteList256.tree.serializeIntoBytes(allocator, tree_node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &serialized, &tree_serialized);

    var hash_root: [32]u8 = undefined;
    try ByteList256.hashTreeRoot(allocator, &value_from_tree, &hash_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &hash_root);
}

test "ByteListType - tree.deserializeFromBytes (96 bytes)" {
    const allocator = std.testing.allocator;
    const ByteList256 = ByteListType(256);

    // 0xb55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1 repeated 3 times
    const chunk = [_]u8{ 0xb5, 0x5b, 0x85, 0x92, 0xbc, 0xac, 0x47, 0x59, 0x06, 0x63, 0x14, 0x81, 0xbb, 0xc7, 0x46, 0xbc, 0xa7, 0x33, 0x9d, 0x04, 0xab, 0x10, 0x85, 0xe8, 0x48, 0x84, 0xa7, 0x00, 0xc0, 0x3d, 0xe4, 0xb1 };
    const serialized = chunk ++ chunk ++ chunk;
    // 0x5d3ae4b886c241ffe8dc7ae1b5f0e2fb9b682e1eac2ddea292ef02cc179e6903
    const expected_root = [_]u8{ 0x5d, 0x3a, 0xe4, 0xb8, 0x86, 0xc2, 0x41, 0xff, 0xe8, 0xdc, 0x7a, 0xe1, 0xb5, 0xf0, 0xe2, 0xfb, 0x9b, 0x68, 0x2e, 0x1e, 0xac, 0x2d, 0xde, 0xa2, 0x92, 0xef, 0x02, 0xcc, 0x17, 0x9e, 0x69, 0x03 };

    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();

    const tree_node = try ByteList256.tree.deserializeFromBytes(allocator, &pool, &serialized);

    const node_root = tree_node.getRoot(&pool);
    try std.testing.expectEqualSlices(u8, &expected_root, node_root);

    var value_from_tree: ByteList256.Type = ByteList256.default_value;
    defer value_from_tree.deinit(allocator);
    try ByteList256.tree.toValue(allocator, tree_node, &pool, &value_from_tree);

    var tree_serialized: [96]u8 = undefined;
    _ = try ByteList256.tree.serializeIntoBytes(allocator, tree_node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &serialized, &tree_serialized);

    var hash_root: [32]u8 = undefined;
    try ByteList256.hashTreeRoot(allocator, &value_from_tree, &hash_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &hash_root);
}
