const std = @import("std");
const TypeKind = @import("type_kind.zig").TypeKind;
const expectEqualRoots = @import("test_utils.zig").expectEqualRoots;
const expectEqualSerialized = @import("test_utils.zig").expectEqualSerialized;
const Node = @import("persistent_merkle_tree").Node;

pub fn UintType(comptime bits: comptime_int) type {
    const NativeType = switch (bits) {
        8 => u8,
        16 => u16,
        32 => u32,
        64 => u64,
        128 => u128,
        256 => u256,
        else => @compileError("bits must be 8, 16, 32, 64, 128, 256"),
    };
    const bytes = bits / 8;
    return struct {
        pub const kind = TypeKind.uint;
        pub const Type: type = NativeType;
        pub const fixed_size: usize = bytes;

        pub const default_value: Type = 0;

        pub fn equals(a: *const Type, b: *const Type) bool {
            return a.* == b.*;
        }

        pub fn hashTreeRoot(value: *const Type, out: *[32]u8) !void {
            @memset(out, 0);
            std.mem.writeInt(Type, out[0..fixed_size], value.*, .little);
        }

        pub fn clone(value: *const Type, out: *Type) !void {
            out.* = value.*;
        }

        pub fn serializeIntoBytes(value: *const Type, out: []u8) usize {
            std.mem.writeInt(Type, out[0..bytes], value.*, .little);
            return bytes;
        }

        pub fn deserializeFromBytes(data: []const u8, out: *Type) !void {
            if (data.len != fixed_size) {
                return error.InvalidSize;
            }

            out.* = std.mem.readInt(Type, data[0..bytes], .little);
        }

        pub const serialized = struct {
            pub fn validate(data: []const u8) !void {
                if (data.len != fixed_size) {
                    return error.InvalidSize;
                }
            }

            pub fn hashTreeRoot(data: []const u8, out: *[32]u8) !void {
                @memset(out, 0);
                @memcpy(out[0..fixed_size], data);
            }
        };

        pub const tree = struct {
            pub fn toValue(node: Node.Id, pool: *Node.Pool, out: *Type) !void {
                const hash = node.getRoot(pool);
                out.* = std.mem.readInt(Type, hash[0..bytes], .little);
            }

            pub fn fromValue(pool: *Node.Pool, value: *const Type) !Node.Id {
                var new_leaf: [32]u8 = [_]u8{0} ** 32;
                std.mem.writeInt(Type, new_leaf[0..bytes], value.*, .little);
                return try pool.createLeaf(&new_leaf);
            }

            pub fn toValuePacked(node: Node.Id, pool: *Node.Pool, index: usize, out: *Type) !void {
                const hash = node.getRoot(pool);
                const offset = index * fixed_size % 32;
                out.* = std.mem.readInt(Type, hash[offset..][0..fixed_size], .little);
            }

            pub fn fromValuePacked(node: Node.Id, pool: *Node.Pool, index: usize, value: *const Type) !Node.Id {
                const hash = node.getRoot(pool);
                var new_leaf: [32]u8 = hash.*;
                const offset = (index * bytes) % 32;
                std.mem.writeInt(Type, new_leaf[offset..][0..bytes], value.*, .little);
                return try pool.createLeaf(&new_leaf);
            }

            pub fn serializeIntoBytes(node: Node.Id, pool: *Node.Pool, out: []u8) usize {
                const hash = node.getRoot(pool);
                @memcpy(out[0..fixed_size], hash[0..fixed_size]);
                return fixed_size;
            }

            pub fn serializedSize(_: Node.Id, _: *Node.Pool) usize {
                return fixed_size;
            }
        };

        pub fn serializeIntoJson(writer: anytype, in: *const Type) !void {
            try writer.print("\"{d}\"", .{in.*});
        }

        pub fn deserializeFromJson(scanner: *std.json.Scanner, out: *Type) !void {
            try switch (try scanner.next()) {
                .string => |v| {
                    out.* = try std.fmt.parseInt(Type, v, 10);
                },
                else => error.invalidJson,
            };
        }
    };
}

test "UintType - sanity" {
    const Uint8 = UintType(8);

    var u: Uint8.Type = undefined;
    var u_buf: [Uint8.fixed_size]u8 = undefined;
    _ = Uint8.serializeIntoBytes(&u, &u_buf);
    try Uint8.deserializeFromBytes(&u_buf, &u);

    // Deserialize "255" into u;
    const input_json = "\"255\"";
    const allocator = std.testing.allocator;
    var json = std.json.Scanner.initCompleteInput(allocator, input_json);
    defer json.deinit();
    try Uint8.deserializeFromJson(&json, &u);

    // Serialize u into "255"
    var output_json = std.ArrayList(u8).init(allocator);
    defer output_json.deinit();
    var write_stream = std.json.writeStream(output_json.writer(), .{});
    defer write_stream.deinit();
    try Uint8.serializeIntoJson(&write_stream, &u);
    var cloned: Uint8.Type = undefined;
    try Uint8.clone(&u, &cloned);
    try expectEqualRoots(Uint8, u, cloned);
    try expectEqualSerialized(Uint8, u, cloned);

    try std.testing.expectEqualSlices(u8, input_json, output_json.items);
}

// Refer to https://github.com/ChainSafe/ssz/blob/f5ed0b457333749b5c3f49fa5eafa096a725f033/packages/ssz/test/unit/byType/uint/valid.test.ts#L4-L135
test "UintType(8) - serializeIntoBytes (0x00)" {
    const allocator = std.testing.allocator;
    const Uint8 = UintType(8);

    const value: Uint8.Type = 0;

    const expected_serialized = [_]u8{0x00};
    const expected_root = [_]u8{0x00} ++ [_]u8{0x00} ** 31;

    var serialized: [Uint8.fixed_size]u8 = undefined;
    const written = Uint8.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 1), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &serialized);

    var root: [32]u8 = undefined;
    try Uint8.hashTreeRoot(&value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try Uint8.tree.fromValue(&pool, &value);
    var tree_serialized: [Uint8.fixed_size]u8 = undefined;
    _ = Uint8.tree.serializeIntoBytes(node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &tree_serialized);
}

test "UintType(8) - serializeIntoBytes (0xff)" {
    const allocator = std.testing.allocator;
    const Uint8 = UintType(8);

    const value: Uint8.Type = 255;

    const expected_serialized = [_]u8{0xff};
    const expected_root = [_]u8{0xff} ++ [_]u8{0x00} ** 31;

    var serialized: [Uint8.fixed_size]u8 = undefined;
    const written = Uint8.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 1), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &serialized);

    var root: [32]u8 = undefined;
    try Uint8.hashTreeRoot(&value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try Uint8.tree.fromValue(&pool, &value);
    var tree_serialized: [Uint8.fixed_size]u8 = undefined;
    _ = Uint8.tree.serializeIntoBytes(node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &tree_serialized);
}

test "UintType(16) - serializeIntoBytes (2^8)" {
    const allocator = std.testing.allocator;
    const Uint16 = UintType(16);

    const value: Uint16.Type = 256; // 2^8

    const expected_serialized = [_]u8{ 0x00, 0x01 };

    var serialized: [Uint16.fixed_size]u8 = undefined;
    const written = Uint16.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 2), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &serialized);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try Uint16.tree.fromValue(&pool, &value);
    var tree_serialized: [Uint16.fixed_size]u8 = undefined;
    _ = Uint16.tree.serializeIntoBytes(node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &tree_serialized);
}

test "UintType(16) - serializeIntoBytes (0xffff)" {
    const allocator = std.testing.allocator;
    const Uint16 = UintType(16);

    const value: Uint16.Type = 65535; // 2^16 - 1

    const expected_serialized = [_]u8{ 0xff, 0xff };

    var serialized: [Uint16.fixed_size]u8 = undefined;
    const written = Uint16.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 2), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &serialized);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try Uint16.tree.fromValue(&pool, &value);
    var tree_serialized: [Uint16.fixed_size]u8 = undefined;
    _ = Uint16.tree.serializeIntoBytes(node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &tree_serialized);
}

test "UintType(32) - serializeIntoBytes (0x00000000)" {
    const allocator = std.testing.allocator;
    const Uint32 = UintType(32);

    const value: Uint32.Type = 0;

    const expected_serialized = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
    const expected_root = [_]u8{ 0x00, 0x00, 0x00, 0x00 } ++ [_]u8{0x00} ** 28;

    var serialized: [Uint32.fixed_size]u8 = undefined;
    const written = Uint32.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 4), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &serialized);

    var root: [32]u8 = undefined;
    try Uint32.hashTreeRoot(&value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try Uint32.tree.fromValue(&pool, &value);
    var tree_serialized: [Uint32.fixed_size]u8 = undefined;
    _ = Uint32.tree.serializeIntoBytes(node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &tree_serialized);
}

test "UintType(32) - serializeIntoBytes (0xffffffff)" {
    const allocator = std.testing.allocator;
    const Uint32 = UintType(32);

    const value: Uint32.Type = 4294967295;

    const expected_serialized = [_]u8{ 0xff, 0xff, 0xff, 0xff };
    const expected_root = [_]u8{ 0xff, 0xff, 0xff, 0xff } ++ [_]u8{0x00} ** 28;

    var serialized: [Uint32.fixed_size]u8 = undefined;
    const written = Uint32.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 4), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &serialized);

    var root: [32]u8 = undefined;
    try Uint32.hashTreeRoot(&value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try Uint32.tree.fromValue(&pool, &value);
    var tree_serialized: [Uint32.fixed_size]u8 = undefined;
    _ = Uint32.tree.serializeIntoBytes(node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &tree_serialized);
}

test "UintType(64) - serializeIntoBytes (100000)" {
    const allocator = std.testing.allocator;
    const Uint64 = UintType(64);

    const value: Uint64.Type = 100000;

    const expected_serialized = [_]u8{ 0xa0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const expected_root = [_]u8{ 0xa0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 } ++ [_]u8{0x00} ** 24;

    var serialized: [Uint64.fixed_size]u8 = undefined;
    const written = Uint64.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 8), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &serialized);

    var root: [32]u8 = undefined;
    try Uint64.hashTreeRoot(&value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try Uint64.tree.fromValue(&pool, &value);
    var tree_serialized: [Uint64.fixed_size]u8 = undefined;
    _ = Uint64.tree.serializeIntoBytes(node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &tree_serialized);
}

test "UintType(64) - serializeIntoBytes (max)" {
    const allocator = std.testing.allocator;
    const Uint64 = UintType(64);

    const value: Uint64.Type = 18446744073709551615;

    const expected_serialized = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    const expected_root = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } ++ [_]u8{0x00} ** 24;

    var serialized: [Uint64.fixed_size]u8 = undefined;
    const written = Uint64.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 8), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &serialized);

    var root: [32]u8 = undefined;
    try Uint64.hashTreeRoot(&value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try Uint64.tree.fromValue(&pool, &value);
    var tree_serialized: [Uint64.fixed_size]u8 = undefined;
    _ = Uint64.tree.serializeIntoBytes(node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &tree_serialized);
}

test "UintType(128) - serializeIntoBytes (0x01)" {
    const allocator = std.testing.allocator;
    const Uint128 = UintType(128);

    const value: Uint128.Type = 0x01;

    const expected_serialized = [_]u8{0x01} ++ [_]u8{0x00} ** 15;
    const expected_root = [_]u8{0x01} ++ [_]u8{0x00} ** 31;

    var serialized: [Uint128.fixed_size]u8 = undefined;
    const written = Uint128.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 16), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &serialized);

    var root: [32]u8 = undefined;
    try Uint128.hashTreeRoot(&value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try Uint128.tree.fromValue(&pool, &value);
    var tree_serialized: [Uint128.fixed_size]u8 = undefined;
    _ = Uint128.tree.serializeIntoBytes(node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &tree_serialized);
}

test "UintType(128) - serializeIntoBytes (max)" {
    const allocator = std.testing.allocator;
    const Uint128 = UintType(128);

    const value: Uint128.Type = 0xffffffffffffffffffffffffffffffff;

    const expected_serialized = [_]u8{0xff} ** 16;
    const expected_root = [_]u8{0xff} ** 16 ++ [_]u8{0x00} ** 16;

    var serialized: [Uint128.fixed_size]u8 = undefined;
    const written = Uint128.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 16), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &serialized);

    var root: [32]u8 = undefined;
    try Uint128.hashTreeRoot(&value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try Uint128.tree.fromValue(&pool, &value);
    var tree_serialized: [Uint128.fixed_size]u8 = undefined;
    _ = Uint128.tree.serializeIntoBytes(node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &tree_serialized);
}

test "UintType(256) - serializeIntoBytes (0xaabb)" {
    const allocator = std.testing.allocator;
    const Uint256 = UintType(256);

    const value: Uint256.Type = 0xaabb;

    const expected_serialized = [_]u8{ 0xbb, 0xaa } ++ [_]u8{0x00} ** 30;
    const expected_root = [_]u8{ 0xbb, 0xaa } ++ [_]u8{0x00} ** 30;

    var serialized: [Uint256.fixed_size]u8 = undefined;
    const written = Uint256.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 32), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &serialized);

    var root: [32]u8 = undefined;
    try Uint256.hashTreeRoot(&value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try Uint256.tree.fromValue(&pool, &value);
    var tree_serialized: [Uint256.fixed_size]u8 = undefined;
    _ = Uint256.tree.serializeIntoBytes(node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &tree_serialized);
}

test "UintType(256) - serializeIntoBytes (max)" {
    const allocator = std.testing.allocator;
    const Uint256 = UintType(256);

    const value: Uint256.Type = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    const expected_serialized = [_]u8{0xff} ** 32;
    const expected_root = [_]u8{0xff} ** 32;

    var serialized: [Uint256.fixed_size]u8 = undefined;
    const written = Uint256.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 32), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &serialized);

    var root: [32]u8 = undefined;
    try Uint256.hashTreeRoot(&value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();
    const node = try Uint256.tree.fromValue(&pool, &value);
    var tree_serialized: [Uint256.fixed_size]u8 = undefined;
    _ = Uint256.tree.serializeIntoBytes(node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &tree_serialized);
}
