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
            pub fn deserializeFromBytes(pool: *Node.Pool, data: []const u8) !Node.Id {
                if (data.len != fixed_size) {
                    return error.InvalidSize;
                }
                var leaf: [32]u8 = [_]u8{0} ** 32;
                @memcpy(leaf[0..fixed_size], data);
                return try pool.createLeaf(&leaf);
            }

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

            pub fn serializeIntoBytes(node: Node.Id, pool: *Node.Pool, out: []u8) !usize {
                const hash = node.getRoot(pool);
                @memcpy(out[0..fixed_size], hash[0..fixed_size]);
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

fn testFixed(
    allocator: std.mem.Allocator,
    comptime ST: type,
    value: ST.Type,
    expected_serialized: []const u8,
    expected_root: []const u8,
) !void {
    var serialized: [ST.fixed_size]u8 = undefined;
    const written = ST.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(ST.fixed_size, written);
    try std.testing.expectEqualSlices(u8, expected_serialized, &serialized);

    var root: [32]u8 = undefined;
    try ST.hashTreeRoot(&value, &root);
    try std.testing.expectEqualSlices(u8, expected_root, &root);

    var value_from_serialized: ST.Type = undefined;
    try ST.deserializeFromBytes(&serialized, &value_from_serialized);
    try std.testing.expectEqual(value, value_from_serialized);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const tree_from_value = try ST.tree.fromValue(&pool, &value);
    try std.testing.expectEqualSlices(u8, expected_root, tree_from_value.getRoot(&pool));

    var value_from_tree: ST.Type = undefined;
    try ST.tree.toValue(tree_from_value, &pool, &value_from_tree);
    try std.testing.expectEqual(value, value_from_tree);

    var tree_serialized: [ST.fixed_size]u8 = undefined;
    _ = try ST.tree.serializeIntoBytes(tree_from_value, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, expected_serialized, &tree_serialized);

    const tree_from_serialized = try ST.tree.deserializeFromBytes(&pool, expected_serialized);
    try std.testing.expectEqualSlices(u8, expected_root, tree_from_serialized.getRoot(&pool));

    try std.testing.expectError(error.InvalidSize, ST.tree.deserializeFromBytes(&pool, &[_]u8{}));
}

// Refer to https://github.com/ChainSafe/ssz/blob/f5ed0b457333749b5c3f49fa5eafa096a725f033/packages/ssz/test/unit/byType/uint/valid.test.ts#L4-L135
test "UintType(8) - 0x00" {
    try testFixed(
        std.testing.allocator,
        UintType(8),
        0,
        &[_]u8{0x00},
        &[_]u8{0x00} ++ [_]u8{0x00} ** 31,
    );
}

test "UintType(8) - 0xff" {
    try testFixed(
        std.testing.allocator,
        UintType(8),
        255,
        &[_]u8{0xff},
        &[_]u8{0xff} ++ [_]u8{0x00} ** 31,
    );
}

test "UintType(16) - 2^8" {
    try testFixed(
        std.testing.allocator,
        UintType(16),
        256,
        &[_]u8{ 0x00, 0x01 },
        &[_]u8{ 0x00, 0x01 } ++ [_]u8{0x00} ** 30,
    );
}

test "UintType(16) - 0xffff" {
    try testFixed(
        std.testing.allocator,
        UintType(16),
        65535,
        &[_]u8{ 0xff, 0xff },
        &[_]u8{ 0xff, 0xff } ++ [_]u8{0x00} ** 30,
    );
}

test "UintType(32) - 0x00000000" {
    try testFixed(
        std.testing.allocator,
        UintType(32),
        0,
        &[_]u8{ 0x00, 0x00, 0x00, 0x00 },
        &[_]u8{ 0x00, 0x00, 0x00, 0x00 } ++ [_]u8{0x00} ** 28,
    );
}

test "UintType(32) - 0xffffffff" {
    try testFixed(
        std.testing.allocator,
        UintType(32),
        4294967295,
        &[_]u8{ 0xff, 0xff, 0xff, 0xff },
        &[_]u8{ 0xff, 0xff, 0xff, 0xff } ++ [_]u8{0x00} ** 28,
    );
}

test "UintType(64) - 100000" {
    try testFixed(
        std.testing.allocator,
        UintType(64),
        100000,
        &[_]u8{ 0xa0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 },
        &[_]u8{ 0xa0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 } ++ [_]u8{0x00} ** 24,
    );
}

test "UintType(64) - max" {
    try testFixed(
        std.testing.allocator,
        UintType(64),
        18446744073709551615,
        &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } ++ [_]u8{0x00} ** 24,
    );
}

test "UintType(128) - 0x01" {
    try testFixed(
        std.testing.allocator,
        UintType(128),
        0x01,
        &[_]u8{0x01} ++ [_]u8{0x00} ** 15,
        &[_]u8{0x01} ++ [_]u8{0x00} ** 31,
    );
}

test "UintType(128) - max" {
    try testFixed(
        std.testing.allocator,
        UintType(128),
        0xffffffffffffffffffffffffffffffff,
        &[_]u8{0xff} ** 16,
        &[_]u8{0xff} ** 16 ++ [_]u8{0x00} ** 16,
    );
}

test "UintType(256) - 0xaabb" {
    try testFixed(
        std.testing.allocator,
        UintType(256),
        0xaabb,
        &[_]u8{ 0xbb, 0xaa } ++ [_]u8{0x00} ** 30,
        &[_]u8{ 0xbb, 0xaa } ++ [_]u8{0x00} ** 30,
    );
}

test "UintType(256) - max" {
    try testFixed(
        std.testing.allocator,
        UintType(256),
        0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
        &[_]u8{0xff} ** 32,
        &[_]u8{0xff} ** 32,
    );
}
