const std = @import("std");
const TypeKind = @import("type_kind.zig").TypeKind;
const expectEqualSerialized = @import("test_utils.zig").expectEqualSerialized;
const expectEqualRoots = @import("test_utils.zig").expectEqualRoots;
const Node = @import("persistent_merkle_tree").Node;

pub fn BoolType() type {
    return struct {
        pub const kind = TypeKind.bool;
        pub const Type: type = bool;
        pub const fixed_size: usize = 1;

        pub const default_value: Type = false;

        pub fn equals(a: *const Type, b: *const Type) bool {
            return a.* == b.*;
        }

        pub fn clone(value: *const Type, out: *Type) !void {
            out.* = value.*;
        }

        pub fn hashTreeRoot(value: *const Type, out: *[32]u8) !void {
            @memset(out, 0);
            out[0] = if (value.*) 1 else 0;
        }

        pub fn serializeIntoBytes(value: *const Type, out: []u8) usize {
            const byte: u8 = if (value.*) 1 else 0;
            out[0] = byte;
            return 1;
        }

        pub fn deserializeFromBytes(data: []const u8, out: *Type) !void {
            if (data.len != 1) {
                return error.InvalidSize;
            }
            const byte = data[0];
            switch (byte) {
                0 => out.* = false,
                1 => out.* = true,
                else => return error.invalidBoolean,
            }
        }

        pub const serialized = struct {
            pub fn validate(data: []const u8) !void {
                if (data.len != 1) {
                    return error.InvalidSize;
                }
                switch (data[0]) {
                    0, 1 => {},
                    else => return error.invalidBoolean,
                }
            }

            pub fn hashTreeRoot(data: []const u8, out: *[32]u8) !void {
                @memset(out, 0);
                @memcpy(out[0..fixed_size], data);
            }
        };

        pub const tree = struct {
            pub fn deserializeFromBytes(pool: *Node.Pool, data: []const u8) !Node.Id {
                try serialized.validate(data);
                var leaf: [32]u8 = [_]u8{0} ** 32;
                leaf[0] = data[0];
                return try pool.createLeaf(&leaf);
            }

            pub fn toValue(node: Node.Id, pool: *Node.Pool, out: *Type) !void {
                const hash = node.getRoot(pool);
                out.* = if (hash[0] == 0) false else true;
            }

            pub fn fromValue(pool: *Node.Pool, value: *const Type) !Node.Id {
                const byte: u8 = if (value.*) 1 else 0;
                return try pool.createLeafFromUint(byte);
            }

            pub fn toValuePacked(node: Node.Id, pool: *Node.Pool, index: usize, out: *Type) !void {
                const offset = index % 32;
                const hash = node.getRoot(pool);
                out.* = if (hash[offset] == 0) false else true;
            }

            pub fn fromValuePacked(node: Node.Id, pool: *Node.Pool, index: usize, value: *const Type) !Node.Id {
                const hash = node.getRoot(pool);
                var new_leaf: [32]u8 = hash.*;
                const offset = index % 32;
                new_leaf[offset] = if (value.*) 1 else 0;
                return try pool.createLeaf(&new_leaf);
            }

            pub fn serializeIntoBytes(node: Node.Id, pool: *Node.Pool, out: []u8) usize {
                const hash = node.getRoot(pool);
                out[0] = hash[0];
                return fixed_size;
            }

            pub fn serializedSize(_: Node.Id, _: *Node.Pool) usize {
                return fixed_size;
            }
        };

        pub fn serializeIntoJson(writer: anytype, in: *const Type) !void {
            try writer.write(in.*);
        }

        pub fn deserializeFromJson(scanner: *std.json.Scanner, out: *Type) !void {
            switch (try scanner.next()) {
                .true => out.* = true,
                .false => out.* = false,
                else => return error.invalidJson,
            }
        }
    };
}

test "BoolType - sanity" {
    const Bool = BoolType();

    var b: Bool.Type = undefined;

    const input_json = "true";
    const allocator = std.testing.allocator;

    // Deserialize
    var json = std.json.Scanner.initCompleteInput(allocator, input_json);
    defer json.deinit();
    try Bool.deserializeFromJson(&json, &b);

    // Serialize
    var output_json = std.ArrayList(u8).init(allocator);
    defer output_json.deinit();
    var write_stream = std.json.writeStream(output_json.writer(), .{});
    defer write_stream.deinit();
    try Bool.serializeIntoJson(&write_stream, &b);

    var cloned: Bool.Type = undefined;
    try Bool.clone(&b, &cloned);

    try expectEqualRoots(Bool, b, cloned);
    try std.testing.expectEqualSlices(u8, input_json, output_json.items);
    try expectEqualSerialized(Bool, b, cloned);
}

// Refer to https://github.com/ChainSafe/ssz/blob/f5ed0b457333749b5c3f49fa5eafa096a725f033/packages/ssz/test/unit/byType/boolean/valid.test.ts#L4-L21
test "BoolType - serializeIntoBytes (false)" {
    const Bool = BoolType();
    const value: Bool.Type = false;

    var serialized: [1]u8 = undefined;
    const size = Bool.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 1), size);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x00}, &serialized);

    var root: [32]u8 = undefined;
    try Bool.hashTreeRoot(&value, &root);
    const expected_root = [_]u8{0x00} ++ [_]u8{0x00} ** 31;
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 32);
    defer pool.deinit();
    const tree_node = try Bool.tree.fromValue(&pool, &value);
    var tree_serialized: [1]u8 = undefined;
    _ = Bool.tree.serializeIntoBytes(tree_node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &serialized, &tree_serialized);
}

test "BoolType - serializeIntoBytes (true)" {
    const Bool = BoolType();
    const value: Bool.Type = true;

    var serialized: [1]u8 = undefined;
    const size = Bool.serializeIntoBytes(&value, &serialized);
    try std.testing.expectEqual(@as(usize, 1), size);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x01}, &serialized);

    var root: [32]u8 = undefined;
    try Bool.hashTreeRoot(&value, &root);
    const expected_root = [_]u8{0x01} ++ [_]u8{0x00} ** 31;
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 32);
    defer pool.deinit();
    const tree_node = try Bool.tree.fromValue(&pool, &value);
    var tree_serialized: [1]u8 = undefined;
    _ = Bool.tree.serializeIntoBytes(tree_node, &pool, &tree_serialized);
    try std.testing.expectEqualSlices(u8, &serialized, &tree_serialized);
}

test "BoolType - tree.deserializeFromBytes" {
    const allocator = std.testing.allocator;
    const Bool = BoolType();

    const TestCase = struct {
        id: []const u8,
        serialized: [1]u8,
        expected_value: bool,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{ .id = "false", .serialized = [_]u8{0x00}, .expected_value = false, .expected_root = [_]u8{0x00} ++ [_]u8{0x00} ** 31 },
        .{ .id = "true", .serialized = [_]u8{0x01}, .expected_value = true, .expected_root = [_]u8{0x01} ++ [_]u8{0x00} ** 31 },
    };

    var pool = try Node.Pool.init(allocator, 32);
    defer pool.deinit();

    for (test_cases) |tc| {
        const tree_node = try Bool.tree.deserializeFromBytes(&pool, &tc.serialized);

        const node_root = tree_node.getRoot(&pool);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, node_root);

        var value_from_tree: Bool.Type = undefined;
        try Bool.tree.toValue(tree_node, &pool, &value_from_tree);
        try std.testing.expectEqual(tc.expected_value, value_from_tree);

        var tree_serialized: [1]u8 = undefined;
        _ = Bool.tree.serializeIntoBytes(tree_node, &pool, &tree_serialized);
        try std.testing.expectEqualSlices(u8, &tc.serialized, &tree_serialized);

        var hash_root: [32]u8 = undefined;
        try Bool.hashTreeRoot(&value_from_tree, &hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }

    try std.testing.expectError(error.invalidBoolean, Bool.tree.deserializeFromBytes(&pool, &[_]u8{0x02}));
    try std.testing.expectError(error.InvalidSize, Bool.tree.deserializeFromBytes(&pool, &[_]u8{}));
}
