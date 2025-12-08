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
