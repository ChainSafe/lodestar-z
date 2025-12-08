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
const chunk = @import("chunk.zig");
const chunkDepth = chunk.chunkDepth;

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
                try node.getNodesAtDepth(pool, chunkDepth(u8, chunk_depth, true), 0, nodes);

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
