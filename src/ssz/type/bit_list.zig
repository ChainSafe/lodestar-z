const std = @import("std");
const expectEqualRootsAlloc = @import("test_utils.zig").expectEqualRootsAlloc;
const expectEqualSerializedAlloc = @import("test_utils.zig").expectEqualSerializedAlloc;
const TypeKind = @import("type_kind.zig").TypeKind;
const BoolType = @import("bool.zig").BoolType;
const hexToBytes = @import("hex").hexToBytes;
const bytesToHex = @import("hex").bytesToHex;
const hexByteLen = @import("hex").hexByteLen;
const hexLenFromBytes = @import("hex").hexLenFromBytes;
const merkleize = @import("hashing").merkleize;
const mixInLength = @import("hashing").mixInLength;
const maxChunksToDepth = @import("hashing").maxChunksToDepth;
const Node = @import("persistent_merkle_tree").Node;

pub fn BitList(comptime limit: comptime_int) type {
    return struct {
        data: std.ArrayListUnmanaged(u8),
        bit_len: usize,

        pub const empty: @This() = .{
            .data = std.ArrayListUnmanaged(u8).empty,
            .bit_len = 0,
        };

        pub fn equals(self: *const @This(), other: *const @This()) bool {
            return self.bit_len == other.bit_len and std.mem.eql(u8, self.data.items, other.data.items);
        }

        pub fn fromBitLen(allocator: std.mem.Allocator, bit_len: usize) !@This() {
            if (bit_len > limit) {
                return error.tooLarge;
            }

            const byte_len = std.math.divCeil(usize, bit_len, 8) catch unreachable;

            var data = try std.ArrayListUnmanaged(u8).initCapacity(allocator, byte_len);
            data.expandToCapacity();
            @memset(data.items, 0);
            return @This(){
                .data = data,
                .bit_len = bit_len,
            };
        }

        pub fn fromBoolSlice(allocator: std.mem.Allocator, bools: []const bool) !@This() {
            var bl = try @This().fromBitLen(allocator, bools.len);
            for (bools, 0..) |bit, i| {
                try bl.set(allocator, i, bit);
            }
            return bl;
        }

        pub fn toBoolSlice(self: *const @This(), out: *[]bool) !void {
            if (out.len != self.bit_len) {
                return error.InvalidSize;
            }
            for (0..self.bit_len) |i| {
                out.*[i] = self.get(i) catch unreachable;
            }
        }

        pub fn getTrueBitIndexes(self: *const @This(), out: []usize) !usize {
            if (out.len < self.bit_len) {
                return error.InvalidSize;
            }

            const full_byte_len = self.bit_len / 8;
            const remainder_bits = self.bit_len % 8;
            var true_bit_count: usize = 0;

            for (0..full_byte_len) |i_byte| {
                var b = self.data.items[i_byte];
                while (b != 0) {
                    const lsb: u8 = @ctz(b);
                    const bit_index = i_byte * 8 + lsb;
                    out[true_bit_count] = bit_index;
                    true_bit_count += 1;
                    b &= b - 1;
                }
            }
            if (remainder_bits <= 0) return true_bit_count;
            const tail_mask: u8 = (@as(u8, 1) << @intCast(remainder_bits)) - 1;
            var b = self.data.items[full_byte_len] & tail_mask;

            while (b != 0) {
                const lsb: u8 = @ctz(b);
                const bit_index = full_byte_len * 8 + lsb;
                out[true_bit_count] = bit_index;
                true_bit_count += 1;
                b &= b - 1;
            }

            return true_bit_count;
        }

        pub fn getSingleTrueBit(self: *const @This()) ?usize {
            var found_index: ?usize = null;

            for (self.data.items, 0..) |byte, i_byte| {
                var b = byte;
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

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            self.data.deinit(allocator);
        }

        pub fn get(self: *const @This(), bit_index: usize) !bool {
            if (bit_index >= self.bit_len) {
                return error.OutOfRange;
            }

            const byte_idx = bit_index / 8;
            const offset_in_byte: u3 = @intCast(bit_index % 8);
            const mask = @as(u8, 1) << offset_in_byte;
            return (self.data.items[byte_idx] & mask) == mask;
        }

        pub fn set(self: *@This(), allocator: std.mem.Allocator, bit_index: usize, bit: bool) !void {
            if (bit_index + 1 > self.bit_len) {
                try self.resize(allocator, bit_index + 1);
            }
            try self.setAssumeCapacity(bit_index, bit);
        }

        pub fn resize(self: *@This(), allocator: std.mem.Allocator, bit_len: usize) !void {
            if (bit_len > limit) {
                return error.tooLarge;
            }

            const old_byte_len = std.math.divCeil(usize, self.bit_len, 8) catch unreachable;
            const byte_len = std.math.divCeil(usize, bit_len, 8) catch unreachable;
            try self.data.resize(allocator, byte_len);
            // zero out additionally allocated bytes
            if (old_byte_len < byte_len) {
                @memset(self.data.items[old_byte_len..], 0);
            } else {
                // In the case of old_byte_len >= byte_len, we need to manually zero out the
                // trailing bits after the last bit
                const remainder_bits = bit_len % 8;
                if (remainder_bits != 0) {
                    const mask: u8 = (@as(u8, 1) << @intCast(remainder_bits)) - 1;
                    self.data.items[byte_len - 1] &= mask;
                }
            }
            self.bit_len = bit_len;
        }

        /// Set bit value at index `bit_index`
        pub fn setAssumeCapacity(self: *@This(), bit_index: usize, bit: bool) !void {
            if (bit_index >= self.bit_len) {
                return error.OutOfRange;
            }

            const byte_index = bit_index / 8;
            const offset_in_byte: u3 = @intCast(bit_index % 8);
            const mask = @as(u8, 1) << offset_in_byte;
            var byte = self.data.items[byte_index];
            if (bit) {
                // For bit in byte, 1,0 OR 1 = 1
                // byte 100110
                // mask 010000
                // res  110110
                byte |= mask;
                self.data.items[byte_index] = byte;
            } else {
                // For bit in byte, 1,0 OR 1 = 0
                if ((byte & mask) == mask) {
                    // byte 110110
                    // mask 010000
                    // res  100110
                    byte ^= mask;
                    self.data.items[byte_index] = byte;
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
            values: []const T,
        ) !std.ArrayList(T) {
            if (values.len != self.bit_len) return error.InvalidSize;

            var indices = try std.ArrayList(T).initCapacity(allocator, self.bit_len);
            const full_byte_len = self.bit_len / 8;
            const remainder_bits = self.bit_len % 8;
            for (0..full_byte_len) |i_byte| {
                var b = self.data.items[i_byte];
                // Kernighan's algorithm to count the set bits instead of going through 0..8 for every byte
                while (b != 0) {
                    const lsb: u8 = @ctz(b); // Get the index of least significant bit
                    const bit_index = i_byte * 8 + lsb;
                    indices.appendAssumeCapacity(values[bit_index]);
                    // The `b - 1` flips the bits starting from `lsb` index
                    // And `&` will reset the last bit at `lsb` index
                    b &= b - 1;
                }
            }
            if (remainder_bits <= 0) return indices;
            const tail_mask: u8 = (@as(u8, 1) << @intCast(remainder_bits)) - 1;
            var b = self.data.items[full_byte_len] & tail_mask;
            // Kernighan's algorithm to count the set bits instead of going through 0..8 for every byte
            while (b != 0) {
                const lsb: u8 = @ctz(b); // Get the index of least significant bit
                const bit_index = full_byte_len * 8 + lsb;
                indices.appendAssumeCapacity(values[bit_index]);
                // The `b - 1` flips the bits starting from `lab` index
                // And `&` will reset the last bit at `lsb` index
                b &= b - 1;
            }

            return indices;
        }
    };
}

pub fn isBitListType(ST: type) bool {
    return ST.kind == .list and ST.Element.kind == .bool and ST.Type == BitList(ST.limit);
}

pub fn BitListType(comptime _limit: comptime_int) type {
    comptime {
        if (_limit <= 0) {
            @compileError("limit must be greater than 0");
        }
    }
    return struct {
        pub const kind = TypeKind.list;
        pub const Element: type = BoolType();
        pub const limit: usize = _limit;
        pub const Type: type = BitList(limit);
        pub const min_size: usize = 1;
        pub const max_size: usize = std.math.divCeil(usize, limit + 1, 8) catch unreachable;
        pub const max_chunk_count: usize = std.math.divCeil(usize, limit, 256) catch unreachable;
        pub const chunk_depth: u8 = maxChunksToDepth(max_chunk_count);

        pub const default_value: Type = Type.empty;

        pub fn equals(a: *const Type, b: *const Type) bool {
            return a.equals(b);
        }

        pub fn deinit(allocator: std.mem.Allocator, value: *Type) void {
            value.data.deinit(allocator);
        }

        pub fn chunkCount(value: *const Type) usize {
            return (value.bit_len + 255) / 256;
        }

        pub fn hashTreeRoot(allocator: std.mem.Allocator, value: *const Type, out: *[32]u8) !void {
            const chunks = try allocator.alloc([32]u8, (chunkCount(value) + 1) / 2 * 2);
            defer allocator.free(chunks);

            @memset(chunks, [_]u8{0} ** 32);
            @memcpy(@as([]u8, @ptrCast(chunks))[0..value.data.items.len], value.data.items);

            try merkleize(@ptrCast(chunks), chunk_depth, out);
            mixInLength(value.bit_len, out);
        }

        /// Clones the underlying `ArrayList` in `data`.
        ///
        /// Caller owns the memory.
        pub fn clone(allocator: std.mem.Allocator, value: *const Type, out: *Type) !void {
            out.data = try value.data.clone(allocator);
            out.bit_len = value.bit_len;
        }

        pub fn serializedSize(value: *const Type) usize {
            return std.math.divCeil(usize, value.bit_len + 1, 8) catch unreachable;
        }

        pub fn serializeIntoBytes(value: *const Type, out: []u8) usize {
            const bit_len = value.bit_len + 1; // + 1 for padding bit
            const byte_len = std.math.divCeil(usize, bit_len, 8) catch unreachable;
            if (value.bit_len % 8 == 0) {
                @memcpy(out[0 .. byte_len - 1], value.data.items);
                // setting the byte in its entirety here
                // ensures that a possibly uninitialized byte gets overridden entirely
                out[byte_len - 1] = 1;
            } else {
                @memcpy(out[0..byte_len], value.data.items);
                out[byte_len - 1] |= @as(u8, 1) << @intCast((bit_len - 1) % 8);
            }
            return byte_len;
        }

        pub fn deserializeFromBytes(allocator: std.mem.Allocator, data: []const u8, out: *Type) !void {
            if (data.len == 0) {
                return error.InvalidSize;
            }

            // ensure padding bit and trailing zeros in last byte
            const last_byte = data[data.len - 1];

            const last_byte_clz = @clz(last_byte);
            if (last_byte_clz == 8) {
                return error.noPaddingBit;
            }
            const last_1_index: u3 = @intCast(7 - last_byte_clz);
            const bit_len = (data.len - 1) * 8 + last_1_index;
            if (bit_len > limit) {
                return error.tooLarge;
            }

            try out.resize(allocator, bit_len);
            if (bit_len == 0) {
                return;
            }

            // if the bit_len is a multiple of 8, we just copy one byte less
            // and avoid removing the padding bit after
            if (bit_len % 8 == 0) {
                @memcpy(out.data.items, data[0 .. data.len - 1]);
            } else {
                @memcpy(out.data.items, data);

                // remove padding bit
                out.data.items[out.data.items.len - 1] ^= @as(u8, 1) << last_1_index;
            }
        }

        pub const serialized = struct {
            pub fn validate(data: []const u8) !void {
                if (data.len == 0) {
                    return error.InvalidSize;
                }

                // ensure 1 bit and trailing zeros in last byte
                const last_byte = data[data.len - 1];

                const last_byte_clz = @clz(last_byte);
                if (last_byte_clz == 8) {
                    return error.noPaddingBit;
                }
                const last_1_index: u3 = @intCast(7 - last_byte_clz);
                const bit_len = (data.len - 1) * 8 + last_1_index;
                if (bit_len > limit) {
                    return error.tooLarge;
                }
            }

            pub fn length(data: []const u8) !usize {
                if (data.len == 0) {
                    return error.InvalidSize;
                }

                // ensure padding bit and trailing zeros in last byte
                const last_byte = data[data.len - 1];

                const last_byte_clz = @clz(last_byte);
                if (last_byte_clz == 8) {
                    return error.noPaddingBit;
                }
                const last_1_index: u3 = @intCast(7 - last_byte_clz);
                const bit_len = (data.len - 1) * 8 + last_1_index;
                if (bit_len > limit) {
                    return error.tooLarge;
                }
                return bit_len;
            }

            pub fn hashTreeRoot(allocator: std.mem.Allocator, data: []const u8, out: *[32]u8) !void {
                if (data.len == 0) {
                    return error.InvalidSize;
                }

                // ensure padding bit and trailing zeros in last byte
                const last_byte = data[data.len - 1];

                const last_byte_clz = @clz(last_byte);
                if (last_byte_clz == 8) {
                    return error.noPaddingBit;
                }
                const last_1_index: u3 = @intCast(7 - last_byte_clz);
                const bit_len = (data.len - 1) * 8 + last_1_index;
                const chunk_count = (bit_len + 255) / 256;
                const chunks = try allocator.alloc([32]u8, (chunk_count + 1) / 2 * 2);
                defer allocator.free(chunks);

                @memset(chunks, [_]u8{0} ** 32);
                if (bit_len % 8 == 0) {
                    @memcpy(@as([]u8, @ptrCast(chunks))[0 .. data.len - 1], data[0 .. data.len - 1]);
                } else {
                    @memcpy(@as([]u8, @ptrCast(chunks))[0..data.len], data);
                    // remove padding bit
                    @as([]u8, @ptrCast(chunks))[data.len - 1] ^= @as(u8, 1) << last_1_index;
                }

                try merkleize(@ptrCast(chunks), chunk_depth, out);
                mixInLength(bit_len, out);
            }
        };

        pub const tree = struct {
            pub fn length(node: Node.Id, pool: *Node.Pool) !usize {
                const right = try node.getRight(pool);
                const hash = right.getRoot(pool);
                return std.mem.readInt(usize, hash[0..8], .little);
            }

            pub fn toValue(allocator: std.mem.Allocator, node: Node.Id, pool: *Node.Pool, out: *Type) !void {
                const bit_len = try length(node, pool);
                const chunk_count = (bit_len + 255) / 256;
                if (chunk_count == 0) {
                    try out.resize(allocator, 0);
                    return;
                }

                const byte_length = (bit_len + 7) / 8;

                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);

                try node.getNodesAtDepth(pool, chunk_depth + 1, 0, nodes);

                try out.resize(allocator, bit_len);
                for (0..chunk_count) |i| {
                    const start_idx = i * 32;
                    const remaining_bytes = byte_length - start_idx;

                    // Determine how many bytes to copy for this chunk
                    const bytes_to_copy = @min(remaining_bytes, 32);

                    // Copy data if there are bytes to copy
                    if (bytes_to_copy > 0) {
                        @memcpy(out.data.items[start_idx..][0..bytes_to_copy], nodes[i].getRoot(pool)[0..bytes_to_copy]);
                    }
                }
            }

            pub fn fromValue(allocator: std.mem.Allocator, pool: *Node.Pool, value: *const Type) !Node.Id {
                const chunk_count = chunkCount(value);
                if (chunk_count == 0) {
                    return try pool.createBranch(
                        @enumFromInt(chunk_depth),
                        @enumFromInt(0),
                        false,
                    );
                }
                const byte_length = (value.bit_len + 7) / 8;

                const nodes = try allocator.alloc(Node.Id, chunk_count);
                defer allocator.free(nodes);
                for (0..chunk_count) |i| {
                    var leaf_buf = [_]u8{0} ** 32;
                    const start_idx = i * 32;
                    const remaining_bytes = byte_length - start_idx;

                    // Determine how many bytes to copy for this chunk
                    const bytes_to_copy = @min(remaining_bytes, 32);

                    // Copy data if there are bytes to copy
                    if (bytes_to_copy > 0) {
                        @memcpy(leaf_buf[0..bytes_to_copy], value.data.items[start_idx..][0..bytes_to_copy]);
                    }

                    nodes[i] = try pool.createLeaf(&leaf_buf, false);
                }
                return try pool.createBranch(
                    try Node.fillWithContents(pool, nodes, chunk_depth, false),
                    try pool.createLeafFromUint(value.bit_len, false),
                    false,
                );
            }
        };

        pub fn serializeIntoJson(allocator: std.mem.Allocator, writer: anytype, in: *const Type) !void {
            const bytes = try allocator.alloc(u8, serializedSize(in));
            defer allocator.free(bytes);
            _ = serializeIntoBytes(in, bytes);

            const byte_str = try allocator.alloc(u8, hexLenFromBytes(bytes));
            defer allocator.free(byte_str);

            _ = try bytesToHex(byte_str, bytes);
            try writer.print("\"{s}\"", .{byte_str});
        }

        pub fn deserializeFromJson(allocator: std.mem.Allocator, source: *std.json.Scanner, out: *Type) !void {
            const hex_bytes = switch (try source.next()) {
                .string => |v| v,
                else => return error.InvalidJson,
            };
            const bytes = try allocator.alloc(u8, hexByteLen(hex_bytes));
            errdefer allocator.free(bytes);
            defer allocator.free(bytes);
            const written = try hexToBytes(bytes, hex_bytes);
            if (written.len > max_size) {
                return error.invalidLength;
            }
            try deserializeFromBytes(allocator, bytes, out);
        }
    };
}

test "BitListType - sanity" {
    const allocator = std.testing.allocator;
    const Bits = BitListType(40);
    var b: Bits.Type = try Bits.Type.fromBitLen(allocator, 30);
    defer b.deinit(allocator);

    try b.setAssumeCapacity(2, true);

    const b_buf = try allocator.alloc(u8, Bits.serializedSize(&b));
    defer allocator.free(b_buf);

    _ = Bits.serializeIntoBytes(&b, b_buf);
    try Bits.deserializeFromBytes(allocator, b_buf, &b);

    try std.testing.expect(try b.get(0) == false);
}

test "BitListType - sanity with bools" {
    const allocator = std.testing.allocator;
    const Bits = BitListType(16);
    const expected_bools = [_]bool{ true, false, true, true, false, true, false, true, true, false, true, true };
    const expected_true_bit_indexes = [_]usize{ 0, 2, 3, 5, 7, 8, 10, 11 };
    var b: Bits.Type = try Bits.Type.fromBoolSlice(allocator, &expected_bools);
    defer b.deinit(allocator);

    var actual_bools = try allocator.alloc(bool, expected_bools.len);
    defer allocator.free(actual_bools);
    try b.toBoolSlice(&actual_bools);

    try std.testing.expectEqualSlices(bool, &expected_bools, actual_bools);
    try std.testing.expect(try b.get(0) == true);

    var true_bit_indexes: [Bits.limit]usize = undefined;
    const true_bit_count = try b.getTrueBitIndexes(true_bit_indexes[0..]);

    try std.testing.expectEqualSlices(usize, &expected_true_bit_indexes, true_bit_indexes[0..true_bit_count]);

    const expected_single_bool = [_]bool{ false, false, false, false, false, true, false, false, false, false, false, false };
    var b_single_bool: Bits.Type = try Bits.Type.fromBoolSlice(allocator, &expected_single_bool);
    defer b_single_bool.deinit(allocator);

    try std.testing.expectEqual(b_single_bool.getSingleTrueBit(), 5);
}

test "BitListType - intersectValues" {
    const TestCase = struct { expected: []const u8, bit_len: usize };
    const test_cases = [_]TestCase{
        .{ .expected = &[_]u8{}, .bit_len = 16 },
        .{ .expected = &[_]u8{3}, .bit_len = 16 },
        .{ .expected = &[_]u8{ 0, 5, 6, 10, 14 }, .bit_len = 16 },
        .{ .expected = &[_]u8{ 0, 5, 6, 10, 14 }, .bit_len = 15 },
    };

    const allocator = std.testing.allocator;
    const Bits = BitListType(16);

    for (test_cases) |tc| {
        var b: Bits.Type = try Bits.Type.fromBitLen(allocator, tc.bit_len);
        defer b.deinit(allocator);

        for (tc.expected) |i| try b.setAssumeCapacity(i, true);

        var values = try std.ArrayList(u8).initCapacity(allocator, tc.bit_len);
        defer values.deinit();
        for (0..tc.bit_len) |i| values.appendAssumeCapacity(@intCast(i));

        var actual = try b.intersectValues(u8, allocator, values.items);
        defer actual.deinit();
        try std.testing.expectEqualSlices(u8, tc.expected, actual.items);
    }
}

test "clone" {
    const allocator = std.testing.allocator;

    const Bits = BitListType(40);
    var b: Bits.Type = try Bits.Type.fromBitLen(allocator, 30);
    defer b.deinit(allocator);

    var cloned: Bits.Type = undefined;
    try Bits.clone(allocator, &b, &cloned);
    defer cloned.deinit(allocator);

    try std.testing.expect(&b != &cloned);
    try std.testing.expect(b.bit_len == cloned.bit_len);
    try std.testing.expect(std.mem.eql(u8, b.data.items, cloned.data.items));
    try expectEqualRootsAlloc(Bits, allocator, b, cloned);
    try expectEqualSerializedAlloc(Bits, allocator, b, cloned);
}

test "resize" {
    const allocator = std.testing.allocator;

    const Bits = BitListType(16);
    // First byte: 1, 0, 1, 1, 0, 1, 0, 1 = 173
    // Second byte: 1, 0, 1, 1, 1, 0, 1, 1 = 221
    const bools = [_]bool{ true, false, true, true, false, true, false, true, true, false, true, true, true, false, true, true };
    var b: Bits.Type = try Bits.Type.fromBoolSlice(allocator, &bools);
    defer b.deinit(allocator);

    try std.testing.expect(b.data.items.len == 2);
    try std.testing.expect(b.data.items[0] == 173);
    try std.testing.expect(b.data.items[1] == 221);

    // Resize to 5 bits. Now it should only have one byte,
    // with the last 3 bits in the byte being wiped out.
    // First byte: 1, 0, 1, 1, 0, 0, 0, 0 = 13
    try b.resize(allocator, 5);

    try std.testing.expect(b.data.items.len == 1);
    try std.testing.expect(b.data.items[0] == 13);
}
