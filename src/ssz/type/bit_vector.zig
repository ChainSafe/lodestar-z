const std = @import("std");
const merkleize = @import("hashing").merkleize;
const TypeKind = @import("type_kind.zig").TypeKind;
const BoolType = @import("bool.zig").BoolType;
const hexToBytes = @import("hex").hexToBytes;
const bytesToHex = @import("hex").bytesToHex;
const maxChunksToDepth = @import("hashing").maxChunksToDepth;
const getZeroHash = @import("hashing").getZeroHash;
const Node = @import("persistent_merkle_tree").Node;
const BitVectorTreeView = @import("../tree_view/root.zig").BitVectorTreeView;

pub fn BitVector(comptime _length: comptime_int) type {
    const byte_len = std.math.divCeil(usize, _length, 8) catch unreachable;
    return struct {
        data: [byte_len]u8,

        pub const length = _length;

        pub const empty: @This() = .{
            .data = [_]u8{0} ** byte_len,
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

            for (0..byte_len) |i_byte| {
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

            for (0..byte_len) |i_byte| {
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
            var indices = try std.ArrayList(T).initCapacity(allocator, byte_len * 8);

            for (0..byte_len) |i_byte| {
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
    };
}

pub fn isBitVectorType(ST: type) bool {
    return ST.kind == .vector and ST.Element.kind == .bool and ST.Type == BitVector(ST.length);
}

pub fn BitVectorType(comptime _length: comptime_int) type {
    comptime {
        if (_length <= 0) {
            @compileError("length must be greater than 0");
        }
    }
    return struct {
        pub const kind = TypeKind.vector;
        pub const Element: type = BoolType();
        pub const length: usize = _length;
        pub const byte_length = std.math.divCeil(usize, length, 8) catch unreachable;
        pub const Type: type = BitVector(length);
        pub const TreeView: type = BitVectorTreeView(@This());
        pub const fixed_size: usize = byte_length;
        pub const chunk_count: usize = std.math.divCeil(usize, fixed_size, 32) catch unreachable;
        pub const chunk_depth: u8 = maxChunksToDepth(chunk_count);

        pub const default_value: Type = Type.empty;

        pub const default_root: [32]u8 = getZeroHash(chunk_depth).*;

        pub fn equals(a: *const Type, b: *const Type) bool {
            return a.equals(b);
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

                var nodes: [chunk_count]Node.Id = @splat(@as(Node.Id, @enumFromInt(0)));
                errdefer pool.free(&nodes);

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
                var nodes: [chunk_count]Node.Id = @splat(@as(Node.Id, @enumFromInt(0)));
                errdefer pool.free(&nodes);

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

test {
    _ = @import("bit_vector_test.zig");
}
