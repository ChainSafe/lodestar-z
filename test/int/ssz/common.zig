const std = @import("std");
const hexToBytes = @import("hex").hexToBytes;
const bytesToHex = @import("hex").bytesToHex;
const isFixedType = @import("ssz").isFixedType;
const UintType = @import("ssz").UintType;
const BoolType = @import("ssz").BoolType;
const ByteVectorType = @import("ssz").ByteVectorType;
const ByteListType = @import("ssz").ByteListType;

pub const TypeTestCase = struct {
    id: []const u8,
    serializedHex: []const u8,
    json: []const u8,
    rootHex: []const u8,
};

const TypeTestError = error{
    InvalidRootHex,
};

/// ST: ssz type
pub fn typeTest(comptime ST: type) type {
    const TypeTest = struct {
        pub fn run(allocator: std.mem.Allocator, tc: *const TypeTestCase) !void {
            var serializedMax = [_]u8{0} ** 1024;
            const serialized = serializedMax[0..((tc.serializedHex.len - 2) / 2)];
            _ = try hexToBytes(serialized, tc.serializedHex);

            if (comptime isFixedType(ST)) {
                // deserialize
                var value: ST.Type = undefined;
                try ST.deserializeFromBytes(serialized, &value);

                // serialize
                var out = [_]u8{0} ** ST.fixed_size;
                _ = ST.serializeIntoBytes(&value, &out);
                try std.testing.expectEqualSlices(u8, serialized, &out);

                // hash tree root
                var root = [_]u8{0} ** 32;
                try ST.hashTreeRoot(&value, root[0..]);
                var root_hex = [_]u8{0} ** 66;
                _ = try bytesToHex(&root_hex, &root);
                try std.testing.expectEqualSlices(u8, tc.rootHex, &root_hex);

                // deserialize from json
                var json_value: ST.Type = undefined;
                var scanner = std.json.Scanner.initCompleteInput(allocator, tc.json);
                defer scanner.deinit();

                try ST.deserializeFromJson(&scanner, &json_value);

                // serialize to json
                var output_json = std.ArrayList(u8).init(allocator);
                defer output_json.deinit();
                var write_stream = std.json.writeStream(output_json.writer(), .{});
                defer write_stream.deinit();

                try ST.serializeIntoJson(&write_stream, &json_value);
                try std.testing.expectEqualSlices(u8, tc.json, output_json.items);
            } else {
                // deserialize
                var value = ST.default_value;
                defer ST.deinit(allocator, &value);

                try ST.deserializeFromBytes(allocator, serialized, &value);

                // serialize
                const out = try allocator.alloc(u8, ST.serializedSize(&value));
                defer allocator.free(out);

                _ = ST.serializeIntoBytes(&value, out);
                try std.testing.expectEqualSlices(u8, serialized, out);

                // hash tree root
                var root = [_]u8{0} ** 32;
                try ST.hashTreeRoot(allocator, &value, root[0..]);
                var root_hex = [_]u8{0} ** 66;
                _ = try bytesToHex(&root_hex, &root);
                try std.testing.expectEqualSlices(u8, tc.rootHex, &root_hex);

                // deserialize from json
                var json_value = ST.default_value;
                defer ST.deinit(allocator, &json_value);

                var scanner = std.json.Scanner.initCompleteInput(allocator, tc.json);
                defer scanner.deinit();

                try ST.deserializeFromJson(allocator, &scanner, &json_value);

                // serialize to json
                var output_json = std.ArrayList(u8).init(allocator);
                defer output_json.deinit();
                var write_stream = std.json.writeStream(output_json.writer(), .{});
                defer write_stream.deinit();

                try ST.serializeIntoJson(allocator, &write_stream, &json_value);
                // sanity check first
                try std.testing.expectEqual(tc.json.len, output_json.items.len);
                try std.testing.expectEqualSlices(u8, tc.json, output_json.items);
            }
        }
    };
    return TypeTest;
}

test "UintType equals" {
    const U64 = UintType(64);

    var a: U64.Type = 42;
    var b: U64.Type = 42;
    var c: U64.Type = 43;

    try std.testing.expect(U64.equals(&a, &b));
    try std.testing.expect(!U64.equals(&a, &c));
}

test "BoolType equals" {
    const Bool = BoolType();

    var a: Bool.Type = true;
    var b: Bool.Type = true;
    var c: Bool.Type = false;

    try std.testing.expect(Bool.equals(&a, &b));
    try std.testing.expect(!Bool.equals(&a, &c));
}

test "ByteVectorType equals" {
    const Bytes32 = ByteVectorType(32);

    var a: Bytes32.Type = [_]u8{1} ** 32;
    var b: Bytes32.Type = [_]u8{1} ** 32;
    var c: Bytes32.Type = [_]u8{2} ** 32;

    try std.testing.expect(Bytes32.equals(&a, &b));
    try std.testing.expect(!Bytes32.equals(&a, &c));
}

test "ByteListType equals" {
    const allocator = std.testing.allocator;
    const ByteList = ByteListType(32);

    var a: ByteList.Type = ByteList.Type.empty;
    var b: ByteList.Type = ByteList.Type.empty;
    var c: ByteList.Type = ByteList.Type.empty;

    defer a.deinit(allocator);
    defer b.deinit(allocator);
    defer c.deinit(allocator);

    try a.appendSlice(allocator, &[_]u8{ 1, 2, 3 });
    try b.appendSlice(allocator, &[_]u8{ 1, 2, 3 });
    try c.appendSlice(allocator, &[_]u8{ 1, 2, 4 }); // Different value

    try std.testing.expect(ByteList.equals(&a, &b));
    try std.testing.expect(!ByteList.equals(&a, &c));
}
