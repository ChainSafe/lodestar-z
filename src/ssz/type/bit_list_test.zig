//! Tests for `bit_list.zig`.

const std = @import("std");
const expectEqualRootsAlloc = @import("test_utils.zig").expectEqualRootsAlloc;
const expectEqualSerializedAlloc = @import("test_utils.zig").expectEqualSerializedAlloc;
const TypeTestCase = @import("test_utils.zig").TypeTestCase;
const Node = @import("persistent_merkle_tree").Node;
const BitListType = @import("bit_list.zig").BitListType;

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
        defer values.deinit(allocator);
        for (0..tc.bit_len) |i| values.appendAssumeCapacity(@intCast(i));

        var actual = try b.intersectValues(u8, allocator, values.items);
        defer actual.deinit(allocator);
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

test "BitList resize and set should enforce length bounds" {
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

    try std.testing.expectError(
        error.tooLarge,
        b.set(allocator, std.math.maxInt(usize), true),
    );
}

// Refer to https://github.com/ChainSafe/ssz/blob/f5ed0b457333749b5c3f49fa5eafa096a725f033/packages/ssz/test/unit/byType/bitList/valid.test.ts#L44-L69
test "BitListType serialized forms should enforce padding and limit" {
    const allocator = std.testing.allocator;

    const TestCase = struct {
        bools: []const bool,
        expected_hex: []const u8,
    };

    const test_cases = [_]TestCase{
        .{ .bools = &[_]bool{}, .expected_hex = &[_]u8{0b1} },
        .{ .bools = &[_]bool{true}, .expected_hex = &[_]u8{0b11} },
        .{ .bools = &[_]bool{false}, .expected_hex = &[_]u8{0b10} },
        .{ .bools = &[_]bool{ true, true, true }, .expected_hex = &[_]u8{0b1111} },
        .{ .bools = &[_]bool{ false, false, false }, .expected_hex = &[_]u8{0b1000} },
        .{ .bools = &[_]bool{ true, true, true, true, true, true, true, true }, .expected_hex = &[_]u8{ 0b11111111, 0b00000001 } },
        .{ .bools = &[_]bool{ false, false, false, false, false, false, false, false }, .expected_hex = &[_]u8{ 0b00000000, 0b00000001 } },
    };

    const Bits = BitListType(8);

    for (test_cases) |tc| {
        var b: Bits.Type = try Bits.Type.fromBoolSlice(allocator, tc.bools);
        defer b.deinit(allocator);

        const serialized = try allocator.alloc(u8, Bits.serializedSize(&b));
        defer allocator.free(serialized);
        _ = Bits.serializeIntoBytes(&b, serialized);
        try std.testing.expectEqualSlices(u8, tc.expected_hex, serialized);

        var deserialized: Bits.Type = Bits.default_value;
        try Bits.deserializeFromBytes(allocator, serialized, &deserialized);
        defer deserialized.deinit(allocator);

        var deserialized_bools = try allocator.alloc(bool, deserialized.bit_len);
        defer allocator.free(deserialized_bools);
        try deserialized.toBoolSlice(&deserialized_bools);
        try std.testing.expectEqualSlices(bool, tc.bools, deserialized_bools);
    }

    const over_limit = [_]u8{ 0x00, 0x02 };
    try std.testing.expectError(error.tooLarge, Bits.serialized.validate(&over_limit));
    try std.testing.expectError(error.tooLarge, Bits.serialized.length(&over_limit));

    var root: [32]u8 = undefined;
    try std.testing.expectError(
        error.tooLarge,
        Bits.serialized.hashTreeRoot(allocator, &over_limit, &root),
    );
}

// Refer to https://github.com/ChainSafe/ssz/blob/f5ed0b457333749b5c3f49fa5eafa096a725f033/packages/ssz/test/unit/byType/bitList/valid.test.ts#L5-L41
test "BitListType - tree roundtrip" {
    const allocator = std.testing.allocator;

    const Bits = BitListType(2048);

    const TestCase = struct {
        id: []const u8,
        serialized: []const u8,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty",
            .serialized = &[_]u8{0x01},
            .expected_root = [_]u8{ 0xe8, 0xe5, 0x27, 0xe8, 0x4f, 0x66, 0x61, 0x63, 0xa9, 0x0e, 0xf9, 0x00, 0xe0, 0x13, 0xf5, 0x6b, 0x0a, 0x4d, 0x02, 0x01, 0x48, 0xb2, 0x22, 0x40, 0x57, 0xb7, 0x19, 0xf3, 0x51, 0xb0, 0x03, 0xa6 },
        },
        .{
            .id = "zero'ed 1 byte",
            .serialized = &[_]u8{ 0x00, 0x10 },
            .expected_root = [_]u8{ 0x07, 0xeb, 0x64, 0x02, 0x82, 0xe1, 0x6e, 0xea, 0x87, 0x30, 0x0c, 0x37, 0x4c, 0x48, 0x94, 0xad, 0x69, 0xb9, 0x48, 0xde, 0x92, 0x4a, 0x15, 0x8d, 0x2d, 0x18, 0x43, 0xb3, 0xcf, 0x01, 0x89, 0x8a },
        },
        .{
            .id = "zero'ed 8 bytes",
            .serialized = &[_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 },
            .expected_root = [_]u8{ 0x5c, 0x59, 0x7e, 0x77, 0xf8, 0x79, 0xe2, 0x49, 0xaf, 0x95, 0xfe, 0x54, 0x3c, 0xf5, 0xf4, 0xdd, 0x16, 0xb6, 0x86, 0x94, 0x8d, 0xc7, 0x19, 0x70, 0x74, 0x45, 0xa3, 0x2a, 0x77, 0xff, 0x62, 0x66 },
        },
    };

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    for (test_cases) |tc| {
        var value: Bits.Type = Bits.default_value;
        try Bits.deserializeFromBytes(allocator, tc.serialized, &value);
        defer value.deinit(allocator);

        const tree_node = try Bits.tree.fromValue(&pool, &value);

        var value_from_tree: Bits.Type = Bits.default_value;
        try Bits.tree.toValue(allocator, tree_node, &pool, &value_from_tree);
        defer value_from_tree.deinit(allocator);

        try std.testing.expect(Bits.equals(&value, &value_from_tree));

        const tree_size = try Bits.tree.serializedSize(tree_node, &pool);
        try std.testing.expectEqual(tc.serialized.len, tree_size);

        const tree_serialized = try allocator.alloc(u8, tree_size);
        defer allocator.free(tree_serialized);
        _ = try Bits.tree.serializeIntoBytes(tree_node, &pool, tree_serialized);
        try std.testing.expectEqualSlices(u8, tc.serialized, tree_serialized);

        var hash_root: [32]u8 = undefined;
        try Bits.hashTreeRoot(allocator, &value, &hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "BitListType - tree.deserializeFromBytes" {
    const allocator = std.testing.allocator;

    const Bits = BitListType(2048);

    const TestCase = struct {
        id: []const u8,
        serialized: []const u8,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty",
            .serialized = &[_]u8{0x01},
            .expected_root = [_]u8{ 0xe8, 0xe5, 0x27, 0xe8, 0x4f, 0x66, 0x61, 0x63, 0xa9, 0x0e, 0xf9, 0x00, 0xe0, 0x13, 0xf5, 0x6b, 0x0a, 0x4d, 0x02, 0x01, 0x48, 0xb2, 0x22, 0x40, 0x57, 0xb7, 0x19, 0xf3, 0x51, 0xb0, 0x03, 0xa6 },
        },
        .{
            .id = "zero'ed 1 byte",
            .serialized = &[_]u8{ 0x00, 0x10 },
            .expected_root = [_]u8{ 0x07, 0xeb, 0x64, 0x02, 0x82, 0xe1, 0x6e, 0xea, 0x87, 0x30, 0x0c, 0x37, 0x4c, 0x48, 0x94, 0xad, 0x69, 0xb9, 0x48, 0xde, 0x92, 0x4a, 0x15, 0x8d, 0x2d, 0x18, 0x43, 0xb3, 0xcf, 0x01, 0x89, 0x8a },
        },
        .{
            .id = "zero'ed 8 bytes",
            .serialized = &[_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 },
            .expected_root = [_]u8{ 0x5c, 0x59, 0x7e, 0x77, 0xf8, 0x79, 0xe2, 0x49, 0xaf, 0x95, 0xfe, 0x54, 0x3c, 0xf5, 0xf4, 0xdd, 0x16, 0xb6, 0x86, 0x94, 0x8d, 0xc7, 0x19, 0x70, 0x74, 0x45, 0xa3, 0x2a, 0x77, 0xff, 0x62, 0x66 },
        },
    };

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    for (test_cases) |tc| {
        const tree_node = try Bits.tree.deserializeFromBytes(&pool, tc.serialized);

        const node_root = tree_node.getRoot(&pool);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, node_root);

        var value_from_tree: Bits.Type = Bits.default_value;
        defer value_from_tree.deinit(allocator);
        try Bits.tree.toValue(allocator, tree_node, &pool, &value_from_tree);

        const tree_size = try Bits.tree.serializedSize(tree_node, &pool);
        try std.testing.expectEqual(tc.serialized.len, tree_size);
        const tree_serialized = try allocator.alloc(u8, tree_size);
        defer allocator.free(tree_serialized);
        _ = try Bits.tree.serializeIntoBytes(tree_node, &pool, tree_serialized);
        try std.testing.expectEqualSlices(u8, tc.serialized, tree_serialized);

        var hash_root: [32]u8 = undefined;
        try Bits.hashTreeRoot(allocator, &value_from_tree, &hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "BitListType" {
    const test_cases = [_]TypeTestCase{
        .{
            .id = "empty",
            .serializedHex = "0x01",
            .json =
            \\"0x01"
            ,
            .rootHex = "0xe8e527e84f666163a90ef900e013f56b0a4d020148b2224057b719f351b003a6",
        },
        .{
            .id = "zero'ed 1 bytes",
            .serializedHex = "0x0010",
            .json =
            \\"0x10"
            ,
            .rootHex = "0x07eb640282e16eea87300c374c4894ad69b948de924a158d2d1843b3cf01898a",
        },
        .{
            .id = "zero'ed 8 bytes",
            .serializedHex = "0x000000000000000010",
            .json =
            \\"0x000000000000000010"
            ,
            .rootHex = "0x5c597e77f879e249af95fe543cf5f4dd16b686948dc719707445a32a77ff6266",
        },
        .{
            .id = "short value",
            .serializedHex = "0xb55b8592bcac475906631481bbc746bc",
            .json =
            \\"0xb55b8592bcac475906631481bbc746bc"
            ,
            .rootHex = "0x9ab378cfbd6ec502da1f9640fd956bbef1f9fcbc10725397805c948865384e77",
        },
        .{
            .id = "long value",
            .serializedHex = "0xb55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1b55b8592bc",
            .json =
            \\"0xb55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1b55b8592bc"
            ,
            .rootHex = "0x4b71a7de822d00a5ff8e7e18e13712a50424cbc0e18108ab1796e591136396a0",
        },
    };

    const allocator = std.testing.allocator;
    const List = BitListType(2048);

    const TypeTest = @import("test_utils.zig").typeTest(List);

    for (test_cases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}

test "BitListType equals" {
    const allocator = std.testing.allocator;
    const BL = BitListType(32);

    var a = try BL.Type.fromBitLen(allocator, 8);
    var b = try BL.Type.fromBitLen(allocator, 8);
    var c = try BL.Type.fromBitLen(allocator, 7);

    defer a.deinit(allocator);
    defer b.deinit(allocator);
    defer c.deinit(allocator);

    try a.set(allocator, 0, true);
    try a.set(allocator, 3, true);

    try b.set(allocator, 0, true);
    try b.set(allocator, 3, true);

    try c.set(allocator, 0, true);

    try std.testing.expect(BL.equals(&a, &b));
    try std.testing.expect(!BL.equals(&a, &c));
}

test "BitListType - default_root" {
    const Bits2048 = BitListType(2048);
    var expected_root: [32]u8 = undefined;

    try Bits2048.hashTreeRoot(std.testing.allocator, &Bits2048.default_value, &expected_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &Bits2048.default_root);

    var pool = try Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = std.testing.allocator, .pool_size = 1024 });
    defer pool.deinit();

    const node = try Bits2048.tree.default(&pool);
    try std.testing.expectEqualSlices(u8, &expected_root, node.getRoot(&pool));
}

test "BitListType - tree.zeros" {
    const allocator = std.testing.allocator;

    const Bits257 = BitListType(257);

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    for (Bits257.limit / 2..Bits257.limit) |len| {
        const tree_node = try Bits257.tree.zeros(&pool, len);
        defer pool.unref(tree_node);

        var value = Bits257.default_value;
        defer Bits257.deinit(allocator, &value);
        // Implicitly set all bits to 0
        try value.resize(allocator, len);

        var expected_root: [32]u8 = undefined;
        try Bits257.hashTreeRoot(allocator, &value, &expected_root);

        try std.testing.expectEqualSlices(u8, &expected_root, tree_node.getRoot(&pool));
    }
}
