//! Tests for `list.zig`.

const std = @import("std");
const pmt = @import("persistent_merkle_tree");
const Node = pmt.Node;
const UintType = @import("uint.zig").UintType;
const ByteVectorType = @import("byte_vector.zig").ByteVectorType;
const FixedContainerType = @import("container.zig").FixedContainerType;
const VariableContainerType = @import("container.zig").VariableContainerType;
const TypeTestCase = @import("test_utils.zig").TypeTestCase;
const FixedListType = @import("list.zig").FixedListType;
const VariableListType = @import("list.zig").VariableListType;

const testCases = [_]TypeTestCase{
    .{ .id = "empty", .serializedHex = "0x", .json = "[]", .rootHex = "0x52e2647abc3d0c9d3be0387f3f0d925422c7a4e98cf4489066f0f43281a899f3" },
    .{ .id = "4 values", .serializedHex = "0xa086010000000000400d030000000000e093040000000000801a060000000000a086010000000000400d030000000000e093040000000000801a060000000000", .json =
    \\["100000","200000","300000","400000","100000","200000","300000","400000"]
    , .rootHex = "0xb55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1" },
    .{
        .id = "8 values",
        .serializedHex = "0xa086010000000000400d030000000000e093040000000000801a060000000000a086010000000000400d030000000000e093040000000000801a060000000000",
        .json =
        \\["100000","200000","300000","400000","100000","200000","300000","400000"]
        ,
        .rootHex = "0xb55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1",
    },
};

test "ListType - sanity" {
    const allocator = std.testing.allocator;

    // create a fixed list type and instance and round-trip serialize
    const Bytes = FixedListType(UintType(8), 32, .{});

    var b: Bytes.Type = Bytes.default_value;
    defer b.deinit(allocator);
    try b.append(allocator, 5);

    const b_buf = try allocator.alloc(u8, Bytes.serializedSize(&b));
    defer allocator.free(b_buf);

    _ = Bytes.serializeIntoBytes(&b, b_buf);
    try Bytes.deserializeFromBytes(allocator, b_buf, &b);

    // create a variable list type and instance and round-trip serialize
    const BytesBytes = VariableListType(Bytes, 32);
    var bb: BytesBytes.Type = BytesBytes.default_value;
    defer bb.deinit(allocator);
    const b2: Bytes.Type = Bytes.default_value;
    try bb.append(allocator, b2);

    const bb_buf = try allocator.alloc(u8, BytesBytes.serializedSize(&bb));
    defer allocator.free(bb_buf);

    _ = BytesBytes.serializeIntoBytes(&bb, bb_buf);
    try BytesBytes.deserializeFromBytes(allocator, bb_buf, &bb);
}

test "clone FixedListType" {
    const allocator = std.testing.allocator;
    const Checkpoint = FixedContainerType(struct {
        epoch: UintType(8),
        root: ByteVectorType(32),
    });
    const CheckpointList = FixedListType(Checkpoint, 8, .{});
    var list: CheckpointList.Type = CheckpointList.default_value;
    defer CheckpointList.deinit(allocator, &list);
    const cp: Checkpoint.Type = .{
        .epoch = 41,
        .root = [_]u8{1} ** 32,
    };
    try list.append(allocator, cp);
    var cloned: CheckpointList.Type = CheckpointList.default_value;
    try CheckpointList.clone(allocator, &list, &cloned);
    defer cloned.deinit(allocator);
    try std.testing.expect(&list != &cloned);
    try std.testing.expect(CheckpointList.equals(&list, &cloned));

    // clone to a list of a different type
    const CheckpointHex = FixedContainerType(struct {
        epoch: UintType(8),
        root: ByteVectorType(32),
        root_hex: ByteVectorType(64),
    });
    const CheckpointHexList = FixedListType(CheckpointHex, 8, .{});
    var list_hex: CheckpointHexList.Type = CheckpointHexList.default_value;
    defer list_hex.deinit(allocator);
    try CheckpointList.clone(allocator, &list, &list_hex);
    try std.testing.expect(list_hex.items.len == 1);
    try std.testing.expect(list_hex.items[0].epoch == cp.epoch);
    try std.testing.expectEqualSlices(u8, &list_hex.items[0].root, &cp.root);
}

test "clone VariableListType" {
    const allocator = std.testing.allocator;
    const FieldA = FixedListType(UintType(8), 32, .{});
    const Foo = VariableContainerType(struct {
        a: FieldA,
    });
    const ListFoo = VariableListType(Foo, 8);
    var list = ListFoo.default_value;
    defer ListFoo.deinit(allocator, &list);
    var fielda = FieldA.default_value;
    try fielda.append(allocator, 100);
    try list.append(allocator, .{ .a = fielda });

    var cloned: ListFoo.Type = ListFoo.default_value;
    defer ListFoo.deinit(allocator, &cloned);
    try ListFoo.clone(allocator, &list, &cloned);
    try std.testing.expect(&list != &cloned);
    try std.testing.expect(cloned.items.len == 1);
    try std.testing.expect(ListFoo.equals(&list, &cloned));

    // clone to a list of a different type
    const Bar = VariableContainerType(struct {
        a: FieldA,
        b: UintType(8),
    });
    const ListBar = VariableListType(Bar, 8);
    var list_bar: ListBar.Type = ListBar.default_value;
    defer ListBar.deinit(allocator, &list_bar);
    try ListFoo.clone(allocator, &list, &list_bar);
    try std.testing.expect(list_bar.items.len == 1);
    try std.testing.expect(FieldA.equals(&list_bar.items[0].a, &fielda));
}

// Tests ported from TypeScript ssz packages/ssz/test/unit/byType/listBasic/valid.test.ts
test "FixedListType - tree roundtrip (ListBasic uint8)" {
    const allocator = std.testing.allocator;

    const ListU8 = FixedListType(UintType(8), 128, .{});

    const TestCase = struct {
        id: []const u8,
        values: []const u8,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty",
            .values = &[_]u8{},
            // 0x28ba1834a3a7b657460ce79fa3a1d909ab8828fd557659d4d0554a9bdbc0ec30
            .expected_root = [_]u8{ 0x28, 0xba, 0x18, 0x34, 0xa3, 0xa7, 0xb6, 0x57, 0x46, 0x0c, 0xe7, 0x9f, 0xa3, 0xa1, 0xd9, 0x09, 0xab, 0x88, 0x28, 0xfd, 0x55, 0x76, 0x59, 0xd4, 0xd0, 0x55, 0x4a, 0x9b, 0xdb, 0xc0, 0xec, 0x30 },
        },
        .{
            .id = "4 values",
            .values = &[_]u8{ 1, 2, 3, 4 },
            // 0xbac511d1f641d6b8823200bb4b3cced3bd4720701f18571dff35a5d2a40190fa
            .expected_root = [_]u8{ 0xba, 0xc5, 0x11, 0xd1, 0xf6, 0x41, 0xd6, 0xb8, 0x82, 0x32, 0x00, 0xbb, 0x4b, 0x3c, 0xce, 0xd3, 0xbd, 0x47, 0x20, 0x70, 0x1f, 0x18, 0x57, 0x1d, 0xff, 0x35, 0xa5, 0xd2, 0xa4, 0x01, 0x90, 0xfa },
        },
    };

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    for (test_cases) |tc| {
        var value: ListU8.Type = ListU8.default_value;
        defer value.deinit(allocator);
        for (tc.values) |v| {
            try value.append(allocator, v);
        }

        const serialized = try allocator.alloc(u8, ListU8.serializedSize(&value));
        defer allocator.free(serialized);
        _ = ListU8.serializeIntoBytes(&value, serialized);

        const tree_node = try ListU8.tree.fromValue(&pool, &value);

        var value_from_tree: ListU8.Type = ListU8.default_value;
        defer value_from_tree.deinit(allocator);
        try ListU8.tree.toValue(allocator, tree_node, &pool, &value_from_tree);

        try std.testing.expectEqual(value.items.len, value_from_tree.items.len);
        try std.testing.expectEqualSlices(u8, value.items, value_from_tree.items);

        const tree_size = try ListU8.tree.serializedSize(tree_node, &pool);
        try std.testing.expectEqual(serialized.len, tree_size);

        const tree_serialized = try allocator.alloc(u8, tree_size);
        defer allocator.free(tree_serialized);
        _ = try ListU8.tree.serializeIntoBytes(tree_node, &pool, tree_serialized);
        try std.testing.expectEqualSlices(u8, serialized, tree_serialized);

        var hash_root: [32]u8 = undefined;
        try ListU8.hashTreeRoot(allocator, &value, &hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "FixedListType - tree roundtrip (ListBasic uint64)" {
    const allocator = std.testing.allocator;

    const ListU64 = FixedListType(UintType(64), 128, .{});

    const TestCase = struct {
        id: []const u8,
        values: []const u64,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty",
            .values = &[_]u64{},
            // 0x52e2647abc3d0c9d3be0387f3f0d925422c7a4e98cf4489066f0f43281a899f3
            .expected_root = [_]u8{ 0x52, 0xe2, 0x64, 0x7a, 0xbc, 0x3d, 0x0c, 0x9d, 0x3b, 0xe0, 0x38, 0x7f, 0x3f, 0x0d, 0x92, 0x54, 0x22, 0xc7, 0xa4, 0xe9, 0x8c, 0xf4, 0x48, 0x90, 0x66, 0xf0, 0xf4, 0x32, 0x81, 0xa8, 0x99, 0xf3 },
        },
        .{
            .id = "4 values",
            .values = &[_]u64{ 100000, 200000, 300000, 400000 },
            // 0xd1daef215502b7746e5ff3e8833e399cb249ab3f81d824be60e174ff5633c1bf
            .expected_root = [_]u8{ 0xd1, 0xda, 0xef, 0x21, 0x55, 0x02, 0xb7, 0x74, 0x6e, 0x5f, 0xf3, 0xe8, 0x83, 0x3e, 0x39, 0x9c, 0xb2, 0x49, 0xab, 0x3f, 0x81, 0xd8, 0x24, 0xbe, 0x60, 0xe1, 0x74, 0xff, 0x56, 0x33, 0xc1, 0xbf },
        },
        .{
            .id = "8 values",
            .values = &[_]u64{ 100000, 200000, 300000, 400000, 100000, 200000, 300000, 400000 },
            // 0xb55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1
            .expected_root = [_]u8{ 0xb5, 0x5b, 0x85, 0x92, 0xbc, 0xac, 0x47, 0x59, 0x06, 0x63, 0x14, 0x81, 0xbb, 0xc7, 0x46, 0xbc, 0xa7, 0x33, 0x9d, 0x04, 0xab, 0x10, 0x85, 0xe8, 0x48, 0x84, 0xa7, 0x00, 0xc0, 0x3d, 0xe4, 0xb1 },
        },
    };

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    for (test_cases) |tc| {
        var value: ListU64.Type = ListU64.default_value;
        defer value.deinit(allocator);
        for (tc.values) |v| {
            try value.append(allocator, v);
        }

        const serialized = try allocator.alloc(u8, ListU64.serializedSize(&value));
        defer allocator.free(serialized);
        _ = ListU64.serializeIntoBytes(&value, serialized);

        const tree_node = try ListU64.tree.fromValue(&pool, &value);

        var value_from_tree: ListU64.Type = ListU64.default_value;
        defer value_from_tree.deinit(allocator);
        try ListU64.tree.toValue(allocator, tree_node, &pool, &value_from_tree);

        try std.testing.expectEqual(value.items.len, value_from_tree.items.len);
        try std.testing.expectEqualSlices(u64, value.items, value_from_tree.items);

        const tree_size = try ListU64.tree.serializedSize(tree_node, &pool);
        const tree_serialized = try allocator.alloc(u8, tree_size);
        defer allocator.free(tree_serialized);
        _ = try ListU64.tree.serializeIntoBytes(tree_node, &pool, tree_serialized);
        try std.testing.expectEqualSlices(u8, serialized, tree_serialized);

        var hash_root: [32]u8 = undefined;
        try ListU64.hashTreeRoot(allocator, &value, &hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "FixedListType - serializeIntoBytes (ListComposite ByteVector32 - empty)" {
    const allocator = std.testing.allocator;
    const ByteVector32 = ByteVectorType(32);
    const ListBV32 = FixedListType(ByteVector32, 128, .{});

    var value: ListBV32.Type = ListBV32.default_value;

    const expected_serialized = [_]u8{};
    const expected_root = [_]u8{ 0x96, 0x55, 0x96, 0x74, 0xa7, 0x96, 0x56, 0xe5, 0x40, 0x87, 0x1e, 0x1f, 0x39, 0xc9, 0xb9, 0x1e, 0x15, 0x2a, 0xa8, 0xcd, 0xdb, 0x71, 0x49, 0x3e, 0x75, 0x48, 0x27, 0xc4, 0xcc, 0x80, 0x9d, 0x57 };

    const size = ListBV32.serializedSize(&value);
    try std.testing.expectEqual(@as(usize, 0), size);
    const serialized = try allocator.alloc(u8, size);
    defer allocator.free(serialized);
    const written = ListBV32.serializeIntoBytes(&value, serialized);
    try std.testing.expectEqual(@as(usize, 0), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, serialized);

    var root: [32]u8 = undefined;
    try ListBV32.hashTreeRoot(allocator, &value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();
    const node = try ListBV32.tree.fromValue(&pool, &value);
    const tree_size = try ListBV32.tree.serializedSize(node, &pool);
    try std.testing.expectEqual(@as(usize, 0), tree_size);
    const tree_serialized = try allocator.alloc(u8, tree_size);
    defer allocator.free(tree_serialized);
    _ = try ListBV32.tree.serializeIntoBytes(node, &pool, tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, tree_serialized);
}

test "FixedListType - serializeIntoBytes (ListComposite ByteVector32 - 2 roots)" {
    const allocator = std.testing.allocator;
    const ByteVector32 = ByteVectorType(32);
    const ListBV32 = FixedListType(ByteVector32, 128, .{});

    var value: ListBV32.Type = ListBV32.default_value;
    defer value.deinit(allocator);
    // [0xdddd...dd, 0xeeee...ee]
    try value.append(allocator, [_]u8{0xdd} ** 32);
    try value.append(allocator, [_]u8{0xee} ** 32);

    // 0xddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
    const expected_serialized = [_]u8{0xdd} ** 32 ++ [_]u8{0xee} ** 32;
    const expected_root = [_]u8{ 0x0c, 0xb9, 0x47, 0x37, 0x7e, 0x17, 0x7f, 0x77, 0x47, 0x19, 0xea, 0xd8, 0xd2, 0x10, 0xaf, 0x9c, 0x64, 0x61, 0xf4, 0x1b, 0xaf, 0x5b, 0x40, 0x82, 0xf8, 0x6a, 0x39, 0x11, 0x45, 0x48, 0x31, 0xb8 };

    const size = ListBV32.serializedSize(&value);
    try std.testing.expectEqual(@as(usize, 64), size);
    const serialized = try allocator.alloc(u8, size);
    defer allocator.free(serialized);
    const written = ListBV32.serializeIntoBytes(&value, serialized);
    try std.testing.expectEqual(@as(usize, 64), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, serialized);

    var root: [32]u8 = undefined;
    try ListBV32.hashTreeRoot(allocator, &value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();
    const node = try ListBV32.tree.fromValue(&pool, &value);
    const tree_size = try ListBV32.tree.serializedSize(node, &pool);
    try std.testing.expectEqual(@as(usize, 64), tree_size);
    const tree_serialized = try allocator.alloc(u8, tree_size);
    defer allocator.free(tree_serialized);
    _ = try ListBV32.tree.serializeIntoBytes(node, &pool, tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, tree_serialized);
}

test "FixedListType - serializeIntoBytes (ListComposite Container - empty)" {
    const allocator = std.testing.allocator;
    const Container = FixedContainerType(struct {
        a: UintType(64),
        b: UintType(64),
    });
    const ListContainer = FixedListType(Container, 128, .{});

    var value: ListContainer.Type = ListContainer.default_value;

    const expected_serialized = [_]u8{};
    const expected_root = [_]u8{ 0x96, 0x55, 0x96, 0x74, 0xa7, 0x96, 0x56, 0xe5, 0x40, 0x87, 0x1e, 0x1f, 0x39, 0xc9, 0xb9, 0x1e, 0x15, 0x2a, 0xa8, 0xcd, 0xdb, 0x71, 0x49, 0x3e, 0x75, 0x48, 0x27, 0xc4, 0xcc, 0x80, 0x9d, 0x57 };

    const size = ListContainer.serializedSize(&value);
    try std.testing.expectEqual(@as(usize, 0), size);
    const serialized = try allocator.alloc(u8, size);
    defer allocator.free(serialized);
    const written = ListContainer.serializeIntoBytes(&value, serialized);
    try std.testing.expectEqual(@as(usize, 0), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, serialized);

    var root: [32]u8 = undefined;
    try ListContainer.hashTreeRoot(allocator, &value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();
    const node = try ListContainer.tree.fromValue(&pool, &value);
    const tree_size = try ListContainer.tree.serializedSize(node, &pool);
    try std.testing.expectEqual(@as(usize, 0), tree_size);
    const tree_serialized = try allocator.alloc(u8, tree_size);
    defer allocator.free(tree_serialized);
    _ = try ListContainer.tree.serializeIntoBytes(node, &pool, tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, tree_serialized);
}

test "FixedListType - serializeIntoBytes (ListComposite Container - 2 values)" {
    const allocator = std.testing.allocator;
    const Container = FixedContainerType(struct {
        a: UintType(64),
        b: UintType(64),
    });
    const ListContainer = FixedListType(Container, 128, .{});

    var value: ListContainer.Type = ListContainer.default_value;
    defer value.deinit(allocator);
    // [{a: 0, b: 0}, {a: 123456, b: 654321}]
    try value.append(allocator, .{ .a = 0, .b = 0 });
    try value.append(allocator, .{ .a = 123456, .b = 654321 });

    // 0x0000000000000000000000000000000040e2010000000000f1fb090000000000
    const expected_serialized = [_]u8{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // a = 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // b = 0
        0x40, 0xe2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // a = 123456
        0xf1, 0xfb, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, // b = 654321
    };
    const expected_root = [_]u8{ 0x8f, 0xf9, 0x4c, 0x10, 0xd3, 0x9f, 0xfa, 0x84, 0xaa, 0x93, 0x7e, 0x2a, 0x07, 0x72, 0x39, 0xc2, 0x74, 0x2c, 0xb4, 0x25, 0xa2, 0xa1, 0x61, 0x74, 0x4a, 0x3e, 0x98, 0x76, 0xeb, 0x3c, 0x72, 0x10 };

    const size = ListContainer.serializedSize(&value);
    try std.testing.expectEqual(@as(usize, 32), size);
    const serialized = try allocator.alloc(u8, size);
    defer allocator.free(serialized);
    const written = ListContainer.serializeIntoBytes(&value, serialized);
    try std.testing.expectEqual(@as(usize, 32), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, serialized);

    var root: [32]u8 = undefined;
    try ListContainer.hashTreeRoot(allocator, &value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();
    const node = try ListContainer.tree.fromValue(&pool, &value);
    const tree_size = try ListContainer.tree.serializedSize(node, &pool);
    try std.testing.expectEqual(@as(usize, 32), tree_size);
    const tree_serialized = try allocator.alloc(u8, tree_size);
    defer allocator.free(tree_serialized);
    _ = try ListContainer.tree.serializeIntoBytes(node, &pool, tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, tree_serialized);
}

test "VariableListType - serializeIntoBytes (List<List<uint16>> - empty)" {
    const allocator = std.testing.allocator;
    const InnerList = FixedListType(UintType(16), 2, .{});
    const OuterList = VariableListType(InnerList, 2);

    var value: OuterList.Type = OuterList.default_value;

    // empty list
    const expected_serialized = [_]u8{};
    const expected_root = [_]u8{ 0x7a, 0x05, 0x01, 0xf5, 0x95, 0x7b, 0xdf, 0x9c, 0xb3, 0xa8, 0xff, 0x49, 0x66, 0xf0, 0x22, 0x65, 0xf9, 0x68, 0x65, 0x8b, 0x7a, 0x9c, 0x62, 0x64, 0x2c, 0xba, 0x11, 0x65, 0xe8, 0x66, 0x42, 0xf5 };

    const size = OuterList.serializedSize(&value);
    try std.testing.expectEqual(@as(usize, 0), size);
    const serialized = try allocator.alloc(u8, size);
    defer allocator.free(serialized);
    const written = OuterList.serializeIntoBytes(&value, serialized);
    try std.testing.expectEqual(@as(usize, 0), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, serialized);

    var root: [32]u8 = undefined;
    try OuterList.hashTreeRoot(allocator, &value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();
    const node = try OuterList.tree.fromValue(&pool, &value);
    const tree_size = try OuterList.tree.serializedSize(node, &pool);
    try std.testing.expectEqual(@as(usize, 0), tree_size);
    const tree_serialized = try allocator.alloc(u8, tree_size);
    defer allocator.free(tree_serialized);
    _ = try OuterList.tree.serializeIntoBytes(node, &pool, tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, tree_serialized);
}

test "VariableListType - serializeIntoBytes (List<List<uint16>> - 2 full values)" {
    const allocator = std.testing.allocator;
    const InnerList = FixedListType(UintType(16), 2, .{});
    const OuterList = VariableListType(InnerList, 2);

    var value: OuterList.Type = OuterList.default_value;
    defer OuterList.deinit(allocator, &value);
    // [[1, 2], [3, 4]]
    var inner1: InnerList.Type = InnerList.default_value;
    try inner1.appendSlice(allocator, &[_]u16{ 1, 2 });
    var inner2: InnerList.Type = InnerList.default_value;
    try inner2.appendSlice(allocator, &[_]u16{ 3, 4 });
    try value.append(allocator, inner1);
    try value.append(allocator, inner2);

    // 0x080000000c0000000100020003000400
    const expected_serialized = [_]u8{
        0x08, 0x00, 0x00, 0x00, // offset to inner1 (8)
        0x0c, 0x00, 0x00, 0x00, // offset to inner2 (12)
        0x01, 0x00, // 1
        0x02, 0x00, // 2
        0x03, 0x00, // 3
        0x04, 0x00, // 4
    };
    const expected_root = [_]u8{ 0x58, 0x14, 0x0d, 0x48, 0xf9, 0xc2, 0x45, 0x45, 0xc1, 0xe3, 0xa5, 0x0f, 0x1e, 0xbc, 0xca, 0x85, 0xfd, 0x40, 0x43, 0x3c, 0x98, 0x59, 0xc0, 0xac, 0x34, 0x34, 0x2f, 0xc8, 0xe0, 0xa8, 0x00, 0xb8 };

    const size = OuterList.serializedSize(&value);
    try std.testing.expectEqual(@as(usize, 16), size);
    const serialized = try allocator.alloc(u8, size);
    defer allocator.free(serialized);
    const written = OuterList.serializeIntoBytes(&value, serialized);
    try std.testing.expectEqual(@as(usize, 16), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, serialized);

    var root: [32]u8 = undefined;
    try OuterList.hashTreeRoot(allocator, &value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();
    const node = try OuterList.tree.fromValue(&pool, &value);
    const tree_size = try OuterList.tree.serializedSize(node, &pool);
    try std.testing.expectEqual(@as(usize, 16), tree_size);
    const tree_serialized = try allocator.alloc(u8, tree_size);
    defer allocator.free(tree_serialized);
    _ = try OuterList.tree.serializeIntoBytes(node, &pool, tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, tree_serialized);
}

test "VariableListType - serializeIntoBytes (List<List<uint16>> - 2 empty values)" {
    const allocator = std.testing.allocator;
    const InnerList = FixedListType(UintType(16), 2, .{});
    const OuterList = VariableListType(InnerList, 2);

    var value: OuterList.Type = OuterList.default_value;
    defer OuterList.deinit(allocator, &value);
    // [[], []]
    const inner1: InnerList.Type = InnerList.default_value;
    const inner2: InnerList.Type = InnerList.default_value;
    try value.append(allocator, inner1);
    try value.append(allocator, inner2);

    // 0x0800000008000000
    const expected_serialized = [_]u8{
        0x08, 0x00, 0x00, 0x00, // offset to inner1 (8)
        0x08, 0x00, 0x00, 0x00, // offset to inner2 (8) - same offset since inner1 is empty
    };
    const expected_root = [_]u8{ 0xe8, 0x39, 0xa2, 0x27, 0x14, 0xbd, 0xa0, 0x59, 0x23, 0xb6, 0x11, 0xd0, 0x7b, 0xe9, 0x3b, 0x4d, 0x70, 0x70, 0x27, 0xd2, 0x9f, 0xd9, 0xee, 0xf7, 0xaa, 0x86, 0x4e, 0xd5, 0x87, 0xe4, 0x62, 0xec };

    const size = OuterList.serializedSize(&value);
    try std.testing.expectEqual(@as(usize, 8), size);
    const serialized = try allocator.alloc(u8, size);
    defer allocator.free(serialized);
    const written = OuterList.serializeIntoBytes(&value, serialized);
    try std.testing.expectEqual(@as(usize, 8), written);
    try std.testing.expectEqualSlices(u8, &expected_serialized, serialized);

    var root: [32]u8 = undefined;
    try OuterList.hashTreeRoot(allocator, &value, &root);
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();
    const node = try OuterList.tree.fromValue(&pool, &value);
    const tree_size = try OuterList.tree.serializedSize(node, &pool);
    try std.testing.expectEqual(@as(usize, 8), tree_size);
    const tree_serialized = try allocator.alloc(u8, tree_size);
    defer allocator.free(tree_serialized);
    _ = try OuterList.tree.serializeIntoBytes(node, &pool, tree_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, tree_serialized);
}

test "FixedListType - tree.deserializeFromBytes (ListBasic uint8)" {
    const allocator = std.testing.allocator;

    const ListU8 = FixedListType(UintType(8), 128, .{});

    const TestCase = struct {
        id: []const u8,
        serialized: []const u8,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty",
            .serialized = &[_]u8{},
            // 0x28ba1834a3a7b657460ce79fa3a1d909ab8828fd557659d4d0554a9bdbc0ec30
            .expected_root = [_]u8{ 0x28, 0xba, 0x18, 0x34, 0xa3, 0xa7, 0xb6, 0x57, 0x46, 0x0c, 0xe7, 0x9f, 0xa3, 0xa1, 0xd9, 0x09, 0xab, 0x88, 0x28, 0xfd, 0x55, 0x76, 0x59, 0xd4, 0xd0, 0x55, 0x4a, 0x9b, 0xdb, 0xc0, 0xec, 0x30 },
        },
        .{
            .id = "4 values",
            .serialized = &[_]u8{ 0x01, 0x02, 0x03, 0x04 },
            // 0xbac511d1f641d6b8823200bb4b3cced3bd4720701f18571dff35a5d2a40190fa
            .expected_root = [_]u8{ 0xba, 0xc5, 0x11, 0xd1, 0xf6, 0x41, 0xd6, 0xb8, 0x82, 0x32, 0x00, 0xbb, 0x4b, 0x3c, 0xce, 0xd3, 0xbd, 0x47, 0x20, 0x70, 0x1f, 0x18, 0x57, 0x1d, 0xff, 0x35, 0xa5, 0xd2, 0xa4, 0x01, 0x90, 0xfa },
        },
    };

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    for (test_cases) |tc| {
        const tree_node = try ListU8.tree.deserializeFromBytes(&pool, tc.serialized);

        var value_from_tree: ListU8.Type = ListU8.default_value;
        defer value_from_tree.deinit(allocator);
        try ListU8.tree.toValue(allocator, tree_node, &pool, &value_from_tree);

        try std.testing.expectEqual(tc.serialized.len, value_from_tree.items.len);
        try std.testing.expectEqualSlices(u8, tc.serialized, value_from_tree.items);

        const tree_size = try ListU8.tree.serializedSize(tree_node, &pool);
        try std.testing.expectEqual(tc.serialized.len, tree_size);
        const tree_serialized = try allocator.alloc(u8, tree_size);
        defer allocator.free(tree_serialized);
        _ = try ListU8.tree.serializeIntoBytes(tree_node, &pool, tree_serialized);
        try std.testing.expectEqualSlices(u8, tc.serialized, tree_serialized);

        var hash_root: [32]u8 = undefined;
        try ListU8.hashTreeRoot(allocator, &value_from_tree, &hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "FixedListType - tree.deserializeFromBytes (ListBasic uint64)" {
    const allocator = std.testing.allocator;

    const ListU64 = FixedListType(UintType(64), 128, .{});

    const TestCase = struct {
        id: []const u8,
        serialized: []const u8,
        expected_values: []const u64,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty",
            .serialized = &[_]u8{},
            .expected_values = &[_]u64{},
            // 0x52e2647abc3d0c9d3be0387f3f0d925422c7a4e98cf4489066f0f43281a899f3
            .expected_root = [_]u8{ 0x52, 0xe2, 0x64, 0x7a, 0xbc, 0x3d, 0x0c, 0x9d, 0x3b, 0xe0, 0x38, 0x7f, 0x3f, 0x0d, 0x92, 0x54, 0x22, 0xc7, 0xa4, 0xe9, 0x8c, 0xf4, 0x48, 0x90, 0x66, 0xf0, 0xf4, 0x32, 0x81, 0xa8, 0x99, 0xf3 },
        },
        .{
            .id = "4 values",
            // 0xa086010000000000400d030000000000e093040000000000801a060000000000
            .serialized = &[_]u8{
                0xa0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // 100000
                0x40, 0x0d, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, // 200000
                0xe0, 0x93, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // 300000
                0x80, 0x1a, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, // 400000
            },
            .expected_values = &[_]u64{ 100000, 200000, 300000, 400000 },
            // 0xd1daef215502b7746e5ff3e8833e399cb249ab3f81d824be60e174ff5633c1bf
            .expected_root = [_]u8{ 0xd1, 0xda, 0xef, 0x21, 0x55, 0x02, 0xb7, 0x74, 0x6e, 0x5f, 0xf3, 0xe8, 0x83, 0x3e, 0x39, 0x9c, 0xb2, 0x49, 0xab, 0x3f, 0x81, 0xd8, 0x24, 0xbe, 0x60, 0xe1, 0x74, 0xff, 0x56, 0x33, 0xc1, 0xbf },
        },
        .{
            .id = "8 values",
            // 0xa086010000000000400d030000000000e093040000000000801a060000000000a086010000000000400d030000000000e093040000000000801a060000000000
            .serialized = &[_]u8{
                0xa0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // 100000
                0x40, 0x0d, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, // 200000
                0xe0, 0x93, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // 300000
                0x80, 0x1a, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, // 400000
                0xa0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // 100000
                0x40, 0x0d, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, // 200000
                0xe0, 0x93, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // 300000
                0x80, 0x1a, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, // 400000
            },
            .expected_values = &[_]u64{ 100000, 200000, 300000, 400000, 100000, 200000, 300000, 400000 },
            // 0xb55b8592bcac475906631481bbc746bca7339d04ab1085e84884a700c03de4b1
            .expected_root = [_]u8{ 0xb5, 0x5b, 0x85, 0x92, 0xbc, 0xac, 0x47, 0x59, 0x06, 0x63, 0x14, 0x81, 0xbb, 0xc7, 0x46, 0xbc, 0xa7, 0x33, 0x9d, 0x04, 0xab, 0x10, 0x85, 0xe8, 0x48, 0x84, 0xa7, 0x00, 0xc0, 0x3d, 0xe4, 0xb1 },
        },
    };

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    for (test_cases) |tc| {
        const tree_node = try ListU64.tree.deserializeFromBytes(&pool, tc.serialized);

        var value_from_tree: ListU64.Type = ListU64.default_value;
        defer value_from_tree.deinit(allocator);
        try ListU64.tree.toValue(allocator, tree_node, &pool, &value_from_tree);

        try std.testing.expectEqual(tc.expected_values.len, value_from_tree.items.len);
        try std.testing.expectEqualSlices(u64, tc.expected_values, value_from_tree.items);

        const tree_size = try ListU64.tree.serializedSize(tree_node, &pool);
        try std.testing.expectEqual(tc.serialized.len, tree_size);
        const tree_serialized = try allocator.alloc(u8, tree_size);
        defer allocator.free(tree_serialized);
        _ = try ListU64.tree.serializeIntoBytes(tree_node, &pool, tree_serialized);
        try std.testing.expectEqualSlices(u8, tc.serialized, tree_serialized);

        var hash_root: [32]u8 = undefined;
        try ListU64.hashTreeRoot(allocator, &value_from_tree, &hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "FixedListType - tree.deserializeFromBytes (ListComposite ByteVector32)" {
    const allocator = std.testing.allocator;
    const ByteVector32 = ByteVectorType(32);
    const ListBV32 = FixedListType(ByteVector32, 128, .{});

    const TestCase = struct {
        id: []const u8,
        serialized: []const u8,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty",
            .serialized = &[_]u8{},
            // 0x96559674a79656e540871e1f39c9b91e152aa8cddb71493e754827c4cc809d57
            .expected_root = [_]u8{ 0x96, 0x55, 0x96, 0x74, 0xa7, 0x96, 0x56, 0xe5, 0x40, 0x87, 0x1e, 0x1f, 0x39, 0xc9, 0xb9, 0x1e, 0x15, 0x2a, 0xa8, 0xcd, 0xdb, 0x71, 0x49, 0x3e, 0x75, 0x48, 0x27, 0xc4, 0xcc, 0x80, 0x9d, 0x57 },
        },
        .{
            .id = "2 roots",
            // 0xddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
            .serialized = &([_]u8{0xdd} ** 32 ++ [_]u8{0xee} ** 32),
            // 0x0cb947377e177f774719ead8d210af9c6461f41baf5b4082f86a3911454831b8
            .expected_root = [_]u8{ 0x0c, 0xb9, 0x47, 0x37, 0x7e, 0x17, 0x7f, 0x77, 0x47, 0x19, 0xea, 0xd8, 0xd2, 0x10, 0xaf, 0x9c, 0x64, 0x61, 0xf4, 0x1b, 0xaf, 0x5b, 0x40, 0x82, 0xf8, 0x6a, 0x39, 0x11, 0x45, 0x48, 0x31, 0xb8 },
        },
    };

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    for (test_cases) |tc| {
        const tree_node = try ListBV32.tree.deserializeFromBytes(&pool, tc.serialized);

        var value_from_tree: ListBV32.Type = ListBV32.default_value;
        defer value_from_tree.deinit(allocator);
        try ListBV32.tree.toValue(allocator, tree_node, &pool, &value_from_tree);

        try std.testing.expectEqual(tc.serialized.len / 32, value_from_tree.items.len);

        const tree_size = try ListBV32.tree.serializedSize(tree_node, &pool);
        try std.testing.expectEqual(tc.serialized.len, tree_size);
        const tree_serialized = try allocator.alloc(u8, tree_size);
        defer allocator.free(tree_serialized);
        _ = try ListBV32.tree.serializeIntoBytes(tree_node, &pool, tree_serialized);
        try std.testing.expectEqualSlices(u8, tc.serialized, tree_serialized);

        var hash_root: [32]u8 = undefined;
        try ListBV32.hashTreeRoot(allocator, &value_from_tree, &hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "FixedListType - tree.deserializeFromBytes (ListComposite Container)" {
    const allocator = std.testing.allocator;
    const Container = FixedContainerType(struct {
        a: UintType(64),
        b: UintType(64),
    });
    const ListContainer = FixedListType(Container, 128, .{});

    const TestCase = struct {
        id: []const u8,
        serialized: []const u8,
        expected_values: []const Container.Type,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty",
            .serialized = &[_]u8{},
            .expected_values = &[_]Container.Type{},
            // 0x96559674a79656e540871e1f39c9b91e152aa8cddb71493e754827c4cc809d57
            .expected_root = [_]u8{ 0x96, 0x55, 0x96, 0x74, 0xa7, 0x96, 0x56, 0xe5, 0x40, 0x87, 0x1e, 0x1f, 0x39, 0xc9, 0xb9, 0x1e, 0x15, 0x2a, 0xa8, 0xcd, 0xdb, 0x71, 0x49, 0x3e, 0x75, 0x48, 0x27, 0xc4, 0xcc, 0x80, 0x9d, 0x57 },
        },
        .{
            .id = "2 values",
            // 0x0000000000000000000000000000000040e2010000000000f1fb090000000000
            .serialized = &[_]u8{
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // a = 0
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // b = 0
                0x40, 0xe2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // a = 123456
                0xf1, 0xfb, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, // b = 654321
            },
            .expected_values = &[_]Container.Type{
                .{ .a = 0, .b = 0 },
                .{ .a = 123456, .b = 654321 },
            },
            // 0x8ff94c10d39ffa84aa937e2a077239c2742cb425a2a161744a3e9876eb3c7210
            .expected_root = [_]u8{ 0x8f, 0xf9, 0x4c, 0x10, 0xd3, 0x9f, 0xfa, 0x84, 0xaa, 0x93, 0x7e, 0x2a, 0x07, 0x72, 0x39, 0xc2, 0x74, 0x2c, 0xb4, 0x25, 0xa2, 0xa1, 0x61, 0x74, 0x4a, 0x3e, 0x98, 0x76, 0xeb, 0x3c, 0x72, 0x10 },
        },
    };

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    for (test_cases) |tc| {
        const tree_node = try ListContainer.tree.deserializeFromBytes(&pool, tc.serialized);

        var value_from_tree: ListContainer.Type = ListContainer.default_value;
        defer value_from_tree.deinit(allocator);
        try ListContainer.tree.toValue(allocator, tree_node, &pool, &value_from_tree);

        try std.testing.expectEqual(tc.expected_values.len, value_from_tree.items.len);
        for (tc.expected_values, 0..) |expected, i| {
            try std.testing.expectEqual(expected.a, value_from_tree.items[i].a);
            try std.testing.expectEqual(expected.b, value_from_tree.items[i].b);
        }

        const tree_size = try ListContainer.tree.serializedSize(tree_node, &pool);
        try std.testing.expectEqual(tc.serialized.len, tree_size);
        const tree_serialized = try allocator.alloc(u8, tree_size);
        defer allocator.free(tree_serialized);
        _ = try ListContainer.tree.serializeIntoBytes(tree_node, &pool, tree_serialized);
        try std.testing.expectEqualSlices(u8, tc.serialized, tree_serialized);

        var hash_root: [32]u8 = undefined;
        try ListContainer.hashTreeRoot(allocator, &value_from_tree, &hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "VariableListType - tree.deserializeFromBytes (List<List<uint16>>)" {
    const allocator = std.testing.allocator;
    const InnerList = FixedListType(UintType(16), 2, .{});
    const OuterList = VariableListType(InnerList, 2);

    const TestCase = struct {
        id: []const u8,
        serialized: []const u8,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "empty",
            .serialized = &[_]u8{},
            // 0x7a0501f5957bdf9cb3a8ff4966f02265f968658b7a9c62642cba1165e86642f5
            .expected_root = [_]u8{ 0x7a, 0x05, 0x01, 0xf5, 0x95, 0x7b, 0xdf, 0x9c, 0xb3, 0xa8, 0xff, 0x49, 0x66, 0xf0, 0x22, 0x65, 0xf9, 0x68, 0x65, 0x8b, 0x7a, 0x9c, 0x62, 0x64, 0x2c, 0xba, 0x11, 0x65, 0xe8, 0x66, 0x42, 0xf5 },
        },
        .{
            .id = "2 full values",
            // 0x080000000c0000000100020003000400
            .serialized = &[_]u8{
                0x08, 0x00, 0x00, 0x00, // offset to inner1 (8)
                0x0c, 0x00, 0x00, 0x00, // offset to inner2 (12)
                0x01, 0x00, // 1
                0x02, 0x00, // 2
                0x03, 0x00, // 3
                0x04, 0x00, // 4
            },
            // 0x58140d48f9c24545c1e3a50f1ebcca85fd40433c9859c0ac34342fc8e0a800b8
            .expected_root = [_]u8{ 0x58, 0x14, 0x0d, 0x48, 0xf9, 0xc2, 0x45, 0x45, 0xc1, 0xe3, 0xa5, 0x0f, 0x1e, 0xbc, 0xca, 0x85, 0xfd, 0x40, 0x43, 0x3c, 0x98, 0x59, 0xc0, 0xac, 0x34, 0x34, 0x2f, 0xc8, 0xe0, 0xa8, 0x00, 0xb8 },
        },
        .{
            .id = "2 empty values",
            // 0x0800000008000000
            .serialized = &[_]u8{
                0x08, 0x00, 0x00, 0x00, // offset to inner1 (8)
                0x08, 0x00, 0x00, 0x00, // offset to inner2 (8) - same offset since inner1 is empty
            },
            // 0xe839a22714bda05923b611d07be93b4d707027d29fd9eef7aa864ed587e462ec
            .expected_root = [_]u8{ 0xe8, 0x39, 0xa2, 0x27, 0x14, 0xbd, 0xa0, 0x59, 0x23, 0xb6, 0x11, 0xd0, 0x7b, 0xe9, 0x3b, 0x4d, 0x70, 0x70, 0x27, 0xd2, 0x9f, 0xd9, 0xee, 0xf7, 0xaa, 0x86, 0x4e, 0xd5, 0x87, 0xe4, 0x62, 0xec },
        },
    };

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    for (test_cases) |tc| {
        const tree_node = try OuterList.tree.deserializeFromBytes(&pool, tc.serialized);

        var value_from_tree: OuterList.Type = OuterList.default_value;
        defer OuterList.deinit(allocator, &value_from_tree);
        try OuterList.tree.toValue(allocator, tree_node, &pool, &value_from_tree);

        const tree_size = try OuterList.tree.serializedSize(tree_node, &pool);
        try std.testing.expectEqual(tc.serialized.len, tree_size);
        const tree_serialized = try allocator.alloc(u8, tree_size);
        defer allocator.free(tree_serialized);
        _ = try OuterList.tree.serializeIntoBytes(tree_node, &pool, tree_serialized);
        try std.testing.expectEqualSlices(u8, tc.serialized, tree_serialized);

        var hash_root: [32]u8 = undefined;
        try OuterList.hashTreeRoot(allocator, &value_from_tree, &hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "valid test for ListBasicType" {
    const allocator = std.testing.allocator;

    // uint of 8 bytes = u64
    const Uint = UintType(64);
    const List = FixedListType(Uint, 128, .{});

    const TypeTest = @import("test_utils.zig").typeTest(List);

    for (testCases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}

test "FixedListType equals" {
    const allocator = std.testing.allocator;
    const List = FixedListType(UintType(8), 32, .{});

    var a: List.Type = List.Type.empty;
    var b: List.Type = List.Type.empty;
    var c: List.Type = List.Type.empty;

    defer a.deinit(allocator);
    defer b.deinit(allocator);
    defer c.deinit(allocator);

    try a.appendSlice(allocator, &[_]u8{ 1, 2, 3 });
    try b.appendSlice(allocator, &[_]u8{ 1, 2, 3 });
    try c.appendSlice(allocator, &[_]u8{ 1, 2 });

    try std.testing.expect(List.equals(&a, &b));
    try std.testing.expect(!List.equals(&a, &c));
}

test "ListCompositeType of Root" {
    const test_cases = [_]TypeTestCase{
        // refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/listComposite/valid.test.ts#L23
        .{
            .id = "2 roots",
            .serializedHex = "0xddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            .json =
            \\["0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"]
            ,
            .rootHex = "0x0cb947377e177f774719ead8d210af9c6461f41baf5b4082f86a3911454831b8",
        },
    };

    const allocator = std.testing.allocator;
    const ByteVector = ByteVectorType(32);
    const List = FixedListType(ByteVector, 128, .{});

    const TypeTest = @import("test_utils.zig").typeTest(List);

    for (test_cases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}

test "ListCompositeType of Container" {
    const test_cases = [_]TypeTestCase{
        // refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/listComposite/valid.test.ts#L46
        .{
            .id = "2 values",
            .serializedHex = "0x0000000000000000000000000000000040e2010000000000f1fb090000000000",
            .json =
            \\[{"a":"0","b":"0"},{"a":"123456","b":"654321"}]
            ,
            .rootHex = "0x8ff94c10d39ffa84aa937e2a077239c2742cb425a2a161744a3e9876eb3c7210",
        },
    };

    const allocator = std.testing.allocator;
    const Uint = UintType(64);
    const Container = FixedContainerType(struct {
        a: Uint,
        b: Uint,
    });
    const List = FixedListType(Container, 128, .{});

    const TypeTest = @import("test_utils.zig").typeTest(List);

    for (test_cases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}

test "VariableListType of FixedList" {
    // refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/listComposite/valid.test.ts#L59
    const test_cases = [_]TypeTestCase{
        .{
            .id = "empty",
            .serializedHex = "0x",
            .json =
            \\[]
            ,
            .rootHex = "0x7a0501f5957bdf9cb3a8ff4966f02265f968658b7a9c62642cba1165e86642f5",
        },
        .{
            .id = "2 full values",
            .serializedHex = "0x080000000c0000000100020003000400",
            .json =
            \\[["1","2"],["3","4"]]
            ,
            .rootHex = "0x58140d48f9c24545c1e3a50f1ebcca85fd40433c9859c0ac34342fc8e0a800b8",
        },
        .{
            .id = "2 empty values",
            .serializedHex = "0x0800000008000000",
            .json =
            \\[[],[]]
            ,
            .rootHex = "0xe839a22714bda05923b611d07be93b4d707027d29fd9eef7aa864ed587e462ec",
        },
    };

    const allocator = std.testing.allocator;
    const FixedList = FixedListType(UintType(16), 2, .{});
    const List = VariableListType(FixedList, 2);

    const TypeTest = @import("test_utils.zig").typeTest(List);

    for (test_cases[0..]) |*tc| {
        try TypeTest.run(allocator, tc);
    }
}

test "FixedListType - default_root" {
    const ListU32 = FixedListType(UintType(32), 16, .{});
    var expected_root: [32]u8 = undefined;

    try ListU32.hashTreeRoot(std.testing.allocator, &ListU32.default_value, &expected_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &ListU32.default_root);

    var pool = try Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = std.testing.allocator, .pool_size = 1024 });
    defer pool.deinit();

    const node = try ListU32.tree.default(&pool);
    try std.testing.expectEqualSlices(u8, &expected_root, node.getRoot(&pool));
}

test "VariableListType - default_root" {
    const ListU32 = FixedListType(UintType(32), 16, .{});
    const ListListU32 = VariableListType(ListU32, 16);
    var expected_root: [32]u8 = undefined;

    try ListListU32.hashTreeRoot(std.testing.allocator, &ListListU32.default_value, &expected_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &ListListU32.default_root);

    var pool = try Node.Pool.init(.{ .page_allocator = std.testing.allocator, .allocator = std.testing.allocator, .pool_size = 1024 });
    defer pool.deinit();

    const node = try ListListU32.tree.default(&pool);
    try std.testing.expectEqualSlices(u8, &expected_root, node.getRoot(&pool));
}

test "FixedListType - tree.zeros" {
    const allocator = std.testing.allocator;

    const ListU16 = FixedListType(UintType(16), 8, .{});

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    for (0..ListU16.limit) |len| {
        const tree_node = try ListU16.tree.zeros(&pool, len);
        defer pool.unref(tree_node);

        var value = ListU16.default_value;
        defer ListU16.deinit(allocator, &value);
        try value.resize(allocator, len);
        @memset(value.items, 0);

        var expected_root: [32]u8 = undefined;
        try ListU16.hashTreeRoot(allocator, &value, &expected_root);

        try std.testing.expectEqualSlices(u8, &expected_root, tree_node.getRoot(&pool));
    }
}

test "VariableListType - tree.zeros" {
    const allocator = std.testing.allocator;

    const ListU32 = FixedListType(UintType(32), 16, .{});
    const ListListU32 = VariableListType(ListU32, 16);

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();

    for (0..ListListU32.limit) |len| {
        const tree_node = try ListListU32.tree.zeros(&pool, len);
        defer pool.unref(tree_node);

        var value = ListListU32.default_value;
        defer ListListU32.deinit(allocator, &value);
        try value.resize(allocator, len);
        @memset(value.items, ListListU32.Element.default_value);

        var expected_root: [32]u8 = undefined;
        try ListListU32.hashTreeRoot(allocator, &value, &expected_root);

        try std.testing.expectEqualSlices(u8, &expected_root, tree_node.getRoot(&pool));
    }
}

test "FixedListType opts.chunked_leaf=true: round-trip fromValue -> tree -> toValue" {
    const allocator = std.testing.allocator;
    const ChunkedLeaf = pmt.ChunkedLeaf;
    const ListT = FixedListType(UintType(64), 1 << 20, .{ .chunked_leaf = true });

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 4096 });
    defer pool.deinit();

    var src = ListT.Type.empty;
    defer src.deinit(allocator);
    const item_count: usize = 2 * @as(usize, ChunkedLeaf.K) * 4 + 7; // odd tail to stress partial chunked_leaf
    try src.ensureTotalCapacity(allocator, item_count);
    for (0..item_count) |i| try src.append(allocator, @as(u64, @intCast(i * 31 + 1)));

    const tree_id = try ListT.tree.fromValue(&pool, &src);
    defer pool.unref(tree_id);

    var dst = ListT.Type.empty;
    defer dst.deinit(allocator);
    try ListT.tree.toValue(allocator, tree_id, &pool, &dst);
    try std.testing.expectEqual(src.items.len, dst.items.len);
    for (src.items, dst.items) |a, b| try std.testing.expectEqual(a, b);

    // Hash matches the leaf-path (non-chunked_leaf) reference root.
    const ListLeafT = FixedListType(UintType(64), 1 << 20, .{});
    const leaf_tree_id = try ListLeafT.tree.fromValue(&pool, &src);
    defer pool.unref(leaf_tree_id);
    try std.testing.expectEqualSlices(u8, leaf_tree_id.getRoot(&pool), tree_id.getRoot(&pool));
}

test "FixedListType opts.chunked_leaf=true: serialize -> deserialize round-trip" {
    const allocator = std.testing.allocator;
    const ChunkedLeaf = pmt.ChunkedLeaf;
    const ListT = FixedListType(UintType(64), 1 << 20, .{ .chunked_leaf = true });

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 4096 });
    defer pool.deinit();

    var src = ListT.Type.empty;
    defer src.deinit(allocator);
    const item_count: usize = 2 * @as(usize, ChunkedLeaf.K) * 4;
    try src.ensureTotalCapacity(allocator, item_count);
    for (0..item_count) |i| try src.append(allocator, @as(u64, @intCast(i)));

    const tree_id = try ListT.tree.fromValue(&pool, &src);
    defer pool.unref(tree_id);

    const buf = try allocator.alloc(u8, item_count * @sizeOf(u64));
    defer allocator.free(buf);
    const written = try ListT.tree.serializeIntoBytes(tree_id, &pool, buf);
    try std.testing.expectEqual(item_count * @sizeOf(u64), written);

    const round_id = try ListT.tree.deserializeFromBytes(&pool, buf);
    defer pool.unref(round_id);
    try std.testing.expectEqualSlices(u8, tree_id.getRoot(&pool), round_id.getRoot(&pool));
}
