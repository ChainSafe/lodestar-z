const std = @import("std");
const ssz = @import("ssz");
const Node = @import("persistent_merkle_tree").Node;

test "TreeView vector element roundtrip" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 128);
    defer pool.deinit();

    const Uint64 = ssz.UintType(64);
    const VectorType = ssz.FixedVectorType(Uint64, 4);

    const original: VectorType.Type = [_]u64{ 11, 22, 33, 44 };

    const root_node = try VectorType.tree.fromValue(&pool, &original);
    var view = try VectorType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    try std.testing.expectEqual(@as(u64, 11), try view.get(0));
    try std.testing.expectEqual(@as(u64, 44), try view.get(3));

    try view.set(1, 77);
    try view.set(2, 88);

    try view.commit();

    var expected = original;
    expected[1] = 77;
    expected[2] = 88;

    var expected_root: [32]u8 = undefined;
    try VectorType.hashTreeRoot(&expected, &expected_root);

    var actual_root: [32]u8 = undefined;
    try view.hashTreeRoot(&actual_root);

    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);

    var roundtrip: VectorType.Type = undefined;
    try VectorType.tree.toValue(view.getRoot(), &pool, &roundtrip);
    try std.testing.expectEqualSlices(u64, &expected, &roundtrip);
}

test "TreeView vector getAll fills provided buffer" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const VectorType = ssz.FixedVectorType(Uint32, 8);

    const values = [_]u32{ 9, 8, 7, 6, 5, 4, 3, 2 };
    const root_node = try VectorType.tree.fromValue(&pool, &values);
    var view = try VectorType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    const out = try allocator.alloc(u32, values.len);
    defer allocator.free(out);

    const filled = try view.getAllInto(out);
    try std.testing.expectEqual(out.ptr, filled.ptr);
    try std.testing.expectEqual(out.len, filled.len);
    try std.testing.expectEqualSlices(u32, values[0..], filled);

    const wrong = try allocator.alloc(u32, values.len - 1);
    defer allocator.free(wrong);
    try std.testing.expectError(error.InvalidSize, view.getAllInto(wrong));
}

test "TreeView vector getAllAlloc roundtrip" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint16 = ssz.UintType(16);
    const VectorType = ssz.FixedVectorType(Uint16, 5);
    const values = [_]u16{ 3, 1, 4, 1, 5 };

    const root_node = try VectorType.tree.fromValue(&pool, &values);
    var view = try VectorType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    const filled = try view.getAll();
    defer allocator.free(filled);

    try std.testing.expectEqualSlices(u16, values[0..], filled);
}

test "TreeView vector getAllAlloc repeat reflects updates" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const VectorType = ssz.FixedVectorType(Uint32, 6);
    var values = [_]u32{ 10, 20, 30, 40, 50, 60 };

    const root_node = try VectorType.tree.fromValue(&pool, &values);
    var view = try VectorType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    const first = try view.getAll();
    defer allocator.free(first);
    try std.testing.expectEqualSlices(u32, values[0..], first);

    try view.set(3, 99);

    const second = try view.getAll();
    defer allocator.free(second);
    values[3] = 99;
    try std.testing.expectEqualSlices(u32, values[0..], second);
}

// Tests ported from TypeScript ssz packages/ssz/test/unit/byType/vector/tree.test.ts
test "ArrayBasicTreeView - serialize (uint64 vector)" {
    const allocator = std.testing.allocator;

    const Uint64 = ssz.UintType(64);
    const VecU64Type = ssz.FixedVectorType(Uint64, 4);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const TestCase = struct {
        id: []const u8,
        values: [4]u64,
        expected_serialized: []const u8,
        expected_root: [32]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .id = "4 values",
            .values = [4]u64{ 100000, 200000, 300000, 400000 },
            // 0xa086010000000000400d030000000000e093040000000000801a060000000000
            .expected_serialized = &[_]u8{ 0xa0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x0d, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x93, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x1a, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00 },
            // For VectorBasic, the root is the same as the serialized bytes (fits in one chunk)
            .expected_root = [_]u8{ 0xa0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x0d, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x93, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x1a, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00 },
        },
    };

    for (test_cases) |tc| {
        const value = tc.values;

        var value_serialized: [VecU64Type.fixed_size]u8 = undefined;
        _ = VecU64Type.serializeIntoBytes(&value, &value_serialized);

        const tree_node = try VecU64Type.tree.fromValue(&pool, &value);
        var view = try VecU64Type.TreeView.init(allocator, &pool, tree_node);
        defer view.deinit();

        var view_serialized: [VecU64Type.fixed_size]u8 = undefined;
        const written = try view.serializeIntoBytes(&view_serialized);
        try std.testing.expectEqual(view_serialized.len, written);

        try std.testing.expectEqualSlices(u8, tc.expected_serialized, &view_serialized);
        try std.testing.expectEqualSlices(u8, &value_serialized, &view_serialized);

        const view_size = view.serializedSize();
        try std.testing.expectEqual(tc.expected_serialized.len, view_size);

        var hash_root: [32]u8 = undefined;
        try view.hashTreeRoot(&hash_root);
        try std.testing.expectEqualSlices(u8, &tc.expected_root, &hash_root);
    }
}

test "ArrayBasicTreeView - serialize (uint8 vector)" {
    const allocator = std.testing.allocator;

    const Uint8 = ssz.UintType(8);
    const VecU8Type = ssz.FixedVectorType(Uint8, 8);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const value = [8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };

    var value_serialized: [VecU8Type.fixed_size]u8 = undefined;
    _ = VecU8Type.serializeIntoBytes(&value, &value_serialized);

    const tree_node = try VecU8Type.tree.fromValue(&pool, &value);
    var view = try VecU8Type.TreeView.init(allocator, &pool, tree_node);
    defer view.deinit();

    var view_serialized: [VecU8Type.fixed_size]u8 = undefined;
    const written = try view.serializeIntoBytes(&view_serialized);
    try std.testing.expectEqual(view_serialized.len, written);

    try std.testing.expectEqualSlices(u8, &value, &view_serialized);

    const view_size = view.serializedSize();
    try std.testing.expectEqual(@as(usize, 8), view_size);
}

test "ArrayBasicTreeView - get and set" {
    const allocator = std.testing.allocator;

    const Uint64 = ssz.UintType(64);
    const VecU64Type = ssz.FixedVectorType(Uint64, 4);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const value = [4]u64{ 100, 200, 300, 400 };
    const tree_node = try VecU64Type.tree.fromValue(&pool, &value);
    var view = try VecU64Type.TreeView.init(allocator, &pool, tree_node);
    defer view.deinit();

    try std.testing.expectEqual(@as(u64, 100), try view.get(0));
    try std.testing.expectEqual(@as(u64, 200), try view.get(1));
    try std.testing.expectEqual(@as(u64, 300), try view.get(2));
    try std.testing.expectEqual(@as(u64, 400), try view.get(3));

    try view.set(1, 999);
    try std.testing.expectEqual(@as(u64, 999), try view.get(1));

    var serialized: [VecU64Type.fixed_size]u8 = undefined;
    const written = try view.serializeIntoBytes(&serialized);
    try std.testing.expectEqual(serialized.len, written);

    const expected = [4]u64{ 100, 999, 300, 400 };
    var expected_serialized: [VecU64Type.fixed_size]u8 = undefined;
    _ = VecU64Type.serializeIntoBytes(&expected, &expected_serialized);
    try std.testing.expectEqualSlices(u8, &expected_serialized, &serialized);
}
