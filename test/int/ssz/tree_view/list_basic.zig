const std = @import("std");
const ssz = @import("ssz");
const Node = @import("persistent_merkle_tree").Node;

test "TreeView list element roundtrip" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const ListType = ssz.FixedListType(Uint32, 16);

    const base_values = [_]u32{ 5, 15, 25, 35, 45 };

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &base_values);

    var expected_list: ListType.Type = .empty;
    defer expected_list.deinit(allocator);
    try expected_list.appendSlice(allocator, &base_values);

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    try std.testing.expectEqual(@as(u32, 5), try view.get(0));
    try std.testing.expectEqual(@as(u32, 45), try view.get(4));

    try view.set(2, 99);
    try view.set(4, 123);

    try view.commit();

    expected_list.items[2] = 99;
    expected_list.items[4] = 123;

    var expected_root: [32]u8 = undefined;
    try ListType.hashTreeRoot(allocator, &expected_list, &expected_root);

    var actual_root: [32]u8 = undefined;
    try view.hashTreeRoot(&actual_root);

    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);

    var roundtrip: ListType.Type = .empty;
    defer roundtrip.deinit(allocator);
    try ListType.tree.toValue(allocator, view.getRoot(), &pool, &roundtrip);
    try std.testing.expectEqual(roundtrip.items.len, expected_list.items.len);
    try std.testing.expectEqualSlices(u32, expected_list.items, roundtrip.items);
}

test "TreeView list push updates cached length" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const ListType = ssz.FixedListType(Uint32, 16);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &[_]u32{ 1, 2, 3 });

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    try std.testing.expectEqual(@as(usize, 3), try view.length());

    try view.push(@as(u32, 55));

    try std.testing.expectEqual(@as(usize, 4), try view.length());
    try std.testing.expectEqual(@as(u32, 55), try view.get(3));

    try view.commit();

    try std.testing.expectEqual(@as(usize, 4), try view.length());

    var expected: ListType.Type = .empty;
    defer expected.deinit(allocator);
    try expected.appendSlice(allocator, &[_]u32{ 1, 2, 3, 55 });

    var expected_root: [32]u8 = undefined;
    try ListType.hashTreeRoot(allocator, &expected, &expected_root);

    var actual_root: [32]u8 = undefined;
    try view.hashTreeRoot(&actual_root);

    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

test "TreeView list getAllAlloc handles zero length" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();

    const Uint8 = ssz.UintType(8);
    const ListType = ssz.FixedListType(Uint8, 4);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    const filled = try view.getAll();
    defer allocator.free(filled);

    try std.testing.expectEqual(@as(usize, 0), filled.len);
}

test "TreeView list getAllAlloc spans multiple chunks" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    const Uint16 = ssz.UintType(16);
    const ListType = ssz.FixedListType(Uint16, 64);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);

    var values: [20]u16 = undefined;
    for (&values, 0..) |*val, idx| {
        val.* = @intCast((idx * 3 + 1) % 17);
    }
    try list.appendSlice(allocator, &values);

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    const filled = try view.getAll();
    defer allocator.free(filled);

    try std.testing.expectEqualSlices(u16, values[0..], filled);
}

test "TreeView list push batches before commit" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const ListType = ssz.FixedListType(Uint32, 16);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &[_]u32{ 1, 2, 3, 4 });

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    try view.push(@as(u32, 5));
    try view.push(@as(u32, 6));
    try view.push(@as(u32, 7));
    try view.push(@as(u32, 8));
    try view.push(@as(u32, 9));

    try std.testing.expectEqual(@as(usize, 9), try view.length());
    try std.testing.expectEqual(@as(u32, 9), try view.get(8));

    try view.commit();

    try std.testing.expectEqual(@as(usize, 9), try view.length());
    try std.testing.expectEqual(@as(u32, 9), try view.get(8));

    var expected: ListType.Type = .empty;
    defer expected.deinit(allocator);
    try expected.appendSlice(allocator, &[_]u32{ 1, 2, 3, 4, 5, 6, 7, 8, 9 });

    var expected_root: [32]u8 = undefined;
    try ListType.hashTreeRoot(allocator, &expected, &expected_root);
    var actual_root: [32]u8 = undefined;
    try view.hashTreeRoot(&actual_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

test "TreeView list push across chunk boundary resets prefetch" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const ListType = ssz.FixedListType(Uint32, 32);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &[_]u32{ 0, 1, 2, 3, 4, 5, 6, 7 });

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    const initial = try view.getAll();
    defer allocator.free(initial);
    try std.testing.expectEqual(@as(usize, 8), initial.len);

    try view.push(@as(u32, 8));
    try view.push(@as(u32, 9));

    try std.testing.expectEqual(@as(usize, 10), try view.length());
    try std.testing.expectEqual(@as(u32, 9), try view.get(9));

    const filled = try view.getAll();
    defer allocator.free(filled);
    var expected: [10]u32 = [_]u32{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    try std.testing.expectEqualSlices(u32, expected[0..], filled);
}

test "TreeView list push enforces limit" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const ListType = ssz.FixedListType(Uint32, 2);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &[_]u32{ 1, 2 });

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    try std.testing.expectError(error.LengthOverLimit, view.push(@as(u32, 3)));
    try std.testing.expectEqual(@as(usize, 2), try view.length());
}

// Refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/listBasic/tree.test.ts#L180-L203
test "TreeView basic list getAll reflects pushes" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const list_limit = 32;
    const Uint64 = ssz.UintType(64);
    const ListType = ssz.FixedListType(Uint64, list_limit);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    var expected: [list_limit]u64 = undefined;
    for (&expected, 0..) |*slot, idx| {
        slot.* = @intCast(idx);
    }

    for (expected, 0..) |value, idx| {
        try view.push(value);
        try std.testing.expectEqual(value, try view.get(idx));
    }

    try std.testing.expectError(error.LengthOverLimit, view.push(@intCast(list_limit)));

    for (expected, 0..) |value, idx| {
        try std.testing.expectEqual(value, try view.get(idx));
    }

    try view.commit();
    const filled = try view.getAll();
    defer allocator.free(filled);
    try std.testing.expectEqualSlices(u64, expected[0..], filled);
}

test "TreeView list sliceTo returns original when truncation unnecessary" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const ListType = ssz.FixedListType(Uint32, 16);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, &[_]u32{ 4, 5, 6, 7 });

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    try view.commit();

    var sliced = try view.sliceTo(100);
    defer sliced.deinit();

    try std.testing.expectEqual(try view.length(), try sliced.length());

    var expected_root: [32]u8 = undefined;
    try ListType.hashTreeRoot(allocator, &list, &expected_root);

    var actual_root: [32]u8 = undefined;
    try sliced.hashTreeRoot(&actual_root);

    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

// Refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/listBasic/tree.test.ts#L219-L247
test "TreeView basic list sliceTo matches incremental snapshots" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 2048);
    defer pool.deinit();

    const Uint64 = ssz.UintType(64);
    const ListType = ssz.FixedListType(Uint64, 1024);
    const total_values: usize = 16;

    var base_values: [total_values]u64 = undefined;
    for (&base_values, 0..) |*value, idx| {
        value.* = @intCast(idx);
    }

    var empty_list: ListType.Type = .empty;
    defer empty_list.deinit(allocator);
    const root_node = try ListType.tree.fromValue(allocator, &pool, &empty_list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    for (base_values) |value| {
        try view.push(value);
    }
    try view.commit();

    for (base_values, 0..) |_, idx| {
        var sliced = try view.sliceTo(idx);
        defer sliced.deinit();

        const expected_len = idx + 1;
        try std.testing.expectEqual(expected_len, try sliced.length());

        var expected: ListType.Type = .empty;
        defer expected.deinit(allocator);
        try expected.appendSlice(allocator, base_values[0..expected_len]);

        var actual: ListType.Type = .empty;
        defer actual.deinit(allocator);
        try ListType.tree.toValue(allocator, sliced.getRoot(), &pool, &actual);

        try std.testing.expectEqual(expected_len, actual.items.len);
        try std.testing.expectEqualSlices(u64, expected.items, actual.items);

        const serialized_len = ListType.serializedSize(&expected);
        const expected_bytes = try allocator.alloc(u8, serialized_len);
        defer allocator.free(expected_bytes);
        const actual_bytes = try allocator.alloc(u8, serialized_len);
        defer allocator.free(actual_bytes);

        _ = ListType.serializeIntoBytes(&expected, expected_bytes);
        _ = ListType.serializeIntoBytes(&actual, actual_bytes);
        try std.testing.expectEqualSlices(u8, expected_bytes, actual_bytes);

        var expected_root: [32]u8 = undefined;
        try ListType.hashTreeRoot(allocator, &expected, &expected_root);

        var actual_root: [32]u8 = undefined;
        try sliced.hashTreeRoot(&actual_root);

        try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
    }
}

test "TreeView list sliceTo truncates tail elements" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const ListType = ssz.FixedListType(Uint32, 32);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);

    const values = [_]u32{ 10, 20, 30, 40, 50 };
    try list.appendSlice(allocator, &values);

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    try view.commit();

    var sliced = try view.sliceTo(2);
    defer sliced.deinit();

    try std.testing.expectEqual(@as(usize, 3), try sliced.length());

    const filled = try sliced.getAll();
    defer allocator.free(filled);

    try std.testing.expectEqualSlices(u32, values[0..3], filled);

    var expected: ListType.Type = .empty;
    defer expected.deinit(allocator);
    try expected.appendSlice(allocator, values[0..3]);

    var expected_root: [32]u8 = undefined;
    try ListType.hashTreeRoot(allocator, &expected, &expected_root);

    var actual_root: [32]u8 = undefined;
    try sliced.hashTreeRoot(&actual_root);

    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}
