const std = @import("std");
const ssz = @import("ssz");
const Node = @import("persistent_merkle_tree").Node;

const Checkpoint = ssz.FixedContainerType(struct {
    epoch: ssz.UintType(64),
    root: ssz.ByteVectorType(32),
});

test "TreeView composite list sliceTo truncates elements" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    const ListType = ssz.FixedListType(Checkpoint, 16);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);

    const checkpoints = [_]Checkpoint.Type{
        .{ .epoch = 1, .root = [_]u8{1} ** 32 },
        .{ .epoch = 2, .root = [_]u8{2} ** 32 },
        .{ .epoch = 3, .root = [_]u8{3} ** 32 },
        .{ .epoch = 4, .root = [_]u8{4} ** 32 },
    };
    try list.appendSlice(allocator, &checkpoints);

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    var sliced = try view.sliceTo(1);
    defer sliced.deinit();

    try std.testing.expectEqual(@as(usize, 2), try sliced.length());

    var roundtrip: ListType.Type = .empty;
    defer roundtrip.deinit(allocator);
    try ListType.tree.toValue(allocator, sliced.base_view.data.root, &pool, &roundtrip);

    try std.testing.expectEqual(@as(usize, 2), roundtrip.items.len);
    try std.testing.expectEqual(checkpoints[0].epoch, roundtrip.items[0].epoch);
    try std.testing.expectEqual(checkpoints[1].epoch, roundtrip.items[1].epoch);
}

test "TreeView composite list sliceFrom returns suffix" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    const ListType = ssz.FixedListType(Checkpoint, 16);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);

    const checkpoints = [_]Checkpoint.Type{
        .{ .epoch = 5, .root = [_]u8{5} ** 32 },
        .{ .epoch = 6, .root = [_]u8{6} ** 32 },
        .{ .epoch = 7, .root = [_]u8{7} ** 32 },
        .{ .epoch = 8, .root = [_]u8{8} ** 32 },
    };
    try list.appendSlice(allocator, &checkpoints);

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    var suffix = try view.sliceFrom(2);
    defer suffix.deinit();

    try std.testing.expectEqual(@as(usize, 2), try suffix.length());

    var roundtrip: ListType.Type = .empty;
    defer roundtrip.deinit(allocator);
    try ListType.tree.toValue(allocator, suffix.base_view.data.root, &pool, &roundtrip);

    try std.testing.expectEqual(@as(usize, 2), roundtrip.items.len);
    try std.testing.expectEqual(checkpoints[2].epoch, roundtrip.items[0].epoch);
    try std.testing.expectEqual(checkpoints[3].epoch, roundtrip.items[1].epoch);

    var empty_suffix = try view.sliceFrom(10);
    defer empty_suffix.deinit();
    try std.testing.expectEqual(@as(usize, 0), try empty_suffix.length());
}

// Refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/listComposite/tree.test.ts#L209-L229
test "TreeView composite list sliceFrom handles boundary conditions" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const ListType = ssz.FixedListType(Checkpoint, 1024);
    const list_length = 16;

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);

    var values: [list_length]Checkpoint.Type = undefined;
    for (&values, 0..) |*value, idx| {
        value.* = Checkpoint.Type{
            .epoch = @intCast(idx),
            .root = [_]u8{@as(u8, @intCast(idx))} ** 32,
        };
    }
    try list.appendSlice(allocator, values[0..list_length]);

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    const min_index: i32 = -@as(i32, list_length) - 1;
    const max_index: i32 = @as(i32, list_length) + 1;
    const signed_len = std.math.cast(i32, list_length) orelse @panic("slice length exceeds i32 range");

    var i = min_index;
    while (i < max_index) : (i += 1) {
        var start_i32 = i;
        if (start_i32 < 0) {
            start_i32 = signed_len + start_i32;
        }
        start_i32 = std.math.clamp(start_i32, 0, signed_len);
        const start_index: usize = @intCast(start_i32);
        const expected_len = list_length - start_index;

        {
            var sliced = try view.sliceFrom(start_index);
            defer sliced.deinit();

            try std.testing.expectEqual(expected_len, try sliced.length());

            var actual: ListType.Type = .empty;
            defer actual.deinit(allocator);
            try ListType.tree.toValue(allocator, sliced.base_view.data.root, &pool, &actual);

            var expected: ListType.Type = .empty;
            defer expected.deinit(allocator);
            try expected.appendSlice(allocator, values[start_index..list_length]);

            try std.testing.expectEqual(expected_len, actual.items.len);
            try std.testing.expectEqual(expected_len, expected.items.len);

            for (expected.items, 0..) |item, idx_item| {
                try std.testing.expectEqual(item.epoch, actual.items[idx_item].epoch);
                try std.testing.expectEqualSlices(u8, &item.root, &actual.items[idx_item].root);
            }

            const expected_node = try ListType.tree.fromValue(allocator, &pool, &expected);
            var expected_root: [32]u8 = expected_node.getRoot(&pool).*;
            defer pool.unref(expected_node);

            var actual_root: [32]u8 = undefined;
            try sliced.hashTreeRoot(&actual_root);

            try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
        }
    }
}

test "TreeView composite list push appends element" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 512);
    defer pool.deinit();

    const ListType = ssz.FixedListType(Checkpoint, 8);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);

    const first = Checkpoint.Type{ .epoch = 9, .root = [_]u8{9} ** 32 };
    try list.append(allocator, first);

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    const next_checkpoint = Checkpoint.Type{ .epoch = 10, .root = [_]u8{10} ** 32 };
    const next_node = try Checkpoint.tree.fromValue(&pool, &next_checkpoint);
    var element_view = try Checkpoint.TreeView.init(allocator, &pool, next_node);
    var transferred = false;
    defer if (!transferred) element_view.deinit();

    try view.push(element_view);
    transferred = true;

    try std.testing.expectEqual(@as(usize, 2), try view.length());

    try view.commit();

    var roundtrip: ListType.Type = .empty;
    defer roundtrip.deinit(allocator);
    try ListType.tree.toValue(allocator, view.base_view.data.root, &pool, &roundtrip);

    try std.testing.expectEqual(@as(usize, 2), roundtrip.items.len);
    try std.testing.expectEqual(next_checkpoint.epoch, roundtrip.items[1].epoch);
}

// Refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/listComposite/tree.test.ts#L182-L207
test "TreeView composite list sliceTo matches incremental snapshots" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 2048);
    defer pool.deinit();

    const ListType = ssz.FixedListType(Checkpoint, 1024);
    const total_values: usize = 16;

    var values: [total_values]Checkpoint.Type = undefined;
    for (&values, 0..) |*value, idx| {
        value.* = Checkpoint.Type{
            .epoch = @intCast(idx + 1),
            .root = [_]u8{@as(u8, @intCast(idx + 1))} ** 32,
        };
    }

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, values[0..]);

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ListType.TreeView.init(allocator, &pool, root_node);
    defer view.deinit();

    try view.commit();

    var i: usize = 0;
    while (i < total_values) : (i += 1) {
        var sliced = try view.sliceTo(i);
        defer sliced.deinit();

        const expected_len = i + 1;
        try std.testing.expectEqual(expected_len, try sliced.length());

        var actual: ListType.Type = .empty;
        defer actual.deinit(allocator);
        try ListType.tree.toValue(allocator, sliced.base_view.data.root, &pool, &actual);

        var expected: ListType.Type = .empty;
        defer expected.deinit(allocator);
        try expected.appendSlice(allocator, values[0..expected_len]);

        try std.testing.expectEqual(expected_len, actual.items.len);
        for (expected.items, 0..) |item, idx_item| {
            try std.testing.expectEqual(item.epoch, actual.items[idx_item].epoch);
            try std.testing.expectEqualSlices(u8, &item.root, &actual.items[idx_item].root);
        }

        var expected_root: [32]u8 = undefined;
        try ListType.hashTreeRoot(allocator, &expected, &expected_root);

        var actual_root: [32]u8 = undefined;
        try sliced.hashTreeRoot(&actual_root);

        try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);

        const serialized_len = ListType.serializedSize(&expected);
        const expected_bytes = try allocator.alloc(u8, serialized_len);
        defer allocator.free(expected_bytes);
        const actual_bytes = try allocator.alloc(u8, serialized_len);
        defer allocator.free(actual_bytes);

        _ = ListType.serializeIntoBytes(&expected, expected_bytes);
        _ = ListType.serializeIntoBytes(&actual, actual_bytes);

        try std.testing.expectEqualSlices(u8, expected_bytes, actual_bytes);
    }
}
