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

test "TreeView list of list commits inner length updates" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const Bytes = ssz.ByteListType(32);
    const Numbers = ssz.FixedListType(Uint32, 8);
    const Vec2 = ssz.FixedVectorType(Uint32, 2);
    const InnerElement = ssz.VariableContainerType(struct {
        id: Uint32,
        payload: Bytes,
        numbers: Numbers,
        vec: Vec2,
    });
    const InnerListType = ssz.VariableListType(InnerElement, 16);
    const OuterListType = ssz.VariableListType(InnerListType, 8);

    var outer_value: OuterListType.Type = .empty;
    defer OuterListType.deinit(allocator, &outer_value);
    const outer_root = try OuterListType.tree.fromValue(allocator, &pool, &outer_value);
    var outer_view = try OuterListType.TreeView.init(allocator, &pool, outer_root);
    defer outer_view.deinit();

    var inner_value: InnerListType.Type = .empty;
    defer InnerListType.deinit(allocator, &inner_value);
    const inner_root = try InnerListType.tree.fromValue(allocator, &pool, &inner_value);
    var inner_view = try InnerListType.TreeView.init(allocator, &pool, inner_root);
    var transferred = false;
    defer if (!transferred) inner_view.deinit();

    var e1_value: InnerElement.Type = InnerElement.default_value;
    defer InnerElement.deinit(allocator, &e1_value);
    const e1_root = try InnerElement.tree.fromValue(allocator, &pool, &e1_value);
    var e1_view: ?InnerElement.TreeView = try InnerElement.TreeView.init(allocator, &pool, e1_root);
    defer if (e1_view) |*view| view.deinit();
    const e1 = &e1_view.?;

    try e1.set("id", @as(u32, 11));

    // payload: ByteListType (list_basic) -> push + set + getAll + getAllInto
    var payload_value: Bytes.Type = Bytes.default_value;
    defer payload_value.deinit(allocator);
    const payload_root = try Bytes.tree.fromValue(allocator, &pool, &payload_value);
    var payload_view: ?Bytes.TreeView = try Bytes.TreeView.init(allocator, &pool, payload_root);
    defer if (payload_view) |*view| view.deinit();
    const payload = &payload_view.?;

    try payload.push(@as(u8, 0xAA));
    try payload.push(@as(u8, 0xAB));
    try payload.set(1, @as(u8, 0xAC));
    {
        const all = try payload.getAll(allocator);
        defer allocator.free(all);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xAC }, all);

        var buf: [2]u8 = undefined;
        _ = try payload.getAllInto(buf[0..]);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xAC }, buf[0..]);
    }

    try e1.set("payload", payload_view.?);
    payload_view = null;

    var numbers_value: Numbers.Type = .empty;
    defer numbers_value.deinit(allocator);
    const numbers_root = try Numbers.tree.fromValue(allocator, &pool, &numbers_value);
    var numbers_view: ?Numbers.TreeView = try Numbers.TreeView.init(allocator, &pool, numbers_root);
    defer if (numbers_view) |*view| view.deinit();
    const numbers = &numbers_view.?;

    try numbers.push(@as(u32, 1));
    try numbers.push(@as(u32, 2));
    try numbers.set(0, @as(u32, 3));
    {
        const all = try numbers.getAll(allocator);
        defer allocator.free(all);
        try std.testing.expectEqual(@as(usize, 2), all.len);
        try std.testing.expectEqual(@as(u32, 3), all[0]);
        try std.testing.expectEqual(@as(u32, 2), all[1]);

        var buf: [2]u32 = undefined;
        _ = try numbers.getAllInto(buf[0..]);
        try std.testing.expectEqual(@as(u32, 3), buf[0]);
        try std.testing.expectEqual(@as(u32, 2), buf[1]);
    }

    try e1.set("numbers", numbers_view.?);
    numbers_view = null;

    var vec_value: Vec2.Type = [_]u32{ 0, 0 };
    const vec_root = try Vec2.tree.fromValue(&pool, &vec_value);
    var vec_view: ?Vec2.TreeView = try Vec2.TreeView.init(allocator, &pool, vec_root);
    defer if (vec_view) |*view| view.deinit();
    const vec = &vec_view.?;

    try vec.set(0, @as(u32, 9));
    try vec.set(1, @as(u32, 10));
    {
        const all = try vec.getAll(allocator);
        defer allocator.free(all);
        try std.testing.expectEqual(@as(usize, 2), all.len);
        try std.testing.expectEqual(@as(u32, 9), all[0]);
        try std.testing.expectEqual(@as(u32, 10), all[1]);

        var buf: [2]u32 = undefined;
        _ = try vec.getAllInto(buf[0..]);
        try std.testing.expectEqual(@as(u32, 9), buf[0]);
        try std.testing.expectEqual(@as(u32, 10), buf[1]);
    }

    try e1.set("vec", vec_view.?);
    vec_view = null;

    try inner_view.push(e1_view.?);
    e1_view = null;

    var e2_value: InnerElement.Type = InnerElement.default_value;
    defer InnerElement.deinit(allocator, &e2_value);
    const e2_root = try InnerElement.tree.fromValue(allocator, &pool, &e2_value);
    var e2_view: ?InnerElement.TreeView = try InnerElement.TreeView.init(allocator, &pool, e2_root);
    defer if (e2_view) |*view| view.deinit();
    const e2 = &e2_view.?;

    try e2.set("id", @as(u32, 22));

    var e2_payload_value: Bytes.Type = Bytes.default_value;
    defer e2_payload_value.deinit(allocator);
    const e2_payload_root = try Bytes.tree.fromValue(allocator, &pool, &e2_payload_value);
    var e2_payload_view: ?Bytes.TreeView = try Bytes.TreeView.init(allocator, &pool, e2_payload_root);
    defer if (e2_payload_view) |*view| view.deinit();
    const e2_payload = &e2_payload_view.?;
    try e2_payload.push(@as(u8, 0xBB));
    try e2.set("payload", e2_payload_view.?);
    e2_payload_view = null;

    try inner_view.push(e2_view.?);
    e2_view = null;

    {
        var e3_value: InnerElement.Type = InnerElement.default_value;
        defer InnerElement.deinit(allocator, &e3_value);
        const e3_root = try InnerElement.tree.fromValue(allocator, &pool, &e3_value);
        var e3_view: ?InnerElement.TreeView = try InnerElement.TreeView.init(allocator, &pool, e3_root);
        defer if (e3_view) |*view| view.deinit();
        const e3 = &e3_view.?;
        try e3.set("id", @as(u32, 33));
        try inner_view.set(1, e3_view.?);
        e3_view = null;
    }

    try std.testing.expectEqual(@as(usize, 2), try inner_view.length());

    try outer_view.push(inner_view);
    transferred = true;

    try outer_view.commit();

    // Roundtrip and verify nested lengths and values.
    var roundtrip: OuterListType.Type = .empty;
    defer OuterListType.deinit(allocator, &roundtrip);
    try OuterListType.tree.toValue(allocator, outer_view.base_view.data.root, &pool, &roundtrip);

    try std.testing.expectEqual(@as(usize, 1), roundtrip.items.len);
    try std.testing.expectEqual(@as(usize, 2), roundtrip.items[0].items.len);
    try std.testing.expectEqual(@as(u32, 11), roundtrip.items[0].items[0].id);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xAC }, roundtrip.items[0].items[0].payload.items);
    try std.testing.expectEqual(@as(usize, 2), roundtrip.items[0].items[0].numbers.items.len);
    try std.testing.expectEqual(@as(u32, 3), roundtrip.items[0].items[0].numbers.items[0]);
    try std.testing.expectEqual(@as(u32, 2), roundtrip.items[0].items[0].numbers.items[1]);
    try std.testing.expectEqual(@as(u32, 9), roundtrip.items[0].items[0].vec[0]);
    try std.testing.expectEqual(@as(u32, 10), roundtrip.items[0].items[0].vec[1]);

    try std.testing.expectEqual(@as(u32, 33), roundtrip.items[0].items[1].id);
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
