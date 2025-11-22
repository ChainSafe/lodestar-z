const std = @import("std");
const ssz = @import("ssz");
const Node = @import("persistent_merkle_tree").Node;

const Checkpoint = ssz.FixedContainerType(struct {
    epoch: ssz.UintType(64),
    root: ssz.ByteVectorType(32),
});

test "TreeView container field roundtrip" {
    var pool = try Node.Pool.init(std.testing.allocator, 1000);
    defer pool.deinit();
    const checkpoint: Checkpoint.Type = .{
        .epoch = 42,
        .root = [_]u8{1} ** 32,
    };

    const root_node = try Checkpoint.tree.fromValue(&pool, &checkpoint);
    var cp_view = try ssz.TreeView(Checkpoint).init(std.testing.allocator, &pool, root_node);
    defer cp_view.deinit();

    // get field "epoch"
    try std.testing.expectEqual(42, try cp_view.getField("epoch"));

    // get field "root"
    var root_view = try cp_view.getField("root");
    var root = [_]u8{0} ** 32;
    const RootView = ssz.TreeView(Checkpoint).Field("root");
    try RootView.SszType.tree.toValue(root_view.data.root, &pool, root[0..]);
    try std.testing.expectEqualSlices(u8, ([_]u8{1} ** 32)[0..], root[0..]);

    // modify field "epoch"
    try cp_view.setField("epoch", 100);
    try std.testing.expectEqual(100, try cp_view.getField("epoch"));

    // modify field "root"
    var new_root = [_]u8{2} ** 32;
    const new_root_node = try RootView.SszType.tree.fromValue(&pool, &new_root);
    const new_root_view = try RootView.init(std.testing.allocator, &pool, new_root_node);
    try cp_view.setField("root", new_root_view);

    // confirm "root" has been modified
    root_view = try cp_view.getField("root");
    try RootView.SszType.tree.toValue(root_view.data.root, &pool, root[0..]);
    try std.testing.expectEqualSlices(u8, ([_]u8{2} ** 32)[0..], root[0..]);

    // commit and check hash_tree_root
    try cp_view.commit();
    var htr_from_value: [32]u8 = undefined;
    const expected_checkpoint: Checkpoint.Type = .{
        .epoch = 100,
        .root = [_]u8{2} ** 32,
    };
    try Checkpoint.hashTreeRoot(&expected_checkpoint, &htr_from_value);

    var htr_from_tree: [32]u8 = undefined;
    try cp_view.hashTreeRoot(&htr_from_tree);

    try std.testing.expectEqualSlices(
        u8,
        &htr_from_value,
        &htr_from_tree,
    );
}

test "TreeView vector element roundtrip" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 128);
    defer pool.deinit();

    const Uint64 = ssz.UintType(64);
    const VectorType = ssz.FixedVectorType(Uint64, 4);

    const original: VectorType.Type = [_]u64{ 11, 22, 33, 44 };

    const root_node = try VectorType.tree.fromValue(&pool, &original);
    var view = try ssz.TreeView(VectorType).init(allocator, &pool, root_node);
    defer view.deinit();

    try std.testing.expectEqual(@as(u64, 11), try view.getElement(0));
    try std.testing.expectEqual(@as(u64, 44), try view.getElement(3));

    try view.setElement(1, 77);
    try view.setElement(2, 88);

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
    try VectorType.tree.toValue(view.data.root, &pool, &roundtrip);
    try std.testing.expectEqualSlices(u64, &expected, &roundtrip);
}

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
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
    defer view.deinit();

    try std.testing.expectEqual(@as(u32, 5), try view.getElement(0));
    try std.testing.expectEqual(@as(u32, 45), try view.getElement(4));

    try view.setElement(2, 99);
    try view.setElement(4, 123);

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
    try ListType.tree.toValue(allocator, view.data.root, &pool, &roundtrip);
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
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
    defer view.deinit();

    try std.testing.expectEqual(@as(usize, 3), try view.getLength());

    try view.push(@as(u32, 55));

    try std.testing.expectEqual(@as(usize, 4), try view.getLength());
    try std.testing.expectEqual(@as(u32, 55), try view.getElement(3));

    try view.commit();

    try std.testing.expectEqual(@as(usize, 4), try view.getLength());

    var expected: ListType.Type = .empty;
    defer expected.deinit(allocator);
    try expected.appendSlice(allocator, &[_]u32{ 1, 2, 3, 55 });

    var expected_root: [32]u8 = undefined;
    try ListType.hashTreeRoot(allocator, &expected, &expected_root);

    var actual_root: [32]u8 = undefined;
    try view.hashTreeRoot(&actual_root);

    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
}

test "TreeView vector getAllElements fills provided buffer" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const VectorType = ssz.FixedVectorType(Uint32, 8);

    const values = [_]u32{ 9, 8, 7, 6, 5, 4, 3, 2 };
    const root_node = try VectorType.tree.fromValue(&pool, &values);
    var view = try ssz.TreeView(VectorType).init(allocator, &pool, root_node);
    defer view.deinit();

    const out = try allocator.alloc(u32, values.len);
    defer allocator.free(out);

    const filled = try view.getAllElements(out);
    try std.testing.expectEqual(out.ptr, filled.ptr);
    try std.testing.expectEqual(out.len, filled.len);
    try std.testing.expectEqualSlices(u32, values[0..], filled);

    const wrong = try allocator.alloc(u32, values.len - 1);
    defer allocator.free(wrong);
    try std.testing.expectError(error.InvalidSize, view.getAllElements(wrong));
}

test "TreeView vector getAllElementsAlloc roundtrip" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint16 = ssz.UintType(16);
    const VectorType = ssz.FixedVectorType(Uint16, 5);
    const values = [_]u16{ 3, 1, 4, 1, 5 };

    const root_node = try VectorType.tree.fromValue(&pool, &values);
    var view = try ssz.TreeView(VectorType).init(allocator, &pool, root_node);
    defer view.deinit();

    const filled = try view.getAllElementsAlloc(allocator);
    defer allocator.free(filled);

    try std.testing.expectEqualSlices(u16, values[0..], filled);
}

test "TreeView vector getAllElementsAlloc repeat reflects updates" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const Uint32 = ssz.UintType(32);
    const VectorType = ssz.FixedVectorType(Uint32, 6);
    var values = [_]u32{ 10, 20, 30, 40, 50, 60 };

    const root_node = try VectorType.tree.fromValue(&pool, &values);
    var view = try ssz.TreeView(VectorType).init(allocator, &pool, root_node);
    defer view.deinit();

    const first = try view.getAllElementsAlloc(allocator);
    defer allocator.free(first);
    try std.testing.expectEqualSlices(u32, values[0..], first);

    try view.setElement(3, 99);

    const second = try view.getAllElementsAlloc(allocator);
    defer allocator.free(second);
    values[3] = 99;
    try std.testing.expectEqualSlices(u32, values[0..], second);
}

test "TreeView list getAllElementsAlloc handles zero length" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();

    const Uint8 = ssz.UintType(8);
    const ListType = ssz.FixedListType(Uint8, 4);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);

    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
    defer view.deinit();

    const filled = try view.getAllElementsAlloc(allocator);
    defer allocator.free(filled);

    try std.testing.expectEqual(@as(usize, 0), filled.len);
}

test "TreeView list getAllElementsAlloc spans multiple chunks" {
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
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
    defer view.deinit();

    const filled = try view.getAllElementsAlloc(allocator);
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
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
    defer view.deinit();

    try view.push(@as(u32, 5));
    try view.push(@as(u32, 6));
    try view.push(@as(u32, 7));
    try view.push(@as(u32, 8));
    try view.push(@as(u32, 9));

    try std.testing.expectEqual(@as(usize, 9), try view.getLength());
    try std.testing.expectEqual(@as(u32, 9), try view.getElement(8));

    try view.commit();

    try std.testing.expectEqual(@as(usize, 9), try view.getLength());
    try std.testing.expectEqual(@as(u32, 9), try view.getElement(8));

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
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
    defer view.deinit();

    const initial = try view.getAllElementsAlloc(allocator);
    defer allocator.free(initial);
    try std.testing.expectEqual(@as(usize, 8), initial.len);

    try view.push(@as(u32, 8));
    try view.push(@as(u32, 9));

    try std.testing.expectEqual(@as(usize, 10), try view.getLength());
    try std.testing.expectEqual(@as(u32, 9), try view.getElement(9));

    const filled = try view.getAllElementsAlloc(allocator);
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
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
    defer view.deinit();

    try std.testing.expectError(error.LengthOverLimit, view.push(@as(u32, 3)));
    try std.testing.expectEqual(@as(usize, 2), try view.getLength());
}

// Refer to https://github.com/ChainSafe/ssz/blob/7f5580c2ea69f9307300ddb6010a8bc7ce2fc471/packages/ssz/test/unit/byType/listBasic/tree.test.ts#L180-L203
test "TreeView basic list getAllElements reflects pushes" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256);
    defer pool.deinit();

    const list_limit = 32;
    const Uint64 = ssz.UintType(64);
    const ListType = ssz.FixedListType(Uint64, list_limit);

    var list: ListType.Type = .empty;
    defer list.deinit(allocator);
    const root_node = try ListType.tree.fromValue(allocator, &pool, &list);
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
    defer view.deinit();

    var expected: [list_limit]u64 = undefined;
    for (&expected, 0..) |*slot, idx| {
        slot.* = @intCast(idx);
    }

    for (expected, 0..) |value, idx| {
        try view.push(value);
        try std.testing.expectEqual(value, try view.getElement(idx));
    }

    try std.testing.expectError(error.LengthOverLimit, view.push(@intCast(list_limit)));

    for (expected, 0..) |value, idx| {
        try std.testing.expectEqual(value, try view.getElement(idx));
    }

    try view.commit();
    const filled = try view.getAllElementsAlloc(allocator);
    defer allocator.free(filled);
    try std.testing.expectEqualSlices(u64, expected[0..], filled);
}

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
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
    defer view.deinit();

    var sliced = try view.sliceTo(1);
    defer sliced.deinit();

    try std.testing.expectEqual(@as(usize, 2), try sliced.getLength());

    var roundtrip: ListType.Type = .empty;
    defer roundtrip.deinit(allocator);
    try ListType.tree.toValue(allocator, sliced.data.root, &pool, &roundtrip);

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
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
    defer view.deinit();

    var suffix = try view.sliceFrom(2);
    defer suffix.deinit();

    try std.testing.expectEqual(@as(usize, 2), try suffix.getLength());

    var roundtrip: ListType.Type = .empty;
    defer roundtrip.deinit(allocator);
    try ListType.tree.toValue(allocator, suffix.data.root, &pool, &roundtrip);

    try std.testing.expectEqual(@as(usize, 2), roundtrip.items.len);
    try std.testing.expectEqual(checkpoints[2].epoch, roundtrip.items[0].epoch);
    try std.testing.expectEqual(checkpoints[3].epoch, roundtrip.items[1].epoch);

    var empty_suffix = try view.sliceFrom(10);
    defer empty_suffix.deinit();
    try std.testing.expectEqual(@as(usize, 0), try empty_suffix.getLength());
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
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
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

            try std.testing.expectEqual(expected_len, try sliced.getLength());

            var actual: ListType.Type = .empty;
            defer actual.deinit(allocator);
            try ListType.tree.toValue(allocator, sliced.data.root, &pool, &actual);

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
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
    defer view.deinit();

    const next_checkpoint = Checkpoint.Type{ .epoch = 10, .root = [_]u8{10} ** 32 };
    const next_node = try Checkpoint.tree.fromValue(&pool, &next_checkpoint);
    var element_view = try ssz.TreeView(Checkpoint).init(allocator, &pool, next_node);
    var transferred = false;
    defer if (!transferred) element_view.deinit();

    try view.push(element_view);
    transferred = true;

    try std.testing.expectEqual(@as(usize, 2), try view.getLength());

    try view.commit();

    var roundtrip: ListType.Type = .empty;
    defer roundtrip.deinit(allocator);
    try ListType.tree.toValue(allocator, view.data.root, &pool, &roundtrip);

    try std.testing.expectEqual(@as(usize, 2), roundtrip.items.len);
    try std.testing.expectEqual(next_checkpoint.epoch, roundtrip.items[1].epoch);
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
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
    defer view.deinit();

    try view.commit();

    var sliced = try view.sliceTo(100);
    defer sliced.deinit();

    try std.testing.expectEqual(try view.getLength(), try sliced.getLength());

    var expected_root: [32]u8 = undefined;
    try ListType.hashTreeRoot(allocator, &list, &expected_root);

    var actual_root: [32]u8 = undefined;
    try sliced.hashTreeRoot(&actual_root);

    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);
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
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
    defer view.deinit();

    try view.commit();

    // The TypeScript test also exercises index -1 to capture the empty snapshot. Since the Zig API
    // uses unsigned indexes, we exercise the zero-length case by operating on an empty view in other
    // tests and cover the incremental prefixes here.
    var i: usize = 0;
    while (i < total_values) : (i += 1) {
        var sliced = try view.sliceTo(i);
        defer sliced.deinit();

        const expected_len = i + 1;
        try std.testing.expectEqual(expected_len, try sliced.getLength());

        var actual: ListType.Type = .empty;
        defer actual.deinit(allocator);
        try ListType.tree.toValue(allocator, sliced.data.root, &pool, &actual);

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
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
    defer view.deinit();

    for (base_values) |value| {
        try view.push(value);
    }
    try view.commit();

    for (base_values, 0..) |_, idx| {
        var sliced = try view.sliceTo(idx);
        defer sliced.deinit();

        const expected_len = idx + 1;
        try std.testing.expectEqual(expected_len, try sliced.getLength());

        var expected: ListType.Type = .empty;
        defer expected.deinit(allocator);
        try expected.appendSlice(allocator, base_values[0..expected_len]);

        var actual: ListType.Type = .empty;
        defer actual.deinit(allocator);
        try ListType.tree.toValue(allocator, sliced.data.root, &pool, &actual);

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
    var view = try ssz.TreeView(ListType).init(allocator, &pool, root_node);
    defer view.deinit();

    try view.commit();

    var sliced = try view.sliceTo(2);
    defer sliced.deinit();

    try std.testing.expectEqual(@as(usize, 3), try sliced.getLength());

    const filled = try sliced.getAllElementsAlloc(allocator);
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
