const std = @import("std");
const ssz = @import("ssz");
const Node = @import("persistent_merkle_tree").Node;

test "BitVectorTreeView get/set roundtrip" {
    const allocator = std.testing.allocator;
    const Bits = ssz.BitVectorType(44);

    var pool = try Node.Pool.init(allocator, 2048);
    defer pool.deinit();

    var expected: Bits.Type = Bits.default_value;
    try expected.set(1, true);
    try expected.set(7, true);
    try expected.set(31, true);
    try expected.set(Bits.length - 1, true);

    const root = try Bits.tree.fromValue(&pool, &expected);
    var view = try Bits.TreeView.init(allocator, &pool, root);
    defer view.deinit();

    for (0..Bits.length) |i| {
        try std.testing.expectEqual(try expected.get(i), try view.get(i));
    }

    try view.set(0, true);
    try view.set(7, false);
    try view.set(12, true);

    try expected.set(0, true);
    try expected.set(7, false);
    try expected.set(12, true);

    var expected_root: [32]u8 = undefined;
    var view_root: [32]u8 = undefined;
    try Bits.hashTreeRoot(&expected, &expected_root);
    try view.hashTreeRoot(&view_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &view_root);
}

test "BitVectorTreeView toBoolArray roundtrip" {
    const allocator = std.testing.allocator;
    const Bits = ssz.BitVectorType(16);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const expected_bools = [_]bool{ true, false, true, true, false, true, false, true, true, false, true, true, false, false, true, false };
    const value = try Bits.Type.fromBoolArray(expected_bools);

    const root = try Bits.tree.fromValue(&pool, &value);
    var view = try Bits.TreeView.init(allocator, &pool, root);
    defer view.deinit();

    const actual_bools = try view.toBoolArray(allocator);
    defer allocator.free(actual_bools);
    try std.testing.expectEqualSlices(bool, &expected_bools, actual_bools);
}

test "BitVectorTreeView toBoolArrayInto roundtrip" {
    const allocator = std.testing.allocator;
    const Bits = ssz.BitVectorType(12);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const expected_bools = [_]bool{ true, false, true, true, false, true, false, true, true, false, true, true };
    const value = try Bits.Type.fromBoolArray(expected_bools);

    const root = try Bits.tree.fromValue(&pool, &value);
    var view = try Bits.TreeView.init(allocator, &pool, root);
    defer view.deinit();

    var out: [Bits.length]bool = undefined;
    try view.toBoolArrayInto(&out);
    try std.testing.expectEqualSlices(bool, &expected_bools, &out);
}

test "BitVectorTreeView set reflects in toBoolArray" {
    const allocator = std.testing.allocator;
    const Bits = ssz.BitVectorType(8);

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const initial_bools = [_]bool{ false, false, false, false, false, false, false, false };
    const value = try Bits.Type.fromBoolArray(initial_bools);

    const root = try Bits.tree.fromValue(&pool, &value);
    var view = try Bits.TreeView.init(allocator, &pool, root);
    defer view.deinit();

    try view.set(0, true);
    try view.set(3, true);
    try view.set(7, true);

    const expected_bools = [_]bool{ true, false, false, true, false, false, false, true };
    const actual_bools = try view.toBoolArray(allocator);
    defer allocator.free(actual_bools);
    try std.testing.expectEqualSlices(bool, &expected_bools, actual_bools);
}

test "BitVectorTreeView multi-chunk" {
    const allocator = std.testing.allocator;
    // 300 bits requires 2 chunks (256 bits per chunk)
    const Bits = ssz.BitVectorType(300);

    var pool = try Node.Pool.init(allocator, 4096);
    defer pool.deinit();

    var value: Bits.Type = Bits.default_value;
    try value.set(0, true);
    try value.set(255, true); // last bit of first chunk
    try value.set(256, true); // first bit of second chunk
    try value.set(299, true); // last bit

    const root = try Bits.tree.fromValue(&pool, &value);
    var view = try Bits.TreeView.init(allocator, &pool, root);
    defer view.deinit();

    try std.testing.expect(try view.get(0));
    try std.testing.expect(try view.get(255));
    try std.testing.expect(try view.get(256));
    try std.testing.expect(try view.get(299));
    try std.testing.expect(!try view.get(1));
    try std.testing.expect(!try view.get(254));

    try view.set(255, false);
    try view.set(256, false);
    try view.set(128, true);
    try view.set(280, true);

    try std.testing.expect(!try view.get(255));
    try std.testing.expect(!try view.get(256));
    try std.testing.expect(try view.get(128));
    try std.testing.expect(try view.get(280));

    try value.set(255, false);
    try value.set(256, false);
    try value.set(128, true);
    try value.set(280, true);

    var expected_root: [32]u8 = undefined;
    var view_root: [32]u8 = undefined;
    try Bits.hashTreeRoot(&value, &expected_root);
    try view.hashTreeRoot(&view_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &view_root);
}

test "BitVectorTreeView remainder edge cases (1 and 255)" {
    const allocator = std.testing.allocator;

    inline for ([_]usize{ 257, 511 }) |len| {
        const Bits = ssz.BitVectorType(len);

        var pool = try Node.Pool.init(allocator, 4096);
        defer pool.deinit();

        var value: Bits.Type = Bits.default_value;
        try value.set(0, true);
        try value.set(255, true);
        try value.set(256, true);
        try value.set(len - 1, true);

        const root = try Bits.tree.fromValue(&pool, &value);
        var view = try Bits.TreeView.init(allocator, &pool, root);
        defer view.deinit();

        const bools = try view.toBoolArray(allocator);
        defer allocator.free(bools);
        try std.testing.expectEqual(len, bools.len);

        try std.testing.expect(bools[0]);
        try std.testing.expect(bools[255]);
        try std.testing.expect(bools[256]);
        try std.testing.expect(bools[len - 1]);

        if (len > 2) try std.testing.expect(!bools[1]);
        if (len > 258) try std.testing.expect(!bools[257]);
    }
}

test "BitVectorTreeView full-chunk edge cases (remainder=0)" {
    const allocator = std.testing.allocator;

    inline for ([_]usize{ 256, 512 }) |len| {
        const Bits = ssz.BitVectorType(len);

        var pool = try Node.Pool.init(allocator, 4096);
        defer pool.deinit();

        var value: Bits.Type = Bits.default_value;
        try value.set(0, true);
        try value.set(255, true);
        if (len > 256) {
            try value.set(256, true);
            try value.set(511, true);
        }

        const root = try Bits.tree.fromValue(&pool, &value);
        var view = try Bits.TreeView.init(allocator, &pool, root);
        defer view.deinit();

        const bools = try view.toBoolArray(allocator);
        defer allocator.free(bools);
        try std.testing.expectEqual(len, bools.len);

        try std.testing.expect(bools[0]);
        try std.testing.expect(bools[255]);
        if (len > 256) {
            try std.testing.expect(bools[256]);
            try std.testing.expect(bools[511]);
        }

        if (len > 2) try std.testing.expect(!bools[1]);
        if (len > 258) try std.testing.expect(!bools[257]);
    }
}
