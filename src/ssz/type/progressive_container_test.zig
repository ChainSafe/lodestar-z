//! Tests for `progressive_container.zig`.

const std = @import("std");
const Node = @import("persistent_merkle_tree").Node;
const BoolType = @import("bool.zig").BoolType;
const ByteVectorType = @import("byte_vector.zig").ByteVectorType;
const FixedProgressiveListType = @import("progressive_list.zig").FixedProgressiveListType;
const UintType = @import("uint.zig").UintType;
const FixedListType = @import("list.zig").FixedListType;
const FixedProgressiveContainerType = @import("progressive_container.zig").FixedProgressiveContainerType;
const VariableProgressiveContainerType = @import("progressive_container.zig").VariableProgressiveContainerType;

test "ProgressiveContainerType " {
    // Square with active_fields=[1, 0, 1]
    const Square = FixedProgressiveContainerType(struct {
        side: UintType(16),
        color: UintType(8),
    }, &[_]u1{ 1, 0, 1 });

    // Circle with active_fields=[0, 1, 1]
    const Circle = FixedProgressiveContainerType(struct {
        radius: UintType(16),
        color: UintType(8),
    }, &[_]u1{ 0, 1, 1 });

    var square: Square.Type = undefined;
    square.side = 10;
    square.color = 5;

    var circle: Circle.Type = undefined;
    circle.radius = 7;
    circle.color = 5;

    // Test that both serialize correctly
    var square_buf: [Square.fixed_size]u8 = undefined;
    _ = Square.serializeIntoBytes(&square, &square_buf);

    var circle_buf: [Circle.fixed_size]u8 = undefined;
    _ = Circle.serializeIntoBytes(&circle, &circle_buf);

    // Test deserialization
    var square2: Square.Type = undefined;
    try Square.deserializeFromBytes(&square_buf, &square2);
    try std.testing.expectEqual(square.side, square2.side);
    try std.testing.expectEqual(square.color, square2.color);

    // Test hash tree root - color should be at the same gindex for both
    var square_root: [32]u8 = undefined;
    try Square.hashTreeRoot(&square, &square_root);

    var circle_root: [32]u8 = undefined;
    try Circle.hashTreeRoot(&circle, &circle_root);

    // The roots should be different since the structures are different
    try std.testing.expect(!std.mem.eql(u8, &square_root, &circle_root));
}

test "ProgressiveContainerType - variable" {
    const allocator = std.testing.allocator;
    const Foo = VariableProgressiveContainerType(struct {
        a: FixedListType(UintType(8), 32, .{}),
        b: FixedListType(UintType(8), 32, .{}),
        c: FixedListType(UintType(8), 32, .{}),
    }, &[_]u1{ 1, 1, 0, 1 });

    var f: Foo.Type = undefined;
    f.a = try std.ArrayList(u8).initCapacity(allocator, 10);
    f.b = try std.ArrayList(u8).initCapacity(allocator, 10);
    f.c = try std.ArrayList(u8).initCapacity(allocator, 10);
    defer f.a.deinit(allocator);
    defer f.b.deinit(allocator);
    defer f.c.deinit(allocator);
    f.a.expandToCapacity();
    f.b.expandToCapacity();
    f.c.expandToCapacity();

    const f_buf = try allocator.alloc(u8, Foo.serializedSize(&f));
    defer allocator.free(f_buf);
    _ = Foo.serializeIntoBytes(&f, f_buf);

    var f2: Foo.Type = Foo.default_value;
    try Foo.deserializeFromBytes(allocator, f_buf, &f2);
    defer Foo.deinit(allocator, &f2);
}

fn expectProgressiveFromValuePoolExhaustionReclaimsNodes(
    comptime ST: type,
    value: *const ST.Type,
    max_available_nodes: usize,
) !void {
    var saw_failure = false;

    // Start with no room and add one slot per attempt. This walks each partial build until the
    // first capacity that can finish the value.
    for (0..max_available_nodes + 1) |available_nodes| {
        var pool = try Node.Pool.init(.{
            .page_allocator = std.testing.allocator,
            .allocator = std.testing.allocator,
            .pool_size = @intCast(available_nodes),
        });
        defer pool.deinit();

        const baseline = pool.getNodesInUse();
        const root = ST.tree.fromValue(&pool, value) catch |err| {
            try std.testing.expectEqual(error.PoolExhausted, err);
            try std.testing.expectEqual(baseline, pool.getNodesInUse());
            saw_failure = true;
            continue;
        };
        pool.unref(root);
        try std.testing.expectEqual(baseline, pool.getNodesInUse());
        try std.testing.expect(saw_failure);
        return;
    }
    return error.TestUnexpectedResult;
}

test "memory_safety: progressive container tree.fromValue reclaims unpublished nodes on pool exhaustion" {
    const Container = FixedProgressiveContainerType(struct {
        a: UintType(64),
        b: ByteVectorType(32),
    }, &.{ 1, 1 });
    const value: Container.Type = .{ .a = 1, .b = [_]u8{2} ** 32 };

    try expectProgressiveFromValuePoolExhaustionReclaimsNodes(Container, &value, 32);
}

test "memory_safety: nested progressive tree.fromValue reclaims unpublished nodes on pool exhaustion" {
    const Items = FixedProgressiveListType(UintType(8));
    const Container = VariableProgressiveContainerType(struct {
        a: UintType(64),
        items: Items,
    }, &.{ 1, 1 });

    var value = Container.default_value;
    defer Container.deinit(std.testing.allocator, &value);
    try value.items.append(std.testing.allocator, 1);

    try expectProgressiveFromValuePoolExhaustionReclaimsNodes(Container, &value, 32);
}

test "memory_safety: variable progressive container clone preserves out on OOM" {
    const Items = FixedListType(UintType(8), 8, .{});
    const Container = VariableProgressiveContainerType(struct {
        a: Items,
        b: Items,
    }, &.{ 1, 1 });

    var value = Container.default_value;
    defer Container.deinit(std.testing.allocator, &value);
    try value.a.append(std.testing.allocator, 1);
    try value.b.append(std.testing.allocator, 2);

    var out = Container.default_value;
    defer Container.deinit(std.testing.allocator, &out);
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });

    try std.testing.expectError(
        error.OutOfMemory,
        Container.clone(failing.allocator(), &value, &out),
    );
    try std.testing.expectEqual(@as(usize, 0), out.a.items.len);
    try std.testing.expectEqual(@as(usize, 0), out.b.items.len);
}

test "memory_safety: fixed progressive container byte deserialization preserves out on malformed input" {
    const Container = FixedProgressiveContainerType(struct {
        a: BoolType(),
        b: BoolType(),
    }, &.{ 1, 1 });
    var out: Container.Type = .{ .a = false, .b = false };

    try std.testing.expectError(
        error.invalidBoolean,
        Container.deserializeFromBytes(&.{ 1, 2 }, &out),
    );
    try std.testing.expect(!out.a);
    try std.testing.expect(!out.b);
}

test "memory_safety: variable progressive container byte deserialization preserves out on malformed input" {
    const Items = FixedProgressiveListType(BoolType());
    const Container = VariableProgressiveContainerType(struct {
        a: UintType(8),
        items: Items,
    }, &.{ 1, 1 });
    var out = Container.default_value;
    defer Container.deinit(std.testing.allocator, &out);
    out.a = 7;
    try out.items.appendSlice(std.testing.allocator, &.{ false, false });

    try std.testing.expectError(
        error.invalidBoolean,
        Container.deserializeFromBytes(
            std.testing.allocator,
            &.{ 9, 5, 0, 0, 0, 1, 2 },
            &out,
        ),
    );
    try std.testing.expectEqual(@as(u8, 7), out.a);
    try std.testing.expectEqualSlices(bool, &.{ false, false }, out.items.items);
}

test "progressive container hashing streams sparse fields without allocation" {
    const allocator = std.testing.allocator;
    const active = comptime blk: {
        var flags: [256]u1 = @splat(0);
        flags[0] = 1;
        flags[85] = 1;
        flags[255] = 1;
        break :blk flags;
    };
    const Fixed = FixedProgressiveContainerType(struct { a: UintType(64), b: BoolType(), c: UintType(8) }, &active);
    const Variable = VariableProgressiveContainerType(struct { a: UintType(64), b: FixedListType(UintType(8), 32, .{}), c: UintType(8) }, &active);
    inline for (.{ Fixed, Variable }) |ST| {
        var value = ST.default_value;
        defer if (ST == Variable) ST.deinit(allocator, &value);
        value.a = 123;
        value.c = 45;
        if (ST == Fixed) value.b = true else try value.b.appendSlice(allocator, &.{ 2, 3, 4 });
        var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 2048 });
        defer pool.deinit();
        const root = try ST.tree.fromValue(&pool, &value);
        defer pool.unref(root);
        const bytes = try allocator.alloc(u8, ST.serializedSize(&value));
        defer allocator.free(bytes);
        _ = ST.serializeIntoBytes(&value, bytes);
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        var actual: [32]u8 = undefined;
        if (ST == Fixed) try ST.hashTreeRoot(&value, &actual) else try ST.hashTreeRoot(failing.allocator(), &value, &actual);
        try std.testing.expectEqualSlices(u8, root.getRoot(&pool), &actual);
        if (ST == Fixed) try ST.serialized.hashTreeRoot(bytes, &actual) else try ST.serialized.hashTreeRoot(failing.allocator(), bytes, &actual);
        try std.testing.expectEqualSlices(u8, root.getRoot(&pool), &actual);
        try std.testing.expect(!failing.has_induced_failure);
    }
}

test "progressive container tree reads stream sparse fields" {
    const allocator = std.testing.allocator;
    const active = comptime blk: {
        var flags: [256]u1 = @splat(0);
        flags[0] = 1;
        flags[85] = 1;
        flags[255] = 1;
        break :blk flags;
    };
    const Fixed = FixedProgressiveContainerType(struct { a: UintType(64), b: BoolType(), c: UintType(8) }, &active);
    const Variable = VariableProgressiveContainerType(struct { a: UintType(64), b: FixedProgressiveListType(UintType(8)), c: UintType(8) }, &active);
    inline for (.{ Fixed, Variable }) |ST| {
        var value = ST.default_value;
        defer if (ST == Variable) ST.deinit(allocator, &value);
        value.a = 123;
        value.c = 45;
        if (ST == Fixed) value.b = true else try value.b.appendSlice(allocator, &.{ 2, 3, 4 });
        var failing = std.testing.FailingAllocator.init(allocator, .{});
        var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = failing.allocator(), .pool_size = 2048 });
        defer pool.deinit();
        const root = try ST.tree.fromValue(&pool, &value);
        defer pool.unref(root);
        failing.fail_index = failing.alloc_index;
        var output_allocator = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
        var actual: ST.Type = undefined;
        if (ST == Fixed) try ST.tree.toValue(root, &pool, &actual) else try ST.tree.toValue(output_allocator.allocator(), root, &pool, &actual);
        defer if (ST == Variable) ST.deinit(output_allocator.allocator(), &actual);
        try std.testing.expect(ST.equals(&value, &actual));
        try std.testing.expect(!output_allocator.has_induced_failure);
        const size = ST.serializedSize(&value);
        try std.testing.expectEqual(size, try ST.tree.serializedSize(root, &pool));
        const bytes = try allocator.alloc(u8, size);
        defer allocator.free(bytes);
        const expected = try allocator.alloc(u8, size);
        defer allocator.free(expected);
        _ = ST.serializeIntoBytes(&value, expected);
        try std.testing.expectEqual(size, try ST.tree.serializeIntoBytes(root, &pool, bytes));
        try std.testing.expectEqualSlices(u8, expected, bytes);
        try std.testing.expectError(error.InvalidSize, ST.tree.serializeIntoBytes(root, &pool, bytes[0 .. size - 1]));
        try std.testing.expect(!failing.has_induced_failure);
    }
}

test "memory_safety: progressive container tree.toValue cleans partial values on OOM" {
    const allocator = std.testing.allocator;
    const Container = VariableProgressiveContainerType(struct {
        a: FixedProgressiveListType(UintType(8)),
        b: FixedListType(UintType(8), 8, .{}),
    }, &.{ 1, 0, 1 });
    var source = Container.default_value;
    defer Container.deinit(allocator, &source);
    try source.a.appendSlice(allocator, &.{ 1, 2, 3 });
    try source.b.appendSlice(allocator, &.{ 4, 5 });

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 64 });
    defer pool.deinit();
    const root = try Container.tree.fromValue(&pool, &source);
    defer pool.unref(root);

    var saw_failure = false;
    var saw_success = false;
    for (0..8) |fail_after| {
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_after });
        var out: Container.Type = undefined;
        Container.tree.toValue(failing.allocator(), root, &pool, &out) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            saw_failure = true;
            continue;
        };
        defer Container.deinit(failing.allocator(), &out);
        try std.testing.expect(Container.equals(&source, &out));
        saw_success = true;
        break;
    }
    try std.testing.expect(saw_failure);
    try std.testing.expect(saw_success);
}

test "memory_safety: progressive container tree reads validate terminators before publishing values" {
    const allocator = std.testing.allocator;
    const Fixed = FixedProgressiveContainerType(struct { a: UintType(64), b: UintType(8) }, &.{ 1, 0, 1 });
    const Variable = VariableProgressiveContainerType(struct {
        a: UintType(64),
        b: FixedProgressiveListType(UintType(8)),
    }, &.{ 1, 0, 1 });
    inline for (.{ Fixed, Variable }) |ST| {
        var source = ST.default_value;
        defer if (ST == Variable) ST.deinit(allocator, &source);
        source.a = 123;
        if (ST == Fixed) source.b = 45 else try source.b.appendSlice(allocator, &.{ 4, 5 });
        var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 64 });
        defer pool.deinit();
        const good = try ST.tree.fromValue(&pool, &source);
        defer pool.unref(good);
        const bad_leaf = try pool.createLeafFromUint(1);
        const bad = try good.setNode(&pool, @enumFromInt(11), bad_leaf);
        defer pool.unref(bad);

        var out: ST.Type = undefined;
        if (ST == Fixed) {
            try std.testing.expectError(error.InvalidTerminatorNode, ST.tree.toValue(bad, &pool, &out));
        } else {
            var failing = std.testing.FailingAllocator.init(allocator, .{});
            try std.testing.expectError(error.InvalidTerminatorNode, ST.tree.toValue(failing.allocator(), bad, &pool, &out));
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        }
        var bytes: [16]u8 = undefined;
        try std.testing.expectError(error.InvalidTerminatorNode, ST.tree.serializeIntoBytes(bad, &pool, &bytes));
    }
}
