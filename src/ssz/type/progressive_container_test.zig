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

    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator, input: *const Container.Type) !void {
            var out: Container.Type = Container.default_value;
            defer Container.deinit(allocator, &out);
            Container.clone(allocator, input, &out) catch |err| {
                try std.testing.expectEqual(@as(usize, 0), out.a.items.len);
                try std.testing.expectEqual(@as(usize, 0), out.b.items.len);
                return err;
            };
            try std.testing.expect(Container.equals(input, &out));
        }
    }.run, .{&value});
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

test "variable progressive container tree decoding rejects every truncated fixed prefix" {
    const allocator = std.testing.allocator;
    const ST = VariableProgressiveContainerType(struct {
        flag: BoolType(),
        bytes: FixedProgressiveListType(UintType(8)),
        bits: @import("progressive_bit_list.zig").ProgressiveBitListType(),
    }, &.{ 1, 0, 1, 0, 0, 1 });
    const encoded = [_]u8{ 1, 9, 0, 0, 0, 9, 0, 0, 0, 1 };
    var pool = try Node.Pool.init(.{ .allocator = allocator, .page_allocator = allocator, .pool_size = 128 });
    defer pool.deinit();
    const baseline = pool.getNodesInUse();
    for (0..encoded.len) |length| {
        try std.testing.expectError(error.InvalidSize, ST.readFieldRanges(encoded[0..length]));
        try std.testing.expectError(error.InvalidSize, ST.tree.deserializeFromBytes(&pool, encoded[0..length]));
        try std.testing.expectEqual(baseline, pool.getNodesInUse());
    }
    const root = try ST.tree.deserializeFromBytes(&pool, &encoded);
    pool.unref(root);
    try std.testing.expectEqual(baseline, pool.getNodesInUse());
}

test "memory_safety: large progressive container tree materialization is atomic on allocation failure" {
    const allocator = std.testing.allocator;
    const Items = FixedProgressiveListType(UintType(8));
    const ST = VariableProgressiveContainerType(struct {
        large: ByteVectorType(64 * 1024),
        first: Items,
        second: Items,
    }, &.{ 1, 0, 1, 0, 1 });
    const source = try allocator.create(ST.Type);
    defer allocator.destroy(source);
    source.* = ST.default_value;
    defer ST.deinit(allocator, source);
    source.large[0] = 77;
    source.large[source.large.len - 1] = 88;
    try source.first.appendSlice(allocator, &.{ 1, 2, 3 });
    try source.second.appendSlice(allocator, &.{ 4, 5, 6 });

    var pool = try Node.Pool.init(.{ .allocator = allocator, .page_allocator = allocator, .pool_size = 8192 });
    defer pool.deinit();
    const initial_nodes = pool.getNodesInUse();
    {
        const root = try ST.tree.fromValue(&pool, source);
        defer pool.unref(root);
        try std.testing.checkAllAllocationFailures(allocator, struct {
            fn run(checked: std.mem.Allocator, node_pool: *Node.Pool, node: Node.Id, expected: *const ST.Type) !void {
                const out = try checked.create(ST.Type);
                defer checked.destroy(out);
                out.* = ST.default_value;
                defer ST.deinit(checked, out);
                out.large[0] = 9;
                try out.first.appendSlice(checked, &.{ 8, 9 });
                try out.second.appendSlice(checked, &.{ 10, 11 });
                const before_root = node.getRoot(node_pool).*;
                const before_nodes = node_pool.getNodesInUse();
                ST.tree.toValue(checked, node, node_pool, out) catch |err| {
                    try std.testing.expectEqual(@as(u8, 9), out.large[0]);
                    try std.testing.expectEqual(@as(u8, 0), out.large[out.large.len - 1]);
                    try std.testing.expectEqualSlices(u8, &.{ 8, 9 }, out.first.items);
                    try std.testing.expectEqualSlices(u8, &.{ 10, 11 }, out.second.items);
                    try std.testing.expectEqualSlices(u8, &before_root, node.getRoot(node_pool));
                    try std.testing.expectEqual(before_nodes, node_pool.getNodesInUse());
                    return err;
                };
                try std.testing.expect(ST.equals(expected, out));
                try std.testing.expectEqualSlices(u8, &before_root, node.getRoot(node_pool));
                try std.testing.expectEqual(before_nodes, node_pool.getNodesInUse());
            }
        }.run, .{ &pool, root, source });
    }
    try std.testing.expectEqual(initial_nodes, pool.getNodesInUse());
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

test "sparse progressive container views commit and clone across subtree depths" {
    const allocator = std.testing.allocator;
    const Items = FixedProgressiveListType(UintType(64));
    const ST = VariableProgressiveContainerType(struct {
        a: UintType(64),
        items: Items,
        tail: ByteVectorType(32),
    }, &.{ 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
    var pool = try Node.Pool.init(.{ .allocator = allocator, .page_allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();
    const baseline = pool.getNodesInUse();
    {
        var expected = ST.default_value;
        defer ST.deinit(allocator, &expected);
        const view = try ST.TreeView.fromValue(allocator, &pool, &expected);
        defer view.deinit();
        try view.set("a", 42);
        expected.a = 42;
        const items = try view.get("items");
        for (0..100) |i| {
            try items.push(i);
            try expected.items.append(allocator, i);
        }
        const tail: [32]u8 = @splat(7);
        try view.setValue("tail", &tail);
        expected.tail = tail;
        var root: [32]u8 = undefined;
        try ST.hashTreeRoot(allocator, &expected, &root);
        try std.testing.expectEqualSlices(u8, &root, try view.hashTreeRoot());
        try std.testing.expectEqual(@as(u64, 42), try view.getReadonly("a"));
        const clone = try view.clone(.{ .transfer_cache = true });
        defer clone.deinit();
        try (try clone.get("items")).set(21, 999);
        try clone.commit();
        try std.testing.expectEqual(@as(u64, 21), try (try view.getReadonly("items")).get(21));
        try std.testing.expectEqual(@as(u64, 999), try (try clone.getReadonly("items")).get(21));

        const bytes = try allocator.alloc(u8, try view.serializedSize());
        defer allocator.free(bytes);
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        const original_allocator = pool.allocator;
        pool.allocator = failing.allocator();
        _ = view.serializeIntoBytes(bytes) catch |err| {
            pool.allocator = original_allocator;
            return err;
        };
        pool.allocator = original_allocator;
        try std.testing.expect(!failing.has_induced_failure);
        const restored = try ST.TreeView.deserialize(allocator, &pool, bytes);
        defer restored.deinit();
        try std.testing.expectEqualSlices(u8, &root, try restored.hashTreeRoot());
    }
    try std.testing.expectEqual(baseline, pool.getNodesInUse());
}

test "sparse progressive container commit retries after every pool exhaustion point" {
    const allocator = std.testing.allocator;
    const ST = FixedProgressiveContainerType(struct { a: UintType(64), b: UintType(64), c: UintType(64) }, &.{ 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
    var saw_failure = false;
    for (0..40) |available| {
        var pool = try Node.Pool.init(.{ .allocator = allocator, .page_allocator = allocator, .pool_size = 128 });
        defer pool.deinit();
        const baseline = pool.getNodesInUse();
        {
            const view = try ST.TreeView.fromValue(allocator, &pool, &ST.default_value);
            defer view.deinit();
            try view.set("a", 1);
            try view.set("b", 2);
            try view.set("c", 3);
            const original = view.getRoot();
            var held: std.ArrayList(Node.Id) = .empty;
            defer held.deinit(allocator);
            while (pool.nodes.len - pool.getNodesInUse() > available) try held.append(allocator, try pool.createLeafFromUint(0));
            defer pool.free(held.items);
            view.commit() catch |err| {
                try std.testing.expectEqual(error.PoolExhausted, err);
                try std.testing.expectEqual(original, view.getRoot());
                pool.free(held.items);
                held.clearRetainingCapacity();
                try view.commit();
                saw_failure = true;
            };
            var expected: [32]u8 = undefined;
            try ST.hashTreeRoot(&.{ .a = 1, .b = 2, .c = 3 }, &expected);
            try std.testing.expectEqualSlices(u8, &expected, try view.hashTreeRoot());
        }
        try std.testing.expectEqual(baseline, pool.getNodesInUse());
    }
    try std.testing.expect(saw_failure);
}
