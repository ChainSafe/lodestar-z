//! Tests for `progressive_list.zig`.

const std = @import("std");
const BoolType = @import("bool.zig").BoolType;
const ProgressiveBitListType = @import("progressive_bit_list.zig").ProgressiveBitListType;
const Node = @import("persistent_merkle_tree").Node;
const FixedProgressiveListType = @import("progressive_list.zig").FixedProgressiveListType;
const VariableProgressiveListType = @import("progressive_list.zig").VariableProgressiveListType;
const UintType = @import("uint.zig").UintType;
const FixedContainerType = @import("container.zig").FixedContainerType;

test "ListType - sanity" {
    const allocator = std.testing.allocator;

    const Bytes = FixedProgressiveListType(UintType(8));

    var b: Bytes.Type = Bytes.default_value;
    defer b.deinit(allocator);
    try b.append(allocator, 5);

    const b_buf = try allocator.alloc(u8, Bytes.serializedSize(&b));
    defer allocator.free(b_buf);

    _ = Bytes.serializeIntoBytes(&b, b_buf);
    try Bytes.deserializeFromBytes(allocator, b_buf, &b);

    const BytesBytes = VariableProgressiveListType(Bytes);
    var b2: BytesBytes.Type = BytesBytes.default_value;
    defer b2.deinit(allocator);
    const b_elem: Bytes.Type = Bytes.default_value;
    try b2.append(allocator, b_elem);

    const b2_buf = try allocator.alloc(u8, BytesBytes.serializedSize(&b2));
    defer allocator.free(b2_buf);

    _ = BytesBytes.serializeIntoBytes(&b2, b2_buf);
    try BytesBytes.deserializeFromBytes(allocator, b2_buf, &b2);
}

test "fixed progressive list tree size needs no allocation" {
    const allocator = std.testing.allocator;
    const Pair = FixedContainerType(struct { a: UintType(64), b: UintType(64) });
    inline for (.{ UintType(8), UintType(64), Pair }) |Element| {
        const List = FixedProgressiveListType(Element);
        var failing = std.testing.FailingAllocator.init(allocator, .{});
        var pool = try Node.Pool.init(.{
            .page_allocator = allocator,
            .allocator = failing.allocator(),
            .pool_size = 128,
        });
        defer pool.deinit();

        var value = List.default_value;
        defer List.deinit(allocator, &value);
        for ([_]usize{ 0, 1, 5, 21 }) |len| {
            try value.resize(allocator, len);
            @memset(value.items, Element.default_value);
            const root = try List.tree.fromValue(&pool, &value);
            defer pool.unref(root);

            failing.fail_index = failing.alloc_index;
            try std.testing.expectEqual(len * Element.fixed_size, try List.tree.serializedSize(root, &pool));
            try std.testing.expect(!failing.has_induced_failure);
            failing.fail_index = std.math.maxInt(usize);
        }
    }
}

test "fixed progressive list tree size rejects overflow" {
    const allocator = std.testing.allocator;
    const List = FixedProgressiveListType(UintType(64));
    var pool = try Node.Pool.init(.{
        .page_allocator = allocator,
        .allocator = allocator,
        .pool_size = 2,
    });
    defer pool.deinit();

    const length_leaf = try pool.createLeafFromUint(std.math.maxInt(usize) / 8 + 1);
    const root = try pool.createBranch(@enumFromInt(0), length_leaf);
    defer pool.unref(root);

    try std.testing.expectError(error.Overflow, List.tree.serializedSize(root, &pool));
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

test "memory_safety: progressive list tree.fromValue reclaims unpublished nodes on pool exhaustion" {
    const List = FixedProgressiveListType(UintType(64));
    var value: List.Type = .empty;
    defer value.deinit(std.testing.allocator);
    for (0..8) |i| try value.append(std.testing.allocator, @intCast(i));

    try expectProgressiveFromValuePoolExhaustionReclaimsNodes(List, &value, 32);
}

test "memory_safety: progressive fixed list byte deserialization preserves out on malformed input" {
    const List = FixedProgressiveListType(BoolType());
    var out: List.Type = .empty;
    defer out.deinit(std.testing.allocator);
    try out.appendSlice(std.testing.allocator, &.{ false, false });

    try std.testing.expectError(
        error.invalidBoolean,
        List.deserializeFromBytes(std.testing.allocator, &.{ 1, 2 }, &out),
    );
    try std.testing.expectEqualSlices(bool, &.{ false, false }, out.items);
}

test "memory_safety: progressive list tree.toValue preserves out on malformed tree" {
    const List = FixedProgressiveListType(UintType(64));
    var pool = try Node.Pool.init(.{
        .page_allocator = std.testing.allocator,
        .allocator = std.testing.allocator,
        .pool_size = 8,
    });
    defer pool.deinit();

    const invalid_contents = try pool.createLeaf(&([_]u8{0} ** 32));
    errdefer pool.unref(invalid_contents);
    const length = try pool.createLeafFromUint(2);
    errdefer pool.unref(length);
    const root = try pool.createBranch(invalid_contents, length);
    defer pool.unref(root);

    var out: List.Type = .empty;
    defer out.deinit(std.testing.allocator);
    try out.append(std.testing.allocator, 99);

    try std.testing.expectError(
        error.InvalidNode,
        List.tree.toValue(std.testing.allocator, root, &pool, &out),
    );
    try std.testing.expectEqualSlices(u64, &.{99}, out.items);
}

test "memory_safety: variable progressive list byte deserialization preserves out on OOM" {
    const Bits = ProgressiveBitListType();
    const List = VariableProgressiveListType(Bits);
    var source: List.Type = .empty;
    defer List.deinit(std.testing.allocator, &source);
    for (0..2) |i| {
        var bits = try Bits.Type.fromBitLen(std.testing.allocator, 16 + i);
        errdefer bits.deinit(std.testing.allocator);
        try bits.setAssumeCapacity(i, true);
        try source.append(std.testing.allocator, bits);
    }

    const bytes = try std.testing.allocator.alloc(u8, List.serializedSize(&source));
    defer std.testing.allocator.free(bytes);
    _ = List.serializeIntoBytes(&source, bytes);

    var saw_failure = false;
    var saw_success = false;
    for (0..16) |fail_after| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var out: List.Type = .empty;
        defer List.deinit(failing.allocator(), &out);
        var sentinel: ?Bits.Type = try Bits.Type.fromBitLen(failing.allocator(), 5);
        errdefer if (sentinel) |*value| value.deinit(failing.allocator());
        try sentinel.?.setAssumeCapacity(4, true);
        try out.append(failing.allocator(), sentinel.?);
        sentinel = null;

        failing.fail_index = failing.alloc_index + fail_after;
        List.deserializeFromBytes(failing.allocator(), bytes, &out) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqual(@as(usize, 1), out.items.len);
            try std.testing.expectEqual(@as(usize, 5), out.items[0].bit_len);
            try std.testing.expect(try out.items[0].get(4));
            saw_failure = true;
            continue;
        };
        try std.testing.expect(List.equals(&source, &out));
        saw_success = true;
    }
    try std.testing.expect(saw_failure);
    try std.testing.expect(saw_success);
}

test "memory_safety: variable progressive list tree.toValue preserves out on OOM" {
    const Bits = ProgressiveBitListType();
    const List = VariableProgressiveListType(Bits);
    var source: List.Type = .empty;
    defer List.deinit(std.testing.allocator, &source);
    for (0..2) |i| {
        var bits = try Bits.Type.fromBitLen(std.testing.allocator, 300 + i);
        errdefer bits.deinit(std.testing.allocator);
        try bits.setAssumeCapacity(i, true);
        try source.append(std.testing.allocator, bits);
    }

    var pool = try Node.Pool.init(.{
        .page_allocator = std.testing.allocator,
        .allocator = std.testing.allocator,
        .pool_size = 64,
    });
    defer pool.deinit();
    const root = try List.tree.fromValue(&pool, &source);
    defer pool.unref(root);

    var saw_failure = false;
    var saw_success = false;
    for (0..24) |fail_after| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var out: List.Type = .empty;
        defer List.deinit(failing.allocator(), &out);
        var sentinel: ?Bits.Type = try Bits.Type.fromBitLen(failing.allocator(), 5);
        errdefer if (sentinel) |*value| value.deinit(failing.allocator());
        try sentinel.?.setAssumeCapacity(4, true);
        try out.append(failing.allocator(), sentinel.?);
        sentinel = null;

        failing.fail_index = failing.alloc_index + fail_after;
        List.tree.toValue(failing.allocator(), root, &pool, &out) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqual(@as(usize, 1), out.items.len);
            try std.testing.expectEqual(@as(usize, 5), out.items[0].bit_len);
            try std.testing.expect(try out.items[0].get(4));
            saw_failure = true;
            continue;
        };
        try std.testing.expect(List.equals(&source, &out));
        saw_success = true;
    }
    try std.testing.expect(saw_failure);
    try std.testing.expect(saw_success);
}
