//! Tests for `progressive_list.zig`.

const std = @import("std");
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
