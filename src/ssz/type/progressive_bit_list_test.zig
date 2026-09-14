//! Tests for `progressive_bit_list.zig`.

const std = @import("std");
const Node = @import("persistent_merkle_tree").Node;
const ProgressiveBitListType = @import("progressive_bit_list.zig").ProgressiveBitListType;

test "ProgressiveBitListType - sanity" {
    const allocator = std.testing.allocator;
    const Bits = ProgressiveBitListType();
    var b: Bits.Type = try Bits.Type.fromBitLen(allocator, 30);
    defer b.deinit(allocator);

    try b.setAssumeCapacity(2, true);

    const b_buf = try allocator.alloc(u8, Bits.serializedSize(&b));
    defer allocator.free(b_buf);

    _ = Bits.serializeIntoBytes(&b, b_buf);
    try Bits.deserializeFromBytes(allocator, b_buf, &b);

    try std.testing.expect(try b.get(0) == false);
    try std.testing.expect(try b.get(2) == true);
}

test "ProgressiveBitListType - shrinking clears truncated bits" {
    const allocator = std.testing.allocator;
    const Bits = ProgressiveBitListType();
    var bits = try Bits.Type.fromBitLen(allocator, 8);
    defer bits.deinit(allocator);

    try bits.setAssumeCapacity(7, true);
    try bits.resize(allocator, 1);

    var serialized: [1]u8 = undefined;
    _ = Bits.serializeIntoBytes(&bits, &serialized);

    var round_trip = Bits.default_value;
    defer round_trip.deinit(allocator);
    try Bits.deserializeFromBytes(allocator, &serialized, &round_trip);

    try std.testing.expectEqual(@as(usize, 1), round_trip.bit_len);
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

test "memory_safety: progressive bit list tree.fromValue reclaims unpublished nodes on pool exhaustion" {
    const Bits = ProgressiveBitListType();
    var value = try Bits.Type.fromBitLen(std.testing.allocator, 300);
    defer value.deinit(std.testing.allocator);

    try expectProgressiveFromValuePoolExhaustionReclaimsNodes(Bits, &value, 32);
}
