//! Tests for `bit_list.zig`.

const std = @import("std");
const Node = @import("persistent_merkle_tree").Node;
const BitListType = @import("../type/bit_list.zig").BitListType;

test "BitListTreeView padding bit roundtrip" {
    const allocator = std.testing.allocator;
    const Bits = BitListType(64);

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 4096 });
    defer pool.deinit();

    const test_cases = [_]usize{ 1, 7, 8, 9, 15, 16, 17, 31, 32, 33 };

    for (test_cases) |bit_len| {
        // Create value with alternating bits
        var value = try Bits.Type.fromBitLen(allocator, bit_len);
        defer value.deinit(allocator);

        for (0..bit_len) |i| {
            value.setAssumeCapacity(i, i % 2 == 0);
        }

        const serialized = try allocator.alloc(u8, Bits.serializedSize(&value));
        defer allocator.free(serialized);
        _ = Bits.serializeIntoBytes(&value, serialized);

        var deserialized: Bits.Type = Bits.Type.empty;
        defer deserialized.deinit(allocator);
        try Bits.deserializeFromBytes(allocator, serialized, &deserialized);

        const root = try Bits.tree.fromValue(&pool, &deserialized);
        var view = try Bits.TreeView.init(allocator, &pool, root);
        defer view.deinit();

        const bools = try view.toBoolArray(allocator);
        defer allocator.free(bools);

        try std.testing.expectEqual(bit_len, bools.len);
        for (0..bit_len) |i| {
            try std.testing.expectEqual(i % 2 == 0, bools[i]);
        }
    }
}
