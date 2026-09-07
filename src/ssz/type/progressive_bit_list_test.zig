//! Tests for `progressive_bit_list.zig`.

const std = @import("std");
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
