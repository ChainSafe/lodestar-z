pub inline fn intSqrt(x: u64) u64 {
    const x_f64: f64 = @floatFromInt(x);
    const sqrt_f64: f64 = @sqrt(x_f64);
    return @intFromFloat(sqrt_f64);
}

const std = @import("std");

test "intSqrt" {
    try std.testing.expectEqual(@as(u64, 0), intSqrt(0));
    try std.testing.expectEqual(@as(u64, 1), intSqrt(1));
    try std.testing.expectEqual(@as(u64, 1), intSqrt(2));
    try std.testing.expectEqual(@as(u64, 1), intSqrt(3));
    try std.testing.expectEqual(@as(u64, 2), intSqrt(4));
    try std.testing.expectEqual(@as(u64, 3), intSqrt(9));
    try std.testing.expectEqual(@as(u64, 10), intSqrt(100));
    try std.testing.expectEqual(@as(u64, 31), intSqrt(999));
    try std.testing.expectEqual(@as(u64, 1000), intSqrt(1_000_000));
    // Large value.
    try std.testing.expectEqual(@as(u64, 4_294_967_295), intSqrt(18_446_744_065_119_617_025));
}
