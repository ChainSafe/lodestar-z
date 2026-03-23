const std = @import("std");

/// Return the largest integer `x` such that `x**2 <= n`.
/// Wraps `std.math.sqrt` which uses a correct integer algorithm
/// (no floating-point precision loss).
pub inline fn intSqrt(n: u64) u64 {
    return std.math.sqrt(n);
}

test "intSqrt" {
    // Basic cases
    try std.testing.expectEqual(@as(u64, 0), intSqrt(0));
    try std.testing.expectEqual(@as(u64, 1), intSqrt(1));
    try std.testing.expectEqual(@as(u64, 1), intSqrt(2));
    try std.testing.expectEqual(@as(u64, 1), intSqrt(3));
    try std.testing.expectEqual(@as(u64, 2), intSqrt(4));
    try std.testing.expectEqual(@as(u64, 3), intSqrt(9));
    try std.testing.expectEqual(@as(u64, 3), intSqrt(10));
    try std.testing.expectEqual(@as(u64, 10), intSqrt(100));
    try std.testing.expectEqual(@as(u64, 31), intSqrt(999));

    // Large values (where f64 would lose precision)
    try std.testing.expectEqual(@as(u64, 4294967295), intSqrt(std.math.maxInt(u64)));
    try std.testing.expectEqual(@as(u64, 4294967295), intSqrt(std.math.maxInt(u64) - 1));

    // Value > 2^53 (f64 precision boundary)
    const large: u64 = (1 << 53) + 1;
    const expected: u64 = 94906265;
    try std.testing.expectEqual(expected, intSqrt(large));
}
