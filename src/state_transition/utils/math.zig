const std = @import("std");

/// Return the largest integer `x` such that `x**2 <= n`.
/// Matches the consensus spec `integer_squareroot` exactly using Newton's method
/// with pure integer arithmetic (no floating-point precision loss).
/// Spec: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#integer_squareroot
pub inline fn intSqrt(n: u64) u64 {
    const uint64_max_sqrt: u64 = 4294967295; // 2^32 - 1

    if (n == std.math.maxInt(u64)) {
        return uint64_max_sqrt;
    }
    var x = n;
    var y = @divFloor(x + 1, 2);
    while (y < x) {
        x = y;
        y = @divFloor(x + @divFloor(n, x), 2);
    }

    // Assert post-condition: x*x <= n < (x+1)*(x+1)
    if (std.debug.runtime_safety) {
        const x_sq = @mulWithOverflow(x, x);
        const x1 = x + 1;
        const x1_sq = @mulWithOverflow(x1, x1);
        std.debug.assert(x_sq[1] == 0 and x_sq[0] <= n);
        std.debug.assert(x1_sq[1] != 0 or x1_sq[0] > n);
    }

    return x;
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
    const expected = 94906265;
    try std.testing.expectEqual(@as(u64, expected), intSqrt(large));
    try std.testing.expect(expected * expected <= large);
    try std.testing.expect((expected + 1) * (expected + 1) > large);
}
