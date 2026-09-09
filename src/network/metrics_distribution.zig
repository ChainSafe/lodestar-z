const std = @import("std");

/// A distribution of the current bounded population, rebuilt with each owner snapshot.
pub fn Distribution(comptime bounds_: []const f64) type {
    comptime {
        std.debug.assert(bounds_.len > 0 and bounds_.len <= 16);
        for (bounds_) |bound| std.debug.assert(std.math.isFinite(bound));
        for (bounds_[1..], bounds_[0 .. bounds_.len - 1]) |next, previous|
            std.debug.assert(next > previous);
    }
    return struct {
        pub const bounds = bounds_;
        buckets: [bounds_.len + 1]u64 = @splat(0),
        count: u64 = 0,
        sum: f64 = 0,

        pub fn observe(self: *@This(), value: f64) void {
            std.debug.assert(std.math.isFinite(value) and self.count < 65_535);
            var index: usize = bounds_.len;
            for (bounds_, 0..) |bound, i| if (value <= bound) {
                index = i;
                break;
            };
            self.buckets[index] += 1;
            self.count += 1;
            self.sum += value;
            std.debug.assert(std.math.isFinite(self.sum));
        }
    };
}

test "population distribution includes negative boundaries and overflow without accumulation" {
    var value: Distribution(&.{ -50, 0, 25 }) = .{};
    for ([_]f64{ -100, -50, -1, 0, 25, 26 }) |sample| value.observe(sample);
    try std.testing.expectEqualSlices(u64, &.{ 2, 2, 1, 1 }, &value.buckets);
    try std.testing.expectEqual(@as(f64, -100), value.sum);
    value = .{};
    try std.testing.expectEqual(@as(u64, 0), value.count);
    try std.testing.expectEqual(@as(f64, 0), value.sum);
}
