const std = @import("std");

pub fn Histogram(comptime bounds_ms: []const u64) type {
    comptime {
        std.debug.assert(bounds_ms.len > 0 and bounds_ms.len <= 16);
        for (bounds_ms[1..], bounds_ms[0 .. bounds_ms.len - 1]) |next, previous| std.debug.assert(next > previous);
    }
    return struct {
        pub const bounds = bounds_ms;
        buckets: [bounds_ms.len + 1]u64 = @splat(0),
        count: u64 = 0,
        sum_ms: u128 = 0,

        pub fn observe(self: *@This(), duration_ms: u64) void {
            if (self.count == std.math.maxInt(u64)) return;
            var index: usize = bounds_ms.len;
            for (bounds_ms, 0..) |bound, i| if (duration_ms <= bound) {
                index = i;
                break;
            };
            self.buckets[index] += 1;
            self.count += 1;
            self.sum_ms += duration_ms;
        }

        pub fn merge(self: *@This(), other: *const @This()) void {
            for (&self.buckets, other.buckets) |*value, addition| value.* +|= addition;
            self.count +|= other.count;
            self.sum_ms +|= other.sum_ms;
        }
    };
}

test "histogram boundaries, zero duration, overflow bucket and independent merges" {
    var histogram: Histogram(&.{ 100, 200 }) = .{};
    for ([_]u64{ 0, 100, 101, 200, 201 }) |value| histogram.observe(value);
    try std.testing.expectEqualSlices(u64, &.{ 2, 2, 1 }, &histogram.buckets);
    try std.testing.expectEqual(@as(u128, 602), histogram.sum_ms);
    var combined: @TypeOf(histogram) = .{};
    combined.merge(&histogram);
    combined.merge(&histogram);
    try std.testing.expectEqual(@as(u64, 10), combined.count);
    try std.testing.expectEqual(@as(u128, 1204), combined.sum_ms);
    try std.testing.expectEqual(@as(u64, 5), histogram.count);
}
