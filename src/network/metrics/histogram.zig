const std = @import("std");

pub const Unit = enum { scalar, seconds, milliseconds };

pub const Options = struct {
    unit: Unit = .scalar,
    population_max: ?u16 = null,
    nonnegative: bool = false,
};

pub fn Duration(comptime bounds_ms: []const u64) type {
    return Histogram(u64, bounds_ms, .{ .unit = .milliseconds });
}

pub fn Distribution(comptime bounds: []const f64) type {
    return Histogram(f64, bounds, .{ .population_max = 65_535 });
}

pub fn Histogram(comptime Value: type, comptime bounds_: []const Value, comptime options: Options) type {
    comptime {
        std.debug.assert(Value == u64 or Value == f64);
        std.debug.assert(bounds_.len > 0 and bounds_.len <= 16);
        for (bounds_) |bound| {
            if (Value == f64) std.debug.assert(std.math.isFinite(bound));
        }
        for (bounds_[1..], bounds_[0 .. bounds_.len - 1]) |next, previous| {
            std.debug.assert(next > previous);
        }
    }
    return struct {
        pub const bounds = bounds_;
        pub const unit = options.unit;
        pub const output_bounds = blk: {
            var values: [bounds.len]f64 = undefined;
            for (bounds, &values) |bound, *value| value.* = output(bound);
            break :blk values;
        };
        const Sum = if (Value == u64) u128 else f64;

        buckets: [bounds.len + 1]u64 = @splat(0),
        count: u64 = 0,
        sum: Sum = 0,

        pub fn observe(self: *@This(), value: Value) void {
            if (Value == f64) std.debug.assert(std.math.isFinite(value));
            if (options.nonnegative) std.debug.assert(value >= 0);
            if (options.population_max) |limit| std.debug.assert(self.count < limit);
            if (self.count == std.math.maxInt(u64)) return;
            var index: usize = bounds.len;
            for (bounds, 0..) |bound, i| {
                if (value <= bound) {
                    index = i;
                    break;
                }
            }
            self.buckets[index] += 1;
            self.count += 1;
            self.sum += value;
            if (Value == f64) std.debug.assert(std.math.isFinite(self.sum));
        }

        pub fn merge(self: *@This(), other: *const @This()) void {
            for (&self.buckets, other.buckets) |*value, addition| value.* +|= addition;
            self.count +|= other.count;
            if (Value == u64) self.sum +|= other.sum else self.sum += other.sum;
            if (Value == f64) std.debug.assert(std.math.isFinite(self.sum));
            if (options.population_max) |limit| std.debug.assert(self.count <= limit);
        }

        pub fn output(value: anytype) f64 {
            const number: f64 = if (@typeInfo(@TypeOf(value)) == .int)
                @floatFromInt(value)
            else
                value;
            return if (unit == .milliseconds) number / 1000 else number;
        }
    };
}

test "histogram inclusive boundaries, exact duration sums and independent merges" {
    var histogram: Duration(&.{ 100, 200 }) = .{};
    for ([_]u64{ 0, 100, 101, 200, 201 }) |value| histogram.observe(value);
    try std.testing.expectEqualSlices(u64, &.{ 2, 2, 1 }, &histogram.buckets);
    try std.testing.expectEqual(@as(u128, 602), histogram.sum);
    var combined: @TypeOf(histogram) = .{};
    combined.merge(&histogram);
    combined.merge(&histogram);
    try std.testing.expectEqual(@as(u64, 10), combined.count);
    try std.testing.expectEqual(@as(u128, 1204), combined.sum);
    try std.testing.expectEqual(@as(u64, 5), histogram.count);
    try std.testing.expectEqual(@as(f64, 0.602), @TypeOf(histogram).output(histogram.sum));
    histogram.observe(std.math.maxInt(u64));
    try std.testing.expectEqual(@as(u128, std.math.maxInt(u64)) + 602, histogram.sum);
}

test "histogram population includes negative boundaries and resets independently" {
    var value: Distribution(&.{ -50, 0, 25 }) = .{};
    for ([_]f64{ -100, -50, -1, 0, 25, 26 }) |sample| value.observe(sample);
    try std.testing.expectEqualSlices(u64, &.{ 2, 2, 1, 1 }, &value.buckets);
    try std.testing.expectEqual(@as(f64, -100), value.sum);
    value = .{};
    try std.testing.expectEqual(@as(u64, 0), value.count);
}

test "histogram lifetime observations stop at count saturation" {
    var value: Histogram(f64, &.{ 10, 100, 1000 }, .{ .nonnegative = true }) = .{};
    value.count = std.math.maxInt(u64);
    value.buckets[0] = value.count;
    value.sum = 12;
    value.observe(1);
    try std.testing.expectEqual(std.math.maxInt(u64), value.count);
    try std.testing.expectEqual(std.math.maxInt(u64), value.buckets[0]);
    try std.testing.expectEqual(@as(f64, 12), value.sum);
}
