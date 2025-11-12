pub inline fn intSqrt(x: u64) u64 {
    const x_f64: f64 = @floatFromInt(x);
    const sqrt_f64: f64 = @sqrt(x_f64);
    return @intFromFloat(sqrt_f64);
}
