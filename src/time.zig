const std = @import("std");

pub fn timestampNow(io: std.Io) std.Io.Timestamp {
    return std.Io.Timestamp.now(io, .awake);
}

pub fn since(io: std.Io, start: std.Io.Timestamp) std.Io.Duration {
    return start.durationTo(timestampNow(io));
}

/// Convert a `Duration` to floating-point seconds. Useful for Prometheus-style
/// histogram observations that expect `f64` seconds.
pub fn durationSeconds(d: std.Io.Duration) f64 {
    return @as(f64, @floatFromInt(d.nanoseconds)) / std.time.ns_per_s;
}
