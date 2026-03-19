//! Stub metrics module for when the external metrics dependency is not available.
//! Provides no-op implementations matching the metrics library API.

pub fn Histogram(comptime T: type, comptime _buckets: anytype) type {
    _ = _buckets;
    return struct {
        pub fn observe(self: *@This(), value: T) void {
            _ = self;
            _ = value;
        }
    };
}

pub fn HistogramVec(comptime T: type, comptime L: type, comptime _buckets: anytype) type {
    _ = _buckets;
    return struct {
        pub fn observe(self: *@This(), labels: L, value: T) !void {
            _ = self;
            _ = labels;
            _ = value;
        }
    };
}

pub fn Gauge(comptime T: type) type {
    return struct {
        pub fn set(self: *@This(), value: T) void {
            _ = self;
            _ = value;
        }
        pub fn inc(self: *@This()) void {
            _ = self;
        }
    };
}

pub fn GaugeVec(comptime T: type, comptime L: type) type {
    return struct {
        pub fn set(self: *@This(), labels: L, value: T) void {
            _ = self;
            _ = labels;
            _ = value;
        }
    };
}

pub fn initializeNoop(comptime T: type) T {
    return std.mem.zeroes(T);
}

const std = @import("std");
