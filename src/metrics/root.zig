pub const server = @import("server.zig");

/// An observer for tracking time.
pub fn Observer(comptime H: type) type {
    return struct {
        hist: H,
        timer: ?std.time.Timer = null,

        pub fn init(hist: anytype) Observer(@TypeOf(hist)) {
            std.debug.assert(@typeInfo(@TypeOf(hist)) == .pointer);
            return .{
                .hist = hist,
            };
        }

        pub fn startTimer(self: *@This()) *@This() {
            self.timer = std.time.Timer.start() catch unreachable;
            return self;
        }

        /// Stops the internal `timer` and calls `observe` on the internal `hist` to record time elapsed.
        pub fn stopAndObserve(obs: *@This()) f32 {
            const ns = obs.timer.?.read();
            const secs = @as(f32, @floatFromInt(ns)) / 1e9;
            obs.hist.observe(secs);
            return secs;
        }
    };
}

/// A labeled observer for tracking time.
pub fn LabeledObserver(comptime H: type, comptime L: type) type {
    return struct {
        hist: H,
        labels: ?L = null,
        timer: ?std.time.Timer = null,

        pub fn init(hist: anytype) LabeledObserver(@TypeOf(hist), L) {
            std.debug.assert(@typeInfo(@TypeOf(hist)) == .pointer);
            return .{ .hist = hist };
        }

        pub fn startTimer(self: *@This(), labels: L) *@This() {
            self.timer = std.time.Timer.start() catch unreachable;
            self.labels = labels;
            return self;
        }

        /// Stops the internal `timer` and calls `observe` on the internal `hist` to record time elapsed.
        ///
        /// Assumes that `startTimer` has been called.
        pub fn stopAndObserve(obs: *@This()) !f32 {
            std.debug.assert(obs.timer != null);
            std.debug.assert(obs.labels != null);
            const ns = obs.timer.?.read();
            const secs = @as(f32, @floatFromInt(ns)) / 1e9;
            try obs.hist.observe(obs.labels.?, secs);
            return secs;
        }
    };
}

/// Initializes a `std.time.Timer` and returns an `Observer`.
/// Suitable for one-time use of `Observer`.
pub fn startTimer(hist: anytype) Observer(@TypeOf(hist)) {
    std.debug.assert(@typeInfo(@TypeOf(hist)) == .pointer);
    return .{
        .hist = hist,
        .timer = std.time.Timer.start() catch unreachable,
    };
}

/// Initializes a `std.time.Timer` and returns a `LabeledObserver`.
/// Suitable for one-time use of `LabeledObserver`.
pub fn startTimerLabeled(hist: anytype, labels: anytype) LabeledObserver(@TypeOf(hist), @TypeOf(labels)) {
    std.debug.assert(@typeInfo(@TypeOf(hist)) == .pointer);
    var obs = LabeledObserver(@TypeOf(hist), @TypeOf(labels)).init(hist);
    _ = obs.startTimer(labels);
    return obs;
}

const std = @import("std");

const m = @import("metrics");
