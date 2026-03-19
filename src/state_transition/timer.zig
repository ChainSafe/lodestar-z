//! Timer shim for Zig 0.16.
//! Replaces std.time.Timer which was removed.
//! Uses std.Io.Clock.awake for high-resolution timing.
const std = @import("std");

const Timer = @This();

start_time: std.Io.Timestamp,
io: std.Io,

pub fn start() !Timer {
    const io = std.Options.debug_io;
    return .{
        .start_time = std.Io.Timestamp.now(io, .awake),
        .io = io,
    };
}

pub fn read(self: *Timer) u64 {
    const now = std.Io.Timestamp.now(self.io, .awake);
    const duration = self.start_time.durationTo(now);
    return @intCast(@max(0, duration.nanoseconds));
}
