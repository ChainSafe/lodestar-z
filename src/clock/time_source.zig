//! Pluggable time source abstraction.
//!
//! Tagged union with two variants:
//!   `.io`   – production: reads wall-clock time from `std.Io`
//!   `.fake` – testing: reads from a mutable `FakeTime` struct

const std = @import("std");
const slot_math = @import("slot_math.zig");

/// Controllable time source for deterministic testing.
pub const FakeTime = struct {
    ms: slot_math.UnixMs = 0,

    pub fn setMs(self: *FakeTime, ms: slot_math.UnixMs) void {
        self.ms = ms;
    }

    pub fn advanceMs(self: *FakeTime, delta: u64) void {
        self.ms += delta;
    }

    pub fn advanceSlot(self: *FakeTime, config: slot_math.Config) void {
        self.ms += config.slotDurationMs() orelse return;
    }
};

pub const TimeSource = union(enum) {
    /// Production: reads wall-clock time via std.Io.Clock.real.
    io: std.Io,
    /// Testing: reads from a mutable FakeTime pointer.
    fake: *FakeTime,

    pub fn nowMs(self: TimeSource) slot_math.UnixMs {
        return switch (self) {
            .io => |io_handle| blk: {
                const ms = std.Io.Clock.real.now(io_handle).toMilliseconds();
                std.debug.assert(ms >= 0);
                break :blk @intCast(ms);
            },
            .fake => |f| f.ms,
        };
    }
};
