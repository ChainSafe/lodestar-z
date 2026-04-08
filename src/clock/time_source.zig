//! Pluggable time source abstraction.
//!
//! Tagged union with two variants:
//!   `.io`   – production: reads wall-clock time from `std.Io`
//!   `.fake` – testing: reads from a mutable `FakeTime` struct

const std = @import("std");
const slot_math = @import("slot_math.zig");

/// Production clock backed by std.Io wall-clock time.
pub const RealClock = struct {
    io: std.Io,

    pub fn nowMs(self: RealClock) slot_math.UnixMs {
        const ms = std.Io.Clock.real.now(self.io).toMilliseconds();
        std.debug.assert(ms >= 0);
        return @intCast(ms);
    }
};

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
    real: RealClock,
    fake: *FakeTime,

    pub fn nowMs(self: TimeSource) slot_math.UnixMs {
        return switch (self) {
            .real => |c| c.nowMs(),
            .fake => |f| f.ms,
        };
    }
};
