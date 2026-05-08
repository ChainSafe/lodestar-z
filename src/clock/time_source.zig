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

    /// Advance time by exactly one slot duration. Uses the duration that
    /// applies at the slot containing the current time; pre-genesis falls
    /// back to the genesis (pre-fork) duration.
    pub fn advanceSlot(self: *FakeTime, config: slot_math.Config) void {
        const slot = slot_math.slotAtMs(config, self.ms) orelse 0;
        self.ms += config.slotDurationMsAt(slot);
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

const testing = std.testing;

test "FakeTime.advanceSlot uses fork-aware duration" {
    const cfg = slot_math.Config{
        .genesis_time_sec = 1_000,
        .slot_duration_ms = 12_000,
        .duration_transitions = slot_math.forkTransitions(&.{
            .{ .from_slot = 2, .new_duration_ms = 6_000 },
        }),
        .slots_per_epoch = 32,
    };

    var fake = FakeTime{ .ms = cfg.genesis_time_sec * 1000 };
    // Slot 0 → uses 12_000 ms
    fake.advanceSlot(cfg);
    try testing.expectEqual(@as(slot_math.UnixMs, 1_012_000), fake.ms);
    // Slot 1 → still 12_000 ms (transition is at slot 2)
    fake.advanceSlot(cfg);
    try testing.expectEqual(@as(slot_math.UnixMs, 1_024_000), fake.ms);
    // Slot 2 → first post-fork slot, 6_000 ms
    fake.advanceSlot(cfg);
    try testing.expectEqual(@as(slot_math.UnixMs, 1_030_000), fake.ms);
}
