//! Pluggable time source so tests can inject deterministic time.

const std = @import("std");
const slot_math = @import("slot_math.zig");

/// Production time source backed by std.Io wall-clock time.
pub const RealTime = struct {
    io: std.Io,

    pub fn nowMs(self: RealTime) u64 {
        const ms = std.Io.Clock.real.now(self.io).toMilliseconds();
        std.debug.assert(ms >= 0);
        return @intCast(ms);
    }
};

/// Controllable time source for deterministic testing.
pub const FakeTime = struct {
    ms: u64 = 0,

    pub fn nowMs(self: FakeTime) u64 {
        return self.ms;
    }

    pub fn setMs(self: *FakeTime, ms: u64) void {
        self.ms = ms;
    }

    pub fn advanceMs(self: *FakeTime, delta: u64) void {
        self.ms += delta;
    }

    /// Advance time by exactly one slot duration. Uses the duration that
    /// applies at the slot containing the current time; pre-genesis falls
    /// back to the genesis (pre-fork) duration.
    pub fn advanceSlot(self: *FakeTime, config: slot_math.ClockConfig) void {
        const slot = slot_math.slotAtMs(config, self.ms) orelse 0;
        self.ms += slot_math.slotDurationMsAt(config, slot);
    }
};

const testing = std.testing;

test "FakeTime.advanceSlot uses fork-aware duration" {
    const cfg = slot_math.ClockConfig{
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
    try testing.expectEqual(@as(u64, 1_012_000), fake.ms);
    // Slot 1 → still 12_000 ms (transition is at slot 2)
    fake.advanceSlot(cfg);
    try testing.expectEqual(@as(u64, 1_024_000), fake.ms);
    // Slot 2 → first post-fork slot, 6_000 ms
    fake.advanceSlot(cfg);
    try testing.expectEqual(@as(u64, 1_030_000), fake.ms);
}
