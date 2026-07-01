//! Internal stateful slot cursor.
//!
//! Wraps `slot_math` with a `std.Io` wall-clock and a cached `current_slot`.
//! Pure-read helpers query wall-clock time; only `advanceTo()` mutates the cache.

const std = @import("std");
const time = @import("time");
const slot_math = @import("slot_math.zig");

const SlotClock = @This();

pub const Slot = slot_math.Slot;
pub const Epoch = slot_math.Epoch;
pub const ClockConfig = slot_math.ClockConfig;

pub const Event = union(enum) {
    slot: Slot,
    epoch: Epoch,
};

config: ClockConfig,
io: std.Io,
current_slot: ?Slot = null,

pub const AdvanceIterator = struct {
    clock: *SlotClock,
    target: Slot,
    pending_epoch: ?Epoch = null,

    /// Advances the clock one step at a time, yielding slot and epoch events.
    /// For each slot advancement: yields .slot first, then .epoch if an epoch
    /// boundary was crossed.
    /// Returns null when caught up to target.
    pub fn next(self: *AdvanceIterator) ?Event {
        if (self.pending_epoch) |epoch| {
            self.pending_epoch = null;
            return .{ .epoch = epoch };
        }

        const current = self.clock.current_slot;
        if (current == null) {
            self.clock.current_slot = 0;
            return .{ .slot = 0 };
        }

        const cur = current.?;
        if (cur >= self.target) return null;

        const next_slot = cur + 1;
        self.clock.current_slot = next_slot;

        const prev_epoch = slot_math.epochAtSlot(self.clock.config, cur);
        const new_epoch = slot_math.epochAtSlot(self.clock.config, next_slot);
        if (prev_epoch < new_epoch) {
            self.pending_epoch = new_epoch;
        }

        return .{ .slot = next_slot };
    }
};

pub fn init(config: ClockConfig, io: std.Io) error{InvalidConfig}!SlotClock {
    try config.validate();
    var self = SlotClock{
        .config = config,
        .io = io,
    };
    self.current_slot = slot_math.slotAtMs(config, time.nowMs(self.io));
    return self;
}

/// Returns the current wall-clock slot. Pure read — does NOT update
/// the internal `current_slot` cache. Only `advanceTo()` advances the cache.
pub fn currentSlot(self: *const SlotClock) ?Slot {
    const now_ms = time.nowMs(self.io);
    return slot_math.slotAtMs(self.config, now_ms);
}

pub fn currentEpoch(self: *const SlotClock) ?Epoch {
    const slot = self.currentSlot() orelse return null;
    return slot_math.epochAtSlot(self.config, slot);
}

pub fn currentSlotOrGenesis(self: *const SlotClock) Slot {
    return self.currentSlot() orelse 0;
}

pub fn currentEpochOrGenesis(self: *const SlotClock) Epoch {
    return self.currentEpoch() orelse 0;
}

/// Advances the clock toward `target` one event at a time.  The caller may
/// drop the iterator mid-walk; the clock is then left at the last slot the
/// iterator returned (i.e. partial advancement is observable).
pub fn advanceTo(self: *SlotClock, target: Slot) AdvanceIterator {
    return .{
        .clock = self,
        .target = target,
    };
}

const testing = std.testing;

const FakeClockIo = struct {
    ms: u64 = 0,
    fn vtableNow(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
        _ = clock;
        const self: *const FakeClockIo = @ptrCast(@alignCast(userdata.?));
        return std.Io.Timestamp.fromNanoseconds(@as(i96, @intCast(self.ms)) * std.time.ns_per_ms);
    }
    // Only `now` is populated: SlotClock is pure-read, so no other std.Io
    // vtable entry is ever called. (Clock's async tests use a real io.)
    const vtable: std.Io.VTable = blk: {
        var vt: std.Io.VTable = undefined;
        vt.now = vtableNow;
        break :blk vt;
    };
    fn io(self: *const FakeClockIo) std.Io {
        return .{ .userdata = @constCast(self), .vtable = &vtable };
    }
};

const test_cfg = ClockConfig{
    .genesis_time_sec = 100,
    .slot_duration_ms = 12_000,
    .slots_per_epoch = 32,
    .maximum_gossip_clock_disparity_ms = 500,
};

test "pre-genesis returns null, genesis fallback returns zero" {
    var fake = FakeClockIo{ .ms = 99_000 };
    var clock = try SlotClock.init(test_cfg, fake.io());
    try testing.expectEqual(@as(?Slot, null), clock.currentSlot());
    try testing.expectEqual(@as(?Epoch, null), clock.currentEpoch());
    try testing.expectEqual(@as(Slot, 0), clock.currentSlotOrGenesis());
    try testing.expectEqual(@as(Epoch, 0), clock.currentEpochOrGenesis());
}

test "currentSlot at genesis and advancing" {
    var fake = FakeClockIo{ .ms = 100_000 };
    var clock = try SlotClock.init(test_cfg, fake.io());
    try testing.expectEqual(@as(?Slot, 0), clock.currentSlot());

    fake.ms = 112_000;
    try testing.expectEqual(@as(?Slot, 1), clock.currentSlot());

    fake.ms = 124_000;
    try testing.expectEqual(@as(?Slot, 2), clock.currentSlot());
}

test "currentEpoch" {
    var fake = FakeClockIo{ .ms = 100_000 + 32 * 12 * 1000 };
    var clock = try SlotClock.init(test_cfg, fake.io());
    try testing.expectEqual(@as(?Epoch, 1), clock.currentEpoch());
}

test "advanceTo produces correct slot events" {
    var fake = FakeClockIo{ .ms = 100_000 };
    var clock = try SlotClock.init(test_cfg, fake.io());

    var events: [16]Event = undefined;
    var count: usize = 0;
    var iter = clock.advanceTo(3);
    while (iter.next()) |e| {
        events[count] = e;
        count += 1;
    }

    try testing.expectEqual(@as(usize, 3), count);
    try testing.expect(events[0] == .slot and events[0].slot == 1);
    try testing.expect(events[1] == .slot and events[1].slot == 2);
    try testing.expect(events[2] == .slot and events[2].slot == 3);
    try testing.expectEqual(@as(?Slot, 3), clock.current_slot);
}

test "advanceTo across epoch boundary emits slot then epoch" {
    var fake = FakeClockIo{ .ms = 100_000 };
    var clock = try SlotClock.init(test_cfg, fake.io());
    clock.current_slot = 31;

    var events: [16]Event = undefined;
    var count: usize = 0;
    var iter = clock.advanceTo(33);
    while (iter.next()) |e| {
        events[count] = e;
        count += 1;
    }

    try testing.expectEqual(@as(usize, 3), count);
    try testing.expect(events[0] == .slot and events[0].slot == 32);
    try testing.expect(events[1] == .epoch and events[1].epoch == 1);
    try testing.expect(events[2] == .slot and events[2].slot == 33);
}

test "advanceTo from null (pre-genesis)" {
    var fake = FakeClockIo{ .ms = 99_000 };
    var clock = try SlotClock.init(test_cfg, fake.io());
    try testing.expectEqual(@as(?Slot, null), clock.current_slot);

    var events: [16]Event = undefined;
    var count: usize = 0;
    var iter = clock.advanceTo(2);
    while (iter.next()) |e| {
        events[count] = e;
        count += 1;
    }

    try testing.expectEqual(@as(usize, 3), count);
    try testing.expect(events[0] == .slot and events[0].slot == 0);
    try testing.expect(events[1] == .slot and events[1].slot == 1);
    try testing.expect(events[2] == .slot and events[2].slot == 2);
}

test "advanceTo already at target returns nothing" {
    var fake = FakeClockIo{ .ms = 112_000 };
    var clock = try SlotClock.init(test_cfg, fake.io());

    var count: usize = 0;
    var iter = clock.advanceTo(1);
    while (iter.next()) |_| count += 1;
    try testing.expectEqual(@as(usize, 0), count);
}
