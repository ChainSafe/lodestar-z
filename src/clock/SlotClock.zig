//! Layer 1 – Stateful slot clock.
//!
//! Wraps `slot_math` with a `TimeSource` and a cached `current_slot`.
//! Pure-read helpers query wall-clock time; only `advanceTo()` mutates the cache.

const std = @import("std");
const slot_math = @import("slot_math.zig");
const time_source = @import("time_source.zig");

const SlotClock = @This();

pub const Slot = slot_math.Slot;
pub const Epoch = slot_math.Epoch;
pub const Config = slot_math.Config;
pub const TimeSource = time_source.TimeSource;

pub const Event = union(enum) {
    slot: Slot,
    epoch: Epoch,
};

pub const AdvanceIterator = struct {
    clock: *SlotClock,
    target: Slot,
    pending_epoch: ?Epoch = null,

    /// Advances the clock one step at a time, yielding slot and epoch events.
    /// For each slot advancement: yields .slot first, then .epoch if an epoch boundary was crossed.
    /// Returns null when caught up to target.
    pub fn next(self: *AdvanceIterator) ?Event {
        // If we have a pending epoch event from the previous step, emit it now
        if (self.pending_epoch) |epoch| {
            self.pending_epoch = null;
            return .{ .epoch = epoch };
        }

        const current = self.clock.current_slot;

        // Genesis case: current_slot is null, advance to slot 0
        if (current == null) {
            self.clock.current_slot = 0;
            return .{ .slot = 0 };
        }

        const cur = current.?;
        if (cur >= self.target) return null;
        if (cur == std.math.maxInt(Slot)) return null;

        const next_slot = cur + 1;
        self.clock.current_slot = next_slot;

        // Check epoch boundary — epochAtSlot returns ?Epoch
        const prev_epoch = slot_math.epochAtSlot(self.clock.config, cur);
        const new_epoch = slot_math.epochAtSlot(self.clock.config, next_slot);
        if (prev_epoch) |prev_ep| {
            if (new_epoch) |new_ep| {
                if (prev_ep < new_ep) {
                    self.pending_epoch = new_ep;
                }
            }
        }

        return .{ .slot = next_slot };
    }
};

config: Config,
time: TimeSource,
current_slot: ?Slot = null,

pub fn init(config: Config, time: TimeSource) error{InvalidConfig}!SlotClock {
    try config.validate();
    var self = SlotClock{
        .config = config,
        .time = time,
    };
    self.current_slot = slot_math.slotAtMs(config, time.nowMs());
    return self;
}

/// Returns the current wall-clock slot. Pure read — does NOT update
/// the internal `current_slot` cache. Only `advanceTo()` advances the cache.
pub fn currentSlot(self: *const SlotClock) ?Slot {
    const now_ms = self.time.nowMs();
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

pub fn currentSlotWithGossipDisparity(self: *const SlotClock) Slot {
    const current = self.currentSlotOrGenesis();
    if (current == std.math.maxInt(Slot)) return current;
    const now_ms = self.time.nowMs();
    const next_slot = current + 1;
    const next_slot_ms = slot_math.slotStartMs(self.config, next_slot) orelse return current;
    return if (next_slot_ms -| now_ms < self.config.maximum_gossip_clock_disparity_ms) next_slot else current;
}

pub fn isCurrentSlotGivenGossipDisparity(self: *const SlotClock, slot: Slot) bool {
    const current = self.currentSlotOrGenesis();
    if (slot == current) return true;

    const now_ms = self.time.nowMs();

    // Check if close to next slot
    if (current != std.math.maxInt(Slot)) {
        const next_slot = current + 1;
        const next_slot_ms = slot_math.slotStartMs(self.config, next_slot) orelse return false;
        if (next_slot_ms -| now_ms < self.config.maximum_gossip_clock_disparity_ms) {
            return slot == next_slot;
        }
    }

    // Check if just passed current slot boundary
    if (current > 0) {
        const current_slot_ms = slot_math.slotStartMs(self.config, current) orelse return false;
        if (now_ms -| current_slot_ms < self.config.maximum_gossip_clock_disparity_ms) {
            return slot == current - 1;
        }
    }

    return false;
}

pub fn slotWithFutureTolerance(self: *const SlotClock, tolerance_ms: u64) ?Slot {
    const now_ms = self.time.nowMs();
    const shifted = @addWithOverflow(now_ms, tolerance_ms);
    if (shifted[1] != 0) return null;
    return slot_math.slotAtMs(self.config, shifted[0]);
}

pub fn slotWithPastTolerance(self: *const SlotClock, tolerance_ms: u64) ?Slot {
    const now_ms = self.time.nowMs();
    // Checked sub: underflow (pre-UNIX-epoch) returns null.
    // Pre-genesis but valid timestamp returns 0.
    const shifted_ms = std.math.sub(u64, now_ms, tolerance_ms) catch return null;
    return slot_math.slotAtMs(self.config, shifted_ms) orelse 0;
}

pub fn secFromSlot(self: *const SlotClock, slot: Slot, to_sec: ?slot_math.UnixSec) ?i64 {
    const from_sec = slot_math.slotStartSec(self.config, slot) orelse return null;
    const end_sec = to_sec orelse @divFloor(self.time.nowMs(), 1000);
    const diff = @as(i128, @intCast(end_sec)) - @as(i128, @intCast(from_sec));
    if (diff < std.math.minInt(i64) or diff > std.math.maxInt(i64)) return null;
    return @intCast(diff);
}

pub fn msFromSlot(self: *const SlotClock, slot: Slot, to_ms: ?slot_math.UnixMs) ?i64 {
    const from_ms = slot_math.slotStartMs(self.config, slot) orelse return null;
    const end_ms = to_ms orelse self.time.nowMs();
    const diff = @as(i128, @intCast(end_ms)) - @as(i128, @intCast(from_ms));
    if (diff < std.math.minInt(i64) or diff > std.math.maxInt(i64)) return null;
    return @intCast(diff);
}

pub fn advanceTo(self: *SlotClock, target: Slot) AdvanceIterator {
    return .{
        .clock = self,
        .target = target,
    };
}

const testing = std.testing;

var fake_ms: slot_math.UnixMs = 0;

fn fakeNowMs(_: ?*anyopaque) slot_math.UnixMs {
    return fake_ms;
}

const fake_time = TimeSource{
    .ctx = null,
    .now_ms_fn = fakeNowMs,
};

const test_cfg = Config{
    .genesis_time_sec = 100,
    .seconds_per_slot = 12,
    .slots_per_epoch = 32,
    .maximum_gossip_clock_disparity_ms = 500,
};

test "pre-genesis returns null, genesis fallback returns zero" {
    fake_ms = 99_000;
    var clock = try SlotClock.init(test_cfg, fake_time);
    try testing.expectEqual(@as(?Slot, null), clock.currentSlot());
    try testing.expectEqual(@as(?Epoch, null), clock.currentEpoch());
    try testing.expectEqual(@as(Slot, 0), clock.currentSlotOrGenesis());
    try testing.expectEqual(@as(Epoch, 0), clock.currentEpochOrGenesis());
}

test "currentSlot at genesis and advancing" {
    fake_ms = 100_000;
    var clock = try SlotClock.init(test_cfg, fake_time);
    try testing.expectEqual(@as(?Slot, 0), clock.currentSlot());

    fake_ms = 112_000;
    try testing.expectEqual(@as(?Slot, 1), clock.currentSlot());

    fake_ms = 124_000;
    try testing.expectEqual(@as(?Slot, 2), clock.currentSlot());
}

test "currentEpoch" {
    fake_ms = 100_000 + 32 * 12 * 1000;
    var clock = try SlotClock.init(test_cfg, fake_time);
    try testing.expectEqual(@as(?Epoch, 1), clock.currentEpoch());
}

test "advanceTo produces correct slot events" {
    fake_ms = 100_000;
    var clock = try SlotClock.init(test_cfg, fake_time);

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
    fake_ms = 100_000;
    var clock = try SlotClock.init(test_cfg, fake_time);
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
    fake_ms = 99_000;
    var clock = try SlotClock.init(test_cfg, fake_time);
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
    fake_ms = 112_000;
    var clock = try SlotClock.init(test_cfg, fake_time);

    var count: usize = 0;
    var iter = clock.advanceTo(1);
    while (iter.next()) |_| count += 1;
    try testing.expectEqual(@as(usize, 0), count);
}

test "gossip disparity: far from boundary" {
    fake_ms = 103_000;
    var clock = try SlotClock.init(test_cfg, fake_time);
    try testing.expectEqual(@as(Slot, 0), clock.currentSlotWithGossipDisparity());
    try testing.expect(clock.isCurrentSlotGivenGossipDisparity(0));
    try testing.expect(!clock.isCurrentSlotGivenGossipDisparity(1));
}

test "gossip disparity: near next slot boundary" {
    fake_ms = 111_600;
    var clock = try SlotClock.init(test_cfg, fake_time);
    try testing.expectEqual(@as(Slot, 1), clock.currentSlotWithGossipDisparity());
    try testing.expect(clock.isCurrentSlotGivenGossipDisparity(1));
}

test "gossip disparity: just after slot boundary" {
    fake_ms = 112_300;
    var clock = try SlotClock.init(test_cfg, fake_time);
    try testing.expect(clock.isCurrentSlotGivenGossipDisparity(0));
}

test "gossip disparity: exact threshold (500ms) does NOT apply" {
    // next_slot_ms - now_ms == 500 → NOT < 500, so disparity doesn't apply
    // Slot 1 starts at 112_000ms. 500ms before = 111_500ms.
    fake_ms = 111_500;
    var clock = try SlotClock.init(test_cfg, fake_time);
    // At exactly the threshold, disparity should NOT bump to next slot
    try testing.expectEqual(@as(Slot, 0), clock.currentSlotWithGossipDisparity());
    try testing.expect(!clock.isCurrentSlotGivenGossipDisparity(1));

    // 1ms closer (111_501): 112_000 - 111_501 = 499 < 500, disparity applies
    fake_ms = 111_501;
    clock = try SlotClock.init(test_cfg, fake_time);
    try testing.expectEqual(@as(Slot, 1), clock.currentSlotWithGossipDisparity());
    try testing.expect(clock.isCurrentSlotGivenGossipDisparity(1));
}

test "tolerance helpers" {
    fake_ms = 112_000;
    var clock = try SlotClock.init(test_cfg, fake_time);
    try testing.expectEqual(@as(?Slot, 2), clock.slotWithFutureTolerance(12_000));
    try testing.expectEqual(@as(?Slot, 0), clock.slotWithPastTolerance(12_000));
    try testing.expectEqual(@as(?Slot, null), clock.slotWithFutureTolerance(std.math.maxInt(u64)));
    // Underflow (tolerance > now_ms) returns null, not 0
    try testing.expectEqual(@as(?Slot, null), clock.slotWithPastTolerance(112_001));
}

test "secFromSlot and msFromSlot" {
    fake_ms = 118_000;
    var clock = try SlotClock.init(test_cfg, fake_time);
    try testing.expectEqual(@as(?i64, 6), clock.secFromSlot(1, null));
    try testing.expectEqual(@as(?i64, 6000), clock.msFromSlot(1, null));
    try testing.expectEqual(@as(?i64, 0), clock.secFromSlot(1, 112));
}
