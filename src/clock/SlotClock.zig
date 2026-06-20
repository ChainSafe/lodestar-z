//! Layer 1 – Stateful slot clock.
//!
//! Wraps `slot_math` with a time source and a cached `current_slot`.
//! Pure-read helpers query wall-clock time; only `advanceTo()` mutates the cache.

const std = @import("std");
const slot_math = @import("slot_math.zig");

pub const Slot = slot_math.Slot;
pub const Epoch = slot_math.Epoch;
pub const ClockConfig = slot_math.ClockConfig;

pub const Event = union(enum) {
    slot: Slot,
    epoch: Epoch,
};

/// `Time` is duck-typed: it must expose `nowMs(self) u64`. A value type
/// (e.g. `RealTime`) and a pointer to a mutable source (e.g. `*FakeTime`)
/// both satisfy this.
pub fn Clock(comptime Time: type) type {
    return struct {
        const Self = @This();

        config: ClockConfig,
        time: Time,
        current_slot: ?Slot = null,

        pub const AdvanceIterator = struct {
            clock: *Self,
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
                if (cur == std.math.maxInt(Slot)) return null;

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

        pub fn init(config: ClockConfig, time: Time) error{InvalidConfig}!Self {
            try config.validate();
            var self = Self{
                .config = config,
                .time = time,
            };
            self.current_slot = slot_math.slotAtMs(config, time.nowMs());
            return self;
        }

        /// Returns the current wall-clock slot. Pure read — does NOT update
        /// the internal `current_slot` cache. Only `advanceTo()` advances the cache.
        pub fn currentSlot(self: *const Self) ?Slot {
            const now_ms = self.time.nowMs();
            return slot_math.slotAtMs(self.config, now_ms);
        }

        pub fn currentEpoch(self: *const Self) ?Epoch {
            const slot = self.currentSlot() orelse return null;
            return slot_math.epochAtSlot(self.config, slot);
        }

        pub fn currentSlotOrGenesis(self: *const Self) Slot {
            return self.currentSlot() orelse 0;
        }

        pub fn currentEpochOrGenesis(self: *const Self) Epoch {
            return self.currentEpoch() orelse 0;
        }

        /// Returns the slot the network may be advancing to, accounting for gossip
        /// clock disparity, or null pre-genesis when no slot is current yet.
        ///
        /// Per phase0/p2p-interface.md, gossip validation rejects future messages with
        /// strict `<` (`current_time + MAXIMUM_GOSSIP_CLOCK_DISPARITY < message_time`),
        /// so the boundary case (exactly equal) is accepted — hence `<=` here.
        ///
        /// Assumes the disparity window reaches at most the adjacent slot — true
        /// for every real config (500 ms disparity vs seconds-long slots). A
        /// config where disparity approaches or exceeds the slot duration is not
        /// supported.
        pub fn currentSlotWithGossipDisparity(self: *const Self) ?Slot {
            const now_ms = self.time.nowMs();
            const current = slot_math.slotAtMs(self.config, now_ms) orelse {
                // Pre-genesis the wall slot is conceptually negative, so slot 0 is
                // "current" only once we're within gossip disparity of genesis;
                // null otherwise.
                const genesis_ms = slot_math.slotStartMs(self.config, 0) orelse return null;
                return if (genesis_ms - now_ms <= self.config.maximum_gossip_clock_disparity_ms)
                    0
                else
                    null;
            };
            if (current == std.math.maxInt(Slot)) return current;
            const next_slot = current + 1;
            const next_slot_ms = slot_math.slotStartMs(self.config, next_slot) orelse
                return current;
            if (next_slot_ms - now_ms <= self.config.maximum_gossip_clock_disparity_ms) {
                return next_slot;
            }
            return current;
        }

        /// See `currentSlotWithGossipDisparity` for the `<=` rationale and the
        /// single-snapshot semantics — both apply here too.
        pub fn isCurrentSlotGivenGossipDisparity(self: *const Self, slot: Slot) bool {
            const now_ms = self.time.nowMs();
            const current = slot_math.slotAtMs(self.config, now_ms) orelse {
                // Pre-genesis the wall slot is conceptually negative, so slot 0 is
                // "current" only once we're within gossip disparity of genesis.
                if (slot != 0) return false;
                const genesis_ms = slot_math.slotStartMs(self.config, 0) orelse return false;
                return genesis_ms - now_ms <= self.config.maximum_gossip_clock_disparity_ms;
            };
            if (slot == current) return true;

            if (current != std.math.maxInt(Slot)) {
                const next_slot = current + 1;
                const next_slot_ms = slot_math.slotStartMs(self.config, next_slot) orelse
                    return false;
                if (next_slot_ms - now_ms <= self.config.maximum_gossip_clock_disparity_ms) {
                    return slot == next_slot;
                }
            }

            if (current > 0) {
                const current_slot_ms = slot_math.slotStartMs(self.config, current) orelse
                    return false;
                if (now_ms - current_slot_ms <= self.config.maximum_gossip_clock_disparity_ms) {
                    return slot == current - 1;
                }
            }

            return false;
        }

        pub fn slotWithFutureToleranceMs(self: *const Self, tolerance_ms: u64) ?Slot {
            const now_ms = self.time.nowMs();
            const shifted_ms = std.math.add(u64, now_ms, tolerance_ms) catch return null;
            return slot_math.slotAtMs(self.config, shifted_ms);
        }

        pub fn slotWithPastToleranceMs(self: *const Self, tolerance_ms: u64) ?Slot {
            const now_ms = self.time.nowMs();
            // Checked sub: underflow (pre-UNIX-epoch) returns null.
            // Pre-genesis but valid timestamp returns 0.
            const shifted_ms = std.math.sub(u64, now_ms, tolerance_ms) catch return null;
            return slot_math.slotAtMs(self.config, shifted_ms) orelse 0;
        }

        pub fn secFromSlot(self: *const Self, slot: Slot, to_sec: ?u64) ?i64 {
            const from_sec = slot_math.slotStartSec(self.config, slot) orelse return null;
            const end_sec = to_sec orelse @divFloor(self.time.nowMs(), 1000);
            const diff = @as(i128, @intCast(end_sec)) - @as(i128, @intCast(from_sec));
            return std.math.cast(i64, diff);
        }

        pub fn msFromSlot(self: *const Self, slot: Slot, to_ms: ?u64) ?i64 {
            const from_ms = slot_math.slotStartMs(self.config, slot) orelse return null;
            const end_ms = to_ms orelse self.time.nowMs();
            const diff = @as(i128, @intCast(end_ms)) - @as(i128, @intCast(from_ms));
            return std.math.cast(i64, diff);
        }

        /// Advances the clock toward `target` one event at a time.  The caller may
        /// drop the iterator mid-walk; the clock is then left at the last slot the
        /// iterator returned (i.e. partial advancement is observable).
        pub fn advanceTo(self: *Self, target: Slot) AdvanceIterator {
            return .{
                .clock = self,
                .target = target,
            };
        }
    };
}

const testing = std.testing;
const time_source = @import("time_source.zig");
const FakeTime = time_source.FakeTime;
const FakeClock = Clock(*FakeTime);

const test_cfg = ClockConfig{
    .genesis_time_sec = 100,
    .slot_duration_ms = 12_000,
    .slots_per_epoch = 32,
    .maximum_gossip_clock_disparity_ms = 500,
};

test "pre-genesis returns null, genesis fallback returns zero" {
    var fake = FakeTime{ .ms = 99_000 };
    var clock = try FakeClock.init(test_cfg, &fake);
    try testing.expectEqual(@as(?Slot, null), clock.currentSlot());
    try testing.expectEqual(@as(?Epoch, null), clock.currentEpoch());
    try testing.expectEqual(@as(Slot, 0), clock.currentSlotOrGenesis());
    try testing.expectEqual(@as(Epoch, 0), clock.currentEpochOrGenesis());
}

test "currentSlot at genesis and advancing" {
    var fake = FakeTime{ .ms = 100_000 };
    var clock = try FakeClock.init(test_cfg, &fake);
    try testing.expectEqual(@as(?Slot, 0), clock.currentSlot());

    fake.setMs(112_000);
    try testing.expectEqual(@as(?Slot, 1), clock.currentSlot());

    fake.setMs(124_000);
    try testing.expectEqual(@as(?Slot, 2), clock.currentSlot());
}

test "currentEpoch" {
    var fake = FakeTime{ .ms = 100_000 + 32 * 12 * 1000 };
    var clock = try FakeClock.init(test_cfg, &fake);
    try testing.expectEqual(@as(?Epoch, 1), clock.currentEpoch());
}

test "advanceTo produces correct slot events" {
    var fake = FakeTime{ .ms = 100_000 };
    var clock = try FakeClock.init(test_cfg, &fake);

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
    var fake = FakeTime{ .ms = 100_000 };
    var clock = try FakeClock.init(test_cfg, &fake);
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
    var fake = FakeTime{ .ms = 99_000 };
    var clock = try FakeClock.init(test_cfg, &fake);
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
    var fake = FakeTime{ .ms = 112_000 };
    var clock = try FakeClock.init(test_cfg, &fake);

    var count: usize = 0;
    var iter = clock.advanceTo(1);
    while (iter.next()) |_| count += 1;
    try testing.expectEqual(@as(usize, 0), count);
}

test "gossip disparity: far from boundary" {
    var fake = FakeTime{ .ms = 103_000 };
    var clock = try FakeClock.init(test_cfg, &fake);
    try testing.expectEqual(@as(?Slot, 0), clock.currentSlotWithGossipDisparity());
    try testing.expect(clock.isCurrentSlotGivenGossipDisparity(0));
    try testing.expect(!clock.isCurrentSlotGivenGossipDisparity(1));
}

test "gossip disparity: near next slot boundary" {
    var fake = FakeTime{ .ms = 111_600 };
    var clock = try FakeClock.init(test_cfg, &fake);
    try testing.expectEqual(@as(?Slot, 1), clock.currentSlotWithGossipDisparity());
    try testing.expect(clock.isCurrentSlotGivenGossipDisparity(1));
}

test "gossip disparity: just after slot boundary" {
    var fake = FakeTime{ .ms = 112_300 };
    var clock = try FakeClock.init(test_cfg, &fake);
    try testing.expect(clock.isCurrentSlotGivenGossipDisparity(0));
}

test "gossip disparity: exact threshold (500ms) applies inclusively" {
    // next_slot_ms - now_ms == 500 → 500 <= 500, disparity applies.
    // Slot 1 starts at 112_000ms. 500ms before = 111_500ms.
    var fake = FakeTime{ .ms = 111_500 };
    var clock = try FakeClock.init(test_cfg, &fake);
    try testing.expectEqual(@as(?Slot, 1), clock.currentSlotWithGossipDisparity());
    try testing.expect(clock.isCurrentSlotGivenGossipDisparity(1));

    // 1ms further out (111_499): 112_000 - 111_499 = 501 > 500, disparity does NOT apply.
    fake.setMs(111_499);
    clock = try FakeClock.init(test_cfg, &fake);
    try testing.expectEqual(@as(?Slot, 0), clock.currentSlotWithGossipDisparity());
    try testing.expect(!clock.isCurrentSlotGivenGossipDisparity(1));
}

test "gossip disparity: pre-genesis slot 0 only within disparity of genesis" {
    // Genesis is 100_000ms; disparity is 500ms.
    // 1000ms before genesis: slot 0 is not yet "current".
    var fake = FakeTime{ .ms = 99_000 };
    var clock = try FakeClock.init(test_cfg, &fake);
    try testing.expectEqual(@as(?Slot, null), clock.currentSlotWithGossipDisparity());
    try testing.expect(!clock.isCurrentSlotGivenGossipDisparity(0));
    try testing.expect(!clock.isCurrentSlotGivenGossipDisparity(1));

    // 300ms before genesis: within disparity, slot 0 is "current".
    fake.setMs(99_700);
    clock = try FakeClock.init(test_cfg, &fake);
    try testing.expectEqual(@as(?Slot, 0), clock.currentSlotWithGossipDisparity());
    try testing.expect(clock.isCurrentSlotGivenGossipDisparity(0));
    try testing.expect(!clock.isCurrentSlotGivenGossipDisparity(1));

    // Exact threshold: 500ms before genesis is inclusive.
    fake.setMs(99_500);
    clock = try FakeClock.init(test_cfg, &fake);
    try testing.expectEqual(@as(?Slot, 0), clock.currentSlotWithGossipDisparity());
    try testing.expect(clock.isCurrentSlotGivenGossipDisparity(0));

    // 1ms further out (501ms before genesis): not "current".
    fake.setMs(99_499);
    clock = try FakeClock.init(test_cfg, &fake);
    try testing.expectEqual(@as(?Slot, null), clock.currentSlotWithGossipDisparity());
    try testing.expect(!clock.isCurrentSlotGivenGossipDisparity(0));
}

test "gossip disparity: pre-genesis with sub-disparity slot duration never advances past 0" {
    // Degenerate config: slot_duration (400ms) <= disparity (500ms). With `slotAtMs
    // orelse 0`, pre-genesis would clamp to slot 0, see next_slot 1 start within
    // disparity, and spuriously report slot 1; null/0 semantics must hold instead.
    const cfg = ClockConfig{
        .genesis_time_sec = 100, // genesis_ms = 100_000
        .slot_duration_ms = 400,
        .slots_per_epoch = 8,
        .maximum_gossip_clock_disparity_ms = 500,
    };

    // 1ms before genesis (within disparity): slot 0, never slot 1.
    var fake = FakeTime{ .ms = 99_999 };
    var clock = try FakeClock.init(cfg, &fake);
    try testing.expectEqual(@as(?Slot, 0), clock.currentSlotWithGossipDisparity());
    try testing.expect(!clock.isCurrentSlotGivenGossipDisparity(1));

    // 501ms before genesis (just outside disparity): no slot is current.
    fake.setMs(99_499);
    clock = try FakeClock.init(cfg, &fake);
    try testing.expectEqual(@as(?Slot, null), clock.currentSlotWithGossipDisparity());
}

test "tolerance helpers" {
    var fake = FakeTime{ .ms = 112_000 };
    var clock = try FakeClock.init(test_cfg, &fake);
    try testing.expectEqual(@as(?Slot, 2), clock.slotWithFutureToleranceMs(12_000));
    try testing.expectEqual(@as(?Slot, 0), clock.slotWithPastToleranceMs(12_000));
    try testing.expectEqual(
        @as(?Slot, null),
        clock.slotWithFutureToleranceMs(std.math.maxInt(u64)),
    );
    // Underflow (tolerance > now_ms) returns null, not 0
    try testing.expectEqual(@as(?Slot, null), clock.slotWithPastToleranceMs(112_001));
}

test "secFromSlot and msFromSlot" {
    var fake = FakeTime{ .ms = 118_000 };
    var clock = try FakeClock.init(test_cfg, &fake);
    try testing.expectEqual(@as(?i64, 6), clock.secFromSlot(1, null));
    try testing.expectEqual(@as(?i64, 6000), clock.msFromSlot(1, null));
    try testing.expectEqual(@as(?i64, 0), clock.secFromSlot(1, 112));
}
