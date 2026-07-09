//! Pure slot/epoch arithmetic and gossip-disparity/tolerance helpers.
//! No state, no allocation, no I/O; every function is comptime-compatible.
//!
//! Arithmetic uses plain operators — out-of-range values are program errors
//! and trap. `slotWithPastToleranceMs` alone saturates: its underflow is
//! reachable with valid caller data.

const std = @import("std");
const ct = @import("consensus_types");

pub const Slot = ct.primitive.Slot.Type;
pub const Epoch = ct.primitive.Epoch.Type;
pub const ClockConfig = @import("config.zig").ClockConfig;
pub const DurationTransition = @import("config.zig").DurationTransition;
pub const DurationTransitions = @import("config.zig").DurationTransitions;
pub const forkTransitions = @import("config.zig").forkTransitions;

/// Returns the slot at the given Unix-millisecond timestamp,
/// or null if pre-genesis.
/// Precondition: `validate()` accepted `config` — guarantees all durations > 0.
pub fn slotAtMs(config: ClockConfig, now_ms: u64) ?Slot {
    std.debug.assert(config.slot_duration_ms != 0);
    const genesis_ms = config.genesis_time_sec * 1000;
    if (now_ms < genesis_ms) return null;

    var seg_start_slot: Slot = 0;
    var seg_start_ms: u64 = genesis_ms;
    var seg_duration: u64 = config.slot_duration_ms;

    for (config.transitions()) |t| {
        const seg_slots = t.from_slot - seg_start_slot;
        const seg_ms_total = seg_slots * seg_duration;
        if (now_ms - seg_start_ms < seg_ms_total) {
            return seg_start_slot + (now_ms - seg_start_ms) / seg_duration;
        }
        seg_start_ms = seg_start_ms + seg_ms_total;
        seg_start_slot = t.from_slot;
        seg_duration = t.new_duration_ms;
    }

    return seg_start_slot + (now_ms - seg_start_ms) / seg_duration;
}

/// Returns the slot at the given Unix-second timestamp,
/// or null if pre-genesis.
pub fn slotAtSec(config: ClockConfig, now_sec: u64) ?Slot {
    const now_ms = now_sec * 1000;
    return slotAtMs(config, now_ms);
}

/// Slot duration that applies at `slot` — the last transition whose
/// `from_slot <= slot`, else the base `slot_duration_ms`.
pub fn slotDurationMsAt(config: ClockConfig, slot: Slot) u64 {
    var duration = config.slot_duration_ms;
    for (config.transitions()) |t| {
        if (t.from_slot > slot) break;
        duration = t.new_duration_ms;
    }
    return duration;
}

/// Returns the epoch that contains `slot`.
/// Precondition: `validate()` accepted `config` — `slots_per_epoch > 0`.
pub fn epochAtSlot(config: ClockConfig, slot: Slot) Epoch {
    std.debug.assert(config.slots_per_epoch != 0);
    return @divFloor(slot, config.slots_per_epoch);
}

/// Returns the Unix-millisecond start time of `slot`.
pub fn slotStartMs(config: ClockConfig, slot: Slot) u64 {
    const genesis_ms = config.genesis_time_sec * 1000;

    var seg_start_slot: Slot = 0;
    var seg_start_ms: u64 = genesis_ms;
    var seg_duration: u64 = config.slot_duration_ms;

    for (config.transitions()) |t| {
        if (slot < t.from_slot) {
            return seg_start_ms + (slot - seg_start_slot) * seg_duration;
        }
        const seg_slots = t.from_slot - seg_start_slot;
        seg_start_ms = seg_start_ms + seg_slots * seg_duration;
        seg_start_slot = t.from_slot;
        seg_duration = t.new_duration_ms;
    }

    return seg_start_ms + (slot - seg_start_slot) * seg_duration;
}

/// Returns the Unix-second start time of `slot`.
/// Sub-second slot durations truncate to the floor second.
pub fn slotStartSec(config: ClockConfig, slot: Slot) u64 {
    return @divFloor(slotStartMs(config, slot), 1000);
}

/// Milliseconds until the next slot boundary.
/// Pre-genesis: returns the time until genesis.
pub fn msUntilNextSlot(config: ClockConfig, now_ms: u64) u64 {
    const genesis_ms = config.genesis_time_sec * 1000;
    if (now_ms < genesis_ms) return genesis_ms - now_ms;
    // now_ms >= genesis_ms here, so slotAtMs is non-null.
    const slot = slotAtMs(config, now_ms).?;
    const next_slot = slot + 1;
    const next_start = slotStartMs(config, next_slot);
    return next_start - now_ms;
}

/// Returns the slot the network may be advancing to, accounting for gossip
/// clock disparity, or null pre-genesis when no slot is current yet.
///
/// Per phase0/p2p-interface.md, gossip validation rejects future messages with
/// strict `<`, hence `<=` here.
///
/// Assumes the disparity window reaches at most the adjacent slot — true
/// for every real config (500 ms disparity vs seconds-long slots).
pub fn slotWithGossipDisparity(config: ClockConfig, now_ms: u64) ?Slot {
    const current = slotAtMs(config, now_ms) orelse {
        // Pre-genesis the wall slot is conceptually negative, so slot 0 is
        // "current" only once we're within gossip disparity of genesis.
        const genesis_ms = slotStartMs(config, 0);
        return if (genesis_ms - now_ms <= config.maximum_gossip_clock_disparity_ms)
            0
        else
            null;
    };
    const next_slot = current + 1;
    const next_slot_ms = slotStartMs(config, next_slot);
    if (next_slot_ms - now_ms <= config.maximum_gossip_clock_disparity_ms) {
        return next_slot;
    }
    return current;
}

/// See `slotWithGossipDisparity` for the `<=` rationale.
pub fn isCurrentSlotGivenGossipDisparity(config: ClockConfig, slot: Slot, now_ms: u64) bool {
    const current = slotAtMs(config, now_ms) orelse {
        // Slot 0 pre-genesis rule: see slotWithGossipDisparity.
        if (slot != 0) return false;
        const genesis_ms = slotStartMs(config, 0);
        return genesis_ms - now_ms <= config.maximum_gossip_clock_disparity_ms;
    };
    if (slot == current) return true;

    const next_slot = current + 1;
    const next_slot_ms = slotStartMs(config, next_slot);
    if (next_slot_ms - now_ms <= config.maximum_gossip_clock_disparity_ms) {
        return slot == next_slot;
    }

    if (current > 0) {
        const current_slot_ms = slotStartMs(config, current);
        if (now_ms - current_slot_ms <= config.maximum_gossip_clock_disparity_ms) {
            return slot == current - 1;
        }
    }

    return false;
}

pub fn slotWithFutureToleranceMs(config: ClockConfig, now_ms: u64, tolerance_ms: u64) ?Slot {
    const shifted_ms = now_ms + tolerance_ms;
    return slotAtMs(config, shifted_ms);
}

/// Saturating `-|`: `tolerance_ms` is caller data, not program-controlled — clamp, don't trap.
pub fn slotWithPastToleranceMs(config: ClockConfig, now_ms: u64, tolerance_ms: u64) Slot {
    const shifted_ms = now_ms -| tolerance_ms;
    return slotAtMs(config, shifted_ms) orelse 0;
}

pub fn secFromSlot(config: ClockConfig, slot: Slot, to_sec: u64) i64 {
    const from_sec = slotStartSec(config, slot);
    return @as(i64, @intCast(to_sec)) - @as(i64, @intCast(from_sec));
}

pub fn msFromSlot(config: ClockConfig, slot: Slot, to_ms: u64) i64 {
    const from_ms = slotStartMs(config, slot);
    return @as(i64, @intCast(to_ms)) - @as(i64, @intCast(from_ms));
}

const testing = std.testing;

const mainnet = ClockConfig{
    .genesis_time_sec = 1_606_824_023,
    .slot_duration_ms = 12_000,
    .slots_per_epoch = 32,
};

test "basic slot math" {
    try testing.expectEqual(@as(?Slot, 0), slotAtSec(mainnet, mainnet.genesis_time_sec));
    try testing.expectEqual(@as(?Slot, 1), slotAtSec(mainnet, mainnet.genesis_time_sec + 12));
    try testing.expectEqual(@as(?Slot, 2), slotAtSec(mainnet, mainnet.genesis_time_sec + 24));

    const genesis_ms = mainnet.genesis_time_sec * 1000;
    try testing.expectEqual(@as(?Slot, 0), slotAtMs(mainnet, genesis_ms));
    try testing.expectEqual(@as(?Slot, 1), slotAtMs(mainnet, genesis_ms + 12_000));

    try testing.expectEqual(@as(Epoch, 0), epochAtSlot(mainnet, 0));
    try testing.expectEqual(@as(Epoch, 0), epochAtSlot(mainnet, 31));
    try testing.expectEqual(@as(Epoch, 1), epochAtSlot(mainnet, 32));
    try testing.expectEqual(@as(Epoch, 1), epochAtSlot(mainnet, 63));
    try testing.expectEqual(@as(Epoch, 2), epochAtSlot(mainnet, 64));

    try testing.expectEqual(@as(u64, mainnet.genesis_time_sec), slotStartSec(mainnet, 0));
    try testing.expectEqual(@as(u64, mainnet.genesis_time_sec + 12), slotStartSec(mainnet, 1));
    try testing.expectEqual(@as(u64, mainnet.genesis_time_sec + 24), slotStartSec(mainnet, 2));

    try testing.expectEqual(@as(u64, mainnet.genesis_time_sec * 1000), slotStartMs(mainnet, 0));
    try testing.expectEqual(
        @as(u64, (mainnet.genesis_time_sec + 12) * 1000),
        slotStartMs(mainnet, 1),
    );

    try testing.expectEqual(@as(u64, 12_000), slotDurationMsAt(mainnet, 0));
    try testing.expectEqual(@as(u64, 12_000), slotDurationMsAt(mainnet, 1_000_000));
}

test "within-slot timing" {
    try testing.expectEqual(@as(?Slot, 0), slotAtSec(mainnet, mainnet.genesis_time_sec + 0));
    try testing.expectEqual(@as(?Slot, 0), slotAtSec(mainnet, mainnet.genesis_time_sec + 6));
    try testing.expectEqual(@as(?Slot, 0), slotAtSec(mainnet, mainnet.genesis_time_sec + 11));
    try testing.expectEqual(@as(?Slot, 1), slotAtSec(mainnet, mainnet.genesis_time_sec + 12));

    const genesis_ms = mainnet.genesis_time_sec * 1000;
    try testing.expectEqual(@as(?Slot, 0), slotAtMs(mainnet, genesis_ms + 1));
    try testing.expectEqual(@as(?Slot, 0), slotAtMs(mainnet, genesis_ms + 6_000));
    try testing.expectEqual(@as(?Slot, 0), slotAtMs(mainnet, genesis_ms + 11_999));
    try testing.expectEqual(@as(?Slot, 1), slotAtMs(mainnet, genesis_ms + 12_000));
    try testing.expectEqual(@as(?Slot, 1), slotAtMs(mainnet, genesis_ms + 18_000));
    try testing.expectEqual(@as(?Slot, 1), slotAtMs(mainnet, genesis_ms + 23_999));
    try testing.expectEqual(@as(?Slot, 2), slotAtMs(mainnet, genesis_ms + 24_000));
}

test "pre-genesis returns null" {
    try testing.expectEqual(@as(?Slot, null), slotAtSec(mainnet, mainnet.genesis_time_sec - 1));
    try testing.expectEqual(@as(?Slot, null), slotAtSec(mainnet, 0));
    try testing.expectEqual(@as(?Slot, null), slotAtMs(mainnet, 0));
}

test "msUntilNextSlot" {
    const genesis_ms = mainnet.genesis_time_sec * 1000;
    const slot_ms: u64 = 12_000;

    try testing.expectEqual(@as(u64, slot_ms), msUntilNextSlot(mainnet, genesis_ms));
    try testing.expectEqual(@as(u64, slot_ms - 1), msUntilNextSlot(mainnet, genesis_ms + 1));
    try testing.expectEqual(
        @as(u64, slot_ms - 6_000),
        msUntilNextSlot(mainnet, genesis_ms + 6_000),
    );
    try testing.expectEqual(@as(u64, 1), msUntilNextSlot(mainnet, genesis_ms + slot_ms - 1));
    try testing.expectEqual(@as(u64, slot_ms), msUntilNextSlot(mainnet, genesis_ms + slot_ms));
    try testing.expectEqual(@as(u64, 1_000), msUntilNextSlot(mainnet, genesis_ms - 1_000));
    try testing.expectEqual(@as(u64, genesis_ms), msUntilNextSlot(mainnet, 0));
}

test "config validate" {
    try mainnet.validate();

    try testing.expectError(error.InvalidConfig, (ClockConfig{
        .genesis_time_sec = 0,
        .slot_duration_ms = 0,
        .slots_per_epoch = 32,
    }).validate());

    try testing.expectError(error.InvalidConfig, (ClockConfig{
        .genesis_time_sec = 0,
        .slot_duration_ms = 12_000,
        .slots_per_epoch = 0,
    }).validate());

    try testing.expectEqual(@as(u64, 500), mainnet.maximum_gossip_clock_disparity_ms);

    try testing.expectError(error.InvalidConfig, (ClockConfig{
        .genesis_time_sec = std.math.maxInt(u64),
        .slot_duration_ms = 12_000,
        .slots_per_epoch = 32,
    }).validate());

    // Zero new_duration_ms in any transition is invalid
    try testing.expectError(error.InvalidConfig, (ClockConfig{
        .genesis_time_sec = 0,
        .slot_duration_ms = 12_000,
        .duration_transitions = forkTransitions(&.{.{ .from_slot = 1024, .new_duration_ms = 0 }}),
        .slots_per_epoch = 32,
    }).validate());

    // Transitions must be sorted strictly ascending
    try testing.expectError(error.InvalidConfig, (ClockConfig{
        .genesis_time_sec = 0,
        .slot_duration_ms = 12_000,
        .duration_transitions = forkTransitions(&.{
            .{ .from_slot = 2048, .new_duration_ms = 6_000 },
            .{ .from_slot = 1024, .new_duration_ms = 4_000 },
        }),
        .slots_per_epoch = 32,
    }).validate());

    // from_slot == 0 is invalid (a transition at genesis is redundant with slot_duration_ms).
    var bad_zero: DurationTransitions = .{};
    bad_zero.push(.{ .from_slot = 0, .new_duration_ms = 6_000 });
    try testing.expectError(error.InvalidConfig, (ClockConfig{
        .genesis_time_sec = 0,
        .slot_duration_ms = 12_000,
        .duration_transitions = bad_zero,
        .slots_per_epoch = 32,
    }).validate());
}

const eip7782 = ClockConfig{
    .genesis_time_sec = 1_000_000,
    .slot_duration_ms = 12_000,
    .duration_transitions = forkTransitions(&.{.{ .from_slot = 1024, .new_duration_ms = 6_000 }}),
    .slots_per_epoch = 32,
};

test "fork-aware: slotDurationMsAt" {
    try testing.expectEqual(@as(u64, 12_000), slotDurationMsAt(eip7782, 0));
    try testing.expectEqual(@as(u64, 12_000), slotDurationMsAt(eip7782, 1023));
    try testing.expectEqual(@as(u64, 6_000), slotDurationMsAt(eip7782, 1024));
    try testing.expectEqual(@as(u64, 6_000), slotDurationMsAt(eip7782, 2048));
}

test "fork-aware: slotStartMs at and across the boundary" {
    const genesis_ms = eip7782.genesis_time_sec * 1000;

    try testing.expectEqual(@as(u64, genesis_ms), slotStartMs(eip7782, 0));
    try testing.expectEqual(@as(u64, genesis_ms + 12_000), slotStartMs(eip7782, 1));

    const fork_ms = genesis_ms + 1024 * 12_000;
    try testing.expectEqual(@as(u64, fork_ms), slotStartMs(eip7782, 1024));

    try testing.expectEqual(@as(u64, fork_ms + 6_000), slotStartMs(eip7782, 1025));
    try testing.expectEqual(@as(u64, fork_ms + 6_000 * 100), slotStartMs(eip7782, 1124));
}

test "fork-aware: slotAtMs across boundary" {
    const genesis_ms = eip7782.genesis_time_sec * 1000;
    const fork_ms = genesis_ms + 1024 * 12_000;

    try testing.expectEqual(@as(?Slot, 1023), slotAtMs(eip7782, fork_ms - 12_000));
    try testing.expectEqual(@as(?Slot, 1023), slotAtMs(eip7782, fork_ms - 1));
    try testing.expectEqual(@as(?Slot, 1024), slotAtMs(eip7782, fork_ms));
    try testing.expectEqual(@as(?Slot, 1024), slotAtMs(eip7782, fork_ms + 5_999));
    try testing.expectEqual(@as(?Slot, 1025), slotAtMs(eip7782, fork_ms + 6_000));
    try testing.expectEqual(@as(?Slot, 1026), slotAtMs(eip7782, fork_ms + 12_000));
}

test "fork-aware: msUntilNextSlot across boundary" {
    const genesis_ms = eip7782.genesis_time_sec * 1000;
    const fork_ms = genesis_ms + 1024 * 12_000;

    try testing.expectEqual(@as(u64, 1), msUntilNextSlot(eip7782, fork_ms - 1));
    try testing.expectEqual(@as(u64, 6_000), msUntilNextSlot(eip7782, fork_ms));
    try testing.expectEqual(@as(u64, 3_000), msUntilNextSlot(eip7782, fork_ms + 3_000));
}

const two_fork = ClockConfig{
    .genesis_time_sec = 1_000_000,
    .slot_duration_ms = 12_000,
    .duration_transitions = forkTransitions(&.{
        .{ .from_slot = 1024, .new_duration_ms = 6_000 },
        .{ .from_slot = 8192, .new_duration_ms = 4_000 },
    }),
    .slots_per_epoch = 32,
};

test "fork-aware: two transitions" {
    const genesis_ms = two_fork.genesis_time_sec * 1000;
    const f1_ms = genesis_ms + 1024 * 12_000; // first fork boundary
    // Slots 1024..8191 are 6s each → 7168 slots × 6_000 ms
    const f2_ms = f1_ms + (8192 - 1024) * 6_000; // second fork boundary

    try testing.expectEqual(@as(u64, 12_000), slotDurationMsAt(two_fork, 0));
    try testing.expectEqual(@as(u64, 6_000), slotDurationMsAt(two_fork, 1024));
    try testing.expectEqual(@as(u64, 4_000), slotDurationMsAt(two_fork, 8192));

    try testing.expectEqual(@as(u64, f1_ms), slotStartMs(two_fork, 1024));
    try testing.expectEqual(@as(u64, f2_ms), slotStartMs(two_fork, 8192));
    try testing.expectEqual(@as(u64, f2_ms + 4_000), slotStartMs(two_fork, 8193));

    try testing.expectEqual(@as(?Slot, 1024), slotAtMs(two_fork, f1_ms));
    try testing.expectEqual(@as(?Slot, 8191), slotAtMs(two_fork, f2_ms - 1));
    try testing.expectEqual(@as(?Slot, 8192), slotAtMs(two_fork, f2_ms));
    try testing.expectEqual(@as(?Slot, 8193), slotAtMs(two_fork, f2_ms + 4_000));
}

const test_cfg = ClockConfig{
    .genesis_time_sec = 100,
    .slot_duration_ms = 12_000,
    .slots_per_epoch = 32,
    .maximum_gossip_clock_disparity_ms = 500,
};
const test_genesis_ms: u64 = test_cfg.genesis_time_sec * 1000;
const test_disparity_ms: u64 = test_cfg.maximum_gossip_clock_disparity_ms;
const test_slot_1_start_ms: u64 = test_genesis_ms + test_cfg.slot_duration_ms;

test "gossip disparity: far from boundary" {
    const now = test_genesis_ms + 3_000;
    try testing.expectEqual(@as(?Slot, 0), slotWithGossipDisparity(test_cfg, now));
    try testing.expect(isCurrentSlotGivenGossipDisparity(test_cfg, 0, now));
    try testing.expect(!isCurrentSlotGivenGossipDisparity(test_cfg, 1, now));
}

test "gossip disparity: near next slot boundary" {
    const now = test_slot_1_start_ms - 400;
    try testing.expectEqual(@as(?Slot, 1), slotWithGossipDisparity(test_cfg, now));
    try testing.expect(isCurrentSlotGivenGossipDisparity(test_cfg, 1, now));
}

test "gossip disparity: just after slot boundary" {
    try testing.expect(
        isCurrentSlotGivenGossipDisparity(test_cfg, 0, test_slot_1_start_ms + 300),
    );
}

test "gossip disparity: exact threshold applies inclusively" {
    const edge = test_slot_1_start_ms - test_disparity_ms;
    try testing.expectEqual(@as(?Slot, 1), slotWithGossipDisparity(test_cfg, edge));
    try testing.expect(isCurrentSlotGivenGossipDisparity(test_cfg, 1, edge));

    try testing.expectEqual(@as(?Slot, 0), slotWithGossipDisparity(test_cfg, edge - 1));
    try testing.expect(!isCurrentSlotGivenGossipDisparity(test_cfg, 1, edge - 1));
}

test "gossip disparity: pre-genesis slot 0 only within disparity of genesis" {
    const far_before = test_genesis_ms - 1_000;
    try testing.expectEqual(@as(?Slot, null), slotWithGossipDisparity(test_cfg, far_before));
    try testing.expect(!isCurrentSlotGivenGossipDisparity(test_cfg, 0, far_before));
    try testing.expect(!isCurrentSlotGivenGossipDisparity(test_cfg, 1, far_before));

    const within = test_genesis_ms - 300;
    try testing.expectEqual(@as(?Slot, 0), slotWithGossipDisparity(test_cfg, within));
    try testing.expect(isCurrentSlotGivenGossipDisparity(test_cfg, 0, within));
    try testing.expect(!isCurrentSlotGivenGossipDisparity(test_cfg, 1, within));

    const edge = test_genesis_ms - test_disparity_ms;
    try testing.expectEqual(@as(?Slot, 0), slotWithGossipDisparity(test_cfg, edge));
    try testing.expect(isCurrentSlotGivenGossipDisparity(test_cfg, 0, edge));

    try testing.expectEqual(@as(?Slot, null), slotWithGossipDisparity(test_cfg, edge - 1));
    try testing.expect(!isCurrentSlotGivenGossipDisparity(test_cfg, 0, edge - 1));
}

test "gossip disparity: pre-genesis with sub-disparity slot duration never advances past 0" {
    // Degenerate config (slot_duration 400 ms < disparity 500 ms): a
    // pre-genesis clamp to slot 0 must not spuriously report slot 1.
    const cfg = ClockConfig{
        .genesis_time_sec = 100,
        .slot_duration_ms = 400,
        .slots_per_epoch = 8,
        .maximum_gossip_clock_disparity_ms = 500,
    };
    const cfg_genesis_ms: u64 = cfg.genesis_time_sec * 1000;

    try testing.expectEqual(@as(?Slot, 0), slotWithGossipDisparity(cfg, cfg_genesis_ms - 1));
    try testing.expect(!isCurrentSlotGivenGossipDisparity(cfg, 1, cfg_genesis_ms - 1));

    try testing.expectEqual(
        @as(?Slot, null),
        slotWithGossipDisparity(cfg, cfg_genesis_ms - cfg.maximum_gossip_clock_disparity_ms - 1),
    );
}

test "tolerance helpers" {
    const one_slot = test_cfg.slot_duration_ms;
    try testing.expectEqual(
        @as(?Slot, 2),
        slotWithFutureToleranceMs(test_cfg, test_slot_1_start_ms, one_slot),
    );
    try testing.expectEqual(
        @as(Slot, 0),
        slotWithPastToleranceMs(test_cfg, test_slot_1_start_ms, one_slot),
    );
    // Pins operand order: a swapped `tolerance_ms - now_ms` saturates pre-genesis → slot 0.
    try testing.expectEqual(
        @as(Slot, 3),
        slotWithPastToleranceMs(test_cfg, test_genesis_ms + 4 * one_slot, one_slot),
    );
    // tolerance > now saturates to 0 ms (pre-genesis → slot 0); a plain `-` would trap.
    try testing.expectEqual(
        @as(Slot, 0),
        slotWithPastToleranceMs(test_cfg, test_genesis_ms, test_genesis_ms + 1),
    );
}

test "secFromSlot and msFromSlot" {
    const slot_1_start_sec = test_slot_1_start_ms / 1000;
    try testing.expectEqual(@as(i64, 6), secFromSlot(test_cfg, 1, slot_1_start_sec + 6));
    try testing.expectEqual(@as(i64, 6000), msFromSlot(test_cfg, 1, test_slot_1_start_ms + 6_000));
    try testing.expectEqual(@as(i64, 0), secFromSlot(test_cfg, 1, slot_1_start_sec));
    try testing.expectEqual(@as(i64, -12), secFromSlot(test_cfg, 1, test_cfg.genesis_time_sec));
    try testing.expectEqual(@as(i64, -12000), msFromSlot(test_cfg, 1, test_genesis_ms));
}
