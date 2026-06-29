//! Layer 0 – Pure slot/epoch arithmetic.
//!
//! No state, no allocation, no I/O.  Every function is comptime-compatible.
//! The only `null` is pre-genesis (a `<` comparison); arithmetic uses plain
//! operators since `now_ms` is the wall clock and slot/config values are
//! program-controlled — an overflow would be a program error and traps.

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
    const genesis_ms = secToMs(config.genesis_time_sec);
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
    const now_ms = secToMs(now_sec);
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
    const genesis_ms = secToMs(config.genesis_time_sec);

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
    const genesis_ms = secToMs(config.genesis_time_sec);
    if (now_ms < genesis_ms) return genesis_ms - now_ms;
    // now_ms >= genesis_ms here, so slotAtMs is non-null.
    const slot = slotAtMs(config, now_ms).?;
    const next_slot = slot + 1;
    const next_start = slotStartMs(config, next_slot);
    return next_start - now_ms;
}

fn secToMs(sec: u64) u64 {
    return sec * 1000;
}

const testing = std.testing;

const mainnet = ClockConfig{
    .genesis_time_sec = 1_606_824_023,
    .slot_duration_ms = 12_000,
    .slots_per_epoch = 32,
};

test "basic slot math" {
    // slotAtSec: genesis is slot 0
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

    // slotStartMs across both boundaries
    try testing.expectEqual(@as(u64, f1_ms), slotStartMs(two_fork, 1024));
    try testing.expectEqual(@as(u64, f2_ms), slotStartMs(two_fork, 8192));
    try testing.expectEqual(@as(u64, f2_ms + 4_000), slotStartMs(two_fork, 8193));

    // slotAtMs across both boundaries
    try testing.expectEqual(@as(?Slot, 1024), slotAtMs(two_fork, f1_ms));
    try testing.expectEqual(@as(?Slot, 8191), slotAtMs(two_fork, f2_ms - 1));
    try testing.expectEqual(@as(?Slot, 8192), slotAtMs(two_fork, f2_ms));
    try testing.expectEqual(@as(?Slot, 8193), slotAtMs(two_fork, f2_ms + 4_000));
}
