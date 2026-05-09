//! Layer 0 – Pure slot/epoch arithmetic.
//!
//! No state, no allocation, no I/O.  Every function is comptime-compatible.
//! All overflow paths return `null` (`?T`) instead of panicking.

const std = @import("std");

// ── Type aliases ──────────────────────────────────────────────────────

pub const Slot = u64;
pub const Epoch = u64;
pub const UnixMs = u64;
pub const UnixSec = u64;

// ── Config ────────────────────────────────────────────────────────────

/// One slot-duration override that takes effect from `from_slot` onwards.
/// `from_slot == 0` is reserved as a sentinel for "unused entry" inside
/// `Config.duration_transitions` (and rejected by `validate()` for any
/// active entry).
pub const DurationTransition = struct {
    from_slot: Slot,
    new_duration_ms: u64,
};

/// Upper bound on slot-duration transitions a chain may carry. Slot
/// duration is a fundamental chain parameter that's expected to change
/// rarely (Ethereum has had zero changes since beacon chain genesis;
/// EIP-7782 anticipates one). 4 leaves slack for any far-future plans.
pub const max_duration_transitions: usize = 4;

const DurationTransitions = [max_duration_transitions]DurationTransition;

/// Comptime-friendly builder for `Config.duration_transitions`. Pads
/// trailing slots with the `from_slot = 0` sentinel.
pub fn forkTransitions(
    comptime list: []const DurationTransition,
) DurationTransitions {
    if (list.len > max_duration_transitions) {
        @compileError("too many slot duration transitions");
    }
    var arr: DurationTransitions = @splat(.{ .from_slot = 0, .new_duration_ms = 0 });
    inline for (list, 0..) |t, i| arr[i] = t;
    return arr;
}

/// - `slot_duration_ms` is the duration from genesis until the first
///   transition (or for the entire chain if none).
/// - `duration_transitions` carries later overrides (e.g. EIP-7782 6s slots).
///   Default is all-sentinel — Ethereum mainnet today has no slot-duration change.
///
/// Active entries must be sorted ascending by `from_slot`, have non-zero
/// `new_duration_ms`, and have `from_slot != 0` (validated).
pub const Config = struct {
    genesis_time_sec: UnixSec,
    slot_duration_ms: u64,
    duration_transitions: DurationTransitions = @splat(.{ .from_slot = 0, .new_duration_ms = 0 }),
    slots_per_epoch: u64,
    maximum_gossip_clock_disparity_ms: u64 = 500,

    pub fn validate(self: Config) error{InvalidConfig}!void {
        if (self.slot_duration_ms == 0) return error.InvalidConfig;
        if (self.slots_per_epoch == 0) return error.InvalidConfig;
        if (secToMs(self.genesis_time_sec) == null) return error.InvalidConfig;
        var prev_slot: Slot = 0;
        var seen_sentinel = false;
        for (self.duration_transitions) |t| {
            if (t.from_slot == 0) {
                // Sentinel ⇒ all later slots must also be sentinels.
                if (t.new_duration_ms != 0) return error.InvalidConfig;
                seen_sentinel = true;
                continue;
            }
            if (seen_sentinel) return error.InvalidConfig;
            if (t.new_duration_ms == 0) return error.InvalidConfig;
            if (t.from_slot <= prev_slot) return error.InvalidConfig;
            prev_slot = t.from_slot;
        }
    }

    /// Returns the active prefix of `duration_transitions` (slice up to
    /// the first sentinel). Each call rescans the inline array; that's
    /// O(max_duration_transitions) which is constant and tiny.
    pub fn transitions(self: *const Config) []const DurationTransition {
        var n: usize = 0;
        while (n < max_duration_transitions and
            self.duration_transitions[n].from_slot != 0) : (n += 1)
        {}
        return self.duration_transitions[0..n];
    }

    /// Slot duration in ms applicable at `slot`. Walks active transitions
    /// from latest to earliest; returns the active override, or
    /// `slot_duration_ms` if no transition has fired yet.
    pub fn slotDurationMsAt(self: Config, slot: Slot) u64 {
        const active = self.transitions();
        var i: usize = active.len;
        while (i > 0) {
            i -= 1;
            if (active[i].from_slot <= slot) return active[i].new_duration_ms;
        }
        return self.slot_duration_ms;
    }
};

/// Returns the slot at the given Unix-millisecond timestamp,
/// or null if pre-genesis or on overflow.
pub fn slotAtMs(config: Config, now_ms: UnixMs) ?Slot {
    const genesis_ms = secToMs(config.genesis_time_sec) orelse return null;
    if (now_ms < genesis_ms) return null;

    // Walk segments cumulatively. The first segment starts at slot 0
    // with `slot_duration_ms`; each transition opens a new segment.
    var seg_start_slot: Slot = 0;
    var seg_start_ms: UnixMs = genesis_ms;
    var seg_duration: u64 = config.slot_duration_ms;

    for (config.transitions()) |t| {
        const seg_slots = t.from_slot - seg_start_slot;
        const seg_ms_total = std.math.mul(u64, seg_slots, seg_duration) catch {
            // Segment overflows ms — `now_ms` cannot exceed it.
            if (seg_duration == 0) return null;
            return seg_start_slot + (now_ms - seg_start_ms) / seg_duration;
        };
        if (now_ms - seg_start_ms < seg_ms_total) {
            if (seg_duration == 0) return null;
            return seg_start_slot + (now_ms - seg_start_ms) / seg_duration;
        }
        seg_start_ms = std.math.add(u64, seg_start_ms, seg_ms_total) catch return null;
        seg_start_slot = t.from_slot;
        seg_duration = t.new_duration_ms;
    }

    if (seg_duration == 0) return null;
    return seg_start_slot + (now_ms - seg_start_ms) / seg_duration;
}

/// Returns the slot at the given Unix-second timestamp,
/// or null if pre-genesis or on overflow.
pub fn slotAtSec(config: Config, now_sec: UnixSec) ?Slot {
    return slotAtMs(config, secToMs(now_sec) orelse return null);
}

/// Returns the epoch that contains `slot`, or null if slots_per_epoch is zero.
pub fn epochAtSlot(config: Config, slot: Slot) ?Epoch {
    if (config.slots_per_epoch == 0) return null;
    return @divFloor(slot, config.slots_per_epoch);
}

/// Returns the Unix-millisecond start time of `slot`, or null on overflow.
pub fn slotStartMs(config: Config, slot: Slot) ?UnixMs {
    const genesis_ms = secToMs(config.genesis_time_sec) orelse return null;

    var seg_start_slot: Slot = 0;
    var seg_start_ms: UnixMs = genesis_ms;
    var seg_duration: u64 = config.slot_duration_ms;

    for (config.transitions()) |t| {
        if (slot < t.from_slot) {
            const offset = std.math.mul(u64, slot - seg_start_slot, seg_duration) catch return null;
            return std.math.add(u64, seg_start_ms, offset) catch null;
        }
        const seg_slots = t.from_slot - seg_start_slot;
        const seg_ms_total = std.math.mul(u64, seg_slots, seg_duration) catch return null;
        seg_start_ms = std.math.add(u64, seg_start_ms, seg_ms_total) catch return null;
        seg_start_slot = t.from_slot;
        seg_duration = t.new_duration_ms;
    }

    const offset = std.math.mul(u64, slot - seg_start_slot, seg_duration) catch return null;
    return std.math.add(u64, seg_start_ms, offset) catch null;
}

/// Returns the Unix-second start time of `slot`, or null on overflow.
/// Sub-second slot durations truncate to the floor second.
pub fn slotStartSec(config: Config, slot: Slot) ?UnixSec {
    const ms = slotStartMs(config, slot) orelse return null;
    return @divFloor(ms, 1000);
}

/// Milliseconds until the next slot boundary.
/// Pre-genesis: returns the time until genesis.
/// Returns null only on arithmetic overflow.
pub fn msUntilNextSlot(config: Config, now_ms: UnixMs) ?u64 {
    const genesis_ms = secToMs(config.genesis_time_sec) orelse return null;
    if (now_ms < genesis_ms) return genesis_ms - now_ms;
    const slot = slotAtMs(config, now_ms) orelse return null;
    // Checked: at the maximum representable slot, `slot + 1` would wrap.
    const next_slot = std.math.add(u64, slot, 1) catch return null;
    const next_start = slotStartMs(config, next_slot) orelse return null;
    return next_start - now_ms;
}

fn secToMs(sec: u64) ?u64 {
    return std.math.mul(u64, sec, 1000) catch return null;
}

const testing = std.testing;

const mainnet = Config{
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

    try testing.expectEqual(@as(?Epoch, 0), epochAtSlot(mainnet, 0));
    try testing.expectEqual(@as(?Epoch, 0), epochAtSlot(mainnet, 31));
    try testing.expectEqual(@as(?Epoch, 1), epochAtSlot(mainnet, 32));
    try testing.expectEqual(@as(?Epoch, 1), epochAtSlot(mainnet, 63));
    try testing.expectEqual(@as(?Epoch, 2), epochAtSlot(mainnet, 64));

    try testing.expectEqual(@as(?UnixSec, mainnet.genesis_time_sec), slotStartSec(mainnet, 0));
    try testing.expectEqual(@as(?UnixSec, mainnet.genesis_time_sec + 12), slotStartSec(mainnet, 1));
    try testing.expectEqual(@as(?UnixSec, mainnet.genesis_time_sec + 24), slotStartSec(mainnet, 2));

    try testing.expectEqual(@as(?UnixMs, mainnet.genesis_time_sec * 1000), slotStartMs(mainnet, 0));
    try testing.expectEqual(@as(?UnixMs, (mainnet.genesis_time_sec + 12) * 1000), slotStartMs(mainnet, 1));

    try testing.expectEqual(@as(u64, 12_000), mainnet.slotDurationMsAt(0));
    try testing.expectEqual(@as(u64, 12_000), mainnet.slotDurationMsAt(1_000_000));
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

test "overflow safety" {
    try testing.expectEqual(@as(?Slot, null), slotAtSec(mainnet, mainnet.genesis_time_sec - 1));
    try testing.expectEqual(@as(?Slot, null), slotAtSec(mainnet, 0));
    try testing.expectEqual(@as(?Slot, null), slotAtMs(mainnet, 0));

    try testing.expectEqual(@as(?UnixSec, null), slotStartSec(mainnet, std.math.maxInt(u64)));
    try testing.expectEqual(@as(?UnixMs, null), slotStartMs(mainnet, std.math.maxInt(u64)));

    const extreme = Config{
        .genesis_time_sec = std.math.maxInt(u64),
        .slot_duration_ms = 12_000,
        .slots_per_epoch = 32,
    };
    try testing.expectEqual(@as(?Slot, null), slotAtMs(extreme, 0));
    try testing.expectEqual(@as(?UnixSec, null), slotStartSec(extreme, 1));
    try testing.expectEqual(@as(?UnixMs, null), slotStartMs(extreme, 0));

    try testing.expectEqual(@as(?u64, null), msUntilNextSlot(extreme, 0));
}

test "msUntilNextSlot" {
    const genesis_ms = mainnet.genesis_time_sec * 1000;
    const slot_ms: u64 = 12_000;

    try testing.expectEqual(@as(?u64, slot_ms), msUntilNextSlot(mainnet, genesis_ms));
    try testing.expectEqual(@as(?u64, slot_ms - 1), msUntilNextSlot(mainnet, genesis_ms + 1));
    try testing.expectEqual(@as(?u64, slot_ms - 6_000), msUntilNextSlot(mainnet, genesis_ms + 6_000));
    try testing.expectEqual(@as(?u64, 1), msUntilNextSlot(mainnet, genesis_ms + slot_ms - 1));
    try testing.expectEqual(@as(?u64, slot_ms), msUntilNextSlot(mainnet, genesis_ms + slot_ms));
    try testing.expectEqual(@as(?u64, 1_000), msUntilNextSlot(mainnet, genesis_ms - 1_000));
    try testing.expectEqual(@as(?u64, genesis_ms), msUntilNextSlot(mainnet, 0));

    // Regression: at the maximum representable slot, `slot + 1` overflows.
    // The function is documented to return null on overflow, not panic.
    const tight = Config{
        .genesis_time_sec = 0,
        .slot_duration_ms = 1,
        .slots_per_epoch = 32,
    };
    try testing.expectEqual(@as(?u64, null), msUntilNextSlot(tight, std.math.maxInt(u64)));
}

test "config validate" {
    try mainnet.validate();

    try testing.expectError(error.InvalidConfig, (Config{
        .genesis_time_sec = 0,
        .slot_duration_ms = 0,
        .slots_per_epoch = 32,
    }).validate());

    try testing.expectError(error.InvalidConfig, (Config{
        .genesis_time_sec = 0,
        .slot_duration_ms = 12_000,
        .slots_per_epoch = 0,
    }).validate());

    try testing.expectEqual(@as(u64, 500), mainnet.maximum_gossip_clock_disparity_ms);

    try testing.expectError(error.InvalidConfig, (Config{
        .genesis_time_sec = std.math.maxInt(u64),
        .slot_duration_ms = 12_000,
        .slots_per_epoch = 32,
    }).validate());

    // Zero new_duration_ms in any transition is invalid
    try testing.expectError(error.InvalidConfig, (Config{
        .genesis_time_sec = 0,
        .slot_duration_ms = 12_000,
        .duration_transitions = forkTransitions(&.{.{ .from_slot = 1024, .new_duration_ms = 0 }}),
        .slots_per_epoch = 32,
    }).validate());

    // Transitions must be sorted strictly ascending
    try testing.expectError(error.InvalidConfig, (Config{
        .genesis_time_sec = 0,
        .slot_duration_ms = 12_000,
        .duration_transitions = forkTransitions(&.{
            .{ .from_slot = 2048, .new_duration_ms = 6_000 },
            .{ .from_slot = 1024, .new_duration_ms = 4_000 },
        }),
        .slots_per_epoch = 32,
    }).validate());

    // Active entry after a sentinel is invalid (gap in the inline array)
    var bad_layout: DurationTransitions = @splat(.{ .from_slot = 0, .new_duration_ms = 0 });
    bad_layout[1] = .{ .from_slot = 1024, .new_duration_ms = 6_000 };
    try testing.expectError(error.InvalidConfig, (Config{
        .genesis_time_sec = 0,
        .slot_duration_ms = 12_000,
        .duration_transitions = bad_layout,
        .slots_per_epoch = 32,
    }).validate());
}

// EIP-7782-shape config: 12s slots up to slot 1024 (fork epoch 32),
// 6s slots thereafter.
const eip7782 = Config{
    .genesis_time_sec = 1_000_000,
    .slot_duration_ms = 12_000,
    .duration_transitions = forkTransitions(&.{.{ .from_slot = 1024, .new_duration_ms = 6_000 }}),
    .slots_per_epoch = 32,
};

test "fork-aware: slotDurationMsAt" {
    try testing.expectEqual(@as(u64, 12_000), eip7782.slotDurationMsAt(0));
    try testing.expectEqual(@as(u64, 12_000), eip7782.slotDurationMsAt(1023));
    try testing.expectEqual(@as(u64, 6_000), eip7782.slotDurationMsAt(1024));
    try testing.expectEqual(@as(u64, 6_000), eip7782.slotDurationMsAt(2048));
}

test "fork-aware: slotStartMs at and across the boundary" {
    const genesis_ms = eip7782.genesis_time_sec * 1000;

    try testing.expectEqual(@as(?UnixMs, genesis_ms), slotStartMs(eip7782, 0));
    try testing.expectEqual(@as(?UnixMs, genesis_ms + 12_000), slotStartMs(eip7782, 1));

    const fork_ms = genesis_ms + 1024 * 12_000;
    try testing.expectEqual(@as(?UnixMs, fork_ms), slotStartMs(eip7782, 1024));

    try testing.expectEqual(@as(?UnixMs, fork_ms + 6_000), slotStartMs(eip7782, 1025));
    try testing.expectEqual(@as(?UnixMs, fork_ms + 6_000 * 100), slotStartMs(eip7782, 1124));
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

    try testing.expectEqual(@as(?u64, 1), msUntilNextSlot(eip7782, fork_ms - 1));
    try testing.expectEqual(@as(?u64, 6_000), msUntilNextSlot(eip7782, fork_ms));
    try testing.expectEqual(@as(?u64, 3_000), msUntilNextSlot(eip7782, fork_ms + 3_000));
}

// Hypothetical 2-fork config (12s → 6s at slot 1024, then 6s → 4s at slot 8192).
// Demonstrates that the schedule extends to N transitions.
const two_fork = Config{
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

    try testing.expectEqual(@as(u64, 12_000), two_fork.slotDurationMsAt(0));
    try testing.expectEqual(@as(u64, 6_000), two_fork.slotDurationMsAt(1024));
    try testing.expectEqual(@as(u64, 4_000), two_fork.slotDurationMsAt(8192));

    // slotStartMs across both boundaries
    try testing.expectEqual(@as(?UnixMs, f1_ms), slotStartMs(two_fork, 1024));
    try testing.expectEqual(@as(?UnixMs, f2_ms), slotStartMs(two_fork, 8192));
    try testing.expectEqual(@as(?UnixMs, f2_ms + 4_000), slotStartMs(two_fork, 8193));

    // slotAtMs across both boundaries
    try testing.expectEqual(@as(?Slot, 1024), slotAtMs(two_fork, f1_ms));
    try testing.expectEqual(@as(?Slot, 8191), slotAtMs(two_fork, f2_ms - 1));
    try testing.expectEqual(@as(?Slot, 8192), slotAtMs(two_fork, f2_ms));
    try testing.expectEqual(@as(?Slot, 8193), slotAtMs(two_fork, f2_ms + 4_000));
}
