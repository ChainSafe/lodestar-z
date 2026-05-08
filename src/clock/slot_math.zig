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

/// One segment of a fork-aware slot-duration schedule.
///
/// `start_slot` is the first slot at which `duration_ms` applies. Forks
/// that change slot duration (e.g. EIP-7782 anticipated 12s → 6s) are
/// expressed by appending an entry whose `start_slot = fork_epoch *
/// slots_per_epoch`.
pub const SlotDuration = struct {
    start_slot: Slot,
    duration_ms: u64,
};

/// Mirrors lodestar TS where slot duration is expressed in ms and may
/// change at known fork boundaries (per EIP-7782 / consensus-specs#4484).
///
/// `slot_durations` MUST start with `start_slot = 0` and be sorted by
/// `start_slot` ascending (validated). For a chain without any fork
/// transition, use `Config.constantDuration(...)`.
pub const Config = struct {
    genesis_time_sec: UnixSec,
    slot_durations: []const SlotDuration,
    slots_per_epoch: u64,
    maximum_gossip_clock_disparity_ms: u64 = 500,

    /// Convenience constructor for the common "single duration, no fork
    /// transition" case. The returned Config borrows a static-lifetime
    /// schedule slice.
    pub fn constantDuration(
        genesis_time_sec: UnixSec,
        slot_duration_ms: u64,
        slots_per_epoch: u64,
    ) Config {
        return .{
            .genesis_time_sec = genesis_time_sec,
            .slot_durations = &.{.{ .start_slot = 0, .duration_ms = slot_duration_ms }},
            .slots_per_epoch = slots_per_epoch,
        };
    }

    /// Slot duration in ms that applies at slot `n`.
    pub fn slotDurationMsAt(self: Config, slot: Slot) u64 {
        // Walk backwards: schedule is short (1–4 entries in practice).
        var i: usize = self.slot_durations.len;
        while (i > 0) {
            i -= 1;
            if (self.slot_durations[i].start_slot <= slot) {
                return self.slot_durations[i].duration_ms;
            }
        }
        // validate() ensures the first entry has start_slot = 0.
        unreachable;
    }

    /// Validates that the config is usable (sorted schedule, non-zero
    /// divisors, no sec→ms overflow).
    pub fn validate(self: Config) error{InvalidConfig}!void {
        if (self.slot_durations.len == 0) return error.InvalidConfig;
        if (self.slot_durations[0].start_slot != 0) return error.InvalidConfig;
        if (self.slots_per_epoch == 0) return error.InvalidConfig;
        var prev_start: Slot = 0;
        for (self.slot_durations, 0..) |sd, i| {
            if (sd.duration_ms == 0) return error.InvalidConfig;
            if (i > 0 and sd.start_slot <= prev_start) return error.InvalidConfig;
            prev_start = sd.start_slot;
        }
        if (secToMs(self.genesis_time_sec) == null) return error.InvalidConfig;
    }
};

/// Returns the slot at the given Unix-millisecond timestamp,
/// or null if pre-genesis or on overflow.
pub fn slotAtMs(config: Config, now_ms: UnixMs) ?Slot {
    const genesis_ms = secToMs(config.genesis_time_sec) orelse return null;
    if (now_ms < genesis_ms) return null;

    var t = genesis_ms;
    for (config.slot_durations, 0..) |sd, i| {
        const next_start_slot = if (i + 1 < config.slot_durations.len)
            config.slot_durations[i + 1].start_slot
        else
            std.math.maxInt(Slot);
        const seg_slots = next_start_slot - sd.start_slot;
        if (std.math.mul(u64, seg_slots, sd.duration_ms)) |seg_ms| {
            if (now_ms - t < seg_ms) {
                return sd.start_slot + (now_ms - t) / sd.duration_ms;
            }
            t = std.math.add(u64, t, seg_ms) catch return null;
        } else |_| {
            // Last segment overflow — `now_ms` is in this segment regardless.
            return sd.start_slot + (now_ms - t) / sd.duration_ms;
        }
    }
    unreachable;
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
    var t = genesis_ms;
    for (config.slot_durations, 0..) |sd, i| {
        const next_start_slot = if (i + 1 < config.slot_durations.len)
            config.slot_durations[i + 1].start_slot
        else
            std.math.maxInt(Slot);
        if (slot < next_start_slot) {
            const offset = std.math.mul(u64, slot - sd.start_slot, sd.duration_ms) catch return null;
            return std.math.add(u64, t, offset) catch null;
        }
        const seg_slots = next_start_slot - sd.start_slot;
        const seg_ms = std.math.mul(u64, seg_slots, sd.duration_ms) catch return null;
        t = std.math.add(u64, t, seg_ms) catch return null;
    }
    unreachable;
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
    const next_start = slotStartMs(config, slot + 1) orelse return null;
    return next_start - now_ms;
}

fn secToMs(sec: u64) ?u64 {
    return std.math.mul(u64, sec, 1000) catch return null;
}

const testing = std.testing;

const mainnet = Config.constantDuration(1_606_824_023, 12_000, 32);

test "basic slot math" {
    // slotAtSec: genesis is slot 0
    try testing.expectEqual(@as(?Slot, 0), slotAtSec(mainnet, mainnet.genesis_time_sec));
    // slotAtSec: 12s after genesis is slot 1
    try testing.expectEqual(@as(?Slot, 1), slotAtSec(mainnet, mainnet.genesis_time_sec + 12));
    // slotAtSec: 24s after genesis is slot 2
    try testing.expectEqual(@as(?Slot, 2), slotAtSec(mainnet, mainnet.genesis_time_sec + 24));

    // slotAtMs at genesis
    const genesis_ms = mainnet.genesis_time_sec * 1000;
    try testing.expectEqual(@as(?Slot, 0), slotAtMs(mainnet, genesis_ms));
    try testing.expectEqual(@as(?Slot, 1), slotAtMs(mainnet, genesis_ms + 12_000));

    // epochAtSlot
    try testing.expectEqual(@as(?Epoch, 0), epochAtSlot(mainnet, 0));
    try testing.expectEqual(@as(?Epoch, 0), epochAtSlot(mainnet, 31));
    try testing.expectEqual(@as(?Epoch, 1), epochAtSlot(mainnet, 32));
    try testing.expectEqual(@as(?Epoch, 1), epochAtSlot(mainnet, 63));
    try testing.expectEqual(@as(?Epoch, 2), epochAtSlot(mainnet, 64));

    // slotStartSec round-trip
    try testing.expectEqual(@as(?UnixSec, mainnet.genesis_time_sec), slotStartSec(mainnet, 0));
    try testing.expectEqual(@as(?UnixSec, mainnet.genesis_time_sec + 12), slotStartSec(mainnet, 1));
    try testing.expectEqual(@as(?UnixSec, mainnet.genesis_time_sec + 24), slotStartSec(mainnet, 2));

    // slotStartMs round-trip
    try testing.expectEqual(@as(?UnixMs, mainnet.genesis_time_sec * 1000), slotStartMs(mainnet, 0));
    try testing.expectEqual(@as(?UnixMs, (mainnet.genesis_time_sec + 12) * 1000), slotStartMs(mainnet, 1));

    // slotDurationMsAt is constant under a single-segment schedule.
    try testing.expectEqual(@as(u64, 12_000), mainnet.slotDurationMsAt(0));
    try testing.expectEqual(@as(u64, 12_000), mainnet.slotDurationMsAt(1_000_000));
}

test "within-slot timing" {
    // Seconds: mid-slot reads still return the current slot
    try testing.expectEqual(@as(?Slot, 0), slotAtSec(mainnet, mainnet.genesis_time_sec + 0));
    try testing.expectEqual(@as(?Slot, 0), slotAtSec(mainnet, mainnet.genesis_time_sec + 6));
    try testing.expectEqual(@as(?Slot, 0), slotAtSec(mainnet, mainnet.genesis_time_sec + 11));
    // The boundary itself is the next slot
    try testing.expectEqual(@as(?Slot, 1), slotAtSec(mainnet, mainnet.genesis_time_sec + 12));

    // Milliseconds: mid-slot reads still return the current slot
    const genesis_ms = mainnet.genesis_time_sec * 1000;
    try testing.expectEqual(@as(?Slot, 0), slotAtMs(mainnet, genesis_ms + 1));
    try testing.expectEqual(@as(?Slot, 0), slotAtMs(mainnet, genesis_ms + 6_000));
    try testing.expectEqual(@as(?Slot, 0), slotAtMs(mainnet, genesis_ms + 11_999));
    // Exact boundary is next slot
    try testing.expectEqual(@as(?Slot, 1), slotAtMs(mainnet, genesis_ms + 12_000));
    // Mid-way through slot 1
    try testing.expectEqual(@as(?Slot, 1), slotAtMs(mainnet, genesis_ms + 18_000));
    try testing.expectEqual(@as(?Slot, 1), slotAtMs(mainnet, genesis_ms + 23_999));
    // Slot 2 boundary
    try testing.expectEqual(@as(?Slot, 2), slotAtMs(mainnet, genesis_ms + 24_000));
}

test "overflow safety" {
    // Pre-genesis returns null
    try testing.expectEqual(@as(?Slot, null), slotAtSec(mainnet, mainnet.genesis_time_sec - 1));
    try testing.expectEqual(@as(?Slot, null), slotAtSec(mainnet, 0));
    try testing.expectEqual(@as(?Slot, null), slotAtMs(mainnet, 0));

    // Huge slot overflows slotStartSec / slotStartMs
    try testing.expectEqual(@as(?UnixSec, null), slotStartSec(mainnet, std.math.maxInt(u64)));
    try testing.expectEqual(@as(?UnixMs, null), slotStartMs(mainnet, std.math.maxInt(u64)));

    // Config with maxInt genesis_time_sec: slotAtMs gets null from secToMs overflow
    const extreme = Config.constantDuration(std.math.maxInt(u64), 12_000, 32);
    try testing.expectEqual(@as(?Slot, null), slotAtMs(extreme, 0));
    try testing.expectEqual(@as(?UnixSec, null), slotStartSec(extreme, 1));
    try testing.expectEqual(@as(?UnixMs, null), slotStartMs(extreme, 0));

    // msUntilNextSlot returns null when genesis overflows ms conversion
    try testing.expectEqual(@as(?u64, null), msUntilNextSlot(extreme, 0));
}

test "msUntilNextSlot" {
    const genesis_ms = mainnet.genesis_time_sec * 1000;
    const slot_ms: u64 = 12_000;

    // Exactly at genesis: full slot duration until next
    try testing.expectEqual(@as(?u64, slot_ms), msUntilNextSlot(mainnet, genesis_ms));

    // 1ms into genesis slot
    try testing.expectEqual(@as(?u64, slot_ms - 1), msUntilNextSlot(mainnet, genesis_ms + 1));

    // Half-way through a slot
    try testing.expectEqual(@as(?u64, slot_ms - 6_000), msUntilNextSlot(mainnet, genesis_ms + 6_000));

    // 1ms before slot boundary
    try testing.expectEqual(@as(?u64, 1), msUntilNextSlot(mainnet, genesis_ms + slot_ms - 1));

    // Exactly at slot 1 boundary: full slot duration until slot 2
    try testing.expectEqual(@as(?u64, slot_ms), msUntilNextSlot(mainnet, genesis_ms + slot_ms));

    // Pre-genesis: returns time until genesis
    try testing.expectEqual(@as(?u64, 1_000), msUntilNextSlot(mainnet, genesis_ms - 1_000));
    try testing.expectEqual(@as(?u64, genesis_ms), msUntilNextSlot(mainnet, 0));
}

test "config validate" {
    // Valid config passes
    try mainnet.validate();

    // Empty schedule is invalid
    try testing.expectError(error.InvalidConfig, (Config{
        .genesis_time_sec = 0,
        .slot_durations = &.{},
        .slots_per_epoch = 32,
    }).validate());

    // First entry must start at slot 0
    try testing.expectError(error.InvalidConfig, (Config{
        .genesis_time_sec = 0,
        .slot_durations = &.{.{ .start_slot = 1, .duration_ms = 12_000 }},
        .slots_per_epoch = 32,
    }).validate());

    // Zero slot duration in any segment is invalid
    try testing.expectError(error.InvalidConfig, (Config{
        .genesis_time_sec = 0,
        .slot_durations = &.{.{ .start_slot = 0, .duration_ms = 0 }},
        .slots_per_epoch = 32,
    }).validate());

    // Zero slots_per_epoch is invalid
    try testing.expectError(
        error.InvalidConfig,
        Config.constantDuration(0, 12_000, 0).validate(),
    );

    // Schedule entries must be sorted by ascending start_slot
    try testing.expectError(error.InvalidConfig, (Config{
        .genesis_time_sec = 0,
        .slot_durations = &.{
            .{ .start_slot = 0, .duration_ms = 12_000 },
            .{ .start_slot = 0, .duration_ms = 6_000 },
        },
        .slots_per_epoch = 32,
    }).validate());

    // Default maximum_gossip_clock_disparity_ms is 500
    try testing.expectEqual(@as(u64, 500), mainnet.maximum_gossip_clock_disparity_ms);

    // genesis_time_sec that overflows sec→ms is invalid
    try testing.expectError(
        error.InvalidConfig,
        Config.constantDuration(std.math.maxInt(u64), 12_000, 32).validate(),
    );
}

// EIP-7782-shape config: 12s slots up to fork epoch, 6s thereafter.
// Fork at epoch 32 → start_slot 32*32 = 1024.
const eip7782 = Config{
    .genesis_time_sec = 1_000_000,
    .slot_durations = &.{
        .{ .start_slot = 0, .duration_ms = 12_000 },
        .{ .start_slot = 1024, .duration_ms = 6_000 },
    },
    .slots_per_epoch = 32,
};

test "fork-aware schedule: slotDurationMsAt" {
    try testing.expectEqual(@as(u64, 12_000), eip7782.slotDurationMsAt(0));
    try testing.expectEqual(@as(u64, 12_000), eip7782.slotDurationMsAt(1023));
    try testing.expectEqual(@as(u64, 6_000), eip7782.slotDurationMsAt(1024));
    try testing.expectEqual(@as(u64, 6_000), eip7782.slotDurationMsAt(2048));
}

test "fork-aware schedule: slotStartMs at and across the boundary" {
    const genesis_ms = eip7782.genesis_time_sec * 1000;

    // Pre-fork segment uses 12s slots
    try testing.expectEqual(@as(?UnixMs, genesis_ms), slotStartMs(eip7782, 0));
    try testing.expectEqual(@as(?UnixMs, genesis_ms + 12_000), slotStartMs(eip7782, 1));

    // Slot 1024 (the fork slot) starts at genesis + 1024 * 12_000
    const fork_ms = genesis_ms + 1024 * 12_000;
    try testing.expectEqual(@as(?UnixMs, fork_ms), slotStartMs(eip7782, 1024));

    // Post-fork: slot 1025 = fork_ms + 6_000 (NOT + 12_000)
    try testing.expectEqual(@as(?UnixMs, fork_ms + 6_000), slotStartMs(eip7782, 1025));
    try testing.expectEqual(@as(?UnixMs, fork_ms + 6_000 * 100), slotStartMs(eip7782, 1124));
}

test "fork-aware schedule: slotAtMs across boundary" {
    const genesis_ms = eip7782.genesis_time_sec * 1000;
    const fork_ms = genesis_ms + 1024 * 12_000;

    // Within last pre-fork slot (1023): time range [fork_ms - 12_000, fork_ms)
    try testing.expectEqual(@as(?Slot, 1023), slotAtMs(eip7782, fork_ms - 12_000));
    try testing.expectEqual(@as(?Slot, 1023), slotAtMs(eip7782, fork_ms - 1));

    // Exactly at fork_ms is slot 1024 (the first 6s slot)
    try testing.expectEqual(@as(?Slot, 1024), slotAtMs(eip7782, fork_ms));

    // Post-fork: 6s slots
    try testing.expectEqual(@as(?Slot, 1024), slotAtMs(eip7782, fork_ms + 5_999));
    try testing.expectEqual(@as(?Slot, 1025), slotAtMs(eip7782, fork_ms + 6_000));
    try testing.expectEqual(@as(?Slot, 1026), slotAtMs(eip7782, fork_ms + 12_000));
}

test "fork-aware schedule: msUntilNextSlot across boundary" {
    const genesis_ms = eip7782.genesis_time_sec * 1000;
    const fork_ms = genesis_ms + 1024 * 12_000;

    // 1ms before fork: still 12s slot (slot 1023), 1ms left
    try testing.expectEqual(@as(?u64, 1), msUntilNextSlot(eip7782, fork_ms - 1));

    // Exactly at fork: now in slot 1024 (6s), 6s until next
    try testing.expectEqual(@as(?u64, 6_000), msUntilNextSlot(eip7782, fork_ms));

    // Mid post-fork slot
    try testing.expectEqual(@as(?u64, 3_000), msUntilNextSlot(eip7782, fork_ms + 3_000));
}
