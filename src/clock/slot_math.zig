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

/// Mirrors lodestar TS `ChainConfig` (`SLOT_DURATION_MS` +
/// `SLOT_DURATION_MS_EIP7782` + `EIP7782_FORK_EPOCH`): one slot duration
/// before the EIP-7782 fork (12s on mainnet) and a possibly-different
/// duration after (anticipated 6s). Set both `fork_slot` and
/// `slot_duration_ms_after_fork` to enable the transition; leave both
/// null for chains without a duration change.
pub const Config = struct {
    genesis_time_sec: UnixSec,
    slot_duration_ms: u64,
    /// First slot at which `slot_duration_ms_after_fork` takes effect.
    /// Typically `EIP7782_FORK_EPOCH * slots_per_epoch`.
    fork_slot: ?Slot = null,
    slot_duration_ms_after_fork: ?u64 = null,
    slots_per_epoch: u64,
    maximum_gossip_clock_disparity_ms: u64 = 500,

    pub fn validate(self: Config) error{InvalidConfig}!void {
        if (self.slot_duration_ms == 0) return error.InvalidConfig;
        if (self.slots_per_epoch == 0) return error.InvalidConfig;
        if (secToMs(self.genesis_time_sec) == null) return error.InvalidConfig;
        // fork_slot and slot_duration_ms_after_fork must be both set or both null.
        if ((self.fork_slot == null) != (self.slot_duration_ms_after_fork == null)) {
            return error.InvalidConfig;
        }
        if (self.slot_duration_ms_after_fork) |after| {
            if (after == 0) return error.InvalidConfig;
        }
    }

    /// Slot duration in ms applicable at `slot`.
    pub fn slotDurationMsAt(self: Config, slot: Slot) u64 {
        if (self.fork_slot) |fs| {
            if (slot >= fs) return self.slot_duration_ms_after_fork.?;
        }
        return self.slot_duration_ms;
    }
};

/// Returns the slot at the given Unix-millisecond timestamp,
/// or null if pre-genesis or on overflow.
pub fn slotAtMs(config: Config, now_ms: UnixMs) ?Slot {
    const genesis_ms = secToMs(config.genesis_time_sec) orelse return null;
    if (now_ms < genesis_ms) return null;

    if (config.fork_slot) |fs| {
        const pre_fork_ms = std.math.mul(u64, fs, config.slot_duration_ms) catch return null;
        const fork_ms = std.math.add(u64, genesis_ms, pre_fork_ms) catch return null;
        if (now_ms >= fork_ms) {
            const after = config.slot_duration_ms_after_fork.?;
            if (after == 0) return null;
            return fs + (now_ms - fork_ms) / after;
        }
    }
    if (config.slot_duration_ms == 0) return null;
    return (now_ms - genesis_ms) / config.slot_duration_ms;
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
    if (config.fork_slot) |fs| {
        if (slot >= fs) {
            const pre_fork_ms = std.math.mul(u64, fs, config.slot_duration_ms) catch return null;
            const fork_ms = std.math.add(u64, genesis_ms, pre_fork_ms) catch return null;
            const after_offset = std.math.mul(u64, slot - fs, config.slot_duration_ms_after_fork.?) catch return null;
            return std.math.add(u64, fork_ms, after_offset) catch null;
        }
    }
    const offset_ms = std.math.mul(u64, slot, config.slot_duration_ms) catch return null;
    return std.math.add(u64, genesis_ms, offset_ms) catch null;
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

const mainnet = Config{
    .genesis_time_sec = 1_606_824_023,
    .slot_duration_ms = 12_000,
    .slots_per_epoch = 32,
};

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
    const extreme = Config{
        .genesis_time_sec = std.math.maxInt(u64),
        .slot_duration_ms = 12_000,
        .slots_per_epoch = 32,
    };
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

    // Zero slot_duration_ms is invalid
    try testing.expectError(error.InvalidConfig, (Config{
        .genesis_time_sec = 0,
        .slot_duration_ms = 0,
        .slots_per_epoch = 32,
    }).validate());

    // Zero slots_per_epoch is invalid
    try testing.expectError(error.InvalidConfig, (Config{
        .genesis_time_sec = 0,
        .slot_duration_ms = 12_000,
        .slots_per_epoch = 0,
    }).validate());

    // Default maximum_gossip_clock_disparity_ms is 500
    try testing.expectEqual(@as(u64, 500), mainnet.maximum_gossip_clock_disparity_ms);

    // genesis_time_sec that overflows sec→ms is invalid
    try testing.expectError(error.InvalidConfig, (Config{
        .genesis_time_sec = std.math.maxInt(u64),
        .slot_duration_ms = 12_000,
        .slots_per_epoch = 32,
    }).validate());

    // fork_slot without slot_duration_ms_after_fork is invalid
    try testing.expectError(error.InvalidConfig, (Config{
        .genesis_time_sec = 0,
        .slot_duration_ms = 12_000,
        .fork_slot = 1024,
        .slots_per_epoch = 32,
    }).validate());

    // slot_duration_ms_after_fork without fork_slot is invalid
    try testing.expectError(error.InvalidConfig, (Config{
        .genesis_time_sec = 0,
        .slot_duration_ms = 12_000,
        .slot_duration_ms_after_fork = 6_000,
        .slots_per_epoch = 32,
    }).validate());

    // Zero slot_duration_ms_after_fork is invalid
    try testing.expectError(error.InvalidConfig, (Config{
        .genesis_time_sec = 0,
        .slot_duration_ms = 12_000,
        .fork_slot = 1024,
        .slot_duration_ms_after_fork = 0,
        .slots_per_epoch = 32,
    }).validate());
}

// EIP-7782-shape config: 12s slots up to slot 1024 (fork epoch 32),
// 6s slots thereafter.
const eip7782 = Config{
    .genesis_time_sec = 1_000_000,
    .slot_duration_ms = 12_000,
    .fork_slot = 1024,
    .slot_duration_ms_after_fork = 6_000,
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

test "fork-aware: slotAtMs across boundary" {
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

test "fork-aware: msUntilNextSlot across boundary" {
    const genesis_ms = eip7782.genesis_time_sec * 1000;
    const fork_ms = genesis_ms + 1024 * 12_000;

    // 1ms before fork: still 12s slot (slot 1023), 1ms left
    try testing.expectEqual(@as(?u64, 1), msUntilNextSlot(eip7782, fork_ms - 1));

    // Exactly at fork: now in slot 1024 (6s), 6s until next
    try testing.expectEqual(@as(?u64, 6_000), msUntilNextSlot(eip7782, fork_ms));

    // Mid post-fork slot
    try testing.expectEqual(@as(?u64, 3_000), msUntilNextSlot(eip7782, fork_ms + 3_000));
}
