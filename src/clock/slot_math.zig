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

pub const Config = struct {
    genesis_time_sec: UnixSec,
    seconds_per_slot: u64,
    slots_per_epoch: u64,
    maximum_gossip_clock_disparity_ms: u64 = 500,

    /// Validates that the config is usable (no zero divisors, no sec→ms overflow).
    pub fn validate(self: Config) error{InvalidConfig}!void {
        if (self.seconds_per_slot == 0 or self.slots_per_epoch == 0)
            return error.InvalidConfig;
        // Ensure sec→ms conversions used by msUntilNextSlot won't overflow at runtime.
        if (secToMs(self.genesis_time_sec) == null) return error.InvalidConfig;
        if (secToMs(self.seconds_per_slot) == null) return error.InvalidConfig;
    }

    /// Returns the slot duration in milliseconds, or null on overflow.
    pub fn slotDurationMs(self: Config) ?u64 {
        return secToMs(self.seconds_per_slot);
    }
};

/// Returns the slot at the given Unix-millisecond timestamp,
/// or null if pre-genesis or on overflow.
pub fn slotAtMs(config: Config, now_ms: UnixMs) ?Slot {
    const genesis_ms = secToMs(config.genesis_time_sec) orelse return null;
    if (now_ms < genesis_ms) return null;
    const slot_ms = secToMs(config.seconds_per_slot) orelse return null;
    if (slot_ms == 0) return null;
    return @divFloor(now_ms - genesis_ms, slot_ms);
}

/// Returns the slot at the given Unix-second timestamp,
/// or null if pre-genesis.
pub fn slotAtSec(config: Config, now_sec: UnixSec) ?Slot {
    if (now_sec < config.genesis_time_sec) return null;
    if (config.seconds_per_slot == 0) return null;
    return @divFloor(now_sec - config.genesis_time_sec, config.seconds_per_slot);
}

/// Returns the epoch that contains `slot`, or null if slots_per_epoch is zero.
pub fn epochAtSlot(config: Config, slot: Slot) ?Epoch {
    if (config.slots_per_epoch == 0) return null;
    return @divFloor(slot, config.slots_per_epoch);
}

/// Returns the Unix-second start time of `slot`, or null on overflow.
pub fn slotStartSec(config: Config, slot: Slot) ?UnixSec {
    const offset = std.math.mul(u64, slot, config.seconds_per_slot) catch return null;
    return std.math.add(u64, config.genesis_time_sec, offset) catch return null;
}

/// Returns the Unix-millisecond start time of `slot`, or null on overflow.
pub fn slotStartMs(config: Config, slot: Slot) ?UnixMs {
    const sec = slotStartSec(config, slot) orelse return null;
    return secToMs(sec);
}

/// Milliseconds until the next slot boundary.
/// Pre-genesis: returns the time until genesis.
/// Returns null only on arithmetic overflow.
pub fn msUntilNextSlot(config: Config, now_ms: UnixMs) ?u64 {
    const genesis_ms = secToMs(config.genesis_time_sec) orelse return null;
    const slot_ms = secToMs(config.seconds_per_slot) orelse return null;
    if (slot_ms == 0) return null;

    if (now_ms < genesis_ms) return genesis_ms - now_ms;

    const delta = now_ms - genesis_ms;
    const rem = delta % slot_ms;
    if (rem == 0) return slot_ms;
    return slot_ms - rem;
}

fn secToMs(sec: u64) ?u64 {
    return std.math.mul(u64, sec, 1000) catch return null;
}

const testing = std.testing;

const mainnet = Config{
    .genesis_time_sec = 1_606_824_023,
    .seconds_per_slot = 12,
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

    // slotDurationMs
    try testing.expectEqual(@as(?u64, 12_000), mainnet.slotDurationMs());
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
        .seconds_per_slot = 12,
        .slots_per_epoch = 32,
    };
    try testing.expectEqual(@as(?Slot, null), slotAtMs(extreme, 0));
    try testing.expectEqual(@as(?UnixSec, null), slotStartSec(extreme, 1));
    try testing.expectEqual(@as(?UnixMs, null), slotStartMs(extreme, 0));

    // slotDurationMs on extreme seconds_per_slot returns null
    const big_slot = Config{
        .genesis_time_sec = 0,
        .seconds_per_slot = std.math.maxInt(u64),
        .slots_per_epoch = 1,
    };
    try testing.expectEqual(@as(?u64, null), big_slot.slotDurationMs());

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

    // Zero seconds_per_slot is invalid
    try testing.expectError(error.InvalidConfig, (Config{
        .genesis_time_sec = 0,
        .seconds_per_slot = 0,
        .slots_per_epoch = 32,
    }).validate());

    // Zero slots_per_epoch is invalid
    try testing.expectError(error.InvalidConfig, (Config{
        .genesis_time_sec = 0,
        .seconds_per_slot = 12,
        .slots_per_epoch = 0,
    }).validate());

    // Both zero is invalid
    try testing.expectError(error.InvalidConfig, (Config{
        .genesis_time_sec = 0,
        .seconds_per_slot = 0,
        .slots_per_epoch = 0,
    }).validate());

    // Default maximum_gossip_clock_disparity_ms is 500
    try testing.expectEqual(@as(u64, 500), mainnet.maximum_gossip_clock_disparity_ms);

    // genesis_time_sec that overflows sec→ms is invalid
    try testing.expectError(error.InvalidConfig, (Config{
        .genesis_time_sec = std.math.maxInt(u64),
        .seconds_per_slot = 12,
        .slots_per_epoch = 32,
    }).validate());

    // seconds_per_slot that overflows sec→ms is invalid
    try testing.expectError(error.InvalidConfig, (Config{
        .genesis_time_sec = 0,
        .seconds_per_slot = std.math.maxInt(u64),
        .slots_per_epoch = 32,
    }).validate());
}
