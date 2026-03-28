//! Shared SlotClock for beacon chain time calculations.
//!
//! This is the canonical SlotClock implementation, used by both the production
//! beacon node and test harnesses. It uses `std.Io` for deterministic testability:
//! - Production: real wall-clock time via std.Io
//! - Testing: deterministic SimIo with controllable time
//!
//! The validator client has a different clock (`validator/clock.zig` → `ValidatorSlotTicker`)
//! that uses `std.time` directly and has callbacks for duty scheduling.

const std = @import("std");
const Io = std.Io;
const config_mod = @import("./root.zig");
const ChainConfig = config_mod.ChainConfig;
const preset = @import("preset").preset;

/// Slots per epoch from the active preset.
pub const SLOTS_PER_EPOCH: u64 = preset.SLOTS_PER_EPOCH;

/// Wall-clock slot ticker for beacon chain time calculations.
///
/// Converts Io-based wall-clock time to Ethereum consensus time (slots, epochs).
/// Works identically in production (real I/O) and deterministic simulation (SimIo).
pub const SlotClock = struct {
    /// Genesis time in seconds since Unix epoch.
    genesis_time_s: u64,
    /// Duration of each slot in seconds.
    seconds_per_slot: u64,

    /// Create a SlotClock from a genesis time and chain config.
    pub fn fromGenesis(genesis_time_s: u64, chain_config: ChainConfig) SlotClock {
        return .{
            .genesis_time_s = genesis_time_s,
            .seconds_per_slot = chain_config.SECONDS_PER_SLOT,
        };
    }

    /// Create a SlotClock with mainnet defaults for testing.
    pub fn fromGenesisDefault(genesis_time_s: u64) SlotClock {
        return .{
            .genesis_time_s = genesis_time_s,
            .seconds_per_slot = 12,
        };
    }

    /// Get current slot from the Io clock.
    /// Returns null if before genesis.
    pub fn currentSlot(self: SlotClock, sio: Io) ?u64 {
        const now_ts = Io.Clock.real.now(sio);
        const now_s: i64 = @intCast(@divFloor(now_ts.nanoseconds, std.time.ns_per_s));
        const genesis_s: i64 = @intCast(self.genesis_time_s);

        if (now_s < genesis_s) return null;

        const elapsed_s: u64 = @intCast(now_s - genesis_s);
        return elapsed_s / self.seconds_per_slot;
    }

    /// Get the start time of a slot in seconds since epoch.
    pub fn slotStartSeconds(self: SlotClock, slot: u64) u64 {
        return self.genesis_time_s + slot * self.seconds_per_slot;
    }

    /// Get the start time of a slot in nanoseconds since epoch.
    pub fn slotStartNs(self: SlotClock, slot: u64) u64 {
        return (self.genesis_time_s + slot * self.seconds_per_slot) * std.time.ns_per_s;
    }

    /// Get current epoch. Returns null if before genesis.
    pub fn currentEpoch(self: SlotClock, sio: Io) ?u64 {
        const slot = self.currentSlot(sio) orelse return null;
        return slot / SLOTS_PER_EPOCH;
    }

    /// Get the epoch for a given slot.
    pub fn epochForSlot(_: SlotClock, slot: u64) u64 {
        return slot / SLOTS_PER_EPOCH;
    }

    /// Get the first slot of an epoch.
    pub fn epochStartSlot(_: SlotClock, epoch: u64) u64 {
        return epoch * SLOTS_PER_EPOCH;
    }

    /// How far into the current slot are we? Returns fraction [0.0, 1.0).
    /// Returns null if before genesis.
    pub fn slotFraction(self: SlotClock, sio: Io) ?f64 {
        const now_ts = Io.Clock.real.now(sio);
        const now_ns: i128 = now_ts.nanoseconds;
        const genesis_ns: i128 = @as(i128, self.genesis_time_s) * std.time.ns_per_s;

        if (now_ns < genesis_ns) return null;

        const elapsed_ns: u128 = @intCast(now_ns - genesis_ns);
        const slot_duration_ns: u128 = @as(u128, self.seconds_per_slot) * std.time.ns_per_s;
        const within_slot_ns: u128 = elapsed_ns % slot_duration_ns;

        return @as(f64, @floatFromInt(within_slot_ns)) / @as(f64, @floatFromInt(slot_duration_ns));
    }

    /// Is this the right time for attestation duty? (1/3 into slot)
    pub fn isAttestationTime(self: SlotClock, sio: Io) bool {
        const fraction = self.slotFraction(sio) orelse return false;
        return fraction >= 1.0 / 3.0 and fraction < 2.0 / 3.0;
    }

    /// Is this the right time to aggregate? (2/3 into slot)
    pub fn isAggregationTime(self: SlotClock, sio: Io) bool {
        const fraction = self.slotFraction(sio) orelse return false;
        return fraction >= 2.0 / 3.0;
    }

    /// Is this the block proposal window? (first 1/3 of slot)
    pub fn isProposalTime(self: SlotClock, sio: Io) bool {
        const fraction = self.slotFraction(sio) orelse return false;
        return fraction < 1.0 / 3.0;
    }

    /// Duration of one slot in nanoseconds.
    pub fn slotDurationNs(self: SlotClock) u64 {
        return self.seconds_per_slot * std.time.ns_per_s;
    }
};
