//! Slot-aware clock utilities for Ethereum consensus simulation.
//!
//! Provides helpers that work with `std.Io` (and specifically `SimIo`) for
//! Ethereum-specific time calculations: slots, epochs, and duty timing windows.

const std = @import("std");
const Io = std.Io;
const preset = @import("preset").preset;

/// Number of slots per epoch — imported from the active preset.
/// Minimal: 8, Mainnet: 32.
pub const SLOTS_PER_EPOCH: u64 = preset.SLOTS_PER_EPOCH;

pub const SlotClock = struct {
    /// Genesis time in seconds since Unix epoch.
    genesis_time_s: u64,

    /// Duration of each slot in seconds.
    seconds_per_slot: u64,

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

    /// Get the start time of a slot in nanoseconds since epoch.
    pub fn slotStartNs(self: SlotClock, slot: u64) u64 {
        return (self.genesis_time_s + slot * self.seconds_per_slot) * std.time.ns_per_s;
    }

    /// Get the start time of a slot in seconds since epoch.
    pub fn slotStartSeconds(self: SlotClock, slot: u64) u64 {
        return self.genesis_time_s + slot * self.seconds_per_slot;
    }

    /// Get current epoch.
    /// Returns null if before genesis.
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

    /// Is this the right time to attest? (1/3 into the slot).
    /// Attestations are due at slot_start + slot_duration/3.
    pub fn isAttestationTime(self: SlotClock, sio: Io) bool {
        const fraction = self.slotFraction(sio) orelse return false;
        // Attestation window: [1/3, 2/3) of slot.
        return fraction >= 1.0 / 3.0 and fraction < 2.0 / 3.0;
    }

    /// Is this the right time to aggregate? (2/3 into the slot).
    /// Aggregation is due at slot_start + 2*slot_duration/3.
    pub fn isAggregationTime(self: SlotClock, sio: Io) bool {
        const fraction = self.slotFraction(sio) orelse return false;
        // Aggregation window: [2/3, 1.0) of slot.
        return fraction >= 2.0 / 3.0;
    }

    /// Is this the block proposal window? (first 1/3 of slot).
    pub fn isProposalTime(self: SlotClock, sio: Io) bool {
        const fraction = self.slotFraction(sio) orelse return false;
        return fraction < 1.0 / 3.0;
    }

    /// Duration of one slot in nanoseconds.
    pub fn slotDurationNs(self: SlotClock) u64 {
        return self.seconds_per_slot * std.time.ns_per_s;
    }
};

// ── Tests ────────────────────────────────────────────────────────────

const SimIo = @import("sim_io.zig").SimIo;

test "SlotClock: currentSlot" {
    const genesis: u64 = 1_606_824_023;
    const clock: SlotClock = .{ .genesis_time_s = genesis, .seconds_per_slot = 12 };

    var sim: SimIo = .{
        .prng = std.Random.DefaultPrng.init(0),
        .realtime_ns = @as(i128, genesis) * std.time.ns_per_s,
    };
    const sio = sim.io();

    // At genesis: slot 0.
    try std.testing.expectEqual(@as(?u64, 0), clock.currentSlot(sio));

    // Advance 12 seconds: slot 1.
    sim.advanceTime(12 * std.time.ns_per_s);
    try std.testing.expectEqual(@as(?u64, 1), clock.currentSlot(sio));

    // Advance another 120 seconds (10 slots): slot 11.
    sim.advanceTime(120 * std.time.ns_per_s);
    try std.testing.expectEqual(@as(?u64, 11), clock.currentSlot(sio));
}

test "SlotClock: before genesis returns null" {
    const genesis: u64 = 1_606_824_023;
    const clock: SlotClock = .{ .genesis_time_s = genesis, .seconds_per_slot = 12 };

    var sim: SimIo = .{
        .prng = std.Random.DefaultPrng.init(0),
        .realtime_ns = @as(i128, genesis - 100) * std.time.ns_per_s,
    };
    const sio = sim.io();

    try std.testing.expectEqual(@as(?u64, null), clock.currentSlot(sio));
    try std.testing.expectEqual(@as(?u64, null), clock.currentEpoch(sio));
}

test "SlotClock: currentEpoch" {
    const genesis: u64 = 1_000_000;
    const clock: SlotClock = .{ .genesis_time_s = genesis, .seconds_per_slot = 12 };

    var sim: SimIo = .{
        .prng = std.Random.DefaultPrng.init(0),
        .realtime_ns = @as(i128, genesis) * std.time.ns_per_s,
    };
    const sio = sim.io();

    // Slot 0 → epoch 0.
    try std.testing.expectEqual(@as(?u64, 0), clock.currentEpoch(sio));

    // Advance to slot 32 → epoch 1.
    sim.advanceTime(32 * 12 * std.time.ns_per_s);
    try std.testing.expectEqual(@as(?u64, 1), clock.currentEpoch(sio));

    // Advance to slot 63 → still epoch 1.
    sim.advanceTime(31 * 12 * std.time.ns_per_s);
    try std.testing.expectEqual(@as(?u64, 1), clock.currentEpoch(sio));

    // Advance to slot 64 → epoch 2.
    sim.advanceTime(12 * std.time.ns_per_s);
    try std.testing.expectEqual(@as(?u64, 2), clock.currentEpoch(sio));
}

test "SlotClock: attestation and aggregation timing" {
    const genesis: u64 = 1_000_000;
    const clock: SlotClock = .{ .genesis_time_s = genesis, .seconds_per_slot = 12 };

    var sim: SimIo = .{
        .prng = std.Random.DefaultPrng.init(0),
        .realtime_ns = @as(i128, genesis) * std.time.ns_per_s,
    };
    const sio = sim.io();

    // At slot start: proposal time, not attestation or aggregation.
    try std.testing.expect(clock.isProposalTime(sio));
    try std.testing.expect(!clock.isAttestationTime(sio));
    try std.testing.expect(!clock.isAggregationTime(sio));

    // At 4s into slot (1/3): attestation time.
    sim.advanceTime(4 * std.time.ns_per_s);
    try std.testing.expect(!clock.isProposalTime(sio));
    try std.testing.expect(clock.isAttestationTime(sio));
    try std.testing.expect(!clock.isAggregationTime(sio));

    // At 8s into slot (2/3): aggregation time.
    sim.advanceTime(4 * std.time.ns_per_s);
    try std.testing.expect(!clock.isProposalTime(sio));
    try std.testing.expect(!clock.isAttestationTime(sio));
    try std.testing.expect(clock.isAggregationTime(sio));
}

test "SlotClock: slotStartNs and slotStartSeconds" {
    const genesis: u64 = 1_000_000;
    const clock: SlotClock = .{ .genesis_time_s = genesis, .seconds_per_slot = 12 };

    try std.testing.expectEqual(genesis, clock.slotStartSeconds(0));
    try std.testing.expectEqual(genesis + 12, clock.slotStartSeconds(1));
    try std.testing.expectEqual(genesis + 120, clock.slotStartSeconds(10));

    try std.testing.expectEqual(genesis * std.time.ns_per_s, clock.slotStartNs(0));
    try std.testing.expectEqual((genesis + 12) * std.time.ns_per_s, clock.slotStartNs(1));
}

test "SlotClock: epochForSlot and epochStartSlot" {
    const clock: SlotClock = .{ .genesis_time_s = 0, .seconds_per_slot = 12 };

    try std.testing.expectEqual(@as(u64, 0), clock.epochForSlot(0));
    try std.testing.expectEqual(@as(u64, 0), clock.epochForSlot(31));
    try std.testing.expectEqual(@as(u64, 1), clock.epochForSlot(32));
    try std.testing.expectEqual(@as(u64, 3), clock.epochForSlot(100));

    try std.testing.expectEqual(@as(u64, 0), clock.epochStartSlot(0));
    try std.testing.expectEqual(@as(u64, 32), clock.epochStartSlot(1));
    try std.testing.expectEqual(@as(u64, 64), clock.epochStartSlot(2));
}

test "SlotClock: slotDurationNs" {
    const clock: SlotClock = .{ .genesis_time_s = 0, .seconds_per_slot = 12 };
    try std.testing.expectEqual(@as(u64, 12 * std.time.ns_per_s), clock.slotDurationNs());
}
