//! Slot-aware clock utilities for Ethereum consensus simulation.
//!
//! Re-exports the canonical SlotClock from config/clock.zig.
//! Keeps the SimIo-based tests here as they validate the clock behavior
//! in deterministic simulation contexts.

const std = @import("std");
const config_mod = @import("config");

/// Re-exported canonical SlotClock from config/clock.zig.
pub const SlotClock = config_mod.SlotClock;

/// Slots per epoch from the active preset (convenience re-export).
pub const SLOTS_PER_EPOCH = config_mod.clock.SLOTS_PER_EPOCH;

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
