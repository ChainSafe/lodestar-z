//! Deterministic simulation tests: single-node STFN.
//!
//! These tests prove end-to-end determinism of the simulation framework
//! by running the real state transition with deterministic block generation
//! and verifying that identical seeds produce identical state histories.

const std = @import("std");
const testing = std.testing;
const preset = @import("preset").preset;

const StateHistoryEntry = @import("invariant_checker.zig").StateHistoryEntry;

const SimTestHarness = @import("sim_test_harness.zig").SimTestHarness;

// ── Test 1: Happy path — process a few slots with blocks ─────────────

test "sim: happy path — process slots with blocks" {
    const allocator = testing.allocator;

    var harness = try SimTestHarness.init(allocator, 42);
    defer harness.deinit();

    // Process 3 slots with blocks.
    const r1 = try harness.sim.processSlot(false);
    try testing.expect(r1.block_processed);

    const r2 = try harness.sim.processSlot(false);
    try testing.expect(r2.block_processed);

    const r3 = try harness.sim.processSlot(false);
    try testing.expect(r3.block_processed);

    try testing.expectEqual(@as(u64, 3), harness.sim.slots_processed);
    try testing.expectEqual(@as(u64, 3), harness.sim.blocks_processed);

    // State roots must differ between slots.
    try testing.expect(!std.mem.eql(u8, &r1.state_root, &r2.state_root));
    try testing.expect(!std.mem.eql(u8, &r2.state_root, &r3.state_root));

    // Invariant checker should have 3 entries.
    try testing.expectEqual(@as(usize, 3), harness.sim.checker.state_history.items.len);
}

// ── Test 2: Skip slots ───────────────────────────────────────────────

test "sim: skip slots — state advances without blocks" {
    const allocator = testing.allocator;

    var harness = try SimTestHarness.init(allocator, 99);
    defer harness.deinit();

    // Process a slot without a block (skip).
    const r1 = try harness.sim.processSlot(true);
    try testing.expect(!r1.block_processed);
    try testing.expectEqual(@as(u64, 1), harness.sim.slots_processed);
    try testing.expectEqual(@as(u64, 0), harness.sim.blocks_processed);

    // Then a slot with a block.
    const r2 = try harness.sim.processSlot(false);
    try testing.expect(r2.block_processed);
    try testing.expectEqual(@as(u64, 1), harness.sim.blocks_processed);

    // Roots differ.
    try testing.expect(!std.mem.eql(u8, &r1.state_root, &r2.state_root));
}

// ── Test 3: Deterministic replay — same seed, same state history ─────

test "sim: deterministic replay — same seed produces identical state history" {
    const allocator = testing.allocator;

    const num_slots = 3;
    var final_roots: [2][32]u8 = undefined;
    var history_storage: [2]std.ArrayListUnmanaged(StateHistoryEntry) = .{ .empty, .empty };
    defer history_storage[0].deinit(allocator);
    defer history_storage[1].deinit(allocator);

    for (0..2) |run| {
        var harness = try SimTestHarness.init(allocator, 42);
        defer harness.deinit();

        try harness.sim.processSlots(num_slots, 0.0);

        final_roots[run] = (try (harness.sim.getHeadState() orelse unreachable).state.hashTreeRoot()).*;

        // Copy checker history for post-run comparison.
        try history_storage[run].appendSlice(allocator, harness.sim.checker.state_history.items);
    }

    // Same seed → identical final state root.
    try testing.expectEqualSlices(u8, &final_roots[0], &final_roots[1]);

    // Same seed → identical history length.
    try testing.expectEqual(history_storage[0].items.len, history_storage[1].items.len);

    // Same seed → identical state roots at every slot.
    for (history_storage[0].items, history_storage[1].items) |a, b| {
        try testing.expectEqual(a.slot, b.slot);
        try testing.expectEqualSlices(u8, &a.state_root, &b.state_root);
    }
}

// ── Test 4: Epoch boundary ───────────────────────────────────────────

test "sim: epoch boundary — processes full epoch with transition" {
    const allocator = testing.allocator;

    var harness = try SimTestHarness.init(allocator, 77);
    defer harness.deinit();

    // The simulation anchor now starts at the beginning of a coherent epoch.
    // Processing a full epoch of blocks should trigger exactly one epoch transition.
    try harness.sim.processSlots(preset.SLOTS_PER_EPOCH, 0.0);

    try testing.expectEqual(preset.SLOTS_PER_EPOCH, harness.sim.slots_processed);
    try testing.expectEqual(preset.SLOTS_PER_EPOCH, harness.sim.blocks_processed);
    try testing.expectEqual(@as(u64, 1), harness.sim.epochs_processed);
}

// ── Test 5: Scenario with skip rate ──────────────────────────────────

test "sim: scenario with skip rate — some slots skipped deterministically" {
    const allocator = testing.allocator;

    var harness = try SimTestHarness.init(allocator, 55);
    defer harness.deinit();

    // Process 5 slots with 50% skip rate (deterministic via PRNG).
    try harness.sim.processSlots(5, 0.5);

    try testing.expectEqual(@as(u64, 5), harness.sim.slots_processed);
    // Some blocks should have been processed, some skipped.
    try testing.expect(harness.sim.blocks_processed > 0);
    try testing.expect(harness.sim.blocks_processed < 5);
}

// ── Test 6: Blocks with attestations — single-node ───────────────────

test "sim: blocks with attestations — single node, 40 slots" {
    const allocator = testing.allocator;

    var harness = try SimTestHarness.init(allocator, 42);
    defer harness.deinit();

    // Enable full attestation participation.
    harness.sim.participation_rate = 1.0;

    // Process 40 slots (slightly more than one epoch with mainnet preset).
    try harness.sim.processSlots(40, 0.0);

    try testing.expectEqual(@as(u64, 40), harness.sim.slots_processed);
    try testing.expectEqual(@as(u64, 40), harness.sim.blocks_processed);

    // Must have crossed at least one epoch boundary.
    try testing.expect(harness.sim.epochs_processed >= 1);

    // Invariant checker should have 40 entries.
    try testing.expectEqual(@as(usize, 40), harness.sim.checker.state_history.items.len);
}

// ── Test 7: Deterministic attestation replay — single node ───────────

test "sim: deterministic attestation replay — same seed same finality" {
    const allocator = testing.allocator;
    const num_slots = 40;

    var final_roots: [2][32]u8 = undefined;
    var finalized_epochs: [2]u64 = undefined;
    var history_storage: [2]std.ArrayListUnmanaged(StateHistoryEntry) = .{ .empty, .empty };
    defer history_storage[0].deinit(allocator);
    defer history_storage[1].deinit(allocator);

    for (0..2) |run| {
        var harness = try SimTestHarness.init(allocator, 42);
        defer harness.deinit();

        harness.sim.participation_rate = 1.0;

        try harness.sim.processSlots(num_slots, 0.0);

        final_roots[run] = (try (harness.sim.getHeadState() orelse unreachable).state.hashTreeRoot()).*;
        finalized_epochs[run] = harness.sim.checker.finalized_epoch;

        // Copy checker history for post-run comparison.
        try history_storage[run].appendSlice(allocator, harness.sim.checker.state_history.items);
    }

    // Same seed → identical final state root.
    try testing.expectEqualSlices(u8, &final_roots[0], &final_roots[1]);

    // Same seed → identical finalized epoch.
    try testing.expectEqual(finalized_epochs[0], finalized_epochs[1]);

    // Same seed → identical history length and state roots at every slot.
    try testing.expectEqual(history_storage[0].items.len, history_storage[1].items.len);
    for (history_storage[0].items, history_storage[1].items) |a, b| {
        try testing.expectEqual(a.slot, b.slot);
        try testing.expectEqualSlices(u8, &a.state_root, &b.state_root);
    }
}

// ── Test 8: Minimal attestation epoch crossing ────────────────────────

test "sim: blocks with attestations — single epoch then boundary" {
    const allocator = testing.allocator;

    var harness = try SimTestHarness.init(allocator, 77);
    defer harness.deinit();

    harness.sim.participation_rate = 1.0;

    // The simulation anchor starts at the beginning of a coherent epoch.
    // Process a full epoch plus one extra slot so attestation-bearing blocks cross
    // a real epoch boundary under the normal runtime path.
    try harness.sim.processSlots(preset.SLOTS_PER_EPOCH + 1, 0.0);

    try testing.expectEqual(@as(u64, preset.SLOTS_PER_EPOCH + 1), harness.sim.slots_processed);
    try testing.expectEqual(@as(u64, preset.SLOTS_PER_EPOCH + 1), harness.sim.blocks_processed);
    try testing.expectEqual(@as(u64, 1), harness.sim.epochs_processed);
}
