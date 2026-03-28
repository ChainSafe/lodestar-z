//! Tests for the scenario system and SimController.
//!
//! Verifies that:
//!   - SimController can advance slots and track finality
//!   - Built-in scenarios execute without invariant violations
//!   - Deterministic replay produces identical results

const std = @import("std");
const testing = std.testing;

const preset = @import("preset").preset;

const SimController = @import("sim_controller.zig").SimController;
const ControllerConfig = @import("sim_controller.zig").ControllerConfig;
const FinalityResult = @import("sim_controller.zig").FinalityResult;
const scenario = @import("scenario.zig");

// ── Test 1: Controller basic slot advancement ────────────────────────

test "controller: advance slots — all nodes agree" {
    const allocator = testing.allocator;

    var ctrl = try SimController.init(allocator, .{
        .num_nodes = 2,
        .seed = 42,
        .validator_count = 64,
        .participation_rate = 1.0,
    });
    defer ctrl.deinit();

    // Advance 3 slots — advanceSlot always produces a block.
    for (0..3) |_| {
        const result = try ctrl.advanceSlot();
        try testing.expect(result.block_produced);
    }

    try testing.expectEqual(@as(u64, 3), ctrl.total_slots);
    try testing.expectEqual(@as(u64, 3), ctrl.total_blocks);
    try testing.expectEqual(@as(u64, 0), ctrl.checker.safety_violations);
    try testing.expectEqual(@as(u64, 0), ctrl.checker.state_divergences);
}

// ── Test 2: Controller skip slot ─────────────────────────────────────

test "controller: skip slot — no block produced" {
    const allocator = testing.allocator;

    var ctrl = try SimController.init(allocator, .{
        .num_nodes = 2,
        .seed = 42,
        .validator_count = 64,
    });
    defer ctrl.deinit();

    const result = try ctrl.advanceSlotWithSkip(true);
    try testing.expect(!result.block_produced);
    try testing.expectEqual(@as(u64, 1), ctrl.total_slots);
    try testing.expectEqual(@as(u64, 0), ctrl.total_blocks);
}

// ── Test 3: Controller reaches finality ──────────────────────────────

test "controller: advance enough slots — reaches finality" {
    const allocator = testing.allocator;

    var ctrl = try SimController.init(allocator, .{
        .num_nodes = 2,
        .seed = 42,
        .validator_count = 64,
        .participation_rate = 1.0,
    });
    defer ctrl.deinit();

    const slots_for_finality = preset.SLOTS_PER_EPOCH * 5;
    try ctrl.advanceSlots(slots_for_finality);

    const result = ctrl.getFinalityResult();
    try testing.expectEqual(@as(u64, slots_for_finality), result.slots_processed);
    try testing.expectEqual(@as(u64, 0), result.safety_violations);
    try testing.expectEqual(@as(u64, 0), result.state_divergences);
    try testing.expect(result.finalized_epoch > 0);
}

// ── Test 4: Run until finality ───────────────────────────────────────

test "controller: runUntilFinality — stops when finalized" {
    const allocator = testing.allocator;

    var ctrl = try SimController.init(allocator, .{
        .num_nodes = 2,
        .seed = 99,
        .validator_count = 64,
        .participation_rate = 1.0,
    });
    defer ctrl.deinit();

    const result = try ctrl.runUntilFinality(preset.SLOTS_PER_EPOCH * 10);

    try testing.expect(result.finalized_epoch > 0);
    try testing.expectEqual(@as(u64, 0), result.safety_violations);
    try testing.expectEqual(@as(u64, 0), result.state_divergences);
    // Should stop before max_slots.
    try testing.expect(result.slots_processed < preset.SLOTS_PER_EPOCH * 10);
}

// ── Test 5: Deterministic replay ─────────────────────────────────────

test "controller: deterministic replay — same seed same results" {
    const allocator = testing.allocator;
    const num_slots: u64 = preset.SLOTS_PER_EPOCH * 3;

    var results: [2]FinalityResult = undefined;

    for (0..2) |run| {
        var ctrl = try SimController.init(allocator, .{
            .num_nodes = 2,
            .seed = 777,
            .validator_count = 64,
            .participation_rate = 0.9,
        });
        defer ctrl.deinit();

        try ctrl.advanceSlots(num_slots);
        results[run] = ctrl.getFinalityResult();
    }

    try testing.expectEqual(results[0].slots_processed, results[1].slots_processed);
    try testing.expectEqual(results[0].blocks_produced, results[1].blocks_produced);
    try testing.expectEqual(results[0].finalized_epoch, results[1].finalized_epoch);
}

// ── Test 6: Missed proposals — no safety violations ──────────────────

test "controller: missed proposals — no safety violations" {
    const allocator = testing.allocator;

    var ctrl = try SimController.init(allocator, .{
        .num_nodes = 2,
        .seed = 42,
        .validator_count = 64,
        .participation_rate = 1.0,
    });
    defer ctrl.deinit();

    // Advance 1 epoch normally.
    try ctrl.advanceSlots(preset.SLOTS_PER_EPOCH);

    // Skip a few slots.
    _ = try ctrl.advanceSlotWithSkip(true);
    _ = try ctrl.advanceSlotWithSkip(true);
    _ = try ctrl.advanceSlot();
    _ = try ctrl.advanceSlot();

    // Continue normally.
    try ctrl.advanceSlots(preset.SLOTS_PER_EPOCH * 3);

    const result = ctrl.getFinalityResult();
    try testing.expectEqual(@as(u64, 0), result.safety_violations);
    try testing.expectEqual(@as(u64, 0), result.state_divergences);
}

// ── Test 7: Late attestations — safety preserved ─────────────────────

test "controller: late attestations — safety preserved" {
    const allocator = testing.allocator;

    var ctrl = try SimController.init(allocator, .{
        .num_nodes = 2,
        .seed = 42,
        .validator_count = 64,
        .participation_rate = 0.0,
    });
    defer ctrl.deinit();

    // Phase 1: no attestations for 2 epochs.
    try ctrl.advanceSlots(preset.SLOTS_PER_EPOCH * 2);

    // Phase 2: enable attestations.
    for (ctrl.nodes) |*n| n.participation_rate = 1.0;
    try ctrl.advanceSlots(preset.SLOTS_PER_EPOCH * 4);

    const result = ctrl.getFinalityResult();
    try testing.expectEqual(@as(u64, 0), result.safety_violations);
    try testing.expectEqual(@as(u64, 0), result.state_divergences);
    // Finality should advance after attestations start.
    try testing.expect(result.finalized_epoch > 0);
}
