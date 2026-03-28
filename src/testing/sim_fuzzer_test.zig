//! Tests for the simulation fuzzer.
//!
//! Verifies that:
//!   - Random steps can be generated and executed without panic
//!   - Invariants are checked after each step
//!   - Deterministic replay produces identical results

const std = @import("std");
const testing = std.testing;

const preset = @import("preset").preset;

const SimController = @import("sim_controller.zig").SimController;
const SimFuzzer = @import("sim_fuzzer.zig").SimFuzzer;
const FuzzWeights = @import("sim_fuzzer.zig").FuzzWeights;
const Invariant = @import("scenario.zig").Invariant;

// ── Test 1: Fuzzer runs without panic ────────────────────────────────

test "fuzzer: 100 random steps without panic" {
    const allocator = testing.allocator;

    var ctrl = try SimController.init(allocator, .{
        .num_nodes = 2,
        .seed = 42,
        .validator_count = 64,
        .participation_rate = 1.0,
    });
    defer ctrl.deinit();

    const invariants = [_]Invariant{
        .safety,
        .no_state_divergence,
    };

    var fuzzer = SimFuzzer.init(
        allocator,
        &ctrl,
        12345,
        .{ .advance_slot = 80, .skip_slot = 10, .inject_fault = 5, .network_ops = 3, .participation_change = 2 },
        &invariants,
    );

    var result = try fuzzer.fuzz(100);
    defer result.deinit(allocator);

    // No safety violations with 2-node sync model.
    try testing.expectEqual(@as(u64, 0), ctrl.checker.safety_violations);
    try testing.expectEqual(@as(u64, 0), ctrl.checker.state_divergences);
    try testing.expectEqual(@as(u64, 100), result.steps_run);
    try testing.expect(result.ok());
}

// ── Test 2: Fuzzer deterministic replay ──────────────────────────────

test "fuzzer: deterministic replay — same seed same results" {
    const allocator = testing.allocator;
    const num_steps: u64 = 50;

    var step_counts: [2]u64 = undefined;
    var blocks: [2]u64 = undefined;

    for (0..2) |run| {
        var ctrl = try SimController.init(allocator, .{
            .num_nodes = 2,
            .seed = 99,
            .validator_count = 64,
            .participation_rate = 1.0,
        });
        defer ctrl.deinit();

        const invariants = [_]Invariant{.safety};

        var fuzzer = SimFuzzer.init(
            allocator,
            &ctrl,
            54321,
            .{},
            &invariants,
        );

        var result = try fuzzer.fuzz(num_steps);
        defer result.deinit(allocator);

        step_counts[run] = result.steps_run;
        blocks[run] = ctrl.total_blocks;
    }

    // Same seed → identical results.
    try testing.expectEqual(step_counts[0], step_counts[1]);
    try testing.expectEqual(blocks[0], blocks[1]);
}

// ── Test 3: Fuzzer with heavy fault injection ────────────────────────

test "fuzzer: heavy faults — no safety violations" {
    const allocator = testing.allocator;

    var ctrl = try SimController.init(allocator, .{
        .num_nodes = 2,
        .seed = 42,
        .validator_count = 64,
        .participation_rate = 0.9,
    });
    defer ctrl.deinit();

    const invariants = [_]Invariant{
        .safety,
        .no_state_divergence,
    };

    // Heavy fault injection weights.
    var fuzzer = SimFuzzer.init(
        allocator,
        &ctrl,
        77777,
        .{
            .advance_slot = 50,
            .skip_slot = 15,
            .inject_fault = 20,
            .network_ops = 10,
            .participation_change = 5,
        },
        &invariants,
    );

    var result = try fuzzer.fuzz(80);
    defer result.deinit(allocator);

    // Safety must hold even under heavy faults.
    try testing.expectEqual(@as(u64, 0), ctrl.checker.safety_violations);
    try testing.expectEqual(@as(u64, 0), ctrl.checker.state_divergences);
}

// ── Test 4: Fuzzer step history tracking ─────────────────────────────

test "fuzzer: step history recorded for reproducer" {
    const allocator = testing.allocator;

    var ctrl = try SimController.init(allocator, .{
        .num_nodes = 2,
        .seed = 42,
        .validator_count = 64,
        .participation_rate = 1.0,
    });
    defer ctrl.deinit();

    const invariants = [_]Invariant{.safety};

    var fuzzer = SimFuzzer.init(allocator, &ctrl, 42, .{}, &invariants);

    var result = try fuzzer.fuzz(20);
    defer result.deinit(allocator);

    // Step history should have exactly 20 entries.
    try testing.expectEqual(@as(usize, 20), result.step_history.items.len);
    try testing.expectEqual(@as(u64, 20), result.steps_run);
}
