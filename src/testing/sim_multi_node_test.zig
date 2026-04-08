//! Multi-node controller-backed simulation tests.
//!
//! These cover the canonical SimController harness directly: head agreement,
//! determinism, participation/finality behavior, and partition recovery.

const std = @import("std");
const testing = std.testing;

const preset = @import("preset").preset;
const controller_mod = @import("sim_controller.zig");
const SimController = controller_mod.SimController;
const ControllerConfig = controller_mod.ControllerConfig;
const FinalityResult = controller_mod.FinalityResult;
const ClusterInvariantChecker = @import("cluster_invariant_checker.zig").ClusterInvariantChecker;

fn runSlots(ctrl: *SimController, count: u64) !FinalityResult {
    try ctrl.advanceSlots(count);
    return ctrl.getFinalityResult();
}

fn runSlotsCollect(ctrl: *SimController, count: u64) !struct {
    blocks_produced: u64,
    saw_epoch_transition: bool,
} {
    const blocks_before = ctrl.total_blocks;
    var saw_epoch_transition = false;
    for (0..count) |_| {
        const tick = try ctrl.advanceSlot();
        saw_epoch_transition = saw_epoch_transition or tick.epoch_transition;
    }
    return .{
        .blocks_produced = ctrl.total_blocks - blocks_before,
        .saw_epoch_transition = saw_epoch_transition,
    };
}

fn headStateRoot(ctrl: *SimController, node_idx: usize) ![32]u8 {
    const head_state = try ctrl.nodes[node_idx].cloneHeadStateSnapshot();
    defer {
        head_state.deinit();
        testing.allocator.destroy(head_state);
    }
    return (try head_state.state.hashTreeRoot()).*;
}

fn expectAllNodesAgreeOnHeadState(ctrl: *SimController) !void {
    const root_0 = try headStateRoot(ctrl, 0);
    const num_nodes: usize = @intCast(ctrl.num_nodes);
    for (1..num_nodes) |i| {
        const root_i = try headStateRoot(ctrl, i);
        try testing.expectEqualSlices(u8, &root_0, &root_i);
    }
}

// ── Test 1: Happy multi-node run — all nodes agree ───────────────────

test "multi-node: happy path — 4 nodes agree on state roots" {
    var ctrl = try SimController.init(testing.allocator, .{
        .num_nodes = 4,
        .seed = 42,
        .validator_count = 64,
    });
    defer ctrl.deinit();

    const result = try runSlots(&ctrl, 3);

    try testing.expectEqual(@as(u64, 3), result.slots_processed);
    try testing.expectEqual(@as(u64, 3), result.blocks_produced);
    try testing.expectEqual(@as(u64, 0), result.safety_violations);
    try testing.expectEqual(@as(u64, 0), result.state_divergences);
    try expectAllNodesAgreeOnHeadState(&ctrl);
}

// ── Test 2: Deterministic multi-node replay ──────────────────────────

test "multi-node: deterministic replay — same seed produces identical results" {
    var final_roots: [2][4][32]u8 = undefined;

    for (0..2) |run| {
        var ctrl = try SimController.init(testing.allocator, .{
            .num_nodes = 4,
            .seed = 99,
            .validator_count = 64,
        });
        defer ctrl.deinit();

        _ = try runSlots(&ctrl, 3);

        for (0..4) |i| {
            final_roots[run][i] = try headStateRoot(&ctrl, i);
        }
    }

    for (0..4) |i| {
        try testing.expectEqualSlices(u8, &final_roots[0][i], &final_roots[1][i]);
    }

    for (0..2) |run| {
        for (1..4) |i| {
            try testing.expectEqualSlices(u8, &final_roots[run][0], &final_roots[run][i]);
        }
    }
}

// ── Test 3: Two-node run ─────────────────────────────────────────────

test "multi-node: two nodes agree on state roots" {
    var ctrl = try SimController.init(testing.allocator, .{
        .num_nodes = 2,
        .seed = 77,
        .validator_count = 64,
    });
    defer ctrl.deinit();

    const result = try runSlots(&ctrl, 5);

    try testing.expectEqual(@as(u64, 5), result.slots_processed);
    try testing.expectEqual(@as(u64, 5), result.blocks_produced);
    try testing.expectEqual(@as(u64, 0), result.state_divergences);
    try expectAllNodesAgreeOnHeadState(&ctrl);
}

// ── Test 4: Cluster invariant checker standalone ─────────────────────

test "multi-node: invariant checker detects divergence" {
    var checker = try ClusterInvariantChecker.init(testing.allocator, 2);
    defer checker.deinit();

    const root_a = [_]u8{0xAA} ** 32;
    const root_b = [_]u8{0xBB} ** 32;
    const processed = [_]bool{ true, true };

    try checker.recordNodeState(0, 1, root_a, 0);
    try checker.recordNodeState(1, 1, root_b, 0);
    try checker.checkTick(1, &processed);

    try testing.expectEqual(@as(u64, 1), checker.state_divergences);

    const report = checker.checkFinal();
    try testing.expectEqual(@as(u64, 1), report.state_divergences);
}

// ── Test 5: Epoch transition across all nodes ────────────────────────

test "multi-node: epoch transition — all nodes cross boundary together" {
    var ctrl = try SimController.init(testing.allocator, .{
        .num_nodes = 2,
        .seed = 55,
        .validator_count = 64,
    });
    defer ctrl.deinit();

    const stats = try runSlotsCollect(&ctrl, preset.SLOTS_PER_EPOCH);

    try testing.expect(stats.saw_epoch_transition);
    try testing.expectEqual(preset.SLOTS_PER_EPOCH, stats.blocks_produced);
    try expectAllNodesAgreeOnHeadState(&ctrl);
}

// ── Test 6: Proposer offline — skipped slots ─────────────────────────

test "multi-node: proposer offline — nodes agree even with skips" {
    var ctrl = try SimController.init(testing.allocator, .{
        .num_nodes = 4,
        .seed = 123,
        .validator_count = 64,
    });
    defer ctrl.deinit();
    ctrl.proposer_offline_rate = 0.25;

    const stats = try runSlotsCollect(&ctrl, 8);
    const result = ctrl.getFinalityResult();

    try testing.expectEqual(@as(u64, 8), result.slots_processed);
    try testing.expect(stats.blocks_produced > 0);
    try testing.expect(stats.blocks_produced <= 8);
    try testing.expectEqual(@as(u64, 0), result.safety_violations);
    try testing.expectEqual(@as(u64, 0), result.state_divergences);
    try expectAllNodesAgreeOnHeadState(&ctrl);
}

// ── Test 7: Deterministic replay with proposer offline ───────────────

test "multi-node: deterministic replay with offline proposers" {
    var results: [2]FinalityResult = undefined;
    var final_roots: [2][32]u8 = undefined;

    for (0..2) |run| {
        var ctrl = try SimController.init(testing.allocator, .{
            .num_nodes = 4,
            .seed = 456,
            .validator_count = 64,
        });
        defer ctrl.deinit();
        ctrl.proposer_offline_rate = 0.3;

        results[run] = try runSlots(&ctrl, 5);
        final_roots[run] = try headStateRoot(&ctrl, 0);
    }

    try testing.expectEqual(results[0].blocks_produced, results[1].blocks_produced);
    try testing.expectEqual(results[0].slots_processed, results[1].slots_processed);
    try testing.expectEqualSlices(u8, &final_roots[0], &final_roots[1]);
}

// ── Test 8: Single-node run ──────────────────────────────────────────

test "multi-node: single node — trivially consistent" {
    var ctrl = try SimController.init(testing.allocator, .{
        .num_nodes = 1,
        .seed = 1,
        .validator_count = 64,
    });
    defer ctrl.deinit();

    const result = try runSlots(&ctrl, 3);

    try testing.expectEqual(@as(u64, 3), result.slots_processed);
    try testing.expectEqual(@as(u64, 3), result.blocks_produced);
    try testing.expectEqual(@as(u64, 0), result.safety_violations);
    try testing.expectEqual(@as(u64, 0), result.state_divergences);
}

// ── Test 9: Finality progresses with attestations ────────────────────

test "multi-node: finality progresses with 90% participation" {
    var ctrl = try SimController.init(testing.allocator, .{
        .num_nodes = 4,
        .seed = 42,
        .validator_count = 64,
        .participation_rate = 0.9,
    });
    defer ctrl.deinit();

    const slots_for_finality = preset.SLOTS_PER_EPOCH * 5;
    const result = try runSlots(&ctrl, slots_for_finality);

    try testing.expectEqual(@as(u64, slots_for_finality), result.slots_processed);
    try testing.expectEqual(@as(u64, 0), result.safety_violations);
    try testing.expectEqual(@as(u64, 0), result.state_divergences);
    try testing.expect(result.finalized_epoch > 0);
    try expectAllNodesAgreeOnHeadState(&ctrl);
}

test "multi-node: low participation — finality stalls vs high participation" {
    const num_slots = preset.SLOTS_PER_EPOCH * 5;

    var low_finalized: u64 = undefined;
    {
        var ctrl = try SimController.init(testing.allocator, .{
            .num_nodes = 4,
            .seed = 42,
            .validator_count = 64,
            .participation_rate = 0.3,
        });
        defer ctrl.deinit();

        const result = try runSlots(&ctrl, num_slots);
        try testing.expectEqual(@as(u64, 0), result.safety_violations);
        try testing.expectEqual(@as(u64, 0), result.state_divergences);
        low_finalized = result.finalized_epoch;
        try expectAllNodesAgreeOnHeadState(&ctrl);
    }

    var high_finalized: u64 = undefined;
    {
        var ctrl = try SimController.init(testing.allocator, .{
            .num_nodes = 4,
            .seed = 42,
            .validator_count = 64,
            .participation_rate = 1.0,
        });
        defer ctrl.deinit();

        const result = try runSlots(&ctrl, num_slots);
        try testing.expectEqual(@as(u64, 0), result.safety_violations);
        try testing.expectEqual(@as(u64, 0), result.state_divergences);
        high_finalized = result.finalized_epoch;
    }

    try testing.expect(high_finalized > low_finalized);
}

// ── Test 11: Deterministic attestation replay ────────────────────────

test "multi-node: deterministic replay with attestations" {
    var results: [2]FinalityResult = undefined;
    var final_roots: [2][32]u8 = undefined;

    for (0..2) |run| {
        var ctrl = try SimController.init(testing.allocator, .{
            .num_nodes = 2,
            .seed = 777,
            .validator_count = 64,
            .participation_rate = 0.8,
        });
        defer ctrl.deinit();

        results[run] = try runSlots(&ctrl, 24);
        final_roots[run] = try headStateRoot(&ctrl, 0);
    }

    try testing.expectEqual(results[0].blocks_produced, results[1].blocks_produced);
    try testing.expectEqual(results[0].slots_processed, results[1].slots_processed);
    try testing.expectEqual(results[0].finalized_epoch, results[1].finalized_epoch);
    try testing.expectEqualSlices(u8, &final_roots[0], &final_roots[1]);
}

// ── Test 12: Single-node run with attestations ───────────────────────

test "multi-node: single node with attestations — finality progresses" {
    var ctrl = try SimController.init(testing.allocator, .{
        .num_nodes = 1,
        .seed = 1,
        .validator_count = 64,
        .participation_rate = 1.0,
    });
    defer ctrl.deinit();

    const slots_for_finality = preset.SLOTS_PER_EPOCH * 5;
    const result = try runSlots(&ctrl, slots_for_finality);

    try testing.expectEqual(@as(u64, slots_for_finality), result.slots_processed);
    try testing.expectEqual(@as(u64, slots_for_finality), result.blocks_produced);
    try testing.expectEqual(@as(u64, 0), result.safety_violations);
    try testing.expect(result.finalized_epoch > 0);
}

test "multi-node: network partition only delivers within proposer partition" {
    var ctrl = try SimController.init(testing.allocator, .{
        .num_nodes = 4,
        .seed = 2024,
        .validator_count = 64,
    });
    defer ctrl.deinit();

    try ctrl.executeStep(.{ .network_partition = .{
        .group_a = &[_]u8{ 0, 1 },
        .group_b = &[_]u8{ 2, 3 },
    } });
    const tick = try ctrl.advanceSlot();

    try testing.expect(tick.block_produced);
    try testing.expectError(error.HeadDisagreement, ctrl.checkInvariant(.head_agreement));
    try testing.expectEqual(@as(u64, 0), ctrl.checker.safety_violations);
}

test "multi-node: healed partition preserves finalized safety" {
    var ctrl = try SimController.init(testing.allocator, .{
        .num_nodes = 4,
        .seed = 2025,
        .validator_count = 64,
    });
    defer ctrl.deinit();

    try ctrl.executeStep(.{ .network_partition = .{
        .group_a = &[_]u8{ 0, 1 },
        .group_b = &[_]u8{ 2, 3 },
    } });
    _ = try runSlots(&ctrl, 2);
    try testing.expectEqual(@as(u64, 0), ctrl.checker.safety_violations);

    try ctrl.executeStep(.{ .heal_partition = {} });
    try ctrl.executeStep(.{ .advance_until = .{
        .condition = .head_agreement,
        .max_slots = preset.SLOTS_PER_EPOCH,
    } });

    try testing.expectEqual(@as(u64, 0), ctrl.checker.safety_violations);
}
