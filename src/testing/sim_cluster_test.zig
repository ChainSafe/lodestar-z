//! Multi-node cluster simulation tests.
//!
//! Proves that N nodes processing the same blocks produce identical state
//! roots, and that network faults cause graceful degradation without
//! safety violations.

const std = @import("std");
const testing = std.testing;

const sim_cluster = @import("sim_cluster.zig");
const SimCluster = sim_cluster.SimCluster;
const ClusterConfig = sim_cluster.ClusterConfig;
const RunResult = sim_cluster.RunResult;
const ClusterInvariantChecker = @import("cluster_invariant_checker.zig").ClusterInvariantChecker;

// ── Test 1: Happy cluster — all nodes agree ──────────────────────────

test "cluster: happy path — 4 nodes agree on state roots" {
    const allocator = testing.allocator;

    var cluster = try SimCluster.init(allocator, .{
        .num_nodes = 4,
        .seed = 42,
        .validator_count = 64,
    });
    defer cluster.deinit();

    // Run 3 slots — all nodes should produce identical state roots.
    const result = try cluster.run(3);

    try testing.expectEqual(@as(u64, 3), result.slots_processed);
    try testing.expectEqual(@as(u64, 3), result.blocks_produced);
    try testing.expectEqual(@as(u64, 0), result.safety_violations);
    try testing.expectEqual(@as(u64, 0), result.state_divergences);

    // Verify all nodes have the same head state root.
    const root_0 = (try cluster.nodes[0].head_state.state.hashTreeRoot()).*;
    for (1..4) |i| {
        const root_i = (try cluster.nodes[i].head_state.state.hashTreeRoot()).*;
        try testing.expectEqualSlices(u8, &root_0, &root_i);
    }
}

// ── Test 2: Deterministic cluster replay ─────────────────────────────

test "cluster: deterministic replay — same seed produces identical results" {
    const allocator = testing.allocator;
    const num_slots = 3;

    var final_roots: [2][4][32]u8 = undefined;

    for (0..2) |run| {
        var cluster = try SimCluster.init(allocator, .{
            .num_nodes = 4,
            .seed = 99,
            .validator_count = 64,
        });
        defer cluster.deinit();

        _ = try cluster.run(num_slots);

        for (0..4) |i| {
            final_roots[run][i] = (try cluster.nodes[i].head_state.state.hashTreeRoot()).*;
        }
    }

    // Same seed → identical state roots across all nodes in both runs.
    for (0..4) |i| {
        try testing.expectEqualSlices(u8, &final_roots[0][i], &final_roots[1][i]);
    }

    // All nodes within each run agree.
    for (0..2) |run| {
        for (1..4) |i| {
            try testing.expectEqualSlices(u8, &final_roots[run][0], &final_roots[run][i]);
        }
    }
}

// ── Test 3: Two-node cluster ─────────────────────────────────────────

test "cluster: two nodes agree on state roots" {
    const allocator = testing.allocator;

    var cluster = try SimCluster.init(allocator, .{
        .num_nodes = 2,
        .seed = 77,
        .validator_count = 64,
    });
    defer cluster.deinit();

    const result = try cluster.run(5);

    try testing.expectEqual(@as(u64, 5), result.slots_processed);
    try testing.expectEqual(@as(u64, 5), result.blocks_produced);
    try testing.expectEqual(@as(u64, 0), result.state_divergences);

    // Both nodes must have the same state root.
    const root_0 = (try cluster.nodes[0].head_state.state.hashTreeRoot()).*;
    const root_1 = (try cluster.nodes[1].head_state.state.hashTreeRoot()).*;
    try testing.expectEqualSlices(u8, &root_0, &root_1);
}

// ── Test 4: Cluster invariant checker standalone ─────────────────────

test "cluster: invariant checker detects divergence" {
    var checker = try ClusterInvariantChecker.init(testing.allocator, 2);
    defer checker.deinit();

    const root_a = [_]u8{0xAA} ** 32;
    const root_b = [_]u8{0xBB} ** 32;
    const processed = [_]bool{ true, true };

    // Two nodes produce different roots at the same slot — divergence.
    try checker.recordNodeState(0, 1, root_a, 0);
    try checker.recordNodeState(1, 1, root_b, 0);
    try checker.checkTick(1, &processed);

    try testing.expectEqual(@as(u64, 1), checker.state_divergences);

    const report = checker.checkFinal();
    try testing.expectEqual(@as(u64, 1), report.state_divergences);
}

// ── Test 5: Epoch transition across cluster ──────────────────────────

test "cluster: epoch transition — all nodes cross boundary together" {
    const allocator = testing.allocator;

    var cluster = try SimCluster.init(allocator, .{
        .num_nodes = 2,
        .seed = 55,
        .validator_count = 64,
    });
    defer cluster.deinit();

    // Process 1 slot — the test state starts 1 slot before epoch boundary.
    const tick_result = try cluster.tick();

    try testing.expect(tick_result.epoch_transition);
    try testing.expect(tick_result.block_produced);

    // Both nodes should have identical post-epoch-transition state.
    const root_0 = (try cluster.nodes[0].head_state.state.hashTreeRoot()).*;
    const root_1 = (try cluster.nodes[1].head_state.state.hashTreeRoot()).*;
    try testing.expectEqualSlices(u8, &root_0, &root_1);
}

// ── Test 6: Proposer offline — skipped slots ─────────────────────────

test "cluster: proposer offline — nodes agree even with skips" {
    const allocator = testing.allocator;

    var cluster = try SimCluster.init(allocator, .{
        .num_nodes = 4,
        .seed = 123,
        .validator_count = 64,
        .proposer_offline_rate = 0.25,
    });
    defer cluster.deinit();

    // Run 8 slots with 25% skip rate.
    const result = try cluster.run(8);

    try testing.expectEqual(@as(u64, 8), result.slots_processed);
    // Some blocks should be produced, some skipped.
    try testing.expect(result.blocks_produced > 0);
    try testing.expect(result.blocks_produced <= 8);
    try testing.expectEqual(@as(u64, 0), result.safety_violations);
    try testing.expectEqual(@as(u64, 0), result.state_divergences);

    // All nodes must still agree.
    const root_0 = (try cluster.nodes[0].head_state.state.hashTreeRoot()).*;
    for (1..4) |i| {
        const root_i = (try cluster.nodes[i].head_state.state.hashTreeRoot()).*;
        try testing.expectEqualSlices(u8, &root_0, &root_i);
    }
}

// ── Test 7: Deterministic replay with proposer offline ───────────────

test "cluster: deterministic replay with offline proposers" {
    const allocator = testing.allocator;

    var results: [2]RunResult = undefined;
    var final_roots: [2][32]u8 = undefined;

    for (0..2) |run| {
        var cluster = try SimCluster.init(allocator, .{
            .num_nodes = 4,
            .seed = 456,
            .validator_count = 64,
            .proposer_offline_rate = 0.3,
        });
        defer cluster.deinit();

        results[run] = try cluster.run(5);
        final_roots[run] = (try cluster.nodes[0].head_state.state.hashTreeRoot()).*;
    }

    // Same seed → identical results.
    try testing.expectEqual(results[0].blocks_produced, results[1].blocks_produced);
    try testing.expectEqual(results[0].slots_processed, results[1].slots_processed);
    try testing.expectEqualSlices(u8, &final_roots[0], &final_roots[1]);
}

// ── Test 8: Single node cluster ──────────────────────────────────────

test "cluster: single node — trivially consistent" {
    const allocator = testing.allocator;

    var cluster = try SimCluster.init(allocator, .{
        .num_nodes = 1,
        .seed = 1,
        .validator_count = 64,
    });
    defer cluster.deinit();

    const result = try cluster.run(3);

    try testing.expectEqual(@as(u64, 3), result.slots_processed);
    try testing.expectEqual(@as(u64, 3), result.blocks_produced);
    try testing.expectEqual(@as(u64, 0), result.safety_violations);
    try testing.expectEqual(@as(u64, 0), result.state_divergences);
}

// ── Test 9: Finality progresses with attestations ────────────────────

test "cluster: finality progresses with 90% participation" {
    const allocator = testing.allocator;

    var cluster = try SimCluster.init(allocator, .{
        .num_nodes = 4,
        .seed = 42,
        .validator_count = 64,
        .participation_rate = 0.9,
    });
    defer cluster.deinit();

    // Run enough slots for finality to progress (3+ epochs minimum).
    // With mainnet preset (32 slots/epoch), 128 slots = 4 epochs.
    const preset_mod = @import("preset").preset;
    const slots_for_finality = preset_mod.SLOTS_PER_EPOCH * 5;
    const result = try cluster.run(slots_for_finality);

    try testing.expectEqual(@as(u64, slots_for_finality), result.slots_processed);
    try testing.expectEqual(@as(u64, 0), result.safety_violations);
    try testing.expectEqual(@as(u64, 0), result.state_divergences);

    // Finality must have progressed past epoch 0 with 90% participation.
    try testing.expect(result.finalized_epoch > 0);

    // All nodes must agree on state.
    const root_0 = (try cluster.nodes[0].head_state.state.hashTreeRoot()).*;
    for (1..4) |i| {
        const root_i = (try cluster.nodes[i].head_state.state.hashTreeRoot()).*;
        try testing.expectEqualSlices(u8, &root_0, &root_i);
    }
}

test "cluster: low participation — finality stalls vs high participation" {
    const allocator = testing.allocator;
    const preset_mod = @import("preset").preset;
    const num_epochs = 5;
    const num_slots = preset_mod.SLOTS_PER_EPOCH * num_epochs;

    // Run with LOW participation (30%).
    var low_finalized: u64 = undefined;
    {
        var cluster = try SimCluster.init(allocator, .{
            .num_nodes = 4,
            .seed = 42,
            .validator_count = 64,
            .participation_rate = 0.3,
        });
        defer cluster.deinit();

        const result = try cluster.run(num_slots);
        try testing.expectEqual(@as(u64, 0), result.safety_violations);
        try testing.expectEqual(@as(u64, 0), result.state_divergences);
        low_finalized = result.finalized_epoch;

        // All nodes must agree.
        const root_0 = (try cluster.nodes[0].head_state.state.hashTreeRoot()).*;
        for (1..4) |i| {
            const root_i = (try cluster.nodes[i].head_state.state.hashTreeRoot()).*;
            try testing.expectEqualSlices(u8, &root_0, &root_i);
        }
    }

    // Run with HIGH participation (100%).
    var high_finalized: u64 = undefined;
    {
        var cluster = try SimCluster.init(allocator, .{
            .num_nodes = 4,
            .seed = 42,
            .validator_count = 64,
            .participation_rate = 1.0,
        });
        defer cluster.deinit();

        const result = try cluster.run(num_slots);
        try testing.expectEqual(@as(u64, 0), result.safety_violations);
        try testing.expectEqual(@as(u64, 0), result.state_divergences);
        high_finalized = result.finalized_epoch;
    }

    // High participation should achieve more finality than low.
    try testing.expect(high_finalized > low_finalized);
}

// ── Test 11: Deterministic attestation replay ────────────────────────

test "cluster: deterministic replay with attestations" {
    const allocator = testing.allocator;

    var results: [2]RunResult = undefined;
    var final_roots: [2][32]u8 = undefined;

    for (0..2) |run| {
        var cluster = try SimCluster.init(allocator, .{
            .num_nodes = 2,
            .seed = 777,
            .validator_count = 64,
            .participation_rate = 0.8,
        });
        defer cluster.deinit();

        results[run] = try cluster.run(24);
        final_roots[run] = (try cluster.nodes[0].head_state.state.hashTreeRoot()).*;
    }

    // Same seed → identical results.
    try testing.expectEqual(results[0].blocks_produced, results[1].blocks_produced);
    try testing.expectEqual(results[0].slots_processed, results[1].slots_processed);
    try testing.expectEqual(results[0].finalized_epoch, results[1].finalized_epoch);
    try testing.expectEqualSlices(u8, &final_roots[0], &final_roots[1]);
}

// ── Test 12: Single node cluster with attestations ───────────────────

test "cluster: single node with attestations — finality progresses" {
    const allocator = testing.allocator;

    var cluster = try SimCluster.init(allocator, .{
        .num_nodes = 1,
        .seed = 1,
        .validator_count = 64,
        .participation_rate = 1.0,
    });
    defer cluster.deinit();

    // Run enough slots for finality with 100% participation.
    const preset_mod = @import("preset").preset;
    const slots_for_finality = preset_mod.SLOTS_PER_EPOCH * 5;
    const result = try cluster.run(slots_for_finality);

    try testing.expectEqual(@as(u64, slots_for_finality), result.slots_processed);
    try testing.expectEqual(@as(u64, slots_for_finality), result.blocks_produced);
    try testing.expectEqual(@as(u64, 0), result.safety_violations);

    // With 100% participation, single node should reach finality.
    try testing.expect(result.finalized_epoch > 0);
}
