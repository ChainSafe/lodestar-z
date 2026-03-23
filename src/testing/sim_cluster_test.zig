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
        .num_nodes = 2,
        .seed = 42,
        .validator_count = 64,
        .participation_rate = 0.9,
    });
    defer cluster.deinit();

    // Run enough slots for finality: need ~4+ epoch transitions.
    // Minimal preset: 8 slots/epoch.  State starts 1 slot before epoch boundary.
    // So: 1 slot to cross first boundary + 4*8 = 33 slots should be plenty.
    const result = try cluster.run(40);

    try testing.expectEqual(@as(u64, 40), result.slots_processed);
    try testing.expectEqual(@as(u64, 0), result.safety_violations);
    try testing.expectEqual(@as(u64, 0), result.state_divergences);

    // Finalized epoch must have advanced past 0.
    try testing.expect(result.finalized_epoch > 0);
}

// ── Test 10: Low participation prevents finality ─────────────────────

test "cluster: low participation prevents finality" {
    const allocator = testing.allocator;

    var cluster = try SimCluster.init(allocator, .{
        .num_nodes = 2,
        .seed = 42,
        .validator_count = 64,
        .participation_rate = 0.1,
    });
    defer cluster.deinit();

    // Run 40 slots — not enough participation for justification/finality.
    const result = try cluster.run(40);

    try testing.expectEqual(@as(u64, 40), result.slots_processed);
    try testing.expectEqual(@as(u64, 0), result.safety_violations);
    try testing.expectEqual(@as(u64, 0), result.state_divergences);

    // With only 10% participation, finality should NOT advance.
    // The initial state already has a finalized epoch set (current_epoch - 3),
    // so we check that it hasn't advanced further.
    // Actually, let's just verify it stays at its initial value.
    // The generated state has finalized_checkpoint.epoch = current_epoch - 3.
    // With 10% participation we expect no NEW finalization.
    // We track this via the cluster checker which records per-node finalized epochs.
    // Since the initial state already has a non-zero finalized epoch, we check
    // that no progress occurred by comparing with a 0% participation run.
    var cluster_zero = try SimCluster.init(allocator, .{
        .num_nodes = 2,
        .seed = 42,
        .validator_count = 64,
        .participation_rate = 0.0,
    });
    defer cluster_zero.deinit();

    const result_zero = try cluster_zero.run(40);

    // With 10% participation, finalized epoch should be <= the zero-participation case.
    // (Both should stay at the initial finalized epoch from genesis state.)
    try testing.expectEqual(result_zero.finalized_epoch, result.finalized_epoch);
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
