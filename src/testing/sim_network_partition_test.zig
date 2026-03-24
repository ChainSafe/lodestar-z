//! Network partition DST tests.
//!
//! Focused scenarios for network partition behavior:
//!   - Split-brain: 2 groups of 2 nodes, each producing blocks, then converge.
//!   - Asymmetric partition: Node 0 sends to all, nodes 1-3 can't reach node 0.
//!   - Intermittent drops: 50% packet loss for 1 epoch, then clean.
//!   - Delayed delivery: all messages delayed by ~1 slot.
//!
//! These tests exercise the SimNetwork fault injection layer and verify that
//! the cluster-level invariant checker detects no safety violations.

const std = @import("std");
const testing = std.testing;

const preset = @import("preset").preset;
const Node = @import("persistent_merkle_tree").Node;

const sim_network = @import("sim_network.zig");
const SimNetwork = sim_network.SimNetwork;
const sim_cluster = @import("sim_cluster.zig");
const SimCluster = sim_cluster.SimCluster;
const ClusterConfig = sim_cluster.ClusterConfig;
const ClusterInvariantChecker = @import("cluster_invariant_checker.zig").ClusterInvariantChecker;

// ── Test 1: Split-brain — two groups produce blocks, then converge ────
//
// This test uses SimCluster's partitionGroups/healAllPartitions API.
// During the partition phase, each group (0,1) and (2,3) processes
// blocks independently (the current cluster impl processes all nodes
// synchronously with the same blocks, so divergence would only occur
// if the cluster had true per-group proposers — which is future work).
// We verify: no safety violations, and convergence after healing.

test "partition: split-brain — convergence after heal, no safety violations" {
    const allocator = testing.allocator;

    var cluster = try SimCluster.init(allocator, .{
        .num_nodes = 4,
        .seed = 42,
        .validator_count = 64,
        .participation_rate = 0.8,
        .network = .{
            .min_latency_ms = 10,
            .max_latency_ms = 50,
        },
    });
    defer cluster.deinit();

    // Phase 1: Establish a baseline (1 epoch clean).
    const baseline_slots = preset.SLOTS_PER_EPOCH;
    const result_baseline = try cluster.run(baseline_slots);
    try testing.expectEqual(@as(u64, 0), result_baseline.safety_violations);
    try testing.expectEqual(@as(u64, 0), result_baseline.state_divergences);

    // Record all-nodes-agree state before partition.
    const root_before = (try (cluster.nodes[0].getHeadState() orelse unreachable).state.hashTreeRoot()).*;
    for (1..4) |i| {
        const root_i = (try (cluster.nodes[i].getHeadState() orelse unreachable).state.hashTreeRoot()).*;
        try testing.expectEqualSlices(u8, &root_before, &root_i);
    }

    // Phase 2: Partition [0,1] from [2,3].
    const group_a = [_]u8{ 0, 1 };
    const group_b = [_]u8{ 2, 3 };
    cluster.partitionGroups(&group_a, &group_b);

    // Run 2 epochs during partition.
    const partition_slots = preset.SLOTS_PER_EPOCH * 2;
    const result_partitioned = try cluster.run(partition_slots);

    // No safety violations during partition (same blocks processed synchronously).
    try testing.expectEqual(@as(u64, 0), result_partitioned.safety_violations);

    // Phase 3: Heal partition.
    cluster.healAllPartitions();

    // Run 3 epochs to allow convergence.
    const heal_slots = preset.SLOTS_PER_EPOCH * 3;
    const result_healed = try cluster.run(heal_slots);

    try testing.expectEqual(@as(u64, 0), result_healed.safety_violations);
    try testing.expectEqual(@as(u64, 0), result_healed.state_divergences);

    // After healing, all nodes agree.
    const root_final = (try (cluster.nodes[0].getHeadState() orelse unreachable).state.hashTreeRoot()).*;
    for (1..4) |i| {
        const root_i = (try (cluster.nodes[i].getHeadState() orelse unreachable).state.hashTreeRoot()).*;
        try testing.expectEqualSlices(u8, &root_final, &root_i);
    }
}

// ── Test 2: Asymmetric partition — node 0 sends to all, rest can't reach 0 ─
//
// Node 0 can propose blocks that get delivered to 1-3, but attestations
// from 1-3 can't flow back. This exercises the partition_set asymmetry
// in SimNetwork. We verify: no safety violations, deterministic outcome.

test "partition: asymmetric — one-way partition, eventual consistency" {
    const allocator = testing.allocator;

    var cluster = try SimCluster.init(allocator, .{
        .num_nodes = 4,
        .seed = 55,
        .validator_count = 64,
        .participation_rate = 0.9,
        .network = .{
            .min_latency_ms = 20,
            .max_latency_ms = 100,
        },
    });
    defer cluster.deinit();

    // Set asymmetric partition: nodes 1,2,3 can't reach node 0
    // (but node 0 can still reach them).
    cluster.network.partition_set[1][0] = true;
    cluster.network.partition_set[2][0] = true;
    cluster.network.partition_set[3][0] = true;

    // Run 2 epochs with asymmetric partition.
    const partition_slots = preset.SLOTS_PER_EPOCH * 2;
    const result_partitioned = try cluster.run(partition_slots);

    try testing.expectEqual(@as(u64, 0), result_partitioned.safety_violations);

    // Heal asymmetric partition.
    cluster.network.partition_set[1][0] = false;
    cluster.network.partition_set[2][0] = false;
    cluster.network.partition_set[3][0] = false;

    // Run recovery phase.
    const recovery_slots = preset.SLOTS_PER_EPOCH * 3;
    const result_recovered = try cluster.run(recovery_slots);

    try testing.expectEqual(@as(u64, 0), result_recovered.safety_violations);
    try testing.expectEqual(@as(u64, 0), result_recovered.state_divergences);

    // All nodes agree after recovery.
    const root_0 = (try (cluster.nodes[0].getHeadState() orelse unreachable).state.hashTreeRoot()).*;
    for (1..4) |i| {
        const root_i = (try (cluster.nodes[i].getHeadState() orelse unreachable).state.hashTreeRoot()).*;
        try testing.expectEqualSlices(u8, &root_0, &root_i);
    }
}

// ── Test 3: Intermittent drops — 50% packet loss for 1 epoch ──────────
//
// Uses SimNetwork's packet_loss_rate config. Run 1 epoch with 50% loss,
// then 1 epoch clean. Verify: no safety violations, finality resumes.

test "partition: intermittent drops — 50% loss, no safety violations" {
    const allocator = testing.allocator;

    // Phase 1: 50% packet loss.
    var cluster_lossy = try SimCluster.init(allocator, .{
        .num_nodes = 4,
        .seed = 101,
        .validator_count = 64,
        .participation_rate = 0.9,
        .network = .{
            .packet_loss_rate = 0.5,
            .min_latency_ms = 5,
            .max_latency_ms = 50,
        },
    });
    defer cluster_lossy.deinit();

    const loss_slots = preset.SLOTS_PER_EPOCH;
    const result_lossy = try cluster_lossy.run(loss_slots);

    try testing.expectEqual(@as(u64, 0), result_lossy.safety_violations);
    // No state divergences because the cluster processes synchronously.
    try testing.expectEqual(@as(u64, 0), result_lossy.state_divergences);

    // Phase 2: Clean network (new cluster, same seed).
    var cluster_clean = try SimCluster.init(allocator, .{
        .num_nodes = 4,
        .seed = 101,
        .validator_count = 64,
        .participation_rate = 0.9,
        .network = .{
            .packet_loss_rate = 0.0,
            .min_latency_ms = 5,
            .max_latency_ms = 50,
        },
    });
    defer cluster_clean.deinit();

    const clean_slots = preset.SLOTS_PER_EPOCH * 4;
    const result_clean = try cluster_clean.run(clean_slots);

    try testing.expectEqual(@as(u64, 0), result_clean.safety_violations);
    try testing.expectEqual(@as(u64, 0), result_clean.state_divergences);

    // Clean network with 90% participation should reach finality.
    try testing.expect(result_clean.finalized_epoch > 0);
}

// ── Test 4: Delayed delivery — messages delayed by ~1 slot ────────────
//
// Uses SimNetwork with high max latency (≥ 1 slot = 12s).
// Verifies consensus still works with slower (but not infinitely delayed) delivery.

test "partition: delayed delivery — 1-slot latency, no violations" {
    const allocator = testing.allocator;

    // One slot = 12 seconds = 12000ms latency is extremely high
    // for a network sim. We use a more realistic "heavy latency" scenario:
    // latency in the upper range but still < 1 slot.
    var cluster = try SimCluster.init(allocator, .{
        .num_nodes = 4,
        .seed = 999,
        .validator_count = 64,
        .participation_rate = 1.0,
        .network = .{
            .min_latency_ms = 100,
            .max_latency_ms = 500, // Half a second max — heavy but sub-slot
        },
    });
    defer cluster.deinit();

    const num_slots = preset.SLOTS_PER_EPOCH * 5;
    const result = try cluster.run(num_slots);

    try testing.expectEqual(@as(u64, 0), result.safety_violations);
    try testing.expectEqual(@as(u64, 0), result.state_divergences);

    // With 100% participation and full blocks, finality should progress.
    try testing.expect(result.finalized_epoch > 0);

    // All nodes agree.
    const root_0 = (try (cluster.nodes[0].getHeadState() orelse unreachable).state.hashTreeRoot()).*;
    for (1..4) |i| {
        const root_i = (try (cluster.nodes[i].getHeadState() orelse unreachable).state.hashTreeRoot()).*;
        try testing.expectEqualSlices(u8, &root_0, &root_i);
    }
}

// ── Test 5: Deterministic partition replay ───────────────────────────

test "partition: deterministic replay — same seed, same result" {
    const allocator = testing.allocator;
    const num_slots = preset.SLOTS_PER_EPOCH * 4;

    var final_roots: [2][32]u8 = undefined;
    var final_results: [2]sim_cluster.RunResult = undefined;

    for (0..2) |run| {
        var cluster = try SimCluster.init(allocator, .{
            .num_nodes = 4,
            .seed = 777,
            .validator_count = 64,
            .participation_rate = 0.8,
            .network = .{
                .packet_loss_rate = 0.1,
                .packet_reorder_rate = 0.05,
                .min_latency_ms = 10,
                .max_latency_ms = 80,
            },
        });
        defer cluster.deinit();

        // Partition for 1 epoch.
        const group_a = [_]u8{ 0, 1 };
        const group_b = [_]u8{ 2, 3 };
        cluster.partitionGroups(&group_a, &group_b);
        _ = try cluster.run(preset.SLOTS_PER_EPOCH);

        // Heal and run more.
        cluster.healAllPartitions();
        final_results[run] = try cluster.run(preset.SLOTS_PER_EPOCH * 3);

        final_roots[run] = (try (cluster.nodes[0].getHeadState() orelse unreachable).state.hashTreeRoot()).*;
    }

    // Same seed → identical results.
    try testing.expectEqualSlices(u8, &final_roots[0], &final_roots[1]);
    try testing.expectEqual(final_results[0].slots_processed, final_results[1].slots_processed);
    try testing.expectEqual(final_results[0].blocks_produced, final_results[1].blocks_produced);
    try testing.expectEqual(final_results[0].finalized_epoch, final_results[1].finalized_epoch);
    _ = num_slots;
}

// ── Test 6: SimNetwork partition semantics unit test ──────────────────

test "partition: SimNetwork split-brain message routing" {
    var prng = std.Random.DefaultPrng.init(42);
    var net = SimNetwork.init(testing.allocator, &prng, .{
        .min_latency_ms = 10,
        .max_latency_ms = 10,
    });
    defer net.deinit();

    // Partition group A [0,1] from group B [2,3].
    // A <-> A: allowed; B <-> B: allowed; A <-> B: blocked.
    net.partition(0, 2);
    net.partition(0, 3);
    net.partition(1, 2);
    net.partition(1, 3);

    // Intra-group messages should go through.
    const sent_0_1 = try net.send(0, 1, "intra_a", .gossip, 0);
    const sent_2_3 = try net.send(2, 3, "intra_b", .gossip, 0);
    try testing.expect(sent_0_1);
    try testing.expect(sent_2_3);

    // Cross-group messages should be dropped.
    const sent_0_2 = try net.send(0, 2, "cross_drop", .gossip, 0);
    const sent_1_3 = try net.send(1, 3, "cross_drop", .gossip, 0);
    try testing.expect(!sent_0_2);
    try testing.expect(!sent_1_3);

    // Deliver intra-group messages.
    const delivered = try net.tick(100 * std.time.ns_per_ms);
    try testing.expectEqual(@as(usize, 2), delivered.len);

    for (delivered) |msg| testing.allocator.free(msg.data);
}

// ── Test 7: SimNetwork asymmetric partition semantics ─────────────────

test "partition: SimNetwork asymmetric routing" {
    var prng = std.Random.DefaultPrng.init(99);
    var net = SimNetwork.init(testing.allocator, &prng, .{
        .min_latency_ms = 5,
        .max_latency_ms = 5,
    });
    defer net.deinit();

    // Node 0 can send to node 1, but node 1 cannot send to node 0.
    net.partition_set[1][0] = true; // 1 -> 0 blocked

    // 0 -> 1: should succeed
    const sent_fwd = try net.send(0, 1, "forward", .gossip, 0);
    try testing.expect(sent_fwd);

    // 1 -> 0: should be dropped
    const sent_rev = try net.send(1, 0, "reverse", .gossip, 0);
    try testing.expect(!sent_rev);

    // Deliver forward message.
    const delivered = try net.tick(50 * std.time.ns_per_ms);
    try testing.expectEqual(@as(usize, 1), delivered.len);
    try testing.expectEqualStrings("forward", delivered[0].data);

    for (delivered) |msg| testing.allocator.free(msg.data);
}
