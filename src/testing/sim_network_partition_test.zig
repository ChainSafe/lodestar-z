//! Network partition DST tests.
//!
//! Focused scenarios for network partition behavior:
//!   - Split-brain: 2 groups of 2 nodes, each producing blocks, then converge.
//!   - Asymmetric partition: Node 0 sends to all, nodes 1-3 can't reach node 0.
//!   - Intermittent drops: 50% packet loss for 1 epoch, then clean.
//!   - Delayed delivery: all messages delayed heavily.
//!
//! The multi-node integration coverage now runs through SimController; only the
//! raw SimNetwork routing semantics remain as unit tests at the transport layer.

const std = @import("std");
const testing = std.testing;

const preset = @import("preset").preset;

const sim_network = @import("sim_network.zig");
const SimNetwork = sim_network.SimNetwork;
const controller_mod = @import("sim_controller.zig");
const SimController = controller_mod.SimController;
const FinalityResult = controller_mod.FinalityResult;
const scenario = @import("scenario.zig");

fn runSlots(ctrl: *SimController, count: u64) !FinalityResult {
    try ctrl.advanceSlots(count);
    return ctrl.getFinalityResult();
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

// ── Test 1: Split-brain — two groups produce blocks, then converge ────

test "partition: split-brain — convergence after heal, no safety violations" {
    var ctrl = try SimController.init(testing.allocator, .{
        .num_nodes = 4,
        .seed = 42,
        .validator_count = 64,
        .participation_rate = 0.8,
        .network = .{
            .min_latency_ms = 10,
            .max_latency_ms = 50,
        },
    });
    defer ctrl.deinit();

    const result = try ctrl.runScenario(scenario.network_partition_quiescent_recovery);

    try testing.expectEqual(@as(u64, 0), result.safety_violations);
    try testing.expectEqual(@as(u64, 0), result.state_divergences);
    try ctrl.checkInvariant(.head_agreement);
    try expectAllNodesAgreeOnHeadState(&ctrl);
}

// ── Test 2: Asymmetric partition — node 0 sends to all, rest can't reach 0 ─

test "partition: asymmetric — one-way partition preserves safety and regains finality agreement" {
    var ctrl = try SimController.init(testing.allocator, .{
        .num_nodes = 4,
        .seed = 55,
        .validator_count = 64,
        .participation_rate = 0.9,
        .network = .{
            .min_latency_ms = 20,
            .max_latency_ms = 100,
        },
    });
    defer ctrl.deinit();

    ctrl.network.partition_set[1][0] = true;
    ctrl.network.partition_set[2][0] = true;
    ctrl.network.partition_set[3][0] = true;

    const result_partitioned = try runSlots(&ctrl, 6);
    try testing.expectEqual(@as(u64, 0), result_partitioned.safety_violations);

    ctrl.network.partition_set[1][0] = false;
    ctrl.network.partition_set[2][0] = false;
    ctrl.network.partition_set[3][0] = false;

    const result_recovered = try runSlots(&ctrl, 16);
    try testing.expectEqual(@as(u64, 0), result_recovered.safety_violations);
    try testing.expectEqual(@as(u64, 0), result_recovered.state_divergences);
    try ctrl.checkInvariant(.finality_agreement);
    try ctrl.checkInvariant(.{ .head_freshness = 8 });
}

// ── Test 3: Intermittent drops — 50% packet loss for 1 epoch ──────────

test "partition: intermittent drops — 50% loss, no safety violations" {
    var ctrl_lossy = try SimController.init(testing.allocator, .{
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
    defer ctrl_lossy.deinit();

    const result_lossy = try runSlots(&ctrl_lossy, preset.SLOTS_PER_EPOCH);
    try testing.expectEqual(@as(u64, 0), result_lossy.safety_violations);
    try testing.expectEqual(@as(u64, 0), result_lossy.state_divergences);

    var ctrl_clean = try SimController.init(testing.allocator, .{
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
    defer ctrl_clean.deinit();

    const result_clean = try runSlots(&ctrl_clean, preset.SLOTS_PER_EPOCH * 4);
    try testing.expectEqual(@as(u64, 0), result_clean.safety_violations);
    try testing.expectEqual(@as(u64, 0), result_clean.state_divergences);
    try testing.expect(result_clean.finalized_epoch > 0);
}

// ── Test 4: Delayed delivery — messages delayed heavily ───────────────

test "partition: delayed delivery — 1-slot latency, no violations" {
    var ctrl = try SimController.init(testing.allocator, .{
        .num_nodes = 4,
        .seed = 999,
        .validator_count = 64,
        .participation_rate = 1.0,
        .network = .{
            .min_latency_ms = 100,
            .max_latency_ms = 500,
        },
    });
    defer ctrl.deinit();

    const result = try runSlots(&ctrl, preset.SLOTS_PER_EPOCH * 5);

    try testing.expectEqual(@as(u64, 0), result.safety_violations);
    try testing.expectEqual(@as(u64, 0), result.state_divergences);
    try testing.expect(result.finalized_epoch > 0);
    try expectAllNodesAgreeOnHeadState(&ctrl);
}

// ── Test 5: Deterministic partition replay ───────────────────────────

test "partition: deterministic replay — same seed, same result" {
    var final_roots: [2][32]u8 = undefined;
    var final_results: [2]FinalityResult = undefined;

    for (0..2) |run| {
        var ctrl = try SimController.init(testing.allocator, .{
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
        defer ctrl.deinit();

        final_results[run] = try ctrl.runScenario(scenario.network_partition_quiescent_recovery);
        final_roots[run] = try headStateRoot(&ctrl, 0);
    }

    try testing.expectEqualSlices(u8, &final_roots[0], &final_roots[1]);
    try testing.expectEqual(final_results[0].slots_processed, final_results[1].slots_processed);
    try testing.expectEqual(final_results[0].blocks_produced, final_results[1].blocks_produced);
    try testing.expectEqual(final_results[0].finalized_epoch, final_results[1].finalized_epoch);
}

// ── Test 6: SimNetwork partition semantics unit test ──────────────────

test "partition: SimNetwork split-brain message routing" {
    var prng = std.Random.DefaultPrng.init(42);
    var net = SimNetwork.init(testing.allocator, &prng, .{
        .min_latency_ms = 10,
        .max_latency_ms = 10,
    });
    defer net.deinit();

    net.partition(0, 2);
    net.partition(0, 3);
    net.partition(1, 2);
    net.partition(1, 3);

    const sent_0_1 = try net.send(0, 1, "intra_a", .gossip, 0);
    const sent_2_3 = try net.send(2, 3, "intra_b", .gossip, 0);
    try testing.expect(sent_0_1);
    try testing.expect(sent_2_3);

    const sent_0_2 = try net.send(0, 2, "cross_drop", .gossip, 0);
    const sent_1_3 = try net.send(1, 3, "cross_drop", .gossip, 0);
    try testing.expect(!sent_0_2);
    try testing.expect(!sent_1_3);

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

    net.partition_set[1][0] = true;

    const sent_fwd = try net.send(0, 1, "forward", .gossip, 0);
    try testing.expect(sent_fwd);

    const sent_rev = try net.send(1, 0, "reverse", .gossip, 0);
    try testing.expect(!sent_rev);

    const delivered = try net.tick(50 * std.time.ns_per_ms);
    try testing.expectEqual(@as(usize, 1), delivered.len);
    try testing.expectEqualStrings("forward", delivered[0].data);

    for (delivered) |msg| testing.allocator.free(msg.data);
}
