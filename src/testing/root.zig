//! Deterministic Simulation Testing (DST) primitives.
//!
//! Provides fully deterministic mocks for time, randomness, networking,
//! and storage — enabling reproducible simulation testing of the entire
//! beacon node. Same seed = identical execution.
//!
//! Follows TigerBeetle's testing infrastructure pattern, adapted for
//! Zig 0.16's `std.Io` abstraction and Ethereum consensus specifics.

const std = @import("std");

pub const sim_io = @import("sim_io.zig");
pub const sim_clock = @import("sim_clock.zig");
pub const sim_network = @import("sim_network.zig");
pub const sim_storage = @import("sim_storage.zig");
pub const block_generator = @import("block_generator.zig");
pub const attestation_generator = @import("attestation_generator.zig");
pub const invariant_checker = @import("invariant_checker.zig");
pub const sim_node_harness = @import("sim_node_harness.zig");
pub const sim_test_harness = @import("sim_test_harness.zig");
pub const sim_test = @import("sim_test.zig");
pub const cluster_invariant_checker = @import("cluster_invariant_checker.zig");
pub const sim_cluster = @import("sim_cluster.zig");
pub const sim_cluster_test = @import("sim_cluster_test.zig");
pub const head_tracker = @import("head_tracker.zig");
pub const block_import = @import("block_import.zig");
pub const block_import_test = @import("block_import_test.zig");

pub const SimIo = sim_io.SimIo;
pub const SlotClock = sim_clock.SlotClock;
pub const SimNetwork = sim_network.SimNetwork;
pub const SimStorage = sim_storage.SimStorage;
pub const BlockGenerator = block_generator.BlockGenerator;
pub const AttestationGenerator = attestation_generator;
pub const InvariantChecker = invariant_checker.InvariantChecker;
pub const SimTestHarness = sim_test_harness.SimTestHarness;
pub const SimNodeHarness = sim_node_harness.SimNodeHarness;
pub const ClusterInvariantChecker = cluster_invariant_checker.ClusterInvariantChecker;
pub const SimCluster = sim_cluster.SimCluster;
pub const HeadTracker = head_tracker.HeadTracker;
pub const BlockImporter = block_import.BlockImporter;

pub const SLOTS_PER_EPOCH = sim_clock.SLOTS_PER_EPOCH;

// ── Integration Tests ────────────────────────────────────────────────

test "integration: SimIo + SlotClock advancing through slots" {
    const genesis: u64 = 1_606_824_023;
    const sps: u64 = 12;

    var sim: SimIo = .{
        .prng = std.Random.DefaultPrng.init(42),
        .monotonic_ns = genesis * std.time.ns_per_s,
        .realtime_ns = @as(i128, genesis) * std.time.ns_per_s,
    };
    const sio = sim.io();
    const clock: SlotClock = .{ .genesis_time_s = genesis, .seconds_per_slot = sps };

    // At genesis: slot 0, epoch 0.
    try std.testing.expectEqual(@as(?u64, 0), clock.currentSlot(sio));
    try std.testing.expectEqual(@as(?u64, 0), clock.currentEpoch(sio));

    // Advance to slot 5.
    sim.advanceToSlot(5, genesis, sps);
    try std.testing.expectEqual(@as(?u64, 5), clock.currentSlot(sio));

    // Advance to first slot of epoch 1 (SLOTS_PER_EPOCH for any preset).
    sim.advanceToSlot(SLOTS_PER_EPOCH, genesis, sps);
    try std.testing.expectEqual(@as(?u64, SLOTS_PER_EPOCH), clock.currentSlot(sio));
    try std.testing.expectEqual(@as(?u64, 1), clock.currentEpoch(sio));
}

test "integration: SimIo + SimNetwork + SlotClock full scenario" {
    const genesis: u64 = 1_000_000;
    const sps: u64 = 12;

    var sim: SimIo = .{
        .prng = std.Random.DefaultPrng.init(99),
        .monotonic_ns = genesis * std.time.ns_per_s,
        .realtime_ns = @as(i128, genesis) * std.time.ns_per_s,
    };
    const sio = sim.io();
    const clock: SlotClock = .{ .genesis_time_s = genesis, .seconds_per_slot = sps };

    var net_prng = std.Random.DefaultPrng.init(99);
    var net = SimNetwork.init(std.testing.allocator, &net_prng, .{
        .min_latency_ms = 50,
        .max_latency_ms = 200,
    });
    defer net.deinit();

    // Node 0 proposes a block at slot 0.
    try std.testing.expect(clock.isProposalTime(sio));
    _ = try net.send(0, 1, "block_slot_0", .gossip, sim.monotonic_ns);
    _ = try net.send(0, 2, "block_slot_0", .gossip, sim.monotonic_ns);

    // Advance 4s into slot (attestation time).
    sim.advanceTime(4 * std.time.ns_per_s);
    try std.testing.expect(clock.isAttestationTime(sio));

    // Deliver messages that have arrived by now.
    const delivered = try net.tick(sim.monotonic_ns);

    // With 50-200ms latency, messages should have arrived within 4 seconds.
    try std.testing.expectEqual(@as(usize, 2), delivered.len);
    for (delivered) |msg| {
        try std.testing.expectEqualStrings("block_slot_0", msg.data);
        std.testing.allocator.free(msg.data);
    }

    // Advance to slot 1.
    sim.advanceToSlot(1, genesis, sps);
    try std.testing.expectEqual(@as(?u64, 1), clock.currentSlot(sio));
}

test "integration: SimIo + SimStorage CRUD with deterministic randomness" {
    var sim: SimIo = .{
        .prng = std.Random.DefaultPrng.init(7),
    };
    const sio = sim.io();

    var storage_prng = std.Random.DefaultPrng.init(7);
    var storage = SimStorage.init(std.testing.allocator, &storage_prng, .{});
    defer storage.deinit();

    // Generate a deterministic "block root" from the Io random.
    var root: [32]u8 = undefined;
    sio.random(&root);

    // Store and retrieve.
    try storage.putBlock(root, "block_data");
    const data = try storage.getBlock(root);
    try std.testing.expectEqualStrings("block_data", data.?);
}

test "integration: deterministic replay — same seed produces identical sequence" {
    const genesis: u64 = 1_000_000;

    var delivery_orders: [2][3]u8 = undefined;

    for (0..2) |run| {
        var sim: SimIo = .{
            .prng = std.Random.DefaultPrng.init(42),
            .monotonic_ns = genesis * std.time.ns_per_s,
            .realtime_ns = @as(i128, genesis) * std.time.ns_per_s,
        };

        var net_prng = std.Random.DefaultPrng.init(42);
        var net = SimNetwork.init(std.testing.allocator, &net_prng, .{
            .min_latency_ms = 10,
            .max_latency_ms = 100,
        });
        defer net.deinit();

        // Three nodes send messages.
        _ = try net.send(0, 3, "from_0", .gossip, sim.monotonic_ns);
        _ = try net.send(1, 3, "from_1", .gossip, sim.monotonic_ns);
        _ = try net.send(2, 3, "from_2", .gossip, sim.monotonic_ns);

        // Advance past max latency.
        sim.advanceTime(200 * std.time.ns_per_ms);
        const delivered = try net.tick(sim.monotonic_ns);

        for (delivered, 0..) |msg, i| {
            if (i < 3) delivery_orders[run][i] = msg.from;
            std.testing.allocator.free(msg.data);
        }
    }

    // Same seed → identical delivery order.
    try std.testing.expectEqualSlices(u8, &delivery_orders[0], &delivery_orders[1]);
}

test "integration: partition during slot progression" {
    const genesis: u64 = 1_000_000;
    const sps: u64 = 12;

    var sim: SimIo = .{
        .prng = std.Random.DefaultPrng.init(42),
        .monotonic_ns = genesis * std.time.ns_per_s,
        .realtime_ns = @as(i128, genesis) * std.time.ns_per_s,
    };
    const clock: SlotClock = .{ .genesis_time_s = genesis, .seconds_per_slot = sps };
    const sio = sim.io();

    var net_prng = std.Random.DefaultPrng.init(42);
    var net = SimNetwork.init(std.testing.allocator, &net_prng, .{
        .min_latency_ms = 10,
        .max_latency_ms = 10,
    });
    defer net.deinit();

    // Partition node 0 from node 1.
    net.partition(0, 1);

    // Node 0 tries to send to node 1 — blocked.
    const sent = try net.send(0, 1, "blocked", .gossip, sim.monotonic_ns);
    try std.testing.expect(!sent);

    // Node 0 can still send to node 2.
    const sent2 = try net.send(0, 2, "allowed", .gossip, sim.monotonic_ns);
    try std.testing.expect(sent2);

    // Advance a slot, heal, try again.
    sim.advanceToSlot(1, genesis, sps);
    try std.testing.expectEqual(@as(?u64, 1), clock.currentSlot(sio));

    net.heal(0, 1);
    const sent3 = try net.send(0, 1, "healed", .gossip, sim.monotonic_ns);
    try std.testing.expect(sent3);

    // Deliver everything.
    const delivered = try net.tick(sim.monotonic_ns + 100 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 2), delivered.len);

    for (delivered) |msg| std.testing.allocator.free(msg.data);
}

// Pull in all sub-module tests.
comptime {
    _ = sim_io;
    _ = sim_clock;
    _ = sim_network;
    _ = sim_storage;
    _ = block_generator;
    _ = attestation_generator;
    _ = invariant_checker;
    _ = sim_node_harness;
    _ = sim_test_harness;
    _ = sim_test;
    _ = cluster_invariant_checker;
    _ = sim_cluster;
    _ = sim_cluster_test;
    _ = head_tracker;
    _ = block_import;
    _ = block_import_test;
}

// ── DST expansion: fork choice, network partition, fault injection ────
pub const sim_forkchoice_test = @import("sim_forkchoice_test.zig");
pub const sim_network_partition_test = @import("sim_network_partition_test.zig");
pub const sim_fault_injection_test = @import("sim_fault_injection_test.zig");

comptime {
    _ = sim_forkchoice_test;
    _ = sim_network_partition_test;
    _ = sim_fault_injection_test;
}
