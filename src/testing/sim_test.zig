//! Deterministic simulation tests: single-node STFN.
//!
//! These tests prove end-to-end determinism of the simulation framework
//! by running the real state transition with deterministic block generation
//! and verifying that identical seeds produce identical state histories.

const std = @import("std");
const testing = std.testing;

const types = @import("consensus_types");
const preset_mod = @import("preset");
const preset = preset_mod.preset;
const config_mod = @import("config");
const fork_types = @import("fork_types");
const state_transition = @import("state_transition");
const Node = @import("persistent_merkle_tree").Node;

const CachedBeaconState = state_transition.CachedBeaconState;
const AnyBeaconState = fork_types.AnyBeaconState;
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

const SimBeaconNode = @import("sim_beacon_node.zig").SimBeaconNode;
const InvariantChecker = @import("invariant_checker.zig").InvariantChecker;
const StateHistoryEntry = @import("invariant_checker.zig").StateHistoryEntry;
const BlockGenerator = @import("block_generator.zig").BlockGenerator;

/// Wraps TestCachedBeaconState + SimBeaconNode with correct lifecycle management.
///
/// After SimBeaconNode processes blocks via stateTransition, the original
/// cached_state is replaced.  This helper ensures everything is freed
/// exactly once.
const SimTestHarness = struct {
    allocator: std.mem.Allocator,
    pool: *Node.Pool,
    // Resources owned by TestCachedBeaconState that outlive the state itself.
    config: *config_mod.BeaconConfig,
    pubkey_index_map: *state_transition.PubkeyIndexMap,
    index_pubkey_cache: *state_transition.Index2PubkeyCache,
    epoch_transition_cache: *state_transition.EpochTransitionCache,
    sim: SimBeaconNode,

    fn init(allocator: std.mem.Allocator, pool: *Node.Pool, seed: u64) !SimTestHarness {
        var test_state = try TestCachedBeaconState.init(allocator, pool, 64);

        const sim = try SimBeaconNode.init(allocator, test_state.cached_state, seed);

        return .{
            .allocator = allocator,
            .pool = pool,
            .config = test_state.config,
            .pubkey_index_map = test_state.pubkey_index_map,
            .index_pubkey_cache = test_state.index_pubkey_cache,
            .epoch_transition_cache = test_state.epoch_transition_cache,
            .sim = sim,
        };
    }

    fn deinit(self: *SimTestHarness) void {
        // Free the sim's current head state (may differ from original).
        self.sim.head_state.deinit();
        self.allocator.destroy(self.sim.head_state);
        self.sim.deinit();

        // Free TestCachedBeaconState ancillary resources.
        self.pubkey_index_map.deinit();
        self.allocator.destroy(self.pubkey_index_map);
        self.index_pubkey_cache.deinit();
        self.epoch_transition_cache.deinit();
        state_transition.deinitStateTransition();
        self.allocator.destroy(self.epoch_transition_cache);
        self.allocator.destroy(self.index_pubkey_cache);
        self.allocator.destroy(self.config);
    }
};

// ── Test 1: Happy path — process a few slots with blocks ─────────────

test "sim: happy path — process slots with blocks" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var harness = try SimTestHarness.init(allocator, &pool, 42);
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
    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var harness = try SimTestHarness.init(allocator, &pool, 99);
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
    var history_storage: [2]std.ArrayList(StateHistoryEntry) = .{ .empty, .empty };
    defer history_storage[0].deinit(allocator);
    defer history_storage[1].deinit(allocator);

    for (0..2) |run| {
        var pool = try Node.Pool.init(allocator, 500_000);
        defer pool.deinit();

        var harness = try SimTestHarness.init(allocator, &pool, 42);
        defer harness.deinit();

        try harness.sim.processSlots(num_slots, 0.0);

        final_roots[run] = (try harness.sim.head_state.state.hashTreeRoot()).*;

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
    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var harness = try SimTestHarness.init(allocator, &pool, 77);
    defer harness.deinit();

    // The generated test state starts at slot = ELECTRA_FORK_EPOCH * SLOTS_PER_EPOCH + 2025 * SLOTS_PER_EPOCH - 1
    // which is 1 slot before the epoch boundary. Processing one slot should trigger an epoch transition.
    const r1 = try harness.sim.processSlot(false);
    try testing.expect(r1.block_processed);
    try testing.expect(r1.epoch_transition);
    try testing.expectEqual(@as(u64, 1), harness.sim.epochs_processed);
}

// ── Test 5: Scenario with skip rate ──────────────────────────────────

test "sim: scenario with skip rate — some slots skipped deterministically" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var harness = try SimTestHarness.init(allocator, &pool, 55);
    defer harness.deinit();

    // Process 5 slots with 50% skip rate (deterministic via PRNG).
    try harness.sim.processSlots(5, 0.5);

    try testing.expectEqual(@as(u64, 5), harness.sim.slots_processed);
    // Some blocks should have been processed, some skipped.
    try testing.expect(harness.sim.blocks_processed > 0);
    try testing.expect(harness.sim.blocks_processed < 5);
}

// ── Test 6: Blocks with attestations — single node ───────────────────

test "sim: blocks with attestations — participation rate 0.9" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var harness = try SimTestHarness.init(allocator, &pool, 42);
    defer harness.deinit();

    // Enable attestations.
    harness.sim.participation_rate = 0.9;

    // Process 20 slots (multiple epochs in minimal preset: 8 slots/epoch).
    try harness.sim.processSlots(20, 0.0);

    try testing.expectEqual(@as(u64, 20), harness.sim.slots_processed);
    try testing.expectEqual(@as(u64, 20), harness.sim.blocks_processed);
}

// ── Test 7: Blocks with attestations — 40 slots (multiple epochs) ────

test "sim: blocks with attestations — 40 slots across multiple epochs" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var harness = try SimTestHarness.init(allocator, &pool, 42);
    defer harness.deinit();

    harness.sim.participation_rate = 0.9;

    // 40 slots = 5 epoch transitions for minimal preset (8 slots/epoch).
    try harness.sim.processSlots(40, 0.0);

    try testing.expectEqual(@as(u64, 40), harness.sim.slots_processed);
    try testing.expectEqual(@as(u64, 40), harness.sim.blocks_processed);

    // Check finality advanced.
    try testing.expect(harness.sim.checker.finalized_epoch > 0);
}
