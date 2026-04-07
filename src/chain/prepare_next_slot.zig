//! PrepareNextSlot — pre-compute state for the next slot.
//!
//! To reduce block processing latency, the beacon node runs state slot
//! processing 2/3 of the way through each slot (~8 seconds into a 12-second
//! slot). This advances the head state from slot N to slot N+1 so that when
//! a block arrives at slot N+1, the pre-state is already available.
//!
//! Architecture:
//! - onSlot(slot) is called at the 2/3 slot tick
//! - It clones the current head state and calls processSlots(head_slot + 1)
//! - The advanced state is stored in the BlockStateCache keyed by a
//!   synthetic state root, and in the CheckpointStateCache when on epoch boundary
//!
//! This is a best-effort optimization: failures are logged but not fatal.

const std = @import("std");
const Allocator = std.mem.Allocator;

const state_transition = @import("state_transition");
const regen_mod = @import("regen/root.zig");
const CachedBeaconState = state_transition.CachedBeaconState;
const CheckpointStateCache = regen_mod.CheckpointStateCache;
const BlockStateCache = regen_mod.BlockStateCache;
const StateGraphGate = regen_mod.StateGraphGate;
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const RegenRuntimeFixture = @import("regen/test_fixture.zig").RegenRuntimeFixture;

const preset = @import("preset").preset;

/// Configuration for the PrepareNextSlot timer.
pub const PrepareNextSlotConfig = struct {
    /// Whether to run the pre-computation at all.
    enabled: bool = true,
};

/// State for the prepare-next-slot optimization.
pub const PrepareNextSlot = struct {
    allocator: Allocator,
    config: PrepareNextSlotConfig,

    /// Reference to the block state cache (not owned).
    block_state_cache: *BlockStateCache,
    /// Reference to the checkpoint state cache (not owned).
    checkpoint_state_cache: *CheckpointStateCache,
    /// Shared published-state mutation gate.
    state_graph_gate: *StateGraphGate,

    /// Slot for which we last ran the pre-computation.
    last_prepared_slot: u64,

    pub fn init(
        allocator: Allocator,
        block_state_cache: *BlockStateCache,
        checkpoint_state_cache: *CheckpointStateCache,
        state_graph_gate: *StateGraphGate,
        config: PrepareNextSlotConfig,
    ) PrepareNextSlot {
        return .{
            .allocator = allocator,
            .config = config,
            .block_state_cache = block_state_cache,
            .checkpoint_state_cache = checkpoint_state_cache,
            .state_graph_gate = state_graph_gate,
            .last_prepared_slot = 0,
        };
    }

    pub fn deinit(_: *PrepareNextSlot) void {}

    /// Called at the 2/3 slot tick (slot N) to pre-compute state for slot N+1.
    ///
    /// Finds the head pre-state, advances it to slot N+1, and stores it in the
    /// block state cache so block import at slot N+1 can skip processSlots.
    ///
    /// `head_state_root` is the state root of the current chain head.
    /// Returns `null` if the head state is not available or computation fails.
    pub fn onSlot(
        self: *PrepareNextSlot,
        current_slot: u64,
        head_state_root: [32]u8,
    ) !void {
        if (!self.config.enabled) return;

        const target_slot = current_slot + 1;

        // Avoid redundant work.
        if (self.last_prepared_slot >= target_slot) return;

        // Find the head state.
        const head_state = self.block_state_cache.get(head_state_root) orelse {
            std.log.debug("prepare next slot: head state not in cache at slot {d}", .{current_slot});
            return;
        };

        var state_graph_lease = self.state_graph_gate.acquire();
        defer state_graph_lease.release();

        // Clone and advance.
        const advanced = try head_state.clone(self.allocator, .{ .transfer_cache = false });
        errdefer {
            advanced.deinit();
            self.allocator.destroy(advanced);
        }

        try state_transition.processSlots(self.allocator, advanced, target_slot, .{});
        try sealPublishedState(advanced);

        // Store in block state cache. The state root after advancing without a
        // block is the ephemeral intermediate state root.
        _ = try self.block_state_cache.add(advanced, false);

        // If this advances to an epoch boundary, also cache as a checkpoint state.
        const prev_epoch = computeEpochAtSlot(current_slot);
        const next_epoch = computeEpochAtSlot(target_slot);
        if (next_epoch != prev_epoch) {
            const cp_state = try advanced.clone(self.allocator, .{ .transfer_cache = false });
            errdefer {
                cp_state.deinit();
                self.allocator.destroy(cp_state);
            }
            try sealPublishedState(cp_state);
            // Use a zero root as the checkpoint block root for the pre-computed state.
            // The actual block root will be written when the block arrives.
            const ephemeral_root = [_]u8{0xFF} ** 32;
            try self.checkpoint_state_cache.add(
                .{ .epoch = next_epoch, .root = ephemeral_root },
                cp_state,
            );
        }

        self.last_prepared_slot = target_slot;
        std.log.debug("prepare next slot: pre-computed state for slot {d}", .{target_slot});
    }

    /// Reset the last-prepared tracker (call on chain reorg or resync).
    pub fn reset(self: *PrepareNextSlot) void {
        self.last_prepared_slot = 0;
    }

    fn sealPublishedState(state: *CachedBeaconState) !void {
        try state.state.commit();
        _ = try state.state.hashTreeRoot();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "PrepareNextSlot: init/deinit is safe" {
    var fixture = try RegenRuntimeFixture.init(std.testing.allocator, 16);
    defer fixture.deinit();

    var pns = PrepareNextSlot.init(
        std.testing.allocator,
        fixture.block_cache,
        fixture.cp_cache,
        fixture.shared_state_graph.gate,
        .{},
    );
    defer pns.deinit();

    try std.testing.expectEqual(@as(u64, 0), pns.last_prepared_slot);
}

test "PrepareNextSlot: disabled config skips work" {
    var fixture = try RegenRuntimeFixture.init(std.testing.allocator, 16);
    defer fixture.deinit();

    var pns = PrepareNextSlot.init(
        std.testing.allocator,
        fixture.block_cache,
        fixture.cp_cache,
        fixture.shared_state_graph.gate,
        .{ .enabled = false },
    );
    defer pns.deinit();

    const zero_root = [_]u8{0} ** 32;
    // Should be a no-op since enabled = false.
    try pns.onSlot(5, zero_root);
    try std.testing.expectEqual(@as(u64, 0), pns.last_prepared_slot);
}

test "PrepareNextSlot: precomputes next-slot head state" {
    defer state_transition.deinitStateTransition();

    var fixture = try RegenRuntimeFixture.init(std.testing.allocator, 16);
    defer fixture.deinit();

    const head_state_root = try fixture.seedHeadState();
    const current_slot = try fixture.published_state.state.slot();

    var pns = PrepareNextSlot.init(
        std.testing.allocator,
        fixture.block_cache,
        fixture.cp_cache,
        fixture.shared_state_graph.gate,
        .{},
    );
    defer pns.deinit();

    const initial_cache_size = fixture.block_cache.size();

    try pns.onSlot(current_slot, head_state_root);

    try std.testing.expectEqual(current_slot + 1, pns.last_prepared_slot);
    try std.testing.expectEqual(initial_cache_size + 1, fixture.block_cache.size());
}
