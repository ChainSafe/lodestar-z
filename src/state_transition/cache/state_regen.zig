//! StateRegen: state regeneration from caches, disk, and block replay.
//!
//! Ties together BlockStateCache, CheckpointStateCache, and (eventually)
//! fork choice + BeaconDB to produce pre-states for block processing.
//!
//! Design mirrors Lodestar's StateRegenerator / QueuedStateRegenerator.
const std = @import("std");
const Allocator = std.mem.Allocator;
const preset = @import("preset").preset;
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;
const computeStartSlotAtEpoch = @import("../utils/epoch.zig").computeStartSlotAtEpoch;

const CachedBeaconState = @import("state_cache.zig").CachedBeaconState;
const BlockStateCache = @import("block_state_cache.zig").BlockStateCache;
const CheckpointStateCache = @import("checkpoint_state_cache.zig").CheckpointStateCache;
const CheckpointKey = @import("datastore.zig").CheckpointKey;

pub const StateRegen = struct {
    allocator: Allocator,
    block_cache: *BlockStateCache,
    checkpoint_cache: *CheckpointStateCache,
    // fork_choice: *ForkChoice,   // TODO: wire when available
    // db: *BeaconDB,              // TODO: wire when available

    pub fn init(
        allocator: Allocator,
        block_cache: *BlockStateCache,
        checkpoint_cache: *CheckpointStateCache,
    ) StateRegen {
        return .{
            .allocator = allocator,
            .block_cache = block_cache,
            .checkpoint_cache = checkpoint_cache,
        };
    }

    /// Get the pre-state for processing a block at `block_slot` with parent `parent_root`.
    ///
    /// Strategy:
    /// 1. Try block cache (hot path — most recent blocks)
    /// 2. Try checkpoint cache with reload (warm path — epoch boundary states)
    /// 3. TODO: Walk fork choice backwards + replay blocks from closest ancestor (cold path)
    pub fn getPreState(self: *StateRegen, parent_root: [32]u8, block_slot: u64) !*CachedBeaconState {
        // 1. Try block cache — O(1) lookup by state root
        if (self.block_cache.get(parent_root)) |state| {
            return state;
        }

        // 2. Try checkpoint cache — look for the closest epoch boundary state
        const target_epoch = computeEpochAtSlot(block_slot);
        if (try self.checkpoint_cache.getOrReload(.{
            .epoch = target_epoch,
            .root = parent_root,
        })) |state| {
            return state;
        }

        // Also try previous epoch (the block might be the first in a new epoch)
        if (target_epoch > 0) {
            if (try self.checkpoint_cache.getOrReload(.{
                .epoch = target_epoch - 1,
                .root = parent_root,
            })) |state| {
                return state;
            }
        }

        // 3. TODO: Walk fork choice backwards to find closest known state,
        //    then replay blocks forward. Requires:
        //    - fork_choice.iterateAncestorBlocks(parent_root)
        //    - db.getBlock(root)
        //    - state_transition.stateTransition(state, block)
        return error.NoPreStateAvailable;
    }

    /// Get a checkpoint state, potentially reloading from disk.
    pub fn getCheckpointState(self: *StateRegen, cp: CheckpointKey) !?*CachedBeaconState {
        return self.checkpoint_cache.getOrReload(cp);
    }

    /// Called after processing a new block — cache the resulting state.
    pub fn onNewBlock(self: *StateRegen, state: *CachedBeaconState, is_head: bool) ![32]u8 {
        return self.block_cache.add(state, is_head);
    }

    /// Called when a new head is selected.
    pub fn onNewHead(self: *StateRegen, state: *CachedBeaconState) ![32]u8 {
        return self.block_cache.setHeadState(state);
    }

    /// Called on epoch boundary — store checkpoint state and maybe persist old epochs.
    pub fn onCheckpoint(
        self: *StateRegen,
        cp: CheckpointKey,
        state: *CachedBeaconState,
    ) !void {
        try self.checkpoint_cache.add(cp, state);
    }

    /// Called on finalization — prune stale states.
    pub fn onFinalized(self: *StateRegen, finalized_epoch: u64) !void {
        self.block_cache.pruneBeforeEpoch(finalized_epoch);
        try self.checkpoint_cache.pruneFinalized(finalized_epoch);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "StateRegen: basic getPreState from block cache" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
    const datastore_mod = @import("datastore.zig");
    const MemoryCPStateDatastore = datastore_mod.MemoryCPStateDatastore;

    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var mem_store = MemoryCPStateDatastore.init(allocator);
    defer mem_store.deinit();
    const ds = mem_store.datastore();

    var block_cache = BlockStateCache.init(allocator, 4);
    defer block_cache.deinit();

    var cp_cache = CheckpointStateCache.init(allocator, ds, &block_cache, 3);
    defer cp_cache.deinit();

    var regen = StateRegen.init(allocator, &block_cache, &cp_cache);

    // Add a state to block cache
    const state = try test_state.cached_state.clone(allocator, .{});
    const root = try regen.onNewBlock(state, true);

    // Should find it via getPreState
    const pre_state = try regen.getPreState(root, 100);
    try std.testing.expectEqual(state, pre_state);
}

test "StateRegen: getPreState returns error when nothing cached" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
    const datastore_mod = @import("datastore.zig");
    const MemoryCPStateDatastore = datastore_mod.MemoryCPStateDatastore;

    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var mem_store = MemoryCPStateDatastore.init(allocator);
    defer mem_store.deinit();
    const ds = mem_store.datastore();

    var block_cache = BlockStateCache.init(allocator, 4);
    defer block_cache.deinit();

    var cp_cache = CheckpointStateCache.init(allocator, ds, &block_cache, 3);
    defer cp_cache.deinit();

    var regen = StateRegen.init(allocator, &block_cache, &cp_cache);

    const unknown_root = [_]u8{0xde} ** 32;
    try std.testing.expectError(error.NoPreStateAvailable, regen.getPreState(unknown_root, 100));
}

test "StateRegen: onFinalized prunes old states" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
    const datastore_mod = @import("datastore.zig");
    const MemoryCPStateDatastore = datastore_mod.MemoryCPStateDatastore;

    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var mem_store = MemoryCPStateDatastore.init(allocator);
    defer mem_store.deinit();
    const ds = mem_store.datastore();

    var block_cache = BlockStateCache.init(allocator, 4);
    defer block_cache.deinit();

    var cp_cache = CheckpointStateCache.init(allocator, ds, &block_cache, 3);
    defer cp_cache.deinit();

    var regen = StateRegen.init(allocator, &block_cache, &cp_cache);

    // Add checkpoint at epoch 5
    const state = try test_state.cached_state.clone(allocator, .{});
    const cp = CheckpointKey{ .epoch = 5, .root = [_]u8{0x05} ** 32 };
    try regen.onCheckpoint(cp, state);

    try std.testing.expectEqual(@as(usize, 1), cp_cache.size());

    // Finalize at epoch 10 — should prune epoch 5
    try regen.onFinalized(10);
    try std.testing.expectEqual(@as(usize, 0), cp_cache.size());
}
