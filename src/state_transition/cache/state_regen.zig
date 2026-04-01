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
const BeaconDB = @import("db").BeaconDB;
const BeaconConfig = @import("config").BeaconConfig;
const PersistentMerkleTreeNode = @import("persistent_merkle_tree").Node;
const deserializeState = @import("../utils/state_deserialize.zig").deserializeState;

pub const StateRegen = struct {
    allocator: Allocator,
    block_cache: *BlockStateCache,
    checkpoint_cache: *CheckpointStateCache,
    // fork_choice: *ForkChoice,   // TODO: wire when available
    db: ?*BeaconDB,
    /// Persistent Merkle tree node pool — shared across all states.
    /// Optional: deserialization from DB is skipped when null.
    pool: ?*PersistentMerkleTreeNode.Pool,
    /// Beacon chain config — required for fork detection during deserialization.
    /// Optional: deserialization from DB is skipped when null.
    config: ?*const BeaconConfig,

    pub fn init(
        allocator: Allocator,
        block_cache: *BlockStateCache,
        checkpoint_cache: *CheckpointStateCache,
    ) StateRegen {
        return initWithDB(allocator, block_cache, checkpoint_cache, null, null, null);
    }

    /// Initialize with an optional BeaconDB for cold-path state retrieval.
    pub fn initWithDB(
        allocator: Allocator,
        block_cache: *BlockStateCache,
        checkpoint_cache: *CheckpointStateCache,
        db: ?*BeaconDB,
        pool: ?*PersistentMerkleTreeNode.Pool,
        config: ?*const BeaconConfig,
    ) StateRegen {
        return .{
            .allocator = allocator,
            .block_cache = block_cache,
            .checkpoint_cache = checkpoint_cache,
            .db = db,
            .pool = pool,
            .config = config,
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

        // 3. Cold path: find closest archived state, replay blocks forward.
        //
        //    Walk backwards from the target epoch to find a persisted state
        //    archive, then replay blocks forward to produce the pre-state.
        //    State deserialization from SSZ bytes is a TODO — requires fork
        //    detection + tree construction + CachedBeaconState init.
        if (self.db) |db| {
            const cold_target_epoch = computeEpochAtSlot(block_slot);
            var search_epoch = cold_target_epoch;
            while (search_epoch > 0) : (search_epoch -= 1) {
                const cp_slot = computeStartSlotAtEpoch(search_epoch);
                if (try db.getStateArchive(cp_slot)) |state_bytes| {
                    defer self.allocator.free(state_bytes);
                    if (self.pool != null and self.config != null) {
                        // Deserialize the archived state.
                        // TODO: replay blocks forward from cp_slot to block_slot once
                        // the STFN loop is available. For now, return the archived
                        // checkpoint state directly (correct only when cp_slot == block_slot - 1).
                        const cached_state = try deserializeState(
                            self.allocator,
                            self.pool.?,
                            self.config.?,
                            state_bytes,
                        );
                        return try self.cacheLoadedState(cached_state, false);
                    }
                    break;
                }
            }
        }
        return error.NoPreStateAvailable;
    }

    /// Get a checkpoint state, potentially reloading from disk.
    pub fn getCheckpointState(self: *StateRegen, cp: CheckpointKey) !?*CachedBeaconState {
        return self.checkpoint_cache.getOrReload(cp);
    }

    /// Look up a state by its state root across all stores.
    ///
    /// Search order:
    /// 1. Block state cache (hot path)
    /// 2. DB state archive by root (cold path)
    ///
    /// State deserialization from archived bytes is a TODO — returns null
    /// for DB hits until the full deserialization pipeline is wired.
    pub fn getStateByRoot(self: *StateRegen, state_root: [32]u8) !?*CachedBeaconState {
        // 1. Check block cache — O(1) lookup
        if (self.block_cache.get(state_root)) |state| return state;

        // 2. Check checkpoint cache.
        // Checkpoint cache is keyed by (epoch, block_root), not state_root,
        // so we cannot efficiently look up by state_root here. Skip for now.

        // 3. Try DB archived state
        if (self.db) |db| {
            if (self.pool == null or self.config == null) return null;
            const bytes = (try db.getStateArchiveByRoot(state_root)) orelse return null;
            defer self.allocator.free(bytes);
            const cached_state = try deserializeState(
                self.allocator,
                self.pool.?,
                self.config.?,
                bytes,
            );
            return try self.cacheLoadedState(cached_state, false);
        }

        return null;
    }

    /// Look up an archived state by slot.
    ///
    /// Search order:
    /// 1. DB state archive by slot (cold path)
    ///
    /// Loaded states are inserted into the block state cache so callers
    /// receive a cache-owned pointer with stable lifetime semantics.
    pub fn getStateBySlot(self: *StateRegen, slot: u64) !?*CachedBeaconState {
        if (self.db == null or self.pool == null or self.config == null) return null;

        const bytes = (try self.db.?.getStateArchive(slot)) orelse return null;
        defer self.allocator.free(bytes);

        const cached_state = try deserializeState(
            self.allocator,
            self.pool.?,
            self.config.?,
            bytes,
        );
        return try self.cacheLoadedState(cached_state, false);
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

    fn cacheLoadedState(
        self: *StateRegen,
        state: *CachedBeaconState,
        is_head: bool,
    ) !*CachedBeaconState {
        const state_root = (try state.state.hashTreeRoot()).*;
        if (self.block_cache.get(state_root)) |existing| {
            state.deinit();
            self.allocator.destroy(state);
            return existing;
        }

        _ = try self.block_cache.add(state, is_head);
        return state;
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

test "StateRegen: getStateByRoot returns state from block cache" {
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
    const state_root = try regen.onNewBlock(state, true);

    // getStateByRoot should find it in block cache
    const found = try regen.getStateByRoot(state_root);
    try std.testing.expectEqual(state, found);
}

test "StateRegen: getStateByRoot returns null for unknown root" {
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

    const unknown_root = [_]u8{0xaa} ** 32;
    const found = try regen.getStateByRoot(unknown_root);
    try std.testing.expectEqual(@as(?*CachedBeaconState, null), found);
}

test "StateRegen: getPreState returns error when nothing cached and no DB" {
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

    // No DB wired
    var regen = StateRegen.init(allocator, &block_cache, &cp_cache);

    const unknown_root = [_]u8{0xbb} ** 32;
    try std.testing.expectError(error.NoPreStateAvailable, regen.getPreState(unknown_root, 64));
}
