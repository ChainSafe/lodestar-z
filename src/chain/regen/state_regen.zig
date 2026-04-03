//! StateRegen: state regeneration from caches, disk, and block replay.
//!
//! Ties together BlockStateCache, CheckpointStateCache, and (eventually)
//! fork choice + BeaconDB to produce pre-states for block processing.
//!
//! Design mirrors Lodestar's StateRegenerator / QueuedStateRegenerator.
const std = @import("std");
const Allocator = std.mem.Allocator;
const preset = @import("preset").preset;
const state_transition = @import("state_transition");
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const computeStartSlotAtEpoch = state_transition.computeStartSlotAtEpoch;
const state_transition_mod = state_transition.state_transition;
const processSlots = state_transition_mod.processSlots;
const stateTransition = state_transition_mod.stateTransition;
const TransitionOpt = state_transition_mod.TransitionOpt;

const CachedBeaconState = state_transition.CachedBeaconState;
const BlockStateCache = @import("block_state_cache.zig").BlockStateCache;
const CheckpointStateCache = @import("checkpoint_state_cache.zig").CheckpointStateCache;
const CheckpointKey = @import("datastore.zig").CheckpointKey;
const PmtMutator = @import("pmt_mutator.zig").PmtMutator;
const StateDisposer = @import("state_disposer.zig").StateDisposer;
const destroyCachedBeaconState = @import("state_disposer.zig").destroyCachedBeaconState;
const BeaconDB = @import("db").BeaconDB;
const BeaconConfig = @import("config").BeaconConfig;
const PersistentMerkleTreeNode = @import("persistent_merkle_tree").Node;
const deserializeState = state_transition.deserializeState;
const AnySignedBeaconBlock = @import("fork_types").AnySignedBeaconBlock;

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
    state_disposer: ?*StateDisposer,
    pmt_mutator: ?*PmtMutator,

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
            .state_disposer = null,
            .pmt_mutator = null,
        };
    }

    pub fn setStateDisposer(self: *StateRegen, state_disposer: *StateDisposer) void {
        self.state_disposer = state_disposer;
    }

    pub fn setPmtMutator(self: *StateRegen, pmt_mutator: *PmtMutator) void {
        self.pmt_mutator = pmt_mutator;
    }

    /// Bind cold-path deserialization to the live shared pool/config of a
    /// published state. Call this once an anchor/head state exists.
    pub fn bindPublishedState(self: *StateRegen, state: *CachedBeaconState) void {
        self.config = state.config;
        self.pool = switch (state.state.*) {
            inline else => |fork_state| fork_state.pool,
        };
    }

    /// Fast pre-state lookup for block import planning.
    ///
    /// This only consults in-memory / checkpoint-backed caches and does not
    /// fall through to expensive replay from disk.
    pub fn getCachedPreState(
        self: *StateRegen,
        parent_state_root: [32]u8,
        block_slot: u64,
    ) !?*CachedBeaconState {
        if (self.block_cache.get(parent_state_root)) |state| {
            return state;
        }

        const target_epoch = computeEpochAtSlot(block_slot);
        if (try self.checkpoint_cache.getOrReload(.{
            .epoch = target_epoch,
            .root = parent_state_root,
        })) |state| {
            return state;
        }

        if (target_epoch > 0) {
            if (try self.checkpoint_cache.getOrReload(.{
                .epoch = target_epoch - 1,
                .root = parent_state_root,
            })) |state| {
                return state;
            }
        }

        return null;
    }

    /// Get the pre-state for processing a block at `block_slot` with parent `parent_root`.
    ///
    /// Strategy:
    /// 1. Try block cache (hot path — most recent blocks)
    /// 2. Try checkpoint cache with reload (warm path — epoch boundary states)
    /// 3. Replay canonical history from the closest archived state (cold path)
    pub fn getPreState(
        self: *StateRegen,
        parent_block_root: [32]u8,
        parent_state_root: [32]u8,
        block_slot: u64,
    ) !*CachedBeaconState {
        if (try self.getCachedPreState(parent_state_root, block_slot)) |state| {
            return state;
        }

        if (try self.getStateByRoot(parent_state_root)) |state| {
            return state;
        }

        if (try self.getCanonicalStateByBlockRoot(parent_block_root)) |state| {
            return state;
        }

        return error.NoPreStateAvailable;
    }

    /// Cold pre-state load for off-main-thread block import.
    ///
    /// Unlike `getPreState()`, this does not touch the shared caches. It
    /// deserializes or replays directly from archival storage and returns an
    /// uncached owned state for the caller to use temporarily.
    pub fn loadPreStateUncached(
        self: *StateRegen,
        parent_block_root: [32]u8,
        parent_state_root: [32]u8,
        block_slot: u64,
    ) !*CachedBeaconState {
        _ = block_slot;

        if (try self.loadArchivedStateByRootUncached(parent_state_root)) |state| {
            return state;
        }

        if (try self.getCanonicalStateByBlockRootUncached(parent_block_root)) |state| {
            return state;
        }

        return error.NoPreStateAvailable;
    }

    /// Destroy a temporary uncached state loaded via deserializeState/replay.
    ///
    /// These states allocate their own pubkey caches and do not share them with
    /// the main published-state graph, so callers must use this path instead of
    /// plain `CachedBeaconState.deinit()` to avoid leaking those transient caches.
    pub fn destroyTransientState(self: *StateRegen, state: *CachedBeaconState) void {
        const pubkey_to_index = state.epoch_cache.pubkey_to_index;
        const index_to_pubkey = state.epoch_cache.index_to_pubkey;
        state.deinit();
        self.allocator.destroy(state);
        pubkey_to_index.deinit();
        self.allocator.destroy(pubkey_to_index);
        index_to_pubkey.deinit();
        self.allocator.destroy(index_to_pubkey);
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
            var pmt_mutation_lease = PmtMutator.acquireOptional(self.pmt_mutator);
            defer pmt_mutation_lease.release();
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
    /// When an exact archive is unavailable, replay canonical blocks forward
    /// from the closest archived epoch-boundary anchor.
    pub fn getStateBySlot(self: *StateRegen, slot: u64) !?*CachedBeaconState {
        if (self.db == null or self.pool == null or self.config == null) return null;

        if (try self.db.?.getStateArchive(slot)) |bytes| {
            defer self.allocator.free(bytes);

            var pmt_mutation_lease = PmtMutator.acquireOptional(self.pmt_mutator);
            defer pmt_mutation_lease.release();
            const cached_state = try deserializeState(
                self.allocator,
                self.pool.?,
                self.config.?,
                bytes,
            );
            return try self.cacheLoadedState(cached_state, false);
        }

        return self.replayCanonicalStateToSlot(slot);
    }

    /// Called after processing a new block — cache the resulting state.
    pub fn onNewBlock(self: *StateRegen, state: *CachedBeaconState, is_head: bool) ![32]u8 {
        try sealPublishedState(state);
        return self.block_cache.add(state, is_head);
    }

    /// Called when a new head is selected.
    pub fn onNewHead(self: *StateRegen, state: *CachedBeaconState) ![32]u8 {
        try sealPublishedState(state);
        return self.block_cache.setHeadState(state);
    }

    /// Called on epoch boundary — store checkpoint state and maybe persist old epochs.
    pub fn onCheckpoint(
        self: *StateRegen,
        cp: CheckpointKey,
        state: *CachedBeaconState,
    ) !void {
        try sealPublishedState(state);
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
        try sealPublishedState(state);
        const state_root = (try state.state.hashTreeRoot()).*;
        if (self.block_cache.get(state_root)) |existing| {
            try self.disposeState(state);
            return existing;
        }

        _ = try self.block_cache.add(state, is_head);
        return state;
    }

    fn getCanonicalStateByBlockRoot(self: *StateRegen, block_root: [32]u8) !?*CachedBeaconState {
        if (self.db == null or self.config == null) return null;

        const block_bytes = try self.getBlockBytesByRoot(block_root) orelse return null;
        defer self.allocator.free(block_bytes);

        const slot = readSignedBlockSlotFromSsz(block_bytes) orelse return null;
        const canonical_root = try self.db.?.getBlockRootBySlot(slot) orelse return null;
        if (!std.mem.eql(u8, &canonical_root, &block_root)) return null;

        return self.replayCanonicalStateToSlot(slot);
    }

    fn getCanonicalStateByBlockRootUncached(self: *StateRegen, block_root: [32]u8) !?*CachedBeaconState {
        if (self.db == null or self.config == null) return null;

        const block_bytes = try self.getBlockBytesByRoot(block_root) orelse return null;
        defer self.allocator.free(block_bytes);

        const slot = readSignedBlockSlotFromSsz(block_bytes) orelse return null;
        const canonical_root = try self.db.?.getBlockRootBySlot(slot) orelse return null;
        if (!std.mem.eql(u8, &canonical_root, &block_root)) return null;

        return self.replayCanonicalStateToSlotUncached(slot);
    }

    fn replayCanonicalStateToSlot(self: *StateRegen, target_slot: u64) !?*CachedBeaconState {
        if (self.db == null or self.pool == null or self.config == null) return null;

        var pmt_mutation_lease = PmtMutator.acquireOptional(self.pmt_mutator);
        defer pmt_mutation_lease.release();

        if (try self.db.?.getStateArchive(target_slot)) |bytes| {
            defer self.allocator.free(bytes);
            const exact_state = try deserializeState(
                self.allocator,
                self.pool.?,
                self.config.?,
                bytes,
            );
            return try self.cacheLoadedState(exact_state, false);
        }

        const anchor_slot = try self.findReplayAnchorSlot(target_slot) orelse return null;
        var working_state = try self.loadArchivedStateUncached(anchor_slot);
        errdefer {
            working_state.deinit();
            self.allocator.destroy(working_state);
        }

        if (anchor_slot == target_slot) {
            return try self.cacheLoadedState(working_state, false);
        }

        var slot = anchor_slot + 1;
        while (slot <= target_slot) : (slot += 1) {
            const block_root = try self.db.?.getBlockRootBySlot(slot);
            if (block_root) |root| {
                const block_bytes = try self.getBlockBytesByRoot(root) orelse return null;
                defer self.allocator.free(block_bytes);

                var any_signed = try self.deserializeSignedBlock(slot, block_bytes);
                defer any_signed.deinit(self.allocator);
                var actual_root: [32]u8 = undefined;
                try any_signed.beaconBlock().hashTreeRoot(self.allocator, &actual_root);
                if (!std.mem.eql(u8, &actual_root, &root)) {
                    try processSlots(self.allocator, working_state, slot, .{});
                    try working_state.state.commit();
                    continue;
                }

                const next_state = try stateTransition(
                    self.allocator,
                    working_state,
                    any_signed,
                    TransitionOpt{
                        .verify_state_root = true,
                        .verify_proposer = false,
                        .verify_signatures = false,
                        .transfer_cache = false,
                    },
                );
                working_state.deinit();
                self.allocator.destroy(working_state);
                working_state = next_state;
            } else {
                try processSlots(self.allocator, working_state, slot, .{});
                try working_state.state.commit();
            }
        }

        return try self.cacheLoadedState(working_state, false);
    }

    fn replayCanonicalStateToSlotUncached(self: *StateRegen, target_slot: u64) !?*CachedBeaconState {
        if (self.db == null or self.pool == null or self.config == null) return null;

        var pmt_mutation_lease = PmtMutator.acquireOptional(self.pmt_mutator);
        defer pmt_mutation_lease.release();

        if (try self.db.?.getStateArchive(target_slot)) |bytes| {
            defer self.allocator.free(bytes);
            return try deserializeState(
                self.allocator,
                self.pool.?,
                self.config.?,
                bytes,
            );
        }

        const anchor_slot = try self.findReplayAnchorSlot(target_slot) orelse return null;
        var working_state = try self.loadArchivedStateUncached(anchor_slot);
        errdefer {
            working_state.deinit();
            self.allocator.destroy(working_state);
        }

        if (anchor_slot == target_slot) {
            return working_state;
        }

        var slot = anchor_slot + 1;
        while (slot <= target_slot) : (slot += 1) {
            const block_root = try self.db.?.getBlockRootBySlot(slot);
            if (block_root) |root| {
                const block_bytes = try self.getBlockBytesByRoot(root) orelse return null;
                defer self.allocator.free(block_bytes);

                var any_signed = try self.deserializeSignedBlock(slot, block_bytes);
                defer any_signed.deinit(self.allocator);
                var actual_root: [32]u8 = undefined;
                try any_signed.beaconBlock().hashTreeRoot(self.allocator, &actual_root);
                if (!std.mem.eql(u8, &actual_root, &root)) {
                    try processSlots(self.allocator, working_state, slot, .{});
                    try working_state.state.commit();
                    continue;
                }

                const next_state = try stateTransition(
                    self.allocator,
                    working_state,
                    any_signed,
                    TransitionOpt{
                        .verify_state_root = true,
                        .verify_proposer = false,
                        .verify_signatures = false,
                        .transfer_cache = false,
                    },
                );
                working_state.deinit();
                self.allocator.destroy(working_state);
                working_state = next_state;
            } else {
                try processSlots(self.allocator, working_state, slot, .{});
                try working_state.state.commit();
            }
        }

        return working_state;
    }

    fn findReplayAnchorSlot(self: *StateRegen, target_slot: u64) !?u64 {
        if (self.db == null) return null;

        var search_slot = computeStartSlotAtEpoch(computeEpochAtSlot(target_slot));
        while (true) {
            if (try self.db.?.getStateArchive(search_slot)) |bytes| {
                self.allocator.free(bytes);
                return search_slot;
            }
            if (search_slot == 0) return null;
            search_slot = search_slot -| preset.SLOTS_PER_EPOCH;
        }
    }

    fn loadArchivedStateUncached(self: *StateRegen, slot: u64) !*CachedBeaconState {
        const bytes = (try self.db.?.getStateArchive(slot)) orelse return error.StateArchiveMissing;
        defer self.allocator.free(bytes);

        return deserializeState(
            self.allocator,
            self.pool.?,
            self.config.?,
            bytes,
        );
    }

    fn loadArchivedStateByRootUncached(self: *StateRegen, state_root: [32]u8) !?*CachedBeaconState {
        if (self.db == null or self.pool == null or self.config == null) return null;
        const bytes = (try self.db.?.getStateArchiveByRoot(state_root)) orelse return null;
        defer self.allocator.free(bytes);

        var pmt_mutation_lease = PmtMutator.acquireOptional(self.pmt_mutator);
        defer pmt_mutation_lease.release();
        return deserializeState(
            self.allocator,
            self.pool.?,
            self.config.?,
            bytes,
        );
    }

    fn getBlockBytesByRoot(self: *StateRegen, block_root: [32]u8) !?[]const u8 {
        if (self.db == null) return null;
        if (try self.db.?.getBlock(block_root)) |block_bytes| return block_bytes;
        return self.db.?.getBlockArchiveByRoot(block_root);
    }

    fn deserializeSignedBlock(
        self: *StateRegen,
        slot: u64,
        block_bytes: []const u8,
    ) !AnySignedBeaconBlock {
        const fork_seq = self.config.?.forkSeq(slot);
        return AnySignedBeaconBlock.deserialize(
            self.allocator,
            .full,
            fork_seq,
            block_bytes,
        );
    }

    fn readSignedBlockSlotFromSsz(block_bytes: []const u8) ?u64 {
        if (block_bytes.len < 108) return null;
        return std.mem.readInt(u64, block_bytes[100..108], .little);
    }

    fn sealPublishedState(state: *CachedBeaconState) !void {
        try state.state.commit();
        _ = try state.state.hashTreeRoot();
    }

    fn disposeState(self: *StateRegen, state: *CachedBeaconState) !void {
        if (self.state_disposer) |state_disposer| {
            try state_disposer.dispose(state);
            return;
        }
        destroyCachedBeaconState(self.allocator, state);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "StateRegen: basic getPreState from block cache" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
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
    const pre_state = try regen.getPreState(root, root, 100);
    try std.testing.expectEqual(state, pre_state);
}

test "StateRegen: getPreState returns error when nothing cached" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
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
    try std.testing.expectError(error.NoPreStateAvailable, regen.getPreState(unknown_root, unknown_root, 100));
}

test "StateRegen: onFinalized prunes old states" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
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

test "StateRegen: checkpoint publication seals lazy PMT roots" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
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

    const state = try test_state.cached_state.clone(allocator, .{});
    try state.state.setSlot((try state.state.slot()) + 1);

    const root_state_before = switch (state.state.*) {
        inline else => |fork_state| fork_state.root.getState(fork_state.pool),
    };
    try std.testing.expect(root_state_before.isBranchLazy());

    const cp = CheckpointKey{ .epoch = 5, .root = [_]u8{0x05} ** 32 };
    try regen.onCheckpoint(cp, state);

    const cached_state = cp_cache.get(cp);
    try std.testing.expect(cached_state != null);
    const root_state_after = switch (cached_state.?.state.*) {
        inline else => |fork_state| fork_state.root.getState(fork_state.pool),
    };
    try std.testing.expect(root_state_after.isBranchComputed());
}

test "StateRegen: getStateByRoot returns state from block cache" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
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
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
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
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
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
    try std.testing.expectError(error.NoPreStateAvailable, regen.getPreState(unknown_root, unknown_root, 64));
}

test "StateRegen: loadPreStateUncached loads archived state root after binding published state" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    const datastore_mod = @import("datastore.zig");
    const MemoryCPStateDatastore = datastore_mod.MemoryCPStateDatastore;
    const db_mod = @import("db");

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

    var kv_store = db_mod.MemoryKVStore.init(allocator);
    defer kv_store.deinit();
    var db = db_mod.BeaconDB.init(allocator, kv_store.kvStore());

    var regen = StateRegen.initWithDB(allocator, &block_cache, &cp_cache, &db, null, null);
    regen.bindPublishedState(test_state.cached_state);

    const archived = try test_state.cached_state.clone(allocator, .{});
    defer {
        archived.deinit();
        allocator.destroy(archived);
    }
    try archived.state.commit();
    const archived_state_root = (try archived.state.hashTreeRoot()).*;
    const archived_slot = try archived.state.slot();
    const archived_bytes = try archived.state.serialize(allocator);
    defer allocator.free(archived_bytes);
    try db.putStateArchive(archived_slot, archived_state_root, archived_bytes);

    const loaded = try regen.loadPreStateUncached(
        [_]u8{0x11} ** 32,
        archived_state_root,
        archived_slot + 1,
    );
    defer {
        regen.destroyTransientState(loaded);
    }

    try std.testing.expectEqual(archived_slot, try loaded.state.slot());
    try std.testing.expectEqual(@as(usize, 0), block_cache.size());
}
