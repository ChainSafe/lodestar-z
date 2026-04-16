//! StateRegen: state regeneration from caches, disk, and block replay.
//!
//! Ties together BlockStateCache, CheckpointStateCache, fork choice, and
//! BeaconDB to produce pre-states for block processing.
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
const SharedValidatorPubkeys = state_transition.SharedValidatorPubkeys;
const BlockStateCache = @import("block_state_cache.zig").BlockStateCache;
const CheckpointStateCache = @import("checkpoint_state_cache.zig").CheckpointStateCache;
const CheckpointKey = @import("datastore.zig").CheckpointKey;
const StateGraphGate = @import("state_graph_gate.zig").StateGraphGate;
const SharedStateGraph = @import("shared_state_graph.zig").SharedStateGraph;
const BeaconDB = @import("db").BeaconDB;
const deserializeState = state_transition.deserializeState;
const AnyBeaconState = @import("fork_types").AnyBeaconState;
const AnySignedBeaconBlock = @import("fork_types").AnySignedBeaconBlock;
const fork_choice_mod = @import("fork_choice");
const ForkChoice = fork_choice_mod.ForkChoiceStruct;
const ProtoBlock = fork_choice_mod.ProtoBlock;

pub const StateRegen = struct {
    allocator: Allocator,
    block_cache: *BlockStateCache,
    checkpoint_cache: *CheckpointStateCache,
    fork_choice: ?*const ForkChoice = null,
    db: *BeaconDB,
    shared_state_graph: *SharedStateGraph,

    const MAX_FORK_CHOICE_REPLAY_BLOCKS: usize = 5 * preset.SLOTS_PER_EPOCH;

    pub fn initForRuntime(
        allocator: Allocator,
        block_cache: *BlockStateCache,
        checkpoint_cache: *CheckpointStateCache,
        db: *BeaconDB,
        shared_state_graph: *SharedStateGraph,
    ) StateRegen {
        return .{
            .allocator = allocator,
            .block_cache = block_cache,
            .checkpoint_cache = checkpoint_cache,
            .fork_choice = null,
            .db = db,
            .shared_state_graph = shared_state_graph,
        };
    }

    pub fn setForkChoice(self: *StateRegen, fork_choice: *const ForkChoice) void {
        self.fork_choice = fork_choice;
    }

    pub fn clearForkChoice(self: *StateRegen) void {
        self.fork_choice = null;
    }

    pub const PreparedCheckpointReload = struct {
        persisted_key: []const u8,
        seed_state: *CachedBeaconState,

        pub fn deinit(self: *PreparedCheckpointReload, state_regen: *StateRegen) void {
            state_regen.allocator.free(self.persisted_key);
            state_regen.destroyTransientState(self.seed_state);
            self.* = undefined;
        }
    };

    /// Verify that a published state borrows the runtime-owned immutable data.
    ///
    /// Published states must already reference the runtime-owned config, PMT
    /// pool, and shared pubkey cache. This function is an invariant check, not
    /// an ownership-transfer hook.
    pub fn verifyPublishedStateOwnership(self: *StateRegen, state: *CachedBeaconState) !void {
        try self.shared_state_graph.verifyPublishedStateOwnership(state);
    }

    /// Fast pre-state lookup for block import planning.
    ///
    /// This only consults in-memory / checkpoint-backed caches and does not
    /// fall through to expensive replay from disk.
    pub fn getCachedPreState(
        self: *StateRegen,
        parent_block_root: [32]u8,
        parent_state_root: [32]u8,
        parent_slot: u64,
        block_slot: u64,
    ) !?*CachedBeaconState {
        const parent_epoch = computeEpochAtSlot(parent_slot);
        const block_epoch = computeEpochAtSlot(block_slot);
        const exact_parent_state = self.block_cache.get(parent_state_root);

        if (parent_epoch < block_epoch) {
            if (self.checkpoint_cache.getLatest(parent_block_root, block_epoch)) |state| {
                const state_epoch = computeEpochAtSlot(try state.state.slot());
                if (state_epoch == block_epoch) return state;
            }
            // Fallback to the exact parent state when no better checkpoint state
            // is cached. This preserves correctness for epoch-boundary imports
            // while still preferring Lodestar's checkpoint-shaped optimization.
            if (exact_parent_state) |state| return state;
        }

        if (exact_parent_state) |state| return state;

        return null;
    }

    /// Get the pre-state for processing a block at `block_slot` with parent `parent_root`.
    ///
    /// Strategy:
    /// 1. Try block cache (hot path — most recent blocks)
    /// 2. Try in-memory checkpoint cache (warm path — epoch boundary states)
    /// 3. Replay fork-choice history from a cached/checkpoint seed (cold path)
    /// 4. Replay canonical history from the closest archived state (fallback)
    pub fn getPreState(
        self: *StateRegen,
        parent_block_root: [32]u8,
        parent_state_root: [32]u8,
        parent_slot: u64,
        block_slot: u64,
    ) !*CachedBeaconState {
        const parent_epoch = computeEpochAtSlot(parent_slot);
        const block_epoch = computeEpochAtSlot(block_slot);

        if (try self.getCachedPreState(parent_block_root, parent_state_root, parent_slot, block_slot)) |state| {
            return state;
        }

        if (parent_epoch < block_epoch) {
            if (try self.checkpoint_cache.getOrReloadLatest(parent_block_root, block_epoch)) |state| {
                return state;
            }
        }

        if (try self.getStateByRoot(parent_state_root)) |state| {
            return state;
        }

        if (try self.getCanonicalStateByBlockRoot(parent_block_root)) |state| {
            return state;
        }

        return error.NoPreStateAvailable;
    }

    /// Uncached archival pre-state helper for isolated callers.
    ///
    /// Production block import resolves cold misses through `QueuedStateRegen`
    /// and the normal cache publication path. This helper remains for tests and
    /// standalone callers that need a temporary uncached state.
    pub fn loadPreStateUncached(
        self: *StateRegen,
        parent_block_root: [32]u8,
        parent_state_root: [32]u8,
        block_slot: u64,
    ) !*CachedBeaconState {
        _ = block_slot;

        if (try self.loadStateByRootUncached(parent_state_root)) |state| {
            return state;
        }

        if (try self.getCanonicalStateByBlockRootUncached(parent_block_root)) |state| {
            return state;
        }

        return error.NoPreStateAvailable;
    }

    /// Uncached state-root load helper for queued regen workers.
    ///
    /// Returns a temporary owned state that must be published or destroyed by
    /// the caller. Unlike `getStateByRoot()`, this does not touch shared caches.
    pub fn loadStateByRootUncached(
        self: *StateRegen,
        state_root: [32]u8,
    ) !?*CachedBeaconState {
        if (try self.loadArchivedStateByRootUncached(state_root)) |state| {
            return state;
        }

        return self.replayForkChoiceStateToRootUncached(state_root);
    }

    /// Prepare a checkpoint reload request for off-thread execution.
    ///
    /// The returned ticket owns a detached seed clone and a copied persisted
    /// datastore key. The caller must later publish or destroy the resulting
    /// transient state on the owner thread.
    pub fn prepareCheckpointReload(
        self: *StateRegen,
        cp: CheckpointKey,
    ) !?PreparedCheckpointReload {
        const persisted_key = (try self.checkpoint_cache.clonePersistedKey(self.allocator, cp)) orelse return null;
        errdefer self.allocator.free(persisted_key);

        const seed_state = self.checkpoint_cache.findSeedStateToReload(cp) orelse {
            self.allocator.free(persisted_key);
            return null;
        };

        var state_graph_lease = self.acquireStateGraphLease();
        defer state_graph_lease.release();

        const cloned_seed = try seed_state.clone(self.allocator, .{ .transfer_cache = false });
        errdefer self.destroyTransientState(cloned_seed);

        return .{
            .persisted_key = persisted_key,
            .seed_state = cloned_seed,
        };
    }

    /// Reload a checkpoint state from persisted bytes using a detached seed.
    ///
    /// This is the worker-side half of checkpoint reload. It intentionally
    /// returns a transient state so publication remains on the owner thread.
    pub fn loadCheckpointStateUncached(
        self: *StateRegen,
        prepared: *const PreparedCheckpointReload,
    ) !?*CachedBeaconState {
        const state_bytes = (try self.checkpoint_cache.loadPersistedStateBytes(prepared.persisted_key)) orelse return null;
        defer self.allocator.free(state_bytes);

        const loadCachedBeaconState = state_transition.loadCachedBeaconState;
        const Node = @import("persistent_merkle_tree").Node;

        const seed_state = prepared.seed_state;
        const fork_seq = seed_state.state.forkSeq();
        const pool: *Node.Pool = switch (seed_state.state.*) {
            inline else => |fork_state| fork_state.pool,
        };

        var state_graph_lease = self.acquireStateGraphLease();
        defer state_graph_lease.release();

        return loadCachedBeaconState(
            self.allocator,
            pool,
            seed_state,
            fork_seq,
            state_bytes,
            null,
        );
    }

    /// Publish a transient loaded state into the runtime block-state cache.
    ///
    /// This is the caller-side publication step for queued regen slow-path
    /// results that were deserialized or replayed off-thread.
    pub fn publishLoadedState(
        self: *StateRegen,
        state: *CachedBeaconState,
    ) !*CachedBeaconState {
        var state_graph_lease = self.acquireStateGraphLease();
        defer state_graph_lease.release();
        return self.cacheLoadedState(state, false);
    }

    /// Publish a transient checkpoint reload result back into the checkpoint cache.
    pub fn publishCheckpointReloadedState(
        self: *StateRegen,
        cp: CheckpointKey,
        state: *CachedBeaconState,
    ) !?*CachedBeaconState {
        var state_graph_lease = self.acquireStateGraphLease();
        defer state_graph_lease.release();
        try sealPublishedState(state);
        try self.verifyPublishedStateOwnership(state);
        return self.checkpoint_cache.publishReloaded(cp, state);
    }

    /// Destroy a transient state cloned or deserialized against the runtime graph.
    ///
    /// These states borrow the runtime singleton pubkey cache and shared PMT
    /// pool, so teardown must flow through the graph-aware disposer.
    pub fn destroyTransientState(self: *StateRegen, state: *CachedBeaconState) void {
        self.disposeState(state) catch @panic("OOM disposing transient state");
    }

    /// Get a checkpoint state, potentially reloading from disk.
    pub fn getCheckpointState(self: *StateRegen, cp: CheckpointKey) !?*CachedBeaconState {
        if (self.checkpoint_cache.get(cp)) |state| return state;

        var prepared = (try self.prepareCheckpointReload(cp)) orelse return null;
        defer prepared.deinit(self);

        const transient = (try self.loadCheckpointStateUncached(&prepared)) orelse return null;
        errdefer self.destroyTransientState(transient);
        return try self.publishCheckpointReloadedState(cp, transient);
    }

    /// Look up a state by its state root across all stores.
    ///
    /// Search order:
    /// 1. Block state cache (hot path)
    /// 2. DB state archive by root (cold path)
    /// 3. Fork-choice replay from a cached/checkpoint seed (fallback)
    ///
    pub fn getStateByRoot(self: *StateRegen, state_root: [32]u8) !?*CachedBeaconState {
        // 1. Check block cache — O(1) lookup
        if (self.block_cache.get(state_root)) |state| return state;

        // 2. Check checkpoint cache.
        // Checkpoint cache is keyed by (epoch, block_root), not state_root,
        // so we cannot efficiently look up by state_root here. Skip for now.

        // 3. Try DB archived state
        if (try self.loadArchivedStateByRootUncached(state_root)) |cached_state| {
            errdefer self.destroyTransientState(cached_state);
            return try self.publishLoadedState(cached_state);
        }

        return self.replayForkChoiceStateToRoot(state_root);
    }

    /// Look up an archived state by slot.
    ///
    /// Search order:
    /// 1. DB state archive by slot (cold path)
    ///
    /// When an exact archive is unavailable, replay canonical blocks forward
    /// from the closest archived epoch-boundary anchor.
    pub fn getStateBySlot(self: *StateRegen, slot: u64) !?*CachedBeaconState {
        if (try self.db.getStateArchive(slot)) |bytes| {
            defer self.allocator.free(bytes);

            var state_graph_lease = self.acquireStateGraphLease();
            defer state_graph_lease.release();
            const cached_state = try deserializeState(
                self.allocator,
                self.shared_state_graph.pool,
                self.shared_state_graph.config,
                self.shared_state_graph.validator_pubkeys,
                bytes,
                self.shared_state_graph.state_transition_metrics,
            );
            return try self.cacheLoadedState(cached_state, false);
        }

        return self.replayCanonicalStateToSlot(slot);
    }

    /// Called after processing a new block — cache the resulting state.
    pub fn onNewBlock(self: *StateRegen, state: *CachedBeaconState, is_head: bool) ![32]u8 {
        var state_graph_lease = self.acquireStateGraphLease();
        defer state_graph_lease.release();
        try sealPublishedState(state);
        return self.block_cache.add(state, is_head);
    }

    /// Called when a new head is selected.
    pub fn onNewHead(self: *StateRegen, state: *CachedBeaconState) ![32]u8 {
        var state_graph_lease = self.acquireStateGraphLease();
        defer state_graph_lease.release();
        try sealPublishedState(state);
        return self.block_cache.setHeadState(state);
    }

    /// Called on epoch boundary — store checkpoint state and maybe persist old epochs.
    pub fn onCheckpoint(
        self: *StateRegen,
        cp: CheckpointKey,
        state: *CachedBeaconState,
    ) !void {
        var state_graph_lease = self.acquireStateGraphLease();
        defer state_graph_lease.release();
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
        const block_bytes = try self.getBlockBytesByRoot(block_root) orelse return null;
        defer self.allocator.free(block_bytes);

        const slot = readSignedBlockSlotFromSsz(block_bytes) orelse return null;
        const canonical_root = try self.db.getFinalizedBlockRootBySlot(slot) orelse return null;
        if (!std.mem.eql(u8, &canonical_root, &block_root)) return null;

        return self.replayCanonicalStateToSlot(slot);
    }

    fn getCanonicalStateByBlockRootUncached(self: *StateRegen, block_root: [32]u8) !?*CachedBeaconState {
        const block_bytes = try self.getBlockBytesByRoot(block_root) orelse return null;
        defer self.allocator.free(block_bytes);

        const slot = readSignedBlockSlotFromSsz(block_bytes) orelse return null;
        const canonical_root = try self.db.getFinalizedBlockRootBySlot(slot) orelse return null;
        if (!std.mem.eql(u8, &canonical_root, &block_root)) return null;

        return self.replayCanonicalStateToSlotUncached(slot);
    }

    fn replayForkChoiceStateToRoot(self: *StateRegen, target_state_root: [32]u8) !?*CachedBeaconState {
        const transient = (try self.replayForkChoiceStateToRootInternal(target_state_root, true)) orelse return null;
        errdefer self.destroyTransientState(transient);

        var state_graph_lease = self.acquireStateGraphLease();
        defer state_graph_lease.release();
        return try self.cacheLoadedState(transient, false);
    }

    fn replayForkChoiceStateToRootUncached(self: *StateRegen, target_state_root: [32]u8) !?*CachedBeaconState {
        return self.replayForkChoiceStateToRootInternal(target_state_root, false);
    }

    fn replayForkChoiceStateToRootInternal(
        self: *StateRegen,
        target_state_root: [32]u8,
        allow_checkpoint_reload: bool,
    ) !?*CachedBeaconState {
        const fc = self.fork_choice orelse return null;
        const target_block = self.findForkChoiceBlockByStateRoot(fc, target_state_root) orelse return null;
        if (target_block.payload_status == .pending) return error.PendingForkChoiceBlock;

        var blocks_to_replay: std.ArrayListUnmanaged(ProtoBlock) = .empty;
        defer blocks_to_replay.deinit(self.allocator);
        try blocks_to_replay.append(self.allocator, target_block);

        var seed_state: ?*CachedBeaconState = null;
        var ancestor_iter = fc.iterateAncestorBlocks(target_block.block_root, target_block.payload_status);
        while (try ancestor_iter.next()) |ancestor_node| {
            if (ancestor_node.payload_status == .pending) return error.PendingForkChoiceBlock;

            if (self.block_cache.get(ancestor_node.state_root)) |cached| {
                seed_state = cached;
                break;
            }

            const last_block_to_replay = blocks_to_replay.items[blocks_to_replay.items.len - 1];
            const checkpoint_epoch = computeEpochAtSlot(last_block_to_replay.slot -| 1);
            const checkpoint_state = if (allow_checkpoint_reload)
                try self.checkpoint_cache.getOrReloadLatest(ancestor_node.block_root, checkpoint_epoch)
            else
                self.checkpoint_cache.getLatest(ancestor_node.block_root, checkpoint_epoch);
            if (checkpoint_state) |state| {
                seed_state = state;
                break;
            }

            if (blocks_to_replay.items.len >= MAX_FORK_CHOICE_REPLAY_BLOCKS) {
                return error.TooManyForkChoiceBlocksToReplay;
            }
            try blocks_to_replay.append(self.allocator, ancestor_node.toBlock());
        }

        const seed = seed_state orelse return null;

        var state_graph_lease = self.acquireStateGraphLease();
        defer state_graph_lease.release();

        var working_state = try seed.clone(self.allocator, .{ .transfer_cache = false });
        errdefer {
            working_state.deinit();
            self.allocator.destroy(working_state);
        }

        const replay_count = blocks_to_replay.items.len;
        var replay_index: usize = replay_count;
        while (replay_index > 0) {
            replay_index -= 1;
            const replay_block = blocks_to_replay.items[replay_index];
            const block_bytes = (try self.getBlockBytesByRoot(replay_block.block_root)) orelse
                return error.ForkChoiceBlockMissingFromDb;
            defer self.allocator.free(block_bytes);

            var any_signed = try self.deserializeSignedBlock(replay_block.slot, block_bytes);
            defer any_signed.deinit(self.allocator);

            var actual_block_root: [32]u8 = undefined;
            try any_signed.beaconBlock().hashTreeRoot(self.allocator, &actual_block_root);
            if (!std.mem.eql(u8, &actual_block_root, &replay_block.block_root)) {
                return error.ForkChoiceBlockRootMismatch;
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

            const actual_state_root = (try working_state.state.hashTreeRoot()).*;
            if (!std.mem.eql(u8, &actual_state_root, &replay_block.state_root)) {
                return error.ForkChoiceStateRootMismatch;
            }
        }

        return working_state;
    }

    fn replayCanonicalStateToSlot(self: *StateRegen, target_slot: u64) !?*CachedBeaconState {
        var state_graph_lease = self.acquireStateGraphLease();
        defer state_graph_lease.release();

        if (try self.db.getStateArchive(target_slot)) |bytes| {
            defer self.allocator.free(bytes);
            const exact_state = try deserializeState(
                self.allocator,
                self.shared_state_graph.pool,
                self.shared_state_graph.config,
                self.shared_state_graph.validator_pubkeys,
                bytes,
                self.shared_state_graph.state_transition_metrics,
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
            const block_root = try self.db.getFinalizedBlockRootBySlot(slot);
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
        var state_graph_lease = self.acquireStateGraphLease();
        defer state_graph_lease.release();

        if (try self.db.getStateArchive(target_slot)) |bytes| {
            defer self.allocator.free(bytes);
            return try deserializeState(
                self.allocator,
                self.shared_state_graph.pool,
                self.shared_state_graph.config,
                self.shared_state_graph.validator_pubkeys,
                bytes,
                self.shared_state_graph.state_transition_metrics,
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
            const block_root = try self.db.getFinalizedBlockRootBySlot(slot);
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
        var search_slot = computeStartSlotAtEpoch(computeEpochAtSlot(target_slot));
        while (true) {
            if (try self.db.getStateArchive(search_slot)) |bytes| {
                self.allocator.free(bytes);
                return search_slot;
            }
            if (search_slot == 0) return null;
            search_slot = search_slot -| preset.SLOTS_PER_EPOCH;
        }
    }

    fn loadArchivedStateUncached(self: *StateRegen, slot: u64) !*CachedBeaconState {
        const bytes = (try self.db.getStateArchive(slot)) orelse return error.StateArchiveMissing;
        defer self.allocator.free(bytes);

        var state_graph_lease = self.acquireStateGraphLease();
        defer state_graph_lease.release();
        return deserializeState(
            self.allocator,
            self.shared_state_graph.pool,
            self.shared_state_graph.config,
            self.shared_state_graph.validator_pubkeys,
            bytes,
            self.shared_state_graph.state_transition_metrics,
        );
    }

    fn loadArchivedStateByRootUncached(self: *StateRegen, state_root: [32]u8) !?*CachedBeaconState {
        const bytes = (try self.db.getStateArchiveByRoot(state_root)) orelse return null;
        defer self.allocator.free(bytes);

        var state_graph_lease = self.acquireStateGraphLease();
        defer state_graph_lease.release();
        return deserializeState(
            self.allocator,
            self.shared_state_graph.pool,
            self.shared_state_graph.config,
            self.shared_state_graph.validator_pubkeys,
            bytes,
            self.shared_state_graph.state_transition_metrics,
        );
    }

    fn findForkChoiceBlockByStateRoot(
        self: *StateRegen,
        fork_choice: *const ForkChoice,
        state_root: [32]u8,
    ) ?ProtoBlock {
        _ = self;
        for (fork_choice.getAllNodes()) |node| {
            if (node.payload_status == .pending) continue;
            if (std.mem.eql(u8, &node.state_root, &state_root)) {
                return node.toBlock();
            }
        }
        return null;
    }

    fn getBlockBytesByRoot(self: *StateRegen, block_root: [32]u8) !?[]const u8 {
        if (try self.db.getBlock(block_root)) |block_bytes| return block_bytes;
        return self.db.getBlockArchiveByRoot(block_root);
    }

    fn deserializeSignedBlock(
        self: *StateRegen,
        slot: u64,
        block_bytes: []const u8,
    ) !AnySignedBeaconBlock {
        const fork_seq = self.shared_state_graph.config.forkSeq(slot);
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
        try self.shared_state_graph.state_disposer.dispose(state);
    }

    fn acquireStateGraphLease(self: *StateRegen) StateGraphGate.Lease {
        return self.shared_state_graph.acquireMutationLease();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const RegenRuntimeFixture = @import("test_fixture.zig").RegenRuntimeFixture;

const ReplayTestBlock = struct {
    block_root: [32]u8,
    state_root: [32]u8,
    parent_root: [32]u8,
    slot: u64,
    post_state: *CachedBeaconState,
};

const ReplayScenario = struct {
    fork_choice: *ForkChoice,
    block1: ReplayTestBlock,
    block2: ReplayTestBlock,
    block3: ReplayTestBlock,
};

fn clonePublishedStateWithSharedPubkeys(
    allocator: Allocator,
    shared_pubkeys: *SharedValidatorPubkeys,
    source: *CachedBeaconState,
) !*CachedBeaconState {
    const cloned_state = try allocator.create(AnyBeaconState);
    errdefer allocator.destroy(cloned_state);
    cloned_state.* = try source.state.clone(.{});
    errdefer cloned_state.deinit();

    const validators = try cloned_state.validatorsSlice(allocator);
    defer allocator.free(validators);
    try shared_pubkeys.syncFromValidators(validators);

    return CachedBeaconState.createCachedBeaconState(
        allocator,
        cloned_state,
        source.metrics,
        shared_pubkeys.immutableData(source.config),
        .{
            .skip_sync_committee_cache = cloned_state.forkSeq() == .phase0,
            .skip_sync_pubkeys = true,
        },
    );
}

fn testJustifiedBalancesGetter(
    _: ?*anyopaque,
    _: fork_choice_mod.CheckpointWithPayloadStatus,
    state: *CachedBeaconState,
) fork_choice_mod.JustifiedBalances {
    return state.epoch_cache.getEffectiveBalanceIncrements();
}

fn initForkChoiceForReplayTest(
    allocator: Allocator,
    fixture: *RegenRuntimeFixture,
    genesis_block_root: [32]u8,
    genesis_state_root: [32]u8,
) !*ForkChoice {
    const genesis_slot = try fixture.published_state.state.slot();
    const justified = fork_choice_mod.CheckpointWithPayloadStatus.fromCheckpoint(.{
        .epoch = computeEpochAtSlot(genesis_slot),
        .root = genesis_block_root,
    }, .full);
    const balances = fixture.published_state.epoch_cache.getEffectiveBalanceIncrements();

    return fork_choice_mod.initFromAnchor(
        allocator,
        fixture.shared_state_graph.config,
        .{
            .slot = genesis_slot,
            .block_root = genesis_block_root,
            .parent_root = genesis_block_root,
            .state_root = genesis_state_root,
            .target_root = genesis_block_root,
            .justified_epoch = justified.epoch,
            .justified_root = justified.root,
            .finalized_epoch = justified.epoch,
            .finalized_root = justified.root,
            .unrealized_justified_epoch = justified.epoch,
            .unrealized_justified_root = justified.root,
            .unrealized_finalized_epoch = justified.epoch,
            .unrealized_finalized_root = justified.root,
            .extra_meta = .{ .pre_merge = {} },
            .timeliness = true,
        },
        genesis_slot,
        justified,
        justified,
        balances.items,
        .{ .getFn = testJustifiedBalancesGetter },
        .{},
        .{
            .proposer_boost = true,
            .proposer_boost_reorg = true,
            .compute_unrealized = true,
        },
    );
}

fn createReplaySignedBlock(
    allocator: Allocator,
    cached_state: *CachedBeaconState,
    target_slot: u64,
) !*@import("consensus_types").electra.SignedBeaconBlock.Type {
    const state = cached_state.state;
    const epoch_cache = cached_state.epoch_cache;

    const proposer_index = epoch_cache.getBeaconProposer(target_slot) catch 0;
    var latest_header = try state.latestBlockHeader();
    const parent_root = try latest_header.hashTreeRoot();

    const genesis_time = try state.genesisTime();
    const seconds_per_slot = cached_state.config.chain.SECONDS_PER_SLOT;
    const expected_timestamp = genesis_time + target_slot * seconds_per_slot;

    var execution_payload = @import("consensus_types").electra.ExecutionPayload.default_value;
    execution_payload.timestamp = expected_timestamp;
    const latest_block_hash = state.latestExecutionPayloadHeaderBlockHash() catch &([_]u8{0} ** 32);
    execution_payload.parent_hash = latest_block_hash.*;

    const current_epoch = computeEpochAtSlot(target_slot);
    const randao_mix = try state_transition.getRandaoMix(
        .electra,
        state.castToFork(.electra),
        current_epoch,
    );
    execution_payload.prev_randao = randao_mix.*;

    const signed_block = try allocator.create(@import("consensus_types").electra.SignedBeaconBlock.Type);
    errdefer allocator.destroy(signed_block);

    signed_block.* = .{
        .message = .{
            .slot = target_slot,
            .proposer_index = proposer_index,
            .parent_root = parent_root.*,
            .state_root = [_]u8{0} ** 32,
            .body = .{
                .randao_reveal = [_]u8{0} ** 96,
                .eth1_data = @import("consensus_types").phase0.Eth1Data.default_value,
                .graffiti = [_]u8{0} ** 32,
                .proposer_slashings = @import("consensus_types").phase0.ProposerSlashings.default_value,
                .attester_slashings = @import("consensus_types").phase0.AttesterSlashings.default_value,
                .attestations = @import("consensus_types").electra.Attestations.default_value,
                .deposits = @import("consensus_types").phase0.Deposits.default_value,
                .voluntary_exits = @import("consensus_types").phase0.VoluntaryExits.default_value,
                .sync_aggregate = .{
                    .sync_committee_bits = @import("ssz").BitVectorType(preset.SYNC_COMMITTEE_SIZE).default_value,
                    .sync_committee_signature = @import("consensus_types").primitive.BLSSignature.default_value,
                },
                .execution_payload = execution_payload,
                .bls_to_execution_changes = @import("consensus_types").capella.SignedBLSToExecutionChanges.default_value,
                .blob_kzg_commitments = @import("consensus_types").electra.BlobKzgCommitments.default_value,
                .execution_requests = @import("consensus_types").electra.ExecutionRequests.default_value,
            },
        },
        .signature = @import("consensus_types").primitive.BLSSignature.default_value,
    };

    return signed_block;
}

fn importReplayTestBlock(
    allocator: Allocator,
    fixture: *RegenRuntimeFixture,
    parent_state: *CachedBeaconState,
) !ReplayTestBlock {
    const parent_slot = try parent_state.state.slot();
    const target_slot = parent_slot + 1;

    var generation_state = try parent_state.clone(allocator, .{ .transfer_cache = false });
    defer {
        generation_state.deinit();
        allocator.destroy(generation_state);
    }
    try processSlots(allocator, generation_state, target_slot, .{});

    const signed_block = try createReplaySignedBlock(allocator, generation_state, target_slot);
    defer {
        @import("consensus_types").electra.SignedBeaconBlock.deinit(allocator, signed_block);
        allocator.destroy(signed_block);
    }

    var any_signed = AnySignedBeaconBlock{ .full_electra = signed_block };
    var transition_pre_state = try parent_state.clone(allocator, .{ .transfer_cache = false });
    errdefer {
        transition_pre_state.deinit();
        allocator.destroy(transition_pre_state);
    }

    const post_state = try stateTransition(
        allocator,
        transition_pre_state,
        any_signed,
        TransitionOpt{
            .verify_state_root = false,
            .verify_proposer = false,
            .verify_signatures = false,
            .transfer_cache = false,
        },
    );
    transition_pre_state.deinit();
    allocator.destroy(transition_pre_state);
    errdefer {
        post_state.deinit();
        allocator.destroy(post_state);
    }

    try post_state.state.commit();
    const state_root = (try post_state.state.hashTreeRoot()).*;
    signed_block.message.state_root = state_root;

    var body_root: [32]u8 = undefined;
    try any_signed.beaconBlock().beaconBlockBody().hashTreeRoot(allocator, &body_root);
    const block_header = @import("consensus_types").phase0.BeaconBlockHeader.Type{
        .slot = target_slot,
        .proposer_index = signed_block.message.proposer_index,
        .parent_root = signed_block.message.parent_root,
        .state_root = state_root,
        .body_root = body_root,
    };
    var block_root: [32]u8 = undefined;
    try @import("consensus_types").phase0.BeaconBlockHeader.hashTreeRoot(&block_header, &block_root);

    const block_bytes = try any_signed.serialize(allocator);
    defer allocator.free(block_bytes);
    try fixture.db.putBlock(block_root, block_bytes);

    const cached_state_root = try fixture.regen.onNewBlock(post_state, true);
    try std.testing.expectEqualSlices(u8, &state_root, &cached_state_root);

    return .{
        .block_root = block_root,
        .state_root = state_root,
        .parent_root = signed_block.message.parent_root,
        .slot = target_slot,
        .post_state = post_state,
    };
}

fn replayProtoBlock(block: ReplayTestBlock) ProtoBlock {
    return .{
        .slot = block.slot,
        .block_root = block.block_root,
        .parent_root = block.parent_root,
        .state_root = block.state_root,
        .target_root = block.block_root,
        .justified_epoch = 0,
        .justified_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .finalized_root = [_]u8{0} ** 32,
        .unrealized_justified_epoch = 0,
        .unrealized_justified_root = [_]u8{0} ** 32,
        .unrealized_finalized_epoch = 0,
        .unrealized_finalized_root = [_]u8{0} ** 32,
        .extra_meta = .{ .pre_merge = {} },
        .timeliness = true,
    };
}

fn evictStateFromBlockCache(cache: *BlockStateCache, state_root: [32]u8) !void {
    if (cache.head_root) |head_root| {
        try std.testing.expect(!std.mem.eql(u8, &head_root, &state_root));
    }

    const removed = cache.cache.fetchOrderedRemove(state_root) orelse return error.StateNotFound;
    for (cache.key_order.items, 0..) |key, idx| {
        if (std.mem.eql(u8, &key, &state_root)) {
            _ = cache.key_order.orderedRemove(idx);
            break;
        }
    }
    try cache.state_disposer.dispose(removed.value);
}

fn initReplayScenario(
    allocator: Allocator,
    fixture: *RegenRuntimeFixture,
) !ReplayScenario {
    const genesis_state_root = try fixture.seedHeadState();
    var genesis_header = try fixture.published_state.state.latestBlockHeader();
    const genesis_block_root = (try genesis_header.hashTreeRoot()).*;

    const fork_choice = try initForkChoiceForReplayTest(
        allocator,
        fixture,
        genesis_block_root,
        genesis_state_root,
    );
    errdefer fork_choice_mod.destroyFromAnchor(allocator, fork_choice);
    fixture.regen.setForkChoice(fork_choice);
    errdefer fixture.regen.clearForkChoice();

    const genesis_state = fixture.block_cache.get(genesis_state_root).?;
    const block1 = try importReplayTestBlock(allocator, fixture, genesis_state);
    try fork_choice_mod.onBlockFromProto(fork_choice, allocator, replayProtoBlock(block1), block1.slot);

    const block2 = try importReplayTestBlock(allocator, fixture, block1.post_state);
    try fork_choice_mod.onBlockFromProto(fork_choice, allocator, replayProtoBlock(block2), block2.slot);

    const block3 = try importReplayTestBlock(allocator, fixture, block2.post_state);
    try fork_choice_mod.onBlockFromProto(fork_choice, allocator, replayProtoBlock(block3), block3.slot);

    return .{
        .fork_choice = fork_choice,
        .block1 = block1,
        .block2 = block2,
        .block3 = block3,
    };
}

test "StateRegen: basic getPreState from block cache" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    // Add a state to block cache
    const state = try fixture.clonePublishedState();
    const root = try fixture.regen.onNewBlock(state, true);
    const parent_slot = try state.state.slot();

    // Should find it via getPreState
    const pre_state = try fixture.regen.getPreState(root, root, parent_slot, parent_slot + 1);
    try std.testing.expectEqual(state, pre_state);
}

test "StateRegen: getPreState returns error when nothing cached" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    const unknown_root = [_]u8{0xde} ** 32;
    try std.testing.expectError(error.NoPreStateAvailable, fixture.regen.getPreState(unknown_root, unknown_root, 99, 100));
}

test "StateRegen: onFinalized prunes old states" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    // Add checkpoint at epoch 5
    const state = try fixture.clonePublishedState();
    const cp = CheckpointKey{ .epoch = 5, .root = [_]u8{0x05} ** 32 };
    try fixture.regen.onCheckpoint(cp, state);

    try std.testing.expectEqual(@as(usize, 1), fixture.cp_cache.size());

    // Finalize at epoch 10 — should prune epoch 5
    try fixture.regen.onFinalized(10);
    try std.testing.expectEqual(@as(usize, 0), fixture.cp_cache.size());
}

test "StateRegen: checkpoint publication seals lazy PMT roots" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    const state = try fixture.clonePublishedState();
    try state.state.setSlot((try state.state.slot()) + 1);

    const root_state_before = switch (state.state.*) {
        inline else => |fork_state| fork_state.root.getState(fork_state.pool),
    };
    try std.testing.expect(root_state_before.isBranchLazy());

    const cp = CheckpointKey{ .epoch = 5, .root = [_]u8{0x05} ** 32 };
    try fixture.regen.onCheckpoint(cp, state);

    const cached_state = fixture.cp_cache.get(cp);
    try std.testing.expect(cached_state != null);
    const root_state_after = switch (cached_state.?.state.*) {
        inline else => |fork_state| fork_state.root.getState(fork_state.pool),
    };
    try std.testing.expect(root_state_after.isBranchComputed());
}

test "StateRegen: getStateByRoot returns state from block cache" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    // Add a state to block cache
    const state = try fixture.clonePublishedState();
    const state_root = try fixture.regen.onNewBlock(state, true);

    // getStateByRoot should find it in block cache
    const found = try fixture.regen.getStateByRoot(state_root);
    try std.testing.expectEqual(state, found);
}

test "StateRegen: getStateByRoot returns null for unknown root" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    const unknown_root = [_]u8{0xaa} ** 32;
    const found = try fixture.regen.getStateByRoot(unknown_root);
    try std.testing.expectEqual(@as(?*CachedBeaconState, null), found);
}

test "StateRegen: getPreState returns error when nothing canonical is available" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    const unknown_root = [_]u8{0xbb} ** 32;
    try std.testing.expectError(error.NoPreStateAvailable, fixture.regen.getPreState(unknown_root, unknown_root, 63, 64));
}

test "StateRegen: loadPreStateUncached loads archived state root after verifying published ownership" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    try fixture.regen.verifyPublishedStateOwnership(fixture.published_state);

    const archived = try fixture.clonePublishedState();
    defer {
        archived.deinit();
        allocator.destroy(archived);
    }
    try archived.state.commit();
    const archived_state_root = (try archived.state.hashTreeRoot()).*;
    const archived_slot = try archived.state.slot();
    const archived_bytes = try archived.state.serialize(allocator);
    defer allocator.free(archived_bytes);
    try fixture.db.putStateArchive(archived_slot, archived_state_root, archived_bytes);

    const loaded = try fixture.regen.loadPreStateUncached(
        [_]u8{0x11} ** 32,
        archived_state_root,
        archived_slot + 1,
    );
    defer {
        fixture.regen.destroyTransientState(loaded);
    }

    try std.testing.expectEqual(archived_slot, try loaded.state.slot());
    try std.testing.expectEqual(@as(usize, 0), fixture.block_cache.size());
}

test "StateRegen: getStateByRoot replays fork-choice state from cached ancestor" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 64);
    defer fixture.deinit();

    const scenario = try initReplayScenario(allocator, &fixture);
    defer {
        fixture.regen.clearForkChoice();
        fork_choice_mod.destroyFromAnchor(allocator, scenario.fork_choice);
    }

    try evictStateFromBlockCache(fixture.block_cache, scenario.block2.state_root);
    try std.testing.expect(fixture.block_cache.get(scenario.block2.state_root) == null);
    try std.testing.expect(fixture.block_cache.get(scenario.block1.state_root) != null);

    const replayed = (try fixture.regen.getStateByRoot(scenario.block2.state_root)).?;
    try std.testing.expectEqual(replayed, fixture.block_cache.get(scenario.block2.state_root).?);
    try std.testing.expectEqual(scenario.block2.slot, try replayed.state.slot());

    const replayed_state_root = (try replayed.state.hashTreeRoot()).*;
    try std.testing.expectEqualSlices(u8, &scenario.block2.state_root, &replayed_state_root);
}

test "StateRegen: loadPreStateUncached replays parent state from fork choice" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 64);
    defer fixture.deinit();

    const scenario = try initReplayScenario(allocator, &fixture);
    defer {
        fixture.regen.clearForkChoice();
        fork_choice_mod.destroyFromAnchor(allocator, scenario.fork_choice);
    }

    try evictStateFromBlockCache(fixture.block_cache, scenario.block2.state_root);
    try std.testing.expect(fixture.block_cache.get(scenario.block2.state_root) == null);
    try std.testing.expect(fixture.block_cache.get(scenario.block1.state_root) != null);

    const replayed = try fixture.regen.loadPreStateUncached(
        scenario.block2.block_root,
        scenario.block2.state_root,
        scenario.block3.slot,
    );
    defer fixture.regen.destroyTransientState(replayed);

    try std.testing.expectEqual(scenario.block2.slot, try replayed.state.slot());
    const replayed_state_root = (try replayed.state.hashTreeRoot()).*;
    try std.testing.expectEqualSlices(u8, &scenario.block2.state_root, &replayed_state_root);
    try std.testing.expect(fixture.block_cache.get(scenario.block2.state_root) == null);
}

test "StateRegen: getStateByRoot reloads persisted checkpoint seed during fork-choice replay" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 64);
    defer fixture.deinit();

    const genesis_state_root = try fixture.seedHeadState();
    var genesis_header = try fixture.published_state.state.latestBlockHeader();
    const genesis_block_root = (try genesis_header.hashTreeRoot()).*;

    const fork_choice = try initForkChoiceForReplayTest(
        allocator,
        &fixture,
        genesis_block_root,
        genesis_state_root,
    );
    defer {
        fixture.regen.clearForkChoice();
        fork_choice_mod.destroyFromAnchor(allocator, fork_choice);
    }
    fixture.regen.setForkChoice(fork_choice);

    var persisted_seed_source: ?*CachedBeaconState = null;
    defer if (persisted_seed_source) |state| {
        fixture.regen.destroyTransientState(state);
    };

    const replay_block_count = preset.SLOTS_PER_EPOCH + 2;
    var blocks: [replay_block_count]ReplayTestBlock = undefined;
    var previous_state = fixture.block_cache.get(genesis_state_root).?;
    var persisted_cp: ?CheckpointKey = null;

    for (0..replay_block_count) |i| {
        const block = try importReplayTestBlock(allocator, &fixture, previous_state);
        blocks[i] = block;
        try fork_choice_mod.onBlockFromProto(fork_choice, allocator, replayProtoBlock(block), block.slot);

        if (i == 0) {
            persisted_seed_source = try block.post_state.clone(allocator, .{ .transfer_cache = false });
            const seed_checkpoint_state = try block.post_state.clone(allocator, .{ .transfer_cache = false });
            const checkpoint = CheckpointKey{
                .epoch = computeEpochAtSlot(block.slot),
                .root = block.block_root,
            };
            persisted_cp = checkpoint;
            try fixture.regen.onCheckpoint(checkpoint, seed_checkpoint_state);
        }

        previous_state = block.post_state;
    }

    const checkpoint_seed_source = persisted_seed_source.?;
    const checkpoint = persisted_cp.?;
    for (1..5) |offset| {
        const dummy_state = try checkpoint_seed_source.clone(allocator, .{ .transfer_cache = false });
        try fixture.regen.onCheckpoint(.{
            .epoch = checkpoint.epoch + offset,
            .root = [_]u8{@as(u8, @intCast(offset))} ** 32,
        }, dummy_state);
    }

    _ = try fixture.cp_cache.processState([_]u8{0xff} ** 32, fixture.published_state);
    try std.testing.expect(fixture.cp_cache.getLatest(checkpoint.root, checkpoint.epoch) == null);

    const target_index = replay_block_count - 2;
    try evictStateFromBlockCache(fixture.block_cache, blocks[target_index].state_root);
    try evictStateFromBlockCache(fixture.block_cache, blocks[target_index - 1].state_root);
    try evictStateFromBlockCache(fixture.block_cache, blocks[target_index - 2].state_root);
    try std.testing.expect(fixture.block_cache.get(blocks[target_index].state_root) == null);

    const replayed = (try fixture.regen.getStateByRoot(blocks[target_index].state_root)).?;
    try std.testing.expectEqual(blocks[target_index].slot, try replayed.state.slot());

    const replayed_state_root = (try replayed.state.hashTreeRoot()).*;
    try std.testing.expectEqualSlices(u8, &blocks[target_index].state_root, &replayed_state_root);
    try std.testing.expect(fixture.cp_cache.getLatest(checkpoint.root, checkpoint.epoch) != null);
}

test "StateRegen: verifyPublishedStateOwnership accepts runtime-owned shared singleton" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    try fixture.regen.verifyPublishedStateOwnership(fixture.published_state);

    try std.testing.expect(fixture.shared_state_graph.validator_pubkeys.ownsStateCaches(
        fixture.published_state.epoch_cache.pubkey_to_index,
        fixture.published_state.epoch_cache.index_to_pubkey,
    ));
    try std.testing.expectEqual(
        @as(usize, 16),
        fixture.shared_state_graph.validator_pubkeys.index_to_pubkey.items.len,
    );
}

test "StateRegen: verifyPublishedStateOwnership rejects detached test-helper pubkey caches" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    const detached_pubkeys = try allocator.create(SharedValidatorPubkeys);
    defer {
        detached_pubkeys.deinit();
        allocator.destroy(detached_pubkeys);
    }
    detached_pubkeys.* = SharedValidatorPubkeys.init(allocator);

    const detached_state = try clonePublishedStateWithSharedPubkeys(
        allocator,
        detached_pubkeys,
        fixture.published_state,
    );
    defer {
        detached_state.deinit();
        allocator.destroy(detached_state);
    }

    try std.testing.expectError(
        error.PublishedStatePubkeyCacheMismatch,
        fixture.regen.verifyPublishedStateOwnership(detached_state),
    );
}
