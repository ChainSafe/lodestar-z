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

pub const StateRegen = struct {
    allocator: Allocator,
    block_cache: *BlockStateCache,
    checkpoint_cache: *CheckpointStateCache,
    // fork_choice: *ForkChoice,   // TODO: wire when available
    db: *BeaconDB,
    shared_state_graph: *SharedStateGraph,

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
            .db = db,
            .shared_state_graph = shared_state_graph,
        };
    }

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
    /// Production cold-path states borrow the runtime singleton pubkey cache.
    /// The fallback cache cleanup remains only for standalone/test callers that
    /// construct detached immutable data without a cold-path binding.
    pub fn destroyTransientState(self: *StateRegen, state: *CachedBeaconState) void {
        state.deinit();
        self.allocator.destroy(state);
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
        const bytes = (try self.db.getStateArchiveByRoot(state_root)) orelse return null;
        defer self.allocator.free(bytes);
        var state_graph_lease = self.acquireStateGraphLease();
        defer state_graph_lease.release();
        const cached_state = try deserializeState(
            self.allocator,
            self.shared_state_graph.pool,
            self.shared_state_graph.config,
            self.shared_state_graph.validator_pubkeys,
            bytes,
        );
        return try self.cacheLoadedState(cached_state, false);
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
        );
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
        shared_pubkeys.immutableData(source.config),
        .{
            .skip_sync_committee_cache = cloned_state.forkSeq() == .phase0,
            .skip_sync_pubkeys = true,
        },
    );
}

test "StateRegen: basic getPreState from block cache" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    // Add a state to block cache
    const state = try fixture.clonePublishedState();
    const root = try fixture.regen.onNewBlock(state, true);

    // Should find it via getPreState
    const pre_state = try fixture.regen.getPreState(root, root, 100);
    try std.testing.expectEqual(state, pre_state);
}

test "StateRegen: getPreState returns error when nothing cached" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    const unknown_root = [_]u8{0xde} ** 32;
    try std.testing.expectError(error.NoPreStateAvailable, fixture.regen.getPreState(unknown_root, unknown_root, 100));
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
    try std.testing.expectError(error.NoPreStateAvailable, fixture.regen.getPreState(unknown_root, unknown_root, 64));
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
