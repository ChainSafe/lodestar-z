//! Chain — owns all chain state and exposes pipeline functions.
//!
//! This is the central coordinator for beacon chain state. It holds
//! pointers to all chain components (fork choice, caches, DB, pools)
//! and exposes the core pipeline functions:
//!
//! - `importBlock` — full block import pipeline (sanity → STFN → FC → persist)
//! - `importAttestation` — validate → FC weight → pool (stub)
//! - `onSlot` — FC time update, seen cache prune
//! - `onFinalized` — archive, prune caches, prune FC (stub)
//! - `getHead` — current head info
//! - `getStatus` — P2P status message
//!
//! The Chain does NOT own the backing memory for its components — the
//! BeaconNode allocates everything and passes pointers. This avoids
//! ownership complexity and keeps Chain as a pure coordinator.

const std = @import("std");
const Allocator = std.mem.Allocator;

const consensus_types = @import("consensus_types");
const preset = @import("preset").preset;
const fork_types = @import("fork_types");
const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const state_transition = @import("state_transition");
const BatchVerifier = @import("bls").BatchVerifier;
const CachedBeaconState = state_transition.CachedBeaconState;
const BlockStateCache = state_transition.BlockStateCache;
const CheckpointStateCache = state_transition.CheckpointStateCache;
const StateRegen = state_transition.StateRegen;
const QueuedStateRegen = @import("queued_regen.zig").QueuedStateRegen;
const RegenPriority = @import("queued_regen.zig").RegenPriority;
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const db_mod = @import("db");
const BeaconDB = db_mod.BeaconDB;

const block_import_mod = @import("block_import.zig");
const HeadTracker = block_import_mod.HeadTracker;
const ImportError = block_import_mod.ImportError;
const verifySanity = block_import_mod.verifySanity;
const op_pool_mod = @import("op_pool.zig");
const OpPool = op_pool_mod.OpPool;
const seen_cache_mod = @import("seen_cache.zig");
const SeenCache = seen_cache_mod.SeenCache;
const produce_block_mod = @import("produce_block.zig");
const ProducedBlockBody = produce_block_mod.ProducedBlockBody;
const produceBlockBody = produce_block_mod.produceBlockBody;

const fork_choice_mod = @import("fork_choice");
const ForkChoice = fork_choice_mod.ForkChoiceStruct;
const ProtoBlock = fork_choice_mod.ProtoBlock;

const networking = @import("networking");
const StatusMessage = networking.messages.StatusMessage;

const chain_types = @import("types.zig");
pub const ImportResult = chain_types.ImportResult;
pub const HeadInfo = chain_types.HeadInfo;
pub const SyncStatus = chain_types.SyncStatus;
pub const EventCallback = chain_types.EventCallback;
pub const SseEvent = chain_types.SseEvent;

const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;

// ---------------------------------------------------------------------------
// Chain
// ---------------------------------------------------------------------------

pub const Chain = struct {
    allocator: Allocator,
    config: *const BeaconConfig,

    // --- State components (not owned, pointers from BeaconNode) ---
    fork_choice: ?*ForkChoice,
    block_state_cache: *BlockStateCache,
    checkpoint_state_cache: *CheckpointStateCache,
    state_regen: *StateRegen,
    /// Queued state regenerator — optional, wraps state_regen with
    /// request deduplication and priority queuing. When set, used for
    /// pre-state lookups in block import and API handlers.
    queued_regen: ?*QueuedStateRegen,
    db: *BeaconDB,
    op_pool: *OpPool,
    seen_cache: *SeenCache,
    head_tracker: *HeadTracker,

    // --- Block import state ---
    /// When true, BLS signatures are verified during block import.
    verify_signatures: bool,

    /// Maps block root → state root for pre-state lookup.
    block_to_state: std.AutoArrayHashMap([32]u8, [32]u8),

    // --- SSE event callback (optional, set by BeaconNode) ---
    event_callback: ?EventCallback,

    // --- Genesis info ---
    genesis_validators_root: [32]u8,

    /// Initialize a Chain with pointers to all components.
    ///
    /// None of the pointed-to objects are owned by Chain. The caller
    /// (BeaconNode) is responsible for their lifetime.
    pub fn init(
        allocator: Allocator,
        config: *const BeaconConfig,
        block_state_cache: *BlockStateCache,
        checkpoint_state_cache: *CheckpointStateCache,
        state_regen: *StateRegen,
        db: *BeaconDB,
        op_pool: *OpPool,
        seen_cache: *SeenCache,
        head_tracker: *HeadTracker,
    ) Chain {
        return .{
            .allocator = allocator,
            .config = config,
            .fork_choice = null,
            .block_state_cache = block_state_cache,
            .checkpoint_state_cache = checkpoint_state_cache,
            .state_regen = state_regen,
            .queued_regen = null,
            .db = db,
            .op_pool = op_pool,
            .seen_cache = seen_cache,
            .head_tracker = head_tracker,
            .verify_signatures = false,
            .block_to_state = std.AutoArrayHashMap([32]u8, [32]u8).init(allocator),
            .event_callback = null,
            .genesis_validators_root = [_]u8{0} ** 32,
        };
    }

    pub fn deinit(self: *Chain) void {
        self.block_to_state.deinit();
    }

    // -----------------------------------------------------------------------
    // Genesis initialization
    // -----------------------------------------------------------------------

    /// Register the genesis block root → state root mapping so the first
    /// block import can find its parent pre-state.
    pub fn registerGenesisRoot(self: *Chain, block_root: [32]u8, state_root: [32]u8) !void {
        try self.block_to_state.put(block_root, state_root);
    }

    // -----------------------------------------------------------------------
    // Block import pipeline
    // -----------------------------------------------------------------------

    /// Full block import pipeline: sanity → STFN → fork choice → persist → head → SSE.
    ///
    /// Returns `error.UnknownParentBlock` when the parent root is not in
    /// the chain — callers should catch this to trigger unknown block sync.
    pub fn importBlock(
        self: *Chain,
        signed_block: *const consensus_types.electra.SignedBeaconBlock.Type,
    ) !ImportResult {
        const block_slot = signed_block.message.slot;
        const parent_root = signed_block.message.parent_root;

        const prev_epoch = computeEpochAtSlot(if (block_slot > 0) block_slot - 1 else 0);
        const target_epoch = computeEpochAtSlot(block_slot);
        const is_epoch_transition = target_epoch != prev_epoch;

        // Compute block root for sanity checks and persistence.
        var body_root: [32]u8 = undefined;
        try consensus_types.electra.BeaconBlockBody.hashTreeRoot(self.allocator, &signed_block.message.body, &body_root);
        const header = consensus_types.phase0.BeaconBlockHeader.Type{
            .slot = block_slot,
            .proposer_index = signed_block.message.proposer_index,
            .parent_root = parent_root,
            .state_root = signed_block.message.state_root,
            .body_root = body_root,
        };
        var block_root: [32]u8 = undefined;
        try consensus_types.phase0.BeaconBlockHeader.hashTreeRoot(&header, &block_root);

        // Stage 1: Sanity checks (cheap, before any state transition work).
        verifySanity(
            block_slot,
            parent_root,
            block_root,
            self.head_tracker.finalized_epoch,
            &self.block_to_state,
        ) catch |err| {
            switch (err) {
                ImportError.UnknownParentBlock => {
                    std.log.info("Unknown parent for slot {d} parent={s}...", .{
                        block_slot, &std.fmt.bytesToHex(parent_root[0..4], .lower),
                    });
                },
                ImportError.BlockAlreadyKnown, ImportError.BlockAlreadyFinalized => {},
                else => {
                    std.log.warn("Sanity check failed for slot {d}: {}", .{ block_slot, err });
                },
            }
            return err;
        };

        // Stage 2: State transition.
        // Use queued regen (with dedup + priority) when available,
        // fall back to direct cache lookup.
        const pre_state = if (self.queued_regen) |qr|
            qr.getPreState(parent_root, block_slot, .block_import) catch |err| {
                std.log.warn("QueuedRegen.getPreState failed: parent_root={s}... err={}", .{
                    &std.fmt.bytesToHex(parent_root[0..4], .lower),
                    err,
                });
                return error.NoPreStateAvailable;
            }
        else
            self.getStateByBlockRoot(parent_root) orelse {
                std.log.warn("NoPreStateAvailable: parent_root={s}... block_to_state has {d} entries", .{
                    &std.fmt.bytesToHex(parent_root[0..4], .lower),
                    self.block_to_state.count(),
                });
                return error.NoPreStateAvailable;
            };

        const stfn_result = try self.runStateTransition(pre_state, signed_block, block_slot);
        const post_state = stfn_result.post_state;

        // Stage 3: Cache post-state + persist block.
        _ = if (self.queued_regen) |qr| try qr.onNewBlock(post_state, true) else try self.state_regen.onNewBlock(post_state, true);
        try self.block_to_state.put(stfn_result.block_root, stfn_result.state_root);

        const any_signed = AnySignedBeaconBlock{ .full_electra = @constCast(signed_block) };
        const block_bytes = try any_signed.serialize(self.allocator);
        defer self.allocator.free(block_bytes);
        try self.db.putBlock(stfn_result.block_root, block_bytes);

        // Checkpoint caching at epoch boundaries.
        if (is_epoch_transition) {
            const cp_state = try post_state.clone(self.allocator, .{ .transfer_cache = false });
            errdefer {
                cp_state.deinit();
                self.allocator.destroy(cp_state);
            }
            if (self.queued_regen) |qr| {
                try qr.onCheckpoint(
                    .{ .epoch = target_epoch, .root = stfn_result.block_root },
                    cp_state,
                );
            } else {
                try self.state_regen.onCheckpoint(
                    .{ .epoch = target_epoch, .root = stfn_result.block_root },
                    cp_state,
                );
            }

        }

        // Stage 4: Head tracking + fork choice update.
        try self.head_tracker.onBlock(stfn_result.block_root, block_slot, stfn_result.state_root);
        if (is_epoch_transition) {
            try self.head_tracker.onEpochTransition(post_state);
        }

        // Wire block into fork choice DAG.
        var justified_cp: consensus_types.phase0.Checkpoint.Type = undefined;
        try post_state.state.currentJustifiedCheckpoint(&justified_cp);
        var finalized_cp: consensus_types.phase0.Checkpoint.Type = undefined;
        try post_state.state.finalizedCheckpoint(&finalized_cp);

        const fc_block = ProtoBlock{
            .slot = block_slot,
            .block_root = stfn_result.block_root,
            .parent_root = parent_root,
            .state_root = stfn_result.state_root,
            .target_root = stfn_result.block_root,
            .justified_epoch = justified_cp.epoch,
            .justified_root = justified_cp.root,
            .finalized_epoch = finalized_cp.epoch,
            .finalized_root = finalized_cp.root,
            .unrealized_justified_epoch = justified_cp.epoch,
            .unrealized_justified_root = justified_cp.root,
            .unrealized_finalized_epoch = finalized_cp.epoch,
            .unrealized_finalized_root = finalized_cp.root,
            .extra_meta = .{ .pre_merge = {} },
            .timeliness = true,
        };

        if (self.fork_choice) |fc| fc.onBlock(self.allocator, fc_block, block_slot) catch |err| switch (err) {
            error.InvalidBlock => {},
            else => return err,
        };

        const result = ImportResult{
            .block_root = stfn_result.block_root,
            .state_root = stfn_result.state_root,
            .slot = block_slot,
            .epoch_transition = is_epoch_transition,
        };

        // Stage 5: Emit SSE events.
        if (self.event_callback) |cb| {
            cb.emit(.{ .block = .{
                .slot = block_slot,
                .block_root = stfn_result.block_root,
            } });
            cb.emit(.{ .head = .{
                .slot = block_slot,
                .block_root = stfn_result.block_root,
                .state_root = stfn_result.state_root,
                .epoch_transition = is_epoch_transition,
            } });
        }

        return result;
    }

    // -----------------------------------------------------------------------
    // Attestation import (stub — to be implemented)
    // -----------------------------------------------------------------------

    /// Import a validated attestation: apply to fork choice and insert into op pool.
    ///
    /// Callers must have already run gossip validation (committee bounds,
    /// slot range, target root known). This function applies the
    /// attestation weight to fork choice and stores it for block packing.
    ///
    /// Signature verification is NOT done here — it is the caller's
    /// responsibility (gossip validation or API layer).
    pub fn importAttestation(
        self: *Chain,
        attestation_slot: u64,
        committee_index: u64,
        target_root: [32]u8,
        target_epoch: u64,
        validator_index: u64,
        attestation: consensus_types.phase0.Attestation.Type,
    ) !void {
        _ = committee_index;

        // Apply vote weight to fork choice.
        if (self.fork_choice) |fc| {
            fc.onAttestation(
                self.allocator,
                @intCast(validator_index),
                target_root,
                target_epoch,
            ) catch |err| {
                std.log.warn("FC onAttestation failed for validator {d} slot {d}: {}", .{
                    validator_index, attestation_slot, err,
                });
                // Non-fatal — still insert into pool for block packing.
            };
        }

        // Insert into attestation pool for block production.
        try self.op_pool.attestation_pool.add(attestation);
    }

    // -----------------------------------------------------------------------
    // Slot tick
    // -----------------------------------------------------------------------

    /// Called at the start of each slot.
    ///
    /// Updates fork choice time and prunes the seen cache.
    pub fn onSlot(self: *Chain, slot: u64) void {
        // Update fork choice time (removes proposer boost from previous slot).
        if (self.fork_choice) |fc| {
            fc.updateTime(slot) catch {};
        }

        // Prune seen blocks older than 2 epochs.
        const min_slot = if (slot > 2 * preset.SLOTS_PER_EPOCH)
            slot - 2 * preset.SLOTS_PER_EPOCH
        else
            0;
        self.seen_cache.pruneBlocks(min_slot);
    }

    // -----------------------------------------------------------------------
    // Finalization handler
    // -----------------------------------------------------------------------

    /// Called when a new finalized checkpoint is detected.
    ///
    /// Prunes caches to free memory from pre-finalization data,
    /// prunes the fork choice DAG, and emits SSE finalized_checkpoint event.
    pub fn onFinalized(self: *Chain, finalized_epoch: u64, finalized_root: [32]u8) void {
        std.log.info("onFinalized: epoch={d} root={s}...", .{
            finalized_epoch,
            &std.fmt.bytesToHex(finalized_root[0..4], .lower),
        });

        // Prune block state cache — evict states older than finalized epoch.
        self.block_state_cache.pruneBeforeEpoch(finalized_epoch);

        // Prune checkpoint state cache — remove checkpoints below finalized epoch.
        self.checkpoint_state_cache.pruneFinalized(finalized_epoch) catch |err| {
            std.log.warn("onFinalized: checkpoint cache prune failed: {}", .{err});
        };

        // Prune fork choice DAG — remove nodes below finalized root.
        if (self.fork_choice) |fc| {
            _ = fc.prune(self.allocator, finalized_root) catch |err| {
                std.log.warn("onFinalized: fork choice prune failed: {}", .{err});
            };
        }

        // Prune seen cache — remove entries older than 2 epochs before finalization.
        const prune_slot = if (finalized_epoch > 2)
            (finalized_epoch - 2) * preset.SLOTS_PER_EPOCH
        else
            0;
        self.seen_cache.pruneBlocks(prune_slot);

        // Emit SSE finalized_checkpoint event.
        if (self.event_callback) |cb| {
            // Look up the state root for the finalized block.
            const state_root = self.block_to_state.get(finalized_root) orelse [_]u8{0} ** 32;
            cb.emit(.{ .finalized_checkpoint = .{
                .epoch = finalized_epoch,
                .root = finalized_root,
                .state_root = state_root,
            } });
        }
    }

    // -----------------------------------------------------------------------
    // Head / status queries
    // -----------------------------------------------------------------------

    /// Get current head info.
    ///
    /// Uses fork choice head when available (authoritative LMD-GHOST head),
    /// falls back to the naive head tracker.
    pub fn getHead(self: *const Chain) HeadInfo {
        if (self.fork_choice) |fc| {
            const fc_head = fc.head;
            const finalized_cp = fc.getFinalizedCheckpoint();
            const justified_cp = fc.getJustifiedCheckpoint();
            return .{
                .slot = fc_head.slot,
                .root = fc_head.block_root,
                .state_root = fc_head.state_root,
                .finalized_epoch = finalized_cp.epoch,
                .justified_epoch = justified_cp.epoch,
            };
        }
        return .{
            .slot = self.head_tracker.head_slot,
            .root = self.head_tracker.head_root,
            .state_root = self.head_tracker.head_state_root,
            .finalized_epoch = self.head_tracker.finalized_epoch,
            .justified_epoch = self.head_tracker.justified_epoch,
        };
    }

    /// Get current sync status.
    pub fn getSyncStatus(self: *const Chain) SyncStatus {
        const head_slot = if (self.fork_choice) |fc| fc.head.slot else self.head_tracker.head_slot;
        return .{
            .head_slot = head_slot,
            .sync_distance = 0,
            .is_syncing = false,
            .is_optimistic = false,
            .el_offline = false,
        };
    }

    /// Build a StatusMessage reflecting the current chain state.
    ///
    /// Used for req/resp Status exchanges with peers.
    pub fn getStatus(self: *const Chain) StatusMessage.Type {
        return .{
            .fork_digest = self.config.forkDigestAtSlot(self.head_tracker.head_slot, self.genesis_validators_root),
            .finalized_root = if (self.head_tracker.finalized_epoch == 0)
                [_]u8{0} ** 32
            else if (self.head_tracker.getBlockRoot(
                self.head_tracker.finalized_epoch * preset.SLOTS_PER_EPOCH,
            )) |r| r else [_]u8{0} ** 32,
            .finalized_epoch = self.head_tracker.finalized_epoch,
            .head_root = self.head_tracker.head_root,
            .head_slot = self.head_tracker.head_slot,
        };
    }

    // -----------------------------------------------------------------------
    // Block production
    // -----------------------------------------------------------------------

    /// Produce a block body from the operation pool.
    pub fn produceBlock(self: *Chain, slot: u64) !ProducedBlockBody {
        return produceBlockBody(self.allocator, slot, self.op_pool);
    }

    // -----------------------------------------------------------------------
    // State archive
    // -----------------------------------------------------------------------

    /// Archive the post-epoch state to the cold store.
    pub fn archiveState(self: *Chain, slot: u64, state_root: [32]u8) !void {
        const cached = self.block_state_cache.get(state_root) orelse return;
        const bytes = try cached.state.serialize(self.allocator);
        defer self.allocator.free(bytes);
        try self.db.putStateArchive(slot, state_root, bytes);
    }

    /// Store a blob sidecar received via gossip or req/resp.
    pub fn importBlobSidecar(self: *Chain, root: [32]u8, data: []const u8) !void {
        try self.db.putBlobSidecars(root, data);
    }

    /// Advance the head state by one empty slot (no block).
    ///
    /// Used for testing skip slots.
    pub fn advanceSlot(self: *Chain, target_slot: u64) !void {
        const head_state_root = self.head_tracker.head_state_root;
        const pre_state = self.block_state_cache.get(head_state_root) orelse
            return error.NoHeadState;

        const post_state = try pre_state.clone(self.allocator, .{ .transfer_cache = false });
        errdefer {
            post_state.deinit();
            self.allocator.destroy(post_state);
        }

        try state_transition.processSlots(self.allocator, post_state, target_slot, .{});
        try post_state.state.commit();

        const new_state_root = if (self.queued_regen) |qr| try qr.onNewBlock(post_state, true) else try self.state_regen.onNewBlock(post_state, true);

        try self.block_to_state.put(
            self.head_tracker.head_root,
            new_state_root,
        );

        self.head_tracker.head_state_root = new_state_root;
        self.head_tracker.head_slot = target_slot;

        try self.head_tracker.slot_roots.put(target_slot, self.head_tracker.head_root);
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn getStateByBlockRoot(self: *Chain, block_root: [32]u8) ?*CachedBeaconState {
        const state_root = self.block_to_state.get(block_root) orelse return null;
        return self.block_state_cache.get(state_root);
    }

    const StfnResult = struct {
        post_state: *CachedBeaconState,
        state_root: [32]u8,
        block_root: [32]u8,
    };

    fn runStateTransition(
        self: *Chain,
        pre_state: *CachedBeaconState,
        signed_block: *const consensus_types.electra.SignedBeaconBlock.Type,
        block_slot: u64,
    ) !StfnResult {
        const post_state = try pre_state.clone(self.allocator, .{ .transfer_cache = false });
        errdefer {
            post_state.deinit();
            self.allocator.destroy(post_state);
        }

        try state_transition.processSlots(self.allocator, post_state, block_slot, .{});

        const any_signed = AnySignedBeaconBlock{ .full_electra = @constCast(signed_block) };
        const block = any_signed.beaconBlock();

        switch (post_state.state.forkSeq()) {
            inline else => |f| {
                switch (block.blockType()) {
                    inline else => |bt| {
                        if (comptime bt == .blinded and f.lt(.bellatrix)) {
                            return error.InvalidBlockTypeForFork;
                        }
                        // Use batch verification when signatures are enabled for ~3-10x speedup.
                        // Collect all signature sets during processBlock, then verify in one shot.
                        var batch = BatchVerifier.init(null);
                        const opts = state_transition.ProcessBlockOpts{
                            .verify_signature = self.verify_signatures,
                            .batch_verifier = if (self.verify_signatures) &batch else null,
                        };
                        try state_transition.processBlock(
                            f,
                            self.allocator,
                            post_state.config,
                            post_state.epoch_cache,
                            post_state.state.castToFork(f),
                            &post_state.slashings_cache,
                            bt,
                            block.castToFork(bt, f),
                            .{
                                .execution_payload_status = .valid,
                                .data_availability_status = .available,
                            },
                            opts,
                        );
                        // Batch-verify all collected signatures
                        if (self.verify_signatures and batch.len() > 0) {
                            const valid = batch.verifyAll() catch false;
                            if (!valid) return error.InvalidBatchSignature;
                        }
                    },
                }
            },
        }

        try post_state.state.commit();
        const state_root = (try post_state.state.hashTreeRoot()).*;

        if (!std.mem.eql(u8, &state_root, &signed_block.message.state_root)) {
            std.log.warn("STFN state_root mismatch at slot {d}: ours={s}... block={s}...", .{
                block_slot,
                &std.fmt.bytesToHex(state_root[0..8], .lower),
                &std.fmt.bytesToHex(signed_block.message.state_root[0..8], .lower),
            });
        } else {
            std.log.info("STFN state_root MATCHES at slot {d}", .{block_slot});
        }

        var br_body_root: [32]u8 = undefined;
        try consensus_types.electra.BeaconBlockBody.hashTreeRoot(self.allocator, &signed_block.message.body, &br_body_root);
        const hdr = consensus_types.phase0.BeaconBlockHeader.Type{
            .slot = block_slot,
            .proposer_index = signed_block.message.proposer_index,
            .parent_root = signed_block.message.parent_root,
            .state_root = signed_block.message.state_root,
            .body_root = br_body_root,
        };
        var computed_block_root: [32]u8 = undefined;
        try consensus_types.phase0.BeaconBlockHeader.hashTreeRoot(&hdr, &computed_block_root);

        return .{
            .post_state = post_state,
            .state_root = state_root,
            .block_root = computed_block_root,
        };
    }
};
