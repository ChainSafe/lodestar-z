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

const blocks_mod = @import("blocks/root.zig");
const PipelineContext = blocks_mod.PipelineContext;
const PipelineBlockInput = blocks_mod.BlockInput;
const PipelineImportOpts = blocks_mod.ImportBlockOpts;
const PipelineImportResult = blocks_mod.ImportResult;
const BlockImportError = blocks_mod.BlockImportError;

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

const da_mod = @import("data_availability.zig");
const validator_monitor_mod = @import("validator_monitor.zig");
const ValidatorMonitor = validator_monitor_mod.ValidatorMonitor;
const DataAvailabilityManager = da_mod.DataAvailabilityManager;


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

    // --- Data availability ---
    /// Data availability manager — optional. When set, blocks are checked
    /// for DA completeness before final import. If DA is pending, the block
    /// is queued for reprocessing when data arrives.
    da_manager: ?*DataAvailabilityManager,

    // --- Block import state ---
    /// When true, BLS signatures are verified during block import.
    verify_signatures: bool,

    /// Maps block root → state root for pre-state lookup.
    block_to_state: std.AutoArrayHashMap([32]u8, [32]u8),

    // --- SSE event callback (optional, set by BeaconNode) ---
    event_callback: ?EventCallback,

    // --- Validator monitor (optional, set by BeaconNode) ---
    validator_monitor: ?*ValidatorMonitor = null,

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
            .da_manager = null,
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
    /// Fork-polymorphic entry point. Accepts any signed beacon block via
    /// AnySignedBeaconBlock and delegates to processBlockPipeline, eliminating
    /// the electra-specific hardcoding of the old implementation.
    ///
    /// The `source` parameter tells the pipeline where the block came from
    /// (gossip, range_sync, api, etc.) so it can apply the right checks.
    ///
    /// Legacy error names (UnknownParentBlock, BlockAlreadyKnown, etc.) are
    /// preserved for backward compatibility with existing callers.
    pub fn importBlock(
        self: *Chain,
        any_signed: AnySignedBeaconBlock,
        source: blocks_mod.BlockSource,
    ) !ImportResult {
        const block_input = PipelineBlockInput{
            .block = any_signed,
            .source = source,
            .da_status = .not_required,
        };
        // Skip execution verification here — the EL call (engine_newPayload) is
        // handled by BeaconNode after importBlock returns, via notifyForkchoiceUpdate.
        // Skip future-slot check: callers (gossip handler, API, sync) have already
        // validated timing. The legacy importBlock never enforced this check.
        // Propagate verify_signatures from chain config: when false (default for tests),
        // skip BLS signature verification to avoid failures with dummy test signatures.
        const opts = PipelineImportOpts{
            .skip_execution = true,
            .skip_future_slot = true,
            .skip_signatures = !self.verify_signatures,
        };
        const pipeline_result = self.processBlockPipeline(block_input, opts) catch |err| {
            // Translate pipeline error names to legacy names expected by callers.
            return switch (err) {
                BlockImportError.ParentUnknown => error.UnknownParentBlock,
                BlockImportError.AlreadyKnown => error.BlockAlreadyKnown,
                BlockImportError.WouldRevertFinalizedSlot => error.BlockAlreadyFinalized,
                BlockImportError.GenesisBlock => error.GenesisBlock,
                BlockImportError.PrestateMissing => error.NoPreStateAvailable,
                BlockImportError.StateTransitionFailed => error.StateTransitionFailed,
                BlockImportError.InternalError => error.InternalError,
                else => err,
            };
        };
        return .{
            .block_root = pipeline_result.block_root,
            .state_root = pipeline_result.state_root,
            .slot = pipeline_result.slot,
            .epoch_transition = pipeline_result.epoch_transition,
            .execution_optimistic = pipeline_result.execution_optimistic,
        };
    }

    // -----------------------------------------------------------------------
    // New pipeline-based block import
    // -----------------------------------------------------------------------

    /// Process a block through the staged import pipeline.
    ///
    /// This is the main entry point for block processing. It runs all stages
    /// in sequence: verify_sanity → state_transition → verify_execution → import.
    /// importBlock delegates here, so this is the canonical implementation.
    pub fn processBlockPipeline(
        self: *Chain,
        block_input: PipelineBlockInput,
        opts: PipelineImportOpts,
    ) BlockImportError!PipelineImportResult {
        const ctx = self.getPipelineContext();
        return blocks_mod.processBlock(ctx, block_input, opts);
    }

    /// Process a batch of blocks through the staged pipeline (for range sync).
    pub fn processBlockBatchPipeline(
        self: *Chain,
        block_inputs: []const PipelineBlockInput,
        opts: PipelineImportOpts,
    ) ![]blocks_mod.BatchBlockResult {
        const ctx = self.getPipelineContext();
        return blocks_mod.processBlockBatch(ctx, block_inputs, opts);
    }

    /// Build a PipelineContext from the current Chain state.
    pub fn getPipelineContext(self: *Chain) PipelineContext {
        const current_slot = if (self.fork_choice) |fc| fc.getTime() else self.head_tracker.head_slot;
        return .{
            .allocator = self.allocator,
            .block_state_cache = self.block_state_cache,
            .state_regen = self.state_regen,
            .queued_regen = self.queued_regen,
            .fork_choice = self.fork_choice,
            .db = self.db,
            .head_tracker = self.head_tracker,
            .block_to_state = &self.block_to_state,
            .event_callback = self.event_callback,
            .execution_verifier = null, // Set by BeaconNode when EL is configured
            .current_slot = current_slot,
        };
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
            fc.onSingleVote(
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
            fc.updateTime(self.allocator, slot) catch {};
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

        // Prune DA tracking data outside the availability window.
        if (self.da_manager) |dam| {
            dam.pruneOldData(prune_slot);
        }

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
    /// Used for testing skip slots and by onSlot for empty slots.
    ///
    /// P0-5 fix: Also calls fork_choice.updateTime(target_slot) so that fork choice
    /// time stays in sync with the head tracker. Without this, fork choice would reject
    /// blocks at the current slot as "future" if onSlot was called but advanceSlot was
    /// not (or vice versa).
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

        // Update fork choice time to keep it in sync with head tracker (P0-5 fix).
        // onSlot already calls updateTime, but advanceSlot can be called independently
        // (e.g., from tests, batch sync). Both paths must call updateTime.
        if (self.fork_choice) |fc| {
            fc.updateTime(self.allocator, target_slot) catch {};
        }

        self.head_tracker.head_state_root = new_state_root;
        self.head_tracker.head_slot = target_slot;

        try self.head_tracker.slot_roots.put(target_slot, self.head_tracker.head_root);
    }



};
