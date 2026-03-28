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
const log_mod = @import("log");

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
const assembleBlock = produce_block_mod.assembleBlock;
const BlockProductionConfig = produce_block_mod.BlockProductionConfig;
const ProducedBlock = produce_block_mod.ProducedBlock;

const fork_choice_mod = @import("fork_choice");
const ForkChoice = fork_choice_mod.ForkChoiceStruct;
const ProtoBlock = fork_choice_mod.ProtoBlock;

const networking = @import("networking");
const StatusMessage = networking.messages.StatusMessage;

const chain_types = @import("types.zig");
const gossip_validation_mod = @import("gossip_validation.zig");
const ChainGossipState = gossip_validation_mod.ChainState;
pub const ImportResult = chain_types.ImportResult;
pub const HeadInfo = chain_types.HeadInfo;
pub const SyncStatus = chain_types.SyncStatus;
pub const EventCallback = chain_types.EventCallback;
pub const SseEvent = chain_types.SseEvent;

const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const sync_contribution_pool_mod = @import("sync_contribution_pool.zig");
const SyncContributionAndProofPool = sync_contribution_pool_mod.SyncContributionAndProofPool;

const da_mod = @import("data_availability.zig");
const validator_monitor_mod = @import("validator_monitor.zig");
const ValidatorMonitor = validator_monitor_mod.ValidatorMonitor;
const DataAvailabilityManager = da_mod.DataAvailabilityManager;
const reprocess_mod = @import("reprocess.zig");
const ReprocessQueue = reprocess_mod.ReprocessQueue;


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

    // --- Reprocessing --- (P1-10 fix)
    /// Reprocess queue — optional. When set, blocks that fail with ParentUnknown
    /// are queued here keyed by their parent_root. When the parent arrives,
    /// onBlockImported() releases the queued children for reprocessing.
    reprocess_queue: ?*ReprocessQueue,

    // --- Sync contribution pool --- (P1-11 fix)
    /// SyncContributionAndProofPool — optional. When set, block production
    /// (assembleBlock) pulls best sync contributions from here to include
    /// in the block's sync_aggregate field.
    sync_contribution_pool: ?*SyncContributionAndProofPool,

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
    /// Genesis time in seconds since the Unix epoch. Used to compute
    /// the wall-clock slot for sync distance calculation. Set during
    /// initFromGenesis / initFromCheckpoint; zero until genesis is known.
    genesis_time_s: u64,

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
            .reprocess_queue = null,
            .sync_contribution_pool = null,
            .verify_signatures = false,
            .block_to_state = std.AutoArrayHashMap([32]u8, [32]u8).init(allocator),
            .event_callback = null,
            .genesis_validators_root = [_]u8{0} ** 32,
            .genesis_time_s = 0,
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

    /// Finality callback shim — called from import_block.zig when a new
    /// finalized epoch is detected.  Signature must match ImportContext.on_finalized_fn.
    fn onFinalizedCallback(ptr: *anyopaque, finalized_epoch: u64, finalized_root: [32]u8) void {
        const chain: *Chain = @ptrCast(@alignCast(ptr));
        chain.onFinalized(finalized_epoch, finalized_root);
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
            .reprocess_queue = self.reprocess_queue, // P1-10: wire reprocess queue
            .on_finalized_ptr = @ptrCast(self), // W2: prune caches on finalization
            .on_finalized_fn = &Chain.onFinalizedCallback,
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
                log_mod.logger(.chain).warn("FC onAttestation failed for validator {d} slot {d}: {}", .{
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

        // Prune aggregators at epoch boundaries.
        // The seen_aggregators map is keyed by (validator_index, epoch) so it grows
        // each epoch. Clear it at the start of each new epoch to bound memory.
        if (slot > 0 and slot % preset.SLOTS_PER_EPOCH == 0) {
            self.seen_cache.pruneAggregators();
        }

        // Prune op_pool attestations — keeps only current + previous epoch.
        // AggregatedAttestationPool and AttestationPool grow with every incoming
        // attestation and have no self-eviction; pruneBySlot / prune must be
        // called every slot to bound memory.
        self.op_pool.agg_attestation_pool.pruneBySlot(slot);
        self.op_pool.attestation_pool.prune(slot);
    }

    // -----------------------------------------------------------------------
    // Finalization handler
    // -----------------------------------------------------------------------

    /// Called when a new finalized checkpoint is detected.
    ///
    /// Prunes caches to free memory from pre-finalization data,
    /// prunes the fork choice DAG, and emits SSE finalized_checkpoint event.
    pub fn onFinalized(self: *Chain, finalized_epoch: u64, finalized_root: [32]u8) void {
        log_mod.logger(.chain).info("onFinalized: epoch={d} root={s}...", .{
            finalized_epoch,
            &std.fmt.bytesToHex(finalized_root[0..4], .lower),
        });

        // Prune block state cache — evict states older than finalized epoch.
        self.block_state_cache.pruneBeforeEpoch(finalized_epoch);

        // Prune checkpoint state cache — remove checkpoints below finalized epoch.
        self.checkpoint_state_cache.pruneFinalized(finalized_epoch) catch |err| {
            log_mod.logger(.chain).warn("onFinalized: checkpoint cache prune failed: {}", .{err});
        };

        // Prune fork choice DAG — remove nodes below finalized root.
        if (self.fork_choice) |fc| {
            _ = fc.prune(self.allocator, finalized_root) catch |err| {
                log_mod.logger(.chain).warn("onFinalized: fork choice prune failed: {}", .{err});
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

        // Prune slot_roots in HeadTracker — remove entries for pre-finalized slots.
        // This prevents the slot→root map from growing unboundedly over time.
        const finalized_slot = finalized_epoch * preset.SLOTS_PER_EPOCH;
        self.head_tracker.pruneBelow(finalized_slot);

        // Prune block_to_state — remove entries for blocks that are now finalized.
        // We use the pruned slot_roots as a guide: any root no longer in slot_roots
        // that is below the finalized slot can be removed. Since pruneBelow already
        // evicted pre-finalized entries from slot_roots, we iterate block_to_state
        // and remove roots that are no longer tracked by slot_roots (i.e., pre-fin).
        {
            var roots_to_remove = std.ArrayList([32]u8).init(self.allocator);
            defer roots_to_remove.deinit();

            // Collect all roots in block_to_state that are not the finalized root
            // and are not referenced by any remaining slot_roots entry.
            var b2s_it = self.block_to_state.iterator();
            while (b2s_it.next()) |entry| {
                const root = entry.key_ptr.*;
                // Never evict the finalized root itself — needed for SSE event above.
                if (std.mem.eql(u8, &root, &finalized_root)) continue;
                // Keep entries still referenced by slot_roots (post-finalization blocks).
                var found = false;
                var sr_it = self.head_tracker.slot_roots.iterator();
                while (sr_it.next()) |sr_entry| {
                    if (std.mem.eql(u8, sr_entry.value_ptr, &root)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    roots_to_remove.append(root) catch {};
                }
            }
            for (roots_to_remove.items) |root| {
                _ = self.block_to_state.swapRemove(root);
            }
        }

        // Prune SeenCache sub-maps on finalization — these dedup caches are not
        // authoritative, so clearing them on finalization is safe and prevents OOM.
        self.seen_cache.pruneOnFinalization();

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

    /// Threshold: if head is more than this many slots behind the wall-clock
    /// slot, we report is_syncing = true.
    const SYNC_DISTANCE_THRESHOLD: u64 = 32;

    /// Get current sync status.
    ///
    /// Computes sync_distance by comparing the head slot to the wall-clock slot
    /// derived from the genesis time. Reports is_syncing when the distance
    /// exceeds SYNC_DISTANCE_THRESHOLD slots.
    pub fn getSyncStatus(self: *const Chain) SyncStatus {
        const head_slot = if (self.fork_choice) |fc| fc.head.slot else self.head_tracker.head_slot;

        // Compute wall-clock slot from genesis_time_s.
        // Falls back to head_slot (distance = 0) when genesis is not yet known.
        const wall_slot: u64 = blk: {
            const gt = self.genesis_time_s;
            if (gt == 0) break :blk head_slot;
            const sps = self.config.chain.SECONDS_PER_SLOT;
            if (sps == 0) break :blk head_slot;
            const now_s: u64 = @intCast(@max(0, std.time.timestamp()));
            if (now_s < gt) break :blk head_slot;
            break :blk (now_s - gt) / sps;
        };

        const sync_distance = if (wall_slot > head_slot) wall_slot - head_slot else 0;
        return .{
            .head_slot = head_slot,
            .sync_distance = sync_distance,
            .is_syncing = sync_distance > SYNC_DISTANCE_THRESHOLD,
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
            else if (self.fork_choice) |fc|
                // Use fork choice's authoritative finalized checkpoint root.
                // Avoid slot_roots lookup which may miss skip slots.
                fc.getFinalizedCheckpoint().root
            else if (self.head_tracker.getBlockRoot(
                self.head_tracker.finalized_epoch * preset.SLOTS_PER_EPOCH,
            )) |r| r else [_]u8{0} ** 32,
            .finalized_epoch = self.head_tracker.finalized_epoch,
            .head_root = self.head_tracker.head_root,
            .head_slot = self.head_tracker.head_slot,
        };
    }

    // -----------------------------------------------------------------------
    // Gossip validation interface (P1-12 fix)
    // -----------------------------------------------------------------------

    /// Build a ChainGossipState snapshot for gossip validation.
    ///
    /// The gossip validator needs a consistent snapshot of chain state to run
    /// validations (proposer index, known blocks, validator count). This provides
    /// the wiring between the gossip_validation.zig ChainState interface and the
    /// actual Chain internals.
    ///
    /// USAGE:
    ///   const gs = chain.makeGossipState();
    ///   const action = gossip_validation.validateGossipBlock(slot, proposer, parent, root, &gs);
    ///
    /// NOTE: The function pointers in ChainGossipState reference `self` via a
    /// captured pointer approach. Since ChainGossipState contains only function
    /// pointer fields and data fields (no allocations), callers must ensure Chain
    /// outlives the returned ChainGossipState.
    pub fn makeGossipState(self: *const Chain) ChainGossipState {
        const current_slot = if (self.fork_choice) |fc| fc.getTime() else self.head_tracker.head_slot;
        const finalized_epoch = if (self.fork_choice) |fc|
            fc.getFinalizedCheckpoint().epoch
        else
            self.head_tracker.finalized_epoch;

        // Callbacks wired to real Chain state — ChainGossipState requires *anyopaque
        // first param matching the ptr: *anyopaque field signature in gossip_validation.zig.
        const Callbacks = struct {
            /// Returns the expected block proposer for `slot` from the head state's epoch cache.
            /// Returns null on cache miss (gossip validator falls back gracefully).
            fn getProposerIndex(_ptr: *anyopaque, _slot: u64) ?u32 {
                const self_: *const Chain = @ptrCast(@alignCast(_ptr));
                const head_state_root = self_.head_tracker.head_state_root;
                const cached = self_.block_state_cache.get(head_state_root) orelse return null;
                const proposer = cached.getBeaconProposer(_slot) catch return null;
                return @intCast(proposer);
            }
            /// Returns true if `root` is tracked in fork choice.
            fn isKnownBlockRoot(_ptr: *anyopaque, root: [32]u8) bool {
                const self_: *const Chain = @ptrCast(@alignCast(_ptr));
                if (self_.fork_choice) |fc| {
                    return fc.hasBlock(root);
                }
                return self_.block_to_state.contains(root);
            }
            /// Returns the total validator count from the head state's epoch cache.
            /// Returns 0 if head state is unavailable (gossip validator skips bounds check).
            fn getValidatorCount(_ptr: *anyopaque) u32 {
                const self_: *const Chain = @ptrCast(@alignCast(_ptr));
                const head_state_root = self_.head_tracker.head_state_root;
                const cached = self_.block_state_cache.get(head_state_root) orelse return 0;
                return @intCast(cached.epoch_cache.index_to_pubkey.items.len);
            }
        };

        return .{
            .ptr = @ptrCast(@constCast(self)),
            .current_slot = current_slot,
            .current_epoch = computeEpochAtSlot(current_slot),
            .finalized_slot = finalized_epoch * preset.SLOTS_PER_EPOCH,
            .seen_cache = self.seen_cache,
            .getProposerIndex = Callbacks.getProposerIndex,
            .isKnownBlockRoot = Callbacks.isKnownBlockRoot,
            .getValidatorCount = Callbacks.getValidatorCount,
        };
    }

    // -----------------------------------------------------------------------
    // Block production
    // -----------------------------------------------------------------------

    /// Produce a block body from the operation pool.
    pub fn produceBlock(self: *Chain, slot: u64) !ProducedBlockBody {
        return produceBlockBody(self.allocator, slot, self.op_pool);
    }

    /// Produce a full block (Electra BeaconBlockBody + blobs bundle).
    ///
    /// Includes sync contributions from the SyncContributionAndProofPool (P1-11 fix).
    /// When sync_contribution_pool is null, the sync_aggregate is empty (all-zero).
    pub fn produceFullBlock(
        self: *Chain,
        slot: u64,
        config: BlockProductionConfig,
    ) !ProducedBlock {
        return assembleBlock(
            self.allocator,
            slot,
            self.op_pool,
            config,
            self.sync_contribution_pool, // P1-11: wire sync contribution pool
        );
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
