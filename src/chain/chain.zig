//! Chain — coordinates the chain runtime state and exposes pipeline functions.
//!
//! This is the central coordinator for beacon chain state. It holds
//! pointers to all chain components (fork choice, caches, DB, pools)
//! and exposes the core pipeline functions:
//!
//! - `importBlock` — full block import pipeline (sanity → STFN → FC → persist)
//! - `importAttestation` — FC vote update → pool insertion
//! - `onSlot` — FC time update, seen cache prune
//! - `onFinalized` — archive and prune finalized history
//! - `getHead` — current head info
//! - `getStatus` — P2P status message
//!
//! The Chain does not own the backing memory for its components. That graph is
//! owned by `chain.Runtime`, which keeps `Chain` as the coordinator over a
//! separately managed runtime.

const std = @import("std");
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.chain);

const consensus_types = @import("consensus_types");
const preset = @import("preset").preset;
const fork_types = @import("fork_types");
const AnyIndexedAttestation = fork_types.AnyIndexedAttestation;
const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const state_transition = @import("state_transition");
const regen_mod = @import("regen/root.zig");
const BlsThreadPool = @import("bls").ThreadPool;
const CachedBeaconState = state_transition.CachedBeaconState;
const BlockStateCache = regen_mod.BlockStateCache;
const CheckpointStateCache = regen_mod.CheckpointStateCache;
const StateGraphGate = regen_mod.StateGraphGate;
const StateRegen = regen_mod.StateRegen;
const QueuedStateRegen = regen_mod.QueuedStateRegen;
const state_work_service_mod = @import("state_work_service.zig");
const StateWorkService = state_work_service_mod.StateWorkService;
const CompletedBlockImport = state_work_service_mod.CompletedBlockImport;
const RegenPriority = regen_mod.RegenPriority;
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const db_mod = @import("db");
const BeaconDB = db_mod.BeaconDB;

const HeadTracker = @import("block_import.zig").HeadTracker;

const blocks_mod = @import("blocks/root.zig");
const PipelineContext = blocks_mod.PipelineContext;
const PipelineBlockInput = blocks_mod.BlockInput;
const PipelineImportOpts = blocks_mod.ImportBlockOpts;
const PipelineImportResult = blocks_mod.ImportResult;
const BlockImportError = blocks_mod.BlockImportError;
const ExecutionPort = @import("ports/execution.zig").ExecutionPort;

const op_pool_mod = @import("op_pool.zig");
const OpPool = op_pool_mod.OpPool;
const seen_cache_mod = @import("seen_cache.zig");
const SeenCache = seen_cache_mod.SeenCache;
const SeenAttesters = @import("seen_attesters.zig").SeenAttesters;
const SeenEpochValidators = @import("seen_epoch_validators.zig").SeenEpochValidators;
const SeenAttestationData = @import("seen_attestation_data.zig").SeenAttestationData;
const produce_block_mod = @import("produce_block.zig");
const ProducedBlockBody = produce_block_mod.ProducedBlockBody;
const produceBlockBody = produce_block_mod.produceBlockBody;
const assembleBlock = produce_block_mod.assembleBlock;
const BlockProductionConfig = produce_block_mod.BlockProductionConfig;
const ProducedBlock = produce_block_mod.ProducedBlock;
const BeaconProposerCache = @import("beacon_proposer_cache.zig").BeaconProposerCache;

const fork_choice_mod = @import("fork_choice");
const ForkChoice = fork_choice_mod.ForkChoiceStruct;
const ProtoBlock = fork_choice_mod.ProtoBlock;
const CheckpointWithPayloadStatus = fork_choice_mod.CheckpointWithPayloadStatus;

const networking = @import("networking");
const StatusMessage = networking.messages.StatusMessage;

const chain_types = @import("types.zig");
const gossip_validation_mod = @import("gossip_validation.zig");
const ChainGossipState = gossip_validation_mod.ChainState;
pub const ImportResult = blocks_mod.ImportResult;
pub const HeadInfo = chain_types.HeadInfo;
pub const SyncStatus = chain_types.SyncStatus;
pub const NotificationSink = chain_types.NotificationSink;
pub const ChainNotification = chain_types.ChainNotification;

/// Pending attachment ingress is driven by slot ticks, not per-message timers.
/// Keep the current and previous slot so late-but-still-reasonable sidecars can
/// complete a block, while bounding memory if the attachments never arrive.
const PENDING_INGRESS_RETENTION_SLOTS: u64 = 1;

const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const sync_contribution_pool_mod = @import("sync_contribution_pool.zig");
const SyncContributionAndProofPool = sync_contribution_pool_mod.SyncContributionAndProofPool;
const SyncCommitteeMessagePool = sync_contribution_pool_mod.SyncCommitteeMessagePool;

const da_mod = @import("data_availability.zig");
const validator_monitor_mod = @import("validator_monitor.zig");
const ValidatorMonitor = validator_monitor_mod.ValidatorMonitor;
const DataAvailabilityManager = da_mod.DataAvailabilityManager;
const ArchiveStore = @import("archive_store.zig").ArchiveStore;
const FinalizationPlan = @import("finalization_plan.zig").FinalizationPlan;
const reprocess_mod = @import("reprocess.zig");
const ReprocessQueue = reprocess_mod.ReprocessQueue;
const pending_block_ingress_mod = @import("block_ingress.zig");
const PendingBlockIngress = pending_block_ingress_mod.PendingBlockIngress;
const payload_envelope_ingress_mod = @import("payload_envelope_ingress.zig");
const PayloadEnvelopeIngress = payload_envelope_ingress_mod.PayloadEnvelopeIngress;
const kzg_mod = @import("kzg");
const Kzg = kzg_mod.Kzg;

fn unixTimestampSeconds() u64 {
    var ts: std.posix.timespec = undefined;
    switch (std.posix.errno(std.posix.system.clock_gettime(.REALTIME, &ts))) {
        .SUCCESS => return if (ts.sec >= 0) @intCast(ts.sec) else 0,
        else => return 0,
    }
}

fn emptyJustifiedBalancesGetterFn(
    _: ?*anyopaque,
    _: CheckpointWithPayloadStatus,
    _: *CachedBeaconState,
) fork_choice_mod.JustifiedBalances {
    return fork_choice_mod.JustifiedBalances.init(std.heap.page_allocator);
}

// ---------------------------------------------------------------------------
// Chain
// ---------------------------------------------------------------------------

pub const Chain = struct {
    const BootstrapResult = struct {
        fork_choice: *ForkChoice,
        genesis_time: u64,
        genesis_validators_root: [32]u8,
        earliest_available_slot: u64,
    };

    allocator: Allocator,
    config: *const BeaconConfig,

    // --- State components (not owned, pointers from BeaconNode) ---
    block_state_cache: *BlockStateCache,
    checkpoint_state_cache: *CheckpointStateCache,
    state_regen: *StateRegen,
    state_graph_gate: *StateGraphGate,
    queued_regen: *QueuedStateRegen,
    state_work_service: *StateWorkService,
    head_tracker: *HeadTracker,
    db: *BeaconDB,
    op_pool: *OpPool,
    seen_cache: *SeenCache,
    seen_attesters: *SeenAttesters,
    seen_block_attesters: *SeenEpochValidators,
    seen_block_proposers: *SeenEpochValidators,
    attestation_data_cache: *SeenAttestationData,
    beacon_proposer_cache: *BeaconProposerCache,

    // --- Data availability ---
    /// Data availability manager — optional. When set, blocks are checked
    /// for DA completeness before final import. If DA is pending, the block
    /// is queued for reprocessing when data arrives.
    da_manager: ?*DataAvailabilityManager,
    /// Finalized-history archival subsystem. Owned by chain.Runtime.
    archive_store: ?*ArchiveStore,
    /// Pending block ingress whose required attachments are incomplete.
    pending_block_ingress: ?*PendingBlockIngress,
    /// Pending second-stage payload-envelope ingress for separated payload forks.
    payload_envelope_ingress: ?*PayloadEnvelopeIngress,

    /// Shared KZG context for blob / column verification.
    /// Owned by chain.Runtime.
    kzg: ?*const Kzg,

    // --- Reprocessing --- (P1-10 fix)
    // --- Sync contribution pool --- (P1-11 fix)
    /// SyncContributionAndProofPool — optional. When set, block production
    /// (assembleBlock) pulls best sync contributions from here to include
    /// in the block's sync_aggregate field.
    sync_contribution_pool: ?*SyncContributionAndProofPool,

    /// SyncCommitteeMessagePool — optional. Stores unaggregated sync committee
    /// messages so aggregators can construct contributions.
    sync_committee_message_pool: ?*SyncCommitteeMessagePool,

    // --- Block import state ---
    /// When true, BLS signatures are verified during block import.
    verify_signatures: bool,
    /// Shared BLS worker pool used by the block STF batch verifier.
    block_bls_thread_pool: ?*BlsThreadPool = null,
    /// Maps block root → state root for pre-state lookup.
    block_to_state: std.array_hash_map.Auto([32]u8, [32]u8),

    // --- Genesis info ---
    genesis_validators_root: [32]u8,
    /// Genesis time in seconds since the Unix epoch. Used to compute
    /// the wall-clock slot for sync distance calculation. Set during
    /// initFromGenesis / initFromCheckpoint; zero until genesis is known.
    genesis_time_s: u64,
    fork_choice_storage: ?*ForkChoice = null,
    execution_port: ?ExecutionPort = null,
    notification_sink: ?NotificationSink = null,
    validator_monitor: ?*ValidatorMonitor = null,
    reprocess_queue: ?*ReprocessQueue = null,

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
        state_graph_gate: *StateGraphGate,
        queued_regen: *QueuedStateRegen,
        state_work_service: *StateWorkService,
        head_tracker: *HeadTracker,
        db: *BeaconDB,
        op_pool: *OpPool,
        seen_cache: *SeenCache,
        seen_attesters: *SeenAttesters,
        seen_block_attesters: *SeenEpochValidators,
        seen_block_proposers: *SeenEpochValidators,
        attestation_data_cache: *SeenAttestationData,
        beacon_proposer_cache: *BeaconProposerCache,
    ) Chain {
        return .{
            .allocator = allocator,
            .config = config,
            .block_state_cache = block_state_cache,
            .checkpoint_state_cache = checkpoint_state_cache,
            .state_regen = state_regen,
            .state_graph_gate = state_graph_gate,
            .queued_regen = queued_regen,
            .state_work_service = state_work_service,
            .head_tracker = head_tracker,
            .db = db,
            .op_pool = op_pool,
            .seen_cache = seen_cache,
            .seen_attesters = seen_attesters,
            .seen_block_attesters = seen_block_attesters,
            .seen_block_proposers = seen_block_proposers,
            .attestation_data_cache = attestation_data_cache,
            .beacon_proposer_cache = beacon_proposer_cache,
            .da_manager = null,
            .archive_store = null,
            .pending_block_ingress = null,
            .payload_envelope_ingress = null,
            .kzg = null,
            .sync_contribution_pool = null,
            .sync_committee_message_pool = null,
            .verify_signatures = false,
            .block_bls_thread_pool = null,
            .block_to_state = .empty,
            .genesis_validators_root = [_]u8{0} ** 32,
            .genesis_time_s = 0,
        };
    }

    pub fn deinit(self: *Chain) void {
        self.destroyForkChoice();
        self.replaceValidatorMonitor(&.{}) catch @panic("validator monitor deinit failed");
        self.block_to_state.deinit(self.allocator);
    }

    fn destroyForkChoice(self: *Chain) void {
        if (self.fork_choice_storage) |fc| {
            self.state_regen.clearForkChoice();
            fork_choice_mod.destroyFromAnchor(self.allocator, fc);
        }
        self.fork_choice_storage = null;
    }

    pub fn installForkChoice(self: *Chain, fork_choice: *ForkChoice) !void {
        if (self.fork_choice_storage != null) return error.ForkChoiceAlreadyInstalled;
        self.fork_choice_storage = fork_choice;
        self.state_regen.setForkChoice(fork_choice);
    }

    pub fn forkChoice(self: *const Chain) *ForkChoice {
        return self.fork_choice_storage orelse @panic("Chain used before fork choice bootstrap");
    }

    pub fn replaceValidatorMonitor(self: *Chain, indices: []const u64) !void {
        if (self.validator_monitor) |vm| {
            vm.deinit();
            self.allocator.destroy(vm);
            self.validator_monitor = null;
        }

        if (indices.len == 0) return;

        const vm = try self.allocator.create(ValidatorMonitor);
        errdefer self.allocator.destroy(vm);
        vm.* = ValidatorMonitor.init(self.allocator, indices);
        self.validator_monitor = vm;
    }

    pub fn setExecutionPort(self: *Chain, port: ?ExecutionPort) void {
        self.execution_port = port;
    }

    pub fn setNotificationSink(self: *Chain, sink: ?NotificationSink) void {
        self.notification_sink = sink;
    }

    pub fn setReprocessQueue(self: *Chain, queue: ?*ReprocessQueue) void {
        self.reprocess_queue = queue;
    }

    pub fn onTrackedBlock(self: *Chain, block_root: [32]u8, slot: u64, state_root: [32]u8) !void {
        try self.head_tracker.onBlock(block_root, slot, state_root);
    }

    pub fn setTrackedHead(self: *Chain, block_root: [32]u8, slot: u64, state_root: [32]u8) void {
        self.head_tracker.setHead(block_root, slot, state_root);
    }

    pub fn onEpochTransition(self: *Chain, state: *CachedBeaconState) !void {
        try self.head_tracker.onEpochTransition(state);
    }

    pub fn headInfo(self: *const Chain) HeadInfo {
        const fc = self.forkChoice();
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

    pub fn trackerHeadInfo(self: *const Chain) HeadInfo {
        return .{
            .slot = self.head_tracker.head_slot,
            .root = self.head_tracker.head_root,
            .state_root = self.head_tracker.head_state_root,
            .finalized_epoch = self.head_tracker.finalized_epoch,
            .justified_epoch = self.head_tracker.justified_epoch,
        };
    }

    pub fn headRoot(self: *const Chain) [32]u8 {
        return self.head_tracker.head_root;
    }

    pub fn headStateRoot(self: *const Chain) [32]u8 {
        return self.head_tracker.head_state_root;
    }

    pub fn blockRootAtTrackedSlot(self: *const Chain, slot: u64) ?[32]u8 {
        return self.head_tracker.getBlockRoot(slot);
    }

    pub fn canonicalHotBlockRootAtSlot(self: *const Chain, slot: u64) !?[32]u8 {
        const head = self.headInfo();
        if (slot > head.slot) return null;
        if (slot == head.slot) return head.root;

        const ancestor = try self.forkChoice().getAncestor(head.root, slot);
        if (ancestor.slot != slot) return null;
        return ancestor.block_root;
    }

    pub fn hasTrackedBlockRoot(self: *const Chain, root: [32]u8) bool {
        var it = self.head_tracker.slot_roots.iterator();
        while (it.next()) |entry| {
            if (std.mem.eql(u8, entry.value_ptr, &root)) return true;
        }
        return false;
    }

    pub fn hasCanonicalBlock(self: *const Chain, root: [32]u8) bool {
        return self.forkChoice().hasBlock(root);
    }

    pub fn currentSlot(self: *const Chain) u64 {
        return self.forkChoice().getTime();
    }

    pub fn headSlot(self: *const Chain) u64 {
        return self.forkChoice().head.slot;
    }

    pub fn justifiedEpoch(self: *const Chain) u64 {
        return self.forkChoice().getJustifiedCheckpoint().epoch;
    }

    pub fn finalizedEpoch(self: *const Chain) u64 {
        return self.forkChoice().getFinalizedCheckpoint().epoch;
    }

    pub fn slotsPresent(self: *const Chain, window_start: u64) u32 {
        return self.forkChoice().getSlotsPresent(window_start);
    }

    pub fn executionForkchoiceState(
        self: *const Chain,
        head_root: [32]u8,
    ) ?chain_types.ForkchoiceUpdateState {
        const fc = self.forkChoice();

        const head_node = fc.getBlockDefaultStatus(head_root) orelse return null;
        const head_block_hash = head_node.extra_meta.executionPayloadBlockHash() orelse return null;

        const justified_cp = fc.getJustifiedCheckpoint();
        const safe_block_hash = if (fc.getBlockDefaultStatus(justified_cp.root)) |node|
            node.extra_meta.executionPayloadBlockHash() orelse std.mem.zeroes([32]u8)
        else
            std.mem.zeroes([32]u8);

        const finalized_cp = fc.getFinalizedCheckpoint();
        const finalized_block_hash = if (fc.getBlockDefaultStatus(finalized_cp.root)) |node|
            node.extra_meta.executionPayloadBlockHash() orelse std.mem.zeroes([32]u8)
        else
            std.mem.zeroes([32]u8);

        return .{
            .head_block_hash = head_block_hash,
            .safe_block_hash = safe_block_hash,
            .finalized_block_hash = finalized_block_hash,
        };
    }

    pub fn currentHeadExecutionOptimistic(self: *const Chain) bool {
        const fc = self.forkChoice();
        const head_node = fc.getBlockDefaultStatus(fc.head.block_root) orelse return false;
        return switch (head_node.extra_meta.executionStatus()) {
            .syncing, .payload_separated => true,
            else => false,
        };
    }

    pub fn blockExecutionOptimistic(self: *const Chain, block_root: [32]u8) bool {
        const fc = self.forkChoice();
        const node = fc.getBlockDefaultStatus(block_root) orelse return false;
        return switch (node.extra_meta.executionStatus()) {
            .syncing, .payload_separated => true,
            else => false,
        };
    }

    pub fn onSingleVote(
        self: *Chain,
        validator_index: u32,
        attestation_slot: u64,
        beacon_block_root: [32]u8,
        target_epoch: u64,
    ) !void {
        try self.forkChoice().onSingleVote(
            self.allocator,
            validator_index,
            attestation_slot,
            beacon_block_root,
            target_epoch,
        );
    }

    pub fn applyIndexedAttestationVote(
        self: *Chain,
        indexed_attestation: *const AnyIndexedAttestation,
        attestation_data_root: [32]u8,
    ) !void {
        try self.forkChoice().onAttestation(
            self.allocator,
            indexed_attestation,
            attestation_data_root,
            false,
        );
    }

    pub fn updateForkChoiceTime(self: *Chain, slot: u64) !void {
        try self.forkChoice().updateTime(self.allocator, slot);
    }

    pub fn pruneForkChoice(
        self: *Chain,
        finalized_root: [32]u8,
        finalized_epoch: u64,
    ) !void {
        const fc = self.forkChoice();
        _ = try fc.prune(self.allocator, finalized_root);
        fc.fc_store.pruneEquivocating(finalized_epoch);
    }

    pub fn advanceHeadState(self: *Chain, target_slot: u64, new_state_root: [32]u8) !void {
        self.head_tracker.head_state_root = new_state_root;
        self.head_tracker.head_slot = target_slot;
        try self.head_tracker.slot_roots.put(self.allocator, target_slot, self.head_tracker.head_root);
    }

    pub fn pruneTrackedBlocksBelow(self: *Chain, slot: u64) void {
        self.head_tracker.pruneBelow(slot);
    }

    // -----------------------------------------------------------------------
    // Genesis initialization
    // -----------------------------------------------------------------------

    /// Register the genesis block root → state root mapping so the first
    /// block import can find its parent pre-state.
    pub fn registerGenesisRoot(self: *Chain, block_root: [32]u8, state_root: [32]u8) !void {
        try self.block_to_state.put(self.allocator, block_root, state_root);
    }

    pub fn bootstrapFromGenesis(self: *Chain, genesis_state: *CachedBeaconState) !BootstrapResult {
        try genesis_state.state.commit();

        var genesis_header = try genesis_state.state.latestBlockHeader();
        const genesis_block_root = (try genesis_header.hashTreeRoot()).*;
        const genesis_slot = try genesis_state.state.slot();
        const genesis_epoch = @divFloor(genesis_slot, preset.SLOTS_PER_EPOCH);

        return self.bootstrapFromAnchorState(
            genesis_state,
            genesis_block_root,
            genesis_block_root,
            genesis_slot,
            genesis_slot,
            genesis_epoch,
            .genesis,
        );
    }

    pub fn bootstrapFromCheckpoint(self: *Chain, checkpoint_state: *CachedBeaconState) !BootstrapResult {
        try checkpoint_state.state.commit();
        const state_root = (try checkpoint_state.state.hashTreeRoot()).*;

        var cp_header = try checkpoint_state.state.latestBlockHeader();
        const header_slot = try cp_header.get("slot");
        const header_proposer = try cp_header.get("proposer_index");
        const header_parent = (try cp_header.getFieldRoot("parent_root")).*;
        const header_body = (try cp_header.getFieldRoot("body_root")).*;

        var header_state_root = (try cp_header.getFieldRoot("state_root")).*;
        if (std.mem.eql(u8, &header_state_root, &([_]u8{0} ** 32))) {
            header_state_root = state_root;
        }

        const cp_header_val = consensus_types.phase0.BeaconBlockHeader.Type{
            .slot = header_slot,
            .proposer_index = header_proposer,
            .parent_root = header_parent,
            .state_root = header_state_root,
            .body_root = header_body,
        };
        var anchor_block_root: [32]u8 = undefined;
        try consensus_types.phase0.BeaconBlockHeader.hashTreeRoot(&cp_header_val, &anchor_block_root);

        const checkpoint_slot = try checkpoint_state.state.slot();
        const checkpoint_epoch = std.math.divCeil(u64, checkpoint_slot, preset.SLOTS_PER_EPOCH) catch unreachable;
        return self.bootstrapFromAnchorState(
            checkpoint_state,
            anchor_block_root,
            header_parent,
            header_slot,
            checkpoint_slot,
            checkpoint_epoch,
            .finalized_checkpoint,
        );
    }

    const AnchorBootstrapKind = enum {
        genesis,
        finalized_checkpoint,
    };

    fn bootstrapFromAnchorState(
        self: *Chain,
        anchor_state: *CachedBeaconState,
        anchor_block_root: [32]u8,
        anchor_parent_root: [32]u8,
        anchor_block_slot: u64,
        anchor_state_slot: u64,
        anchor_checkpoint_epoch: u64,
        anchor_kind: AnchorBootstrapKind,
    ) !BootstrapResult {
        try self.state_regen.verifyPublishedStateOwnership(anchor_state);

        const cached_state_root = try self.queued_regen.onNewBlock(anchor_state, true);

        try self.registerGenesisRoot(anchor_block_root, cached_state_root);
        try self.onTrackedBlock(anchor_block_root, anchor_block_slot, cached_state_root);
        self.setTrackedHead(anchor_block_root, anchor_block_slot, cached_state_root);
        try self.onEpochTransition(anchor_state);

        const genesis_validators_root = (try anchor_state.state.genesisValidatorsRoot()).*;
        self.genesis_validators_root = genesis_validators_root;
        const genesis_time = try anchor_state.state.genesisTime();
        self.genesis_time_s = genesis_time;
        const earliest_archived_slot = try self.db.getEarliestBlockArchiveSlot();

        const bootstrap_finalized_cp = consensus_types.phase0.Checkpoint.Type{
            .epoch = anchor_checkpoint_epoch,
            .root = anchor_block_root,
        };
        const bootstrap_justified_cp = switch (anchor_kind) {
            .genesis => consensus_types.phase0.Checkpoint.Type{
                .epoch = anchor_checkpoint_epoch,
                .root = anchor_block_root,
            },
            .finalized_checkpoint => consensus_types.phase0.Checkpoint.Type{
                .epoch = if (anchor_checkpoint_epoch == 0) 0 else anchor_checkpoint_epoch + 1,
                .root = anchor_block_root,
            },
        };

        if (self.archive_store) |store| {
            store.restoreProgress(bootstrap_finalized_cp.epoch * preset.SLOTS_PER_EPOCH) catch |err| {
                log.warn("archive progress restore failed: {}", .{err});
            };

            const finalized_slot = bootstrap_finalized_cp.epoch * preset.SLOTS_PER_EPOCH;
            if (store.last_finalized_slot < finalized_slot) {
                store.catchUpToFinalized(
                    .{
                        .epoch = bootstrap_finalized_cp.epoch,
                        .root = bootstrap_finalized_cp.root,
                    },
                    &self.block_to_state,
                ) catch |err| {
                    log.warn("archive catch-up during bootstrap failed: {}", .{err});
                };
            }
        }

        const balances = anchor_state.epoch_cache.getEffectiveBalanceIncrements();
        const justified_root = bootstrap_justified_cp.root;
        const finalized_root = bootstrap_finalized_cp.root;
        const anchor_extra_meta: fork_choice_mod.BlockExtraMeta = blk: {
            const exec_block_hash = anchor_state.state.latestExecutionPayloadHeaderBlockHash() catch {
                break :blk fork_choice_mod.BlockExtraMeta{ .pre_merge = {} };
            };
            if (std.mem.eql(u8, exec_block_hash[0..], &([_]u8{0} ** 32))) {
                break :blk fork_choice_mod.BlockExtraMeta{ .pre_merge = {} };
            }

            break :blk fork_choice_mod.BlockExtraMeta{
                .post_merge = fork_choice_mod.BlockExtraMeta.PostMergeMeta.init(
                    exec_block_hash.*,
                    try anchor_state.state.latestExecutionPayloadHeaderBlockNumber(),
                    .valid,
                    .available,
                ),
            };
        };

        const fc_anchor = ProtoBlock{
            .slot = anchor_block_slot,
            .block_root = anchor_block_root,
            .parent_root = anchor_parent_root,
            .state_root = cached_state_root,
            .target_root = anchor_block_root,
            .justified_epoch = bootstrap_justified_cp.epoch,
            .justified_root = justified_root,
            .finalized_epoch = bootstrap_finalized_cp.epoch,
            .finalized_root = finalized_root,
            .unrealized_justified_epoch = bootstrap_justified_cp.epoch,
            .unrealized_justified_root = justified_root,
            .unrealized_finalized_epoch = bootstrap_finalized_cp.epoch,
            .unrealized_finalized_root = finalized_root,
            .extra_meta = anchor_extra_meta,
            .timeliness = true,
        };

        const fc = try fork_choice_mod.initFromAnchor(
            self.allocator,
            self.config,
            fc_anchor,
            @max(anchor_block_slot, anchor_state_slot),
            CheckpointWithPayloadStatus.fromCheckpoint(.{
                .epoch = bootstrap_justified_cp.epoch,
                .root = justified_root,
            }, .full),
            CheckpointWithPayloadStatus.fromCheckpoint(.{
                .epoch = bootstrap_finalized_cp.epoch,
                .root = finalized_root,
            }, .full),
            balances.items,
            .{ .getFn = emptyJustifiedBalancesGetterFn },
            .{},
            .{
                .proposer_boost = true,
                .proposer_boost_reorg = true,
                .compute_unrealized = true,
            },
        );

        return .{
            .fork_choice = fc,
            .genesis_time = genesis_time,
            .genesis_validators_root = genesis_validators_root,
            .earliest_available_slot = if (earliest_archived_slot) |slot| @min(anchor_state_slot, slot) else anchor_state_slot,
        };
    }

    // -----------------------------------------------------------------------
    // Block import pipeline
    // -----------------------------------------------------------------------

    pub const ReadyBlockPlanResult = union(enum) {
        skipped: BlockImportError,
        planned: blocks_mod.PlannedBlockImport,
    };

    /// Full block import pipeline: sanity → STFN → fork choice → persist → head → notifications.
    ///
    fn importBlockSync(
        self: *Chain,
        any_signed: AnySignedBeaconBlock,
        source: blocks_mod.BlockSource,
    ) !ImportResult {
        const block_input = PipelineBlockInput{
            .block = any_signed,
            .source = source,
            .da_status = .not_required,
        };
        return self.importPipelineBlockInput(block_input);
    }

    fn importReadyBlockSync(self: *Chain, ready: chain_types.ReadyBlockInput) !ImportResult {
        var owned_ready = ready;
        const planned = try self.planReadyBlockImport(&owned_ready);
        const completed = self.executePlannedReadyBlockImportSync(planned);
        return self.finishCompletedReadyBlockImport(completed);
    }

    fn importPipelineBlockInput(self: *Chain, block_input: PipelineBlockInput) !ImportResult {
        // Skip future-slot check: callers (gossip handler, API, sync) have already
        // validated timing before reaching the pipeline.
        // Propagate verify_signatures from chain config: when false (default for tests),
        // skip BLS signature verification to avoid failures with dummy test signatures.
        const opts = PipelineImportOpts{
            .skip_future_slot = true,
            .skip_signatures = !self.verify_signatures,
        };
        const pipeline_result = try self.processBlockPipeline(block_input, opts);
        return .{
            .block_root = pipeline_result.block_root,
            .state_root = pipeline_result.state_root,
            .slot = pipeline_result.slot,
            .epoch_transition = pipeline_result.epoch_transition,
            .execution_optimistic = pipeline_result.execution_optimistic,
        };
    }

    pub fn planReadyBlockImport(self: *Chain, ready: *chain_types.ReadyBlockInput) !blocks_mod.PlannedBlockImport {
        const plan_result = try self.planReadyBlockImportWithOpts(ready, .{
            .skip_future_slot = true,
            .skip_signatures = !self.verify_signatures,
        });
        return switch (plan_result) {
            .skipped => error.InternalError,
            .planned => |planned| planned,
        };
    }

    pub fn planRangeSyncReadyBlockImport(self: *Chain, ready: *chain_types.ReadyBlockInput) !ReadyBlockPlanResult {
        return self.planReadyBlockImportWithOpts(ready, self.rangeSyncImportOpts());
    }

    pub fn rangeSyncImportOpts(self: *const Chain) PipelineImportOpts {
        return .{
            .ignore_if_known = true,
            .ignore_if_finalized = true,
            .from_range_sync = true,
            .skip_future_slot = true,
            .skip_signatures = !self.verify_signatures,
        };
    }

    fn planReadyBlockImportWithOpts(
        self: *Chain,
        ready: *chain_types.ReadyBlockInput,
        opts: PipelineImportOpts,
    ) !ReadyBlockPlanResult {
        const block_input = PipelineBlockInput{
            .block = ready.block,
            .source = ready.source,
            .da_status = ready.da_status,
            .seen_timestamp_sec = ready.seen_timestamp_sec,
        };
        const plan_result = try self.planPipelineBlockInput(block_input, opts);
        switch (plan_result) {
            .skipped => |skip| return .{ .skipped = skip.reason },
            .planned => |planned| {
                ready.block_data_plan.deinit(self.allocator);
                ready.* = undefined;
                return .{ .planned = planned };
            },
        }
    }

    fn getReadyBlockImportPreState(
        self: *Chain,
        planned: blocks_mod.PlannedBlockImport,
    ) BlockImportError!*CachedBeaconState {
        return blocks_mod.getPlannedBlockImportPreState(self.getPipelineContext(), planned);
    }

    pub const QueuePlannedReadyBlockImportResult = union(enum) {
        queued,
        not_queued: blocks_mod.PlannedBlockImport,
    };

    pub fn tryQueuePlannedReadyBlockImport(
        self: *Chain,
        planned: blocks_mod.PlannedBlockImport,
    ) !QueuePlannedReadyBlockImportResult {
        const service = self.state_work_service;
        if (!service.canAcceptBlockImport()) return .{ .not_queued = planned };

        const pre_state = try self.getReadyBlockImportPreState(planned);
        var job = try blocks_mod.captureStateTransitionJob(
            self.allocator,
            self.state_graph_gate,
            planned,
            pre_state,
        );

        const submitted = service.submitBlockImport(job) catch |err| {
            self.state_regen.destroyTransientState(job.transient_pre_state);
            return err;
        };
        if (!submitted) {
            const transient_pre_state = job.transient_pre_state;
            const restored_planned = job.releasePlanned();
            self.state_regen.destroyTransientState(transient_pre_state);
            return .{ .not_queued = restored_planned };
        }
        return .queued;
    }

    pub fn popCompletedReadyBlockImport(self: *Chain) ?CompletedBlockImport {
        const service = self.state_work_service;
        return service.popCompletedBlockImport();
    }

    pub fn waitForCompletedReadyBlockImport(self: *Chain) StateWorkService.WaitResult {
        const service = self.state_work_service;
        return service.waitForCompletion();
    }

    pub fn executePlannedReadyBlockImportSync(
        self: *Chain,
        planned: blocks_mod.PlannedBlockImport,
    ) CompletedBlockImport {
        var owned_planned = planned;
        const pre_state = self.getReadyBlockImportPreState(owned_planned) catch |err| {
            return .{ .failure = .{
                .planned = owned_planned,
                .err = err,
            } };
        };
        const prepared = blocks_mod.executePlannedBlockImport(
            self.allocator,
            self.state_graph_gate,
            self.block_bls_thread_pool,
            &owned_planned,
            pre_state,
        ) catch |err| {
            return .{ .failure = .{
                .planned = owned_planned,
                .err = err,
            } };
        };
        return .{ .success = prepared };
    }

    pub fn deinitPlannedReadyBlockImport(
        self: *Chain,
        planned: *blocks_mod.PlannedBlockImport,
    ) void {
        planned.deinit(self.allocator);
    }

    pub fn deinitCompletedReadyBlockImport(self: *Chain, completed: *CompletedBlockImport) void {
        completed.deinit(self.allocator);
    }

    pub fn finishCompletedReadyBlockImport(self: *Chain, completed: CompletedBlockImport) !ImportResult {
        var owned_completed = completed;
        defer owned_completed.deinit(self.allocator);

        switch (owned_completed) {
            .failure => |failure| return failure.err,
            .success => |*prepared| return self.finishPreparedReadyBlockImport(prepared, try blocks_mod.verifyExecutionPayload(
                self.allocator,
                prepared.block_input,
                self.execution_port,
                prepared.opts,
            )),
        }
    }

    pub fn finishPreparedReadyBlockImport(
        self: *Chain,
        prepared: *blocks_mod.PreparedBlockImport,
        exec_status: blocks_mod.ExecutionStatus,
    ) !ImportResult {
        const ctx = self.getPipelineContext();
        return blocks_mod.finishPreparedBlockImport(ctx, prepared, exec_status);
    }

    fn planPipelineBlockInput(
        self: *Chain,
        block_input: PipelineBlockInput,
        opts: PipelineImportOpts,
    ) BlockImportError!blocks_mod.BlockPlanResult {
        const ctx = self.getPipelineContext();
        return blocks_mod.planBlockForImport(ctx, block_input, opts);
    }

    // -----------------------------------------------------------------------
    // New pipeline-based block import
    // -----------------------------------------------------------------------

    /// Process a block through the staged import pipeline.
    ///
    /// This is the main entry point for block processing. It runs all stages
    /// in sequence: verify_sanity → state_transition → verify_execution → import.
    /// importBlockSync delegates here, so this is the canonical synchronous implementation.
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
        const current_slot = self.currentSlot();
        return .{
            .allocator = self.allocator,
            .block_state_cache = self.block_state_cache,
            .state_regen = self.state_regen,
            .queued_regen = self.queued_regen,
            .fork_choice = self.forkChoice(),
            .db = self.db,
            .head_tracker = self.head_tracker,
            .block_to_state = &self.block_to_state,
            .seen_block_attesters = self.seen_block_attesters,
            .seen_block_proposers = self.seen_block_proposers,
            .notification_sink = self.notification_sink,
            .execution_port = self.execution_port,
            .current_slot = current_slot,
            .state_graph_gate = self.state_graph_gate,
            .block_bls_thread_pool = self.block_bls_thread_pool,
            .reprocess_queue = self.reprocess_queue, // P1-10: wire reprocess queue
            .on_finalized_ptr = @ptrCast(self), // W2: prune caches on finalization
            .on_finalized_fn = &Chain.onFinalizedCallback,
        };
    }

    // -----------------------------------------------------------------------
    // Attestation import
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
        validator_index: u64,
        attestation: fork_types.AnyAttestation,
    ) !void {
        const data = attestation.data();
        if (self.seen_attesters.isKnown(data.target.epoch, validator_index)) {
            return error.AttestationAlreadyKnown;
        }

        // Apply vote weight to fork choice.
        _ = self.onSingleVote(
            @intCast(validator_index),
            data.slot,
            data.beacon_block_root,
            data.target.epoch,
        ) catch |err| {
            log.warn("FC onAttestation failed validator_index={d} slot={d}: {}", .{ validator_index, data.slot, err });
            // Non-fatal — still insert into pool for block packing.
        };

        // Insert into attestation pool for block production.
        // Both formats are accepted; the pool handles fork-aware storage.
        try self.op_pool.attestation_pool.addAny(attestation);
        self.seen_attesters.add(data.target.epoch, validator_index) catch |err| switch (err) {
            error.EpochTooLow => {},
            else => return err,
        };

        // Publish attestation notification.
        if (self.notification_sink) |sink| {
            var aggregation_bits = [_]u8{0} ** 8;
            const aggregation_bits_bytes = attestation.aggregationBitsBytes();
            const copy_len = @min(aggregation_bits.len, aggregation_bits_bytes.len);
            @memcpy(aggregation_bits[0..copy_len], aggregation_bits_bytes[0..copy_len]);

            sink.publish(.{
                .attestation = .{
                    .aggregation_bits = aggregation_bits,
                    .slot = data.slot,
                    .committee_index = attestation.committeeIndex(),
                    .beacon_block_root = data.beacon_block_root,
                    .source_epoch = data.source.epoch,
                    .source_root = data.source.root,
                    .target_epoch = data.target.epoch,
                    .target_root = data.target.root,
                    .signature = attestation.signature(),
                },
            });
        }
    }

    pub fn importIndexedAttestation(
        self: *Chain,
        validator_index: u64,
        attestation: fork_types.AnyAttestation,
        indexed_attestation: *const AnyIndexedAttestation,
        attestation_data_root: [32]u8,
    ) !void {
        const data = attestation.data();
        if (self.seen_attesters.isKnown(data.target.epoch, validator_index)) {
            return error.AttestationAlreadyKnown;
        }

        self.applyIndexedAttestationVote(indexed_attestation, attestation_data_root) catch |err| {
            log.warn("FC onAttestation failed validator_index={d} slot={d}: {}", .{ validator_index, data.slot, err });
        };

        try self.op_pool.attestation_pool.addAny(attestation);
        self.seen_attesters.add(data.target.epoch, validator_index) catch |err| switch (err) {
            error.EpochTooLow => {},
            else => return err,
        };

        if (self.notification_sink) |sink| {
            var aggregation_bits = [_]u8{0} ** 8;
            const aggregation_bits_bytes = attestation.aggregationBitsBytes();
            const copy_len = @min(aggregation_bits.len, aggregation_bits_bytes.len);
            @memcpy(aggregation_bits[0..copy_len], aggregation_bits_bytes[0..copy_len]);

            sink.publish(.{
                .attestation = .{
                    .aggregation_bits = aggregation_bits,
                    .slot = data.slot,
                    .committee_index = attestation.committeeIndex(),
                    .beacon_block_root = data.beacon_block_root,
                    .source_epoch = data.source.epoch,
                    .source_root = data.source.root,
                    .target_epoch = data.target.epoch,
                    .target_root = data.target.root,
                    .signature = attestation.signature(),
                },
            });
        }
    }

    pub fn importIndexedAggregate(
        self: *Chain,
        attestation: fork_types.AnyAttestation,
        indexed_attestation: *const AnyIndexedAttestation,
        attestation_data_root: [32]u8,
    ) !void {
        const data = attestation.data();

        self.applyIndexedAttestationVote(indexed_attestation, attestation_data_root) catch |err| {
            log.debug("FC onAggregate failed slot={d}: {}", .{ data.slot, err });
        };

        _ = try self.op_pool.agg_attestation_pool.addAny(attestation);
    }

    // -----------------------------------------------------------------------
    // Slot tick
    // -----------------------------------------------------------------------

    /// Called at the start of each slot.
    ///
    /// Updates fork choice time and prunes the seen cache.
    pub fn onSlot(self: *Chain, slot: u64) void {
        // Update fork choice time (removes proposer boost from previous slot).
        self.updateForkChoiceTime(slot) catch |err| {
            log.err("fork choice updateTime failed slot={d}: {}", .{ slot, err });
            // Prune stale queued attestations to prevent unbounded growth when
            // updateTime fails (e.g. OOM during attestation processing).
            self.forkChoice().pruneStaleQueuedAttestations(self.allocator, slot);
        };

        // Prune seen blocks older than 2 epochs.
        const min_slot = if (slot > 2 * preset.SLOTS_PER_EPOCH)
            slot - 2 * preset.SLOTS_PER_EPOCH
        else
            0;
        self.seen_cache.pruneBlocks(min_slot);
        self.attestation_data_cache.onSlot(slot);
        const current_epoch = computeEpochAtSlot(slot);
        self.seen_attesters.prune(current_epoch);
        self.seen_block_attesters.prune(current_epoch);
        self.seen_block_proposers.prune(current_epoch);

        // Prune aggregators at epoch boundaries.
        // The seen_aggregators map is keyed by (validator_index, epoch) so it grows
        // each epoch. Clear it at the start of each new epoch to bound memory.
        if (slot > 0 and slot % preset.SLOTS_PER_EPOCH == 0) {
            self.seen_cache.pruneAggregators();
            self.beacon_proposer_cache.prune(slot / preset.SLOTS_PER_EPOCH);
        }

        // Prune op_pool attestations — keeps only current + previous epoch.
        // AggregatedAttestationPool and AttestationPool grow with every incoming
        // attestation and have no self-eviction; pruneBySlot / prune must be
        // called every slot to bound memory.
        self.op_pool.agg_attestation_pool.pruneBySlot(slot);
        self.op_pool.attestation_pool.prune(slot);

        const pending_min_slot = if (slot > PENDING_INGRESS_RETENTION_SLOTS)
            slot - PENDING_INGRESS_RETENTION_SLOTS
        else
            0;
        if (self.pending_block_ingress) |pending| {
            _ = pending.pruneBeforeSlot(pending_min_slot);
        }
        if (self.da_manager) |dam| {
            dam.prunePendingBeforeSlot(pending_min_slot);
        }
        if (self.payload_envelope_ingress) |ingress| {
            _ = ingress.pruneBeforeSlot(pending_min_slot);
        }
    }

    // -----------------------------------------------------------------------
    // Finalization handler
    // -----------------------------------------------------------------------

    /// Called when a new finalized checkpoint is detected.
    ///
    /// Finalization is a two-phase cleanup:
    /// 1. Durably archive finalized history.
    /// 2. Prune hot in-memory structures only after archival succeeds.
    ///
    /// If archival fails, pruning is skipped so the node retains the hot data
    /// needed to retry archival later.
    pub fn onFinalized(self: *Chain, finalized_epoch: u64, finalized_root: [32]u8) void {
        log.info("onFinalized epoch={d} root={s}...", .{ finalized_epoch, &std.fmt.bytesToHex(finalized_root[0..4], .lower) });

        var plan = if (self.archive_store) |store| blk: {
            break :blk FinalizationPlan.initForArchive(
                self.allocator,
                self.forkChoice(),
                store.last_finalized_slot + 1,
                finalized_epoch,
                finalized_root,
            ) catch |err| {
                log.warn("onFinalized: failed to build finalization plan: {}", .{err});
                return;
            };
        } else FinalizationPlan.init(self.allocator, finalized_epoch, finalized_root);
        defer plan.deinit();

        if (self.archive_store) |store| {
            store.onFinalized(&plan, &self.block_to_state) catch |err| {
                log.warn("onFinalized: archive store failed: {}", .{err});
                return;
            };
        }

        self.queued_regen.onFinalized(plan.finalized_epoch) catch |err| {
            log.warn("onFinalized: regen prune failed: {}", .{err});
            return;
        };

        // Prune fork choice DAG — remove nodes below finalized root.
        self.pruneForkChoice(plan.finalized_root, plan.finalized_epoch) catch |err| {
            log.warn("onFinalized: fork choice prune failed: {}", .{err});
            return;
        };

        // Prune seen cache — remove entries older than 2 epochs before finalization.
        self.seen_cache.pruneBlocks(plan.prune_slot);
        self.attestation_data_cache.onSlot(plan.prune_slot);
        self.seen_attesters.prune(plan.finalized_epoch);

        // Prune DA tracking data outside the availability window.
        if (self.da_manager) |dam| {
            dam.pruneOldData(plan.prune_slot);
        }

        // Prune slot_roots in HeadTracker — remove entries for pre-finalized slots.
        // This prevents the slot→root map from growing unboundedly over time.
        if (self.pending_block_ingress) |pending| {
            _ = pending.pruneBeforeSlot(plan.finalized_slot);
        }
        if (self.da_manager) |dam| {
            dam.prunePendingBeforeSlot(plan.finalized_slot);
        }
        if (self.payload_envelope_ingress) |ingress| {
            _ = ingress.pruneBeforeSlot(plan.finalized_slot);
        }
        self.pruneTrackedBlocksBelow(plan.finalized_slot);

        // Prune block_to_state for blocks no longer present in fork choice's hot DAG.
        // HeadTracker only tracks one root per slot and is not a complete liveness
        // set for competing hot branches. Fork choice is the authoritative hot view.
        prune_b2s: {
            var roots_to_remove = plan.collectBlockStateRemovals(
                self.forkChoice(),
                &self.block_to_state,
            ) catch {
                log.warn("onFinalized: OOM collecting roots_to_remove, skipping block_to_state prune", .{});
                break :prune_b2s;
            };
            defer roots_to_remove.deinit();
            for (roots_to_remove.items) |root| {
                _ = self.block_to_state.swapRemove(root);
            }
        }

        // Prune SeenCache sub-maps on finalization — these dedup caches are not
        // authoritative, so clearing them on finalization is safe and prevents OOM.
        self.seen_cache.pruneOnFinalization();

        // Prune op_pool secondary pools — remove stale slashings/exits.
        // The SeenCache dedup was already cleared above; now evict actual entries.
        self.op_pool.voluntary_exit_pool.prune(plan.finalized_epoch);
        self.op_pool.proposer_slashing_pool.pruneFinalized(plan.finalized_epoch);
        self.op_pool.attester_slashing_pool.pruneAll();

        // Prune ReprocessQueue — drop blocks queued for slots below finalized.
        if (self.reprocess_queue) |rq| {
            rq.prune(plan.finalized_slot);
        }

        // Note: finalized_checkpoint notification is emitted in import_block.zig
        // (after fork choice head recomputation) with accurate state_root context.
        // Emitting it again here would produce duplicates.
    }

    // -----------------------------------------------------------------------
    // Head / status queries
    // -----------------------------------------------------------------------

    /// Get current head info.
    ///
    /// Uses fork choice head when available (authoritative LMD-GHOST head),
    /// falls back to the naive head tracker.
    pub fn getHead(self: *const Chain) HeadInfo {
        return self.headInfo();
    }

    pub fn validatorSeenAtEpoch(self: *const Chain, validator_index: u64, epoch: u64) bool {
        return self.seen_block_attesters.isKnown(epoch, validator_index) or
            self.seen_attesters.isKnown(epoch, validator_index) or
            self.seen_cache.hasSeenAggregator(validator_index, epoch) or
            self.seen_block_proposers.isKnown(epoch, validator_index);
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
        const head_slot = self.headSlot();
        const is_optimistic = self.currentHeadExecutionOptimistic();

        // Compute wall-clock slot from genesis_time_s.
        // Falls back to head_slot (distance = 0) when genesis is not yet known.
        const wall_slot = self.currentWallSlot() orelse head_slot;

        const sync_distance = if (wall_slot > head_slot) wall_slot - head_slot else 0;
        return .{
            .head_slot = head_slot,
            .sync_distance = sync_distance,
            .is_syncing = sync_distance > SYNC_DISTANCE_THRESHOLD,
            .is_optimistic = is_optimistic,
            .el_offline = false,
        };
    }

    pub fn currentWallSlot(self: *const Chain) ?u64 {
        const gt = self.genesis_time_s;
        if (gt == 0) return null;

        const sps = self.config.chain.SECONDS_PER_SLOT;
        if (sps == 0) return null;

        const now_s = unixTimestampSeconds();
        if (now_s < gt) return null;

        return (now_s - gt) / sps;
    }

    /// Build a StatusMessage reflecting the current chain state.
    ///
    /// Used for req/resp Status exchanges with peers.
    pub fn getStatus(self: *const Chain) StatusMessage.Type {
        const head = self.getHead();
        const finalized = self.forkChoice().getFinalizedCheckpoint();
        const network_slot = self.currentWallSlot() orelse head.slot;
        return .{
            .fork_digest = self.config.networkingForkDigestAtSlot(network_slot, self.genesis_validators_root),
            .finalized_root = finalized.root,
            .finalized_epoch = finalized.epoch,
            .head_root = head.root,
            .head_slot = head.slot,
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
        const current_slot = self.currentSlot();
        const finalized_epoch = self.finalizedEpoch();

        // Callbacks wired to real Chain state — ChainGossipState requires *anyopaque
        // first param matching the ptr: *anyopaque field signature in gossip_validation.zig.
        const Callbacks = struct {
            /// Returns the expected block proposer for `slot` from the head state's epoch cache.
            /// Returns null on cache miss (gossip validator falls back gracefully).
            fn getProposerIndex(_ptr: *anyopaque, _slot: u64) ?u32 {
                const self_: *const Chain = @ptrCast(@alignCast(_ptr));
                const head_state_root = self_.headStateRoot();
                const cached = self_.block_state_cache.get(head_state_root) orelse return null;
                const proposer = cached.getBeaconProposer(_slot) catch return null;
                return @intCast(proposer);
            }
            /// Returns true if `root` is tracked in fork choice.
            fn isKnownBlockRoot(_ptr: *anyopaque, root: [32]u8) bool {
                const self_: *const Chain = @ptrCast(@alignCast(_ptr));
                return self_.hasCanonicalBlock(root) or self_.block_to_state.contains(root);
            }
            fn getKnownBlockSlot(_ptr: *anyopaque, root: [32]u8) ?u64 {
                const self_: *const Chain = @ptrCast(@alignCast(_ptr));
                const block = self_.forkChoice().getBlockDefaultStatus(root) orelse return null;
                return block.slot;
            }
            /// Returns the total validator count from the head state's epoch cache.
            /// Returns 0 if head state is unavailable (gossip validator skips bounds check).
            fn getValidatorCount(_ptr: *anyopaque) u32 {
                const self_: *const Chain = @ptrCast(@alignCast(_ptr));
                const head_state_root = self_.headStateRoot();
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
            .getKnownBlockSlot = Callbacks.getKnownBlockSlot,
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

    /// Store a blob sidecar received via gossip or req/resp.
    pub fn importBlobSidecar(self: *Chain, root: [32]u8, data: []const u8) !void {
        try self.db.putBlobSidecars(root, data);

        // Publish blob_sidecar notification.
        // TODO: Parse actual blob fields (index, slot, kzg_commitment) from data.
        if (self.notification_sink) |sink| {
            sink.publish(.{ .blob_sidecar = .{
                .block_root = root,
                .index = 0,
                .slot = 0,
                .kzg_commitment = [_]u8{0} ** 48,
                .versioned_hash = [_]u8{0} ** 32,
            } });
        }
    }

    pub fn importDataColumnSidecar(
        self: *Chain,
        root: [32]u8,
        column_index: u64,
        data: []const u8,
    ) !void {
        try self.db.putDataColumn(root, column_index, data);
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
        const cloned = blk: {
            var state_graph_lease = self.state_graph_gate.acquire();
            defer state_graph_lease.release();

            const head_state_root = self.headStateRoot();
            const pre_state = self.block_state_cache.get(head_state_root) orelse
                return error.NoHeadState;

            break :blk .{
                .head_root = self.headRoot(),
                .post_state = try pre_state.clone(self.allocator, .{ .transfer_cache = false }),
            };
        };
        const head_root = cloned.head_root;
        const post_state = cloned.post_state;
        errdefer {
            post_state.deinit();
            self.allocator.destroy(post_state);
        }

        try state_transition.processSlots(self.allocator, post_state, target_slot, .{});
        try post_state.state.commit();

        const new_state_root = try self.queued_regen.onNewBlock(post_state, true);

        // Store the advanced state root for this block root. Note: this records the
        // "latest known" state root for the head root (i.e. the post-slot-processing
        // state), NOT the post-block state root. When a block is later imported at
        // this slot, the entry will be overwritten with the actual post-block state root.
        try self.block_to_state.put(
            self.allocator,
            head_root,
            new_state_root,
        );

        // Update fork choice time to keep it in sync with head tracker (P0-5 fix).
        // onSlot already calls updateTime, but advanceSlot can be called independently
        // (e.g., from tests, batch sync). Both paths must call updateTime.
        self.updateForkChoiceTime(target_slot) catch |err| {
            log.err("fork choice updateTime failed slot={d}: {}", .{ target_slot, err });
        };

        try self.advanceHeadState(target_slot, new_state_root);
    }

    pub fn acquireStateGraphLease(self: *Chain) StateGraphGate.Lease {
        return self.state_graph_gate.acquire();
    }
};
