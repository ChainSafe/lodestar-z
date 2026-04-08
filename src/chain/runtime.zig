//! Chain runtime — owns the hot chain subsystem graph.
//!
//! This is the production ownership boundary for chain state. `Chain` remains
//! the coordinator over these components, but the allocation and teardown of
//! the chain graph now lives in the chain module instead of `node/lifecycle`.

const std = @import("std");
const Allocator = std.mem.Allocator;

const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;
const SharedValidatorPubkeys = state_transition.SharedValidatorPubkeys;
const Node = @import("persistent_merkle_tree").Node;
const regen_mod = @import("regen/root.zig");
const BlockStateCache = regen_mod.BlockStateCache;
const CheckpointStateCache = regen_mod.CheckpointStateCache;
const MemoryCPStateDatastore = regen_mod.MemoryCPStateDatastore;
const StateRegen = regen_mod.StateRegen;
const StateDisposer = regen_mod.StateDisposer;
const SharedStateGraph = regen_mod.SharedStateGraph;
const StateGraphGate = regen_mod.StateGraphGate;
const db_mod = @import("db");
const BeaconDB = db_mod.BeaconDB;
const MemoryKVStore = db_mod.MemoryKVStore;
const LmdbKVStore = db_mod.LmdbKVStore;
const DatabaseMetricsSnapshot = db_mod.MetricsSnapshot;

const Chain = @import("chain.zig").Chain;
const HeadTracker = @import("block_import.zig").HeadTracker;
const QueuedStateRegen = regen_mod.QueuedStateRegen;
const OpPool = @import("op_pool.zig").OpPool;
const SeenCache = @import("seen_cache.zig").SeenCache;
const SeenAttesters = @import("seen_attesters.zig").SeenAttesters;
const SeenEpochValidators = @import("seen_epoch_validators.zig").SeenEpochValidators;
const SeenAttestationData = @import("seen_attestation_data.zig").SeenAttestationData;
const sync_contribution_pool_mod = @import("sync_contribution_pool.zig");
const SyncContributionAndProofPool = sync_contribution_pool_mod.SyncContributionAndProofPool;
const SyncCommitteeMessagePool = sync_contribution_pool_mod.SyncCommitteeMessagePool;
const ValidatorMonitor = @import("validator_monitor.zig").ValidatorMonitor;
const BeaconProposerCache = @import("beacon_proposer_cache.zig").BeaconProposerCache;
const DataAvailabilityManager = @import("data_availability.zig").DataAvailabilityManager;
const state_work_service_mod = @import("state_work_service.zig");
const StateWorkService = state_work_service_mod.StateWorkService;
const PendingBlockIngress = @import("block_ingress.zig").PendingBlockIngress;
const PayloadEnvelopeIngress = @import("payload_envelope_ingress.zig").PayloadEnvelopeIngress;
const Service = @import("service.zig").Service;
const chain_effects = @import("effects.zig");
const archive_store_mod = @import("archive_store.zig");
const ArchiveStore = archive_store_mod.ArchiveStore;
const kzg_mod = @import("kzg");
const Kzg = kzg_mod.Kzg;
const BlsThreadPool = @import("bls").ThreadPool;
const StateTransitionMetrics = state_transition.metrics.StateTransitionMetrics;

pub const RuntimeOptions = struct {
    pmt_pool_size: u32 = 200_000,
    max_block_states: u32 = 64,
    max_checkpoint_epochs: u32 = 3,
    verify_signatures: bool = false,
    block_bls_thread_pool: ?*BlsThreadPool = null,
    validator_monitor_indices: []const u64 = &.{},
    custody_columns: []const u64 = &.{},
    state_transition_metrics: *StateTransitionMetrics = state_transition.metrics.noop(),
};

pub const StorageBackend = union(enum) {
    memory: *MemoryKVStore,
    lmdb: *LmdbKVStore,

    pub fn kvStore(self: StorageBackend) db_mod.KVStore {
        return switch (self) {
            .memory => |store| store.kvStore(),
            .lmdb => |store| store.kvStore(),
        };
    }

    pub fn deinit(self: StorageBackend, allocator: Allocator) void {
        switch (self) {
            .memory => |store| {
                store.deinit();
                allocator.destroy(store);
            },
            .lmdb => |store| {
                store.deinit();
                allocator.destroy(store);
            },
        }
    }
};

const OwnedGraph = struct {
    db: *BeaconDB,
    shared_state_graph: *SharedStateGraph,
    cp_datastore: *MemoryCPStateDatastore,
    block_state_cache: *BlockStateCache,
    checkpoint_state_cache: *CheckpointStateCache,
    state_regen: *StateRegen,
    op_pool: *OpPool,
    seen_cache: *SeenCache,
    seen_attesters: *SeenAttesters,
    seen_block_attesters: *SeenEpochValidators,
    seen_block_proposers: *SeenEpochValidators,
    seen_attestation_data: *SeenAttestationData,
    sync_contribution_pool: *SyncContributionAndProofPool,
    sync_committee_message_pool: *SyncCommitteeMessagePool,
    beacon_proposer_cache: *BeaconProposerCache,
    custody_columns: []u64,
    kzg: *Kzg,
    da_manager: *DataAvailabilityManager,
    archive_store: *ArchiveStore,
    pending_block_ingress: *PendingBlockIngress,
    payload_envelope_ingress: *PayloadEnvelopeIngress,
    chain: *Chain,

    fn deinit(self: *OwnedGraph, allocator: Allocator, storage_backend: StorageBackend) void {
        self.chain.deinit();
        allocator.destroy(self.chain);

        self.sync_committee_message_pool.deinit();
        allocator.destroy(self.sync_committee_message_pool);

        self.sync_contribution_pool.deinit();
        allocator.destroy(self.sync_contribution_pool);

        self.beacon_proposer_cache.deinit();
        allocator.destroy(self.beacon_proposer_cache);

        self.archive_store.deinit();
        allocator.destroy(self.archive_store);

        self.pending_block_ingress.deinit();
        allocator.destroy(self.pending_block_ingress);

        self.payload_envelope_ingress.deinit();
        allocator.destroy(self.payload_envelope_ingress);

        self.da_manager.deinit();
        allocator.destroy(self.da_manager);

        self.kzg.deinit();
        allocator.destroy(self.kzg);

        allocator.free(self.custody_columns);

        self.seen_cache.deinit();
        allocator.destroy(self.seen_cache);

        self.seen_attesters.deinit();
        allocator.destroy(self.seen_attesters);

        self.seen_block_attesters.deinit();
        allocator.destroy(self.seen_block_attesters);

        self.seen_block_proposers.deinit();
        allocator.destroy(self.seen_block_proposers);

        self.seen_attestation_data.deinit();
        allocator.destroy(self.seen_attestation_data);

        self.op_pool.deinit();
        allocator.destroy(self.op_pool);

        self.chain.state_work_service.deinit();

        self.chain.queued_regen.deinit();
        allocator.destroy(self.chain.queued_regen);

        self.chain.head_tracker.deinit();
        allocator.destroy(self.chain.head_tracker);

        allocator.destroy(self.state_regen);

        self.checkpoint_state_cache.deinit();
        allocator.destroy(self.checkpoint_state_cache);

        self.block_state_cache.deinit();
        allocator.destroy(self.block_state_cache);

        self.shared_state_graph.validator_pubkeys.deinit();
        allocator.destroy(self.shared_state_graph.validator_pubkeys);

        allocator.destroy(self.shared_state_graph.gate);

        self.shared_state_graph.state_disposer.deinit();
        allocator.destroy(self.shared_state_graph.state_disposer);

        self.cp_datastore.deinit();
        allocator.destroy(self.cp_datastore);

        self.db.close();
        allocator.destroy(self.db);

        self.shared_state_graph.pool.deinit();
        allocator.destroy(self.shared_state_graph.pool);

        allocator.destroy(self.shared_state_graph);

        storage_backend.deinit(allocator);
    }
};

fn initOwnedGraph(
    allocator: Allocator,
    io: std.Io,
    config: *const BeaconConfig,
    storage_backend: StorageBackend,
    opts: RuntimeOptions,
) !OwnedGraph {
    const db = try allocator.create(BeaconDB);
    errdefer allocator.destroy(db);
    db.* = BeaconDB.init(allocator, storage_backend.kvStore());
    errdefer db.close();

    const pool = try allocator.create(Node.Pool);
    errdefer allocator.destroy(pool);
    pool.* = try Node.Pool.init(allocator, opts.pmt_pool_size);
    errdefer pool.deinit();

    const state_disposer = try allocator.create(StateDisposer);
    errdefer allocator.destroy(state_disposer);
    state_disposer.* = StateDisposer.init(allocator, io);
    errdefer state_disposer.deinit();

    const state_graph_gate = try allocator.create(StateGraphGate);
    errdefer allocator.destroy(state_graph_gate);
    state_graph_gate.* = StateGraphGate.init(io, state_disposer);

    const validator_pubkeys = try allocator.create(SharedValidatorPubkeys);
    errdefer allocator.destroy(validator_pubkeys);
    validator_pubkeys.* = SharedValidatorPubkeys.init(allocator);
    errdefer validator_pubkeys.deinit();

    const shared_state_graph = try allocator.create(SharedStateGraph);
    errdefer allocator.destroy(shared_state_graph);
    shared_state_graph.* = .{
        .config = config,
        .pool = pool,
        .validator_pubkeys = validator_pubkeys,
        .state_disposer = state_disposer,
        .gate = state_graph_gate,
        .state_transition_metrics = opts.state_transition_metrics,
    };

    const block_cache = try allocator.create(BlockStateCache);
    errdefer allocator.destroy(block_cache);
    block_cache.* = BlockStateCache.init(
        allocator,
        opts.max_block_states,
        shared_state_graph.state_disposer,
    );
    errdefer block_cache.deinit();

    const cp_datastore = try allocator.create(MemoryCPStateDatastore);
    errdefer allocator.destroy(cp_datastore);
    cp_datastore.* = MemoryCPStateDatastore.init(allocator);
    errdefer cp_datastore.deinit();

    const cp_cache = try allocator.create(CheckpointStateCache);
    errdefer allocator.destroy(cp_cache);
    cp_cache.* = CheckpointStateCache.init(
        allocator,
        cp_datastore.datastore(),
        block_cache,
        opts.max_checkpoint_epochs,
        shared_state_graph.state_disposer,
        shared_state_graph.gate,
    );
    errdefer cp_cache.deinit();

    const regen = try allocator.create(StateRegen);
    errdefer allocator.destroy(regen);
    regen.* = StateRegen.initForRuntime(
        allocator,
        block_cache,
        cp_cache,
        db,
        shared_state_graph,
    );

    const queued_regen = try allocator.create(QueuedStateRegen);
    errdefer allocator.destroy(queued_regen);
    queued_regen.* = QueuedStateRegen.init(allocator, io, regen);
    errdefer queued_regen.deinit();
    try queued_regen.start();

    const state_work_service = try StateWorkService.init(
        allocator,
        io,
        regen,
        shared_state_graph.gate,
        opts.block_bls_thread_pool,
        state_work_service_mod.DEFAULT_MAX_PENDING_BLOCK_IMPORTS,
    );
    errdefer state_work_service.deinit();

    const head_tracker = try allocator.create(HeadTracker);
    errdefer allocator.destroy(head_tracker);
    head_tracker.* = HeadTracker.init(allocator, [_]u8{0} ** 32);
    errdefer head_tracker.deinit();

    const op_pool = try allocator.create(OpPool);
    errdefer allocator.destroy(op_pool);
    op_pool.* = OpPool.init(allocator);
    errdefer op_pool.deinit();

    const seen_cache = try allocator.create(SeenCache);
    errdefer allocator.destroy(seen_cache);
    seen_cache.* = SeenCache.init(allocator);
    errdefer seen_cache.deinit();

    const seen_attesters = try allocator.create(SeenAttesters);
    errdefer allocator.destroy(seen_attesters);
    seen_attesters.* = SeenAttesters.init(allocator);
    errdefer seen_attesters.deinit();

    const seen_block_attesters = try allocator.create(SeenEpochValidators);
    errdefer allocator.destroy(seen_block_attesters);
    seen_block_attesters.* = SeenEpochValidators.init(allocator);
    errdefer seen_block_attesters.deinit();

    const seen_block_proposers = try allocator.create(SeenEpochValidators);
    errdefer allocator.destroy(seen_block_proposers);
    seen_block_proposers.* = SeenEpochValidators.init(allocator);
    errdefer seen_block_proposers.deinit();

    const seen_attestation_data = try allocator.create(SeenAttestationData);
    errdefer allocator.destroy(seen_attestation_data);
    seen_attestation_data.* = SeenAttestationData.init(allocator);
    errdefer seen_attestation_data.deinit();

    const sync_contrib_pool = try allocator.create(SyncContributionAndProofPool);
    errdefer allocator.destroy(sync_contrib_pool);
    sync_contrib_pool.* = SyncContributionAndProofPool.init(allocator);
    errdefer sync_contrib_pool.deinit();

    const sync_msg_pool = try allocator.create(SyncCommitteeMessagePool);
    errdefer allocator.destroy(sync_msg_pool);
    sync_msg_pool.* = SyncCommitteeMessagePool.init(allocator);
    errdefer sync_msg_pool.deinit();

    const proposer_cache = try allocator.create(BeaconProposerCache);
    errdefer allocator.destroy(proposer_cache);
    proposer_cache.* = BeaconProposerCache.init(allocator);
    errdefer proposer_cache.deinit();

    const custody_columns = try allocator.dupe(u64, opts.custody_columns);
    errdefer allocator.free(custody_columns);

    const kzg = try allocator.create(Kzg);
    errdefer allocator.destroy(kzg);
    kzg.* = try Kzg.initBundled();
    errdefer kzg.deinit();

    const da_manager = try allocator.create(DataAvailabilityManager);
    errdefer allocator.destroy(da_manager);
    da_manager.* = DataAvailabilityManager.init(
        allocator,
        .{
            .min_epochs_for_blob_sidecars_requests = config.chain.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS,
        },
        custody_columns,
    );
    errdefer da_manager.deinit();

    const archive_store = try allocator.create(ArchiveStore);
    errdefer allocator.destroy(archive_store);
    archive_store.* = ArchiveStore.init(allocator, io, db, regen, .{});
    errdefer archive_store.deinit();

    const pending_block_ingress = try allocator.create(PendingBlockIngress);
    errdefer allocator.destroy(pending_block_ingress);
    pending_block_ingress.* = PendingBlockIngress.init(allocator);
    errdefer pending_block_ingress.deinit();

    const payload_envelope_ingress = try allocator.create(PayloadEnvelopeIngress);
    errdefer allocator.destroy(payload_envelope_ingress);
    payload_envelope_ingress.* = PayloadEnvelopeIngress.init(allocator);
    errdefer payload_envelope_ingress.deinit();

    const chain = try allocator.create(Chain);
    errdefer allocator.destroy(chain);
    chain.* = Chain.init(
        allocator,
        config,
        block_cache,
        cp_cache,
        regen,
        shared_state_graph.gate,
        queued_regen,
        state_work_service,
        head_tracker,
        db,
        op_pool,
        seen_cache,
        seen_attesters,
        seen_block_attesters,
        seen_block_proposers,
        seen_attestation_data,
        proposer_cache,
    );
    errdefer chain.deinit();
    chain.verify_signatures = opts.verify_signatures;
    chain.block_bls_thread_pool = opts.block_bls_thread_pool;
    chain.sync_contribution_pool = sync_contrib_pool;
    chain.sync_committee_message_pool = sync_msg_pool;
    chain.kzg = kzg;
    chain.da_manager = da_manager;
    chain.archive_store = archive_store;
    chain.pending_block_ingress = pending_block_ingress;
    chain.payload_envelope_ingress = payload_envelope_ingress;

    try chain.replaceValidatorMonitor(opts.validator_monitor_indices);

    return .{
        .db = db,
        .shared_state_graph = shared_state_graph,
        .cp_datastore = cp_datastore,
        .block_state_cache = block_cache,
        .checkpoint_state_cache = cp_cache,
        .state_regen = regen,
        .op_pool = op_pool,
        .seen_cache = seen_cache,
        .seen_attesters = seen_attesters,
        .seen_block_attesters = seen_block_attesters,
        .seen_block_proposers = seen_block_proposers,
        .seen_attestation_data = seen_attestation_data,
        .sync_contribution_pool = sync_contrib_pool,
        .sync_committee_message_pool = sync_msg_pool,
        .beacon_proposer_cache = proposer_cache,
        .custody_columns = custody_columns,
        .kzg = kzg,
        .da_manager = da_manager,
        .archive_store = archive_store,
        .pending_block_ingress = pending_block_ingress,
        .payload_envelope_ingress = payload_envelope_ingress,
        .chain = chain,
    };
}

fn runtimeFromOwnedGraph(
    allocator: Allocator,
    config: *const BeaconConfig,
    storage_backend: StorageBackend,
    graph: OwnedGraph,
) Runtime {
    return .{
        .allocator = allocator,
        .config = config,
        .storage_backend = storage_backend,
        .db = graph.db,
        .shared_state_graph = graph.shared_state_graph,
        .cp_datastore = graph.cp_datastore,
        .block_state_cache = graph.block_state_cache,
        .checkpoint_state_cache = graph.checkpoint_state_cache,
        .state_regen = graph.state_regen,
        .op_pool = graph.op_pool,
        .seen_cache = graph.seen_cache,
        .seen_attesters = graph.seen_attesters,
        .seen_block_attesters = graph.seen_block_attesters,
        .seen_block_proposers = graph.seen_block_proposers,
        .seen_attestation_data = graph.seen_attestation_data,
        .sync_contribution_pool = graph.sync_contribution_pool,
        .sync_committee_message_pool = graph.sync_committee_message_pool,
        .beacon_proposer_cache = graph.beacon_proposer_cache,
        .custody_columns = graph.custody_columns,
        .kzg = graph.kzg,
        .da_manager = graph.da_manager,
        .archive_store = graph.archive_store,
        .pending_block_ingress = graph.pending_block_ingress,
        .payload_envelope_ingress = graph.payload_envelope_ingress,
        .chain = graph.chain,
    };
}

pub const MetricsSnapshot = struct {
    block_state_cache_entries: u64,
    checkpoint_state_cache_entries: u64,
    checkpoint_state_datastore_entries: u64,
    queued_state_regen_cache_hits: u64,
    queued_state_regen_queue_hits: u64,
    queued_state_regen_dropped: u64,
    queued_state_regen_queue_len: u64,
    forkchoice_nodes: u64,
    forkchoice_block_roots: u64,
    forkchoice_votes: u64,
    forkchoice_queued_attestation_slots: u64,
    forkchoice_queued_attestations_previous_slot: u64,
    forkchoice_validated_attestation_data_roots: u64,
    forkchoice_equivocating_validators: u64,
    forkchoice_proposer_boost_active: bool,
    archive_last_finalized_slot: u64,
    archive_last_archived_state_epoch: u64,
    archive_runs_total: u64,
    archive_failures_total: u64,
    archive_finalized_slots_advanced_total: u64,
    archive_state_epochs_archived_total: u64,
    archive_run_milliseconds_total: u64,
    archive_last_slots_advanced: u64,
    archive_last_batch_ops: u64,
    archive_last_run_milliseconds: u64,
    validator_monitor_monitored_validators: u64,
    validator_monitor_last_processed_epoch: u64,
    attestation_pool_groups: u64,
    aggregate_attestation_pool_groups: u64,
    aggregate_attestation_pool_entries: u64,
    voluntary_exit_pool_size: u64,
    proposer_slashing_pool_size: u64,
    attester_slashing_pool_size: u64,
    bls_to_execution_change_pool_size: u64,
    sync_committee_message_pool_size: u64,
    sync_contribution_pool_size: u64,
    beacon_proposer_cache_entries: u64,
    pending_block_ingress_size: u64,
    pending_block_ingress_added_total: u64,
    pending_block_ingress_replaced_total: u64,
    pending_block_ingress_resolved_total: u64,
    pending_block_ingress_removed_total: u64,
    pending_block_ingress_pruned_total: u64,
    pending_payload_envelope_ingress_size: u64,
    pending_payload_envelope_ingress_added_total: u64,
    pending_payload_envelope_ingress_replaced_total: u64,
    pending_payload_envelope_ingress_removed_total: u64,
    pending_payload_envelope_ingress_pruned_total: u64,
    reprocess_queue_size: u64,
    reprocess_queued_total: u64,
    reprocess_released_total: u64,
    reprocess_dropped_total: u64,
    reprocess_pruned_total: u64,
    da_blob_tracker_entries: u64,
    da_column_tracker_entries: u64,
    da_pending_blocks: u64,
    da_pending_marked_total: u64,
    da_pending_resolved_total: u64,
    da_pending_pruned_total: u64,
};

pub const Runtime = struct {
    allocator: Allocator,
    config: *const BeaconConfig,
    storage_backend: StorageBackend,
    db: *BeaconDB,
    shared_state_graph: *SharedStateGraph,
    cp_datastore: *MemoryCPStateDatastore,
    block_state_cache: *BlockStateCache,
    checkpoint_state_cache: *CheckpointStateCache,
    state_regen: *StateRegen,
    op_pool: *OpPool,
    seen_cache: *SeenCache,
    seen_attesters: *SeenAttesters,
    seen_block_attesters: *SeenEpochValidators,
    seen_block_proposers: *SeenEpochValidators,
    seen_attestation_data: *SeenAttestationData,
    sync_contribution_pool: *SyncContributionAndProofPool,
    sync_committee_message_pool: *SyncCommitteeMessagePool,
    beacon_proposer_cache: *BeaconProposerCache,
    custody_columns: []u64,
    kzg: *Kzg,
    da_manager: *DataAvailabilityManager,
    archive_store: *ArchiveStore,
    pending_block_ingress: *PendingBlockIngress,
    payload_envelope_ingress: *PayloadEnvelopeIngress,
    chain: *Chain,

    pub fn init(
        allocator: Allocator,
        io: std.Io,
        config: *const BeaconConfig,
        storage_backend: StorageBackend,
        opts: RuntimeOptions,
    ) !*Runtime {
        const runtime = try allocator.create(Runtime);
        errdefer allocator.destroy(runtime);
        var graph = try initOwnedGraph(allocator, io, config, storage_backend, opts);
        errdefer graph.deinit(allocator, storage_backend);

        runtime.* = runtimeFromOwnedGraph(allocator, config, storage_backend, graph);
        return runtime;
    }

    pub fn setValidatorMonitor(self: *Runtime, indices: []const u64) !void {
        try self.chain.replaceValidatorMonitor(indices);
    }

    pub fn metricsSnapshot(self: *const Runtime) MetricsSnapshot {
        const queued_regen_metrics = self.chain.queued_regen.getMetrics();
        const da_metrics = self.da_manager.metricsSnapshot();
        const pending_block_ingress_metrics = self.pending_block_ingress.metricsSnapshot();
        const payload_envelope_ingress_metrics = self.payload_envelope_ingress.metricsSnapshot();
        const reprocess_metrics = if (self.chain.reprocess_queue) |queue|
            queue.metricsSnapshot()
        else
            @import("reprocess.zig").MetricsSnapshot{};
        const forkchoice_metrics = if (self.chain.fork_choice_storage) |fc|
            fc.metricsSnapshot()
        else
            @import("fork_choice").MetricsSnapshot{};
        const archive_store = self.archive_store;
        const archive_metrics = archive_store.metricsSnapshot();
        const validator_monitor = self.chain.validator_monitor;
        return .{
            .block_state_cache_entries = @intCast(self.block_state_cache.size()),
            .checkpoint_state_cache_entries = @intCast(self.checkpoint_state_cache.size()),
            .checkpoint_state_datastore_entries = @intCast(self.cp_datastore.count()),
            .queued_state_regen_cache_hits = queued_regen_metrics.cache_hits,
            .queued_state_regen_queue_hits = queued_regen_metrics.queue_hits,
            .queued_state_regen_dropped = queued_regen_metrics.dropped,
            .queued_state_regen_queue_len = @intCast(queued_regen_metrics.queue_len),
            .forkchoice_nodes = forkchoice_metrics.proto_array_nodes,
            .forkchoice_block_roots = forkchoice_metrics.proto_array_block_roots,
            .forkchoice_votes = forkchoice_metrics.votes,
            .forkchoice_queued_attestation_slots = forkchoice_metrics.queued_attestation_slots,
            .forkchoice_queued_attestations_previous_slot = forkchoice_metrics.queued_attestations_previous_slot,
            .forkchoice_validated_attestation_data_roots = forkchoice_metrics.validated_attestation_data_roots,
            .forkchoice_equivocating_validators = forkchoice_metrics.equivocating_validators,
            .forkchoice_proposer_boost_active = forkchoice_metrics.proposer_boost_active,
            .archive_last_finalized_slot = archive_store.last_finalized_slot,
            .archive_last_archived_state_epoch = archive_store.last_archived_state_epoch,
            .archive_runs_total = archive_metrics.runs_total,
            .archive_failures_total = archive_metrics.failures_total,
            .archive_finalized_slots_advanced_total = archive_metrics.finalized_slots_advanced_total,
            .archive_state_epochs_archived_total = archive_metrics.state_epochs_archived_total,
            .archive_run_milliseconds_total = archive_metrics.run_milliseconds_total,
            .archive_last_slots_advanced = archive_metrics.last_slots_advanced,
            .archive_last_batch_ops = archive_metrics.last_batch_ops,
            .archive_last_run_milliseconds = archive_metrics.last_run_milliseconds,
            .validator_monitor_monitored_validators = if (validator_monitor) |monitor| @intCast(monitor.monitoredCount()) else 0,
            .validator_monitor_last_processed_epoch = if (validator_monitor) |monitor| monitor.last_processed_epoch orelse 0 else 0,
            .attestation_pool_groups = @intCast(self.op_pool.attestation_pool.groupCount()),
            .aggregate_attestation_pool_groups = @intCast(self.op_pool.agg_attestation_pool.groupCount()),
            .aggregate_attestation_pool_entries = @intCast(self.op_pool.agg_attestation_pool.entryCount()),
            .voluntary_exit_pool_size = @intCast(self.op_pool.voluntary_exit_pool.size()),
            .proposer_slashing_pool_size = @intCast(self.op_pool.proposer_slashing_pool.size()),
            .attester_slashing_pool_size = @intCast(self.op_pool.attester_slashing_pool.size()),
            .bls_to_execution_change_pool_size = @intCast(self.op_pool.bls_change_pool.size()),
            .sync_committee_message_pool_size = @intCast(self.sync_committee_message_pool.size()),
            .sync_contribution_pool_size = @intCast(self.sync_contribution_pool.size()),
            .beacon_proposer_cache_entries = @intCast(self.beacon_proposer_cache.len()),
            .pending_block_ingress_size = @intCast(self.pending_block_ingress.len()),
            .pending_block_ingress_added_total = pending_block_ingress_metrics.added_total,
            .pending_block_ingress_replaced_total = pending_block_ingress_metrics.replaced_total,
            .pending_block_ingress_resolved_total = pending_block_ingress_metrics.resolved_total,
            .pending_block_ingress_removed_total = pending_block_ingress_metrics.removed_total,
            .pending_block_ingress_pruned_total = pending_block_ingress_metrics.pruned_total,
            .pending_payload_envelope_ingress_size = @intCast(self.payload_envelope_ingress.len()),
            .pending_payload_envelope_ingress_added_total = payload_envelope_ingress_metrics.added_total,
            .pending_payload_envelope_ingress_replaced_total = payload_envelope_ingress_metrics.replaced_total,
            .pending_payload_envelope_ingress_removed_total = payload_envelope_ingress_metrics.removed_total,
            .pending_payload_envelope_ingress_pruned_total = payload_envelope_ingress_metrics.pruned_total,
            .reprocess_queue_size = if (self.chain.reprocess_queue) |queue| queue.len() else 0,
            .reprocess_queued_total = reprocess_metrics.queued_total,
            .reprocess_released_total = reprocess_metrics.released_total,
            .reprocess_dropped_total = reprocess_metrics.dropped_total,
            .reprocess_pruned_total = reprocess_metrics.pruned_total,
            .da_blob_tracker_entries = @intCast(da_metrics.blob_tracker_entries),
            .da_column_tracker_entries = @intCast(da_metrics.column_tracker_entries),
            .da_pending_blocks = @intCast(da_metrics.pending_blocks),
            .da_pending_marked_total = da_metrics.pending_marked_total,
            .da_pending_resolved_total = da_metrics.pending_resolved_total,
            .da_pending_pruned_total = da_metrics.pending_pruned_total,
        };
    }

    pub fn storageMetricsSnapshot(self: *Runtime) !DatabaseMetricsSnapshot {
        return switch (self.storage_backend) {
            .memory => |store| store.metricsSnapshot(),
            .lmdb => |store| try store.metricsSnapshot(),
        };
    }

    pub fn deinit(self: *Runtime) void {
        var graph = OwnedGraph{
            .db = self.db,
            .shared_state_graph = self.shared_state_graph,
            .cp_datastore = self.cp_datastore,
            .block_state_cache = self.block_state_cache,
            .checkpoint_state_cache = self.checkpoint_state_cache,
            .state_regen = self.state_regen,
            .op_pool = self.op_pool,
            .seen_cache = self.seen_cache,
            .seen_attesters = self.seen_attesters,
            .seen_block_attesters = self.seen_block_attesters,
            .seen_block_proposers = self.seen_block_proposers,
            .seen_attestation_data = self.seen_attestation_data,
            .sync_contribution_pool = self.sync_contribution_pool,
            .sync_committee_message_pool = self.sync_committee_message_pool,
            .beacon_proposer_cache = self.beacon_proposer_cache,
            .custody_columns = self.custody_columns,
            .kzg = self.kzg,
            .da_manager = self.da_manager,
            .archive_store = self.archive_store,
            .pending_block_ingress = self.pending_block_ingress,
            .payload_envelope_ingress = self.payload_envelope_ingress,
            .chain = self.chain,
        };
        graph.deinit(self.allocator, self.storage_backend);
        self.allocator.destroy(self);
    }
};

pub const Builder = struct {
    allocator: Allocator,
    config: *const BeaconConfig,
    storage_backend: StorageBackend,
    graph: OwnedGraph,
    active: bool = true,

    pub const FinishedBootstrap = struct {
        runtime: *Runtime,
        outcome: chain_effects.BootstrapOutcome,
    };

    pub fn init(
        allocator: Allocator,
        io: std.Io,
        config: *const BeaconConfig,
        storage_backend: StorageBackend,
        opts: RuntimeOptions,
    ) !Builder {
        return .{
            .allocator = allocator,
            .config = config,
            .storage_backend = storage_backend,
            .graph = try initOwnedGraph(allocator, io, config, storage_backend, opts),
        };
    }

    pub fn deinit(self: *Builder) void {
        if (!self.active) return;
        self.graph.deinit(self.allocator, self.storage_backend);
        self.active = false;
    }

    fn ensureActive(self: *const Builder) void {
        if (!self.active) @panic("chain.Runtime.Builder used after finish");
    }

    pub fn sharedStateGraph(self: *const Builder) *SharedStateGraph {
        self.ensureActive();
        return self.graph.shared_state_graph;
    }

    pub fn latestStateArchiveSlot(self: *const Builder) !?u64 {
        self.ensureActive();
        return self.graph.db.getLatestStateArchiveSlot();
    }

    pub fn stateArchiveAtSlot(self: *const Builder, slot: u64) !?[]const u8 {
        self.ensureActive();
        return self.graph.db.getStateArchive(slot);
    }

    fn finish(self: *Builder, outcome: chain_effects.BootstrapOutcome) !FinishedBootstrap {
        self.ensureActive();
        const runtime = try self.allocator.create(Runtime);
        runtime.* = runtimeFromOwnedGraph(self.allocator, self.config, self.storage_backend, self.graph);
        self.active = false;
        return .{
            .runtime = runtime,
            .outcome = outcome,
        };
    }

    pub fn finishGenesis(self: *Builder, genesis_state: *CachedBeaconState) !FinishedBootstrap {
        self.ensureActive();
        const outcome = try Service.init(self.graph.chain).bootstrapFromGenesis(genesis_state);
        return self.finish(outcome);
    }

    pub fn finishCheckpoint(self: *Builder, checkpoint_state: *CachedBeaconState) !FinishedBootstrap {
        self.ensureActive();
        const outcome = try Service.init(self.graph.chain).bootstrapFromCheckpoint(checkpoint_state);
        return self.finish(outcome);
    }
};

test "Runtime.Builder: finishCheckpoint repairs archive lag during bootstrap" {
    const ct = @import("consensus_types");
    const active_preset = @import("preset").active_preset;
    const preset = @import("preset").preset;
    const BatchOp = db_mod.BatchOp;

    const allocator = std.testing.allocator;
    const chain_config = if (active_preset == .mainnet)
        config_mod.mainnet.chain_config
    else
        config_mod.minimal.chain_config;

    var temp_pool = try Node.Pool.init(allocator, 256 * 5);
    defer temp_pool.deinit();

    const temp_state = try state_transition.test_utils.generateElectraState(
        allocator,
        &temp_pool,
        chain_config,
        16,
    );
    defer {
        temp_state.deinit();
        allocator.destroy(temp_state);
    }

    const config = try allocator.create(BeaconConfig);
    defer allocator.destroy(config);
    config.* = BeaconConfig.init(chain_config, (try temp_state.genesisValidatorsRoot()).*);

    const mem_store = try allocator.create(MemoryKVStore);
    mem_store.* = MemoryKVStore.init(allocator);

    var builder = try Builder.init(
        allocator,
        std.testing.io,
        config,
        .{ .memory = mem_store },
        .{},
    );
    defer builder.deinit();

    const shared_state_graph = builder.sharedStateGraph();
    const raw_state = try state_transition.test_utils.generateElectraState(
        allocator,
        shared_state_graph.pool,
        chain_config,
        16,
    );
    const validators = try raw_state.validatorsSlice(allocator);
    defer allocator.free(validators);
    try shared_state_graph.validator_pubkeys.syncFromValidators(validators);

    const checkpoint_state = try CachedBeaconState.createCachedBeaconState(
        allocator,
        raw_state,
        shared_state_graph.state_transition_metrics,
        shared_state_graph.validator_pubkeys.immutableData(shared_state_graph.config),
        .{
            .skip_sync_committee_cache = raw_state.forkSeq() == .phase0,
            .skip_sync_pubkeys = true,
        },
    );
    errdefer {
        checkpoint_state.deinit();
        allocator.destroy(checkpoint_state);
    }

    const anchor_epoch: u64 = 1024;
    const anchor_slot: u64 = anchor_epoch * preset.SLOTS_PER_EPOCH;
    const parent_root = [_]u8{0x41} ** 32;
    const state_root_hint = [_]u8{0x52} ** 32;
    const body_root = [_]u8{0x63} ** 32;
    const checkpoint_header = ct.phase0.BeaconBlockHeader.Type{
        .slot = anchor_slot,
        .proposer_index = 0,
        .parent_root = parent_root,
        .state_root = state_root_hint,
        .body_root = body_root,
    };

    try checkpoint_state.state.setSlot(anchor_slot);
    try checkpoint_state.state.setLatestBlockHeader(&checkpoint_header);

    var anchor_block_root: [32]u8 = undefined;
    try ct.phase0.BeaconBlockHeader.hashTreeRoot(&checkpoint_header, &anchor_block_root);

    const finalized_checkpoint = ct.phase0.Checkpoint.Type{
        .epoch = anchor_epoch,
        .root = anchor_block_root,
    };
    try checkpoint_state.state.setCurrentJustifiedCheckpoint(&finalized_checkpoint);
    try checkpoint_state.state.setFinalizedCheckpoint(&finalized_checkpoint);
    try checkpoint_state.state.commit();

    try builder.graph.db.putBlock(anchor_block_root, "lagging-finalized-block");

    const finalized_slot_key = db_mod.slotKey(anchor_slot);
    const finalized_slot_value = db_mod.slotKey(anchor_slot);
    const finalized_index_ops = [_]BatchOp{
        .{ .put = .{ .db = .idx_main_chain, .key = &finalized_slot_key, .value = &anchor_block_root } },
        .{ .put = .{ .db = .idx_block_root, .key = &anchor_block_root, .value = &finalized_slot_value } },
        .{ .put = .{ .db = .idx_block_parent_root, .key = &parent_root, .value = &finalized_slot_value } },
        .{ .put = .{ .db = .chain_info, .key = BeaconDB.chainInfoKeyBytes(.finalized_slot), .value = &finalized_slot_value } },
        .{ .put = .{ .db = .chain_info, .key = BeaconDB.chainInfoKeyBytes(.finalized_root), .value = &anchor_block_root } },
    };
    try builder.graph.db.writeBatch(&finalized_index_ops);

    const finished = try builder.finishCheckpoint(checkpoint_state);
    const runtime = finished.runtime;
    defer runtime.deinit();

    const archived = try runtime.db.getBlockArchive(anchor_slot);
    try std.testing.expect(archived != null);
    defer if (archived) |bytes| allocator.free(bytes);
    try std.testing.expectEqualSlices(u8, "lagging-finalized-block", archived.?);

    const archive_progress = try runtime.db.getChainInfoU64(.archive_finalized_slot);
    try std.testing.expectEqual(@as(?u64, anchor_slot), archive_progress);

    const archived_state = try runtime.db.getStateArchive(anchor_slot);
    try std.testing.expect(archived_state != null);
    defer if (archived_state) |bytes| allocator.free(bytes);

    const archived_state_epoch = try runtime.db.getChainInfoU64(.archive_state_epoch);
    try std.testing.expectEqual(@as(?u64, anchor_epoch), archived_state_epoch);

    const hot = try runtime.db.getBlock(anchor_block_root);
    defer if (hot) |bytes| allocator.free(bytes);
    try std.testing.expect(hot == null);

    try std.testing.expectEqual(anchor_slot, runtime.archive_store.last_finalized_slot);
    try std.testing.expectEqual(anchor_epoch, runtime.archive_store.last_archived_state_epoch);
}
