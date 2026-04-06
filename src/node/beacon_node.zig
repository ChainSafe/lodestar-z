//! BeaconNode: top-level orchestrator that ties all modules together.
//!
//! Owns and wires the core components of a beacon chain node:
//! - State caches (BlockStateCache, CheckpointStateCache, StateRegen)
//! - Database (BeaconDB over KVStore)
//! - Chain management (OpPool, SeenCache, HeadTracker)
//! - API context for the REST API
//! - Clock for slot/epoch timing
//!
//! The BeaconNode provides a high-level interface for:
//! - Initialization from genesis or checkpoint
//! - Gossip message processing (blocks, attestations)
//! - Req/resp request handling
//! - Block production for validators
//! - Head and sync status queries
//!
//! This is the production analog of SimBeaconNode — where SimBeaconNode
//! uses deterministic I/O and generates blocks internally, BeaconNode
//! processes blocks received from the network and produces blocks on
//! demand from validators.

const std = @import("std");
const Allocator = std.mem.Allocator;
const log = @import("log");

const types = @import("consensus_types");
const preset = @import("preset").preset;
const preset_root = @import("preset");
const fork_types = @import("fork_types");
const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const state_transition = @import("state_transition");
const bls_mod = @import("bls");
const BlsThreadPool = bls_mod.ThreadPool;
const CachedBeaconState = state_transition.CachedBeaconState;
const StateTransitionMetrics = state_transition.metrics.StateTransitionMetrics;
const chain_mod = @import("chain");
const Chain = chain_mod.Chain;
const ChainRuntime = chain_mod.Runtime;
const ChainRuntimeBuilder = chain_mod.RuntimeBuilder;
const ChainService = chain_mod.Service;
const SharedStateGraph = chain_mod.SharedStateGraph;
const ProducedBlockBody = chain_mod.ProducedBlockBody;
const ProducedBlock = chain_mod.ProducedBlock;
const ValidatorMonitor = chain_mod.ValidatorMonitor;
const BlockProductionConfig = chain_mod.BlockProductionConfig;
const ImportResult = chain_mod.ImportResult;
const networking = @import("networking");
const DiscoveryService = networking.DiscoveryService;
const DiscoveryConfig = networking.DiscoveryConfig;
const PeerManager = networking.PeerManager;
const PeerManagerConfig = networking.PeerManagerConfig;
const discv5 = @import("discv5");
const ssl = @import("ssl");
const ReqRespContext = networking.ReqRespContext;
const ResponseChunk = networking.ResponseChunk;
const Method = networking.Method;
const handleRequest = networking.handleRequest;
const freeResponseChunks = networking.freeResponseChunks;
const StatusMessage = networking.messages.StatusMessage;
const P2pService = networking.p2p_service.P2pService;
const api_mod = @import("api");
const ApiContext = api_mod.context.ApiContext;

const SlotClock = @import("clock.zig").SlotClock;
const NodeOptions = @import("options.zig").NodeOptions;
const identity_mod = @import("identity.zig");
const NodeIdentity = identity_mod.NodeIdentity;
const sync_mod = @import("sync");
const UnknownBlockSync = sync_mod.UnknownBlockSync;
const UnknownChainSync = sync_mod.UnknownChainSync;
const SyncService = sync_mod.SyncService;
const SyncMode = sync_mod.SyncMode;
const SyncServiceCallbacks = sync_mod.SyncServiceCallbacks;
const BatchBlock = sync_mod.BatchBlock;
const BatchId = sync_mod.BatchId;
const RangeSyncType = sync_mod.RangeSyncType;

const execution_mod = @import("execution");
const PayloadAttributesV3 = execution_mod.engine_api_types.PayloadAttributesV3;
const GetPayloadResponse = execution_mod.GetPayloadResponse;
const constants = @import("constants");
const Sha256 = std.crypto.hash.sha2.Sha256;
const metrics_mod = @import("metrics.zig");
pub const BeaconMetrics = metrics_mod.BeaconMetrics;

const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const BlockSource = chain_mod.blocks.BlockSource;
const gossip_handler_mod = @import("gossip_handler.zig");
pub const GossipHandler = gossip_handler_mod.GossipHandler;
const GossipIngressMetadata = gossip_handler_mod.GossipIngressMetadata;

const api_callbacks_mod = @import("api_callbacks.zig");
const block_production_mod = @import("block_production.zig");
const ExecutionRuntime = @import("execution_runtime.zig").ExecutionRuntime;
const CompletedPayloadVerification = @import("execution_runtime.zig").CompletedPayloadVerification;
const CompletedForkchoiceUpdate = @import("execution_runtime.zig").CompletedForkchoiceUpdate;
const lifecycle_mod = @import("lifecycle.zig");
const p2p_runtime_mod = @import("p2p_runtime.zig");
const sync_bridge_mod = @import("sync_bridge.zig");
const reqresp_callbacks_mod = @import("reqresp_callbacks.zig");
const gossip_node_callbacks_mod = @import("gossip_node_callbacks.zig");

// BeaconProcessor — central priority scheduling loop.
const processor_mod = @import("processor");
const BeaconProcessor = processor_mod.BeaconProcessor;
const QueueConfig = processor_mod.QueueConfig;
const WorkItem = processor_mod.WorkItem;
const WorkQueues = processor_mod.WorkQueues;
const AttestationWork = processor_mod.work_item.AttestationWork;
const AggregateWork = processor_mod.work_item.AggregateWork;
const ResolvedAggregate = processor_mod.work_item.ResolvedAggregate;
const ResolvedAttestation = processor_mod.work_item.ResolvedAttestation;
// Chain import/result types come from chain_mod (src/chain).
const SyncCallbackCtx = sync_bridge_mod.SyncCallbackCtx;

// ---------------------------------------------------------------------------
// SyncStatus
// ---------------------------------------------------------------------------

pub const SyncStatus = struct {
    head_slot: u64,
    sync_distance: u64,
    is_syncing: bool,
    is_optimistic: bool,
    el_offline: bool,
};

const SyncSegmentKey = struct {
    chain_id: u32,
    batch_id: BatchId,
    generation: u32,
};

const QueuedStateWorkOwner = union(enum) {
    generic,
    sync_segment: SyncSegmentKey,
};

const PendingSyncSegment = struct {
    key: SyncSegmentKey,
    sync_type: RangeSyncType,
    blocks: []const BatchBlock,
    before_snapshot: chain_mod.ChainSnapshot,
    started_at: std.Io.Timestamp,
    next_index: usize = 0,
    in_flight: bool = false,
    imported_count: usize = 0,
    skipped_count: usize = 0,
    failed_count: usize = 0,
    stop_after_current: bool = false,

    pub fn deinit(self: *PendingSyncSegment, allocator: Allocator) void {
        _ = allocator;
        self.* = undefined;
    }
};

const ExecutionImportWork = struct {
    owner: QueuedStateWorkOwner,
    prepared: chain_mod.PreparedBlockImport,

    pub fn deinit(self: *ExecutionImportWork, allocator: Allocator) void {
        self.prepared.deinit(allocator);
        self.* = undefined;
    }
};

const WaitingExecutionPayload = union(enum) {
    import: ExecutionImportWork,
    revalidation: chain_mod.PreparedExecutionRevalidation,

    pub fn deinit(self: *WaitingExecutionPayload, allocator: Allocator) void {
        switch (self.*) {
            .import => |*pending| pending.deinit(allocator),
            .revalidation => |*prepared| prepared.deinit(allocator),
        }
        self.* = undefined;
    }
};

const PendingExecutionPayload = struct {
    ticket: u64,
    work: union(enum) {
        import: ExecutionImportWork,
        revalidation: chain_mod.PendingExecutionRevalidation,
    },

    pub fn deinit(self: *PendingExecutionPayload, allocator: Allocator) void {
        switch (self.work) {
            .import => |*pending| pending.deinit(allocator),
            .revalidation => {},
        }
        self.* = undefined;
    }
};

// ---------------------------------------------------------------------------
// HeadInfo — canonical version from chain/types.zig.
// ---------------------------------------------------------------------------

pub const HeadInfo = chain_mod.HeadInfo;

pub const BeaconNode = struct {
    pub const PublishedProposalKey = struct {
        slot: u64,
        proposer_index: u64,
    };

    pub const InitConfig = struct {
        options: NodeOptions,
        db_path: ?[]const u8 = null,
        node_identity: NodeIdentity,
        jwt_secret: ?[32]u8 = null,
        bootstrap_peers: []const []const u8 = &.{},
        discovery_bootnodes: []const []const u8 = &.{},
        identify_agent_version: ?[]const u8 = null,
        metrics: ?*BeaconMetrics = null,
        state_transition_metrics: *StateTransitionMetrics = state_transition.metrics.noop(),
    };

    pub const Builder = struct {
        allocator: Allocator,
        io: std.Io,
        config: *const BeaconConfig,
        node_options: NodeOptions,
        runtime_builder: ChainRuntimeBuilder,
        block_bls_thread_pool: *BlsThreadPool,
        gossip_bls_thread_pool: *BlsThreadPool,
        node_identity: ?NodeIdentity,
        execution_runtime: ?*ExecutionRuntime,
        api_context: ?*ApiContext,
        api_node_identity: ?*api_mod.types.NodeIdentity,
        event_bus: ?*api_mod.EventBus,
        metrics: ?*BeaconMetrics = null,
        bootstrap_peers: []const []const u8 = &.{},
        discovery_bootnodes: []const []const u8 = &.{},
        identify_agent_version: ?[]const u8 = null,
        finished: bool = false,

        pub fn init(
            allocator: Allocator,
            io: std.Io,
            beacon_config: *const BeaconConfig,
            init_config: InitConfig,
        ) !Builder {
            return lifecycle_mod.initBuilder(allocator, io, beacon_config, init_config);
        }

        pub fn deinit(self: *Builder) void {
            lifecycle_mod.deinitBuilder(self);
        }

        fn ensureActive(self: *const Builder) void {
            if (self.finished) @panic("BeaconNode.Builder used after finish");
        }

        pub fn nodeIdentity(self: *const Builder) *const NodeIdentity {
            self.ensureActive();
            return &(self.node_identity orelse @panic("BeaconNode.Builder missing node identity"));
        }

        pub fn sharedStateGraph(self: *const Builder) *SharedStateGraph {
            self.ensureActive();
            return self.runtime_builder.sharedStateGraph();
        }

        pub fn latestStateArchiveSlot(self: *const Builder) !?u64 {
            self.ensureActive();
            return self.runtime_builder.latestStateArchiveSlot();
        }

        pub fn stateArchiveAtSlot(self: *const Builder, slot: u64) !?[]const u8 {
            self.ensureActive();
            return self.runtime_builder.stateArchiveAtSlot(slot);
        }

        pub fn finishGenesis(self: *Builder, genesis_state: *CachedBeaconState) !*BeaconNode {
            return lifecycle_mod.finishBuilderGenesis(self, genesis_state);
        }

        pub fn finishCheckpoint(self: *Builder, checkpoint_state: *CachedBeaconState) !*BeaconNode {
            return lifecycle_mod.finishBuilderCheckpoint(self, checkpoint_state);
        }
    };

    allocator: Allocator,
    config: *const BeaconConfig,

    // Chain runtime ownership root.
    chain_runtime: *ChainRuntime,

    // Chain coordinator (delegates to all chain components)
    chain: *Chain,

    // Clock
    clock: ?SlotClock,

    // API context
    api_context: *ApiContext,
    api_node_identity: *api_mod.types.NodeIdentity,
    api_bindings: ?*api_callbacks_mod.ApiBindings = null,
    /// EventBus for SSE beacon chain events. Owned by BeaconNode, wired into
    /// ApiContext.event_bus and Chain.notification_sink.
    event_bus: *api_mod.EventBus,

    // Prometheus metrics (real or noop depending on --metrics flag).
    // Optional pointer so BeaconNode doesn't own the metrics instance —
    // it's allocated by main() and passed in.
    metrics: ?*BeaconMetrics = null,

    // HTTP server for the Beacon REST API (lazy-initialized via startApi).
    http_server: ?api_mod.HttpServer = null,

    // Discovery service (lazy-initialized via startP2p).
    discovery_service: ?*DiscoveryService = null,

    // Peer manager — tracks peer connections, scoring, and lifecycle (v2).
    peer_manager: ?*PeerManager = null,

    // Validator-driven subnet state for gossip subscriptions, metadata, and
    // peer prioritization.
    subnet_service: ?*networking.SubnetService = null,
    gossip_attestation_subscriptions: networking.peer_info.AttnetsBitfield = networking.peer_info.AttnetsBitfield.initEmpty(),
    gossip_sync_subscriptions: networking.peer_info.SyncnetsBitfield = networking.peer_info.SyncnetsBitfield.initEmpty(),

    // P2P service (lazy-initialized via startP2p).
    // Owns the libp2p Switch, gossipsub service, and gossip adapter.
    p2p_service: ?P2pService = null,

    // Req/resp context and server policy used by the P2P service.
    // The callback context uses self.allocator as scratch; block bytes returned
    // by callbacks are copied by the handler before the callback returns.
    p2p_req_resp_ctx: ?*ReqRespContext = null,
    p2p_req_resp_policy: ?*networking.ReqRespServerPolicy = null,
    req_resp_rate_limiter: ?*networking.RateLimiter = null,
    p2p_request_ctx: ?*reqresp_callbacks_mod.RequestContext = null,

    // Sync controller — wires P2P events into the sync pipeline.
    // Optional: nil until initialized (e.g. when running without P2P).

    // Last known active fork digest — used to detect fork transitions
    // so we can resubscribe gossip topics under the new fork digest.
    last_active_fork_digest: [4]u8 = [4]u8{ 0, 0, 0, 0 },

    // Last slot for which chain.onSlot() was applied.
    last_slot_tick: ?u64 = null,

    // Sync subsystem components (lazily initialized when P2P starts).

    sync_service_inst: ?*SyncService = null,
    sync_callback_ctx: ?*SyncCallbackCtx = null, // bridges to P2P transport
    queued_state_work_owners: std.ArrayListUnmanaged(QueuedStateWorkOwner) = .empty,
    waiting_execution_payloads: std.ArrayListUnmanaged(WaitingExecutionPayload) = .empty,
    pending_execution_payloads: std.ArrayListUnmanaged(PendingExecutionPayload) = .empty,
    next_execution_ticket: u64 = 1,
    pending_sync_segments: std.ArrayListUnmanaged(PendingSyncSegment) = .empty,

    // GossipHandler — lazily initialized when P2P starts (owns its SeenSets).
    gossip_handler: ?*GossipHandler = null,

    // BeaconProcessor — priority-based work queue scheduler.
    // Routes gossip messages through priority queues instead of inline processing.
    // Instantiated in init(); drained by the main sync/gossip loop.
    beacon_processor: ?*BeaconProcessor = null,

    // Unknown block sync — queues blocks whose parent is not yet known.
    // Initialized eagerly in init(); used by the gossip block import path.
    unknown_block_sync: UnknownBlockSync,

    // Unknown chain sync — backwards header chain sync for blocks/roots
    // not in fork choice. Tracks multiple chains of headers backwards
    // until they link to our known chain, then hands off to forward sync.
    // Complements unknown_block_sync with a header-only approach that
    // handles extended non-finality without OOMing.
    unknown_chain_sync: UnknownChainSync,

    // Validator monitor — optional on-chain performance tracker for specified validators.
    validator_monitor: ?*ValidatorMonitor = null,

    // Execution runtime owns EL transport, builder clients, and payload-build cache.
    execution_runtime: *ExecutionRuntime,

    /// Process-local guard against publishing conflicting blocks for the same
    /// proposer/slot through the BN API.
    published_proposals_mu: std.atomic.Mutex = .unlocked,
    published_proposals: std.AutoHashMap(PublishedProposalKey, [32]u8),

    /// I/O context for runtime operations.
    io: std.Io,

    /// BLS thread pool reserved for block STF verification work.
    block_bls_thread_pool: *BlsThreadPool,
    /// BLS thread pool reserved for gossip attestation/aggregate verification.
    gossip_bls_thread_pool: *BlsThreadPool,
    pending_gossip_bls_batches: std.ArrayListUnmanaged(PendingGossipBlsBatch) = .empty,

    // Node identity — secp256k1 keypair loaded/generated during init().
    node_identity: NodeIdentity,

    // Genesis validators root — set by initFromGenesis, used for fork digest computation.
    genesis_validators_root: [32]u8 = [_]u8{0} ** 32,

    /// Earliest slot this node can honestly serve over req/resp.
    earliest_available_slot: u64 = 0,

    // Node configuration options — stored for lazy-initialized components.
    node_options: NodeOptions = .{},

    // Explicit bootstrap peers to dial during startup.
    bootstrap_peers: []const []const u8 = &.{},

    // Discovery seed ENRs prepared by the launcher.
    discovery_bootnodes: []const []const u8 = &.{},

    // Identify agent version exposed on libp2p identify. Null hides it.
    identify_agent_version: ?[]const u8 = null,

    /// Set to true to request graceful shutdown of all event loops.
    shutdown_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// Signal all loops to stop.
    pub fn requestShutdown(self: *BeaconNode) void {
        self.shutdown_requested.store(true, .release);
        if (self.http_server) |*srv| srv.shutdown(self.io);
    }

    /// Low-level unbootstrapped constructor used by tests and bring-up code.
    ///
    /// Production callers should prefer `BeaconNode.Builder`, which only yields
    /// a live node after genesis/checkpoint bootstrap is complete.
    pub fn initUnbootstrapped(
        allocator: Allocator,
        io: std.Io,
        beacon_config: *const BeaconConfig,
        init_config: InitConfig,
    ) !*BeaconNode {
        return lifecycle_mod.init(allocator, io, beacon_config, init_config);
    }

    /// Clean up all owned resources.
    pub fn deinit(self: *BeaconNode) void {
        lifecycle_mod.deinit(self);
    }

    /// Initialize from a genesis state.
    ///
    /// Loads the genesis state into caches, sets up the head tracker at slot 0,
    /// and configures the clock from the genesis time.
    pub fn initFromGenesis(self: *BeaconNode, genesis_state: *CachedBeaconState) !void {
        try lifecycle_mod.initFromGenesis(self, genesis_state);
    }

    /// Initialize the beacon node from a checkpoint state at an arbitrary slot.
    ///
    /// Similar to initFromGenesis(), but seeds the fork choice at the
    /// checkpoint's slot rather than slot 0. Used for:
    /// - Checkpoint sync from URL (--checkpoint-sync-url)
    /// - Checkpoint sync from file (--checkpoint-state)
    /// - Resume from DB (loading persisted state from previous run)
    ///
    /// The checkpoint state must be a finalized state — its latest_block_header
    /// defines the anchor block root for fork choice.
    pub fn initFromCheckpoint(self: *BeaconNode, checkpoint_state: *CachedBeaconState) !void {
        try lifecycle_mod.initFromCheckpoint(self, checkpoint_state);
    }
    pub fn ingestBlock(
        self: *BeaconNode,
        any_signed: AnySignedBeaconBlock,
        source: BlockSource,
    ) !ReadyIngressResult {
        const ready = try self.chainService().prepareBlockInput(any_signed, source);
        return self.completeReadyIngressDetailed(ready, null);
    }

    pub const ReadyIngressResult = union(enum) {
        ignored,
        queued,
        imported: ImportResult,
    };

    pub fn ingestRawBlockBytes(
        self: *BeaconNode,
        block_bytes: []const u8,
        source: BlockSource,
    ) !ReadyIngressResult {
        const ready = try self.chainService().prepareRawBlockInput(block_bytes, source);
        return self.completeReadyIngressDetailed(ready, block_bytes);
    }

    pub fn importReadyBlock(
        self: *BeaconNode,
        ready: chain_mod.ReadyBlockInput,
    ) !ReadyIngressResult {
        return self.completeReadyIngressDetailed(ready, null);
    }

    pub fn completeReadyIngress(
        self: *BeaconNode,
        ready: chain_mod.ReadyBlockInput,
        raw_block_bytes: ?[]const u8,
    ) !?ImportResult {
        return switch (try self.completeReadyIngressDetailed(ready, raw_block_bytes)) {
            .ignored, .queued => null,
            .imported => |result| result,
        };
    }

    fn completeReadyIngressDetailed(
        self: *BeaconNode,
        ready: chain_mod.ReadyBlockInput,
        raw_block_bytes: ?[]const u8,
    ) !ReadyIngressResult {
        var owned_ready = ready;
        const t0 = std.Io.Clock.awake.now(self.io);

        const planned = self.chainService().planReadyBlockImport(&owned_ready) catch |err| {
            switch (err) {
                error.ParentUnknown => {
                    if (raw_block_bytes) |bytes| {
                        self.queueOrphanBlock(owned_ready.block, bytes);
                    } else {
                        const serialized = owned_ready.block.serialize(self.allocator) catch |serialize_err| {
                            owned_ready.deinit(self.allocator);
                            return serialize_err;
                        };
                        defer self.allocator.free(serialized);
                        self.queueOrphanBlock(owned_ready.block, serialized);
                    }
                    owned_ready.deinit(self.allocator);
                    return .ignored;
                },
                error.AlreadyKnown, error.WouldRevertFinalizedSlot => {
                    owned_ready.deinit(self.allocator);
                    return .ignored;
                },
                else => {
                    owned_ready.deinit(self.allocator);
                    return err;
                },
            }
        };

        try self.queued_state_work_owners.ensureUnusedCapacity(self.allocator, 1);
        if (try self.chainService().tryQueuePlannedReadyBlockImport(planned)) {
            self.queued_state_work_owners.appendAssumeCapacity(.generic);
            return .queued;
        }

        const completed = self.chainService().executePlannedReadyBlockImportSync(planned);
        switch (completed) {
            .failure => {
                const outcome = try self.chainService().finishCompletedReadyBlockImport(completed);
                const result = try self.finishImportOutcome(t0, outcome);
                self.processPendingChildren(result.block_root);
                return .{ .imported = result };
            },
            .success => |prepared| {
                self.queuePreparedBlockImportExecution(.generic, prepared);
                return .queued;
            },
        }
    }

    pub fn processPendingBlockStateWork(self: *BeaconNode) bool {
        var did_work = false;

        while (self.chainService().popCompletedReadyBlockImport()) |completed| {
            did_work = true;
            const owner: QueuedStateWorkOwner = if (self.queued_state_work_owners.items.len > 0)
                self.queued_state_work_owners.orderedRemove(0)
            else
                .generic;

            switch (completed) {
                .failure => switch (owner) {
                    .generic => self.finishGenericQueuedBlockImport(completed),
                    .sync_segment => |key| self.finishSyncSegmentQueuedBlockImport(key, completed),
                },
                .success => |prepared| {
                    self.queuePreparedBlockImportExecution(owner, prepared);
                },
            }
        }

        return did_work;
    }

    pub fn processPendingExecutionPayloadVerifications(self: *BeaconNode) bool {
        var did_work = false;

        while (self.execution_runtime.popCompletedPayloadVerification()) |completed| {
            did_work = true;
            self.observeExecutionPayloadVerification(completed);

            const pending_index = findPendingExecutionPayloadIndex(self, completed.ticket) orelse {
                log.logger(.node).warn("missing pending execution payload for completed newPayload result", .{});
                self.dispatchWaitingExecutionPayloads();
                continue;
            };

            var pending = self.pending_execution_payloads.orderedRemove(pending_index);
            switch (pending.work) {
                .import => |import_work| {
                    const exec_status = chain_mod.blocks.executionStatusFromNewPayloadResult(
                        completed.result,
                        import_work.prepared.opts,
                    ) catch |err| {
                        self.finishPreparedQueuedBlockImportError(import_work.owner, import_work.prepared, err);
                        pending = undefined;
                        self.dispatchWaitingExecutionPayloads();
                        continue;
                    };

                    self.finishPreparedQueuedBlockImport(import_work.owner, import_work.prepared, exec_status);
                    pending = undefined;
                },
                .revalidation => |revalidation| {
                    const outcome = self.chainService().finishCurrentOptimisticHeadRevalidation(
                        revalidation,
                        completed.result,
                    ) catch |err| {
                        log.logger(.node).warn("execution revalidation finish failed: {}", .{err});
                        pending = undefined;
                        self.dispatchWaitingExecutionPayloads();
                        continue;
                    };
                    if (outcome) |revalidated| {
                        self.finishExecutionRevalidationOutcome(revalidated);
                    }
                    pending = undefined;
                },
            }
            self.dispatchWaitingExecutionPayloads();
        }

        return did_work;
    }

    pub fn processPendingExecutionForkchoiceUpdates(self: *BeaconNode) bool {
        var did_work = false;

        while (self.execution_runtime.popCompletedForkchoiceUpdate()) |completed| {
            did_work = true;
            self.observeExecutionForkchoiceUpdate(completed);
        }

        return did_work;
    }

    fn queuePreparedBlockImportExecution(
        self: *BeaconNode,
        owner: QueuedStateWorkOwner,
        prepared: chain_mod.PreparedBlockImport,
    ) void {
        self.waiting_execution_payloads.append(self.allocator, .{ .import = .{
            .owner = owner,
            .prepared = prepared,
        } }) catch {
            const owned_prepared = prepared;
            self.finishPreparedQueuedBlockImportError(owner, owned_prepared, error.OutOfMemory);
            return;
        };
        self.dispatchWaitingExecutionPayloads();
    }

    pub fn queueCurrentOptimisticHeadRevalidation(self: *BeaconNode) void {
        if (self.hasPendingExecutionRevalidation()) return;

        var prepared = self.chainService().prepareCurrentOptimisticHeadRevalidation() catch |err| {
            std.log.warn("Optimistic head revalidation planning failed: {}", .{err});
            return;
        } orelse return;

        self.waiting_execution_payloads.append(self.allocator, .{ .revalidation = prepared }) catch |err| {
            prepared.deinit(self.allocator);
            std.log.warn("failed to queue optimistic head revalidation: {}", .{err});
            return;
        };
        self.dispatchWaitingExecutionPayloads();
    }

    fn hasPendingExecutionRevalidation(self: *const BeaconNode) bool {
        for (self.waiting_execution_payloads.items) |pending| {
            if (pending == .revalidation) return true;
        }
        for (self.pending_execution_payloads.items) |pending| {
            if (pending.work == .revalidation) return true;
        }
        return false;
    }

    fn dispatchWaitingExecutionPayloads(self: *BeaconNode) void {
        while (self.pending_execution_payloads.items.len == 0 and self.waiting_execution_payloads.items.len > 0) {
            if (!self.execution_runtime.canAcceptPayloadVerification()) break;

            var waiting = self.waiting_execution_payloads.orderedRemove(0);
            self.pending_execution_payloads.ensureUnusedCapacity(self.allocator, 1) catch |err| {
                waiting.deinit(self.allocator);
                std.log.warn("failed to allocate pending execution payload slot: {}", .{err});
                continue;
            };

            const ticket = self.next_execution_ticket;
            self.next_execution_ticket += 1;

            switch (waiting) {
                .import => |pending| {
                    if (pending.prepared.opts.skip_execution or
                        pending.prepared.block_input.block.forkSeq().lt(.bellatrix) or
                        !self.execution_runtime.hasExecutionEngine())
                    {
                        self.finishPreparedQueuedBlockImport(pending.owner, pending.prepared, .pre_merge);
                        waiting = undefined;
                        continue;
                    }

                    var request = chain_mod.ports.execution.makeNewPayloadRequest(
                        self.allocator,
                        pending.prepared.block_input.block,
                    ) catch |err| {
                        self.finishPreparedQueuedBlockImportError(pending.owner, pending.prepared, err);
                        waiting = undefined;
                        continue;
                    } orelse {
                        self.finishPreparedQueuedBlockImport(pending.owner, pending.prepared, .pre_merge);
                        waiting = undefined;
                        continue;
                    };

                    if (self.execution_runtime.submitPayloadVerification(ticket, request) catch false) {
                        self.pending_execution_payloads.appendAssumeCapacity(.{
                            .ticket = ticket,
                            .work = .{ .import = pending },
                        });
                        waiting = undefined;
                    } else {
                        request.deinit(self.allocator);
                        self.waiting_execution_payloads.insert(self.allocator, 0, .{ .import = pending }) catch |err| {
                            self.finishPreparedQueuedBlockImportError(pending.owner, pending.prepared, err);
                        };
                        waiting = undefined;
                        break;
                    }
                },
                .revalidation => |prepared| {
                    if (!self.execution_runtime.hasExecutionEngine()) {
                        var owned_prepared = prepared;
                        owned_prepared.deinit(self.allocator);
                        waiting = undefined;
                        continue;
                    }

                    const request = prepared.request;
                    if (self.execution_runtime.submitPayloadVerification(ticket, request) catch false) {
                        self.pending_execution_payloads.appendAssumeCapacity(.{
                            .ticket = ticket,
                            .work = .{ .revalidation = prepared.pending },
                        });
                        waiting = undefined;
                    } else {
                        self.waiting_execution_payloads.insert(self.allocator, 0, .{ .revalidation = prepared }) catch |err| {
                            var owned_prepared = prepared;
                            owned_prepared.deinit(self.allocator);
                            std.log.warn("failed to requeue optimistic head revalidation: {}", .{err});
                        };
                        waiting = undefined;
                        break;
                    }
                },
            }
        }
    }

    fn findPendingExecutionPayloadIndex(self: *BeaconNode, ticket: u64) ?usize {
        for (self.pending_execution_payloads.items, 0..) |pending, i| {
            if (pending.ticket == ticket) return i;
        }
        return null;
    }

    fn observeExecutionPayloadVerification(
        self: *BeaconNode,
        completed: CompletedPayloadVerification,
    ) void {
        if (self.metrics) |m| {
            m.execution_new_payload_seconds.observe(completed.elapsed_s);
            switch (completed.result) {
                .valid => m.execution_payload_valid_total.incr(),
                .invalid, .invalid_block_hash => m.execution_payload_invalid_total.incr(),
                .syncing, .accepted => m.execution_payload_syncing_total.incr(),
                .unavailable => if (completed.had_engine) m.execution_errors_total.incr(),
            }
        }
    }

    fn observeExecutionForkchoiceUpdate(
        self: *BeaconNode,
        completed: CompletedForkchoiceUpdate,
    ) void {
        if (self.metrics) |m| {
            m.execution_forkchoice_updated_seconds.observe(completed.elapsed_s);
            if (completed.status == .failed and completed.had_engine) {
                m.execution_errors_total.incr();
            }
        }

        const fc_state = completed.update.state;
        switch (completed.status) {
            .success => {
                if (completed.payload_id) |payload_id| {
                    std.log.info("forkchoiceUpdated: payload building started, id={s}", .{
                        &std.fmt.bytesToHex(payload_id[0..8], .lower),
                    });
                }
                std.log.info("forkchoiceUpdated: status={s} head={s}... safe={s}... finalized={s}...", .{
                    @tagName(completed.payload_status.?),
                    &std.fmt.bytesToHex(fc_state.head_block_hash[0..4], .lower),
                    &std.fmt.bytesToHex(fc_state.safe_block_hash[0..4], .lower),
                    &std.fmt.bytesToHex(fc_state.finalized_block_hash[0..4], .lower),
                });

                switch (completed.request) {
                    .plain => {},
                    .payload_preparation => |payload_preparation| {
                        self.event_bus.emit(.{ .payload_attributes = .{
                            .proposer_index = 0,
                            .proposal_slot = payload_preparation.slot,
                            .parent_block_number = 0,
                            .parent_block_root = completed.update.beacon_block_root,
                            .parent_block_hash = fc_state.head_block_hash,
                            .timestamp = payload_preparation.timestamp,
                            .prev_randao = payload_preparation.prev_randao,
                            .suggested_fee_recipient = payload_preparation.suggested_fee_recipient,
                        } });
                    },
                }
            },
            .unavailable => {},
            .failed => {},
        }
    }

    fn finishPreparedQueuedBlockImport(
        self: *BeaconNode,
        owner: QueuedStateWorkOwner,
        prepared: chain_mod.PreparedBlockImport,
        exec_status: chain_mod.ExecutionStatus,
    ) void {
        switch (owner) {
            .generic => self.finishGenericPreparedQueuedBlockImport(prepared, exec_status),
            .sync_segment => |key| self.finishSyncSegmentPreparedQueuedBlockImport(key, prepared, exec_status),
        }
    }

    fn finishGenericPreparedQueuedBlockImport(
        self: *BeaconNode,
        prepared: chain_mod.PreparedBlockImport,
        exec_status: chain_mod.ExecutionStatus,
    ) void {
        const t0 = std.Io.Clock.awake.now(self.io);
        var owned_prepared = prepared;
        defer {
            owned_prepared.deinit(self.allocator);
            owned_prepared = undefined;
        }

        const outcome = self.chainService().finishPreparedReadyBlockImport(owned_prepared, exec_status) catch |err| {
            log.logger(.node).warn("deferred block execution commit failed: {}", .{err});
            return;
        };
        const result = self.finishImportOutcome(t0, outcome) catch |err| {
            log.logger(.node).warn("deferred block import commit failed: {}", .{err});
            return;
        };
        self.processPendingChildren(result.block_root);
    }

    fn finishSyncSegmentPreparedQueuedBlockImport(
        self: *BeaconNode,
        key: SyncSegmentKey,
        prepared: chain_mod.PreparedBlockImport,
        exec_status: chain_mod.ExecutionStatus,
    ) void {
        const index = findPendingSyncSegmentIndex(self, key) orelse {
            log.logger(.node).warn("missing pending sync segment for prepared block commit", .{});
            self.finishGenericPreparedQueuedBlockImport(prepared, exec_status);
            return;
        };

        var segment = &self.pending_sync_segments.items[index];
        segment.in_flight = false;
        segment.next_index += 1;

        var owned_prepared = prepared;
        defer {
            owned_prepared.deinit(self.allocator);
            owned_prepared = undefined;
        }

        const outcome = self.chainService().finishPreparedReadyBlockImport(owned_prepared, exec_status) catch |err| {
            switch (err) {
                error.ExecutionPayloadInvalid => {
                    segment.failed_count += 1;
                    segment.stop_after_current = true;
                },
                else => {
                    segment.failed_count += 1;
                    log.logger(.node).warn("deferred sync segment block commit failed: {}", .{err});
                },
            }
            return;
        };

        segment.imported_count += 1;
        self.processPendingChildren(outcome.result.block_root);
    }

    fn finishPreparedQueuedBlockImportError(
        self: *BeaconNode,
        owner: QueuedStateWorkOwner,
        prepared: chain_mod.PreparedBlockImport,
        err: anyerror,
    ) void {
        switch (owner) {
            .generic => {
                var owned_prepared = prepared;
                owned_prepared.deinit(self.allocator);
                log.logger(.node).warn("deferred block execution verification failed: {}", .{err});
            },
            .sync_segment => |key| {
                const index = findPendingSyncSegmentIndex(self, key) orelse {
                    var owned_prepared = prepared;
                    owned_prepared.deinit(self.allocator);
                    log.logger(.node).warn("missing pending sync segment for execution verification failure", .{});
                    return;
                };

                var segment = &self.pending_sync_segments.items[index];
                segment.in_flight = false;
                segment.next_index += 1;

                switch (err) {
                    error.AlreadyKnown, error.WouldRevertFinalizedSlot, error.GenesisBlock => {
                        segment.skipped_count += 1;
                    },
                    error.ExecutionPayloadInvalid => {
                        segment.failed_count += 1;
                        segment.stop_after_current = true;
                    },
                    else => {
                        segment.failed_count += 1;
                        log.logger(.node).warn("deferred sync segment execution verification failed: {}", .{err});
                    },
                }

                var owned_prepared = prepared;
                owned_prepared.deinit(self.allocator);
            },
        }
    }

    pub fn processRangeSyncSegment(
        self: *BeaconNode,
        raw_blocks: []const chain_mod.RawBlockBytes,
    ) !void {
        const t0 = std.Io.Clock.awake.now(self.io);
        const outcome = try self.chainService().processRangeSyncSegment(raw_blocks);
        const all_failed = outcome.imported_count == 0 and outcome.skipped_count == 0 and outcome.failed_count > 0;
        self.finishSegmentImportOutcome(t0, outcome);
        if (all_failed) return error.AllBlocksFailed;
    }

    pub fn enqueueSyncSegment(
        self: *BeaconNode,
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
        blocks: []const BatchBlock,
        sync_type: RangeSyncType,
    ) !void {
        const key: SyncSegmentKey = .{
            .chain_id = chain_id,
            .batch_id = batch_id,
            .generation = generation,
        };
        if (findPendingSyncSegmentIndex(self, key) != null) return;

        try self.pending_sync_segments.append(self.allocator, .{
            .key = key,
            .sync_type = sync_type,
            .blocks = blocks,
            .before_snapshot = self.chainService().query().currentSnapshot(),
            .started_at = std.Io.Clock.awake.now(self.io),
        });
    }

    pub fn drivePendingSyncSegments(self: *BeaconNode) bool {
        var did_work = false;
        var i: usize = 0;

        while (i < self.pending_sync_segments.items.len) {
            if (self.pending_sync_segments.items[i].in_flight) {
                i += 1;
                continue;
            }

            if (self.pending_sync_segments.items[i].stop_after_current or
                self.pending_sync_segments.items[i].next_index >= self.pending_sync_segments.items[i].blocks.len)
            {
                finalizePendingSyncSegment(self, i);
                did_work = true;
                continue;
            }

            const started = startPendingSyncSegmentBlock(self, i) catch |err| {
                log.logger(.node).warn("failed to start pending sync segment block: {}", .{err});
                self.pending_sync_segments.items[i].stop_after_current = true;
                did_work = true;
                continue;
            };
            did_work = started or did_work;
            if (!started) {
                const segment = &self.pending_sync_segments.items[i];
                if (segment.stop_after_current or segment.next_index >= segment.blocks.len) {
                    did_work = true;
                    continue;
                }
                break;
            }
            i += 1;
        }

        return did_work;
    }

    fn finishImportOutcome(
        self: *BeaconNode,
        t0: std.Io.Timestamp,
        outcome: chain_mod.ImportOutcome,
    ) !ImportResult {
        const result = outcome.result;

        // Notify EL of fork choice update after each block import.
        if (outcome.effects.forkchoice_update) |update| self.queueExecutionForkchoiceUpdate(update);

        const t1 = std.Io.Clock.awake.now(self.io);
        const elapsed_s: f64 = @as(f64, @floatFromInt(t1.nanoseconds - t0.nanoseconds)) / 1e9;

        // Update metrics.
        if (self.metrics) |m| {
            m.blocks_imported_total.incr();
            m.block_import_seconds.observe(elapsed_s);
            m.head_slot.set(outcome.snapshot.head.slot);
            m.finalized_epoch.set(outcome.snapshot.finalized.epoch);
            m.justified_epoch.set(outcome.snapshot.justified.epoch);
            // Encode first 8 bytes of block root as u64 for change detection.
            m.head_root.set(std.mem.readInt(u64, outcome.snapshot.head.root[0..8], .big));
        }
        self.updateSyncProgress(outcome.snapshot);

        if (result.epoch_transition) {
            if (outcome.effects.finalized_checkpoint) |finalized| {
                self.unknown_chain_sync.onFinalized(finalized.slot);
            }
            log.logger(.chain).info("epoch transition", .{
                .slot = result.slot,
                .finalized_epoch = outcome.snapshot.finalized.epoch,
                .justified_epoch = outcome.snapshot.justified.epoch,
            });
        }

        log.logger(.chain).verbose("block imported", .{
            .slot = result.slot,
            .root = result.block_root,
            .epoch_transition = result.epoch_transition,
        });

        return result;
    }

    fn finishSegmentImportOutcome(
        self: *BeaconNode,
        t0: std.Io.Timestamp,
        outcome: chain_mod.SegmentImportOutcome,
    ) void {
        if (outcome.effects.forkchoice_update) |update| self.queueExecutionForkchoiceUpdate(update);

        const t1 = std.Io.Clock.awake.now(self.io);
        const elapsed_s: f64 = @as(f64, @floatFromInt(t1.nanoseconds - t0.nanoseconds)) / 1e9;

        if (self.metrics) |m| {
            if (outcome.imported_count > 0) {
                m.blocks_imported_total.incrBy(@intCast(outcome.imported_count));
                m.block_import_seconds.observe(elapsed_s);
            }
            m.head_slot.set(outcome.snapshot.head.slot);
            m.finalized_epoch.set(outcome.snapshot.finalized.epoch);
            m.justified_epoch.set(outcome.snapshot.justified.epoch);
            m.head_root.set(std.mem.readInt(u64, outcome.snapshot.head.root[0..8], .big));
        }
        self.updateSyncProgress(outcome.snapshot);

        if (outcome.effects.finalized_checkpoint) |finalized| {
            self.unknown_chain_sync.onFinalized(finalized.slot);
        }

        log.logger(.chain).info("range sync segment imported", .{
            .imported = outcome.imported_count,
            .skipped = outcome.skipped_count,
            .failed = outcome.failed_count,
            .head_slot = outcome.snapshot.head.slot,
            .finalized_epoch = outcome.snapshot.finalized.epoch,
        });
    }

    fn finishGenericQueuedBlockImport(
        self: *BeaconNode,
        completed: chain_mod.CompletedBlockImport,
    ) void {
        const t0 = std.Io.Clock.awake.now(self.io);
        const outcome = self.chainService().finishCompletedReadyBlockImport(completed) catch |err| {
            log.logger(.node).warn("deferred block state work failed: {}", .{err});
            return;
        };
        const result = self.finishImportOutcome(t0, outcome) catch |err| {
            log.logger(.node).warn("deferred block import commit failed: {}", .{err});
            return;
        };
        self.processPendingChildren(result.block_root);
    }

    fn finishSyncSegmentQueuedBlockImport(
        self: *BeaconNode,
        key: SyncSegmentKey,
        completed: chain_mod.CompletedBlockImport,
    ) void {
        const index = findPendingSyncSegmentIndex(self, key) orelse {
            log.logger(.node).warn("missing pending sync segment for completed block work", .{});
            self.finishGenericQueuedBlockImport(completed);
            return;
        };

        var segment = &self.pending_sync_segments.items[index];
        segment.in_flight = false;
        segment.next_index += 1;

        const outcome = self.chainService().finishCompletedReadyBlockImport(completed) catch |err| {
            switch (err) {
                error.AlreadyKnown, error.WouldRevertFinalizedSlot, error.GenesisBlock => {
                    segment.skipped_count += 1;
                },
                error.ExecutionPayloadInvalid => {
                    segment.failed_count += 1;
                    segment.stop_after_current = true;
                },
                else => {
                    segment.failed_count += 1;
                    log.logger(.node).warn("deferred sync segment block commit failed: {}", .{err});
                },
            }
            return;
        };

        segment.imported_count += 1;

        self.processPendingChildren(outcome.result.block_root);
    }

    pub fn finishExecutionRevalidationOutcome(
        self: *BeaconNode,
        outcome: chain_mod.ExecutionRevalidationOutcome,
    ) void {
        if (outcome.forkchoice_update) |update| self.queueExecutionForkchoiceUpdate(update);

        if (self.metrics) |m| {
            m.head_slot.set(outcome.snapshot.head.slot);
            m.finalized_epoch.set(outcome.snapshot.finalized.epoch);
            m.justified_epoch.set(outcome.snapshot.justified.epoch);
            m.head_root.set(std.mem.readInt(u64, outcome.snapshot.head.root[0..8], .big));
        }
        self.updateSyncProgress(outcome.snapshot);

        if (outcome.head_changed) {
            log.logger(.chain).info("execution revalidation changed head", .{
                .head_slot = outcome.snapshot.head.slot,
                .head_root = outcome.snapshot.head.root,
                .finalized_epoch = outcome.snapshot.finalized.epoch,
            });
        }
    }

    fn updateSyncProgress(self: *BeaconNode, snapshot: chain_mod.ChainSnapshot) void {
        if (self.sync_service_inst) |svc| {
            svc.onHeadUpdate(snapshot.head.slot);
            svc.onFinalizedUpdate(snapshot.finalized.epoch);
        }
    }

    /// Store a blob sidecar received via gossip or req/resp.
    ///
    /// Blob sidecars arrive separately from blocks (via GossipSub or BlobSidecarsByRoot).
    /// All sidecars for a given block root are stored together as raw bytes, keyed by root.
    /// Callers that have disaggregated sidecar data should aggregate before calling this.
    pub fn importBlobSidecar(self: *BeaconNode, root: [32]u8, data: []const u8) !void {
        try self.chainService().importBlobSidecar(root, data);
    }

    pub fn ingestBlobSidecar(
        self: *BeaconNode,
        root: [32]u8,
        blob_index: u64,
        slot: u64,
        data: []const u8,
    ) !?chain_mod.ReadyBlockInput {
        return self.chainService().ingestBlobSidecar(root, blob_index, slot, data);
    }

    /// Store a data column sidecar received via gossip or req/resp (PeerDAS / Fulu).
    ///
    /// Data column sidecars arrive individually, keyed by (block_root, column_index).
    /// Each sidecar is stored independently to support per-column availability tracking.
    pub fn importDataColumnSidecar(self: *BeaconNode, root: [32]u8, column_index: u64, data: []const u8) !void {
        try self.chainService().importDataColumnSidecar(root, column_index, data);
        std.log.info("Imported data column sidecar root={s}... column={d}", .{
            &std.fmt.bytesToHex(root[0..4], .lower),
            column_index,
        });
    }

    pub fn ingestDataColumnSidecar(
        self: *BeaconNode,
        root: [32]u8,
        column_index: u64,
        slot: u64,
        data: []const u8,
    ) !?chain_mod.ReadyBlockInput {
        const ready = try self.chainService().ingestDataColumnSidecar(root, column_index, slot, data);
        if (ready != null) {
            std.log.info("Imported data column sidecar root={s}... column={d}", .{
                &std.fmt.bytesToHex(root[0..4], .lower),
                column_index,
            });
        }
        return ready;
    }

    /// Check data availability for a block: do we have all required custody columns?
    ///
    /// Returns true if we have all columns required by our custody groups.
    /// For now, this checks if at least CUSTODY_REQUIREMENT columns are stored.
    pub fn isDataAvailable(self: *BeaconNode, root: [32]u8) bool {
        const custody_req = self.config.chain.CUSTODY_REQUIREMENT;
        var columns_found: u64 = 0;
        var col_idx: u64 = 0;
        while (col_idx < 128) : (col_idx += 1) {
            if (self.chainQuery().dataColumnByRoot(root, col_idx) catch null) |data| {
                self.allocator.free(data);
                columns_found += 1;
                if (columns_found >= custody_req) return true;
            }
        }
        return false;
    }

    /// Retrieve a single data column sidecar from the DB.
    /// Used by req/resp handlers to serve DataColumnSidecarsByRoot requests.
    pub fn getDataColumnSidecar(self: *BeaconNode, root: [32]u8, column_index: u64) !?[]const u8 {
        return self.chainQuery().dataColumnByRoot(root, column_index);
    }

    /// Advance the head state by one empty slot (no block).
    ///
    /// Used for testing skip slots. Advances the head state via processSlots,
    /// stores the new state in the block_state_cache, and updates the head
    /// tracker so the next importBlock can find its parent state.
    ///
    /// The head_tracker.head_root stays the same (last real block root),
    /// but head_state_root advances to the new state.
    pub fn advanceSlot(self: *BeaconNode, target_slot: u64) !void {
        try self.chainService().advanceSlot(target_slot);
        self.last_slot_tick = target_slot;
    }

    /// Start the Beacon REST API HTTP server (blocking).
    ///
    /// Listens on the configured address:port and dispatches requests
    /// to the Beacon API handlers.
    pub fn startApi(self: *BeaconNode, io: std.Io, address: []const u8, port: u16, cors_origin: ?[]const u8) !void {
        self.http_server = api_mod.HttpServer.initWithCors(self.allocator, self.api_context, address, port, cors_origin);
        log.logger(.rest).info("REST API listening", .{});
        try self.http_server.?.serve(io);
    }

    /// Start the libp2p P2P networking service.
    ///
    /// Initialises the eth-p2p-z Switch (QUIC transport, all eth2 req/resp methods,
    /// gossipsub), subscribes to all global eth2 gossip topics for the current fork
    /// digest, and begins listening for inbound connections.
    ///
    /// The listen address is a QUIC multiaddr string, e.g.:
    ///   "/ip4/0.0.0.0/udp/9000/quic-v1"
    ///
    /// This method blocks in the sense that the Switch runs its accept loop
    /// on the provided io (cooperative fibers via Io.Group.async). Use a
    /// dedicated fiber or call from a background task.
    pub fn startP2p(self: *BeaconNode, io: std.Io, listen_addr: []const u8, port: u16) !void {
        try p2p_runtime_mod.start(self, io, listen_addr, port);
    }

    /// Queue an orphan block whose parent is not yet known.
    ///
    /// Computes the block root and stores the raw SSZ bytes in the
    /// UnknownBlockSync pending set. The parent will be fetched via
    /// BeaconBlocksByRoot during the next sync cycle.
    pub fn queueOrphanBlock(
        self: *BeaconNode,
        any_signed: AnySignedBeaconBlock,
        ssz_bytes: []const u8,
    ) void {
        // Compute the block root using the fork-polymorphic interface.
        const beacon_block = any_signed.beaconBlock();
        const block_slot = beacon_block.slot();
        const parent_root = beacon_block.parentRoot().*;

        var block_root: [32]u8 = undefined;
        beacon_block.hashTreeRoot(self.allocator, &block_root) catch return;

        const added = self.unknown_block_sync.addPendingBlock(
            block_root,
            parent_root,
            block_slot,
            ssz_bytes,
        ) catch return;

        if (added) {
            std.log.info("Queued orphan block slot={d} parent={s}... ({d} pending)", .{
                block_slot,
                &std.fmt.bytesToHex(parent_root[0..4], .lower),
                self.unknown_block_sync.pendingCount(),
            });
        }

        // Also feed the unknown chain sync — it tracks the parent root as
        // an unknown chain and builds backwards to our fork choice.
        self.unknown_chain_sync.onUnknownBlockInput(
            block_slot,
            block_root,
            parent_root,
            null, // peer_id not available from gossip context
        ) catch {};

        // If the parent root is truly unknown, start a chain for it.
        self.unknown_chain_sync.onUnknownBlockRoot(
            parent_root,
            null,
        ) catch {};
    }

    /// After a block is successfully imported, check if any orphan children
    /// were waiting on it and try to import them. Also notifies the unknown
    /// chain sync so it can link any backwards chains.
    pub fn processPendingChildren(self: *BeaconNode, parent_root: [32]u8) void {
        // Notify backwards chain sync — may link a chain.
        self.unknown_chain_sync.onBlockImported(parent_root);
        // Notify unknown block sync — handles recursive resolution internally.
        self.unknown_block_sync.notifyBlockImported(parent_root) catch {};
    }

    fn findPendingSyncSegmentIndex(self: *BeaconNode, key: SyncSegmentKey) ?usize {
        for (self.pending_sync_segments.items, 0..) |segment, i| {
            if (segment.key.chain_id != key.chain_id) continue;
            if (segment.key.batch_id != key.batch_id) continue;
            if (segment.key.generation != key.generation) continue;
            return i;
        }
        return null;
    }

    fn startPendingSyncSegmentBlock(self: *BeaconNode, index: usize) !bool {
        var segment = &self.pending_sync_segments.items[index];

        while (segment.next_index < segment.blocks.len and !segment.stop_after_current) {
            const block = segment.blocks[segment.next_index];
            var ready = self.chainService().prepareRawBlockInput(block.block_bytes, .range_sync) catch |err| {
                segment.failed_count += 1;
                segment.next_index += 1;
                log.logger(.node).warn("range sync block preparation failed: {}", .{err});
                continue;
            };

            const planned = self.chainService().planReadyBlockImport(&ready) catch |err| {
                ready.deinit(self.allocator);
                switch (err) {
                    error.AlreadyKnown, error.WouldRevertFinalizedSlot, error.GenesisBlock => {
                        segment.skipped_count += 1;
                    },
                    else => {
                        segment.failed_count += 1;
                        log.logger(.node).warn("range sync block planning failed: {}", .{err});
                    },
                }
                segment.next_index += 1;
                continue;
            };

            try self.queued_state_work_owners.ensureUnusedCapacity(self.allocator, 1);
            if (try self.chainService().tryQueuePlannedReadyBlockImport(planned)) {
                self.queued_state_work_owners.appendAssumeCapacity(.{ .sync_segment = segment.key });
                segment.in_flight = true;
                return true;
            }

            var owned_planned = planned;
            owned_planned.deinit(self.allocator);
            return false;
        }

        return false;
    }

    fn finalizePendingSyncSegment(self: *BeaconNode, index: usize) void {
        var segment = self.pending_sync_segments.orderedRemove(index);
        defer segment.deinit(self.allocator);

        if (segment.stop_after_current and segment.next_index < segment.blocks.len) {
            segment.failed_count += segment.blocks.len - segment.next_index;
            segment.next_index = segment.blocks.len;
        }

        const outcome = self.chainService().buildDeferredRangeSyncSegmentOutcome(
            segment.before_snapshot,
            segment.imported_count,
            segment.skipped_count,
            segment.failed_count,
        );
        const all_failed = outcome.imported_count == 0 and outcome.skipped_count == 0 and outcome.failed_count > 0;
        self.finishSegmentImportOutcome(segment.started_at, outcome);

        if (self.sync_service_inst) |sync_svc| {
            if (all_failed) {
                sync_svc.onSegmentProcessingError(
                    segment.key.chain_id,
                    segment.key.batch_id,
                    segment.key.generation,
                );
            } else {
                sync_svc.onSegmentProcessingSuccess(
                    segment.key.chain_id,
                    segment.key.batch_id,
                    segment.key.generation,
                );
            }
        }
    }

    fn queueExecutionForkchoiceUpdate(
        self: *BeaconNode,
        update: chain_mod.ExecutionForkchoiceUpdate,
    ) void {
        self.execution_runtime.submitForkchoiceUpdateAsync(update) catch |err| {
            log.logger(.node).warn("forkchoiceUpdated failed: {}", .{err});
        };
    }

    pub fn hasExecutionEngine(self: *const BeaconNode) bool {
        return self.execution_runtime.hasExecutionEngine();
    }

    /// Queue payload preparation on the execution runtime.
    ///
    /// This no longer implies the payload id is available when the call returns.
    /// Proposal-building paths that need the payload immediately must wait on the
    /// queued execution completion through the normal runtime lane.
    pub fn preparePayload(
        self: *BeaconNode,
        slot: u64,
        timestamp: u64,
        prev_randao: [32]u8,
        fee_recipient: [20]u8,
        withdrawals_slice: []const execution_mod.engine_api_types.Withdrawal,
        parent_beacon_block_root: [32]u8,
    ) !void {
        try block_production_mod.preparePayload(
            self,
            slot,
            timestamp,
            prev_randao,
            fee_recipient,
            withdrawals_slice,
            parent_beacon_block_root,
        );
    }

    /// Register validators with the builder relay.
    ///
    /// Should be called once per epoch for all active validators.
    /// Errors are logged but not propagated — builder failure must not
    /// interrupt normal validator operation.
    pub fn registerValidatorsWithBuilder(
        self: *BeaconNode,
        registrations: []const execution_mod.builder.SignedValidatorRegistration,
    ) void {
        block_production_mod.registerValidatorsWithBuilder(self, registrations);
    }

    pub fn refreshBuilderStatus(self: *BeaconNode, clock_slot: u64) void {
        block_production_mod.refreshBuilderStatus(self, clock_slot);
    }

    /// Get the current head info.
    pub fn getHead(self: *const BeaconNode) HeadInfo {
        return self.chainQuery().head();
    }

    pub fn chainQuery(self: *const BeaconNode) chain_mod.Query {
        return chain_mod.Query.init(self.chain);
    }

    pub fn chainService(self: *BeaconNode) chain_mod.Service {
        return chain_mod.Service.init(self.chain);
    }

    pub fn headState(self: *const BeaconNode) ?*CachedBeaconState {
        return self.chainQuery().headState();
    }

    pub fn currentHeadSlot(self: *const BeaconNode) u64 {
        return self.getHead().slot;
    }

    pub fn currentHeadRoot(self: *const BeaconNode) [32]u8 {
        return self.getHead().root;
    }

    pub fn currentFinalizedSlot(self: *const BeaconNode) u64 {
        return self.chainQuery().finalizedCheckpoint().slot;
    }

    /// Get the current sync status.
    ///
    /// For now returns a simple status based on head slot. In production this
    /// would compare against the clock's wall-clock slot to determine sync
    /// distance.
    pub fn getSyncStatus(self: *const BeaconNode) SyncStatus {
        const chain_sync = self.chainQuery().syncStatus();

        // Use the sync service state machine when available.
        if (self.sync_service_inst) |svc| {
            const ss = svc.getSyncStatus();
            return .{
                .head_slot = ss.head_slot,
                .sync_distance = ss.sync_distance,
                .is_syncing = ss.state == .syncing_finalized or ss.state == .syncing_head,
                .is_optimistic = ss.is_optimistic or chain_sync.is_optimistic,
                .el_offline = self.execution_runtime.el_offline,
            };
        }
        return .{
            .head_slot = chain_sync.head_slot,
            .sync_distance = chain_sync.sync_distance,
            .is_syncing = chain_sync.is_syncing,
            .is_optimistic = chain_sync.is_optimistic,
            .el_offline = self.execution_runtime.el_offline,
        };
    }

    /// Produce a block body from the operation pool.
    ///
    /// Returns pending attestations, slashings, exits, etc. selected for
    /// inclusion. The caller is responsible for constructing the full
    /// SignedBeaconBlock with execution payload, RANDAO, etc.
    pub fn produceBlock(self: *BeaconNode, slot: u64) !ProducedBlockBody {
        return block_production_mod.produceBlock(self, slot);
    }

    /// Produce a full beacon block with execution payload for a given slot.
    ///
    /// This is the main entry point for block production. It:
    /// 1. Gets the head state and verifies the proposer for the slot
    /// 2. Retrieves the execution payload from the EL (must call preparePayload first)
    /// 3. Converts the engine API payload to SSZ format
    /// 4. Assembles the full BeaconBlockBody with all fields populated
    /// 5. Returns a ProducedBlock with the body, blobs bundle, and metadata
    ///
    /// The caller is responsible for:
    /// - Calling preparePayload() before this (typically at slot N-1)
    /// - Setting the RANDAO reveal (validator client signs)
    /// - Computing the state root via state transition
    /// - Signing the block
    /// - Broadcasting via gossip
    pub fn produceFullBlock(self: *BeaconNode, slot: u64, prod_config: BlockProductionConfig) !ProducedBlock {
        return block_production_mod.produceFullBlock(self, slot, prod_config);
    }
    /// Produce a full block and submit it through the normal local ingress path.
    ///
    /// This is the complete block production pipeline:
    /// 1. Produce block body with execution payload
    /// 2. Wrap in BeaconBlock with slot, proposer, parent root
    /// 3. Compute state root via state transition (with verification off)
    /// 4. Wrap in SignedBeaconBlock (with zero signature — VC signs separately)
    /// 5. Submit the block through the normal ingress pipeline
    ///
    /// Returns the signed block and ingress result. The block is owned by the
    /// caller and must be freed.
    ///
    /// Preconditions:
    /// - preparePayload() called at slot N-1 (to have a cached payload)
    /// - Head state available in block_state_cache
    pub fn produceAndIngestBlock(
        self: *BeaconNode,
        slot: u64,
        prod_config: BlockProductionConfig,
    ) !struct { signed_block: *types.electra.SignedBeaconBlock.Type, ingress_result: ReadyIngressResult } {
        return block_production_mod.produceAndIngestBlock(self, slot, prod_config);
    }

    /// Broadcast a signed block to the network via gossip.
    ///
    /// Serializes and publishes the block on the beacon_block gossip topic.
    /// Should be called after `produceAndIngestBlock()`.
    ///
    /// NOTE: Gossip encoding (SSZ + Snappy) and topic construction are
    /// handled by the networking layer's gossip adapter. This method
    /// delegates to publishGossip which handles compression internally.
    pub fn broadcastBlock(
        self: *BeaconNode,
        signed_block: *const types.electra.SignedBeaconBlock.Type,
    ) !void {
        try block_production_mod.broadcastBlock(self, signed_block);
    }
    /// Used for req/resp Status exchanges with peers.
    pub fn getStatus(self: *const BeaconNode) StatusMessage.Type {
        return self.chainQuery().status();
    }

    /// Handle an incoming req/resp request.
    ///
    /// Dispatches to the appropriate handler based on method. Uses the node's
    /// database and state to service the request.
    ///
    /// Uses the EngineApi vtable pattern: a `RequestContext` wrapping `*BeaconNode`
    /// is passed as `ptr: *anyopaque` to each callback.
    pub fn onReqResp(
        self: *BeaconNode,
        method: Method,
        request_bytes: []const u8,
    ) ![]const ResponseChunk {
        var req_ctx = reqresp_callbacks_mod.RequestContext{
            .node = @ptrCast(self),
        };
        const ctx = reqresp_callbacks_mod.makeReqRespContext(&req_ctx);
        return handleRequest(self.allocator, method, request_bytes, &ctx);
    }

    pub fn applyBootstrapOutcome(self: *BeaconNode, outcome: chain_mod.BootstrapOutcome) void {
        self.genesis_validators_root = outcome.genesis_validators_root;
        self.earliest_available_slot = outcome.earliest_available_slot;
        self.last_slot_tick = null;
        self.clock = SlotClock.fromGenesis(outcome.genesis_time, self.config.chain);
        self.api_context.genesis_time = outcome.genesis_time;
        _ = outcome.snapshot;
    }

    pub fn processPendingGossipBlsBatch(self: *BeaconNode) bool {
        return processPendingGossipBlsBatchImpl(self);
    }

    pub fn flushPendingGossipBlsBatch(self: *BeaconNode) void {
        flushPendingGossipBlsBatchImpl(self);
    }
};

const PendingAttestationBlsBatch = struct {
    items: []AttestationWork,
    owned_sets: []bls_mod.OwnedSignatureSet,
    future: *BlsThreadPool.VerifySetsFuture,

    fn isReady(self: *const PendingAttestationBlsBatch) bool {
        return self.future.isReady();
    }

    fn finish(self: *PendingAttestationBlsBatch, node: *BeaconNode) void {
        const batch_valid = self.future.finish() catch false;
        importAttestationBatchItems(node, self.items, batch_valid);
        freeOwnedSignatureSets(node.allocator, self.owned_sets);
        node.allocator.free(self.items);
    }
};

const PendingAggregateBlsBatch = struct {
    items: []AggregateWork,
    owned_sets: []bls_mod.OwnedSignatureSet,
    future: *BlsThreadPool.VerifySetsFuture,

    fn isReady(self: *const PendingAggregateBlsBatch) bool {
        return self.future.isReady();
    }

    fn finish(self: *PendingAggregateBlsBatch, node: *BeaconNode) void {
        const batch_valid = self.future.finish() catch false;
        importAggregateBatchItems(node, self.items, batch_valid);
        freeOwnedSignatureSets(node.allocator, self.owned_sets);
        node.allocator.free(self.items);
    }
};

const PendingSyncMessageBlsBatch = struct {
    items: []processor_mod.work_item.SyncMessageWork,
    owned_sets: []bls_mod.OwnedSignatureSet,
    future: *BlsThreadPool.VerifySetsFuture,

    fn isReady(self: *const PendingSyncMessageBlsBatch) bool {
        return self.future.isReady();
    }

    fn finish(self: *PendingSyncMessageBlsBatch, node: *BeaconNode) void {
        const batch_valid = self.future.finish() catch false;
        importSyncMessageBatchItems(node, self.items, batch_valid);
        freeOwnedSignatureSets(node.allocator, self.owned_sets);
        node.allocator.free(self.items);
    }
};

const PendingGossipBlsBatch = union(enum) {
    attestation: PendingAttestationBlsBatch,
    aggregate: PendingAggregateBlsBatch,
    sync_message: PendingSyncMessageBlsBatch,

    fn priority(self: *const PendingGossipBlsBatch) bls_mod.ThreadPool.VerifySetsPriority {
        return switch (self.*) {
            .attestation => .high,
            .aggregate => .normal,
            .sync_message => .normal,
        };
    }

    fn isStarted(self: *const PendingGossipBlsBatch) bool {
        return switch (self.*) {
            .attestation => |batch| batch.future.started.isSet(),
            .aggregate => |batch| batch.future.started.isSet(),
            .sync_message => |batch| batch.future.started.isSet(),
        };
    }

    fn isReady(self: *const PendingGossipBlsBatch) bool {
        return switch (self.*) {
            .attestation => |batch| batch.isReady(),
            .aggregate => |batch| batch.isReady(),
            .sync_message => |batch| batch.isReady(),
        };
    }

    fn finish(self: *PendingGossipBlsBatch, node: *BeaconNode) void {
        switch (self.*) {
            .attestation => |*batch| batch.finish(node),
            .aggregate => |*batch| batch.finish(node),
            .sync_message => |*batch| batch.finish(node),
        }
    }
};

fn setGossipBlsBatchDispatchState(node: *BeaconNode) void {
    if (node.beacon_processor) |bp| {
        const enabled = node.gossip_bls_thread_pool.canAcceptWork();
        bp.setGossipBlsBatchDispatchEnabled(enabled);
    }
}

fn processPendingGossipBlsBatchImpl(node: *BeaconNode) bool {
    defer setGossipBlsBatchDispatchState(node);

    var did_work = false;
    while (findReadyPendingGossipBlsBatch(node)) |ready_index| {
        var ready = node.pending_gossip_bls_batches.orderedRemove(ready_index);
        ready.finish(node);
        did_work = true;
    }

    return did_work or node.pending_gossip_bls_batches.items.len > 0;
}

fn flushPendingGossipBlsBatchImpl(node: *BeaconNode) void {
    defer setGossipBlsBatchDispatchState(node);

    while (node.pending_gossip_bls_batches.items.len > 0) {
        const active_index = findStartedPendingGossipBlsBatch(node) orelse 0;
        var pending = node.pending_gossip_bls_batches.orderedRemove(active_index);
        pending.finish(node);
    }
}

fn findReadyPendingGossipBlsBatch(node: *const BeaconNode) ?usize {
    for (node.pending_gossip_bls_batches.items, 0..) |pending, i| {
        if (pending.isReady()) return i;
    }
    return null;
}

fn findStartedPendingGossipBlsBatch(node: *const BeaconNode) ?usize {
    for (node.pending_gossip_bls_batches.items, 0..) |pending, i| {
        if (pending.isStarted()) return i;
    }
    return null;
}

fn appendPendingGossipBlsBatch(node: *BeaconNode, pending: PendingGossipBlsBatch) void {
    const items = node.pending_gossip_bls_batches.items;
    var insert_at = items.len;
    if (pending.priority() == .high) {
        insert_at = 0;
        while (insert_at < items.len) : (insert_at += 1) {
            if (items[insert_at].priority() != .high) break;
        }
    }

    node.pending_gossip_bls_batches.insertAssumeCapacity(insert_at, pending);
}

fn cloneAttestationBatchItems(allocator: Allocator, items: []const AttestationWork) ![]AttestationWork {
    const owned = try allocator.alloc(AttestationWork, items.len);
    @memcpy(owned, items);
    return owned;
}

fn cloneAggregateBatchItems(allocator: Allocator, items: []const AggregateWork) ![]AggregateWork {
    const owned = try allocator.alloc(AggregateWork, items.len);
    @memcpy(owned, items);
    return owned;
}

fn cloneSyncMessageBatchItems(
    allocator: Allocator,
    items: []const processor_mod.work_item.SyncMessageWork,
) ![]processor_mod.work_item.SyncMessageWork {
    const owned = try allocator.alloc(processor_mod.work_item.SyncMessageWork, items.len);
    @memcpy(owned, items);
    return owned;
}

fn freeOwnedSignatureSets(allocator: Allocator, owned_sets: []bls_mod.OwnedSignatureSet) void {
    for (owned_sets) |*owned_set| {
        owned_set.deinit();
    }
    allocator.free(owned_sets);
}

fn deinitAttestationBatchItems(node: *BeaconNode, items: []AttestationWork) void {
    for (items) |*item| {
        item.attestation.deinit(node.allocator);
    }
}

fn deinitAggregateBatchItems(node: *BeaconNode, items: []AggregateWork) void {
    for (items) |*item| {
        item.resolved.deinit(node.allocator);
        item.aggregate.deinit(node.allocator);
    }
}

fn attestationBatchSharesDataRoot(items: []const AttestationWork) bool {
    if (items.len < 2) return false;

    const attestation_data_root = items[0].attestation_data_root;
    for (items[1..]) |item| {
        if (!std.mem.eql(u8, &item.attestation_data_root, &attestation_data_root)) return false;
    }

    return true;
}

fn syncMessageBatchSharesSigningRoot(items: []const processor_mod.work_item.SyncMessageWork) bool {
    if (items.len < 2) return false;

    const slot = items[0].message.slot;
    const beacon_block_root = items[0].message.beacon_block_root;
    for (items[1..]) |item| {
        if (item.message.slot != slot) return false;
        if (!std.mem.eql(u8, &item.message.beacon_block_root, &beacon_block_root)) return false;
    }

    return true;
}

fn verifyAttestationBatchSync(node: *BeaconNode, items: []const AttestationWork) bool {
    const gh = node.gossip_handler orelse return true;
    if (gh.verifyAttestationSignatureFn == null) return true;
    const same_message = attestationBatchSharesDataRoot(items);

    var owned_sets: [processor_mod.work_item.max_attestation_batch_size]bls_mod.OwnedSignatureSet = undefined;
    var signature_sets: [processor_mod.work_item.max_attestation_batch_size]bls_mod.SignatureSet = undefined;
    var owned_count: usize = 0;
    defer {
        while (owned_count > 0) {
            owned_count -= 1;
            owned_sets[owned_count].deinit();
        }
    }

    for (items) |item| {
        const owned_set = blk: {
            const built = if (same_message)
                gossip_node_callbacks_mod.buildResolvedAttestationSignatureSet(
                    gh.node,
                    &item.attestation,
                    &item.resolved,
                )
            else
                gossip_node_callbacks_mod.buildResolvedAttestationSignatureSet(
                    gh.node,
                    &item.attestation,
                    &item.resolved,
                );
            break :blk built catch return false;
        };

        owned_sets[owned_count] = owned_set;
        signature_sets[owned_count] = owned_set.set;
        owned_count += 1;
    }

    const sets = signature_sets[0..owned_count];
    if (same_message) {
        var rands: [processor_mod.work_item.max_attestation_batch_size][32]u8 = undefined;
        std.Options.debug_io.randomSecure(std.mem.sliceAsBytes(rands[0..owned_count])) catch
            std.Options.debug_io.random(std.mem.sliceAsBytes(rands[0..owned_count]));
        var pairing_buf: [bls_mod.Pairing.sizeOf()]u8 align(bls_mod.Pairing.buf_align) = undefined;
        return bls_mod.verifySignatureSetsSameMessage(
            &pairing_buf,
            sets,
            bls_mod.DST,
            rands[0..owned_count],
        ) catch false;
    }

    var batch_verifier = bls_mod.BatchVerifier.init(node.gossip_bls_thread_pool);
    for (sets) |set| {
        batch_verifier.addSet(set) catch return false;
    }

    return batch_verifier.verifyAll() catch false;
}

fn verifyAggregateBatchSync(node: *BeaconNode, items: []const AggregateWork) bool {
    const gh = node.gossip_handler orelse return true;
    if (gh.verifyAggregateSignatureFn == null) return true;

    var batch_verifier = bls_mod.BatchVerifier.init(node.gossip_bls_thread_pool);
    var owned_sets: [processor_mod.work_item.max_aggregate_batch_size * 3]bls_mod.OwnedSignatureSet = undefined;
    var owned_count: usize = 0;
    defer {
        while (owned_count > 0) {
            owned_count -= 1;
            owned_sets[owned_count].deinit();
        }
    }

    for (items) |item| {
        var local_sets: [3]bls_mod.OwnedSignatureSet = undefined;
        gossip_node_callbacks_mod.buildResolvedAggregateSignatureSets(
            node.allocator,
            gh.node,
            &item.aggregate,
            &item.resolved,
            &local_sets,
        ) catch return false;

        var local_added = true;
        for (local_sets) |owned_set| {
            batch_verifier.addSet(owned_set.set) catch {
                local_added = false;
                break;
            };
        }

        if (!local_added) {
            inline for (0..3) |idx| {
                local_sets[idx].deinit();
            }
            return false;
        }

        inline for (0..3) |idx| {
            owned_sets[owned_count] = local_sets[idx];
            owned_count += 1;
        }
    }

    return batch_verifier.verifyAll() catch false;
}

fn verifySyncMessageBatchSync(
    node: *BeaconNode,
    items: []const processor_mod.work_item.SyncMessageWork,
) bool {
    const gh = node.gossip_handler orelse return true;
    if (gh.verifySyncCommitteeSignatureFn == null) return true;
    const same_message = syncMessageBatchSharesSigningRoot(items);

    var owned_sets: [processor_mod.work_item.max_sync_message_batch_size]bls_mod.OwnedSignatureSet = undefined;
    var signature_sets: [processor_mod.work_item.max_sync_message_batch_size]bls_mod.SignatureSet = undefined;
    var owned_count: usize = 0;
    defer {
        while (owned_count > 0) {
            owned_count -= 1;
            owned_sets[owned_count].deinit();
        }
    }

    for (items) |item| {
        const owned_set = gossip_node_callbacks_mod.buildSyncCommitteeSignatureSet(
            gh.node,
            &item.message,
        ) catch return false;
        owned_sets[owned_count] = owned_set;
        signature_sets[owned_count] = owned_set.set;
        owned_count += 1;
    }

    const sets = signature_sets[0..owned_count];
    if (same_message) {
        var rands: [processor_mod.work_item.max_sync_message_batch_size][32]u8 = undefined;
        std.Options.debug_io.randomSecure(std.mem.sliceAsBytes(rands[0..owned_count])) catch
            std.Options.debug_io.random(std.mem.sliceAsBytes(rands[0..owned_count]));
        var pairing_buf: [bls_mod.Pairing.sizeOf()]u8 align(bls_mod.Pairing.buf_align) = undefined;
        return bls_mod.verifySignatureSetsSameMessage(
            &pairing_buf,
            sets,
            bls_mod.DST,
            rands[0..owned_count],
        ) catch false;
    }

    var batch_verifier = bls_mod.BatchVerifier.init(node.gossip_bls_thread_pool);
    for (sets) |set| {
        batch_verifier.addSet(set) catch return false;
    }

    return batch_verifier.verifyAll() catch false;
}

fn importAttestationBatchItems(node: *BeaconNode, items: []AttestationWork, batch_valid: bool) void {
    for (items) |item| {
        var attestation = item.attestation;
        defer attestation.deinit(node.allocator);

        if (!batch_valid) {
            if (node.gossip_handler) |gh| {
                if (gh.verifyAttestationSignatureFn) |verifyFn| {
                    if (!verifyFn(gh.node, &attestation, &item.resolved)) {
                        std.log.warn("Attestation BLS failed in batch fallback slot={d}", .{attestation.slot()});
                        continue;
                    }
                }
            }
        }

        const gh = node.gossip_handler orelse continue;
        const importFn = gh.importResolvedAttestationFn orelse continue;

        importFn(gh.node, &attestation, &item.resolved) catch |err| {
            std.log.warn("Processor: attestation import failed for slot {d}: {}", .{
                attestation.slot(), err,
            });
        };
    }
}

fn importAggregateBatchItems(node: *BeaconNode, items: []AggregateWork, batch_valid: bool) void {
    for (items) |item| {
        var aggregate = item.aggregate;
        defer aggregate.deinit(node.allocator);
        defer item.resolved.deinit(node.allocator);

        if (!batch_valid) {
            if (node.gossip_handler) |gh| {
                if (gh.verifyAggregateSignatureFn) |verifyFn| {
                    if (!verifyFn(gh.node, &aggregate, &item.resolved)) {
                        std.log.warn("Aggregate BLS failed in batch fallback slot={d}", .{
                            aggregate.attestation().slot(),
                        });
                        continue;
                    }
                }
            }
        }

        if (node.gossip_handler) |gh| {
            if (gh.importResolvedAggregateFn) |importFn| {
                importFn(gh.node, &aggregate, &item.resolved) catch |err| {
                    std.log.warn("Processor: aggregate import failed slot={d}: {}", .{
                        aggregate.attestation().slot(),
                        err,
                    });
                };
            }
        }
    }
}

fn importSyncMessageBatchItems(
    node: *BeaconNode,
    items: []processor_mod.work_item.SyncMessageWork,
    batch_valid: bool,
) void {
    for (items) |item| {
        if (!batch_valid) {
            const gh = node.gossip_handler orelse continue;
            if (gh.verifySyncCommitteeSignatureFn != null) {
                if (!gossip_node_callbacks_mod.verifySyncCommitteeMessage(gh.node, &item.message)) {
                    std.log.warn("Sync committee message BLS failed in batch fallback slot={d}", .{
                        item.message.slot,
                    });
                    continue;
                }
            }
        }

        handleQueuedSyncMessage(node, item);
    }
}

fn tryStartPendingAttestationBatch(node: *BeaconNode, items: []AttestationWork) bool {
    const gh = node.gossip_handler orelse return false;
    if (gh.verifyAttestationSignatureFn == null) return false;
    if (!node.gossip_bls_thread_pool.canAcceptWork()) return false;
    node.pending_gossip_bls_batches.ensureUnusedCapacity(node.allocator, 1) catch return false;
    const same_message = attestationBatchSharesDataRoot(items);

    const owned_sets = node.allocator.alloc(bls_mod.OwnedSignatureSet, items.len) catch return false;
    var owned_count: usize = 0;

    var signature_sets: [processor_mod.work_item.max_attestation_batch_size]bls_mod.SignatureSet = undefined;
    for (items, 0..) |item, i| {
        const owned_set = (if (same_message)
            gossip_node_callbacks_mod.buildResolvedAttestationSignatureSet(
                gh.node,
                &item.attestation,
                &item.resolved,
            )
        else
            gossip_node_callbacks_mod.buildResolvedAttestationSignatureSet(
                gh.node,
                &item.attestation,
                &item.resolved,
            )) catch {
            while (owned_count > 0) {
                owned_count -= 1;
                owned_sets[owned_count].deinit();
            }
            node.allocator.free(owned_sets);
            return false;
        };
        owned_sets[i] = owned_set;
        signature_sets[i] = owned_set.set;
        owned_count += 1;
    }

    const sets = signature_sets[0..items.len];
    const future = (if (same_message)
        node.gossip_bls_thread_pool.startVerifySignatureSetsSameMessage(
            node.allocator,
            sets,
            bls_mod.DST,
            .{ .priority = .high },
        )
    else
        node.gossip_bls_thread_pool.startVerifySignatureSets(
            node.allocator,
            sets,
            bls_mod.DST,
            .{ .priority = .high },
        )) catch {
        while (owned_count > 0) {
            owned_count -= 1;
            owned_sets[owned_count].deinit();
        }
        node.allocator.free(owned_sets);
        return false;
    };

    appendPendingGossipBlsBatch(node, .{ .attestation = .{
        .items = items,
        .owned_sets = owned_sets,
        .future = future,
    } });
    setGossipBlsBatchDispatchState(node);
    return true;
}

fn tryStartPendingAggregateBatch(node: *BeaconNode, items: []AggregateWork) bool {
    const gh = node.gossip_handler orelse return false;
    if (gh.verifyAggregateSignatureFn == null) return false;
    if (!node.gossip_bls_thread_pool.canAcceptWork()) return false;
    node.pending_gossip_bls_batches.ensureUnusedCapacity(node.allocator, 1) catch return false;

    const owned_sets = node.allocator.alloc(bls_mod.OwnedSignatureSet, items.len * 3) catch return false;
    var owned_count: usize = 0;

    var signature_sets: [processor_mod.work_item.max_aggregate_batch_size * 3]bls_mod.SignatureSet = undefined;
    for (items) |item| {
        var local_sets: [3]bls_mod.OwnedSignatureSet = undefined;
        gossip_node_callbacks_mod.buildResolvedAggregateSignatureSets(
            node.allocator,
            gh.node,
            &item.aggregate,
            &item.resolved,
            &local_sets,
        ) catch {
            while (owned_count > 0) {
                owned_count -= 1;
                owned_sets[owned_count].deinit();
            }
            node.allocator.free(owned_sets);
            return false;
        };

        inline for (0..3) |idx| {
            owned_sets[owned_count] = local_sets[idx];
            signature_sets[owned_count] = local_sets[idx].set;
            owned_count += 1;
        }
    }

    const future = node.gossip_bls_thread_pool.startVerifySignatureSets(
        node.allocator,
        signature_sets[0..owned_count],
        bls_mod.DST,
        .{ .priority = .normal },
    ) catch {
        while (owned_count > 0) {
            owned_count -= 1;
            owned_sets[owned_count].deinit();
        }
        node.allocator.free(owned_sets);
        return false;
    };

    appendPendingGossipBlsBatch(node, .{ .aggregate = .{
        .items = items,
        .owned_sets = owned_sets,
        .future = future,
    } });
    setGossipBlsBatchDispatchState(node);
    return true;
}

fn tryStartPendingSyncMessageBatch(
    node: *BeaconNode,
    items: []processor_mod.work_item.SyncMessageWork,
) bool {
    const gh = node.gossip_handler orelse return false;
    if (gh.verifySyncCommitteeSignatureFn == null) return false;
    if (!node.gossip_bls_thread_pool.canAcceptWork()) return false;
    node.pending_gossip_bls_batches.ensureUnusedCapacity(node.allocator, 1) catch return false;
    const same_message = syncMessageBatchSharesSigningRoot(items);

    const owned_sets = node.allocator.alloc(bls_mod.OwnedSignatureSet, items.len) catch return false;
    var owned_count: usize = 0;

    var signature_sets: [processor_mod.work_item.max_sync_message_batch_size]bls_mod.SignatureSet = undefined;
    for (items, 0..) |item, i| {
        const owned_set = gossip_node_callbacks_mod.buildSyncCommitteeSignatureSet(
            gh.node,
            &item.message,
        ) catch {
            while (owned_count > 0) {
                owned_count -= 1;
                owned_sets[owned_count].deinit();
            }
            node.allocator.free(owned_sets);
            return false;
        };

        owned_sets[i] = owned_set;
        signature_sets[i] = owned_set.set;
        owned_count += 1;
    }

    const sets = signature_sets[0..items.len];
    const future = (if (same_message)
        node.gossip_bls_thread_pool.startVerifySignatureSetsSameMessage(
            node.allocator,
            sets,
            bls_mod.DST,
            .{ .priority = .normal },
        )
    else
        node.gossip_bls_thread_pool.startVerifySignatureSets(
            node.allocator,
            sets,
            bls_mod.DST,
            .{ .priority = .normal },
        )) catch {
        while (owned_count > 0) {
            owned_count -= 1;
            owned_sets[owned_count].deinit();
        }
        node.allocator.free(owned_sets);
        return false;
    };

    appendPendingGossipBlsBatch(node, .{ .sync_message = .{
        .items = items,
        .owned_sets = owned_sets,
        .future = future,
    } });
    setGossipBlsBatchDispatchState(node);
    return true;
}

// ---------------------------------------------------------------------------
// Gossip callbacks — wired into GossipHandler as function pointers.
// These bridge the type-erased *anyopaque back to *BeaconNode.
//
// ---------------------------------------------------------------------------
// BeaconProcessor handler callback.
//
// Called by BeaconProcessor.dispatchOne() for each dequeued work item.
// Routes work items to the appropriate chain import / validation function.
// The context pointer is a *BeaconNode.
// ---------------------------------------------------------------------------

pub fn processorHandlerCallback(item: WorkItem, context: *anyopaque) void {
    const node: *BeaconNode = @ptrCast(@alignCast(context));
    const wtype = item.workType();

    switch (item) {
        .gossip_block => |work| {
            const seen_timestamp_sec: u64 = if (work.seen_timestamp_ns > 0)
                @intCast(@divFloor(work.seen_timestamp_ns, std.time.ns_per_s))
            else
                0;
            const accepted = node.chainService().acceptGossipBlock(work.block, seen_timestamp_sec) catch |err| {
                work.block.deinit(node.allocator);
                std.log.warn("Processor: gossip block ingress failed: {}", .{err});
                return;
            };

            const ready = switch (accepted) {
                .pending_block_data => return,
                .ready => |ready| ready,
            };

            const maybe_result = node.completeReadyIngress(ready, null) catch |err| {
                std.log.warn("Processor: gossip block import failed: {}", .{err});
                return;
            };
            if (maybe_result) |result| {
                std.log.info("PROCESSOR: block imported slot={d} root={x:0>2}{x:0>2}{x:0>2}{x:0>2}...", .{
                    result.slot,
                    result.block_root[0],
                    result.block_root[1],
                    result.block_root[2],
                    result.block_root[3],
                });
            }
        },
        .attestation_batch => |batch| {
            std.log.debug("Processor: attestation batch (count={d})", .{batch.count});
            if (cloneAttestationBatchItems(node.allocator, batch.items[0..batch.count])) |owned_items| {
                if (tryStartPendingAttestationBatch(node, owned_items)) {
                    return;
                }

                defer node.allocator.free(owned_items);
                const batch_valid = verifyAttestationBatchSync(node, owned_items);
                importAttestationBatchItems(node, owned_items, batch_valid);
            } else |_| {
                const batch_items = batch.items[0..batch.count];
                const batch_valid = verifyAttestationBatchSync(node, batch_items);
                importAttestationBatchItems(node, batch_items, batch_valid);
            }
        },
        .aggregate_batch => |batch| {
            std.log.debug("Processor: aggregate batch (count={d})", .{batch.count});
            if (cloneAggregateBatchItems(node.allocator, batch.items[0..batch.count])) |owned_items| {
                if (tryStartPendingAggregateBatch(node, owned_items)) {
                    return;
                }

                defer node.allocator.free(owned_items);
                const batch_valid = verifyAggregateBatchSync(node, owned_items);
                importAggregateBatchItems(node, owned_items, batch_valid);
            } else |_| {
                const batch_items = batch.items[0..batch.count];
                const batch_valid = verifyAggregateBatchSync(node, batch_items);
                importAggregateBatchItems(node, batch_items, batch_valid);
            }
        },
        .sync_message_batch => |batch| {
            std.log.debug("Processor: sync message batch (count={d})", .{batch.count});
            if (cloneSyncMessageBatchItems(node.allocator, batch.items[0..batch.count])) |owned_items| {
                if (tryStartPendingSyncMessageBatch(node, owned_items)) {
                    return;
                }

                defer node.allocator.free(owned_items);
                const batch_valid = verifySyncMessageBatchSync(node, owned_items);
                importSyncMessageBatchItems(node, owned_items, batch_valid);
            } else |_| {
                const batch_items = batch.items[0..batch.count];
                const batch_valid = verifySyncMessageBatchSync(node, batch_items);
                importSyncMessageBatchItems(node, batch_items, batch_valid);
            }
        },
        .aggregate => |work| {
            if (node.gossip_handler) |gh| {
                if (gh.verifyAggregateSignatureFn) |verifyFn| {
                    if (!verifyFn(gh.node, &work.aggregate, &work.resolved)) {
                        std.log.warn("Single aggregate BLS failed aggregator={d}", .{work.aggregate.aggregatorIndex()});
                        work.resolved.deinit(node.allocator);
                        var aggregate = work.aggregate;
                        aggregate.deinit(node.allocator);
                        return;
                    }
                }
            }
            handleQueuedAggregate(node, work);
        },
        .attestation => |att_work| {
            // Single attestation (not batched).
            // BLS verify and import to fork choice.
            var attestation = att_work.attestation;
            defer attestation.deinit(node.allocator);

            // BLS signature verification.
            if (node.gossip_handler) |gh| {
                if (gh.verifyAttestationSignatureFn) |verifyFn| {
                    if (!verifyFn(gh.node, &attestation, &att_work.resolved)) {
                        std.log.warn("Single attestation BLS failed slot={d}", .{attestation.slot()});
                        return;
                    }
                }
                const importFn = gh.importResolvedAttestationFn orelse return;
                importFn(gh.node, &attestation, &att_work.resolved) catch |err| {
                    std.log.warn("Processor: attestation import failed for slot {d}: {}", .{
                        attestation.slot(), err,
                    });
                };
            }
        },
        .gossip_voluntary_exit => |work| {
            handleQueuedVoluntaryExit(node, work);
        },
        .gossip_proposer_slashing => |work| {
            handleQueuedProposerSlashing(node, work);
        },
        .gossip_attester_slashing => |work| {
            handleQueuedAttesterSlashing(node, work);
        },
        .gossip_bls_to_exec => |work| {
            handleQueuedBlsChange(node, work);
        },
        .gossip_blob => |work| {
            handleQueuedBlobSidecar(node, work);
        },
        .gossip_data_column => |work| {
            handleQueuedDataColumnSidecar(node, work);
        },
        .sync_contribution => |work| {
            handleQueuedSyncContribution(node, work);
        },
        .sync_message => |work| {
            if (node.gossip_handler) |gh| {
                if (gh.verifySyncCommitteeSignatureFn != null) {
                    if (!gossip_node_callbacks_mod.verifySyncCommitteeMessage(gh.node, &work.message)) {
                        std.log.warn("Single sync committee message BLS failed validator={d} slot={d}", .{
                            work.message.validator_index,
                            work.message.slot,
                        });
                        return;
                    }
                }
            }
            handleQueuedSyncMessage(node, work);
        },
        else => {
            // For all other work types, log at debug level.
            // Full handler wiring per work type is progressive — add as needed.
            std.log.debug("Processor: dispatched {s}", .{@tagName(wtype)});
        },
    }
}

fn handleQueuedAggregate(node: *BeaconNode, work: processor_mod.work_item.AggregateWork) void {
    const gh = node.gossip_handler orelse {
        work.resolved.deinit(node.allocator);
        var aggregate = work.aggregate;
        aggregate.deinit(node.allocator);
        return;
    };
    const importFn = gh.importResolvedAggregateFn orelse {
        work.resolved.deinit(node.allocator);
        var aggregate = work.aggregate;
        aggregate.deinit(node.allocator);
        return;
    };

    var aggregate = work.aggregate;
    defer aggregate.deinit(node.allocator);
    defer work.resolved.deinit(node.allocator);

    importFn(gh.node, &aggregate, &work.resolved) catch |err| {
        std.log.warn("Processor: aggregate import failed for aggregator {d}: {}", .{
            aggregate.aggregatorIndex(), err,
        });
    };
}

fn handleQueuedVoluntaryExit(node: *BeaconNode, work: processor_mod.work_item.VoluntaryExitWork) void {
    const gh = node.gossip_handler orelse {
        return;
    };
    const importFn = gh.importVoluntaryExitFn orelse {
        return;
    };

    importFn(gh.node, &work.exit) catch |err| {
        std.log.warn("Processor: voluntary exit import failed for validator {d}: {}", .{
            work.exit.message.validator_index, err,
        });
    };
}

fn handleQueuedAttesterSlashingTyped(
    node: *BeaconNode,
    slashing: *const fork_types.AnyAttesterSlashing,
) void {
    const gh = node.gossip_handler orelse {
        return;
    };
    const importFn = gh.importAttesterSlashingFn orelse {
        return;
    };

    importFn(gh.node, slashing) catch |err| {
        std.log.warn("Processor: attester slashing import failed: {}", .{err});
    };
}

fn handleQueuedProposerSlashing(
    node: *BeaconNode,
    work: processor_mod.work_item.ProposerSlashingWork,
) void {
    const gh = node.gossip_handler orelse {
        return;
    };
    const importFn = gh.importProposerSlashingFn orelse {
        return;
    };

    importFn(gh.node, &work.slashing) catch |err| {
        std.log.warn("Processor: proposer slashing import failed: {}", .{err});
    };
}

fn handleQueuedAttesterSlashing(
    node: *BeaconNode,
    work: processor_mod.work_item.AttesterSlashingWork,
) void {
    var slashing = work.slashing;
    defer slashing.deinit(node.allocator);
    handleQueuedAttesterSlashingTyped(node, &slashing);
}

fn handleQueuedBlsChange(
    node: *BeaconNode,
    work: processor_mod.work_item.BlsToExecutionChangeWork,
) void {
    const gh = node.gossip_handler orelse {
        return;
    };
    const importFn = gh.importBlsChangeFn orelse {
        return;
    };

    importFn(gh.node, &work.change) catch |err| {
        std.log.warn("Processor: BLS change import failed: {}", .{err});
    };
}

fn handleQueuedSyncContribution(
    node: *BeaconNode,
    work: processor_mod.work_item.SyncContributionWork,
) void {
    const gh = node.gossip_handler orelse {
        return;
    };
    const importFn = gh.importSyncContributionFn orelse {
        return;
    };

    importFn(gh.node, &work.signed_contribution) catch |err| {
        std.log.warn("Processor: sync contribution import failed: {}", .{err});
    };
}

fn handleQueuedBlobSidecar(
    node: *BeaconNode,
    work: processor_mod.work_item.GossipBlobWork,
) void {
    const gh = node.gossip_handler orelse {
        work.data.deinit();
        return;
    };
    const importFn = gh.importBlobSidecarFn orelse {
        work.data.deinit();
        return;
    };

    const QueuedSszBytes = gossip_handler_mod.QueuedSszBytes;
    const queued = work.data.cast(QueuedSszBytes);
    defer work.data.deinit();

    importFn(gh.node, queued.ssz_bytes) catch |err| {
        std.log.warn("Processor: blob sidecar import failed: {}", .{err});
    };
}

fn handleQueuedDataColumnSidecar(
    node: *BeaconNode,
    work: processor_mod.work_item.GossipColumnWork,
) void {
    const gh = node.gossip_handler orelse {
        work.data.deinit();
        return;
    };
    const importFn = gh.importDataColumnSidecarFn orelse {
        work.data.deinit();
        return;
    };

    const QueuedSszBytes = gossip_handler_mod.QueuedSszBytes;
    const queued = work.data.cast(QueuedSszBytes);
    defer work.data.deinit();

    importFn(gh.node, queued.ssz_bytes) catch |err| {
        std.log.warn("Processor: data column sidecar import failed: {}", .{err});
    };
}

fn handleQueuedSyncMessage(
    node: *BeaconNode,
    work: processor_mod.work_item.SyncMessageWork,
) void {
    const gh = node.gossip_handler orelse {
        return;
    };
    const importFn = gh.importSyncCommitteeMessageFn orelse {
        return;
    };

    importFn(gh.node, &work.message, work.subnet_id) catch |err| {
        std.log.warn("Processor: sync committee message import failed: {}", .{err});
    };
}

// Gossip callbacks are defined in gossip_node_callbacks.zig.
// Req/resp callbacks are defined in reqresp_callbacks.zig.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const ProcessorImportTestContext = struct {
    aggregate_import_count: usize = 0,
    aggregate_aggregator_index: ?u64 = null,
    aggregate_slot: ?u64 = null,
    aggregate_target_epoch: ?u64 = null,
    attestation_slot: ?u64 = null,
    attestation_committee_index: ?u64 = null,
    attestation_is_electra_single: bool = false,
    validator_index: ?u64 = null,
    exit_epoch: ?u64 = null,
    sync_subnet: ?u64 = null,
    sync_slot: ?u64 = null,
    sync_validator_index: ?u64 = null,
    blob_bytes_len: usize = 0,
    data_column_bytes_len: usize = 0,

    fn importVoluntaryExit(ptr: *anyopaque, exit: *const types.phase0.SignedVoluntaryExit.Type) anyerror!void {
        const ctx: *ProcessorImportTestContext = @ptrCast(@alignCast(ptr));
        ctx.validator_index = exit.message.validator_index;
        ctx.exit_epoch = exit.message.epoch;
    }

    fn importAggregate(
        ptr: *anyopaque,
        aggregate: *const fork_types.AnySignedAggregateAndProof,
        resolved: *const ResolvedAggregate,
    ) anyerror!void {
        _ = resolved;
        const ctx: *ProcessorImportTestContext = @ptrCast(@alignCast(ptr));
        ctx.aggregate_import_count += 1;
        ctx.aggregate_aggregator_index = aggregate.aggregatorIndex();
        const attestation = aggregate.attestation();
        const data = attestation.data();
        ctx.aggregate_slot = data.slot;
        ctx.aggregate_target_epoch = data.target.epoch;
    }

    fn importAttestation(
        ptr: *anyopaque,
        attestation: *const fork_types.AnyGossipAttestation,
        resolved: *const ResolvedAttestation,
    ) anyerror!void {
        const ctx: *ProcessorImportTestContext = @ptrCast(@alignCast(ptr));
        const data = attestation.data();
        ctx.attestation_slot = data.slot;
        ctx.attestation_committee_index = attestation.committeeIndex();
        ctx.attestation_is_electra_single = switch (attestation.*) {
            .electra_single => true,
            .phase0 => false,
        };
        ctx.validator_index = resolved.validator_index;
    }

    fn importSyncCommitteeMessage(ptr: *anyopaque, msg: *const types.altair.SyncCommitteeMessage.Type, subnet: u64) anyerror!void {
        const ctx: *ProcessorImportTestContext = @ptrCast(@alignCast(ptr));
        ctx.sync_subnet = subnet;
        ctx.sync_slot = msg.slot;
        ctx.sync_validator_index = msg.validator_index;
    }

    fn importBlobSidecar(ptr: *anyopaque, ssz_bytes: []const u8) anyerror!void {
        const ctx: *ProcessorImportTestContext = @ptrCast(@alignCast(ptr));
        ctx.blob_bytes_len = ssz_bytes.len;
    }

    fn importDataColumnSidecar(ptr: *anyopaque, ssz_bytes: []const u8) anyerror!void {
        const ctx: *ProcessorImportTestContext = @ptrCast(@alignCast(ptr));
        ctx.data_column_bytes_len = ssz_bytes.len;
    }
};

fn makeQueuedSszHandle(
    allocator: Allocator,
    fork_seq: config_mod.ForkSeq,
    ssz_bytes: []const u8,
) !processor_mod.work_item.GossipDataHandle {
    const QueuedSszBytes = gossip_handler_mod.QueuedSszBytes;
    const queued = try allocator.create(QueuedSszBytes);
    errdefer allocator.destroy(queued);

    const ssz_copy = try allocator.dupe(u8, ssz_bytes);
    queued.* = .{
        .ssz_bytes = ssz_copy,
        .allocator = allocator,
        .fork_seq = fork_seq,
    };
    return processor_mod.work_item.GossipDataHandle.initOwned(QueuedSszBytes, queued);
}

test "processorHandlerCallback imports queued voluntary exits" {
    const allocator = std.testing.allocator;

    var ctx = ProcessorImportTestContext{};
    var node: BeaconNode = undefined;
    node.allocator = allocator;

    var gh: GossipHandler = undefined;
    gh.node = @ptrCast(&ctx);
    gh.importVoluntaryExitFn = &ProcessorImportTestContext.importVoluntaryExit;
    node.gossip_handler = &gh;

    var exit = types.phase0.SignedVoluntaryExit.Type{
        .message = .{
            .epoch = 12,
            .validator_index = 34,
        },
        .signature = [_]u8{0} ** 96,
    };
    const ssz_size = types.phase0.SignedVoluntaryExit.fixed_size;
    const ssz_bytes = try allocator.alloc(u8, ssz_size);
    defer allocator.free(ssz_bytes);
    _ = types.phase0.SignedVoluntaryExit.serializeIntoBytes(&exit, ssz_bytes);

    processorHandlerCallback(.{ .gossip_voluntary_exit = .{
        .source = .{ .key = 1 },
        .message_id = std.mem.zeroes(processor_mod.work_item.MessageId),
        .exit = exit,
        .seen_timestamp_ns = 0,
    } }, @ptrCast(&node));

    try std.testing.expectEqual(@as(?u64, 34), ctx.validator_index);
    try std.testing.expectEqual(@as(?u64, 12), ctx.exit_epoch);
}

test "processorHandlerCallback imports queued aggregates" {
    const allocator = std.testing.allocator;

    var ctx = ProcessorImportTestContext{};
    var node: BeaconNode = undefined;
    node.allocator = allocator;

    var gh: GossipHandler = undefined;
    gh.node = @ptrCast(&ctx);
    gh.importResolvedAggregateFn = &ProcessorImportTestContext.importAggregate;
    gh.verifyAggregateSignatureFn = null;
    node.gossip_handler = &gh;

    var signed_agg = types.phase0.SignedAggregateAndProof.default_value;
    signed_agg.message.aggregator_index = 21;
    signed_agg.message.aggregate.data.slot = 123;
    signed_agg.message.aggregate.data.target.epoch = 4;

    processorHandlerCallback(.{ .aggregate = .{
        .source = .{ .key = 1 },
        .message_id = std.mem.zeroes(processor_mod.work_item.MessageId),
        .aggregate = .{ .phase0 = signed_agg },
        .attestation_data_root = [_]u8{0} ** 32,
        .resolved = .{
            .attestation_signing_root = [_]u8{0} ** 32,
            .selection_signing_root = [_]u8{0} ** 32,
            .aggregate_signing_root = [_]u8{0} ** 32,
            .attesting_indices = &.{},
        },
        .seen_timestamp_ns = 0,
    } }, @ptrCast(&node));

    try std.testing.expectEqual(@as(usize, 1), ctx.aggregate_import_count);
    try std.testing.expectEqual(@as(?u64, 21), ctx.aggregate_aggregator_index);
    try std.testing.expectEqual(@as(?u64, 123), ctx.aggregate_slot);
    try std.testing.expectEqual(@as(?u64, 4), ctx.aggregate_target_epoch);
}

test "processorHandlerCallback imports queued aggregate batches" {
    const allocator = std.testing.allocator;

    var ctx = ProcessorImportTestContext{};
    var node: BeaconNode = undefined;
    node.allocator = allocator;

    var gh: GossipHandler = undefined;
    gh.node = @ptrCast(&ctx);
    gh.importResolvedAggregateFn = &ProcessorImportTestContext.importAggregate;
    gh.verifyAggregateSignatureFn = null;
    node.gossip_handler = &gh;

    var signed_agg_1 = types.phase0.SignedAggregateAndProof.default_value;
    signed_agg_1.message.aggregator_index = 21;
    signed_agg_1.message.aggregate.data.slot = 123;
    signed_agg_1.message.aggregate.data.target.epoch = 4;

    var signed_agg_2 = types.phase0.SignedAggregateAndProof.default_value;
    signed_agg_2.message.aggregator_index = 22;
    signed_agg_2.message.aggregate.data.slot = 124;
    signed_agg_2.message.aggregate.data.target.epoch = 5;

    var batch_items = [_]processor_mod.work_item.AggregateWork{
        .{
            .source = .{ .key = 1 },
            .message_id = std.mem.zeroes(processor_mod.work_item.MessageId),
            .aggregate = .{ .phase0 = signed_agg_1 },
            .attestation_data_root = [_]u8{0} ** 32,
            .resolved = .{
                .attestation_signing_root = [_]u8{0} ** 32,
                .selection_signing_root = [_]u8{0} ** 32,
                .aggregate_signing_root = [_]u8{0} ** 32,
                .attesting_indices = &.{},
            },
            .seen_timestamp_ns = 0,
        },
        .{
            .source = .{ .key = 2 },
            .message_id = std.mem.zeroes(processor_mod.work_item.MessageId),
            .aggregate = .{ .phase0 = signed_agg_2 },
            .attestation_data_root = [_]u8{0} ** 32,
            .resolved = .{
                .attestation_signing_root = [_]u8{0} ** 32,
                .selection_signing_root = [_]u8{0} ** 32,
                .aggregate_signing_root = [_]u8{0} ** 32,
                .attesting_indices = &.{},
            },
            .seen_timestamp_ns = 0,
        },
    };

    processorHandlerCallback(.{ .aggregate_batch = .{
        .items = &batch_items,
        .count = batch_items.len,
    } }, @ptrCast(&node));

    try std.testing.expectEqual(@as(usize, 2), ctx.aggregate_import_count);
    try std.testing.expectEqual(@as(?u64, 22), ctx.aggregate_aggregator_index);
    try std.testing.expectEqual(@as(?u64, 124), ctx.aggregate_slot);
    try std.testing.expectEqual(@as(?u64, 5), ctx.aggregate_target_epoch);
}

test "processorHandlerCallback imports queued attestations" {
    const allocator = std.testing.allocator;

    var ctx = ProcessorImportTestContext{};
    var node: BeaconNode = undefined;
    node.allocator = allocator;

    var gh: GossipHandler = undefined;
    gh.node = @ptrCast(&ctx);
    gh.importResolvedAttestationFn = &ProcessorImportTestContext.importAttestation;
    gh.verifyAttestationSignatureFn = null;
    node.gossip_handler = &gh;

    var attestation = types.electra.SingleAttestation.default_value;
    attestation.committee_index = 7;
    attestation.attester_index = 19;
    attestation.data.slot = 222;
    var attestation_data_root: [32]u8 = undefined;
    try types.phase0.AttestationData.hashTreeRoot(&attestation.data, &attestation_data_root);

    processorHandlerCallback(.{ .attestation = .{
        .source = .{ .key = 1 },
        .message_id = std.mem.zeroes(processor_mod.work_item.MessageId),
        .attestation = .{ .electra_single = attestation },
        .attestation_data_root = attestation_data_root,
        .resolved = .{
            .validator_index = 19,
            .validator_committee_index = 0,
            .committee_size = 1,
            .signing_root = [_]u8{0x33} ** 32,
            .expected_subnet = 0,
        },
        .subnet_id = 0,
        .seen_timestamp_ns = 0,
    } }, @ptrCast(&node));

    try std.testing.expectEqual(@as(?u64, 222), ctx.attestation_slot);
    try std.testing.expectEqual(@as(?u64, 7), ctx.attestation_committee_index);
    try std.testing.expect(ctx.attestation_is_electra_single);
    try std.testing.expectEqual(@as(?u64, 19), ctx.validator_index);
}

test "processorHandlerCallback imports queued sync committee messages" {
    const allocator = std.testing.allocator;

    var ctx = ProcessorImportTestContext{};
    var node: BeaconNode = undefined;
    node.allocator = allocator;

    var gh: GossipHandler = undefined;
    gh.node = @ptrCast(&ctx);
    gh.importSyncCommitteeMessageFn = &ProcessorImportTestContext.importSyncCommitteeMessage;
    node.gossip_handler = &gh;

    var msg = types.altair.SyncCommitteeMessage.Type{
        .slot = 99,
        .beacon_block_root = [_]u8{0xAB} ** 32,
        .validator_index = 7,
        .signature = [_]u8{0xCD} ** 96,
    };
    const ssz_size = types.altair.SyncCommitteeMessage.fixed_size;
    const ssz_bytes = try allocator.alloc(u8, ssz_size);
    defer allocator.free(ssz_bytes);
    _ = types.altair.SyncCommitteeMessage.serializeIntoBytes(&msg, ssz_bytes);

    processorHandlerCallback(.{ .sync_message = .{
        .source = .{ .key = 1 },
        .message_id = std.mem.zeroes(processor_mod.work_item.MessageId),
        .message = msg,
        .subnet_id = 3,
        .seen_timestamp_ns = 0,
    } }, @ptrCast(&node));

    try std.testing.expectEqual(@as(?u64, 3), ctx.sync_subnet);
    try std.testing.expectEqual(@as(?u64, 99), ctx.sync_slot);
    try std.testing.expectEqual(@as(?u64, 7), ctx.sync_validator_index);
}

test "processorHandlerCallback imports queued blob sidecars" {
    const allocator = std.testing.allocator;

    var ctx = ProcessorImportTestContext{};
    var node: BeaconNode = undefined;
    node.allocator = allocator;

    var gh: GossipHandler = undefined;
    gh.node = @ptrCast(&ctx);
    gh.importBlobSidecarFn = &ProcessorImportTestContext.importBlobSidecar;
    node.gossip_handler = &gh;

    const ssz_bytes = try allocator.dupe(u8, "blob-sidecar");
    defer allocator.free(ssz_bytes);

    processorHandlerCallback(.{ .gossip_blob = .{
        .source = .{ .key = 1 },
        .message_id = std.mem.zeroes(processor_mod.work_item.MessageId),
        .data = try makeQueuedSszHandle(allocator, .deneb, ssz_bytes),
        .seen_timestamp_ns = 0,
    } }, @ptrCast(&node));

    try std.testing.expectEqual(ssz_bytes.len, ctx.blob_bytes_len);
}

test "processorHandlerCallback imports queued data column sidecars" {
    const allocator = std.testing.allocator;

    var ctx = ProcessorImportTestContext{};
    var node: BeaconNode = undefined;
    node.allocator = allocator;

    var gh: GossipHandler = undefined;
    gh.node = @ptrCast(&ctx);
    gh.importDataColumnSidecarFn = &ProcessorImportTestContext.importDataColumnSidecar;
    node.gossip_handler = &gh;

    const ssz_bytes = try allocator.dupe(u8, "data-column-sidecar");
    defer allocator.free(ssz_bytes);

    processorHandlerCallback(.{ .gossip_data_column = .{
        .source = .{ .key = 1 },
        .message_id = std.mem.zeroes(processor_mod.work_item.MessageId),
        .data = try makeQueuedSszHandle(allocator, .fulu, ssz_bytes),
        .seen_timestamp_ns = 0,
    } }, @ptrCast(&node));

    try std.testing.expectEqual(ssz_bytes.len, ctx.data_column_bytes_len);
}
