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
const node_log = std.log.scoped(.node);
const chain_log = std.log.scoped(.chain);
const rest_log = std.log.scoped(.rest);

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
const db_mod = @import("db");
const Chain = chain_mod.Chain;
const ChainRuntime = chain_mod.Runtime;
const ChainRuntimeMetricsSnapshot = chain_mod.MetricsSnapshot;
const DatabaseMetricsSnapshot = db_mod.MetricsSnapshot;
const PeerManagerMetricsSnapshot = networking.PeerManagerMetricsSnapshot;
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
const DiscoveryStats = networking.discovery_service.DiscoveryStats;
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
const SyncServiceMetricsSnapshot = sync_mod.sync_service.MetricsSnapshot;
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
const pending_unknown_block_gossip_mod = @import("pending_unknown_block_gossip.zig");

// BeaconProcessor — central priority scheduling loop.
const processor_mod = @import("processor");
const BeaconProcessor = processor_mod.BeaconProcessor;
const ProcessorMetricsSnapshot = processor_mod.processor.MetricsSnapshot;
const QueueConfig = processor_mod.QueueConfig;
const WorkItem = processor_mod.WorkItem;
const WorkQueues = processor_mod.WorkQueues;
const AttestationWork = processor_mod.work_item.AttestationWork;
const AggregateWork = processor_mod.work_item.AggregateWork;
const ResolvedAggregate = processor_mod.work_item.ResolvedAggregate;
const ResolvedAttestation = processor_mod.work_item.ResolvedAttestation;
const PendingUnknownBlockGossipQueue = pending_unknown_block_gossip_mod.Queue;
const PendingUnknownBlockGossipItem = pending_unknown_block_gossip_mod.PendingItem;
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

const SyncStatusInputs = struct {
    head_slot: u64,
    sync_distance: u64,
    connected_peers: u32,
    is_optimistic: bool,
    el_offline: bool,
    has_wall_slot: bool,
};

const ComputedSyncStatus = struct {
    status: SyncStatus,
    sync_state: u64,
};

const HeadProgressSnapshot = struct {
    slot: u64,
    optimistic: bool,
};

const SyncMetricsCache = struct {
    const optimistic_bit: u64 = @as(u64, 1) << 63;

    latest_head_progress: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    head_catchup_pending_slots: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    fn headProgress(self: *const @This()) HeadProgressSnapshot {
        const encoded = self.latest_head_progress.load(.acquire);
        return .{
            .slot = encoded & ~optimistic_bit,
            .optimistic = (encoded & optimistic_bit) != 0,
        };
    }

    fn headCatchupPendingCount(self: *const @This()) u64 {
        return self.head_catchup_pending_slots.load(.acquire);
    }

    fn syncHeadProgress(self: *@This(), head_slot: u64, optimistic: bool) void {
        std.debug.assert(head_slot < optimistic_bit);
        self.latest_head_progress.store(
            head_slot | if (optimistic) optimistic_bit else 0,
            .release,
        );
    }

    fn setHeadCatchupPendingCount(self: *@This(), pending_slots: u64) void {
        self.head_catchup_pending_slots.store(pending_slots, .release);
    }
};

const SyncSegmentKey = struct {
    chain_id: u32,
    batch_id: BatchId,
    generation: u32,
};

pub const BlockIngressTicket = u64;
pub const WaitAsyncIdleResult = enum {
    idle,
    shutdown,
};

const QueuedStateWorkOwner = union(enum) {
    generic: ?BlockIngressTicket,
    sync_segment: SyncSegmentKey,
};

pub const QueuedBlockIngressCompletion = union(enum) {
    ignored: anyerror,
    imported: ImportResult,
    failed: anyerror,
};

const CompletedQueuedBlockIngress = struct {
    ticket: BlockIngressTicket,
    completion: QueuedBlockIngressCompletion,
};

// Keep the secondary planned-import backlog in the same range as the
// unknown-parent sync DOS limit. The stash's 1024-entry queue was too large
// for full block inputs with attached data.
const max_waiting_planned_block_imports: usize = sync_mod.sync_types.MAX_PENDING_BLOCKS;

const WaitingPlannedBlockImport = struct {
    owner: ?BlockIngressTicket,
    planned: chain_mod.blocks.PlannedBlockImport,

    pub fn deinit(self: *WaitingPlannedBlockImport, allocator: Allocator) void {
        self.planned.deinit(allocator);
        self.* = undefined;
    }
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
    optimistic_imported_count: usize = 0,
    epoch_transition_count: usize = 0,
    error_counts: chain_mod.BlockImportErrorCounts = .{},
    stop_after_current: bool = false,

    pub fn deinit(self: *PendingSyncSegment, allocator: Allocator) void {
        freeBatchBlocks(allocator, self.blocks);
        self.* = undefined;
    }
};

const RangeSyncSegmentLogContext = struct {
    sync_type: RangeSyncType,
    total_blocks: usize,
    key: ?SyncSegmentKey = null,
};

const max_tracked_head_catchup_slots = 64;

const PendingHeadCatchupSlot = struct {
    slot: u64 = 0,
    started_at_ns: i64 = 0,
};

const GossipBlsPendingSnapshot = struct {
    attestation_batches: u64 = 0,
    attestation_items: u64 = 0,
    aggregate_batches: u64 = 0,
    aggregate_items: u64 = 0,
    sync_message_batches: u64 = 0,
    sync_message_items: u64 = 0,
};

fn wallNowNs(io: std.Io) i64 {
    const now_ns = std.Io.Timestamp.now(io, .real).toNanoseconds();
    return std.math.cast(i64, now_ns) orelse if (now_ns < 0)
        std.math.minInt(i64)
    else
        std.math.maxInt(i64);
}

fn elapsedNsBetween(start_ns: i64, end_ns: i64) u64 {
    return if (end_ns > start_ns) @intCast(end_ns - start_ns) else 0;
}

fn secondsFromNs(elapsed_ns: u64) f64 {
    return @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));
}

fn millisFromNs(elapsed_ns: u64) u64 {
    return elapsed_ns / std.time.ns_per_ms;
}

fn cloneBatchBlocks(allocator: Allocator, blocks: []const BatchBlock) ![]BatchBlock {
    const owned = try allocator.alloc(BatchBlock, blocks.len);
    errdefer allocator.free(owned);

    for (blocks, 0..) |block, i| {
        const block_bytes = try allocator.dupe(u8, block.block_bytes);
        errdefer allocator.free(block_bytes);
        owned[i] = .{
            .slot = block.slot,
            .block_bytes = block_bytes,
        };
    }

    return owned;
}

fn freeBatchBlocks(allocator: Allocator, blocks: []const BatchBlock) void {
    for (blocks) |block| {
        allocator.free(block.block_bytes);
    }
    allocator.free(blocks);
}

fn segmentHasProcessingFailure(outcome: chain_mod.SegmentImportOutcome) bool {
    // Lodestar retries a range-sync batch whenever processing throws, even if
    // some earlier blocks in the segment were already known or finalized.
    // Advancing the batch past parent/prestate failures strands the chain.
    return outcome.failed_count > 0;
}

fn shouldDropIncomingStateWorkBacklog(
    owner: ?BlockIngressTicket,
    source: BlockSource,
) bool {
    return owner == null and source == .gossip;
}

fn shouldEvictWaitingStateWorkBacklog(
    waiting_owner: ?BlockIngressTicket,
    waiting_source: BlockSource,
    incoming_source: BlockSource,
) bool {
    return incoming_source != .gossip and shouldDropIncomingStateWorkBacklog(waiting_owner, waiting_source);
}

test "state work backlog drops only untracked gossip" {
    try std.testing.expect(shouldDropIncomingStateWorkBacklog(null, .gossip));
    try std.testing.expect(!shouldDropIncomingStateWorkBacklog(7, .gossip));
    try std.testing.expect(!shouldDropIncomingStateWorkBacklog(null, .unknown_block_sync));
    try std.testing.expect(!shouldDropIncomingStateWorkBacklog(null, .api));
}

test "higher priority state work backlog can evict waiting gossip" {
    try std.testing.expect(shouldEvictWaitingStateWorkBacklog(null, .gossip, .unknown_block_sync));
    try std.testing.expect(shouldEvictWaitingStateWorkBacklog(null, .gossip, .api));
    try std.testing.expect(!shouldEvictWaitingStateWorkBacklog(null, .gossip, .gossip));
    try std.testing.expect(!shouldEvictWaitingStateWorkBacklog(3, .gossip, .unknown_block_sync));
    try std.testing.expect(!shouldEvictWaitingStateWorkBacklog(null, .unknown_block_sync, .api));
}

test "cloneBatchBlocks owns copied block bytes" {
    var source_bytes = [_]u8{ 0x01, 0x02, 0x03 };
    const source_blocks = [_]BatchBlock{
        .{ .slot = 12, .block_bytes = source_bytes[0..] },
    };

    const owned_blocks = try cloneBatchBlocks(std.testing.allocator, source_blocks[0..]);
    defer freeBatchBlocks(std.testing.allocator, owned_blocks);

    source_bytes[0] = 0xFF;
    try std.testing.expectEqual(@as(u64, 12), owned_blocks[0].slot);
    try std.testing.expectEqual(@as(u8, 0x01), owned_blocks[0].block_bytes[0]);
    try std.testing.expect(owned_blocks[0].block_bytes.ptr != source_blocks[0].block_bytes.ptr);
}

test "segmentHasProcessingFailure retries mixed skipped and failed outcomes" {
    try std.testing.expect(segmentHasProcessingFailure(.{
        .imported_count = 0,
        .skipped_count = 2,
        .failed_count = 1,
        .snapshot = undefined,
        .effects = .{},
    }));
    try std.testing.expect(!segmentHasProcessingFailure(.{
        .imported_count = 0,
        .skipped_count = 2,
        .failed_count = 0,
        .snapshot = undefined,
        .effects = .{},
    }));
}

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

pub const DiscoveryDialCompletion = union(enum) {
    success: struct {
        peer_id: []const u8,
        predicted_peer_id: []const u8,
        ma_str: []const u8,
        node_id: [32]u8,
        pubkey: [33]u8,
        elapsed_ns: u64,
    },
    failure: struct {
        predicted_peer_id: []const u8,
        ma_str: []const u8,
        err: anyerror,
        elapsed_ns: u64,
    },

    pub fn deinit(self: *DiscoveryDialCompletion, allocator: Allocator) void {
        switch (self.*) {
            .success => |success| {
                allocator.free(success.peer_id);
                allocator.free(success.predicted_peer_id);
                allocator.free(success.ma_str);
            },
            .failure => |failure| {
                allocator.free(failure.predicted_peer_id);
                allocator.free(failure.ma_str);
            },
        }
        self.* = undefined;
    }
};

pub const PeerReqRespMetadata = struct {
    metadata: networking.messages.MetadataV2.Type,
    custody_group_count: ?u64 = null,
};

pub const PeerReqRespCompletion = union(enum) {
    status: struct {
        peer_id: []const u8,
        status: StatusMessage.Type,
        earliest_available_slot: ?u64 = null,
        metadata: ?PeerReqRespMetadata = null,
        follow_up_ping: bool = false,
    },
    ping: struct {
        peer_id: []const u8,
        remote_seq: u64,
        metadata: ?PeerReqRespMetadata = null,
    },
    failure: struct {
        peer_id: []const u8,
        protocol: networking.ReqRespScoringProtocol,
        err: anyerror,
        disconnect_peer: bool = true,
    },

    pub fn peerId(self: *const PeerReqRespCompletion) []const u8 {
        return switch (self.*) {
            .status => |status| status.peer_id,
            .ping => |ping| ping.peer_id,
            .failure => |failure| failure.peer_id,
        };
    }

    pub fn deinit(self: *PeerReqRespCompletion, allocator: Allocator) void {
        allocator.free(self.peerId());
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
        pubkey_cache_path: ?[]const u8 = null,
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
        pubkey_cache_path: ?[]const u8 = null,
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
    last_chain_metrics_snapshot: ?ChainRuntimeMetricsSnapshot = null,
    last_peer_manager_metrics_snapshot: ?PeerManagerMetricsSnapshot = null,
    last_processor_metrics_snapshot: ?ProcessorMetricsSnapshot = null,
    last_discovery_stats: ?DiscoveryStats = null,
    last_sync_service_metrics_snapshot: ?SyncServiceMetricsSnapshot = null,
    last_db_metrics_snapshot: ?DatabaseMetricsSnapshot = null,
    last_state_metrics_root: ?[32]u8 = null,
    last_previous_epoch_orphaned_epoch: ?u64 = null,

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
    discovery_dial_mutex: std.Io.Mutex = .init,
    completed_discovery_dials: std.ArrayListUnmanaged(DiscoveryDialCompletion) = .empty,
    pending_discovery_dial_count: usize = 0,
    peer_reqresp_mutex: std.Io.Mutex = .init,
    pending_peer_reqresp_ids: std.ArrayListUnmanaged([]const u8) = .empty,
    completed_peer_reqresp: std.ArrayListUnmanaged(PeerReqRespCompletion) = .empty,

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
    last_gossipsub_topic_mismatch_log_ns: u64 = 0,

    // Last slot for which chain.onSlot() was applied.
    last_slot_tick: ?u64 = null,
    last_time_to_head_observed_slot: ?u64 = null,
    sync_metrics_cache: SyncMetricsCache = .{},
    head_catchup_slots: [max_tracked_head_catchup_slots]PendingHeadCatchupSlot = [_]PendingHeadCatchupSlot{.{}} ** max_tracked_head_catchup_slots,
    head_catchup_slots_len: usize = 0,

    // Sync subsystem components (lazily initialized when P2P starts).

    sync_service_inst: ?*SyncService = null,
    sync_callback_ctx: ?*SyncCallbackCtx = null, // bridges to P2P transport
    waiting_planned_block_imports: std.ArrayListUnmanaged(WaitingPlannedBlockImport) = .empty,
    queued_state_work_owners: std.ArrayListUnmanaged(QueuedStateWorkOwner) = .empty,
    completed_block_ingresses: std.ArrayListUnmanaged(CompletedQueuedBlockIngress) = .empty,
    waiting_execution_payloads: std.ArrayListUnmanaged(WaitingExecutionPayload) = .empty,
    pending_execution_payloads: std.ArrayListUnmanaged(PendingExecutionPayload) = .empty,
    next_block_ingress_ticket: BlockIngressTicket = 1,
    pending_block_ingress_count: usize = 0,
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

    /// Gossip attestations and aggregates parked behind an unknown
    /// `beacon_block_root` until that block is imported.
    pending_unknown_block_gossip: PendingUnknownBlockGossipQueue,

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

    // Best-effort warm-start cache path for validator pubkeys.
    pubkey_cache_path: ?[]const u8 = null,

    /// Earliest slot this node can honestly serve over req/resp.
    earliest_available_slot: u64 = 0,

    // Node configuration options — stored for lazy-initialized components.
    node_options: NodeOptions = .{},

    // Explicit bootstrap peers to dial during startup.
    bootstrap_peers: []const []const u8 = &.{},

    // Discovery seed ENRs prepared by the launcher.
    discovery_bootnodes: []const []const u8 = &.{},

    // Runtime bootstrap cursor for `--direct-peers` dialing.
    next_direct_peer_index: usize = 0,

    // Identify agent version exposed on libp2p identify. Null hides it.
    identify_agent_version: ?[]const u8 = null,

    /// Set to true to request graceful shutdown of all event loops.
    shutdown_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// Signal all loops to stop.
    pub fn requestShutdown(self: *BeaconNode) void {
        self.shutdown_requested.store(true, .release);
        if (self.http_server) |*srv| srv.shutdown(self.io);
    }

    /// Keep the experimental header-only unknown-chain path disabled in the
    /// live node until it proves more robust than the Lodestar-style orphan
    /// recovery path that already exists through UnknownBlockSync.
    pub fn unknownChainSyncEnabled(_: *const BeaconNode) bool {
        return false;
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
        return switch (try self.completeReadyIngressDetailed(ready, null, .untracked)) {
            .ignored => .ignored,
            .pending => .ignored,
            .queued => .queued,
            .imported => |result| .{ .imported = result },
        };
    }

    pub fn ingestBlockTracked(
        self: *BeaconNode,
        any_signed: AnySignedBeaconBlock,
        source: BlockSource,
    ) !TrackedReadyIngressResult {
        const ready = try self.chainService().prepareBlockInput(any_signed, source);
        return switch (try self.completeReadyIngressDetailed(ready, null, .tracked)) {
            .ignored => .ignored,
            .pending => .ignored,
            .queued => |ticket| .{ .queued = ticket orelse @panic("tracked ingress missing ticket") },
            .imported => |result| .{ .imported = result },
        };
    }

    pub const ReadyIngressResult = union(enum) {
        ignored,
        queued,
        imported: ImportResult,
    };

    pub const TrackedReadyIngressResult = union(enum) {
        ignored,
        queued: BlockIngressTicket,
        imported: ImportResult,
    };

    pub const PreparedBlockIngressResult = union(enum) {
        ignored,
        pending,
        imported: ImportResult,
    };

    const DetailedReadyIngressResult = union(enum) {
        ignored,
        pending,
        queued: ?BlockIngressTicket,
        imported: ImportResult,
    };

    pub fn ingestRawBlockBytes(
        self: *BeaconNode,
        block_bytes: []const u8,
        source: BlockSource,
    ) !ReadyIngressResult {
        const ready = try self.chainService().prepareRawBlockInput(block_bytes, source);
        return switch (try self.completeReadyIngressDetailed(ready, block_bytes, .untracked)) {
            .ignored => .ignored,
            .pending => .ignored,
            .queued => .queued,
            .imported => |result| .{ .imported = result },
        };
    }

    pub fn ingestRawBlockBytesTracked(
        self: *BeaconNode,
        block_bytes: []const u8,
        source: BlockSource,
    ) !TrackedReadyIngressResult {
        const ready = try self.chainService().prepareRawBlockInput(block_bytes, source);
        return switch (try self.completeReadyIngressDetailed(ready, block_bytes, .tracked)) {
            .ignored => .ignored,
            .pending => .ignored,
            .queued => |ticket| .{ .queued = ticket orelse @panic("tracked ingress missing ticket") },
            .imported => |result| .{ .imported = result },
        };
    }

    pub fn importReadyBlock(
        self: *BeaconNode,
        ready: chain_mod.ReadyBlockInput,
    ) !ReadyIngressResult {
        return switch (try self.completeReadyIngressDetailed(ready, null, .untracked)) {
            .ignored => .ignored,
            .pending => .ignored,
            .queued => .queued,
            .imported => |result| .{ .imported = result },
        };
    }

    pub fn importReadyBlockTracked(
        self: *BeaconNode,
        ready: chain_mod.ReadyBlockInput,
    ) !TrackedReadyIngressResult {
        return switch (try self.completeReadyIngressDetailed(ready, null, .tracked)) {
            .ignored => .ignored,
            .pending => .ignored,
            .queued => |ticket| .{ .queued = ticket orelse @panic("tracked ingress missing ticket") },
            .imported => |result| .{ .imported = result },
        };
    }

    pub fn completeReadyIngress(
        self: *BeaconNode,
        ready: chain_mod.ReadyBlockInput,
        raw_block_bytes: ?[]const u8,
    ) !?ImportResult {
        return switch (try self.completeReadyIngressDetailed(ready, raw_block_bytes, .untracked)) {
            .ignored => null,
            .pending => null,
            .queued => null,
            .imported => |result| result,
        };
    }

    pub fn importPreparedBlock(
        self: *BeaconNode,
        prepared: chain_mod.PreparedBlockInput,
    ) !PreparedBlockIngressResult {
        if (prepared.source == .gossip) {
            const accepted = try self.chainService().acceptPreparedGossipBlock(prepared);
            return switch (accepted) {
                .pending_block_data => {
                    self.recordBlockImportResult(.gossip, "pending_block_data", 1);
                    return .pending;
                },
                .ready => |ready| switch (try self.completeReadyIngressDetailed(ready, null, .untracked)) {
                    .ignored => .ignored,
                    .pending, .queued => .pending,
                    .imported => |result| .{ .imported = result },
                },
            };
        }

        const ready = try self.chainService().readyBlockInputFromPrepared(prepared);
        return switch (try self.completeReadyIngressDetailed(ready, null, .untracked)) {
            .ignored => .ignored,
            .pending, .queued => .pending,
            .imported => |result| .{ .imported = result },
        };
    }

    fn completeReadyIngressDetailed(
        self: *BeaconNode,
        ready: chain_mod.ReadyBlockInput,
        raw_block_bytes: ?[]const u8,
        receipt_mode: enum { untracked, tracked },
    ) !DetailedReadyIngressResult {
        var owned_ready = ready;

        const planned = self.chainService().planReadyBlockImport(&owned_ready) catch |err| {
            switch (err) {
                error.ParentUnknown => {
                    _ = raw_block_bytes;
                    const peer_id = owned_ready.peerId();
                    const prepared = owned_ready.intoPrepared(self.allocator);
                    _ = try self.queueOrphanPreparedBlock(prepared, peer_id);
                    return .pending;
                },
                error.AlreadyKnown, error.WouldRevertFinalizedSlot => {
                    self.recordBlockImportResult(owned_ready.source, blockImportOutcomeLabel(err), 1);
                    owned_ready.deinit(self.allocator);
                    return .ignored;
                },
                else => {
                    self.recordBlockImportResult(owned_ready.source, blockImportOutcomeLabel(err), 1);
                    owned_ready.deinit(self.allocator);
                    return err;
                },
            }
        };

        const maybe_ticket = switch (receipt_mode) {
            .untracked => null,
            .tracked => try self.reserveBlockIngressTicket(),
        };
        var ticket_reserved = maybe_ticket != null;
        errdefer if (ticket_reserved) self.releaseReservedBlockIngressTicket();

        try self.queued_state_work_owners.ensureUnusedCapacity(self.allocator, 1);

        var owned_planned = planned;
        const queue_result = self.chainService().tryQueuePlannedReadyBlockImport(owned_planned) catch |err| {
            self.chainService().deinitPlannedReadyBlockImport(&owned_planned);
            return err;
        };
        switch (queue_result) {
            .queued => {
                self.queued_state_work_owners.appendAssumeCapacity(.{ .generic = maybe_ticket });
                ticket_reserved = false;
                owned_planned = undefined;
                return .{ .queued = maybe_ticket };
            },
            .not_queued => |returned_planned| {
                owned_planned = returned_planned;
                const block_slot = owned_planned.block_input.block.beaconBlock().slot();
                const source = owned_planned.block_input.source;

                if (self.waiting_planned_block_imports.items.len >= max_waiting_planned_block_imports) {
                    for (self.waiting_planned_block_imports.items, 0..) |waiting, i| {
                        if (!shouldEvictWaitingStateWorkBacklog(waiting.owner, waiting.planned.block_input.source, source)) continue;

                        var evicted = self.waiting_planned_block_imports.orderedRemove(i);
                        self.recordBlockImportResult(evicted.planned.block_input.source, "dropped_state_work_backlog_evicted", 1);
                        node_log.debug(
                            "evicting deferred gossip block from state work backlog slot={d} source={s}",
                            .{
                                evicted.planned.block_input.block.beaconBlock().slot(),
                                blockImportSourceLabel(evicted.planned.block_input.source),
                            },
                        );
                        evicted.deinit(self.allocator);
                        break;
                    }
                }

                if (self.waiting_planned_block_imports.items.len >= max_waiting_planned_block_imports) {
                    self.recordBlockImportResult(source, "dropped_state_work_backlog_full", 1);
                    node_log.debug(
                        "state work backlog full, dropping ready block slot={d} source={s} backlog={d}",
                        .{
                            block_slot,
                            blockImportSourceLabel(source),
                            self.waiting_planned_block_imports.items.len,
                        },
                    );
                    self.chainService().deinitPlannedReadyBlockImport(&owned_planned);
                    if (shouldDropIncomingStateWorkBacklog(maybe_ticket, source)) {
                        if (ticket_reserved) {
                            self.releaseReservedBlockIngressTicket();
                            ticket_reserved = false;
                        }
                        return .ignored;
                    }
                    return error.StateWorkBacklogFull;
                }

                try self.waiting_planned_block_imports.ensureUnusedCapacity(self.allocator, 1);
                self.waiting_planned_block_imports.appendAssumeCapacity(.{
                    .owner = maybe_ticket,
                    .planned = owned_planned,
                });
                ticket_reserved = false;
                owned_planned = undefined;
                self.recordBlockImportResult(source, "queued_state_work_backlog", 1);
                node_log.debug("state work queue busy, queued ready block backlog slot={d} source={s} backlog={d}", .{
                    block_slot,
                    blockImportSourceLabel(source),
                    self.waiting_planned_block_imports.items.len,
                });
                return .{ .queued = maybe_ticket };
            },
        }
    }

    fn reserveBlockIngressTicket(self: *BeaconNode) !BlockIngressTicket {
        const required_capacity = self.completed_block_ingresses.items.len + self.pending_block_ingress_count + 1;
        try self.completed_block_ingresses.ensureTotalCapacity(self.allocator, required_capacity);
        const ticket = self.next_block_ingress_ticket;
        self.next_block_ingress_ticket += 1;
        self.pending_block_ingress_count += 1;
        return ticket;
    }

    fn releaseReservedBlockIngressTicket(self: *BeaconNode) void {
        if (self.pending_block_ingress_count == 0) {
            @panic("released queued block ingress ticket without reservation");
        }
        self.pending_block_ingress_count -= 1;
    }

    fn recordCompletedBlockIngress(
        self: *BeaconNode,
        ticket: BlockIngressTicket,
        completion: QueuedBlockIngressCompletion,
    ) void {
        if (self.pending_block_ingress_count == 0) {
            @panic("completed queued block ingress without reservation");
        }
        self.completed_block_ingresses.appendAssumeCapacity(.{
            .ticket = ticket,
            .completion = completion,
        });
        self.pending_block_ingress_count -= 1;
    }

    fn isIgnoredBlockImportError(err: anyerror) bool {
        return switch (err) {
            error.AlreadyKnown,
            error.WouldRevertFinalizedSlot,
            error.GenesisBlock,
            => true,
            else => false,
        };
    }

    fn recordGenericBlockIngressError(
        self: *BeaconNode,
        ticket: ?BlockIngressTicket,
        err: anyerror,
    ) void {
        const owned_ticket = ticket orelse return;
        if (isIgnoredBlockImportError(err)) {
            self.recordCompletedBlockIngress(owned_ticket, .{ .ignored = err });
            return;
        }
        self.recordCompletedBlockIngress(owned_ticket, .{ .failed = err });
    }

    pub fn takeCompletedBlockIngress(
        self: *BeaconNode,
        ticket: BlockIngressTicket,
    ) ?QueuedBlockIngressCompletion {
        for (self.completed_block_ingresses.items, 0..) |completed, i| {
            if (completed.ticket != ticket) continue;
            return self.completed_block_ingresses.orderedRemove(i).completion;
        }
        return null;
    }

    pub const WaitTrackedBlockIngressResult = union(enum) {
        completed: QueuedBlockIngressCompletion,
        shutdown,
        lost,
    };

    const TrackedBlockIngressPhase = enum {
        state_work,
        execution,
        none,
    };

    pub fn waitForTrackedBlockIngress(
        self: *BeaconNode,
        ticket: BlockIngressTicket,
    ) WaitTrackedBlockIngressResult {
        while (true) {
            if (self.takeCompletedBlockIngress(ticket)) |completion| {
                return .{ .completed = completion };
            }

            _ = self.processPendingBlockStateWork();
            _ = self.processPendingExecutionPayloadVerifications();
            _ = self.processPendingExecutionForkchoiceUpdates();
            self.dispatchWaitingExecutionPayloads();

            if (self.takeCompletedBlockIngress(ticket)) |completion| {
                return .{ .completed = completion };
            }

            switch (self.trackedBlockIngressPhase(ticket)) {
                .execution => switch (self.execution_runtime.waitForAsyncCompletion()) {
                    .completed => continue,
                    .shutdown => return .shutdown,
                    .idle => {
                        if (self.trackedBlockIngressPhase(ticket) == .none) return .lost;
                        continue;
                    },
                },
                .state_work => switch (self.chainService().waitForCompletedReadyBlockImport()) {
                    .completed => continue,
                    .shutdown => return .shutdown,
                    .idle => {
                        if (self.trackedBlockIngressPhase(ticket) == .none) return .lost;
                        continue;
                    },
                },
                .none => return .lost,
            }
        }
    }

    pub fn waitForAsyncIdle(self: *BeaconNode) WaitAsyncIdleResult {
        while (true) {
            _ = self.processPendingBlockStateWork();
            _ = self.processPendingExecutionPayloadVerifications();
            _ = self.processPendingExecutionForkchoiceUpdates();
            self.dispatchWaitingExecutionPayloads();

            switch (self.chainService().waitForCompletedReadyBlockImport()) {
                .completed => continue,
                .shutdown => return .shutdown,
                .idle => {},
            }

            switch (self.execution_runtime.waitForAsyncCompletion()) {
                .completed => continue,
                .shutdown => return .shutdown,
                .idle => return .idle,
            }
        }
    }

    fn trackedBlockIngressPhase(
        self: *BeaconNode,
        ticket: BlockIngressTicket,
    ) TrackedBlockIngressPhase {
        if (self.hasTrackedExecutionPayload(ticket)) return .execution;
        if (self.hasQueuedTrackedBlockIngress(ticket)) return .state_work;
        return .none;
    }

    fn hasQueuedTrackedBlockIngress(self: *const BeaconNode, ticket: BlockIngressTicket) bool {
        for (self.waiting_planned_block_imports.items) |waiting| {
            if (waiting.owner == ticket) return true;
        }
        for (self.queued_state_work_owners.items) |owner| {
            switch (owner) {
                .generic => |maybe_ticket| if (maybe_ticket == ticket) return true,
                .sync_segment => {},
            }
        }
        return false;
    }

    fn hasTrackedExecutionPayload(self: *BeaconNode, ticket: BlockIngressTicket) bool {
        for (self.waiting_execution_payloads.items) |waiting| {
            switch (waiting) {
                .import => |import_work| switch (import_work.owner) {
                    .generic => |maybe_ticket| if (maybe_ticket == ticket) return true,
                    .sync_segment => {},
                },
                .revalidation => {},
            }
        }

        for (self.pending_execution_payloads.items) |pending| {
            switch (pending.work) {
                .import => |import_work| switch (import_work.owner) {
                    .generic => |maybe_ticket| if (maybe_ticket == ticket) return true,
                    .sync_segment => {},
                },
                .revalidation => {},
            }
        }

        return false;
    }

    pub fn processPendingBlockStateWork(self: *BeaconNode) bool {
        var did_work = false;

        while (self.chainService().popCompletedReadyBlockImport()) |completed| {
            did_work = true;
            if (self.queued_state_work_owners.items.len == 0) {
                node_log.warn("missing queued state work owner for completed block work", .{});
                self.finishGenericQueuedBlockImport(null, completed);
                continue;
            }

            const owner = self.queued_state_work_owners.orderedRemove(0);
            switch (completed) {
                .failure => switch (owner) {
                    .generic => |ticket| self.finishGenericQueuedBlockImport(ticket, completed),
                    .sync_segment => |key| self.finishSyncSegmentQueuedBlockImport(key, completed),
                },
                .success => |prepared| {
                    self.queuePreparedBlockImportExecution(owner, prepared);
                },
            }
        }

        return self.dispatchWaitingPlannedBlockImports() or did_work;
    }

    fn dispatchWaitingPlannedBlockImports(self: *BeaconNode) bool {
        var did_work = false;

        while (self.waiting_planned_block_imports.items.len > 0) {
            self.queued_state_work_owners.ensureUnusedCapacity(self.allocator, 1) catch |err| {
                node_log.warn("failed to reserve queued state work owner slot: {}", .{err});
                break;
            };

            var waiting = &self.waiting_planned_block_imports.items[0];
            var owned_planned = waiting.planned;
            const owner = waiting.owner;
            const block_slot = owned_planned.block_input.block.beaconBlock().slot();
            const source = owned_planned.block_input.source;
            const queue_result = self.chainService().tryQueuePlannedReadyBlockImport(owned_planned) catch |err| {
                waiting.planned = undefined;
                _ = self.waiting_planned_block_imports.orderedRemove(0);
                self.recordBlockImportResult(source, blockImportOutcomeLabel(err), 1);
                node_log.warn("deferred block state work queue failed slot={d} source={s}: {}", .{
                    block_slot,
                    blockImportSourceLabel(source),
                    err,
                });
                if (owner) |ticket| {
                    self.recordCompletedBlockIngress(ticket, .{ .failed = err });
                }
                did_work = true;
                continue;
            };

            switch (queue_result) {
                .queued => {
                    waiting.planned = undefined;
                    _ = self.waiting_planned_block_imports.orderedRemove(0);
                    self.queued_state_work_owners.appendAssumeCapacity(.{ .generic = owner });
                    node_log.debug("queued deferred block state work slot={d} source={s} remaining_backlog={d}", .{
                        block_slot,
                        blockImportSourceLabel(source),
                        self.waiting_planned_block_imports.items.len,
                    });
                    did_work = true;
                },
                .not_queued => |returned_planned| {
                    waiting.planned = returned_planned;
                    break;
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
                node_log.warn("missing pending execution payload for completed newPayload result", .{});
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
                        node_log.warn("execution revalidation finish failed: {}", .{err});
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
            node_log.warn("Optimistic head revalidation planning failed: {}", .{err});
            return;
        } orelse return;

        self.waiting_execution_payloads.append(self.allocator, .{ .revalidation = prepared }) catch |err| {
            prepared.deinit(self.allocator);
            node_log.warn("failed to queue optimistic head revalidation: {}", .{err});
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
                node_log.warn("failed to allocate pending execution payload slot: {}", .{err});
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
                            node_log.warn("failed to requeue optimistic head revalidation: {}", .{err});
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
                    node_log.debug("forkchoiceUpdated: payload building started, id={s}", .{
                        &std.fmt.bytesToHex(payload_id[0..8], .lower),
                    });
                }
                node_log.debug("forkchoiceUpdated: status={s} head={s}... safe={s}... finalized={s}...", .{
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
            .generic => |ticket| self.finishGenericPreparedQueuedBlockImport(ticket, prepared, exec_status),
            .sync_segment => |key| self.finishSyncSegmentPreparedQueuedBlockImport(key, prepared, exec_status),
        }
    }

    fn finishGenericPreparedQueuedBlockImport(
        self: *BeaconNode,
        ticket: ?BlockIngressTicket,
        prepared: chain_mod.PreparedBlockImport,
        exec_status: chain_mod.ExecutionStatus,
    ) void {
        const t0 = std.Io.Clock.awake.now(self.io);
        var owned_prepared = prepared;
        defer {
            owned_prepared.deinit(self.allocator);
            owned_prepared = undefined;
        }

        const source = owned_prepared.block_input.source;
        const outcome = self.chainService().finishPreparedReadyBlockImport(&owned_prepared, exec_status) catch |err| {
            self.recordBlockImportResult(source, blockImportOutcomeLabel(err), 1);
            self.recordGenericBlockIngressError(ticket, err);
            node_log.warn("deferred block execution commit failed: {}", .{err});
            return;
        };
        const result = self.finishImportOutcome(source, t0, outcome) catch |err| {
            self.recordGenericBlockIngressError(ticket, err);
            node_log.warn("deferred block import commit failed: {}", .{err});
            return;
        };
        self.processPendingChildren(result.block_root);
        if (ticket) |owned_ticket| {
            self.recordCompletedBlockIngress(owned_ticket, .{ .imported = result });
        }
    }

    fn finishSyncSegmentPreparedQueuedBlockImport(
        self: *BeaconNode,
        key: SyncSegmentKey,
        prepared: chain_mod.PreparedBlockImport,
        exec_status: chain_mod.ExecutionStatus,
    ) void {
        const index = findPendingSyncSegmentIndex(self, key) orelse {
            node_log.warn("missing pending sync segment for prepared block commit", .{});
            self.finishGenericPreparedQueuedBlockImport(null, prepared, exec_status);
            return;
        };

        var segment = &self.pending_sync_segments.items[index];
        segment.in_flight = false;
        segment.next_index += 1;
        const block_index = segment.next_index - 1;

        var owned_prepared = prepared;
        defer {
            owned_prepared.deinit(self.allocator);
            owned_prepared = undefined;
        }

        const outcome = self.chainService().finishPreparedReadyBlockImport(&owned_prepared, exec_status) catch |err| {
            switch (err) {
                error.ExecutionPayloadInvalid => {
                    segment.failed_count += 1;
                    _ = recordBlockImportError(&segment.error_counts, error.ExecutionPayloadInvalid);
                    segment.stop_after_current = true;
                    self.recordRangeSyncSegmentFailure(segment.sync_type, .commit, err);
                },
                error.NotViableForHead => {
                    segment.failed_count += 1;
                    _ = recordBlockImportError(&segment.error_counts, err);
                    segment.stop_after_current = true;
                    self.recordRangeSyncSegmentFailure(segment.sync_type, .commit, err);
                },
                else => {
                    segment.failed_count += 1;
                    switch (err) {
                        error.ParentUnknown,
                        error.FutureSlot,
                        error.BlacklistedBlock,
                        error.InvalidProposer,
                        error.InvalidSignature,
                        error.DataUnavailable,
                        error.InvalidKzgProof,
                        error.PrestateMissing,
                        error.StateTransitionFailed,
                        error.InvalidStateRoot,
                        error.ExecutionEngineUnavailable,
                        error.ForkChoiceError,
                        error.InternalError,
                        => segment.error_counts.incr(err),
                        else => {},
                    }
                    self.recordRangeSyncSegmentFailure(segment.sync_type, .commit, err);
                    node_log.warn(
                        "deferred sync segment block commit failed slot_index={d} chain_id={d} batch_id={d} generation={d}: {}",
                        .{ block_index, segment.key.chain_id, segment.key.batch_id, segment.key.generation, err },
                    );
                },
            }
            return;
        };

        segment.imported_count += 1;
        if (outcome.result.execution_optimistic) segment.optimistic_imported_count += 1;
        if (outcome.result.epoch_transition) segment.epoch_transition_count += 1;
        node_log.debug("deferred range sync block imported slot={d} chain_id={d} batch_id={d} generation={d} imported={d} skipped={d} failed={d}", .{
            outcome.result.slot,
            segment.key.chain_id,
            segment.key.batch_id,
            segment.key.generation,
            segment.imported_count,
            segment.skipped_count,
            segment.failed_count,
        });
        self.processPendingChildren(outcome.result.block_root);
    }

    fn finishPreparedQueuedBlockImportError(
        self: *BeaconNode,
        owner: QueuedStateWorkOwner,
        prepared: chain_mod.PreparedBlockImport,
        err: anyerror,
    ) void {
        switch (owner) {
            .generic => |ticket| {
                self.recordBlockImportResult(prepared.block_input.source, blockImportOutcomeLabel(err), 1);
                self.recordGenericBlockIngressError(ticket, err);
                var owned_prepared = prepared;
                owned_prepared.deinit(self.allocator);
                node_log.warn("deferred block execution verification failed: {}", .{err});
            },
            .sync_segment => |key| {
                const index = findPendingSyncSegmentIndex(self, key) orelse {
                    var owned_prepared = prepared;
                    owned_prepared.deinit(self.allocator);
                    node_log.warn("missing pending sync segment for execution verification failure", .{});
                    return;
                };

                var segment = &self.pending_sync_segments.items[index];
                segment.in_flight = false;
                segment.next_index += 1;
                const block_index = segment.next_index - 1;

                switch (err) {
                    error.AlreadyKnown, error.WouldRevertFinalizedSlot, error.GenesisBlock => {
                        segment.skipped_count += 1;
                        _ = recordBlockImportError(&segment.error_counts, err);
                    },
                    error.ExecutionPayloadInvalid => {
                        segment.failed_count += 1;
                        _ = recordBlockImportError(&segment.error_counts, err);
                        segment.stop_after_current = true;
                        self.recordRangeSyncSegmentFailure(segment.sync_type, .execution_verify, err);
                    },
                    error.NotViableForHead => {
                        segment.failed_count += 1;
                        _ = recordBlockImportError(&segment.error_counts, err);
                        segment.stop_after_current = true;
                        self.recordRangeSyncSegmentFailure(segment.sync_type, .execution_verify, err);
                    },
                    error.ParentUnknown,
                    error.FutureSlot,
                    error.BlacklistedBlock,
                    error.InvalidProposer,
                    error.InvalidSignature,
                    error.DataUnavailable,
                    error.InvalidKzgProof,
                    error.PrestateMissing,
                    error.StateTransitionFailed,
                    error.InvalidStateRoot,
                    error.ExecutionEngineUnavailable,
                    error.ForkChoiceError,
                    error.InternalError,
                    => {
                        segment.failed_count += 1;
                        _ = recordBlockImportError(&segment.error_counts, err);
                        self.recordRangeSyncSegmentFailure(segment.sync_type, .execution_verify, err);
                        node_log.warn(
                            "deferred sync segment execution verification failed slot_index={d} chain_id={d} batch_id={d} generation={d}: {}",
                            .{ block_index, segment.key.chain_id, segment.key.batch_id, segment.key.generation, err },
                        );
                    },
                    else => {
                        segment.failed_count += 1;
                        self.recordRangeSyncSegmentFailure(segment.sync_type, .execution_verify, err);
                        node_log.warn(
                            "deferred sync segment execution verification failed slot_index={d} chain_id={d} batch_id={d} generation={d}: {}",
                            .{ block_index, segment.key.chain_id, segment.key.batch_id, segment.key.generation, err },
                        );
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
        const segment_failed = segmentHasProcessingFailure(outcome);
        self.finishSegmentImportOutcome(t0, outcome, null);
        if (segment_failed) return error.SegmentImportFailed;
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

        const owned_blocks = try cloneBatchBlocks(self.allocator, blocks);
        errdefer freeBatchBlocks(self.allocator, owned_blocks);

        try self.pending_sync_segments.append(self.allocator, .{
            .key = key,
            .sync_type = sync_type,
            .blocks = owned_blocks,
            .before_snapshot = self.chainService().query().currentSnapshot(),
            .started_at = std.Io.Clock.awake.now(self.io),
        });
    }

    pub fn drivePendingSyncSegments(self: *BeaconNode) bool {
        if (self.pending_sync_segments.items.len == 0) return false;

        // Keep queued range-sync segment processing single-flight like
        // Lodestar's batch processor, but execute the whole segment through the
        // direct batch pipeline instead of cloning a pre-state per block into
        // StateWorkService.
        var segment = self.pending_sync_segments.orderedRemove(0);
        defer segment.deinit(self.allocator);

        processQueuedSyncSegment(self, &segment);
        return true;
    }

    fn processQueuedSyncSegment(self: *BeaconNode, segment: *PendingSyncSegment) void {
        const raw_blocks = self.allocator.alloc(chain_mod.RawBlockBytes, segment.blocks.len) catch |err| {
            node_log.warn(
                "failed to allocate queued sync segment chain_id={d} batch_id={d} generation={d}: {}",
                .{ segment.key.chain_id, segment.key.batch_id, segment.key.generation, err },
            );
            if (self.sync_service_inst) |sync_svc| {
                sync_svc.onSegmentProcessingError(
                    segment.key.chain_id,
                    segment.key.batch_id,
                    segment.key.generation,
                );
            }
            return;
        };
        defer self.allocator.free(raw_blocks);

        for (segment.blocks, 0..) |block, i| {
            raw_blocks[i] = .{
                .slot = block.slot,
                .bytes = block.block_bytes,
            };
        }

        const outcome = self.chainService().processRangeSyncSegment(raw_blocks) catch |err| {
            node_log.warn(
                "queued sync segment processing failed chain_id={d} batch_id={d} generation={d}: {}",
                .{ segment.key.chain_id, segment.key.batch_id, segment.key.generation, err },
            );
            if (self.sync_service_inst) |sync_svc| {
                sync_svc.onSegmentProcessingError(
                    segment.key.chain_id,
                    segment.key.batch_id,
                    segment.key.generation,
                );
            }
            return;
        };

        const segment_failed = segmentHasProcessingFailure(outcome);
        self.finishSegmentImportOutcome(segment.started_at, outcome, .{
            .sync_type = segment.sync_type,
            .total_blocks = segment.blocks.len,
            .key = segment.key,
        });

        if (self.sync_service_inst) |sync_svc| {
            if (segment_failed) {
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

    fn blockImportSourceLabel(source: chain_mod.BlockSource) []const u8 {
        return @tagName(source);
    }

    fn blockImportOutcomeLabel(err: anyerror) []const u8 {
        return switch (err) {
            error.AlreadyKnown => "already_known",
            error.WouldRevertFinalizedSlot => "would_revert_finalized",
            error.GenesisBlock => "genesis_block",
            error.ParentUnknown => "parent_unknown",
            error.FutureSlot => "future_slot",
            error.BlacklistedBlock => "blacklisted_block",
            error.InvalidProposer => "invalid_proposer",
            error.InvalidSignature => "invalid_signature",
            error.DataUnavailable => "data_unavailable",
            error.InvalidKzgProof => "invalid_kzg_proof",
            error.PrestateMissing => "prestate_missing",
            error.StateTransitionFailed => "state_transition_failed",
            error.InvalidStateRoot => "invalid_state_root",
            error.ExecutionPayloadInvalid => "execution_payload_invalid",
            error.ExecutionEngineUnavailable => "execution_engine_unavailable",
            error.ForkChoiceError => "forkchoice_error",
            error.NotViableForHead => "not_viable_for_head",
            error.InternalError => "internal_error",
            else => "failed",
        };
    }

    fn rangeSyncSegmentResult(
        outcome: chain_mod.SegmentImportOutcome,
    ) metrics_mod.BeaconMetrics.RangeSyncSegmentResult {
        if (outcome.imported_count > 0 and outcome.failed_count == 0 and outcome.skipped_count == 0) {
            return .complete;
        }
        if (outcome.imported_count > 0 and outcome.failed_count == 0 and outcome.skipped_count > 0) {
            return .complete_with_skips;
        }
        if (outcome.imported_count > 0) return .partial;
        if (outcome.failed_count > 0) return .failed;
        return .skipped;
    }

    fn summarizeBlockImportErrorCounts(
        buf: []u8,
        counts: chain_mod.BlockImportErrorCounts,
    ) []const u8 {
        var written: usize = 0;
        var wrote_any = false;

        inline for (std.meta.fields(chain_mod.BlockImportErrorCounts)) |field| {
            const count: usize = @field(counts, field.name);
            if (count != 0) {
                const formatted = std.fmt.bufPrint(
                    buf[written..],
                    "{s}{s}={d}",
                    .{ if (wrote_any) "," else "", field.name, count },
                ) catch break;
                written += formatted.len;
                wrote_any = true;
            }
        }

        return if (wrote_any) buf[0..written] else "none";
    }

    fn recordBlockImportResult(
        self: *BeaconNode,
        source: chain_mod.BlockSource,
        outcome: []const u8,
        count: usize,
    ) void {
        if (self.metrics) |m| {
            m.incrBlockImportResult(blockImportSourceLabel(source), outcome, @intCast(count));
        }
    }

    fn recordBlockImportErrorCounts(
        self: *BeaconNode,
        source: chain_mod.BlockSource,
        counts: chain_mod.BlockImportErrorCounts,
    ) void {
        inline for (std.meta.fields(chain_mod.BlockImportErrorCounts)) |field| {
            const count: usize = @field(counts, field.name);
            if (count > 0) self.recordBlockImportResult(source, field.name, count);
        }
    }

    fn countBlockImportErrorCounts(counts: chain_mod.BlockImportErrorCounts) usize {
        var total: usize = 0;
        inline for (std.meta.fields(chain_mod.BlockImportErrorCounts)) |field| {
            total += @field(counts, field.name);
        }
        return total;
    }

    fn recordBlockImportError(counts: *chain_mod.BlockImportErrorCounts, err: anyerror) bool {
        switch (err) {
            error.GenesisBlock => counts.incr(error.GenesisBlock),
            error.WouldRevertFinalizedSlot => counts.incr(error.WouldRevertFinalizedSlot),
            error.AlreadyKnown => counts.incr(error.AlreadyKnown),
            error.ParentUnknown => counts.incr(error.ParentUnknown),
            error.FutureSlot => counts.incr(error.FutureSlot),
            error.BlacklistedBlock => counts.incr(error.BlacklistedBlock),
            error.InvalidProposer => counts.incr(error.InvalidProposer),
            error.InvalidSignature => counts.incr(error.InvalidSignature),
            error.DataUnavailable => counts.incr(error.DataUnavailable),
            error.InvalidKzgProof => counts.incr(error.InvalidKzgProof),
            error.PrestateMissing => counts.incr(error.PrestateMissing),
            error.StateTransitionFailed => counts.incr(error.StateTransitionFailed),
            error.InvalidStateRoot => counts.incr(error.InvalidStateRoot),
            error.ExecutionPayloadInvalid => counts.incr(error.ExecutionPayloadInvalid),
            error.ExecutionEngineUnavailable => counts.incr(error.ExecutionEngineUnavailable),
            error.ForkChoiceError => counts.incr(error.ForkChoiceError),
            error.NotViableForHead => counts.incr(error.NotViableForHead),
            error.InternalError => counts.incr(error.InternalError),
            else => return false,
        }
        return true;
    }

    fn observeImportedBlocks(
        self: *BeaconNode,
        source: chain_mod.BlockSource,
        count: usize,
        elapsed_s: f64,
    ) void {
        if (self.metrics) |m| {
            m.observeImportedBlocks(blockImportSourceLabel(source), @intCast(count), elapsed_s);
        }
    }

    fn recordRangeSyncSegmentFailure(
        self: *BeaconNode,
        sync_type: RangeSyncType,
        stage: metrics_mod.BeaconMetrics.RangeSyncSegmentStage,
        err: anyerror,
    ) void {
        if (self.metrics) |m| {
            m.incrRangeSyncSegmentFailure(sync_type, stage, blockImportOutcomeLabel(err));
        }
    }

    fn incrRangeSyncSegmentQueueBusy(
        self: *BeaconNode,
        sync_type: RangeSyncType,
    ) void {
        if (self.metrics) |m| {
            m.incrRangeSyncSegmentQueueBusy(sync_type);
        }
    }

    fn finishImportOutcome(
        self: *BeaconNode,
        source: chain_mod.BlockSource,
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
            self.observeImportedBlocks(source, 1, elapsed_s);
            if (result.execution_optimistic) m.incrOptimisticImports(1);
            if (result.epoch_transition) m.incrEpochTransitions(1);
            m.head_slot.set(outcome.snapshot.head.slot);
            m.finalized_epoch.set(outcome.snapshot.finalized.epoch);
            m.justified_epoch.set(outcome.snapshot.justified.epoch);
            m.head_root.set(metrics_mod.rootMetricValue(outcome.snapshot.head.root));
        }
        self.updateSyncProgress(outcome.snapshot);
        self.observeHeadCatchup(outcome.snapshot.head.slot);

        if (result.epoch_transition) {
            if (self.unknownChainSyncEnabled()) {
                if (outcome.effects.finalized_checkpoint) |finalized| {
                    self.unknown_chain_sync.onFinalized(finalized.slot);
                }
            }
            chain_log.info("epoch transition slot={d} finalized_epoch={d} justified_epoch={d}", .{
                result.slot,
                outcome.snapshot.finalized.epoch,
                outcome.snapshot.justified.epoch,
            });
        }

        chain_log.debug("block imported slot={d} root={s}... epoch_transition={}", .{
            result.slot,
            &std.fmt.bytesToHex(result.block_root[0..4], .lower),
            result.epoch_transition,
        });

        return result;
    }

    fn finishSegmentImportOutcome(
        self: *BeaconNode,
        t0: std.Io.Timestamp,
        outcome: chain_mod.SegmentImportOutcome,
        log_ctx: ?RangeSyncSegmentLogContext,
    ) void {
        if (outcome.effects.forkchoice_update) |update| self.queueExecutionForkchoiceUpdate(update);

        const t1 = std.Io.Clock.awake.now(self.io);
        const elapsed_s: f64 = @as(f64, @floatFromInt(t1.nanoseconds - t0.nanoseconds)) / 1e9;
        const elapsed_ms: u64 = @intFromFloat(elapsed_s * 1000.0);
        const segment_result = rangeSyncSegmentResult(outcome);

        if (self.metrics) |m| {
            if (outcome.imported_count > 0) {
                self.observeImportedBlocks(.range_sync, outcome.imported_count, elapsed_s);
            }
            if (outcome.optimistic_imported_count > 0) m.incrOptimisticImports(@intCast(outcome.optimistic_imported_count));
            if (outcome.epoch_transition_count > 0) m.incrEpochTransitions(@intCast(outcome.epoch_transition_count));
            self.recordBlockImportErrorCounts(.range_sync, outcome.error_counts);
            const typed_error_count = countBlockImportErrorCounts(outcome.error_counts);
            const total_non_success = outcome.skipped_count + outcome.failed_count;
            const generic_failed_count = if (typed_error_count < total_non_success)
                total_non_success - typed_error_count
            else
                0;
            if (generic_failed_count > 0) self.recordBlockImportResult(.range_sync, "failed", generic_failed_count);
            m.head_slot.set(outcome.snapshot.head.slot);
            m.finalized_epoch.set(outcome.snapshot.finalized.epoch);
            m.justified_epoch.set(outcome.snapshot.justified.epoch);
            m.head_root.set(metrics_mod.rootMetricValue(outcome.snapshot.head.root));
            if (log_ctx) |ctx| {
                m.observeRangeSyncSegment(ctx.sync_type, segment_result, @intCast(ctx.total_blocks), elapsed_s);
            }
        }
        self.updateSyncProgress(outcome.snapshot);
        self.observeHeadCatchup(outcome.snapshot.head.slot);

        if (self.unknownChainSyncEnabled()) {
            if (outcome.effects.finalized_checkpoint) |finalized| {
                self.unknown_chain_sync.onFinalized(finalized.slot);
            }
        }

        if (log_ctx) |ctx| {
            var errors_buf: [512]u8 = undefined;
            const errors_summary = summarizeBlockImportErrorCounts(errors_buf[0..], outcome.error_counts);
            if (ctx.key) |key| {
                chain_log.info(
                    "range sync segment completed sync_type={s} result={s} chain_id={d} batch_id={d} generation={d} blocks={d} imported={d} skipped={d} failed={d} optimistic={d} epoch_transitions={d} elapsed_ms={d} errors={s} head_slot={d} finalized_epoch={d}",
                    .{
                        @tagName(ctx.sync_type),
                        @tagName(segment_result),
                        key.chain_id,
                        key.batch_id,
                        key.generation,
                        ctx.total_blocks,
                        outcome.imported_count,
                        outcome.skipped_count,
                        outcome.failed_count,
                        outcome.optimistic_imported_count,
                        outcome.epoch_transition_count,
                        elapsed_ms,
                        errors_summary,
                        outcome.snapshot.head.slot,
                        outcome.snapshot.finalized.epoch,
                    },
                );
            } else {
                chain_log.info(
                    "range sync segment completed sync_type={s} result={s} blocks={d} imported={d} skipped={d} failed={d} optimistic={d} epoch_transitions={d} elapsed_ms={d} errors={s} head_slot={d} finalized_epoch={d}",
                    .{
                        @tagName(ctx.sync_type),
                        @tagName(segment_result),
                        ctx.total_blocks,
                        outcome.imported_count,
                        outcome.skipped_count,
                        outcome.failed_count,
                        outcome.optimistic_imported_count,
                        outcome.epoch_transition_count,
                        elapsed_ms,
                        errors_summary,
                        outcome.snapshot.head.slot,
                        outcome.snapshot.finalized.epoch,
                    },
                );
            }
            return;
        }

        chain_log.info(
            "range sync segment imported imported={d} skipped={d} failed={d} elapsed_ms={d} head_slot={d} finalized_epoch={d}",
            .{
                outcome.imported_count,
                outcome.skipped_count,
                outcome.failed_count,
                elapsed_ms,
                outcome.snapshot.head.slot,
                outcome.snapshot.finalized.epoch,
            },
        );
    }

    fn finishGenericQueuedBlockImport(
        self: *BeaconNode,
        ticket: ?BlockIngressTicket,
        completed: chain_mod.CompletedBlockImport,
    ) void {
        const t0 = std.Io.Clock.awake.now(self.io);
        const source = switch (completed) {
            .success => |prepared| prepared.block_input.source,
            .failure => |failure| failure.planned.block_input.source,
        };
        const outcome = self.chainService().finishCompletedReadyBlockImport(completed) catch |err| {
            self.recordBlockImportResult(source, blockImportOutcomeLabel(err), 1);
            self.recordGenericBlockIngressError(ticket, err);
            node_log.warn("deferred block state work failed: {}", .{err});
            return;
        };
        const result = self.finishImportOutcome(source, t0, outcome) catch |err| {
            self.recordGenericBlockIngressError(ticket, err);
            node_log.warn("deferred block import commit failed: {}", .{err});
            return;
        };
        self.processPendingChildren(result.block_root);
        if (ticket) |owned_ticket| {
            self.recordCompletedBlockIngress(owned_ticket, .{ .imported = result });
        }
    }

    fn finishSyncSegmentQueuedBlockImport(
        self: *BeaconNode,
        key: SyncSegmentKey,
        completed: chain_mod.CompletedBlockImport,
    ) void {
        const index = findPendingSyncSegmentIndex(self, key) orelse {
            node_log.warn("missing pending sync segment for completed block work", .{});
            self.finishGenericQueuedBlockImport(null, completed);
            return;
        };

        var segment = &self.pending_sync_segments.items[index];
        segment.in_flight = false;
        segment.next_index += 1;
        const block_index = segment.next_index - 1;

        const outcome = self.chainService().finishCompletedReadyBlockImport(completed) catch |err| {
            switch (err) {
                error.AlreadyKnown, error.WouldRevertFinalizedSlot, error.GenesisBlock => {
                    segment.skipped_count += 1;
                    _ = recordBlockImportError(&segment.error_counts, err);
                },
                error.ExecutionPayloadInvalid => {
                    segment.failed_count += 1;
                    _ = recordBlockImportError(&segment.error_counts, error.ExecutionPayloadInvalid);
                    segment.stop_after_current = true;
                    self.recordRangeSyncSegmentFailure(segment.sync_type, .commit, err);
                },
                error.NotViableForHead => {
                    segment.failed_count += 1;
                    _ = recordBlockImportError(&segment.error_counts, err);
                    segment.stop_after_current = true;
                    self.recordRangeSyncSegmentFailure(segment.sync_type, .commit, err);
                },
                else => {
                    segment.failed_count += 1;
                    switch (err) {
                        error.ParentUnknown,
                        error.FutureSlot,
                        error.BlacklistedBlock,
                        error.InvalidProposer,
                        error.InvalidSignature,
                        error.DataUnavailable,
                        error.InvalidKzgProof,
                        error.PrestateMissing,
                        error.StateTransitionFailed,
                        error.InvalidStateRoot,
                        error.ExecutionEngineUnavailable,
                        error.ForkChoiceError,
                        error.InternalError,
                        => segment.error_counts.incr(err),
                        else => {},
                    }
                    self.recordRangeSyncSegmentFailure(segment.sync_type, .commit, err);
                    node_log.warn(
                        "deferred sync segment block commit failed slot_index={d} chain_id={d} batch_id={d} generation={d}: {}",
                        .{ block_index, segment.key.chain_id, segment.key.batch_id, segment.key.generation, err },
                    );
                },
            }
            return;
        };

        segment.imported_count += 1;
        if (outcome.result.execution_optimistic) segment.optimistic_imported_count += 1;
        if (outcome.result.epoch_transition) segment.epoch_transition_count += 1;
        node_log.debug("deferred range sync block imported slot={d} chain_id={d} batch_id={d} generation={d} imported={d} skipped={d} failed={d}", .{
            outcome.result.slot,
            segment.key.chain_id,
            segment.key.batch_id,
            segment.key.generation,
            segment.imported_count,
            segment.skipped_count,
            segment.failed_count,
        });

        self.updateSyncProgress(outcome.snapshot);
        self.observeHeadCatchup(outcome.snapshot.head.slot);
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
            m.head_root.set(metrics_mod.rootMetricValue(outcome.snapshot.head.root));
        }
        self.updateSyncProgress(outcome.snapshot);
        self.observeHeadCatchup(outcome.snapshot.head.slot);

        if (outcome.head_changed) {
            chain_log.info("execution revalidation changed head head_slot={d} head_root={s}... finalized_epoch={d}", .{
                outcome.snapshot.head.slot,
                &std.fmt.bytesToHex(outcome.snapshot.head.root[0..4], .lower),
                outcome.snapshot.finalized.epoch,
            });
        }
    }

    fn updateSyncProgress(self: *BeaconNode, snapshot: chain_mod.ChainSnapshot) void {
        if (self.sync_service_inst) |svc| {
            svc.onHeadUpdate(snapshot.head.slot);
            svc.onFinalizedUpdate(snapshot.finalized.epoch);
        }
    }

    pub fn gossipBlsPendingSnapshot(self: *const BeaconNode) GossipBlsPendingSnapshot {
        var snapshot: GossipBlsPendingSnapshot = .{};
        for (self.pending_gossip_bls_batches.items) |pending| {
            switch (pending) {
                .attestation => |batch| {
                    snapshot.attestation_batches += 1;
                    snapshot.attestation_items += @intCast(batch.items.len);
                },
                .aggregate => |batch| {
                    snapshot.aggregate_batches += 1;
                    snapshot.aggregate_items += @intCast(batch.items.len);
                },
                .sync_message => |batch| {
                    snapshot.sync_message_batches += 1;
                    snapshot.sync_message_items += @intCast(batch.items.len);
                },
            }
        }
        return snapshot;
    }

    pub fn headCatchupPendingCount(self: *const BeaconNode) u64 {
        return self.sync_metrics_cache.headCatchupPendingCount();
    }

    pub fn currentTimeToHeadMs(self: *BeaconNode, current_slot: u64, head_slot: u64) u64 {
        if (head_slot >= current_slot) return 0;
        return millisFromNs(elapsedNsBetween(self.slotStartNs(current_slot), wallNowNs(self.io)));
    }

    pub fn latestHeadSlotForMetrics(self: *const BeaconNode) u64 {
        return self.sync_metrics_cache.headProgress().slot;
    }

    pub fn noteHeadCatchupSlotsStarted(self: *BeaconNode, start_slot: u64, end_slot: u64) void {
        if (start_slot > end_slot) return;

        var slot = start_slot;
        while (slot <= end_slot) : (slot += 1) {
            self.appendHeadCatchupSlot(slot);
        }
    }

    pub fn observeHeadCatchup(self: *BeaconNode, head_slot: u64) void {
        const now_ns = wallNowNs(self.io);
        self.syncHeadProgressForMetrics(head_slot);
        if (self.metrics) |metrics| {
            if (self.last_time_to_head_observed_slot) |last_slot| {
                if (head_slot > last_slot) {
                    var slot = last_slot + 1;
                    while (slot <= head_slot) : (slot += 1) {
                        const elapsed_ns = elapsedNsBetween(self.slotStartNs(slot), now_ns);
                        metrics.observeTimeToHead(secondsFromNs(elapsed_ns), millisFromNs(elapsed_ns));
                    }
                    self.last_time_to_head_observed_slot = head_slot;
                }
            } else {
                self.last_time_to_head_observed_slot = head_slot;
            }
        } else {
            self.last_time_to_head_observed_slot = head_slot;
        }

        while (self.head_catchup_slots_len > 0 and self.head_catchup_slots[0].slot <= head_slot) {
            const pending = self.head_catchup_slots[0];
            var i: usize = 1;
            while (i < self.head_catchup_slots_len) : (i += 1) {
                self.head_catchup_slots[i - 1] = self.head_catchup_slots[i];
            }
            self.head_catchup_slots_len -= 1;
            self.syncHeadCatchupPendingCount();

            if (self.metrics) |metrics| {
                const elapsed_ns = elapsedNsBetween(pending.started_at_ns, now_ns);
                metrics.observeTimeToHead(secondsFromNs(elapsed_ns), millisFromNs(elapsed_ns));
            }
        }
    }

    fn appendHeadCatchupSlot(self: *BeaconNode, slot: u64) void {
        if (self.head_catchup_slots_len > 0) {
            const last = self.head_catchup_slots[self.head_catchup_slots_len - 1];
            if (last.slot >= slot) return;
        }

        if (self.head_catchup_slots_len == self.head_catchup_slots.len) {
            var i: usize = 1;
            while (i < self.head_catchup_slots_len) : (i += 1) {
                self.head_catchup_slots[i - 1] = self.head_catchup_slots[i];
            }
            self.head_catchup_slots_len -= 1;
        }

        self.head_catchup_slots[self.head_catchup_slots_len] = .{
            .slot = slot,
            .started_at_ns = self.slotStartNs(slot),
        };
        self.head_catchup_slots_len += 1;
        self.syncHeadCatchupPendingCount();
    }

    fn syncHeadCatchupPendingCount(self: *BeaconNode) void {
        self.sync_metrics_cache.setHeadCatchupPendingCount(@intCast(self.head_catchup_slots_len));
    }

    pub fn latestHeadProgressForMetrics(self: *const BeaconNode) HeadProgressSnapshot {
        return self.sync_metrics_cache.headProgress();
    }

    fn syncHeadProgressForMetrics(self: *BeaconNode, head_slot: u64) void {
        self.sync_metrics_cache.syncHeadProgress(head_slot, self.chain.currentHeadExecutionOptimistic());
    }

    fn slotStartNs(self: *BeaconNode, slot: u64) i64 {
        if (self.clock) |clock| {
            const start_ns = clock.slotStartNs(slot);
            return if (start_ns > std.math.maxInt(i64))
                std.math.maxInt(i64)
            else
                @intCast(start_ns);
        }
        return wallNowNs(self.io);
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
        node_log.debug("Imported data column sidecar root={s}... column={d}", .{
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
            node_log.debug("Imported data column sidecar root={s}... column={d}", .{
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
        self.syncHeadProgressForMetrics(target_slot);
    }

    /// Start the Beacon REST API HTTP server (blocking).
    ///
    /// Listens on the configured address:port and dispatches requests
    /// to the Beacon API handlers.
    pub fn startApi(self: *BeaconNode, io: std.Io, address: []const u8, port: u16, cors_origin: ?[]const u8) !void {
        var http_options: api_mod.HttpServer.Options = .{
            .cors_origin = cors_origin,
        };
        if (self.metrics) |metrics| {
            http_options.observer = metrics.apiObserver();
        }
        self.http_server = api_mod.HttpServer.initWithOptions(
            self.allocator,
            self.api_context,
            address,
            port,
            http_options,
        );
        rest_log.info("REST API listening", .{});
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
    /// Stores the parsed block plus canonical metadata in UnknownBlockSync.
    pub fn queueOrphanPreparedBlock(
        self: *BeaconNode,
        prepared: chain_mod.PreparedBlockInput,
        peer_id: ?[]const u8,
    ) !bool {
        const effective_peer_id = prepared.peerId() orelse peer_id;
        const slot = prepared.slot();
        const parent_root = prepared.block.beaconBlock().parentRoot().*;

        const added = try self.unknown_block_sync.addPendingBlockWithPeer(prepared, effective_peer_id);

        if (added) {
            self.recordBlockImportResult(switch (prepared.source) {
                .gossip => .gossip,
                .range_sync => .range_sync,
                .unknown_block_sync => .unknown_block_sync,
                .api => .api,
                .checkpoint_sync => .checkpoint_sync,
                .regen => .regen,
            }, "queued_unknown_parent", 1);
            node_log.debug("Queued orphan block slot={d} parent={s}... ({d} pending)", .{
                slot,
                &std.fmt.bytesToHex(parent_root[0..4], .lower),
                self.unknown_block_sync.pendingCount(),
            });
        }

        return added;
    }

    /// Queue an orphan block whose parent is not yet known.
    ///
    /// Computes the canonical block root once and forwards into the prepared
    /// orphan queue.
    pub fn queueOrphanBlock(
        self: *BeaconNode,
        any_signed: AnySignedBeaconBlock,
        source: BlockSource,
        seen_timestamp_sec: u64,
        peer_id: ?[]const u8,
    ) !bool {
        var prepared = try self.chainService().preparePreparedBlockInput(any_signed, source, seen_timestamp_sec);
        prepared.setPeerId(peer_id);
        return self.queueOrphanPreparedBlock(prepared, peer_id);
    }

    /// After a block is successfully imported, check if any orphan children
    /// were waiting on it and try to import them.
    pub fn processPendingChildren(self: *BeaconNode, parent_root: [32]u8) void {
        // Notify unknown block sync — handles recursive resolution internally.
        self.unknown_block_sync.notifyBlockImported(parent_root) catch {};
        self.releasePendingUnknownBlockGossip(parent_root);
    }

    pub fn queueUnknownBlockAttestation(
        self: *BeaconNode,
        block_root: [32]u8,
        work: AttestationWork,
        peer_id: ?[]const u8,
    ) !bool {
        const added = try self.pending_unknown_block_gossip.addAttestation(block_root, peer_id, work);
        if (!added) return false;
        self.recordBlockImportResult(.gossip, "queued_unknown_parent", 1);
        return true;
    }

    pub fn queueUnknownBlockAggregate(
        self: *BeaconNode,
        block_root: [32]u8,
        work: AggregateWork,
        peer_id: ?[]const u8,
    ) !bool {
        const added = try self.pending_unknown_block_gossip.addAggregate(block_root, peer_id, work);
        if (!added) return false;
        self.recordBlockImportResult(.gossip, "queued_unknown_parent", 1);
        return true;
    }

    pub fn onPendingUnknownBlockFetchAccepted(self: *BeaconNode, block_root: [32]u8) void {
        self.pending_unknown_block_gossip.onFetchAccepted(block_root);
    }

    pub fn onPendingUnknownBlockFetchFailed(self: *BeaconNode, block_root: [32]u8, peer_id: ?[]const u8) void {
        self.pending_unknown_block_gossip.onFetchFailed(block_root, peer_id);
    }

    pub fn dropPendingUnknownBlock(self: *BeaconNode, block_root: [32]u8) void {
        self.pending_unknown_block_gossip.dropRoot(block_root);
    }

    pub fn drivePendingUnknownBlockGossip(self: *BeaconNode) void {
        const cb_ctx = self.sync_callback_ctx orelse return;
        self.pending_unknown_block_gossip.tick(.{
            .ptr = @ptrCast(cb_ctx),
            .requestBlockByRootFn = &sync_bridge_mod.SyncCallbackCtx.enqueueUnknownBlockGossipRequestFn,
            .getConnectedPeersFn = &sync_bridge_mod.SyncCallbackCtx.connectedPeerIdsFn,
        });
    }

    fn releasePendingUnknownBlockGossip(self: *BeaconNode, block_root: [32]u8) void {
        var released = pending_unknown_block_gossip_mod.ReleasedItems.empty;
        defer {
            for (released.items) |*item| item.deinit(self.allocator);
            released.deinit(self.allocator);
        }

        self.pending_unknown_block_gossip.releaseImported(block_root, &released) catch return;
        for (released.items) |*item| {
            self.requeuePendingUnknownBlockGossipItem(item.*);
            item.* = undefined;
        }
        released.items.len = 0;
    }

    fn requeuePendingUnknownBlockGossipItem(self: *BeaconNode, item: PendingUnknownBlockGossipItem) void {
        if (self.beacon_processor) |bp| {
            switch (item) {
                .attestation => |work| bp.ingest(.{ .attestation = work }),
                .aggregate => |work| bp.ingest(.{ .aggregate = work }),
            }
            return;
        }

        switch (item) {
            .attestation => |work| handleQueuedAttestation(self, work),
            .aggregate => |work| handleQueuedAggregate(self, work),
        }
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
                self.recordRangeSyncSegmentFailure(segment.sync_type, .prepare, err);
                node_log.warn(
                    "range sync block preparation failed slot={d} chain_id={d} batch_id={d} generation={d} index={d}: {}",
                    .{ block.slot, segment.key.chain_id, segment.key.batch_id, segment.key.generation, segment.next_index - 1, err },
                );
                continue;
            };

            const plan_result = self.chainService().planRangeSyncReadyBlockImport(&ready) catch |err| {
                ready.deinit(self.allocator);
                switch (err) {
                    error.AlreadyKnown, error.WouldRevertFinalizedSlot, error.GenesisBlock => {
                        segment.skipped_count += 1;
                        _ = recordBlockImportError(&segment.error_counts, err);
                    },
                    error.NotViableForHead => {
                        segment.failed_count += 1;
                        _ = recordBlockImportError(&segment.error_counts, err);
                        segment.stop_after_current = true;
                        self.recordRangeSyncSegmentFailure(segment.sync_type, .plan, err);
                        node_log.warn(
                            "range sync block planning failed slot={d} chain_id={d} batch_id={d} generation={d} index={d}: {}",
                            .{ block.slot, segment.key.chain_id, segment.key.batch_id, segment.key.generation, segment.next_index, err },
                        );
                    },
                    error.ParentUnknown,
                    error.FutureSlot,
                    error.BlacklistedBlock,
                    error.InvalidProposer,
                    error.InvalidSignature,
                    error.DataUnavailable,
                    error.InvalidKzgProof,
                    error.PrestateMissing,
                    error.StateTransitionFailed,
                    error.InvalidStateRoot,
                    error.ExecutionPayloadInvalid,
                    error.ExecutionEngineUnavailable,
                    error.ForkChoiceError,
                    error.InternalError,
                    => {
                        segment.failed_count += 1;
                        _ = recordBlockImportError(&segment.error_counts, err);
                        self.recordRangeSyncSegmentFailure(segment.sync_type, .plan, err);
                        node_log.warn(
                            "range sync block planning failed slot={d} chain_id={d} batch_id={d} generation={d} index={d}: {}",
                            .{ block.slot, segment.key.chain_id, segment.key.batch_id, segment.key.generation, segment.next_index, err },
                        );
                    },
                }
                segment.next_index += 1;
                continue;
            };

            const planned = switch (plan_result) {
                .skipped => |reason| {
                    ready.deinit(self.allocator);
                    segment.skipped_count += 1;
                    _ = recordBlockImportError(&segment.error_counts, reason);
                    segment.next_index += 1;
                    continue;
                },
                .planned => |planned| planned,
            };

            try self.queued_state_work_owners.ensureUnusedCapacity(self.allocator, 1);
            var owned_planned = planned;
            const queue_result = self.chainService().tryQueuePlannedReadyBlockImport(owned_planned) catch |err| {
                self.chainService().deinitPlannedReadyBlockImport(&owned_planned);
                self.recordRangeSyncSegmentFailure(segment.sync_type, .queue, err);
                return err;
            };
            switch (queue_result) {
                .queued => {
                    self.queued_state_work_owners.appendAssumeCapacity(.{ .sync_segment = segment.key });
                    segment.in_flight = true;
                    owned_planned = undefined;
                    node_log.debug("queued range sync block state work slot={d} chain_id={d} batch_id={d} generation={d} index={d}", .{
                        block.slot,
                        segment.key.chain_id,
                        segment.key.batch_id,
                        segment.key.generation,
                        segment.next_index,
                    });
                    return true;
                },
                .not_queued => |returned_planned| {
                    owned_planned = returned_planned;
                    self.incrRangeSyncSegmentQueueBusy(segment.sync_type);
                    node_log.debug("state work queue busy for range sync slot={d} chain_id={d} batch_id={d} generation={d} index={d}", .{
                        block.slot,
                        segment.key.chain_id,
                        segment.key.batch_id,
                        segment.key.generation,
                        segment.next_index,
                    });
                },
            }

            self.chainService().deinitPlannedReadyBlockImport(&owned_planned);
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
            segment.optimistic_imported_count,
            segment.epoch_transition_count,
            segment.error_counts,
        );
        const segment_failed = segmentHasProcessingFailure(outcome);
        self.finishSegmentImportOutcome(segment.started_at, outcome, .{
            .sync_type = segment.sync_type,
            .total_blocks = segment.blocks.len,
            .key = segment.key,
        });

        if (self.sync_service_inst) |sync_svc| {
            if (segment_failed) {
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
            node_log.warn("forkchoiceUpdated failed: {}", .{err});
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

    pub fn refreshScrapeMetrics(self: *BeaconNode) void {
        p2p_runtime_mod.refreshScrapeMetrics(self);
    }

    fn computeSyncStatus(self: *const BeaconNode, inputs: SyncStatusInputs) ComputedSyncStatus {
        const has_sync_peers = self.node_options.sync_is_single_node or inputs.connected_peers > 0;
        const is_synced = !inputs.has_wall_slot or
            (inputs.sync_distance <= sync_mod.sync_types.SYNC_DISTANCE_THRESHOLD and has_sync_peers);

        return .{
            .status = .{
                .head_slot = inputs.head_slot,
                .sync_distance = inputs.sync_distance,
                .is_syncing = !is_synced,
                .is_optimistic = inputs.is_optimistic,
                .el_offline = inputs.el_offline,
            },
            .sync_state = if (!is_synced)
                if (has_sync_peers) 2 else 0
            else
                1,
        };
    }

    fn currentSyncStatusInputs(self: *const BeaconNode) SyncStatusInputs {
        const chain_sync = self.chainQuery().syncStatus();
        return .{
            .head_slot = chain_sync.head_slot,
            .sync_distance = chain_sync.sync_distance,
            .connected_peers = if (self.peer_manager) |pm| pm.peerCount() else 0,
            .is_optimistic = chain_sync.is_optimistic,
            .el_offline = self.execution_runtime.isElOffline(),
            .has_wall_slot = self.chain.currentWallSlot() != null,
        };
    }

    pub fn currentComputedSyncStatus(self: *const BeaconNode) ComputedSyncStatus {
        return self.computeSyncStatus(self.currentSyncStatusInputs());
    }

    pub fn scrapeComputedSyncStatus(self: *const BeaconNode) ComputedSyncStatus {
        const head_progress = self.latestHeadProgressForMetrics();
        const wall_slot = self.chain.currentWallSlot();
        return self.computeSyncStatus(.{
            .head_slot = head_progress.slot,
            .sync_distance = (wall_slot orelse head_progress.slot) -| head_progress.slot,
            .connected_peers = if (self.peer_manager) |pm| pm.peerCount() else 0,
            .is_optimistic = head_progress.optimistic,
            .el_offline = self.execution_runtime.isElOffline(),
            .has_wall_slot = wall_slot != null,
        });
    }

    pub fn publishSyncMetrics(metrics: *BeaconMetrics, sync: ComputedSyncStatus) void {
        metrics.setSyncSnapshot(
            if (sync.status.is_syncing) @as(u64, 1) else @as(u64, 0),
            sync.status.sync_distance,
            sync.status.is_optimistic,
            sync.status.el_offline,
        );
        metrics.setSyncState(sync.sync_state);
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
        return self.chain.forkChoice().head.slot;
    }

    pub fn currentHeadRoot(self: *const BeaconNode) [32]u8 {
        return self.chain.forkChoice().head.block_root;
    }

    pub fn currentFinalizedSlot(self: *const BeaconNode) u64 {
        return self.chainQuery().finalizedCheckpoint().slot;
    }

    /// Get the current sync status.
    pub fn getSyncStatus(self: *const BeaconNode) SyncStatus {
        return self.currentComputedSyncStatus().status;
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
        self.last_time_to_head_observed_slot = null;
        self.last_state_metrics_root = null;
        self.last_previous_epoch_orphaned_epoch = null;
        self.syncHeadProgressForMetrics(outcome.snapshot.head.slot);
        self.head_catchup_slots_len = 0;
        self.sync_metrics_cache.setHeadCatchupPendingCount(0);
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
    enqueued_at_ns: i64,
    started_at_ns: i64 = 0,

    fn isReady(self: *const PendingAttestationBlsBatch) bool {
        return self.future.isReady();
    }

    fn markStarted(self: *PendingAttestationBlsBatch, now_ns: i64) void {
        if (self.started_at_ns == 0 and self.future.started.isSet()) {
            self.started_at_ns = now_ns;
        }
    }

    fn finish(self: *PendingAttestationBlsBatch, node: *BeaconNode, finished_at_ns: i64) void {
        self.markStarted(finished_at_ns);
        const batch_valid = self.future.finish() catch false;
        const verify_started_ns = if (self.started_at_ns != 0) self.started_at_ns else self.enqueued_at_ns;
        recordGossipBlsVerificationMetrics(
            node,
            .attestation,
            .batch_async,
            if (batch_valid) .success else .fallback,
            self.items.len,
            if (self.started_at_ns != 0) secondsFromNs(elapsedNsBetween(self.enqueued_at_ns, self.started_at_ns)) else null,
            elapsedNsBetween(verify_started_ns, finished_at_ns),
        );
        importAttestationBatchItems(node, self.items, batch_valid);
        freeOwnedSignatureSets(node.allocator, self.owned_sets);
        node.allocator.free(self.items);
    }
};

const PendingAggregateBlsBatch = struct {
    items: []AggregateWork,
    owned_sets: []bls_mod.OwnedSignatureSet,
    future: *BlsThreadPool.VerifySetsFuture,
    enqueued_at_ns: i64,
    started_at_ns: i64 = 0,

    fn isReady(self: *const PendingAggregateBlsBatch) bool {
        return self.future.isReady();
    }

    fn markStarted(self: *PendingAggregateBlsBatch, now_ns: i64) void {
        if (self.started_at_ns == 0 and self.future.started.isSet()) {
            self.started_at_ns = now_ns;
        }
    }

    fn finish(self: *PendingAggregateBlsBatch, node: *BeaconNode, finished_at_ns: i64) void {
        self.markStarted(finished_at_ns);
        const batch_valid = self.future.finish() catch false;
        const verify_started_ns = if (self.started_at_ns != 0) self.started_at_ns else self.enqueued_at_ns;
        recordGossipBlsVerificationMetrics(
            node,
            .aggregate,
            .batch_async,
            if (batch_valid) .success else .fallback,
            self.items.len,
            if (self.started_at_ns != 0) secondsFromNs(elapsedNsBetween(self.enqueued_at_ns, self.started_at_ns)) else null,
            elapsedNsBetween(verify_started_ns, finished_at_ns),
        );
        importAggregateBatchItems(node, self.items, batch_valid);
        freeOwnedSignatureSets(node.allocator, self.owned_sets);
        node.allocator.free(self.items);
    }
};

const PendingSyncMessageBlsBatch = struct {
    items: []processor_mod.work_item.SyncMessageWork,
    owned_sets: []bls_mod.OwnedSignatureSet,
    future: *BlsThreadPool.VerifySetsFuture,
    enqueued_at_ns: i64,
    started_at_ns: i64 = 0,

    fn isReady(self: *const PendingSyncMessageBlsBatch) bool {
        return self.future.isReady();
    }

    fn markStarted(self: *PendingSyncMessageBlsBatch, now_ns: i64) void {
        if (self.started_at_ns == 0 and self.future.started.isSet()) {
            self.started_at_ns = now_ns;
        }
    }

    fn finish(self: *PendingSyncMessageBlsBatch, node: *BeaconNode, finished_at_ns: i64) void {
        self.markStarted(finished_at_ns);
        const batch_valid = self.future.finish() catch false;
        const verify_started_ns = if (self.started_at_ns != 0) self.started_at_ns else self.enqueued_at_ns;
        recordGossipBlsVerificationMetrics(
            node,
            .sync_message,
            .batch_async,
            if (batch_valid) .success else .fallback,
            self.items.len,
            if (self.started_at_ns != 0) secondsFromNs(elapsedNsBetween(self.enqueued_at_ns, self.started_at_ns)) else null,
            elapsedNsBetween(verify_started_ns, finished_at_ns),
        );
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

    fn itemCount(self: *const PendingGossipBlsBatch) usize {
        return switch (self.*) {
            .attestation => |batch| batch.items.len,
            .aggregate => |batch| batch.items.len,
            .sync_message => |batch| batch.items.len,
        };
    }

    fn markStarted(self: *PendingGossipBlsBatch, now_ns: i64) void {
        switch (self.*) {
            .attestation => |*batch| batch.markStarted(now_ns),
            .aggregate => |*batch| batch.markStarted(now_ns),
            .sync_message => |*batch| batch.markStarted(now_ns),
        }
    }

    fn finish(self: *PendingGossipBlsBatch, node: *BeaconNode, finished_at_ns: i64) void {
        switch (self.*) {
            .attestation => |*batch| batch.finish(node, finished_at_ns),
            .aggregate => |*batch| batch.finish(node, finished_at_ns),
            .sync_message => |*batch| batch.finish(node, finished_at_ns),
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

    const now_ns = wallNowNs(node.io);
    for (node.pending_gossip_bls_batches.items) |*pending| {
        pending.markStarted(now_ns);
    }

    var did_work = false;
    while (findReadyPendingGossipBlsBatch(node)) |ready_index| {
        const finished_at_ns = wallNowNs(node.io);
        var ready = node.pending_gossip_bls_batches.orderedRemove(ready_index);
        ready.markStarted(finished_at_ns);
        ready.finish(node, finished_at_ns);
        did_work = true;
    }

    return did_work or node.pending_gossip_bls_batches.items.len > 0;
}

fn flushPendingGossipBlsBatchImpl(node: *BeaconNode) void {
    defer setGossipBlsBatchDispatchState(node);

    while (node.pending_gossip_bls_batches.items.len > 0) {
        const active_index = findStartedPendingGossipBlsBatch(node) orelse 0;
        const finished_at_ns = wallNowNs(node.io);
        var pending = node.pending_gossip_bls_batches.orderedRemove(active_index);
        pending.markStarted(finished_at_ns);
        pending.finish(node, finished_at_ns);
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

fn queueSecondsFromSeenTimestamp(seen_timestamp_ns: i64, started_at_ns: i64) f64 {
    if (seen_timestamp_ns <= 0) return 0;
    return secondsFromNs(elapsedNsBetween(seen_timestamp_ns, started_at_ns));
}

fn recordGossipBlsVerificationMetrics(
    node: *BeaconNode,
    kind: metrics_mod.BeaconMetrics.GossipBlsKind,
    path: metrics_mod.BeaconMetrics.GossipBlsPath,
    outcome: metrics_mod.BeaconMetrics.GossipBlsOutcome,
    item_count: usize,
    queue_seconds: ?f64,
    verify_elapsed_ns: u64,
) void {
    const metrics = node.metrics orelse return;
    metrics.observeGossipBlsVerification(
        kind,
        path,
        outcome,
        @intCast(item_count),
        queue_seconds,
        secondsFromNs(verify_elapsed_ns),
    );
}

fn observeGossipProcessorWork(
    node: *BeaconNode,
    kind: metrics_mod.BeaconMetrics.GossipProcessorKind,
    seen_timestamp_ns: i64,
    started_at_ns: i64,
) void {
    const metrics = node.metrics orelse return;
    const finished_at_ns = wallNowNs(node.io);
    metrics.observeGossipProcessor(
        kind,
        1,
        queueSecondsFromSeenTimestamp(seen_timestamp_ns, started_at_ns),
        secondsFromNs(elapsedNsBetween(started_at_ns, finished_at_ns)),
    );
}

fn observeGossipProcessorAttestationBatch(
    node: *BeaconNode,
    items: []const AttestationWork,
    started_at_ns: i64,
) void {
    const metrics = node.metrics orelse return;
    const handle_seconds = secondsFromNs(elapsedNsBetween(started_at_ns, wallNowNs(node.io)));
    for (items) |item| {
        metrics.observeGossipProcessor(
            .attestation,
            1,
            queueSecondsFromSeenTimestamp(item.seen_timestamp_ns, started_at_ns),
            handle_seconds,
        );
    }
}

fn observeGossipProcessorAggregateBatch(
    node: *BeaconNode,
    items: []const AggregateWork,
    started_at_ns: i64,
) void {
    const metrics = node.metrics orelse return;
    const handle_seconds = secondsFromNs(elapsedNsBetween(started_at_ns, wallNowNs(node.io)));
    for (items) |item| {
        metrics.observeGossipProcessor(
            .aggregate,
            1,
            queueSecondsFromSeenTimestamp(item.seen_timestamp_ns, started_at_ns),
            handle_seconds,
        );
    }
}

fn observeGossipProcessorSyncMessageBatch(
    node: *BeaconNode,
    items: []const processor_mod.work_item.SyncMessageWork,
    started_at_ns: i64,
) void {
    const metrics = node.metrics orelse return;
    const handle_seconds = secondsFromNs(elapsedNsBetween(started_at_ns, wallNowNs(node.io)));
    for (items) |item| {
        metrics.observeGossipProcessor(
            .sync_message,
            1,
            queueSecondsFromSeenTimestamp(item.seen_timestamp_ns, started_at_ns),
            handle_seconds,
        );
    }
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
        bls_mod.fillRandomScalars(node.io, rands[0..owned_count]);
        var pairing_buf: [bls_mod.Pairing.sizeOf()]u8 align(bls_mod.Pairing.buf_align) = undefined;
        return bls_mod.verifySignatureSetsSameMessage(
            &pairing_buf,
            sets,
            bls_mod.DST,
            rands[0..owned_count],
        ) catch false;
    }

    var batch_verifier = bls_mod.BatchVerifier.init(node.io, node.gossip_bls_thread_pool);
    for (sets) |set| {
        batch_verifier.addSet(set) catch return false;
    }

    return batch_verifier.verifyAll() catch false;
}

fn verifyAggregateBatchSync(node: *BeaconNode, items: []const AggregateWork) bool {
    const gh = node.gossip_handler orelse return true;
    if (gh.verifyAggregateSignatureFn == null) return true;

    var batch_verifier = bls_mod.BatchVerifier.init(node.io, node.gossip_bls_thread_pool);
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
        bls_mod.fillRandomScalars(node.io, rands[0..owned_count]);
        var pairing_buf: [bls_mod.Pairing.sizeOf()]u8 align(bls_mod.Pairing.buf_align) = undefined;
        return bls_mod.verifySignatureSetsSameMessage(
            &pairing_buf,
            sets,
            bls_mod.DST,
            rands[0..owned_count],
        ) catch false;
    }

    var batch_verifier = bls_mod.BatchVerifier.init(node.io, node.gossip_bls_thread_pool);
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
                        node_log.debug("attestation BLS failed in batch fallback at slot {d}", .{attestation.slot()});
                        continue;
                    }
                }
            }
        }

        const gh = node.gossip_handler orelse continue;
        const importFn = gh.importResolvedAttestationFn orelse continue;

        importFn(gh.node, &attestation, &item.attestation_data_root, &item.resolved) catch |err| {
            node_log.debug("processor attestation import failed for slot {d}: {}", .{
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
                        node_log.debug("aggregate BLS failed in batch fallback at slot {d}", .{
                            aggregate.attestation().slot(),
                        });
                        continue;
                    }
                }
            }
        }

        if (node.gossip_handler) |gh| {
            if (gh.importResolvedAggregateFn) |importFn| {
                importFn(gh.node, &aggregate, &item.attestation_data_root, &item.resolved) catch |err| {
                    node_log.debug("processor aggregate import failed at slot {d}: {}", .{
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
                    node_log.debug("sync committee message BLS failed in batch fallback at slot {d}", .{
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
        .enqueued_at_ns = wallNowNs(node.io),
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
        .enqueued_at_ns = wallNowNs(node.io),
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
        .enqueued_at_ns = wallNowNs(node.io),
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
            const started_at_ns = wallNowNs(node.io);
            defer observeGossipProcessorWork(node, .block, work.seen_timestamp_ns, started_at_ns);
            var peer_id = work.peer_id;
            defer peer_id.deinit();
            const seen_timestamp_sec: u64 = if (work.seen_timestamp_ns > 0)
                @intCast(@divFloor(work.seen_timestamp_ns, std.time.ns_per_s))
            else
                0;
            var prepared = node.chainService().preparePreparedBlockInput(work.block, .gossip, seen_timestamp_sec) catch |err| {
                work.block.deinit(node.allocator);
                node_log.debug("processor gossip block ingress failed: {}", .{err});
                return;
            };
            prepared.setPeerId(peer_id.bytes());

            const result = node.importPreparedBlock(prepared) catch |err| {
                node_log.debug("processor gossip block import failed: {}", .{err});
                return;
            };
            switch (result) {
                .ignored, .pending => {},
                .imported => |imported| {
                    node_log.debug("PROCESSOR: block imported slot={d} root={x:0>2}{x:0>2}{x:0>2}{x:0>2}...", .{
                        imported.slot,
                        imported.block_root[0],
                        imported.block_root[1],
                        imported.block_root[2],
                        imported.block_root[3],
                    });
                },
            }
        },
        .attestation_batch => |batch| {
            const batch_items = batch.items[0..batch.count];
            const started_at_ns = wallNowNs(node.io);
            defer observeGossipProcessorAttestationBatch(node, batch_items, started_at_ns);
            node_log.debug("Processor: attestation batch (count={d})", .{batch.count});
            if (cloneAttestationBatchItems(node.allocator, batch_items)) |owned_items| {
                if (tryStartPendingAttestationBatch(node, owned_items)) {
                    return;
                }

                defer node.allocator.free(owned_items);
                const verify_started_ns = wallNowNs(node.io);
                const batch_valid = verifyAttestationBatchSync(node, owned_items);
                recordGossipBlsVerificationMetrics(
                    node,
                    .attestation,
                    .batch_sync,
                    if (batch_valid) .success else .fallback,
                    owned_items.len,
                    null,
                    elapsedNsBetween(verify_started_ns, wallNowNs(node.io)),
                );
                importAttestationBatchItems(node, owned_items, batch_valid);
            } else |_| {
                const verify_started_ns = wallNowNs(node.io);
                const batch_valid = verifyAttestationBatchSync(node, batch_items);
                recordGossipBlsVerificationMetrics(
                    node,
                    .attestation,
                    .batch_sync,
                    if (batch_valid) .success else .fallback,
                    batch_items.len,
                    null,
                    elapsedNsBetween(verify_started_ns, wallNowNs(node.io)),
                );
                importAttestationBatchItems(node, batch_items, batch_valid);
            }
        },
        .aggregate_batch => |batch| {
            const batch_items = batch.items[0..batch.count];
            const started_at_ns = wallNowNs(node.io);
            defer observeGossipProcessorAggregateBatch(node, batch_items, started_at_ns);
            node_log.debug("Processor: aggregate batch (count={d})", .{batch.count});
            if (cloneAggregateBatchItems(node.allocator, batch_items)) |owned_items| {
                if (tryStartPendingAggregateBatch(node, owned_items)) {
                    return;
                }

                defer node.allocator.free(owned_items);
                const verify_started_ns = wallNowNs(node.io);
                const batch_valid = verifyAggregateBatchSync(node, owned_items);
                recordGossipBlsVerificationMetrics(
                    node,
                    .aggregate,
                    .batch_sync,
                    if (batch_valid) .success else .fallback,
                    owned_items.len,
                    null,
                    elapsedNsBetween(verify_started_ns, wallNowNs(node.io)),
                );
                importAggregateBatchItems(node, owned_items, batch_valid);
            } else |_| {
                const verify_started_ns = wallNowNs(node.io);
                const batch_valid = verifyAggregateBatchSync(node, batch_items);
                recordGossipBlsVerificationMetrics(
                    node,
                    .aggregate,
                    .batch_sync,
                    if (batch_valid) .success else .fallback,
                    batch_items.len,
                    null,
                    elapsedNsBetween(verify_started_ns, wallNowNs(node.io)),
                );
                importAggregateBatchItems(node, batch_items, batch_valid);
            }
        },
        .sync_message_batch => |batch| {
            const batch_items = batch.items[0..batch.count];
            const started_at_ns = wallNowNs(node.io);
            defer observeGossipProcessorSyncMessageBatch(node, batch_items, started_at_ns);
            node_log.debug("Processor: sync message batch (count={d})", .{batch.count});
            if (cloneSyncMessageBatchItems(node.allocator, batch_items)) |owned_items| {
                if (tryStartPendingSyncMessageBatch(node, owned_items)) {
                    return;
                }

                defer node.allocator.free(owned_items);
                const verify_started_ns = wallNowNs(node.io);
                const batch_valid = verifySyncMessageBatchSync(node, owned_items);
                recordGossipBlsVerificationMetrics(
                    node,
                    .sync_message,
                    .batch_sync,
                    if (batch_valid) .success else .fallback,
                    owned_items.len,
                    null,
                    elapsedNsBetween(verify_started_ns, wallNowNs(node.io)),
                );
                importSyncMessageBatchItems(node, owned_items, batch_valid);
            } else |_| {
                const verify_started_ns = wallNowNs(node.io);
                const batch_valid = verifySyncMessageBatchSync(node, batch_items);
                recordGossipBlsVerificationMetrics(
                    node,
                    .sync_message,
                    .batch_sync,
                    if (batch_valid) .success else .fallback,
                    batch_items.len,
                    null,
                    elapsedNsBetween(verify_started_ns, wallNowNs(node.io)),
                );
                importSyncMessageBatchItems(node, batch_items, batch_valid);
            }
        },
        .aggregate => |work| {
            const started_at_ns = wallNowNs(node.io);
            defer observeGossipProcessorWork(node, .aggregate, work.seen_timestamp_ns, started_at_ns);
            if (node.gossip_handler) |gh| {
                if (gh.verifyAggregateSignatureFn) |verifyFn| {
                    const verify_started_ns = wallNowNs(node.io);
                    const signature_valid = verifyFn(gh.node, &work.aggregate, &work.resolved);
                    recordGossipBlsVerificationMetrics(
                        node,
                        .aggregate,
                        .single,
                        if (signature_valid) .success else .failure,
                        1,
                        null,
                        elapsedNsBetween(verify_started_ns, wallNowNs(node.io)),
                    );
                    if (!signature_valid) {
                        node_log.debug("single aggregate BLS failed for aggregator {d}", .{work.aggregate.aggregatorIndex()});
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
            const started_at_ns = wallNowNs(node.io);
            defer observeGossipProcessorWork(node, .attestation, att_work.seen_timestamp_ns, started_at_ns);
            handleQueuedAttestation(node, att_work);
        },
        .gossip_voluntary_exit => |work| {
            const started_at_ns = wallNowNs(node.io);
            defer observeGossipProcessorWork(node, .voluntary_exit, work.seen_timestamp_ns, started_at_ns);
            handleQueuedVoluntaryExit(node, work);
        },
        .gossip_proposer_slashing => |work| {
            const started_at_ns = wallNowNs(node.io);
            defer observeGossipProcessorWork(node, .proposer_slashing, work.seen_timestamp_ns, started_at_ns);
            handleQueuedProposerSlashing(node, work);
        },
        .gossip_attester_slashing => |work| {
            const started_at_ns = wallNowNs(node.io);
            defer observeGossipProcessorWork(node, .attester_slashing, work.seen_timestamp_ns, started_at_ns);
            handleQueuedAttesterSlashing(node, work);
        },
        .gossip_bls_to_exec => |work| {
            const started_at_ns = wallNowNs(node.io);
            defer observeGossipProcessorWork(node, .bls_to_execution_change, work.seen_timestamp_ns, started_at_ns);
            handleQueuedBlsChange(node, work);
        },
        .gossip_blob => |work| {
            const started_at_ns = wallNowNs(node.io);
            defer observeGossipProcessorWork(node, .blob_sidecar, work.seen_timestamp_ns, started_at_ns);
            handleQueuedBlobSidecar(node, work);
        },
        .gossip_data_column => |work| {
            const started_at_ns = wallNowNs(node.io);
            defer observeGossipProcessorWork(node, .data_column_sidecar, work.seen_timestamp_ns, started_at_ns);
            handleQueuedDataColumnSidecar(node, work);
        },
        .sync_contribution => |work| {
            const started_at_ns = wallNowNs(node.io);
            defer observeGossipProcessorWork(node, .sync_contribution, work.seen_timestamp_ns, started_at_ns);
            handleQueuedSyncContribution(node, work);
        },
        .sync_message => |work| {
            const started_at_ns = wallNowNs(node.io);
            defer observeGossipProcessorWork(node, .sync_message, work.seen_timestamp_ns, started_at_ns);
            if (node.gossip_handler) |gh| {
                if (gh.verifySyncCommitteeSignatureFn != null) {
                    const verify_started_ns = wallNowNs(node.io);
                    const signature_valid = gossip_node_callbacks_mod.verifySyncCommitteeMessage(gh.node, &work.message);
                    recordGossipBlsVerificationMetrics(
                        node,
                        .sync_message,
                        .single,
                        if (signature_valid) .success else .failure,
                        1,
                        null,
                        elapsedNsBetween(verify_started_ns, wallNowNs(node.io)),
                    );
                    if (!signature_valid) {
                        node_log.debug("single sync committee message BLS failed for validator {d} at slot {d}", .{
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
            node_log.debug("Processor: dispatched {s}", .{@tagName(wtype)});
        },
    }
}

fn handleQueuedAttestation(node: *BeaconNode, work: processor_mod.work_item.AttestationWork) void {
    var attestation = work.attestation;
    defer attestation.deinit(node.allocator);

    if (node.gossip_handler) |gh| {
        if (gh.verifyAttestationSignatureFn) |verifyFn| {
            const verify_started_ns = wallNowNs(node.io);
            const signature_valid = verifyFn(gh.node, &attestation, &work.resolved);
            recordGossipBlsVerificationMetrics(
                node,
                .attestation,
                .single,
                if (signature_valid) .success else .failure,
                1,
                null,
                elapsedNsBetween(verify_started_ns, wallNowNs(node.io)),
            );
            if (!signature_valid) {
                node_log.debug("single attestation BLS failed at slot {d}", .{attestation.slot()});
                return;
            }
        }
        const importFn = gh.importResolvedAttestationFn orelse return;
        importFn(gh.node, &attestation, &work.attestation_data_root, &work.resolved) catch |err| {
            node_log.debug("processor attestation import failed for slot {d}: {}", .{
                attestation.slot(),
                err,
            });
        };
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

    importFn(gh.node, &aggregate, &work.attestation_data_root, &work.resolved) catch |err| {
        node_log.debug("processor aggregate import failed for aggregator {d}: {}", .{
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
        node_log.debug("processor voluntary exit import failed for validator {d}: {}", .{
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
        node_log.debug("processor attester slashing import failed: {}", .{err});
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
        node_log.debug("processor proposer slashing import failed: {}", .{err});
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
        node_log.debug("processor BLS change import failed: {}", .{err});
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
        node_log.debug("processor sync contribution import failed: {}", .{err});
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
        node_log.debug("processor blob sidecar import failed: {}", .{err});
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
        node_log.debug("processor data column sidecar import failed: {}", .{err});
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
        node_log.debug("processor sync committee message import failed: {}", .{err});
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
        _: *const [32]u8,
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
        _: *const [32]u8,
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

test "releasePendingUnknownBlockGossip transfers queued attestations without double cleanup" {
    const allocator = std.testing.allocator;

    var ctx = ProcessorImportTestContext{};
    var node: BeaconNode = undefined;
    node.allocator = allocator;
    node.beacon_processor = null;
    node.pending_unknown_block_gossip = PendingUnknownBlockGossipQueue.init(allocator);
    defer node.pending_unknown_block_gossip.deinit();

    var gh: GossipHandler = undefined;
    gh.node = @ptrCast(&ctx);
    gh.importResolvedAttestationFn = &ProcessorImportTestContext.importAttestation;
    gh.verifyAttestationSignatureFn = null;
    node.gossip_handler = &gh;

    const root = [_]u8{0x44} ** 32;
    const added = try node.queueUnknownBlockAttestation(root, .{
        .source = .{ .key = 1 },
        .message_id = std.mem.zeroes(processor_mod.work_item.MessageId),
        .attestation = .{ .phase0 = .{
            .aggregation_bits = .{ .bit_len = 1, .data = .empty },
            .data = .{
                .slot = 333,
                .index = 9,
                .beacon_block_root = root,
                .source = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
                .target = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
            },
            .signature = [_]u8{0} ** 96,
        } },
        .attestation_data_root = [_]u8{0} ** 32,
        .resolved = .{
            .validator_index = 27,
            .validator_committee_index = 0,
            .committee_size = 1,
            .signing_root = [_]u8{0x55} ** 32,
            .expected_subnet = 0,
        },
        .subnet_id = 0,
        .seen_timestamp_ns = 0,
    }, "peer-a");
    try std.testing.expect(added);

    node.releasePendingUnknownBlockGossip(root);

    try std.testing.expectEqual(@as(?u64, 333), ctx.attestation_slot);
    try std.testing.expectEqual(@as(?u64, 9), ctx.attestation_committee_index);
    try std.testing.expectEqual(@as(?u64, 27), ctx.validator_index);
    try std.testing.expectEqual(@as(usize, 0), node.pending_unknown_block_gossip.pendingCount());
}

test "processorHandlerCallback imports queued sync committee messages" {
    const allocator = std.testing.allocator;

    var ctx = ProcessorImportTestContext{};
    var node: BeaconNode = undefined;
    node.allocator = allocator;

    var gh: GossipHandler = undefined;
    gh.node = @ptrCast(&ctx);
    gh.importSyncCommitteeMessageFn = &ProcessorImportTestContext.importSyncCommitteeMessage;
    gh.verifySyncCommitteeSignatureFn = null;
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
