//! BeaconNode: top-level orchestrator that ties all modules together.
//!
//! Owns and wires the core components of a beacon chain node:
//! - State caches (BlockStateCache, CheckpointStateCache, StateRegen)
//! - Database (BeaconDB over KVStore)
//! - Chain management (OpPool, SeenCache, HeadTracker, BlockImporter)
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
const BlockStateCache = state_transition.BlockStateCache;
const CheckpointStateCache = state_transition.CheckpointStateCache;
const MemoryCPStateDatastore = state_transition.MemoryCPStateDatastore;
const CheckpointKey = state_transition.CheckpointKey;
const StateRegen = state_transition.StateRegen;
const db_mod = @import("db");
const BeaconDB = db_mod.BeaconDB;
const MemoryKVStore = db_mod.MemoryKVStore;
const LmdbKVStore = db_mod.LmdbKVStore;
const chain_mod = @import("chain");
const Chain = chain_mod.Chain;
const QueuedStateRegen = chain_mod.QueuedStateRegen;
const OpPool = chain_mod.OpPool;
const SeenCache = chain_mod.SeenCache;
const SyncContributionAndProofPool = chain_mod.SyncContributionAndProofPool;
const SyncCommitteeMessagePool = chain_mod.SyncCommitteeMessagePool;
const ProducedBlockBody = chain_mod.ProducedBlockBody;
const ProducedBlock = chain_mod.ProducedBlock;
const ValidatorMonitor = chain_mod.ValidatorMonitor;
const BlockProductionConfig = chain_mod.BlockProductionConfig;
pub const HeadTracker = chain_mod.HeadTracker;
pub const ImportResult = chain_mod.ImportResult;
const ImportError = chain_mod.ImportError;
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
const PassthroughValidator = networking.p2p_service.PassthroughValidator;
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

const fork_choice_mod = @import("fork_choice");
const ForkChoice = fork_choice_mod.ForkChoiceStruct;
const ProtoBlock = fork_choice_mod.ProtoBlock;
const BlockExtraMeta = fork_choice_mod.BlockExtraMeta;
const ForkChoiceCheckpoint = fork_choice_mod.Checkpoint;
const LVHExecResponse = fork_choice_mod.LVHExecResponse;
const ForkChoiceStore = fork_choice_mod.ForkChoiceStore;
const ProtoArrayStruct = fork_choice_mod.ProtoArrayStruct;
const CheckpointWithPayloadStatus = fork_choice_mod.CheckpointWithPayloadStatus;
const ForkChoiceOpts = fork_choice_mod.ForkChoiceOpts;
const JustifiedBalancesGetter = fork_choice_mod.JustifiedBalancesGetter;
const JustifiedBalances = fork_choice_mod.JustifiedBalances;

const execution_mod = @import("execution");
const EngineApi = execution_mod.EngineApi;
const MockEngine = execution_mod.MockEngine;
const HttpEngine = execution_mod.HttpEngine;
const IoHttpTransport = execution_mod.IoHttpTransport;
const PayloadAttributesV3 = execution_mod.engine_api_types.PayloadAttributesV3;
const GetPayloadResponse = execution_mod.GetPayloadResponse;
const BuilderApi = execution_mod.BuilderApi;
const BuilderStatus = execution_mod.BuilderStatus;
const constants = @import("constants");
const Sha256 = std.crypto.hash.sha2.Sha256;
const metrics_mod = @import("metrics.zig");
pub const BeaconMetrics = metrics_mod.BeaconMetrics;

const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const BlockSource = chain_mod.blocks.BlockSource;
const gossip_handler_mod = @import("gossip_handler.zig");
pub const GossipHandler = gossip_handler_mod.GossipHandler;
const GossipIngressMetadata = gossip_handler_mod.GossipIngressMetadata;

const block_import_mod = @import("block_import.zig");
const api_callbacks_mod = @import("api_callbacks.zig");
const block_production_mod = @import("block_production.zig");
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
// HeadTracker, ImportResult, ImportError are in chain_mod (src/chain).

// dummyBalancesGetterFn is defined in block_import.zig.
pub const dummyBalancesGetterFn = block_import_mod.dummyBalancesGetterFn;

// ---------------------------------------------------------------------------
// SyncCallbackCtx — bridging sync pipeline callbacks to P2P transport.
// Defined in sync_bridge.zig; re-exported here for backwards compatibility.
// ---------------------------------------------------------------------------

pub const PendingBatchRequest = sync_bridge_mod.PendingBatchRequest;
pub const SyncCallbackCtx = sync_bridge_mod.SyncCallbackCtx;

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

// ---------------------------------------------------------------------------
// HeadInfo — canonical version from chain/types.zig.
// ---------------------------------------------------------------------------

pub const HeadInfo = chain_mod.HeadInfo;

pub const BeaconNode = struct {
    pub const InitConfig = struct {
        options: NodeOptions,
        db_path: ?[]const u8 = null,
        node_identity: NodeIdentity,
        jwt_secret: ?[32]u8 = null,
        bootstrap_peers: []const []const u8 = &.{},
        discovery_bootnodes: []const []const u8 = &.{},
        identify_agent_version: ?[]const u8 = null,
    };

    allocator: Allocator,
    config: *const BeaconConfig,

    // Core components
    db: *BeaconDB,
    state_regen: *StateRegen,
    queued_regen: *QueuedStateRegen,
    block_state_cache: *BlockStateCache,
    checkpoint_state_cache: *CheckpointStateCache,
    head_tracker: *HeadTracker,
    fork_choice: ?*ForkChoice,

    // Chain coordinator (delegates to all chain components)
    chain: *Chain,

    // Chain components (owned by BeaconNode, pointers held by chain)
    op_pool: *OpPool,
    seen_cache: *SeenCache,

    // Sync committee pools — collect contributions for SyncAggregate production.
    sync_contribution_pool: ?*SyncContributionAndProofPool,
    sync_committee_message_pool: ?*SyncCommitteeMessagePool,

    // Clock
    clock: ?SlotClock,

    // Checkpoint state datastore (memory-backed)
    cp_datastore: *MemoryCPStateDatastore,

    // KV backend (kept for cleanup — BeaconDB holds the vtable)
    kv_backend: KVBackend,

    // API context
    api_context: *ApiContext,
    api_head_tracker: *api_mod.context.HeadTracker,
    api_sync_status: *api_mod.context.SyncStatus,
    api_node_identity: *api_mod.types.NodeIdentity,
    api_bindings: ?*api_callbacks_mod.ApiBindings = null,
    /// EventBus for SSE beacon chain events. Owned by BeaconNode, wired into
    /// ApiContext.event_bus and Chain.event_callback.
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

    // P2P service (lazy-initialized via startP2p).
    // Owns the libp2p Switch, gossipsub service, and gossip adapter.
    p2p_service: ?P2pService = null,

    // Passthrough gossip validator — owned by BeaconNode for the lifetime of p2p_service.
    // Heap-allocated so its internal pointers remain stable even if BeaconNode moves.
    p2p_validator: ?*PassthroughValidator = null,

    // Req/resp context used by the P2P service (persistent, heap-allocated).
    // Uses self.allocator as scratch; block bytes returned by callbacks are copied
    // by the handler before the callback returns.
    p2p_req_resp_ctx: ?*ReqRespContext = null,
    p2p_request_ctx: ?*reqresp_callbacks_mod.RequestContext = null,

    // Sync controller — wires P2P events into the sync pipeline.
    // Optional: nil until initialized (e.g. when running without P2P).
    // sync_controller removed — SyncService is the direct entry point.

    // Last known active fork digest — used to detect fork transitions
    // so we can resubscribe gossip topics under the new fork digest.
    last_active_fork_digest: [4]u8 = [4]u8{ 0, 0, 0, 0 },

    // Sync subsystem components (lazily initialized when P2P starts).

    sync_service_inst: ?*SyncService = null,
    sync_callback_ctx: ?*SyncCallbackCtx = null, // bridges to P2P transport

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

    // Execution Layer engine (Engine API client or mock).
    mock_engine: ?*MockEngine = null,
    http_engine: ?*HttpEngine = null,
    io_transport: ?*IoHttpTransport = null,
    engine_api: ?EngineApi = null,

    /// Cached payload ID from the last forkchoiceUpdated call with payload attributes.
    /// Used by produceBlockWithPayload to retrieve the built execution payload via getPayload.
    cached_payload_id: ?[8]u8 = null,

    /// Optional MEV-boost builder relay client.
    /// When configured, block production attempts to use the builder for higher rewards.
    /// Falls back to local execution engine if builder is unavailable or bid too low.
    builder_api: ?BuilderApi = null,

    /// Minimum builder bid value threshold relative to local payload value (0.0 to 1.0).
    /// Builder bid must exceed local_value * threshold to use the blinded path.
    /// Default: 0.0 (any positive bid is acceptable).
    builder_bid_threshold: f64 = 0.0,

    /// Track whether the EL is offline (unreachable). Reset on successful Engine API call.
    el_offline: bool = false,

    /// I/O context for runtime operations.
    io: std.Io,

    /// BLS thread pool for parallel signature verification.
    /// Shared between BlockImporter (block import) and GossipHandler (gossip BLS — TODO).
    bls_thread_pool: *BlsThreadPool,

    // Node identity — secp256k1 keypair loaded/generated during init().
    node_identity: NodeIdentity,

    // Genesis validators root — set by initFromGenesis, used for fork digest computation.
    genesis_validators_root: [32]u8 = [_]u8{0} ** 32,

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
        if (self.http_server) |*srv| srv.shutdown();
    }

    pub const KVBackend = union(enum) {
        memory: *MemoryKVStore,
        lmdb: *LmdbKVStore,
    };

    /// Create a new BeaconNode with all components wired together.
    ///
    /// Uses MemoryKVStore for the database backend — production would
    /// swap this for LMDB or similar. All caches, pools, and trackers
    /// are heap-allocated and owned by the node.
    pub fn init(allocator: Allocator, io: std.Io, beacon_config: *const BeaconConfig, init_config: InitConfig) !*BeaconNode {
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

    /// Import a signed beacon block through the full pipeline.
    ///
    /// Fork-polymorphic: accepts any signed beacon block via AnySignedBeaconBlock.
    /// Delegates to chain.importBlock which routes through the modular pipeline.
    pub fn importBlock(
        self: *BeaconNode,
        any_signed: AnySignedBeaconBlock,
        source: BlockSource,
    ) !ImportResult {
        const t0 = std.Io.Clock.awake.now(self.io);
        const result = try self.chain.importBlock(any_signed, source);

        // Notify EL of fork choice update after each block import.
        self.notifyForkchoiceUpdate(result.block_root) catch |err| {
            log.logger(.node).warn("forkchoiceUpdated failed: {}", .{err});
        };

        const t1 = std.Io.Clock.awake.now(self.io);
        const elapsed_s: f64 = @as(f64, @floatFromInt(t1.nanoseconds - t0.nanoseconds)) / 1e9;

        // Update metrics.
        if (self.metrics) |m| {
            m.blocks_imported_total.incr();
            m.block_import_seconds.observe(elapsed_s);
            m.head_slot.set(result.slot);
            m.finalized_epoch.set(self.head_tracker.finalized_epoch);
            m.justified_epoch.set(self.head_tracker.justified_epoch);
            // Encode first 8 bytes of block root as u64 for change detection.
            m.head_root.set(std.mem.readInt(u64, result.block_root[0..8], .big));
        }

        // Update API context
        self.api_head_tracker.head_slot = result.slot;
        self.api_head_tracker.head_root = result.block_root;
        self.api_head_tracker.head_state_root = result.state_root;

        if (result.epoch_transition) {
            // Store epoch-start slot; see HeadTracker.finalized_slot comment.
            self.api_head_tracker.finalized_slot = self.head_tracker.finalized_epoch * preset.SLOTS_PER_EPOCH;
            self.api_head_tracker.justified_slot = self.head_tracker.justified_epoch * preset.SLOTS_PER_EPOCH;
            if (self.chain.fork_choice) |fc| {
                self.api_head_tracker.justified_root = fc.getJustifiedCheckpoint().root;
                self.api_head_tracker.finalized_root = fc.getFinalizedCheckpoint().root;
            }
            // Archive the post-epoch state for cold-path recovery.
            // Errors are non-fatal — the block is already imported.
            self.archiveState(result.slot, result.state_root) catch {};
            // Prune backwards chains that are behind finalization.
            self.unknown_chain_sync.onFinalized(
                self.head_tracker.finalized_epoch * preset.SLOTS_PER_EPOCH,
            );
            log.logger(.chain).info("epoch transition", .{
                .slot = result.slot,
                .finalized_epoch = self.head_tracker.finalized_epoch,
                .justified_epoch = self.head_tracker.justified_epoch,
            });
        }

        log.logger(.chain).verbose("block imported", .{
            .slot = result.slot,
            .root = result.block_root,
            .epoch_transition = result.epoch_transition,
        });

        return result;
    }

    /// Store a blob sidecar received via gossip or req/resp.
    ///
    /// Blob sidecars arrive separately from blocks (via GossipSub or BlobSidecarsByRoot).
    /// All sidecars for a given block root are stored together as raw bytes, keyed by root.
    /// Callers that have disaggregated sidecar data should aggregate before calling this.
    pub fn importBlobSidecar(self: *BeaconNode, root: [32]u8, data: []const u8) !void {
        try self.db.putBlobSidecars(root, data);
    }

    /// Store a data column sidecar received via gossip or req/resp (PeerDAS / Fulu).
    ///
    /// Data column sidecars arrive individually, keyed by (block_root, column_index).
    /// Each sidecar is stored independently to support per-column availability tracking.
    pub fn importDataColumnSidecar(self: *BeaconNode, root: [32]u8, column_index: u64, data: []const u8) !void {
        try self.db.putDataColumn(root, column_index, data);
        std.log.info("Imported data column sidecar root={s}... column={d}", .{
            &std.fmt.bytesToHex(root[0..4], .lower),
            column_index,
        });
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
            if (self.db.getDataColumn(root, col_idx) catch null) |data| {
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
        return self.db.getDataColumn(root, column_index);
    }

    /// Archive the post-epoch state to the cold store.
    ///
    /// Called at epoch boundaries so that the cold path in StateRegen can
    /// find a nearby anchor state and replay blocks forward from it.
    ///
    /// Serializes the CachedBeaconState's inner AnyBeaconState to SSZ bytes
    /// and stores it via `BeaconDB.putStateArchive(slot, state_root, bytes)`.
    pub fn archiveState(self: *BeaconNode, slot: u64, state_root: [32]u8) !void {
        // Look up the live state from the block cache by its state root.
        const cached = self.block_state_cache.get(state_root) orelse return;

        // Serialize the inner AnyBeaconState to SSZ bytes.
        const bytes = try cached.state.serialize(self.allocator);
        defer self.allocator.free(bytes);

        // Persist to the archive store keyed by (slot, state_root).
        try self.db.putStateArchive(slot, state_root, bytes);
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
        const head_state_root = self.head_tracker.head_state_root;
        const pre_state = self.block_state_cache.get(head_state_root) orelse
            return error.NoHeadState;

        // Clone and advance.
        const post_state = try pre_state.clone(self.allocator, .{ .transfer_cache = false });
        errdefer {
            post_state.deinit();
            self.allocator.destroy(post_state);
        }

        try state_transition.processSlots(self.allocator, post_state, target_slot, .{});
        try post_state.state.commit();

        // Cache the new state as the head.
        const new_state_root = try self.queued_regen.onNewBlock(post_state, true);

        // Update chain's block_root -> state_root mapping so the
        // next block import can find this state as parent.
        try self.chain.block_to_state.put(
            self.head_tracker.head_root,
            new_state_root,
        );

        // Update head tracker to reflect the new state_root.
        self.head_tracker.head_state_root = new_state_root;
        self.head_tracker.head_slot = target_slot;

        // Persist slot->root for range queries.
        try self.head_tracker.slot_roots.put(target_slot, self.head_tracker.head_root);

        // Update API context.
        self.api_head_tracker.head_slot = target_slot;
        self.api_head_tracker.head_state_root = new_state_root;
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

    /// Notify the EL of the current fork choice and optionally trigger payload building.
    ///
    /// Called after each block import. Sends engine_forkchoiceUpdatedV3 with the
    /// current head/safe/finalized block hashes. If payload_attrs is provided
    /// (e.g., this node is the next proposer), also starts building a new payload.
    /// The returned payload_id is cached for later getPayload calls.
    fn notifyForkchoiceUpdate(self: *BeaconNode, new_head_root: [32]u8) !void {
        try block_production_mod.notifyForkchoiceUpdate(self, new_head_root);
    }

    /// Inner forkchoiceUpdated with optional payload attributes.
    fn notifyForkchoiceUpdateWithAttrs(
        self: *BeaconNode,
        new_head_root: [32]u8,
        payload_attrs: ?PayloadAttributesV3,
    ) !void {
        try block_production_mod.notifyForkchoiceUpdateWithAttrs(self, new_head_root, payload_attrs);
    }

    /// Trigger payload building by sending forkchoiceUpdated with payload attributes.
    ///
    /// Called before block production when this node is the proposer for the next slot.
    /// Sends the current fork choice state with payload attributes to start the EL
    /// building an execution payload. The payload_id is cached for retrieval via
    /// getExecutionPayload().
    pub fn preparePayload(
        self: *BeaconNode,
        timestamp: u64,
        prev_randao: [32]u8,
        fee_recipient: [20]u8,
        withdrawals_slice: []const execution_mod.engine_api_types.Withdrawal,
        parent_beacon_block_root: [32]u8,
    ) !void {
        try block_production_mod.preparePayload(
            self,
            timestamp,
            prev_randao,
            fee_recipient,
            withdrawals_slice,
            parent_beacon_block_root,
        );
    }

    /// Retrieve the execution payload built by the EL via engine_getPayloadV3.
    ///
    /// Must be called after preparePayload() has been called and the EL returned
    /// a payload_id. Returns the complete execution payload, block value, and
    /// blobs bundle for inclusion in the beacon block.
    ///
    /// If a builder relay is configured and available, this method first attempts
    /// to retrieve a builder bid (getHeader). If the bid value exceeds the local
    /// payload value * threshold, the blinded block path is used.
    pub fn getExecutionPayload(self: *BeaconNode) !GetPayloadResponse {
        return block_production_mod.getExecutionPayload(self);
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

    /// Get the current head info.
    pub fn getHead(self: *const BeaconNode) HeadInfo {
        // Use fork choice head when available (authoritative LMD-GHOST head).
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
        // Fallback to naive head tracker (before initFromGenesis is called).
        return .{
            .slot = self.head_tracker.head_slot,
            .root = self.head_tracker.head_root,
            .state_root = self.head_tracker.head_state_root,
            .finalized_epoch = self.head_tracker.finalized_epoch,
            .justified_epoch = self.head_tracker.justified_epoch,
        };
    }

    /// Get the current sync status.
    ///
    /// For now returns a simple status based on head slot. In production this
    /// would compare against the clock's wall-clock slot to determine sync
    /// distance.
    pub fn getSyncStatus(self: *const BeaconNode) SyncStatus {
        // Use the sync service state machine when available.
        if (self.sync_service_inst) |svc| {
            const ss = svc.getSyncStatus();
            return .{
                .head_slot = ss.head_slot,
                .sync_distance = ss.sync_distance,
                .is_syncing = ss.state == .syncing_finalized or ss.state == .syncing_head,
                .is_optimistic = ss.is_optimistic,
                .el_offline = self.el_offline,
            };
        }
        // Fallback: no sync service (e.g. tests without P2P).
        const head_slot = if (self.fork_choice) |fc| fc.head.slot else self.head_tracker.head_slot;
        return .{
            .head_slot = head_slot,
            .sync_distance = 0,
            .is_syncing = false,
            .is_optimistic = false,
            .el_offline = self.el_offline,
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
    /// Produce a full block and import it locally.
    ///
    /// This is the complete block production pipeline:
    /// 1. Produce block body with execution payload
    /// 2. Wrap in BeaconBlock with slot, proposer, parent root
    /// 3. Compute state root via state transition (with verification off)
    /// 4. Wrap in SignedBeaconBlock (with zero signature — VC signs separately)
    /// 5. Import the block locally
    ///
    /// Returns the signed block and import result. The block is owned by the
    /// caller and must be freed.
    ///
    /// Preconditions:
    /// - preparePayload() called at slot N-1 (to have a cached payload)
    /// - Head state available in block_state_cache
    pub fn produceAndImportBlock(
        self: *BeaconNode,
        slot: u64,
        prod_config: BlockProductionConfig,
    ) !struct { signed_block: *types.electra.SignedBeaconBlock.Type, import_result: ImportResult } {
        return block_production_mod.produceAndImportBlock(self, slot, prod_config);
    }

    /// Broadcast a signed block to the network via gossip.
    ///
    /// Serializes and publishes the block on the beacon_block gossip topic.
    /// Should be called after produceAndImportBlock() succeeds.
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
        // Always use head_tracker which is updated during range sync import.
        // Fork choice head isn't reliably updated during batch import.
        return .{
            .fork_digest = self.config.forkDigestAtSlot(self.head_tracker.head_slot, self.genesis_validators_root),
            .finalized_root = if (self.head_tracker.finalized_epoch == 0)
                [_]u8{0} ** 32
            else if (self.fork_choice) |fc|
                // Use fork choice's authoritative finalized checkpoint root (C2 fix).
                // Slot-based lookup fails on skip slots.
                fc.getFinalizedCheckpoint().root
            else if (self.head_tracker.getBlockRoot(
                self.head_tracker.finalized_epoch * preset.SLOTS_PER_EPOCH,
            )) |r| r else [_]u8{0} ** 32,
            .finalized_epoch = self.head_tracker.finalized_epoch,
            .head_root = self.head_tracker.head_root,
            .head_slot = self.head_tracker.head_slot,
        };
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
};

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
            // Full block import via STFN + fork choice.
            // The AnySignedBeaconBlock is owned by the work item.
            const result = node.importBlock(work.block, .gossip) catch |err| {
                if (err == error.UnknownParentBlock) {
                    const ssz_bytes = work.block.serialize(node.allocator) catch {
                        work.block.deinit(node.allocator);
                        return;
                    };
                    defer node.allocator.free(ssz_bytes);
                    node.queueOrphanBlock(work.block, ssz_bytes);
                } else if (err != error.BlockAlreadyKnown and err != error.BlockAlreadyFinalized) {
                    std.log.warn("Processor: gossip block import failed: {}", .{err});
                }
                work.block.deinit(node.allocator);
                return;
            };
            work.block.deinit(node.allocator);
            node.processPendingChildren(result.block_root);
            std.log.info("PROCESSOR: block imported slot={d} root={x:0>2}{x:0>2}{x:0>2}{x:0>2}...", .{
                result.slot,
                result.block_root[0],
                result.block_root[1],
                result.block_root[2],
                result.block_root[3],
            });
        },
        .attestation_batch => |batch| {
            // Batch BLS verification: the key performance optimization.
            //
            // Architecture (matches TS Lodestar's gossipQueues/indexed.ts):
            // 1. Collect N attestation signature sets
            // 2. Batch-verify all N signatures at once (~3-10x faster than individual)
            // 3. On batch success: import all attestations to fork choice + pool
            // 4. On batch failure: fall back to individual verification to find bad one(s)
            const QueuedAttestation = gossip_handler_mod.QueuedAttestation;

            std.log.debug("Processor: attestation batch (count={d})", .{batch.count});

            // Step 1: Try batch BLS verification of all attestations.
            var batch_valid = false;
            if (node.gossip_handler) |gh| {
                if (gh.verifyAttestationSignatureFn) |verifyFn| {
                    // Attempt batch: verify each individually for now.
                    // TODO: Collect signature sets into BatchVerifier for true batch pairing.
                    // When real signature set extraction is implemented, this becomes:
                    //   var bv = BatchVerifier.init(node.bls_thread_pool);
                    //   for items: bv.addSet(extractSigSet(queued.ssz_bytes));
                    //   batch_valid = bv.verifyAll();
                    batch_valid = true;
                    var j: u32 = 0;
                    while (j < batch.count) : (j += 1) {
                        const att_work = batch.items[j];
                        const queued: *QueuedAttestation = @ptrCast(@alignCast(att_work.data));
                        if (!verifyFn(gh.node, queued.ssz_bytes)) {
                            batch_valid = false;
                            break;
                        }
                    }
                } else {
                    // No BLS verification configured — accept all (test mode).
                    batch_valid = true;
                }
            } else {
                batch_valid = true;
            }

            // Step 2: Import valid attestations to fork choice + pool.
            var i: u32 = 0;
            while (i < batch.count) : (i += 1) {
                const att_work = batch.items[i];
                const queued: *QueuedAttestation = @ptrCast(@alignCast(att_work.data));
                defer queued.deinit();

                if (!batch_valid) {
                    // Batch failed — verify individually to find the bad one(s).
                    if (node.gossip_handler) |gh| {
                        if (gh.verifyAttestationSignatureFn) |verifyFn| {
                            if (!verifyFn(gh.node, queued.ssz_bytes)) {
                                std.log.warn("Attestation BLS failed in batch fallback slot={d}", .{queued.att.slot});
                                continue; // Skip this invalid attestation.
                            }
                        }
                    }
                }

                // Import to fork choice (apply vote weight).
                // Op pool insertion requires a full Attestation struct — deferred to
                // when full attestation objects are threaded through the pipeline.
                if (node.chain.fork_choice) |fc| {
                    fc.onSingleVote(
                        node.allocator,
                        @intCast(queued.att.attester_index),
                        queued.att.slot,
                        queued.att.target_root,
                        queued.att.target_epoch,
                    ) catch |err| {
                        std.log.warn("FC onSingleVote failed validator={d} slot={d}: {}", .{
                            queued.att.attester_index, queued.att.slot, err,
                        });
                    };
                }
            }
        },
        .aggregate_batch => |batch| {
            // Batch BLS verification for aggregates.
            // Same pattern as attestation batching.
            std.log.debug("Processor: aggregate batch (count={d})", .{batch.count});

            var i: u32 = 0;
            while (i < batch.count) : (i += 1) {
                const agg_work = batch.items[i];
                _ = agg_work; // TODO: import individual aggregate
            }
        },
        .attestation => |att_work| {
            // Single attestation (not batched).
            // BLS verify and import to fork choice.
            const QueuedAttestation = gossip_handler_mod.QueuedAttestation;
            const queued: *QueuedAttestation = @ptrCast(@alignCast(att_work.data));
            defer queued.deinit();

            // BLS signature verification.
            if (node.gossip_handler) |gh| {
                if (gh.verifyAttestationSignatureFn) |verifyFn| {
                    if (!verifyFn(gh.node, queued.ssz_bytes)) {
                        std.log.warn("Single attestation BLS failed slot={d}", .{queued.att.slot});
                        return;
                    }
                }
            }

            // Import to fork choice.
            if (node.chain.fork_choice) |fc| {
                fc.onSingleVote(
                    node.allocator,
                    @intCast(queued.att.attester_index),
                    queued.att.slot,
                    queued.att.target_root,
                    queued.att.target_epoch,
                ) catch |err| {
                    std.log.warn("FC onSingleVote failed validator={d}: {}", .{ queued.att.attester_index, err });
                };
            }
        },
        else => {
            // For all other work types, log at debug level.
            // Full handler wiring per work type is progressive — add as needed.
            std.log.debug("Processor: dispatched {s}", .{@tagName(wtype)});
        },
    }
}

// Gossip callbacks are defined in gossip_node_callbacks.zig.
// Req/resp callbacks are defined in reqresp_callbacks.zig.
// The gossip_node module-level global has been removed — BeaconNode pointer
// is now threaded through GossipHandler.node (*anyopaque).

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
