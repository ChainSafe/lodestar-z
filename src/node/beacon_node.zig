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
const chain_mod = @import("chain");
const Chain = chain_mod.Chain;
const ChainRuntime = chain_mod.Runtime;
const ChainService = chain_mod.Service;
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

const execution_mod = @import("execution");
const EngineApi = execution_mod.EngineApi;
const MockEngine = execution_mod.MockEngine;
const HttpEngine = execution_mod.HttpEngine;
const IoHttpTransport = execution_mod.IoHttpTransport;
const PayloadAttributesV3 = execution_mod.engine_api_types.PayloadAttributesV3;
const GetPayloadResponse = execution_mod.GetPayloadResponse;
const BuilderApi = execution_mod.BuilderApi;
const HttpBuilder = execution_mod.HttpBuilder;
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

    // Last slot for which chain.onSlot() was applied.
    last_slot_tick: ?u64 = null,

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
    http_builder: ?*HttpBuilder = null,
    builder_transport: ?*IoHttpTransport = null,

    /// Cached payload ID from the last forkchoiceUpdated call with payload attributes.
    /// Used by produceBlockWithPayload to retrieve the built execution payload via getPayload.
    cached_payload_id: ?[8]u8 = null,
    cached_payload_slot: ?u64 = null,
    cached_payload_parent_root: ?[32]u8 = null,
    last_builder_status_slot: ?u64 = null,

    /// Optional MEV-boost builder relay client.
    /// When configured, block production attempts to use the builder for higher rewards.
    /// Falls back to local execution engine if builder is unavailable or bid too low.
    builder_api: ?BuilderApi = null,

    /// Track whether the EL is offline (unreachable). Reset on successful Engine API call.
    el_offline: bool = false,

    /// Process-local guard against publishing conflicting blocks for the same
    /// proposer/slot through the BN API.
    published_proposals_mu: std.atomic.Mutex = .unlocked,
    published_proposals: std.AutoHashMap(PublishedProposalKey, [32]u8),

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
        if (self.http_server) |*srv| srv.shutdown(self.io);
    }

    /// Create a new BeaconNode with all components wired together.
    ///
    /// Uses MemoryKVStore for the database backend — production would
    /// swap this for LMDB or similar. The hot chain graph is heap-allocated
    /// and owned by `chain.Runtime`, with BeaconNode holding aliases into it.
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
        const outcome = try self.chainService().importBlock(any_signed, source);
        return self.finishImportOutcome(t0, outcome);
    }

    pub fn importRawBlockBytes(
        self: *BeaconNode,
        block_bytes: []const u8,
        source: BlockSource,
    ) !ImportResult {
        const t0 = std.Io.Clock.awake.now(self.io);
        const outcome = try self.chainService().importRawBlockBytes(block_bytes, source);
        return self.finishImportOutcome(t0, outcome);
    }

    pub fn importReadyBlock(
        self: *BeaconNode,
        ready: chain_mod.ReadyBlockInput,
    ) !ImportResult {
        const t0 = std.Io.Clock.awake.now(self.io);
        const outcome = try self.chainService().importReadyBlock(ready);
        return self.finishImportOutcome(t0, outcome);
    }

    pub fn completeReadyIngress(
        self: *BeaconNode,
        ready: chain_mod.ReadyBlockInput,
        raw_block_bytes: ?[]const u8,
    ) !?ImportResult {
        var owned_ready = ready;

        const result = self.importReadyBlock(owned_ready) catch |err| {
            switch (err) {
                error.UnknownParentBlock => {
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
                    return null;
                },
                error.BlockAlreadyKnown, error.BlockAlreadyFinalized => {
                    owned_ready.deinit(self.allocator);
                    return null;
                },
                else => {
                    owned_ready.deinit(self.allocator);
                    return err;
                },
            }
        };

        owned_ready.deinit(self.allocator);
        self.processPendingChildren(result.block_root);
        return result;
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

    fn finishImportOutcome(
        self: *BeaconNode,
        t0: std.Io.Timestamp,
        outcome: chain_mod.ImportOutcome,
    ) !ImportResult {
        const result = outcome.result;

        // Notify EL of fork choice update after each block import.
        self.notifyForkchoiceUpdate(outcome.effects.notify_forkchoice_update_root) catch |err| {
            log.logger(.node).warn("forkchoiceUpdated failed: {}", .{err});
        };

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
            // Archive the post-epoch state for cold-path recovery.
            // Errors are non-fatal — the block is already imported.
            if (outcome.effects.archive_state) |archive_state| {
                self.chainService().archiveState(archive_state.slot, archive_state.state_root) catch {};
            }
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
        defer if (outcome.effects.archive_states.len > 0) self.allocator.free(outcome.effects.archive_states);

        self.notifyForkchoiceUpdate(outcome.effects.notify_forkchoice_update_root) catch |err| {
            log.logger(.node).warn("forkchoiceUpdated failed after range sync segment: {}", .{err});
        };

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

        for (outcome.effects.archive_states) |archive_state| {
            self.chainService().archiveState(archive_state.slot, archive_state.state_root) catch {};
        }
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

    /// Archive the post-epoch state to the cold store.
    ///
    /// Called at epoch boundaries so that the cold path in StateRegen can
    /// find a nearby anchor state and replay blocks forward from it.
    ///
    /// Serializes the CachedBeaconState's inner AnyBeaconState to SSZ bytes
    /// and stores it via `BeaconDB.putStateArchive(slot, state_root, bytes)`.
    pub fn archiveState(self: *BeaconNode, slot: u64, state_root: [32]u8) !void {
        try self.chainService().archiveState(slot, state_root);
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
        return .{
            .head_slot = self.currentHeadSlot(),
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
        self.last_slot_tick = null;
        self.clock = SlotClock.fromGenesis(outcome.genesis_time, self.config.chain);
        self.api_context.genesis_time = outcome.genesis_time;
        _ = outcome.snapshot;
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
            // Batch BLS verification: the key performance optimization.
            //
            // Architecture (matches TS Lodestar's gossipQueues/indexed.ts):
            // 1. Collect N attestation signature sets
            // 2. Batch-verify all N signatures at once (~3-10x faster than individual)
            // 3. On batch success: import all attestations to fork choice + pool
            // 4. On batch failure: fall back to individual verification to find bad one(s)
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
                        if (!verifyFn(gh.node, &att_work.attestation)) {
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
                var attestation = att_work.attestation;
                defer attestation.deinit(node.allocator);

                if (!batch_valid) {
                    // Batch failed — verify individually to find the bad one(s).
                    if (node.gossip_handler) |gh| {
                        if (gh.verifyAttestationSignatureFn) |verifyFn| {
                            if (!verifyFn(gh.node, &attestation)) {
                                std.log.warn("Attestation BLS failed in batch fallback slot={d}", .{attestation.slot()});
                                continue; // Skip this invalid attestation.
                            }
                        }
                    }
                }

                const gh = node.gossip_handler orelse continue;
                const importFn = gh.importAttestationFn orelse continue;

                importFn(gh.node, &attestation) catch |err| {
                    std.log.warn("Processor: attestation import failed for slot {d}: {}", .{
                        attestation.slot(), err,
                    });
                };
            }
        },
        .aggregate_batch => |batch| {
            // Batch BLS verification for aggregates.
            // Same pattern as attestation batching.
            std.log.debug("Processor: aggregate batch (count={d})", .{batch.count});

            var i: u32 = 0;
            while (i < batch.count) : (i += 1) {
                const agg_work = batch.items[i];
                handleQueuedAggregate(node, agg_work);
            }
        },
        .aggregate => |work| {
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
                    if (!verifyFn(gh.node, &attestation)) {
                        std.log.warn("Single attestation BLS failed slot={d}", .{attestation.slot()});
                        return;
                    }
                }
                const importFn = gh.importAttestationFn orelse return;
                importFn(gh.node, &attestation) catch |err| {
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
        var aggregate = work.aggregate;
        aggregate.deinit(node.allocator);
        return;
    };
    const importFn = gh.importAggregateFn orelse {
        var aggregate = work.aggregate;
        aggregate.deinit(node.allocator);
        return;
    };

    var aggregate = work.aggregate;
    defer aggregate.deinit(node.allocator);

    importFn(gh.node, &aggregate) catch |err| {
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
// The gossip_node module-level global has been removed — BeaconNode pointer
// is now threaded through GossipHandler.node (*anyopaque).

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const ProcessorImportTestContext = struct {
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

    fn importAggregate(ptr: *anyopaque, aggregate: *const fork_types.AnySignedAggregateAndProof) anyerror!void {
        const ctx: *ProcessorImportTestContext = @ptrCast(@alignCast(ptr));
        ctx.aggregate_aggregator_index = aggregate.aggregatorIndex();
        const attestation = aggregate.attestation();
        const data = attestation.data();
        ctx.aggregate_slot = data.slot;
        ctx.aggregate_target_epoch = data.target.epoch;
    }

    fn importAttestation(ptr: *anyopaque, attestation: *const fork_types.AnyGossipAttestation) anyerror!void {
        const ctx: *ProcessorImportTestContext = @ptrCast(@alignCast(ptr));
        const data = attestation.data();
        ctx.attestation_slot = data.slot;
        ctx.attestation_committee_index = attestation.committeeIndex();
        ctx.attestation_is_electra_single = switch (attestation.*) {
            .electra_single => true,
            .phase0 => false,
        };
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
    gh.importAggregateFn = &ProcessorImportTestContext.importAggregate;
    node.gossip_handler = &gh;

    var signed_agg = types.phase0.SignedAggregateAndProof.default_value;
    signed_agg.message.aggregator_index = 21;
    signed_agg.message.aggregate.data.slot = 123;
    signed_agg.message.aggregate.data.target.epoch = 4;

    processorHandlerCallback(.{ .aggregate = .{
        .source = .{ .key = 1 },
        .message_id = std.mem.zeroes(processor_mod.work_item.MessageId),
        .aggregate = .{ .phase0 = signed_agg },
        .seen_timestamp_ns = 0,
    } }, @ptrCast(&node));

    try std.testing.expectEqual(@as(?u64, 21), ctx.aggregate_aggregator_index);
    try std.testing.expectEqual(@as(?u64, 123), ctx.aggregate_slot);
    try std.testing.expectEqual(@as(?u64, 4), ctx.aggregate_target_epoch);
}

test "processorHandlerCallback imports queued attestations" {
    const allocator = std.testing.allocator;

    var ctx = ProcessorImportTestContext{};
    var node: BeaconNode = undefined;
    node.allocator = allocator;

    var gh: GossipHandler = undefined;
    gh.node = @ptrCast(&ctx);
    gh.importAttestationFn = &ProcessorImportTestContext.importAttestation;
    gh.verifyAttestationSignatureFn = null;
    node.gossip_handler = &gh;

    var attestation = types.electra.SingleAttestation.default_value;
    attestation.committee_index = 7;
    attestation.attester_index = 19;
    attestation.data.slot = 222;

    processorHandlerCallback(.{ .attestation = .{
        .source = .{ .key = 1 },
        .message_id = std.mem.zeroes(processor_mod.work_item.MessageId),
        .attestation = .{ .electra_single = attestation },
        .subnet_id = 0,
        .seen_timestamp_ns = 0,
    } }, @ptrCast(&node));

    try std.testing.expectEqual(@as(?u64, 222), ctx.attestation_slot);
    try std.testing.expectEqual(@as(?u64, 7), ctx.attestation_committee_index);
    try std.testing.expect(ctx.attestation_is_electra_single);
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
