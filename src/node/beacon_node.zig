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

const types = @import("consensus_types");
const preset = @import("preset").preset;
const fork_types = @import("fork_types");
const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;
const BlockStateCache = state_transition.BlockStateCache;
const CheckpointStateCache = state_transition.CheckpointStateCache;
const MemoryCPStateDatastore = state_transition.MemoryCPStateDatastore;
const CheckpointKey = state_transition.CheckpointKey;
const StateRegen = state_transition.StateRegen;
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const db_mod = @import("db");
const BeaconDB = db_mod.BeaconDB;
const MemoryKVStore = db_mod.MemoryKVStore;
const LmdbKVStore = db_mod.LmdbKVStore;
const chain_mod = @import("chain");
const OpPool = chain_mod.OpPool;
const SeenCache = chain_mod.SeenCache;
const produceBlockBody = chain_mod.produceBlockBody;
const ProducedBlockBody = chain_mod.ProducedBlockBody;
const networking = @import("networking");
const ReqRespContext = networking.ReqRespContext;
const ResponseChunk = networking.ResponseChunk;
const Method = networking.Method;
const handleRequest = networking.handleRequest;
const freeResponseChunks = networking.freeResponseChunks;
const StatusMessage = networking.messages.StatusMessage;
const api_mod = @import("api");
const ApiContext = api_mod.context.ApiContext;
const api_types = api_mod.types;

const SlotClock = @import("clock.zig").SlotClock;
const NodeOptions = @import("options.zig").NodeOptions;

const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;

// ---------------------------------------------------------------------------
// HeadTracker — re-implemented here to avoid circular dep on testing module.
// Same logic as testing/head_tracker.zig but standalone.
// ---------------------------------------------------------------------------

pub const HeadTracker = struct {
    head_root: [32]u8,
    head_slot: u64,
    finalized_epoch: u64,
    justified_epoch: u64,
    head_state_root: [32]u8,

    slot_roots: std.AutoArrayHashMap(u64, [32]u8),
    allocator: Allocator,

    pub fn init(allocator: Allocator, genesis_root: [32]u8) HeadTracker {
        return .{
            .head_root = genesis_root,
            .head_slot = 0,
            .finalized_epoch = 0,
            .justified_epoch = 0,
            .head_state_root = [_]u8{0} ** 32,
            .slot_roots = std.AutoArrayHashMap(u64, [32]u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *HeadTracker) void {
        self.slot_roots.deinit();
    }

    pub fn onBlock(self: *HeadTracker, block_root: [32]u8, slot: u64, state_root: [32]u8) !void {
        try self.slot_roots.put(slot, block_root);
        if (slot >= self.head_slot) {
            self.head_root = block_root;
            self.head_slot = slot;
            self.head_state_root = state_root;
        }
    }

    pub fn onEpochTransition(self: *HeadTracker, state: *CachedBeaconState) !void {
        var finalized_cp: types.phase0.Checkpoint.Type = undefined;
        try state.state.finalizedCheckpoint(&finalized_cp);
        self.finalized_epoch = finalized_cp.epoch;

        var justified_cp: types.phase0.Checkpoint.Type = undefined;
        try state.state.currentJustifiedCheckpoint(&justified_cp);
        self.justified_epoch = justified_cp.epoch;
    }

    pub fn getBlockRoot(self: *const HeadTracker, slot: u64) ?[32]u8 {
        return self.slot_roots.get(slot);
    }
};

// ---------------------------------------------------------------------------
// BlockImporter — adapted from testing/block_import.zig for BeaconNode use.
// ---------------------------------------------------------------------------

pub const ImportResult = struct {
    block_root: [32]u8,
    state_root: [32]u8,
    slot: u64,
    epoch_transition: bool,
};

pub const BlockImporter = struct {
    allocator: Allocator,
    block_cache: *BlockStateCache,
    cp_cache: *CheckpointStateCache,
    regen: *StateRegen,
    db: *BeaconDB,
    head_tracker: *HeadTracker,

    /// Maps block root → state root for state lookup in block cache.
    block_to_state: std.AutoArrayHashMap([32]u8, [32]u8),

    pub fn init(
        allocator: Allocator,
        block_cache: *BlockStateCache,
        cp_cache: *CheckpointStateCache,
        regen: *StateRegen,
        db: *BeaconDB,
        head_tracker: *HeadTracker,
    ) BlockImporter {
        return .{
            .allocator = allocator,
            .block_cache = block_cache,
            .cp_cache = cp_cache,
            .regen = regen,
            .db = db,
            .head_tracker = head_tracker,
            .block_to_state = std.AutoArrayHashMap([32]u8, [32]u8).init(allocator),
        };
    }

    pub fn deinit(self: *BlockImporter) void {
        self.block_to_state.deinit();
    }

    pub fn registerGenesisRoot(self: *BlockImporter, block_root: [32]u8, state_root: [32]u8) !void {
        try self.block_to_state.put(block_root, state_root);
    }

    fn getStateByBlockRoot(self: *BlockImporter, block_root: [32]u8) ?*CachedBeaconState {
        const state_root = self.block_to_state.get(block_root) orelse return null;
        return self.block_cache.get(state_root);
    }

    pub fn importBlock(
        self: *BlockImporter,
        signed_block: *const types.electra.SignedBeaconBlock.Type,
    ) !ImportResult {
        const block_slot = signed_block.message.slot;
        const parent_root = signed_block.message.parent_root;

        const prev_epoch = computeEpochAtSlot(if (block_slot > 0) block_slot - 1 else 0);
        const target_epoch = computeEpochAtSlot(block_slot);
        const is_epoch_transition = target_epoch != prev_epoch;

        const pre_state = self.getStateByBlockRoot(parent_root) orelse
            return error.NoPreStateAvailable;

        const stfn_result = try self.runStateTransition(pre_state, signed_block, block_slot);
        const post_state = stfn_result.post_state;

        _ = try self.regen.onNewBlock(post_state, true);

        try self.block_to_state.put(stfn_result.block_root, stfn_result.state_root);

        const any_signed = AnySignedBeaconBlock{ .full_electra = @constCast(signed_block) };
        const block_bytes = try any_signed.serialize(self.allocator);
        defer self.allocator.free(block_bytes);
        try self.db.putBlock(stfn_result.block_root, block_bytes);

        if (is_epoch_transition) {
            const cp_state = try post_state.clone(self.allocator, .{ .transfer_cache = false });
            errdefer {
                cp_state.deinit();
                self.allocator.destroy(cp_state);
            }
            try self.regen.onCheckpoint(
                .{ .epoch = target_epoch, .root = stfn_result.block_root },
                cp_state,
            );
        }

        try self.head_tracker.onBlock(stfn_result.block_root, block_slot, stfn_result.state_root);
        if (is_epoch_transition) {
            try self.head_tracker.onEpochTransition(post_state);
        }

        return .{
            .block_root = stfn_result.block_root,
            .state_root = stfn_result.state_root,
            .slot = block_slot,
            .epoch_transition = is_epoch_transition,
        };
    }

    const StfnResult = struct {
        post_state: *CachedBeaconState,
        state_root: [32]u8,
        block_root: [32]u8,
    };

    fn runStateTransition(
        self: *BlockImporter,
        pre_state: *CachedBeaconState,
        signed_block: *const types.electra.SignedBeaconBlock.Type,
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
                            .{ .verify_signature = false },
                        );
                    },
                }
            },
        }

        try post_state.state.commit();
        const state_root = (try post_state.state.hashTreeRoot()).*;

        const any_block = any_signed.beaconBlock();
        var body_root: [32]u8 = undefined;
        try any_block.beaconBlockBody().hashTreeRoot(self.allocator, &body_root);
        const header = types.phase0.BeaconBlockHeader.Type{
            .slot = block_slot,
            .proposer_index = signed_block.message.proposer_index,
            .parent_root = signed_block.message.parent_root,
            .state_root = state_root,
            .body_root = body_root,
        };
        var block_root: [32]u8 = undefined;
        try types.phase0.BeaconBlockHeader.hashTreeRoot(&header, &block_root);

        return .{
            .post_state = post_state,
            .state_root = state_root,
            .block_root = block_root,
        };
    }
};

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
// HeadInfo
// ---------------------------------------------------------------------------

pub const HeadInfo = struct {
    slot: u64,
    root: [32]u8,
    state_root: [32]u8,
    finalized_epoch: u64,
    justified_epoch: u64,
};

// ---------------------------------------------------------------------------
// BeaconNode
// ---------------------------------------------------------------------------

pub const BeaconNode = struct {
    allocator: Allocator,
    config: *const BeaconConfig,

    // Core components
    db: *BeaconDB,
    state_regen: *StateRegen,
    block_state_cache: *BlockStateCache,
    checkpoint_state_cache: *CheckpointStateCache,
    head_tracker: *HeadTracker,

    // Chain
    op_pool: *OpPool,
    seen_cache: *SeenCache,
    block_importer: *BlockImporter,

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

    // HTTP server for the Beacon REST API (lazy-initialized via startApi).
    http_server: ?api_mod.HttpServer = null,

    pub const KVBackend = union(enum) {
        memory: *MemoryKVStore,
        lmdb: *LmdbKVStore,
    };

    /// Create a new BeaconNode with all components wired together.
    ///
    /// Uses MemoryKVStore for the database backend — production would
    /// swap this for LMDB or similar. All caches, pools, and trackers
    /// are heap-allocated and owned by the node.
    pub fn init(allocator: Allocator, beacon_config: *const BeaconConfig, opts: NodeOptions) !*BeaconNode {
        // KV store → BeaconDB
        // Use LMDB if data_dir is provided; fall back to MemoryKVStore for tests.
        var kv_backend: KVBackend = undefined;
        var kv_iface: db_mod.KVStore = undefined;

        if (opts.data_dir.len > 0) {
            // Build null-terminated path for LMDB.
            // The data directory must already exist.
            const db_path = try std.fs.path.join(allocator, &.{ opts.data_dir, "chain.lmdb" });
            defer allocator.free(db_path);
            const z_path = try allocator.dupeZ(u8, db_path);
            defer allocator.free(z_path);

            const lmdb_store = try allocator.create(LmdbKVStore);
            lmdb_store.* = LmdbKVStore.open(allocator, z_path, .{
                .map_size = 256 * 1024 * 1024 * 1024, // 256 GB
            }) catch |err| {
                allocator.destroy(lmdb_store);
                return err;
            };
            kv_backend = .{ .lmdb = lmdb_store };
            kv_iface = lmdb_store.kvStore();
        } else {
            const mem_store = try allocator.create(MemoryKVStore);
            mem_store.* = MemoryKVStore.init(allocator);
            kv_backend = .{ .memory = mem_store };
            kv_iface = mem_store.kvStore();
        }

        const db = try allocator.create(BeaconDB);
        db.* = BeaconDB.init(allocator, kv_iface);

        // State caches
        const block_cache = try allocator.create(BlockStateCache);
        block_cache.* = BlockStateCache.init(allocator, opts.max_block_states);

        const cp_datastore = try allocator.create(MemoryCPStateDatastore);
        cp_datastore.* = MemoryCPStateDatastore.init(allocator);

        const cp_cache = try allocator.create(CheckpointStateCache);
        cp_cache.* = CheckpointStateCache.init(
            allocator,
            cp_datastore.datastore(),
            block_cache,
            opts.max_checkpoint_epochs,
        );

        // StateRegen
        const regen = try allocator.create(StateRegen);
        regen.* = StateRegen.initWithDB(allocator, block_cache, cp_cache, db);

        // HeadTracker
        const head_tracker = try allocator.create(HeadTracker);
        head_tracker.* = HeadTracker.init(allocator, [_]u8{0} ** 32);

        // Chain components
        const op_pool = try allocator.create(OpPool);
        op_pool.* = OpPool.init(allocator);

        const seen_cache = try allocator.create(SeenCache);
        seen_cache.* = SeenCache.init(allocator);

        // BlockImporter
        const block_importer = try allocator.create(BlockImporter);
        block_importer.* = BlockImporter.init(
            allocator,
            block_cache,
            cp_cache,
            regen,
            db,
            head_tracker,
        );

        // API stubs
        const api_head = try allocator.create(api_mod.context.HeadTracker);
        api_head.* = .{
            .head_slot = 0,
            .head_root = [_]u8{0} ** 32,
            .head_state_root = [_]u8{0} ** 32,
            .finalized_slot = 0,
            .finalized_root = [_]u8{0} ** 32,
            .justified_slot = 0,
            .justified_root = [_]u8{0} ** 32,
        };

        const api_sync = try allocator.create(api_mod.context.SyncStatus);
        api_sync.* = .{
            .head_slot = 0,
            .sync_distance = 0,
            .is_syncing = false,
            .is_optimistic = false,
            .el_offline = false,
        };

        const api_regen = try allocator.create(api_mod.context.StateRegen);
        api_regen.* = .{};

        const api_ctx = try allocator.create(ApiContext);
        api_ctx.* = .{
            .head_tracker = api_head,
            .regen = api_regen,
            .db = db,
            .node_identity = .{
                .peer_id = "BeaconNode-lodestar-z",
                .enr = "",
                .p2p_addresses = &.{},
                .discovery_addresses = &.{},
                .metadata = .{
                    .seq_number = 0,
                    .attnets = [_]u8{0} ** 8,
                    .syncnets = [_]u8{0} ** 1,
                },
            },
            .sync_status = api_sync,
            .beacon_config = beacon_config,
            .allocator = allocator,
        };

        const node = try allocator.create(BeaconNode);
        node.* = .{
            .allocator = allocator,
            .config = beacon_config,
            .db = db,
            .state_regen = regen,
            .block_state_cache = block_cache,
            .checkpoint_state_cache = cp_cache,
            .head_tracker = head_tracker,
            .op_pool = op_pool,
            .seen_cache = seen_cache,
            .block_importer = block_importer,
            .clock = null,
            .cp_datastore = cp_datastore,
            .kv_backend = kv_backend,
            .api_context = api_ctx,
            .api_head_tracker = api_head,
            .api_sync_status = api_sync,
        };

        return node;
    }

    /// Clean up all owned resources.
    pub fn deinit(self: *BeaconNode) void {
        const allocator = self.allocator;

        self.block_importer.deinit();
        allocator.destroy(self.block_importer);

        self.seen_cache.deinit();
        allocator.destroy(self.seen_cache);

        self.op_pool.deinit();
        allocator.destroy(self.op_pool);

        self.head_tracker.deinit();
        allocator.destroy(self.head_tracker);

        // api_regen was allocated but stored in api_context.regen
        allocator.destroy(self.api_context.regen);
        allocator.destroy(self.api_context);
        allocator.destroy(self.api_head_tracker);
        allocator.destroy(self.api_sync_status);

        allocator.destroy(self.state_regen);

        self.checkpoint_state_cache.deinit();
        allocator.destroy(self.checkpoint_state_cache);

        self.block_state_cache.deinit();
        allocator.destroy(self.block_state_cache);

        self.cp_datastore.deinit();
        allocator.destroy(self.cp_datastore);

        self.db.close();
        allocator.destroy(self.db);

        switch (self.kv_backend) {
            .memory => |mem| allocator.destroy(mem),
            .lmdb => |lmdb_store| {
                lmdb_store.deinit();
                allocator.destroy(lmdb_store);
            },
        }

        allocator.destroy(self);
    }

    /// Initialize from a genesis state.
    ///
    /// Loads the genesis state into caches, sets up the head tracker at slot 0,
    /// and configures the clock from the genesis time.
    pub fn initFromGenesis(self: *BeaconNode, genesis_state: *CachedBeaconState) !void {
        const genesis_root = (try genesis_state.state.hashTreeRoot()).*;

        // Cache the genesis state
        const state_root = try self.state_regen.onNewBlock(genesis_state, true);

        // Register genesis root mapping for block importer
        try self.block_importer.registerGenesisRoot(genesis_root, state_root);

        // Set head at slot 0
        try self.head_tracker.onBlock(genesis_root, 0, state_root);

        // Set up clock
        const genesis_time = try genesis_state.state.genesisTime();
        self.clock = SlotClock.fromGenesis(genesis_time, self.config.chain);

        // Update API context
        self.api_head_tracker.head_slot = 0;
        self.api_head_tracker.head_root = genesis_root;
        self.api_head_tracker.head_state_root = state_root;
    }

    /// Import a signed beacon block through the full pipeline.
    ///
    /// Decodes the block, runs STFN, caches the post-state, persists to DB,
    /// and updates the head tracker.
    pub fn importBlock(
        self: *BeaconNode,
        signed_block: *const types.electra.SignedBeaconBlock.Type,
    ) !ImportResult {
        const result = try self.block_importer.importBlock(signed_block);

        // Update API context
        self.api_head_tracker.head_slot = result.slot;
        self.api_head_tracker.head_root = result.block_root;
        self.api_head_tracker.head_state_root = result.state_root;

        if (result.epoch_transition) {
            self.api_head_tracker.finalized_slot = self.head_tracker.finalized_epoch * preset.SLOTS_PER_EPOCH;
            self.api_head_tracker.justified_slot = self.head_tracker.justified_epoch * preset.SLOTS_PER_EPOCH;
        }

        return result;
    }

    /// Start the Beacon REST API HTTP server (blocking).
    ///
    /// Listens on the configured address:port and dispatches requests
    /// to the Beacon API handlers.
    pub fn startApi(self: *BeaconNode, io: std.Io, address: []const u8, port: u16) !void {
        self.http_server = api_mod.HttpServer.init(self.allocator, self.api_context, address, port);
        try self.http_server.?.serve(io);
    }

    /// Get the current head info.
    pub fn getHead(self: *const BeaconNode) HeadInfo {
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
        return .{
            .head_slot = self.head_tracker.head_slot,
            .sync_distance = 0,
            .is_syncing = false,
            .is_optimistic = false,
            .el_offline = false,
        };
    }

    /// Produce a block body from the operation pool.
    ///
    /// Returns pending attestations, slashings, exits, etc. selected for
    /// inclusion. The caller is responsible for constructing the full
    /// SignedBeaconBlock with execution payload, RANDAO, etc.
    pub fn produceBlock(self: *BeaconNode, slot: u64) !ProducedBlockBody {
        return produceBlockBody(self.allocator, slot, self.op_pool);
    }

    /// Build a StatusMessage reflecting the current chain state.
    ///
    /// Used for req/resp Status exchanges with peers.
    pub fn getStatus(self: *const BeaconNode) StatusMessage.Type {
        return .{
            .fork_digest = [_]u8{0} ** 4, // TODO: compute from config + genesis validators root
            .finalized_root = if (self.head_tracker.getBlockRoot(
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
    pub fn onReqResp(
        self: *BeaconNode,
        method: Method,
        request_bytes: []const u8,
    ) ![]const ResponseChunk {
        // Build the ReqRespContext callbacks that close over our node state.
        // For now, use simple function pointers that return stub data.
        // A full implementation would capture `self` via a closure pattern.
        const ctx = ReqRespContext{
            .getStatus = &getStatusStub,
            .getMetadata = &getMetadataStub,
            .getPingSequence = &getPingSequenceStub,
            .getBlockByRoot = &getBlockByRootStub,
            .getBlocksByRange = &getBlocksByRangeStub,
            .getBlobByRoot = &getBlobByRootStub,
            .getBlobsByRange = &getBlobsByRangeStub,
            .getForkDigest = &getForkDigestStub,
            .onGoodbye = &onGoodbyeStub,
            .onPeerStatus = &onPeerStatusStub,
        };
        return handleRequest(self.allocator, method, request_bytes, &ctx);
    }

    // Stub callbacks for ReqRespContext. In a full implementation these
    // would be replaced with proper closures over the node's state.
    fn getStatusStub() StatusMessage.Type {
        return .{
            .fork_digest = [_]u8{0} ** 4,
            .finalized_root = [_]u8{0} ** 32,
            .finalized_epoch = 0,
            .head_root = [_]u8{0} ** 32,
            .head_slot = 0,
        };
    }

    fn getMetadataStub() networking.messages.MetadataV2.Type {
        return .{
            .seq_number = 0,
            .attnets = .{ .data = std.mem.zeroes([8]u8) },
            .syncnets = .{ .data = std.mem.zeroes([1]u8) },
        };
    }

    fn getPingSequenceStub() u64 {
        return 0;
    }

    fn getBlockByRootStub(_: [32]u8) ?[]const u8 {
        return null;
    }

    fn getBlocksByRangeStub(_: u64, _: u64) []const []const u8 {
        return &.{};
    }

    fn getBlobByRootStub(_: [32]u8, _: u64) ?[]const u8 {
        return null;
    }

    fn getBlobsByRangeStub(_: u64, _: u64) []const []const u8 {
        return &.{};
    }

    fn getForkDigestStub(_: u64) [4]u8 {
        return [_]u8{0} ** 4;
    }

    fn onGoodbyeStub(_: u64) void {}

    fn onPeerStatusStub(_: StatusMessage.Type) void {}
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "BeaconNode: init and deinit" {
    const Node = @import("persistent_merkle_tree").Node;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    // Use the config from the test state
    const node = try BeaconNode.init(allocator, test_state.cached_state.config, .{});
    defer node.deinit();

    // All components should be accessible (non-null pointers guaranteed by init)
    const head = node.getHead();
    try std.testing.expectEqual(@as(u64, 0), head.slot);
    try std.testing.expectEqual(@as(u64, 0), head.finalized_epoch);
    try std.testing.expectEqual(@as(usize, 0), node.op_pool.attestation_pool.groupCount());
}

test "BeaconNode: initFromGenesis sets head at slot 0" {
    const Node = @import("persistent_merkle_tree").Node;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    const node = try BeaconNode.init(allocator, test_state.cached_state.config, .{});
    defer node.deinit();

    // Clone the state so the node can own it in the cache
    const genesis_state = try test_state.cached_state.clone(allocator, .{});
    // Set slot to 0 for genesis
    try genesis_state.state.setSlot(0);

    try node.initFromGenesis(genesis_state);

    const head = node.getHead();
    try std.testing.expectEqual(@as(u64, 0), head.slot);
    try std.testing.expectEqual(@as(u64, 0), head.finalized_epoch);
    try std.testing.expectEqual(@as(u64, 0), head.justified_epoch);

    // Clock should be configured
    try std.testing.expect(node.clock != null);
}

test "BeaconNode: getHead returns initial state" {
    const Node = @import("persistent_merkle_tree").Node;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    const node = try BeaconNode.init(allocator, test_state.cached_state.config, .{});
    defer node.deinit();

    const head = node.getHead();
    try std.testing.expectEqual(@as(u64, 0), head.slot);
    try std.testing.expectEqual(@as(u64, 0), head.finalized_epoch);
}

test "BeaconNode: getSyncStatus" {
    const Node = @import("persistent_merkle_tree").Node;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    const node = try BeaconNode.init(allocator, test_state.cached_state.config, .{});
    defer node.deinit();

    const sync = node.getSyncStatus();
    try std.testing.expectEqual(@as(u64, 0), sync.head_slot);
    try std.testing.expect(!sync.is_syncing);
    try std.testing.expect(!sync.el_offline);
}

test "BeaconNode: getStatus returns current chain state" {
    const Node = @import("persistent_merkle_tree").Node;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    const node = try BeaconNode.init(allocator, test_state.cached_state.config, .{});
    defer node.deinit();

    const status = node.getStatus();
    try std.testing.expectEqual(@as(u64, 0), status.head_slot);
    try std.testing.expectEqual(@as(u64, 0), status.finalized_epoch);
}

test "BeaconNode: produceBlock from empty pool" {
    const Node = @import("persistent_merkle_tree").Node;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    const node = try BeaconNode.init(allocator, test_state.cached_state.config, .{});
    defer node.deinit();

    var body = try node.produceBlock(1);
    defer body.deinit(allocator);

    // Empty pool → empty slices
    try std.testing.expectEqual(@as(usize, 0), body.attestations.len);
    try std.testing.expectEqual(@as(usize, 0), body.voluntary_exits.len);
    try std.testing.expectEqual(@as(usize, 0), body.proposer_slashings.len);
    try std.testing.expectEqual(@as(usize, 0), body.attester_slashings.len);
    try std.testing.expectEqual(@as(usize, 0), body.bls_to_execution_changes.len);
}

test "BeaconNode: op pool integration" {
    const Node = @import("persistent_merkle_tree").Node;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    const node = try BeaconNode.init(allocator, test_state.cached_state.config, .{});
    defer node.deinit();

    // Add an exit to the op pool
    const exit = chain_mod.op_pool.makeTestExit(42, 10);
    try node.op_pool.voluntary_exit_pool.add(exit);

    var body = try node.produceBlock(1);
    defer body.deinit(allocator);

    // Should include the exit
    try std.testing.expectEqual(@as(usize, 1), body.voluntary_exits.len);
}

test "BeaconNode: seen cache dedup" {
    const Node = @import("persistent_merkle_tree").Node;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    const node = try BeaconNode.init(allocator, test_state.cached_state.config, .{});
    defer node.deinit();

    const root = [_]u8{0xAB} ** 32;
    try std.testing.expect(!node.seen_cache.hasSeenBlock(root));

    try node.seen_cache.markBlockSeen(root, 5);
    try std.testing.expect(node.seen_cache.hasSeenBlock(root));
}

test "BeaconNode: onReqResp Status" {
    const Node = @import("persistent_merkle_tree").Node;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    const node = try BeaconNode.init(allocator, test_state.cached_state.config, .{});
    defer node.deinit();

    // Encode a Status request
    const status_msg = StatusMessage.Type{
        .fork_digest = [_]u8{0} ** 4,
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .head_root = [_]u8{0} ** 32,
        .head_slot = 0,
    };
    var buf: [StatusMessage.fixed_size]u8 = undefined;
    _ = StatusMessage.serializeIntoBytes(&status_msg, &buf);

    const chunks = try node.onReqResp(.status, &buf);
    defer freeResponseChunks(allocator, chunks);

    // Should get exactly one response chunk with success code
    try std.testing.expectEqual(@as(usize, 1), chunks.len);
    try std.testing.expectEqual(networking.protocol.ResponseCode.success, chunks[0].result);
}

test "HeadTracker: basic tracking" {
    var tracker = HeadTracker.init(std.testing.allocator, [_]u8{0x00} ** 32);
    defer tracker.deinit();

    try std.testing.expectEqual(@as(u64, 0), tracker.head_slot);

    const root_1 = [_]u8{0x01} ** 32;
    try tracker.onBlock(root_1, 1, [_]u8{0x11} ** 32);
    try std.testing.expectEqual(@as(u64, 1), tracker.head_slot);
    try std.testing.expectEqualSlices(u8, &root_1, &tracker.head_root);

    const root_3 = [_]u8{0x03} ** 32;
    try tracker.onBlock(root_3, 3, [_]u8{0x33} ** 32);
    try std.testing.expectEqual(@as(u64, 3), tracker.head_slot);
    try std.testing.expectEqualSlices(u8, &root_3, &tracker.head_root);
}
