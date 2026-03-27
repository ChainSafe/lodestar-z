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
const BatchVerifier = @import("bls").BatchVerifier;
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
const Chain = chain_mod.Chain;
const OpPool = chain_mod.OpPool;
const SeenCache = chain_mod.SeenCache;
const produceBlockBody = chain_mod.produceBlockBody;
const ProducedBlockBody = chain_mod.ProducedBlockBody;
pub const HeadTracker = chain_mod.HeadTracker;
pub const ImportResult = chain_mod.ImportResult;
const ImportError = chain_mod.ImportError;
const networking = @import("networking");
const DiscoveryService = networking.DiscoveryService;
const DiscoveryConfig = networking.DiscoveryConfig;
const ConnectionManager = networking.ConnectionManager;
const ConnectionManagerConfig = networking.ConnectionManagerConfig;
const eth2_protocols = networking.eth2_protocols;
const discv5 = @import("discv5");
const ssl = @import("ssl");
const ReqRespContext = networking.ReqRespContext;
const ResponseChunk = networking.ResponseChunk;
const Method = networking.Method;
const handleRequest = networking.handleRequest;
const freeResponseChunks = networking.freeResponseChunks;
const StatusMessage = networking.messages.StatusMessage;
const P2pService = networking.p2p_service.P2pService;
const P2pConfig = networking.p2p_service.P2pConfig;
const PassthroughValidator = networking.p2p_service.PassthroughValidator;
const Multiaddr = @import("multiaddr").Multiaddr;
const api_mod = @import("api");
const ApiContext = api_mod.context.ApiContext;
const api_types = api_mod.types;

const SlotClock = @import("clock.zig").SlotClock;
const SyncController = @import("sync_controller.zig").SyncController;
const NodeOptions = @import("options.zig").NodeOptions;
const identity_mod = @import("identity.zig");
const NodeIdentity = identity_mod.NodeIdentity;
const sync_mod = @import("sync");
const UnknownBlockSync = sync_mod.UnknownBlockSync;
const SyncService = sync_mod.SyncService;
const SyncMode = sync_mod.SyncMode;
const PeerManager = sync_mod.PeerManager;
const BatchRequestCallback = sync_mod.BatchRequestCallback;
const BlockImporterCallback = sync_mod.BlockImporterCallback;
const BatchBlock = sync_mod.BatchBlock;

const fork_choice_mod = @import("fork_choice");
const ForkChoice = fork_choice_mod.ForkChoiceStruct;
const ForkChoiceInit = fork_choice_mod.fork_choice.InitOpts;
const ProtoBlock = fork_choice_mod.ProtoBlock;
const BlockExtraMeta = fork_choice_mod.BlockExtraMeta;
const ForkChoiceCheckpoint = fork_choice_mod.Checkpoint;

const execution_mod = @import("execution");
const EngineApi = execution_mod.EngineApi;
const ExecutionPayloadStatus = execution_mod.ExecutionPayloadStatus;
const ForkchoiceStateV1 = execution_mod.ForkchoiceStateV1;
const MockEngine = execution_mod.MockEngine;
const HttpEngine = execution_mod.HttpEngine;
const IoHttpTransport = execution_mod.IoHttpTransport;
const PayloadAttributesV3 = execution_mod.engine_api_types.PayloadAttributesV3;
const GetPayloadResponse = execution_mod.GetPayloadResponse;
const constants = @import("constants");
const Sha256 = std.crypto.hash.sha2.Sha256;

const metrics_mod = @import("metrics.zig");
pub const BeaconMetrics = metrics_mod.BeaconMetrics;

const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const gossip_handler_mod = @import("gossip_handler.zig");
pub const GossipHandler = gossip_handler_mod.GossipHandler;

// HeadTracker, ImportResult, ImportError are in chain_mod (src/chain/block_import.zig).
// BlockImporter lives here because it depends on db, fork_choice, and state_transition
// directly — extracting it would require either circular deps or vtable indirection.

pub const BlockImporter = struct {
    allocator: Allocator,
    block_cache: *BlockStateCache,
    cp_cache: *CheckpointStateCache,
    regen: *StateRegen,
    db: *BeaconDB,
    head_tracker: *HeadTracker,
    fork_choice: ?*ForkChoice,

    /// Engine API client for EL communication.
    /// When null, execution payload verification is skipped (pre-merge).
    engine_api: ?EngineApi = null,

    /// Data availability check callback (PeerDAS / Fulu).
    /// Returns true if sufficient data columns are available for the block root.
    /// When null, data is assumed available (pre-fulu behavior).
    isDataAvailableFn: ?*const fn (root: [32]u8) bool = null,

    /// When true, BLS signatures are verified in processBlock.
    verify_signatures: bool,

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
            .fork_choice = null,
            .verify_signatures = false,
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

    /// Full block import pipeline: sanity → STFN → fork choice → persist → head.
    ///
    /// Returns `error.UnknownParentBlock` when the parent root is not in
    /// the chain — callers should catch this to trigger unknown block sync.
    /// Returns `error.BlockAlreadyKnown` / `error.BlockAlreadyFinalized` /
    /// `error.GenesisBlock` for other sanity failures.
    pub fn importBlock(
        self: *BlockImporter,
        signed_block: *const types.electra.SignedBeaconBlock.Type,
    ) !ImportResult {
        const block_slot = signed_block.message.slot;
        const parent_root = signed_block.message.parent_root;

        const prev_epoch = computeEpochAtSlot(if (block_slot > 0) block_slot - 1 else 0);
        const target_epoch = computeEpochAtSlot(block_slot);
        const is_epoch_transition = target_epoch != prev_epoch;

        // Compute block root for sanity checks and persistence.
        var body_root: [32]u8 = undefined;
        try types.electra.BeaconBlockBody.hashTreeRoot(self.allocator, &signed_block.message.body, &body_root);
        const header = types.phase0.BeaconBlockHeader.Type{
            .slot = block_slot,
            .proposer_index = signed_block.message.proposer_index,
            .parent_root = parent_root,
            .state_root = signed_block.message.state_root,
            .body_root = body_root,
        };
        var block_root: [32]u8 = undefined;
        try types.phase0.BeaconBlockHeader.hashTreeRoot(&header, &block_root);

        // Stage 1: Sanity checks (cheap, before any state transition work).
        chain_mod.block_import.verifySanity(
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
        const pre_state = self.getStateByBlockRoot(parent_root) orelse {
            std.log.warn("NoPreStateAvailable: parent_root={s}... block_to_state has {d} entries", .{
                &std.fmt.bytesToHex(parent_root[0..4], .lower),
                self.block_to_state.count(),
            });
            return error.NoPreStateAvailable;
        };

        const stfn_result = try self.runStateTransition(pre_state, signed_block, block_slot);
        const post_state = stfn_result.post_state;

        // Stage 2b: Verify execution payload via Engine API.
        const execution_status = try self.verifyExecutionPayload(signed_block, stfn_result.block_root);
        if (execution_status == .invalid or execution_status == .invalid_block_hash) {
            std.log.err("Block at slot {d} has INVALID execution payload, rejecting", .{block_slot});
            return error.InvalidExecutionPayload;
        }

        // Stage 3: Cache post-state + persist block.
        _ = try self.regen.onNewBlock(post_state, true);
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
            try self.regen.onCheckpoint(
                .{ .epoch = target_epoch, .root = stfn_result.block_root },
                cp_state,
            );
        }

        // Stage 4: Head tracking + fork choice update.
        try self.head_tracker.onBlock(stfn_result.block_root, block_slot, stfn_result.state_root);
        if (is_epoch_transition) {
            try self.head_tracker.onEpochTransition(post_state);
        }

        // Wire block into fork choice DAG.
        var justified_cp: types.phase0.Checkpoint.Type = undefined;
        try post_state.state.currentJustifiedCheckpoint(&justified_cp);
        var finalized_cp: types.phase0.Checkpoint.Type = undefined;
        try post_state.state.finalizedCheckpoint(&finalized_cp);

        // Build execution metadata for fork choice.
        const extra_meta: BlockExtraMeta = switch (execution_status) {
            .valid, .syncing, .accepted => .{
                .post_merge = BlockExtraMeta.PostMergeMeta.init(
                    signed_block.message.body.execution_payload.block_hash,
                    signed_block.message.body.execution_payload.block_number,
                    switch (execution_status) {
                        .valid => .valid,
                        .syncing, .accepted => .syncing,
                        else => unreachable,
                    },
                    if (self.isDataAvailableFn) |check_da|
                        (if (check_da(stfn_result.block_root)) .available else .pre_data)
                    else
                        .available,
                ),
            },
            else => .{ .pre_merge = {} },
        };

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
            .extra_meta = extra_meta,
            .timeliness = true,
        };

        if (self.fork_choice) |fc| fc.onBlock(self.allocator, fc_block, block_slot) catch |err| switch (err) {
            error.InvalidBlock => {},
            else => return err,
        };

        return .{
            .block_root = stfn_result.block_root,
            .state_root = stfn_result.state_root,
            .slot = block_slot,
            .epoch_transition = is_epoch_transition,
            .execution_optimistic = execution_status == .syncing or execution_status == .accepted,
        };
    }

    /// Verify the block's execution payload via the Engine API.
    ///
    /// Calls engine_newPayloadV3 with the execution payload from the block.
    /// Returns the EL's verdict: valid, invalid, syncing, etc.
    /// When no Engine API is configured, returns .valid (mock/pre-merge).
    fn verifyExecutionPayload(
        self: *BlockImporter,
        signed_block: *const types.electra.SignedBeaconBlock.Type,
        block_root: [32]u8,
    ) !ExecutionPayloadStatus {
        const engine = self.engine_api orelse return .valid;

        const payload = &signed_block.message.body.execution_payload;

        // Convert transactions: ArrayListUnmanaged(ArrayListUnmanaged(u8)) -> []const []const u8.
        // Each SSZ transaction is an ArrayListUnmanaged(u8); the Engine API needs []const u8 slices.
        const ssz_txs = payload.transactions.items;
        const tx_slices = try self.allocator.alloc([]const u8, ssz_txs.len);
        defer self.allocator.free(tx_slices);
        for (ssz_txs, 0..) |tx, i| {
            tx_slices[i] = tx.items;
        }

        // Compute versioned hashes from blob_kzg_commitments.
        // Each versioned hash = SHA256(commitment) with byte 0 set to VERSIONED_HASH_VERSION_KZG.
        const commitments = signed_block.message.body.blob_kzg_commitments.items;
        const versioned_hashes = try self.allocator.alloc([32]u8, commitments.len);
        defer self.allocator.free(versioned_hashes);
        for (commitments, 0..) |commitment, i| {
            Sha256.hash(&commitment, &versioned_hashes[i], .{});
            versioned_hashes[i][0] = constants.VERSIONED_HASH_VERSION_KZG;
        }

        // Build the Engine API payload from the SSZ block body payload.
        const engine_payload = execution_mod.ExecutionPayloadV3{
            .parent_hash = payload.parent_hash,
            .fee_recipient = payload.fee_recipient,
            .state_root = payload.state_root,
            .receipts_root = payload.receipts_root,
            .logs_bloom = payload.logs_bloom,
            .prev_randao = payload.prev_randao,
            .block_number = payload.block_number,
            .gas_limit = payload.gas_limit,
            .gas_used = payload.gas_used,
            .timestamp = payload.timestamp,
            .extra_data = payload.extra_data.items,
            .base_fee_per_gas = payload.base_fee_per_gas,
            .block_hash = payload.block_hash,
            .transactions = tx_slices,
            // Withdrawals: same memory layout as engine_api_types.Withdrawal.
            .withdrawals = if (payload.withdrawals.items.len > 0)
                @as([]const execution_mod.engine_api_types.Withdrawal, @ptrCast(payload.withdrawals.items))
            else
                &.{},
            .blob_gas_used = payload.blob_gas_used,
            .excess_blob_gas = payload.excess_blob_gas,
        };

        const parent_beacon_root = signed_block.message.parent_root;

        const result = engine.newPayload(engine_payload, versioned_hashes, parent_beacon_root) catch |err| {
            std.log.warn("Engine API newPayload failed for root={s}...: {}", .{
                &std.fmt.bytesToHex(block_root[0..4], .lower), err,
            });
            // On EL communication failure, accept optimistically and track EL offline.
            return .syncing;
        };

        std.log.info("Engine API newPayload slot {d}: status={s}", .{
            signed_block.message.slot, @tagName(result.status),
        });

        return result.status;
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

        // Log state root comparison.
        if (!std.mem.eql(u8, &state_root, &signed_block.message.state_root)) {
            std.log.warn("STFN state_root mismatch at slot {d}: ours={s}... block={s}...", .{
                block_slot,
                &std.fmt.bytesToHex(state_root[0..8], .lower),
                &std.fmt.bytesToHex(signed_block.message.state_root[0..8], .lower),
            });
        } else {
            std.log.info("STFN state_root MATCHES at slot {d}", .{block_slot});
        }

        // Compute block root from header.
        var br_body_root: [32]u8 = undefined;
        try types.electra.BeaconBlockBody.hashTreeRoot(self.allocator, &signed_block.message.body, &br_body_root);
        const hdr = types.phase0.BeaconBlockHeader.Type{
            .slot = block_slot,
            .proposer_index = signed_block.message.proposer_index,
            .parent_root = signed_block.message.parent_root,
            .state_root = signed_block.message.state_root,
            .body_root = br_body_root,
        };
        var computed_block_root: [32]u8 = undefined;
        try types.phase0.BeaconBlockHeader.hashTreeRoot(&hdr, &computed_block_root);

        return .{
            .post_state = post_state,
            .state_root = state_root,
            .block_root = computed_block_root,
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


/// Load a JWT secret from a hex-encoded file.
///
/// The file must contain a 0x-prefixed (or bare) hex string of exactly
/// 32 bytes (64 hex chars). Whitespace and newlines are stripped.
/// This matches the format used by Geth, Nethermind, Besu, etc.
/// Load a JWT secret from a hex-encoded file using std.Io.
///
/// The file must contain a 0x-prefixed (or bare) hex string of exactly
/// 32 bytes (64 hex chars). Whitespace and newlines are stripped.
/// This matches the format used by Geth, Nethermind, Besu, etc.
fn loadJwtSecret(_: Allocator, io: std.Io, file_path: []const u8) ![32]u8 {
    const file = std.Io.Dir.cwd().openFile(io, file_path, .{}) catch
        return error.JwtFileNotFound;
    defer file.close(io);

    const stat = file.stat(io) catch return error.JwtFileReadError;
    if (stat.size > 1024) return error.JwtFileReadError;

    var buf: [1024]u8 = undefined;
    const total = file.readPositionalAll(io, buf[0..@intCast(stat.size)], 0) catch
        return error.JwtFileReadError;
    const file_content = buf[0..total];

    // Strip whitespace and newlines.
    const trimmed = std.mem.trim(u8, file_content, " \t\n\r");

    // Strip optional "0x" prefix.
    const hex_str = if (trimmed.len >= 2 and trimmed[0] == '0' and trimmed[1] == 'x')
        trimmed[2..]
    else
        trimmed;

    if (hex_str.len != 64) return error.InvalidJwtSecretLength;

    var secret: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&secret, hex_str) catch return error.InvalidJwtSecretHex;
    return secret;
}

// ---------------------------------------------------------------------------
// SyncCallbackCtx — bridges sync pipeline callbacks to the P2P transport.
//
// The sync state machine (RangeSyncManager) fires callbacks synchronously,
// but P2P operations require cooperative I/O. This context queues batch
// requests for the main loop to drain via actual network calls.
// ---------------------------------------------------------------------------

pub const PendingBatchRequest = struct {
    batch_id: u32,
    start_slot: u64,
    count: u64,
    peer_id_buf: [128]u8,
    peer_id_len: u8,

    pub fn peerId(self: *const PendingBatchRequest) []const u8 {
        return self.peer_id_buf[0..self.peer_id_len];
    }
};

pub const SyncCallbackCtx = struct {
    node: *BeaconNode,

    /// Pending batch requests queued by the sync state machine.
    /// Drained by processSyncBatches() in the main loop.
    pending_requests: [32]PendingBatchRequest = undefined,
    pending_count: u8 = 0,

    /// Create a BlockImporterCallback that imports blocks through the node.
    pub fn importerCallback(self: *SyncCallbackCtx) BlockImporterCallback {
        return .{
            .ptr = @ptrCast(self),
            .importFn = &syncImportBlock,
        };
    }

    /// Create a BatchRequestCallback that queues requests for later P2P dispatch.
    pub fn requesterCallback(self: *SyncCallbackCtx) BatchRequestCallback {
        return .{
            .ptr = @ptrCast(self),
            .requestFn = &syncRequestBatch,
        };
    }

    fn syncImportBlock(ptr: *anyopaque, block_bytes: []const u8) anyerror!void {
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        const node = ctx.node;
        const allocator = node.allocator;

        // Determine the active fork for deserialization.
        const raw_fork_seq = node.config.forkSeq(node.head_tracker.head_slot);
        const fork_seq = if (@intFromEnum(raw_fork_seq) > @intFromEnum(config_mod.ForkSeq.electra))
            config_mod.ForkSeq.electra
        else
            raw_fork_seq;

        const any_signed = AnySignedBeaconBlock.deserialize(
            allocator, .full, fork_seq, block_bytes,
        ) catch |err| {
            std.log.warn("SyncCallbackCtx: block deserialize error: {}", .{err});
            return err;
        };
        defer any_signed.deinit(allocator);

        switch (any_signed) {
            .full_electra => |blk| {
                const result = node.importBlock(blk) catch |err| {
                    if (err != error.BlockAlreadyKnown and err != error.BlockAlreadyFinalized) {
                        std.log.warn("SyncCallbackCtx: import error: {}", .{err});
                    }
                    return err;
                };
                std.log.info("SyncCallbackCtx: imported slot={d}", .{result.slot});
            },
            else => {
                std.log.warn("SyncCallbackCtx: unsupported block fork", .{});
                return error.UnsupportedFork;
            },
        }
    }

    fn syncRequestBatch(
        ptr: *anyopaque,
        batch_id: u32,
        start_slot: u64,
        count: u64,
        peer_id: []const u8,
    ) void {
        const ctx: *SyncCallbackCtx = @ptrCast(@alignCast(ptr));
        if (ctx.pending_count >= 32) {
            std.log.warn("SyncCallbackCtx: pending request queue full, dropping batch {d}", .{batch_id});
            return;
        }
        var req = PendingBatchRequest{
            .batch_id = batch_id,
            .start_slot = start_slot,
            .count = count,
            .peer_id_buf = undefined,
            .peer_id_len = @intCast(@min(peer_id.len, 128)),
        };
        @memcpy(req.peer_id_buf[0..req.peer_id_len], peer_id[0..req.peer_id_len]);
        ctx.pending_requests[ctx.pending_count] = req;
        ctx.pending_count += 1;
        std.log.debug("SyncCallbackCtx: queued batch {d} slots {d}..{d} for peer {s}", .{
            batch_id, start_slot, start_slot + count - 1, peer_id,
        });
    }
};

pub const BeaconNode = struct {
    allocator: Allocator,
    config: *const BeaconConfig,

    // Core components
    db: *BeaconDB,
    state_regen: *StateRegen,
    block_state_cache: *BlockStateCache,
    checkpoint_state_cache: *CheckpointStateCache,
    head_tracker: *HeadTracker,
    fork_choice: ?*ForkChoice,

    // Chain coordinator (delegates to all chain components)
    chain: *Chain,

    // Chain components (owned by BeaconNode, pointers held by chain)
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
    block_import_ctx: *BlockImportCallbackCtx,
    head_state_cb_ctx: *HeadStateCallbackCtx,

    // Prometheus metrics (real or noop depending on --metrics flag).
    // Optional pointer so BeaconNode doesn't own the metrics instance —
    // it's allocated by main() and passed in.
    metrics: ?*BeaconMetrics = null,

    // HTTP server for the Beacon REST API (lazy-initialized via startApi).
    http_server: ?api_mod.HttpServer = null,

    // Discovery service (lazy-initialized via startP2p).
    discovery_service: ?*DiscoveryService = null,

    // Connection manager — tracks peer connections and enforces limits.
    connection_manager: ?*ConnectionManager = null,

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
    p2p_request_ctx: ?*RequestContext = null,

    // Sync controller — wires P2P events into the sync pipeline.
    // Optional: nil until initialized (e.g. when running without P2P).
    sync_controller: ?*SyncController = null,

    // Sync subsystem components (lazily initialized when P2P starts).
    sync_peer_manager: ?*PeerManager = null,
    sync_service_inst: ?*SyncService = null,
    sync_callback_ctx: ?*SyncCallbackCtx = null,

    // GossipHandler — lazily initialized when P2P starts (owns its SeenSets).
    gossip_handler: ?*GossipHandler = null,

    // Unknown block sync — queues blocks whose parent is not yet known.
    // Initialized eagerly in init(); used by the gossip block import path.
    unknown_block_sync: UnknownBlockSync,

    // Execution Layer engine (Engine API client or mock).
    mock_engine: ?*MockEngine = null,
    http_engine: ?*HttpEngine = null,
    io_transport: ?*IoHttpTransport = null,
    engine_api: ?EngineApi = null,

    /// Cached payload ID from the last forkchoiceUpdated call with payload attributes.
    /// Used by produceBlockWithPayload to retrieve the built execution payload via getPayload.
    cached_payload_id: ?[8]u8 = null,

    /// Track whether the EL is offline (unreachable). Reset on successful Engine API call.
    el_offline: bool = false,

    /// I/O context — set when the event loop starts (before services launch).
    /// Required for std.http.Client, timing, and other I/O operations.
    io: ?std.Io = null,

    /// JWT secret file path — loaded lazily in setIo() when Io becomes available.
    jwt_secret_path: ?[]const u8 = null,

    // Data directory path — needed for identity persistence and other disk ops.
    data_dir: []const u8 = "",

    // Node identity — secp256k1 keypair loaded/generated in setIo().
    node_identity: ?NodeIdentity = null,

    // Genesis validators root — set by initFromGenesis, used for fork digest computation.
    genesis_validators_root: [32]u8 = [_]u8{0} ** 32,


    // Node configuration options — stored for lazy-initialized components.
    node_options: NodeOptions = .{},

    // Bootnode ENRs — provided via --bootnodes CLI flag, used to dial initial peers.
    bootnodes: []const []const u8 = &.{},

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
        regen.* = StateRegen.initWithDB(allocator, block_cache, cp_cache, db, null, null);

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
        block_importer.verify_signatures = opts.verify_signatures;

        // Chain coordinator — wraps all chain components behind a single interface.
        const chain_struct = try allocator.create(Chain);
        chain_struct.* = Chain.init(
            allocator,
            beacon_config,
            block_cache,
            cp_cache,
            regen,
            db,
            op_pool,
            seen_cache,
            head_tracker,
        );
        chain_struct.verify_signatures = opts.verify_signatures;

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

        const block_import_ctx = try allocator.create(BlockImportCallbackCtx);
        block_import_ctx.* = .{
            .importer = block_importer,
            .beacon_config = beacon_config,
        };

        const head_state_cb_ctx = try allocator.create(HeadStateCallbackCtx);
        head_state_cb_ctx.* = .{
            .block_state_cache = block_cache,
            .head_tracker = head_tracker,
        };

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
            .block_import = .{
                .ptr = @ptrCast(block_import_ctx),
                .importFn = &importBlockCallback,
            },
            .head_state = .{
                .ptr = @ptrCast(head_state_cb_ctx),
                .getHeadStateFn = &getHeadStateCallback,
            },
        };

        // Initialize execution engine.
        // Use HttpEngine when an execution URL is provided; fall back to MockEngine.
        var mock_engine_ptr: ?*MockEngine = null;
        var http_engine_ptr: ?*HttpEngine = null;
        var io_transport_ptr: ?*IoHttpTransport = null;
        var engine: ?EngineApi = null;

        if (opts.engine_mock) {
            // Explicit --engine-mock flag — always use MockEngine.
            const mock = try allocator.create(MockEngine);
            mock.* = MockEngine.init(allocator);
            mock_engine_ptr = mock;
            engine = mock.engine();
            std.log.info("Execution engine: MockEngine (--engine-mock)", .{});
        } else if (opts.execution_urls.len > 0) {
            // JWT secret will be loaded lazily in setIo() when Io becomes available.
            // Create production HTTP transport and HttpEngine (jwt_secret=null for now).
            const transport = try allocator.create(IoHttpTransport);
            transport.* = IoHttpTransport.init(allocator);
            io_transport_ptr = transport;

            const http_eng = try allocator.create(HttpEngine);
            http_eng.* = HttpEngine.init(
                allocator,
                opts.execution_urls[0],
                null, // JWT loaded in setIo()
                transport.transport(),
            );
            http_engine_ptr = http_eng;
            engine = http_eng.engine();
            std.log.info("Execution engine: HttpEngine -> {s}", .{opts.execution_urls[0]});
        } else {
            // No execution URL — use mock engine (tests / pre-merge).
            const mock = try allocator.create(MockEngine);
            mock.* = MockEngine.init(allocator);
            mock_engine_ptr = mock;
            engine = mock.engine();
            std.log.info("Execution engine: MockEngine (no --execution-url)", .{});
        }

        const node = try allocator.create(BeaconNode);
        node.* = .{
            .allocator = allocator,
            .config = beacon_config,
            .bootnodes = opts.bootnodes,
            .node_options = opts,
            .db = db,
            .state_regen = regen,
            .block_state_cache = block_cache,
            .checkpoint_state_cache = cp_cache,
            .head_tracker = head_tracker,
            .fork_choice = null,
            .op_pool = op_pool,
            .seen_cache = seen_cache,
            .block_importer = block_importer,
            .chain = chain_struct,
            .clock = null,
            .mock_engine = mock_engine_ptr,
            .http_engine = http_engine_ptr,
            .io_transport = io_transport_ptr,
            .jwt_secret_path = if (opts.execution_urls.len > 0) opts.jwt_secret_path else null,
            .data_dir = opts.data_dir,
            .engine_api = engine,
            .cp_datastore = cp_datastore,
            .kv_backend = kv_backend,
            .api_context = api_ctx,
            .api_head_tracker = api_head,
            .api_sync_status = api_sync,
            .block_import_ctx = block_import_ctx,
            .head_state_cb_ctx = head_state_cb_ctx,
            .unknown_block_sync = UnknownBlockSync.init(allocator),
        };

        // Wire engine API into block importer for execution payload verification.
        block_importer.engine_api = engine;

        // Wire data availability check (will be populated after node is created).
        // Note: The callback is set after BeaconNode.init returns since it needs
        // the node pointer. See the isDataAvailableCallback below.

        return node;
    }

    /// Clean up all owned resources.
    pub fn deinit(self: *BeaconNode) void {
        const allocator = self.allocator;

        self.chain.deinit();
        allocator.destroy(self.chain);

        self.block_importer.deinit();
        allocator.destroy(self.block_importer);

        self.seen_cache.deinit();
        allocator.destroy(self.seen_cache);

        self.op_pool.deinit();
        allocator.destroy(self.op_pool);

        self.head_tracker.deinit();
        allocator.destroy(self.head_tracker);

        if (self.mock_engine) |me| {
            me.deinit();
            allocator.destroy(me);
        }

        if (self.http_engine) |he| {
            he.deinit();
            allocator.destroy(he);
        }

        if (self.io_transport) |pt| {
            pt.deinit();
            allocator.destroy(pt);
        }

        if (self.fork_choice) |fc| {
            fc.deinit(allocator);
            allocator.destroy(fc);
        }

        // api_regen was allocated but stored in api_context.regen
        allocator.destroy(self.api_context.regen);
        allocator.destroy(self.api_context);
        allocator.destroy(self.api_head_tracker);
        allocator.destroy(self.api_sync_status);
        allocator.destroy(self.block_import_ctx);
        allocator.destroy(self.head_state_cb_ctx);

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
            .memory => |mem| {
                mem.deinit();
                allocator.destroy(mem);
            },
            .lmdb => |lmdb_store| {
                lmdb_store.deinit();
                allocator.destroy(lmdb_store);
            },
        }

        // Discovery service cleanup.
        if (self.discovery_service) |ds| {
            ds.deinit();
            allocator.destroy(ds);
        }

        // Connection manager cleanup.
        if (self.connection_manager) |cm| {
            cm.deinit();
            allocator.destroy(cm);
        }

        // P2P validator (heap-allocated to keep pointers stable; p2p_service
        // must be stopped before deinit is called since it takes Io).
        if (self.p2p_validator) |v| {
            v.deinit();
            allocator.destroy(v);
        }
        if (self.p2p_req_resp_ctx) |ctx| {
            allocator.destroy(ctx);
        }
        if (self.p2p_request_ctx) |ctx| {
            allocator.destroy(ctx);
        }

        if (self.gossip_handler) |gh| {
            gh.deinit();
        }

        // Sync pipeline cleanup.
        if (self.sync_controller) |sc| {
            allocator.destroy(sc);
        }
        if (self.sync_service_inst) |svc| {
            allocator.destroy(svc);
        }
        if (self.sync_callback_ctx) |ctx| {
            allocator.destroy(ctx);
        }
        if (self.sync_peer_manager) |pm| {
            pm.deinit();
            allocator.destroy(pm);
        }

        self.unknown_block_sync.deinit();
        allocator.destroy(self);
    }

    /// Set the I/O context for the node and all sub-components.
    /// Must be called before services start (importBlock, EL communication).
    pub fn setIo(self: *BeaconNode, io: std.Io) void {
        self.io = io;
        if (self.http_engine) |he| he.setIo(io);
        if (self.io_transport) |t| t.setIo(io);

        // Load JWT secret now that Io is available.
        // Load or create node identity now that Io is available.
        if (self.node_identity == null) {
            self.node_identity = identity_mod.loadOrCreateIdentity(io, self.data_dir) catch |err| blk: {
                std.log.err("Failed to load node identity: {}", .{err});
                break :blk null;
            };
        }

        if (self.jwt_secret_path) |jwt_path| {
            if (self.http_engine) |he| {
                const secret = loadJwtSecret(self.allocator, io, jwt_path) catch |err| {
                    std.log.err("Failed to load JWT secret from '{s}': {}", .{ jwt_path, err });
                    return;
                };
                he.jwt_secret = secret;
                std.log.info("Loaded JWT secret from {s}", .{jwt_path});
            }
        }
    }

    /// Initialize from a genesis state.
    ///
    /// Loads the genesis state into caches, sets up the head tracker at slot 0,
    /// and configures the clock from the genesis time.
    pub fn initFromGenesis(self: *BeaconNode, genesis_state: *CachedBeaconState) !void {
        // The genesis block root is the hash of the latest block header stored
        // in the genesis state. This matches what BlockGenerator computes as
        // parent_root when building the first block (from state.latestBlockHeader()).
        // Compute the genesis state root first — needed for the genesis block root.
        // The genesis state's latestBlockHeader has state_root=0x00..00 initially;
        // per spec, the actual genesis block root uses the real state_root.
        try genesis_state.state.commit();
        const state_root_for_header = (try genesis_state.state.hashTreeRoot()).*;

        var genesis_header = try genesis_state.state.latestBlockHeader();
        // Per spec: genesis block header has state_root=0 initially.
        // Compute the genesis block root with the real state_root filled in,
        // but do NOT mutate the live tree — read fields into a plain struct.
        const header_slot = try genesis_header.get("slot");
        const header_proposer = try genesis_header.get("proposer_index");
        const header_parent = (try genesis_header.getFieldRoot("parent_root")).*;
        const header_body = (try genesis_header.getFieldRoot("body_root")).*;
        const genesis_header_val = types.phase0.BeaconBlockHeader.Type{
            .slot = header_slot,
            .proposer_index = header_proposer,
            .parent_root = header_parent,
            .state_root = state_root_for_header,
            .body_root = header_body,
        };
        var genesis_block_root: [32]u8 = undefined;
        try types.phase0.BeaconBlockHeader.hashTreeRoot(&genesis_header_val, &genesis_block_root);

        // Cache the genesis state
        const state_root = try self.state_regen.onNewBlock(genesis_state, true);

        // Register genesis block_root → state_root mapping for block importer.
        // Incoming blocks reference parent_root = genesis_block_root, so the
        // importer needs to resolve that to find the pre-state.
        try self.block_importer.registerGenesisRoot(genesis_block_root, state_root);
        try self.chain.registerGenesisRoot(genesis_block_root, state_root);

        // Set head at slot 0
        try self.head_tracker.onBlock(genesis_block_root, 0, state_root);

        // Capture genesis validators root for fork digest computation
        self.genesis_validators_root = (try genesis_state.state.genesisValidatorsRoot()).*;
        self.chain.genesis_validators_root = self.genesis_validators_root;
        std.log.info("Genesis validators root: 0x{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}...", .{
            self.genesis_validators_root[0], self.genesis_validators_root[1],
            self.genesis_validators_root[2], self.genesis_validators_root[3],
            self.genesis_validators_root[4], self.genesis_validators_root[5],
            self.genesis_validators_root[6], self.genesis_validators_root[7],
        });

        // Set up clock
        const genesis_time = try genesis_state.state.genesisTime();
        self.clock = SlotClock.fromGenesis(genesis_time, self.config.chain);

        // Initialize fork choice with genesis anchor block.
        // Get justified/finalized checkpoints from genesis state.
        var genesis_justified_cp: types.phase0.Checkpoint.Type = undefined;
        try genesis_state.state.currentJustifiedCheckpoint(&genesis_justified_cp);
        var genesis_finalized_cp: types.phase0.Checkpoint.Type = undefined;
        try genesis_state.state.finalizedCheckpoint(&genesis_finalized_cp);

        // Get effective balances from genesis epoch cache.
        const genesis_balances = genesis_state.epoch_cache.getEffectiveBalanceIncrements();

        const fc_anchor = ProtoBlock{
            .slot = 0,
            .block_root = genesis_block_root,
            .parent_root = genesis_block_root, // anchor: parent = self
            .state_root = state_root,
            .target_root = genesis_block_root,
            .justified_epoch = genesis_justified_cp.epoch,
            .justified_root = genesis_justified_cp.root,
            .finalized_epoch = genesis_finalized_cp.epoch,
            .finalized_root = genesis_finalized_cp.root,
            .unrealized_justified_epoch = genesis_justified_cp.epoch,
            .unrealized_justified_root = genesis_justified_cp.root,
            .unrealized_finalized_epoch = genesis_finalized_cp.epoch,
            .unrealized_finalized_root = genesis_finalized_cp.root,
            .extra_meta = .{ .pre_merge = {} },
            .timeliness = true,
        };

        const fc = try self.allocator.create(ForkChoice);
        errdefer self.allocator.destroy(fc);
        fc.* = try ForkChoice.init(
            self.allocator,
            .{
                .justified_checkpoint = .{
                    .epoch = genesis_justified_cp.epoch,
                    .root = genesis_justified_cp.root,
                },
                .finalized_checkpoint = .{
                    .epoch = genesis_finalized_cp.epoch,
                    .root = genesis_finalized_cp.root,
                },
                .justified_balances = genesis_balances.items,
            },
            fc_anchor,
            0, // current_slot = 0 at genesis
        );

        // Clean up any previous fork choice (re-genesis case).
        if (self.fork_choice) |old_fc| {
            old_fc.deinit(self.allocator);
            self.allocator.destroy(old_fc);
        }
        self.fork_choice = fc;
        self.block_importer.fork_choice = fc;
        self.chain.fork_choice = fc;
        self.chain.genesis_validators_root = self.genesis_validators_root;

        // Update API context
        self.api_head_tracker.head_slot = 0;
        self.api_head_tracker.head_root = genesis_block_root;
        self.api_head_tracker.head_state_root = state_root;
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
        // Compute the checkpoint state root.
        try checkpoint_state.state.commit();
        const state_root = (try checkpoint_state.state.hashTreeRoot()).*;

        // Extract the latest block header from the checkpoint state.
        // Fill in the state_root to compute the correct block root.
        var cp_header = try checkpoint_state.state.latestBlockHeader();
        const header_slot = try cp_header.get("slot");
        const header_proposer = try cp_header.get("proposer_index");
        const header_parent = (try cp_header.getFieldRoot("parent_root")).*;
        const header_body = (try cp_header.getFieldRoot("body_root")).*;

        // The header's state_root may be zero (as per spec for the slot's
        // latest block header). Fill it in with the computed state_root.
        var header_state_root = (try cp_header.getFieldRoot("state_root")).*;
        if (std.mem.eql(u8, &header_state_root, &([_]u8{0} ** 32))) {
            header_state_root = state_root;
        }

        const cp_header_val = types.phase0.BeaconBlockHeader.Type{
            .slot = header_slot,
            .proposer_index = header_proposer,
            .parent_root = header_parent,
            .state_root = header_state_root,
            .body_root = header_body,
        };
        var anchor_block_root: [32]u8 = undefined;
        try types.phase0.BeaconBlockHeader.hashTreeRoot(&cp_header_val, &anchor_block_root);

        // The slot of the state — this is where we're anchoring.
        const cp_slot = try checkpoint_state.state.slot();

        std.log.info("Checkpoint anchor: slot={d} block_root=0x{s}...", .{
            cp_slot,
            &std.fmt.bytesToHex(anchor_block_root[0..8], .lower),
        });

        // Cache the checkpoint state.
        const cached_state_root = try self.state_regen.onNewBlock(checkpoint_state, true);

        // Register block_root → state_root mapping.
        try self.block_importer.registerGenesisRoot(anchor_block_root, cached_state_root);
        try self.chain.registerGenesisRoot(anchor_block_root, cached_state_root);

        // Set head at the checkpoint slot.
        try self.head_tracker.onBlock(anchor_block_root, cp_slot, cached_state_root);

        // Capture genesis validators root for fork digest computation.
        self.genesis_validators_root = (try checkpoint_state.state.genesisValidatorsRoot()).*;
        self.chain.genesis_validators_root = self.genesis_validators_root;
        std.log.info("Genesis validators root: 0x{s}...", .{
            &std.fmt.bytesToHex(self.genesis_validators_root[0..8], .lower),
        });

        // Set up clock from genesis_time.
        const genesis_time = try checkpoint_state.state.genesisTime();
        self.clock = SlotClock.fromGenesis(genesis_time, self.config.chain);

        // Initialize fork choice with checkpoint as anchor.
        var justified_cp: types.phase0.Checkpoint.Type = undefined;
        try checkpoint_state.state.currentJustifiedCheckpoint(&justified_cp);
        var finalized_cp: types.phase0.Checkpoint.Type = undefined;
        try checkpoint_state.state.finalizedCheckpoint(&finalized_cp);

        const balances = checkpoint_state.epoch_cache.getEffectiveBalanceIncrements();

        const fc_anchor = ProtoBlock{
            .slot = cp_slot,
            .block_root = anchor_block_root,
            .parent_root = anchor_block_root, // anchor: parent = self
            .state_root = cached_state_root,
            .target_root = anchor_block_root,
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

        const fc = try self.allocator.create(ForkChoice);
        errdefer self.allocator.destroy(fc);
        fc.* = try ForkChoice.init(
            self.allocator,
            .{
                .justified_checkpoint = .{
                    .epoch = justified_cp.epoch,
                    .root = justified_cp.root,
                },
                .finalized_checkpoint = .{
                    .epoch = finalized_cp.epoch,
                    .root = finalized_cp.root,
                },
                .justified_balances = balances.items,
            },
            fc_anchor,
            cp_slot,
        );

        // Clean up any previous fork choice.
        if (self.fork_choice) |old_fc| {
            old_fc.deinit(self.allocator);
            self.allocator.destroy(old_fc);
        }
        self.fork_choice = fc;
        self.block_importer.fork_choice = fc;
        self.chain.fork_choice = fc;
        self.chain.genesis_validators_root = self.genesis_validators_root;

        // Update API context.
        self.api_head_tracker.head_slot = cp_slot;
        self.api_head_tracker.head_root = anchor_block_root;
        self.api_head_tracker.head_state_root = cached_state_root;
        self.api_head_tracker.finalized_slot = finalized_cp.epoch * preset.SLOTS_PER_EPOCH;
        self.api_head_tracker.justified_slot = justified_cp.epoch * preset.SLOTS_PER_EPOCH;

        std.log.info("Initialized from checkpoint: slot={d} finalized_epoch={d} justified_epoch={d}", .{
            cp_slot,
            finalized_cp.epoch,
            justified_cp.epoch,
        });
    }

    /// Import a signed beacon block through the full pipeline.
    ///
    /// Decodes the block, runs STFN, caches the post-state, persists to DB,
    /// and updates the head tracker.
    pub fn importBlock(
        self: *BeaconNode,
        signed_block: *const types.electra.SignedBeaconBlock.Type,
    ) !ImportResult {
        const t0 = if (self.io) |io| std.Io.Clock.awake.now(io) else null;
        const result = try self.block_importer.importBlock(signed_block);

        // Notify EL of fork choice update after each block import.
        self.notifyForkchoiceUpdate(result.block_root) catch |err| {
            std.log.warn("forkchoiceUpdated failed: {}", .{err});
        };

        const elapsed_s: f64 = if (t0) |start| blk: {
            const t1 = std.Io.Clock.awake.now(self.io.?);
            break :blk @as(f64, @floatFromInt(t1.nanoseconds - start.nanoseconds)) / 1e9;
        } else 0.0;

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
            self.api_head_tracker.finalized_slot = self.head_tracker.finalized_epoch * preset.SLOTS_PER_EPOCH;
            self.api_head_tracker.justified_slot = self.head_tracker.justified_epoch * preset.SLOTS_PER_EPOCH;
            // Archive the post-epoch state for cold-path recovery.
            // Errors are non-fatal — the block is already imported.
            self.archiveState(result.slot, result.state_root) catch {};
        }

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
        const new_state_root = try self.state_regen.onNewBlock(post_state, true);

        // Update block_importer's block_root -> state_root mapping so the
        // next block import can find this state as parent.
        try self.block_importer.block_to_state.put(
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
    pub fn startApi(self: *BeaconNode, io: std.Io, address: []const u8, port: u16) !void {
        self.http_server = api_mod.HttpServer.init(self.allocator, self.api_context, address, port);
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
        // Build QUIC multiaddr: /ip4/{addr}/udp/{port}/quic-v1
        var ma_buf: [64]u8 = undefined;
        const ma_str = try std.fmt.bufPrint(&ma_buf, "/ip4/{s}/udp/{d}/quic-v1", .{ listen_addr, port });
        const listen_multiaddr = try Multiaddr.fromString(self.allocator, ma_str);
        defer listen_multiaddr.deinit();

        // Build a persistent RequestContext (heap-allocated, stable for P2P lifetime).
        // Uses self.allocator as scratch so returned block slices outlive callbacks;
        // they are copied into response chunks by the handler before use.
        const p2p_req_ctx = try self.allocator.create(RequestContext);
        errdefer self.allocator.destroy(p2p_req_ctx);
        p2p_req_ctx.* = .{ .node = self, .scratch = self.allocator };
        self.p2p_request_ctx = p2p_req_ctx;

        const req_resp_ctx = try self.allocator.create(ReqRespContext);
        errdefer self.allocator.destroy(req_resp_ctx);
        req_resp_ctx.* = ReqRespContext{
            .ptr = @ptrCast(p2p_req_ctx),
            .getStatus = &reqRespGetStatus,
            .getMetadata = &reqRespGetMetadata,
            .getPingSequence = &reqRespGetPingSequence,
            .getBlockByRoot = &reqRespGetBlockByRoot,
            .getBlocksByRange = &reqRespGetBlocksByRange,
            .getBlobByRoot = &reqRespGetBlobByRoot,
            .getBlobsByRange = &reqRespGetBlobsByRange,
            .getDataColumnByRoot = &reqRespGetDataColumnByRoot,
            .getDataColumnsByRange = &reqRespGetDataColumnsByRange,
            .getForkDigest = &reqRespGetForkDigest,
            .onGoodbye = &reqRespOnGoodbye,
            .onPeerStatus = &reqRespOnPeerStatus,
        };
        self.p2p_req_resp_ctx = req_resp_ctx;

        // Passthrough gossip validator — heap-allocated so its internal pointers
        // remain stable for the lifetime of p2p_service.
        const validator = try self.allocator.create(PassthroughValidator);
        errdefer self.allocator.destroy(validator);
        validator.* = PassthroughValidator.init(self.allocator);
        validator.fixupPointers();
        self.p2p_validator = validator;

        const fork_digest = self.config.forkDigestAtSlot(
            self.head_tracker.head_slot,
            self.genesis_validators_root,
        );

        // Generate an Ed25519 host key for TLS certificate (libp2p identity).
        const pctx = ssl.EVP_PKEY_CTX_new_id(ssl.EVP_PKEY_ED25519, null) orelse return error.KeyGenFailed;
        defer ssl.EVP_PKEY_CTX_free(pctx);
        if (ssl.EVP_PKEY_keygen_init(pctx) <= 0) return error.KeyGenFailed;
        var host_key: ?*ssl.EVP_PKEY = null;
        if (ssl.EVP_PKEY_keygen(pctx, &host_key) <= 0) return error.KeyGenFailed;
        // Note: host_key ownership is transferred to the engine; do not free here.

        // Store into BeaconNode BEFORE calling start() — start() spawns
        // background fibers that capture &self.p2p_service. If we used a
        // stack variable, the fibers would hold dangling pointers after
        // this function returns.
        self.p2p_service = try P2pService.init(self.allocator, P2pConfig{
            .fork_digest = fork_digest,
            .req_resp_context = req_resp_ctx,
            .validator = &validator.ctx,
            .host_key = host_key,
            .gossipsub_config = .{
                // Match Lodestar TS gossipsub params
                .mesh_degree = 8,
                .mesh_degree_lo = 6,
                .mesh_degree_hi = 12,
                .mesh_degree_lazy = 6,
                .heartbeat_interval_ms = 700,
            },
        });
        var svc = &self.p2p_service.?;
        try svc.start(io, listen_multiaddr);

        // Initialize discovery service.
        self.initDiscoveryService() catch |err| {
            std.log.warn("Failed to initialize discovery service: {}", .{err});
        };

        // Initialize connection manager.
        self.initConnectionManager() catch |err| {
            std.log.warn("Failed to initialize connection manager: {}", .{err});
        };

        // Initialize GossipHandler for attestation/aggregate processing.
        self.initGossipHandler();

        // Initialize the sync pipeline before dialing any peers.
        self.initSyncPipeline() catch |err| {
            std.log.warn("Failed to initialize sync pipeline: {}", .{err});
        };

        // Dial bootnodes: decode ENR → extract IP/port → build multiaddr → dial.
        if (self.bootnodes.len > 0) {
            std.log.info("Dialing {d} bootnode(s)...", .{self.bootnodes.len});
            for (self.bootnodes) |enr_str| {
                self.dialBootnodeEnr(io, svc, enr_str) catch |err| {
                    std.log.warn("Failed to dial bootnode: {}", .{err});
                };
            }
        }
    }
    /// Decode an ENR string and dial the peer via QUIC multiaddr.
    fn dialBootnodeEnr(self: *BeaconNode, io: std.Io, svc: *networking.P2pService, enr_str: []const u8) !void {
        // Strip "enr:" prefix if present.
        var s: []const u8 = enr_str;
        if (std.mem.startsWith(u8, s, "enr:")) s = s[4..];

        // Base64url decode.
        const decoded_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(s) catch |e| {
            std.log.err("ENR base64 calcSize failed: {} for input[0..@min(s.len,20)]={s}", .{ e, s[0..@min(s.len, 20)] });
            return error.InvalidEnr;
        };
        const raw = try self.allocator.alloc(u8, decoded_len);
        defer self.allocator.free(raw);
        std.base64.url_safe_no_pad.Decoder.decode(raw, s) catch |e| {
            std.log.err("ENR base64 decode failed: {}", .{e});
            return error.InvalidEnr;
        };

        // RLP decode the ENR to extract IP + UDP port.
        var enr = try discv5.enr.decode(self.allocator, raw);
        defer enr.deinit();

        const ip = enr.ip orelse return error.NoIpInEnr;
        // Prefer QUIC port (libp2p transport) over UDP port (discv5 only).
        const quic_port = enr.quic orelse enr.udp orelse return error.NoPortInEnr;

        // Build QUIC multiaddr: /ip4/{ip}/udp/{port}/quic-v1
        var ma_buf: [64]u8 = undefined;
        const ma_str = try std.fmt.bufPrint(&ma_buf, "/ip4/{d}.{d}.{d}.{d}/udp/{d}/quic-v1", .{
            ip[0], ip[1], ip[2], ip[3], quic_port,
        });

        std.log.info("Dialing bootnode at {s}", .{ma_str});

        const peer_addr = try Multiaddr.fromString(self.allocator, ma_str);
        defer peer_addr.deinit();

        const peer_id = svc.dial(io, peer_addr) catch |err| {
            std.log.warn("Bootnode dial failed: {}", .{err});
            return err;
        };
        std.log.info("Connected to bootnode, peer_id: {s}", .{peer_id});

        // Brief yield to let Lighthouse's inbound streams (identify, gossipsub)
        // settle before we open our outbound Status stream. Avoids lsquic
        // connection refcount assertion when streams are opened concurrently.
        {
            const delay: std.Io.Timeout = .{ .duration = .{
                .raw = std.Io.Duration.fromMilliseconds(500),
                .clock = .awake,
            } };
            delay.sleep(io) catch {};
        }

        // Initiate eth2 Status exchange with the bootnode.
        // Uses dialProtocol to get a raw stream, then does wire-level req/resp.
        // Use the peer's fork_digest from their ENR (avoids fork_digest mismatch
        // when all forks activate at epoch 0 in devnet configs).
        const peer_fork_digest: ?[4]u8 = enr.eth2_fork_digest;
        if (peer_fork_digest) |fd| {
            std.log.info("Peer ENR fork_digest: {x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{ fd[0], fd[1], fd[2], fd[3] });
        }
        const peer_status = self.sendStatus(io, svc, peer_id) catch |err| {
            std.log.warn("Status exchange failed: {}", .{err});
            return;
        };

        // Notify sync controller of the new peer — this triggers the sync
        // state machine to evaluate whether range sync should start.
        if (self.sync_controller) |sc| {
            sc.onPeerConnected(peer_id, peer_status) catch |err| {
                std.log.warn("SyncController.onPeerConnected failed: {}", .{err});
            };
        }

        // Process any pending sync batch requests that were queued by the
        // sync controller during onPeerConnected evaluation.
        self.processSyncBatches(io, svc);

        // Open outbound gossipsub stream to send our subscriptions to the peer.
        // This triggers handleOutbound which stores the stream for writing
        // and sends our topic subscription announcements.
        var p2p_svc = &self.p2p_service.?;
        const GossipsubHandler = @import("zig-libp2p").gossipsub.Handler;
        svc.newStream(io, peer_id, GossipsubHandler, null) catch |err| {
            std.log.warn("Failed to open outbound gossipsub stream: {}", .{err});
        };
        std.log.info("Opened outbound gossipsub stream to peer", .{});

        // Subscribe to all 64 attestation subnets.
        {
            const gossip_topics = networking.gossip_topics;
            var subnet_i: u8 = 0;
            while (subnet_i < gossip_topics.MAX_ATTESTATION_SUBNET_ID) : (subnet_i += 1) {
                p2p_svc.subscribeSubnet(.beacon_attestation, subnet_i) catch |err| {
                    std.log.warn("Failed to subscribe to attestation subnet {d}: {}", .{ subnet_i, err });
                };
            }
            std.log.info("Subscribed to {d} attestation subnets", .{gossip_topics.MAX_ATTESTATION_SUBNET_ID});
        }

        // Subscribe to data column sidecar subnets (PeerDAS / Fulu).
        // In production, only custody subnets would be subscribed. For now, subscribe to a subset.
        {
            const gossip_topics = networking.gossip_topics;
            const custody_req = self.config.chain.CUSTODY_REQUIREMENT;
            var subnet_i: u8 = 0;
            while (subnet_i < custody_req and subnet_i < gossip_topics.MAX_DATA_COLUMN_SIDECAR_SUBNET_ID) : (subnet_i += 1) {
                p2p_svc.subscribeSubnet(.data_column_sidecar, subnet_i) catch |err| {
                    std.log.warn("Failed to subscribe to data column subnet {d}: {}", .{ subnet_i, err });
                };
            }
            std.log.info("Subscribed to {d} data column subnets (custody requirement)", .{custody_req});
        }

        // Start gossipsub heartbeat on a background fiber (runs every 700ms).
        p2p_svc.startHeartbeat(io);
        std.log.info("Gossipsub heartbeat started (700ms interval)", .{});

        // Main sync + gossip loop: tick the sync state machine and poll gossip.
        std.log.info("Starting sync-driven maintenance loop...", .{});
        while (true) {
            const slot_sleep: std.Io.Timeout = .{ .duration = .{
                .raw = std.Io.Duration.fromNanoseconds(@as(i96, 6) * std.time.ns_per_s),
                .clock = .awake,
            } };
            slot_sleep.sleep(io) catch break;

            // Run discovery tick — find new peers if below target.
            if (self.discovery_service) |ds| {
                if (self.connection_manager) |cm| {
                    ds.setConnectedPeers(cm.connectedCount());
                }
                ds.discoverPeers();
            }

            // Poll gossipsub for all gossip messages (blocks, attestations, aggregates).
            if (self.p2p_service) |p2p| {
                self.processGossipEvents(p2p);
            }

            // Tick the sync service state machine — evaluates mode, dispatches
            // new batches, re-dispatches failed ones.
            if (self.sync_controller) |sc| {
                sc.tick() catch |err| {
                    std.log.warn("SyncController.tick failed: {}", .{err});
                };
            }

            // Drain any batch requests queued by the sync tick.
            self.processSyncBatches(io, svc);

            // Update API sync status from the sync service.
            self.updateApiSyncStatus();
        }
    }

    /// Initialize the discovery service.

/// Parse a dotted-decimal IPv4 string ("1.2.3.4") into [4]u8.
fn parseIp4(s: []const u8) ?[4]u8 {
    var result: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var start: usize = 0;
    for (s, 0..) |c, i| {
        if (c == '.') {
            if (octet_idx >= 3) return null;
            result[octet_idx] = std.fmt.parseInt(u8, s[start..i], 10) catch return null;
            octet_idx += 1;
            start = i + 1;
        }
    }
    if (octet_idx != 3) return null;
    result[3] = std.fmt.parseInt(u8, s[start..], 10) catch return null;
    return result;
}

    fn initDiscoveryService(self: *BeaconNode) !void {
        const allocator = self.allocator;

        // Use the persistent node identity (loaded/generated in setIo).
        const secret_key = if (self.node_identity) |id| id.secret_key else {
            std.log.err("Cannot init discovery: node identity not loaded (setIo not called?)", .{});
            return error.NoNodeIdentity;
        };

        const fork_digest = self.config.forkDigestAtSlot(
            self.head_tracker.head_slot,
            self.genesis_validators_root,
        );

        const ds = try allocator.create(DiscoveryService);
        errdefer allocator.destroy(ds);
        // Resolve discovery port: explicit --discovery-port, or fall back to p2p_port.
        const disc_port = self.node_options.discovery_port orelse self.node_options.p2p_port;

        // Parse p2p_host string ("0.0.0.0") into [4]u8 for the discovery service.
        const local_ip = parseIp4(self.node_options.p2p_host) orelse [4]u8{ 0, 0, 0, 0 };

        ds.* = try DiscoveryService.init(allocator, .{
            .listen_port = disc_port,
            .secret_key = secret_key,
            .local_ip = local_ip,
            .p2p_port = self.node_options.p2p_port,
            .fork_digest = fork_digest,
            .target_peers = self.node_options.target_peers,
            .cli_bootnodes = self.bootnodes,
        });

        // Seed the routing table with bootnodes.
        ds.seedBootnodes();
        self.discovery_service = ds;

        std.log.info("Discovery service initialized (known_peers={d})", .{ds.knownPeerCount()});
    }

    /// Initialize the connection manager.
    fn initConnectionManager(self: *BeaconNode) !void {
        const allocator = self.allocator;
        const cm = try allocator.create(ConnectionManager);
        errdefer allocator.destroy(cm);
        cm.* = ConnectionManager.init(allocator, .{
            .target_peers = self.node_options.target_peers,
        });
        self.connection_manager = cm;
        std.log.info("Connection manager initialized (target_peers={d})", .{cm.config.target_peers});
    }

    /// Initialize the sync pipeline (PeerManager, SyncService, SyncController).
    ///
    /// Called once from startP2p() after the P2P service is ready. Creates
    /// heap-allocated sync components and wires them into the BeaconNode.
    pub fn initSyncPipeline(self: *BeaconNode) !void {
        const allocator = self.allocator;

        // PeerManager tracks connected peers and their chain views.
        const pm = try allocator.create(PeerManager);
        pm.* = PeerManager.init(allocator);
        self.sync_peer_manager = pm;

        // SyncCallbackCtx bridges sync callbacks to the P2P transport.
        const cb_ctx = try allocator.create(SyncCallbackCtx);
        cb_ctx.* = .{ .node = self };
        self.sync_callback_ctx = cb_ctx;

        // SyncService: top-level sync coordinator with range sync.
        const svc = try allocator.create(SyncService);
        svc.* = SyncService.init(
            allocator,
            cb_ctx.importerCallback(),
            cb_ctx.requesterCallback(),
            pm,
            self.head_tracker.head_slot,
        );
        self.sync_service_inst = svc;

        // SyncController: glue between P2P events and sync pipeline.
        const sc = try allocator.create(SyncController);
        sc.* = SyncController.init(allocator, self, svc, pm);
        self.sync_controller = sc;

        std.log.info("Sync pipeline initialized (head_slot={d})", .{self.head_tracker.head_slot});
    }

    /// Process pending batch requests from the sync state machine.
    ///
    /// Drains the SyncCallbackCtx pending request queue, executing each
    /// batch request via P2P (requestBlocksByRange) and feeding the
    /// results back to the sync controller.
    fn processSyncBatches(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) void {
        const cb_ctx = self.sync_callback_ctx orelse return;
        const sc = self.sync_controller orelse return;

        while (cb_ctx.pending_count > 0) {
            // Pop the first pending request.
            const req = cb_ctx.pending_requests[0];
            cb_ctx.pending_count -= 1;
            // Shift remaining requests left.
            var j: u8 = 0;
            while (j < cb_ctx.pending_count) : (j += 1) {
                cb_ctx.pending_requests[j] = cb_ctx.pending_requests[j + 1];
            }

            const peer_id = req.peerId();
            std.log.info("Processing sync batch {d}: slots {d}..{d} from peer {s}", .{
                req.batch_id, req.start_slot, req.start_slot + req.count - 1, peer_id,
            });

            // Fetch raw blocks via P2P.
            const blocks = self.fetchRawBlocksByRange(io, svc, peer_id, req.start_slot, req.count) catch |err| {
                std.log.warn("Batch {d} fetch failed: {}", .{ req.batch_id, err });
                sc.onBatchError(req.batch_id);
                continue;
            };
            defer {
                for (blocks) |blk| {
                    self.allocator.free(blk.block_bytes);
                }
                self.allocator.free(blocks);
            }

            if (blocks.len == 0) {
                std.log.warn("Batch {d}: empty response from peer", .{req.batch_id});
                sc.onBatchError(req.batch_id);
                continue;
            }

            // Feed blocks to the sync controller which imports them
            // via the BlockImporterCallback.
            sc.onBlocksReceived(req.batch_id, blocks) catch |err| {
                std.log.warn("Batch {d} import failed: {}", .{ req.batch_id, err });
                sc.onBatchError(req.batch_id);
                continue;
            };

            std.log.info("Batch {d}: delivered {d} blocks to sync pipeline", .{
                req.batch_id, blocks.len,
            });
        }
    }

    /// Fetch raw blocks by range from a peer, returning BatchBlock slices.
    ///
    /// Unlike requestBlocksByRange() which imports inline, this returns
    /// raw SSZ bytes for the sync pipeline to process via callbacks.
    fn fetchRawBlocksByRange(
        self: *BeaconNode,
        io: std.Io,
        svc: *networking.P2pService,
        peer_id: []const u8,
        start_slot: u64,
        count: u64,
    ) ![]BatchBlock {
        const protocol_id = "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy";
        const req_resp_encoding = networking.req_resp_encoding;

        var stream = try svc.dialProtocol(io, peer_id, protocol_id);

        // Encode the range request.
        const request = networking.messages.BeaconBlocksByRangeRequest.Type{
            .start_slot = start_slot,
            .count = count,
            .step = 1,
        };
        var req_ssz: [networking.messages.BeaconBlocksByRangeRequest.fixed_size]u8 = undefined;
        _ = networking.messages.BeaconBlocksByRangeRequest.serializeIntoBytes(&request, &req_ssz);

        const wire_request = try req_resp_encoding.encodeRequest(self.allocator, &req_ssz);
        defer self.allocator.free(wire_request);

        // Write request.
        var written: usize = 0;
        while (written < wire_request.len) {
            written += stream.write(io, wire_request[written..]) catch |err| {
                std.log.warn("fetchRawBlocksByRange write error: {}", .{err});
                return err;
            };
        }

        // Read response chunks into BatchBlock array.
        var result: std.ArrayList(BatchBlock) = .empty;
        errdefer {
            for (result.items) |blk| self.allocator.free(blk.block_bytes);
            result.deinit(self.allocator);
        }

        var buf: [1024 * 1024]u8 = undefined;
        var buf_len: usize = 0;
        var blocks_received: u64 = 0;

        while (blocks_received < count) {
            const n = stream.read(io, buf[buf_len..]) catch |err| {
                std.log.info("fetchRawBlocksByRange: stream ended after {d} blocks ({})", .{ blocks_received, err });
                break;
            };
            if (n == 0) break;
            buf_len += n;

            while (buf_len > 0 and blocks_received < count) {
                const decoded = req_resp_encoding.decodeResponseChunk(
                    self.allocator,
                    buf[0..buf_len],
                    true,
                ) catch |err| {
                    if (err == error.InsufficientData) break;
                    std.log.warn("fetchRawBlocksByRange: decode error: {}", .{err});
                    return result.toOwnedSlice(self.allocator) catch return error.OutOfMemory;
                };

                if (decoded.result != .success) {
                    self.allocator.free(decoded.ssz_bytes);
                    break;
                }

                // Infer slot from the SSZ bytes if possible (first 8 bytes of message = slot).
                // For BatchBlock we store raw SSZ + slot.
                // Slot is at offset 8 of the SignedBeaconBlock message (after signature).
                const slot = if (decoded.ssz_bytes.len >= 104)
                    std.mem.readInt(u64, decoded.ssz_bytes[96..104], .little)
                else
                    start_slot + blocks_received;

                try result.append(self.allocator, .{
                    .slot = slot,
                    .block_bytes = decoded.ssz_bytes, // caller owns
                });
                blocks_received += 1;

                const consumed = decoded.bytes_consumed;
                if (consumed < buf_len) {
                    std.mem.copyForwards(u8, buf[0 .. buf_len - consumed], buf[consumed..buf_len]);
                    buf_len -= consumed;
                } else {
                    buf_len = 0;
                }
            }
        }

        return result.toOwnedSlice(self.allocator);
    }

    /// Poll gossipsub for beacon_block messages and import them.
    ///
    /// Extracted from the inline loop to be callable from the sync-driven
    /// maintenance loop.
    fn pollGossipBlocks(self: *BeaconNode) void {
        if (self.p2p_service) |p2p| {
            const gossip_decoding = networking.gossip_decoding;
            const events = p2p.gossipsub.drainEvents() catch return;
            defer self.allocator.free(events);
            for (events) |event| {
                switch (event) {
                    .message => |msg| {
                        if (std.mem.indexOf(u8, msg.topic, "beacon_block") == null) continue;
                        const ssz_bytes = gossip_decoding.decompressGossipPayload(
                            self.allocator, msg.data,
                        ) catch continue;
                        defer self.allocator.free(ssz_bytes);

                        const raw_fork_seq2 = self.config.forkSeq(self.head_tracker.head_slot);
                        const fork_seq = if (@intFromEnum(raw_fork_seq2) > @intFromEnum(config_mod.ForkSeq.electra))
                            config_mod.ForkSeq.electra
                        else
                            raw_fork_seq2;
                        const any_signed = AnySignedBeaconBlock.deserialize(
                            self.allocator, .full, fork_seq, ssz_bytes,
                        ) catch |err| {
                            std.log.warn("Gossip block deserialize: {}", .{err});
                            continue;
                        };
                        defer any_signed.deinit(self.allocator);

                        switch (any_signed) {
                            .full_electra => |blk| {
                                const result = self.importBlock(blk) catch |err| {
                                    if (err == error.UnknownParentBlock) {
                                        self.queueOrphanBlock(blk, ssz_bytes);
                                    } else if (err != error.BlockAlreadyKnown and err != error.BlockAlreadyFinalized) {
                                        std.log.warn("Gossip block import: {}", .{err});
                                    }
                                    continue;
                                };
                                self.processPendingChildren(result.block_root);
                                std.log.info("GOSSIP BLOCK IMPORTED slot={d} root={x:0>2}{x:0>2}{x:0>2}{x:0>2}...", .{
                                    result.slot,
                                    result.block_root[0], result.block_root[1],
                                    result.block_root[2], result.block_root[3],
                                });
                            },
                            else => {},
                        }
                    },
                    else => {},
                }
            }
        }
    }

    /// Update the API sync status from the sync service state machine.
    fn updateApiSyncStatus(self: *BeaconNode) void {
        if (self.sync_service_inst) |svc| {
            const status = svc.getSyncStatus();
            self.api_sync_status.head_slot = status.head_slot;
            self.api_sync_status.sync_distance = status.sync_distance;
            self.api_sync_status.is_syncing = status.state == .syncing;
            self.api_sync_status.is_optimistic = status.is_optimistic;
        }
    }

        /// Perform a Status req/resp exchange with a connected peer.
        ///
        /// Opens a stream via dialProtocol, sends our wire-encoded Status request,
        /// reads the wire-encoded response, decodes the peer's Status, and logs it.
        /// Also notifies the sync controller of the peer's status.
        fn sendStatus(self: *BeaconNode, io: std.Io, svc: *networking.P2pService, peer_id: []const u8) !networking.messages.StatusMessage.Type {
            const status_protocol_id = "/eth2/beacon_chain/req/status/1/ssz_snappy";
            const req_resp_encoding = networking.req_resp_encoding;

            // Open a negotiated stream for Status.
            var stream = try svc.dialProtocol(io, peer_id, status_protocol_id);

            // SSZ-encode our Status message.
            var status_ssz: [networking.messages.StatusMessage.fixed_size]u8 = undefined;
            const our_status = self.getStatus();
            _ = networking.messages.StatusMessage.serializeIntoBytes(&our_status, &status_ssz);
            std.log.info("Sending Status: fork_digest={x:0>2}{x:0>2}{x:0>2}{x:0>2} head_slot={d} finalized_epoch={d}", .{
                our_status.fork_digest[0], our_status.fork_digest[1],
                our_status.fork_digest[2], our_status.fork_digest[3],
                our_status.head_slot, our_status.finalized_epoch,
            });

            // Wire-encode: varint length prefix + snappy-compressed SSZ.
            const wire_request = try req_resp_encoding.encodeRequest(self.allocator, &status_ssz);
            defer self.allocator.free(wire_request);

            // Write request to stream.
            var written: usize = 0;
            while (written < wire_request.len) {
                written += stream.write(io, wire_request[written..]) catch |err| {
                    std.log.warn("Status write error: {}", .{err});
                    return err;
                };
            }

            // Read response from stream.
            // Status response is small: 1 (result) + varint + snappy(84 SSZ) ≈ ~100 bytes.
            var resp_buf: [1024]u8 = undefined;
            var resp_len: usize = 0;
            while (resp_len < resp_buf.len) {
                const n = stream.read(io, resp_buf[resp_len..]) catch |err| {
                    // EOF or stream close — we have what we have.
                    std.log.info("Status read completed ({d} bytes, end: {})", .{ resp_len, err });
                    break;
                };
                if (n == 0) break;
                resp_len += n;
            }

            if (resp_len == 0) {
                std.log.warn("Status: peer sent empty response", .{});
                return error.EmptyResponse;
            }

            // Hex dump raw response for debugging
            // Log raw response bytes in groups of 16
            std.log.info("Status raw response: {d} bytes", .{resp_len});
            {
                var offset: usize = 0;
                while (offset < resp_len and offset < 112) : (offset += 8) {
                    const end = @min(offset + 8, resp_len);
                    switch (end - offset) {
                        8 => std.log.info("  [{d:>3}]: {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2}", .{
                            offset,
                            resp_buf[offset], resp_buf[offset+1], resp_buf[offset+2], resp_buf[offset+3],
                            resp_buf[offset+4], resp_buf[offset+5], resp_buf[offset+6], resp_buf[offset+7],
                        }),
                        4 => std.log.info("  [{d:>3}]: {x:0>2} {x:0>2} {x:0>2} {x:0>2}", .{
                            offset,
                            resp_buf[offset], resp_buf[offset+1], resp_buf[offset+2], resp_buf[offset+3],
                        }),
                        else => {},
                    }
                }
            }

            // Decode the response chunk (no context bytes for Status).
            const decoded = req_resp_encoding.decodeResponseChunk(
                self.allocator,
                resp_buf[0..resp_len],
                false, // Status has no context bytes
            ) catch |err| {
                std.log.warn("Status response decode error: {} (raw {d} bytes)", .{ err, resp_len });
                return err;
            };
            defer self.allocator.free(decoded.ssz_bytes);

            if (decoded.result != .success) {
                std.log.warn("Status response: error code {}", .{decoded.result});
                return error.StatusRejected;
            }

            // Deserialize the peer's Status from SSZ.
            var peer_status: networking.messages.StatusMessage.Type = undefined;
            networking.messages.StatusMessage.deserializeFromBytes(decoded.ssz_bytes, &peer_status) catch |err| {
                std.log.warn("Status SSZ deserialize error: {}", .{err});
                return err;
            };

            std.log.info("Peer Status: fork_digest={x:0>2}{x:0>2}{x:0>2}{x:0>2} head_slot={d} finalized_epoch={d} finalized_root={x:0>2}{x:0>2}{x:0>2}{x:0>2}...", .{
                peer_status.fork_digest[0], peer_status.fork_digest[1],
                peer_status.fork_digest[2], peer_status.fork_digest[3],
                peer_status.head_slot, peer_status.finalized_epoch,
                peer_status.finalized_root[0], peer_status.finalized_root[1],
                peer_status.finalized_root[2], peer_status.finalized_root[3],
            });

            // Notify sync controller of the peer's head.
            if (self.sync_controller) |sc| {
                sc.onPeerConnected(peer_id, peer_status) catch |err| {
                    std.log.warn("SyncController.onPeerConnected failed: {}", .{err});
                };
            }

            return peer_status;
        }

        /// Poll gossipsub for all gossip messages and import them.
        ///
        /// Runs after range sync to stay at the head of the chain.
        /// Polls the gossipsub service for events, parses topics, and
        /// routes to the appropriate handler (blocks, attestations, aggregates).
        fn gossipBlockLoop(self: *BeaconNode, io: std.Io, svc: *networking.P2pService) !void {
            _ = svc;
            const gossipsub = self.p2p_service.?.gossipsub;

            while (true) {
                // Poll gossipsub for raw events
                const events = gossipsub.drainEvents() catch |err| {
                    std.log.warn("Gossip drain error: {}", .{err});
                    const t: std.Io.Timeout = .{ .duration = .{
                        .raw = std.Io.Duration.fromMilliseconds(1000),
                        .clock = .awake,
                    } };
                    t.sleep(io) catch return;
                    continue;
                };
                defer self.allocator.free(events);

                if (events.len == 0) {
                    const t: std.Io.Timeout = .{ .duration = .{
                        .raw = std.Io.Duration.fromMilliseconds(500),
                        .clock = .awake,
                    } };
                    t.sleep(io) catch return;
                    continue;
                }

                self.processGossipEventsFromSlice(events);
            }
        }

        /// Initialize the GossipHandler for attestation/aggregate/operation validation.
        fn initGossipHandler(self: *BeaconNode) void {
            if (self.gossip_handler != null) return;

            // Set module-level node pointer for ptr-free vtable callbacks.
            gossip_node = self;

            self.gossip_handler = GossipHandler.create(
                self.allocator,
                @ptrCast(self),
                &gossipImportBlockFromGossip,
                &gossipGetProposerIndex,
                &gossipIsKnownBlockRoot,
                &gossipGetValidatorCount,
            ) catch |err| {
                std.log.warn("Failed to create GossipHandler: {}", .{err});
                return;
            };

            // Wire all import callbacks.
            if (self.gossip_handler) |gh| {
                gh.importAttestationFn = &gossipImportAttestation;
                gh.importVoluntaryExitFn = &gossipImportVoluntaryExit;
                gh.importProposerSlashingFn = &gossipImportProposerSlashing;
                gh.importAttesterSlashingFn = &gossipImportAttesterSlashing;
                gh.importBlsChangeFn = &gossipImportBlsChange;
            }
        }

        /// Process gossip events from P2P service: parse topic, route to handler.
        fn processGossipEvents(self: *BeaconNode, p2p: anytype) void {
            const events = p2p.gossipsub.drainEvents() catch &.{};
            defer self.allocator.free(events);
            self.processGossipEventsFromSlice(events);
        }

        /// Process a slice of gossip events: parse topic, route to handler.
        ///
        /// For beacon_block: decompress, deserialize, import via STFN pipeline.
        /// For beacon_attestation / beacon_aggregate_and_proof: delegate to GossipHandler.
        fn processGossipEventsFromSlice(self: *BeaconNode, events: anytype) void {
            const gossip_topics_mod = networking.gossip_topics;
            const gossip_decoding = networking.gossip_decoding;

            for (events) |event| {
                switch (event) {
                    .message => |msg| {
                        // Parse the gossip topic to determine message type.
                        const parsed = gossip_topics_mod.parseTopic(msg.topic) orelse continue;

                        switch (parsed.topic_type) {
                            .beacon_block => {
                                self.handleGossipBlock(gossip_decoding, msg.data);
                            },
                            .data_column_sidecar => {
                                // Route data column sidecars through decompress + import.
                                self.handleGossipDataColumn(gossip_decoding, msg.data, parsed.subnet_id);
                            },
                            else => {
                                // Route all other topics through GossipHandler:
                                // attestations, aggregates, voluntary exits, slashings,
                                // BLS changes, sync committee messages/contributions, blob sidecars.
                                if (self.gossip_handler) |gh| {
                                    // Update clock state for validation using head tracker.
                                    {
                                        const slot = self.head_tracker.head_slot;
                                        gh.updateClock(slot, computeEpochAtSlot(slot), self.head_tracker.finalized_epoch * preset.SLOTS_PER_EPOCH);
                                    }
                                    gh.onGossipMessageWithSubnet(parsed.topic_type, parsed.subnet_id, msg.data) catch |err| {
                                        switch (err) {
                                            error.ValidationIgnored => {},
                                            error.ValidationRejected => {
                                                std.log.debug("Gossip {s} rejected", .{parsed.topic_type.topicName()});
                                            },
                                            error.DecodeFailed => {
                                                std.log.debug("Gossip {s} decode failed", .{parsed.topic_type.topicName()});
                                            },
                                            else => {
                                                std.log.warn("Gossip {s} error: {}", .{ parsed.topic_type.topicName(), err });
                                            },
                                        }
                                    };
                                }
                            },
                        }
                    },
                    else => {},
                }
            }
        }

        /// Handle a gossip beacon_block message: decompress, deserialize, import.
        fn handleGossipBlock(self: *BeaconNode, gossip_decoding: anytype, data: []const u8) void {
            const ssz_bytes = gossip_decoding.decompressGossipPayload(
                self.allocator, data,
            ) catch {
                std.log.warn("Gossip: failed to decompress block", .{});
                return;
            };
            defer self.allocator.free(ssz_bytes);

            const raw_fork_seq = self.config.forkSeq(self.head_tracker.head_slot);
            const fork_seq = if (@intFromEnum(raw_fork_seq) > @intFromEnum(config_mod.ForkSeq.electra))
                config_mod.ForkSeq.electra
            else
                raw_fork_seq;
            const any_signed = AnySignedBeaconBlock.deserialize(
                self.allocator, .full, fork_seq, ssz_bytes,
            ) catch |err| {
                std.log.warn("Gossip block deserialize: {}", .{err});
                return;
            };
            defer any_signed.deinit(self.allocator);

            switch (any_signed) {
                .full_electra => |blk| {
                    const result = self.importBlock(blk) catch |err| {
                        if (err == error.UnknownParentBlock) {
                            self.queueOrphanBlock(blk, ssz_bytes);
                        } else if (err != error.BlockAlreadyKnown and err != error.BlockAlreadyFinalized) {
                            std.log.warn("Gossip block import: {}", .{err});
                        }
                        return;
                    };
                    self.processPendingChildren(result.block_root);
                    std.log.info("GOSSIP BLOCK IMPORTED slot={d} root={x:0>2}{x:0>2}{x:0>2}{x:0>2}...", .{
                        result.slot,
                        result.block_root[0], result.block_root[1],
                        result.block_root[2], result.block_root[3],
                    });
                },
                else => {},
            }
        }

        /// Handle a gossip data_column_sidecar message: decompress, validate, import.
        fn handleGossipDataColumn(self: *BeaconNode, gossip_decoding_mod: anytype, data: []const u8, subnet_id: ?u8) void {
            _ = subnet_id;
            const ssz_bytes = gossip_decoding_mod.decompressGossipPayload(
                self.allocator, data,
            ) catch {
                std.log.warn("Gossip: failed to decompress data column sidecar", .{});
                return;
            };
            defer self.allocator.free(ssz_bytes);

            // Extract block root and column index from the sidecar.
            // DataColumnSidecar layout: index(8) + variable fields...
            // The signed_block_header is at offset after column, kzg_commitments, kzg_proofs.
            // For validation we need the slot and proposer from the block header.
            // Since this is a variable-size container, we'll store the raw bytes
            // and do minimal validation for now.
            if (ssz_bytes.len < 8) {
                std.log.warn("Gossip: data column sidecar too short", .{});
                return;
            }

            const column_index = std.mem.readInt(u64, ssz_bytes[0..8], .little);

            // Use a synthetic block root for now (slot-based).
            // Full HTR would require decoding the signed_block_header.
            var block_root: [32]u8 = std.mem.zeroes([32]u8);
            @memcpy(block_root[0..8], ssz_bytes[0..8]);

            // Store the sidecar
            self.importDataColumnSidecar(block_root, column_index, ssz_bytes) catch |err| {
                std.log.warn("Gossip data column import error: {}", .{err});
            };
        }

        /// Request blocks by range from a connected peer via dialProtocol.
        ///
        /// Opens a stream for BeaconBlocksByRange/2, sends the range request,
        /// reads response chunks (each with context bytes + varint + snappy SSZ block),
        /// and imports each block.
        fn requestBlocksByRange(
            self: *BeaconNode,
            io: std.Io,
            svc: *networking.P2pService,
            peer_id: []const u8,
            start_slot: u64,
            count: u64,
        ) !u64 {
            const protocol_id = "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy";
            const req_resp_encoding = networking.req_resp_encoding;

            var stream = try svc.dialProtocol(io, peer_id, protocol_id);

            // Encode the range request
            const request = networking.messages.BeaconBlocksByRangeRequest.Type{
                .start_slot = start_slot,
                .count = count,
                .step = 1,
            };
            var req_ssz: [networking.messages.BeaconBlocksByRangeRequest.fixed_size]u8 = undefined;
            _ = networking.messages.BeaconBlocksByRangeRequest.serializeIntoBytes(&request, &req_ssz);

            const wire_request = try req_resp_encoding.encodeRequest(self.allocator, &req_ssz);
            defer self.allocator.free(wire_request);

            // Write request
            var written: usize = 0;
            while (written < wire_request.len) {
                written += stream.write(io, wire_request[written..]) catch |err| {
                    std.log.warn("BlocksByRange write error: {}", .{err});
                    return err;
                };
            }

            std.log.info("BlocksByRange: requested slots {d}..{d}", .{ start_slot, start_slot + count - 1 });

            // Read response chunks from the stream using an accumulation buffer.
            // Multiple response chunks may arrive in a single read.
            var blocks_received: u64 = 0;
            var buf: [1024 * 1024]u8 = undefined;
            var buf_len: usize = 0;

            while (blocks_received < count) {
                // Read more data from the stream
                const n = stream.read(io, buf[buf_len..]) catch |err| {
                    std.log.info("BlocksByRange: stream ended after {d} blocks ({})", .{ blocks_received, err });
                    break;
                };
                if (n == 0) break;
                buf_len += n;

                // Process as many complete response chunks as possible
                while (buf_len > 0 and blocks_received < count) {
                    const decoded = req_resp_encoding.decodeResponseChunk(
                        self.allocator,
                        buf[0..buf_len],
                        true,
                    ) catch |err| {
                        if (err == error.InsufficientData) break;
                        std.log.warn("BlocksByRange: decode error: {}", .{err});
                        return blocks_received;
                    };

                    if (decoded.result != .success) {
                        self.allocator.free(decoded.ssz_bytes);
                        std.log.warn("BlocksByRange: error response: {}", .{decoded.result});
                        return blocks_received;
                    }

                    // Import block
                    {
                        defer self.allocator.free(decoded.ssz_bytes);
                        if (decoded.context_bytes) |ctx| {
                            std.log.info("BlocksByRange: block {d} ({d} bytes, fork={x:0>2}{x:0>2}{x:0>2}{x:0>2})", .{
                                blocks_received + 1, decoded.ssz_bytes.len, ctx[0], ctx[1], ctx[2], ctx[3],
                            });
                        }
                        // Cap fork_seq at electra for import — fulu blocks are structurally
                        // identical to electra and importBlock only handles electra type.
                        const raw_fork_seq = self.config.forkSeq(self.head_tracker.head_slot);
                        const fork_seq = if (@intFromEnum(raw_fork_seq) > @intFromEnum(config_mod.ForkSeq.electra))
                            config_mod.ForkSeq.electra
                        else
                            raw_fork_seq;
                        const any_signed = AnySignedBeaconBlock.deserialize(
                            self.allocator, .full, fork_seq, decoded.ssz_bytes,
                        ) catch |err| {
                            std.log.warn("BlocksByRange: deserialize error: {}", .{err});
                            blocks_received += 1;
                            continue;
                        };
                        defer any_signed.deinit(self.allocator);
                        switch (any_signed) {
                            .full_electra => |blk| {
                                const result = self.importBlock(blk) catch |err| {
                                    std.log.warn("BlocksByRange: import error at block {d}: {}", .{ blocks_received + 1, err });
                                    blocks_received += 1;
                                    continue;
                                };
                                std.log.info("BlocksByRange: imported slot {d} root={x:0>2}{x:0>2}{x:0>2}{x:0>2}...", .{
                                    result.slot,
                                    result.block_root[0], result.block_root[1],
                                    result.block_root[2], result.block_root[3],
                                });
                            },

                            else => {
                                std.log.warn("BlocksByRange: unsupported block fork variant, skipping", .{});
                            },
                        }
                    }
                    blocks_received += 1;

                    // Advance buffer past consumed bytes
                    const consumed = decoded.bytes_consumed;
                    if (consumed < buf_len) {
                        std.mem.copyForwards(u8, buf[0 .. buf_len - consumed], buf[consumed..buf_len]);
                        buf_len -= consumed;
                    } else {
                        buf_len = 0;
                    }
                }
            }

            std.log.info("BlocksByRange: received {d} blocks total", .{blocks_received});
            return blocks_received;
        }

        /// Queue an orphan block whose parent is not yet known.
    ///
    /// Computes the block root and stores the raw SSZ bytes in the
    /// UnknownBlockSync pending set. The parent will be fetched via
    /// BeaconBlocksByRoot during the next sync cycle.
    fn queueOrphanBlock(
        self: *BeaconNode,
        blk: *const types.electra.SignedBeaconBlock.Type,
        ssz_bytes: []const u8,
    ) void {
        // Compute the block root for dedup.
        var body_root: [32]u8 = undefined;
        types.electra.BeaconBlockBody.hashTreeRoot(
            self.allocator, &blk.message.body, &body_root,
        ) catch return;
        const hdr = types.phase0.BeaconBlockHeader.Type{
            .slot = blk.message.slot,
            .proposer_index = blk.message.proposer_index,
            .parent_root = blk.message.parent_root,
            .state_root = blk.message.state_root,
            .body_root = body_root,
        };
        var block_root: [32]u8 = undefined;
        types.phase0.BeaconBlockHeader.hashTreeRoot(&hdr, &block_root) catch return;

        const added = self.unknown_block_sync.addPendingBlock(
            block_root,
            blk.message.parent_root,
            blk.message.slot,
            ssz_bytes,
        ) catch return;

        if (added) {
            std.log.info("Queued orphan block slot={d} parent={s}... ({d} pending)", .{
                blk.message.slot,
                &std.fmt.bytesToHex(blk.message.parent_root[0..4], .lower),
                self.unknown_block_sync.pendingCount(),
            });
        }
    }

    /// After a block is successfully imported, check if any orphan children
    /// were waiting on it and try to import them.
    fn processPendingChildren(self: *BeaconNode, parent_root: [32]u8) void {
        const children = self.unknown_block_sync.onParentImported(parent_root) catch return;
        defer self.allocator.free(children);

        for (children) |child| {
            defer self.allocator.free(child.block_bytes);

            // Deserialize and import.
            const raw_fork_seq = self.config.forkSeq(self.head_tracker.head_slot);
            const fork_seq = if (@intFromEnum(raw_fork_seq) > @intFromEnum(config_mod.ForkSeq.electra))
                config_mod.ForkSeq.electra
            else
                raw_fork_seq;
            const any_signed = AnySignedBeaconBlock.deserialize(
                self.allocator, .full, fork_seq, child.block_bytes,
            ) catch |err| {
                std.log.warn("Failed to deserialize pending child: {}", .{err});
                continue;
            };
            defer any_signed.deinit(self.allocator);

            switch (any_signed) {
                .full_electra => |blk| {
                    const result = self.importBlock(blk) catch |err| {
                        std.log.warn("Failed to import pending child slot={d}: {}", .{ child.slot, err });
                        continue;
                    };
                    std.log.info("Imported pending child slot={d} root={s}...", .{
                        result.slot,
                        &std.fmt.bytesToHex(result.block_root[0..4], .lower),
                    });
                    // Recursively check for more children.
                    self.processPendingChildren(result.block_root);
                },
                else => {},
            }
        }
    }

    /// Notify the EL of the current fork choice and optionally trigger payload building.
    ///
    /// Called after each block import. Sends engine_forkchoiceUpdatedV3 with the
    /// current head/safe/finalized block hashes. If payload_attrs is provided
    /// (e.g., this node is the next proposer), also starts building a new payload.
    /// The returned payload_id is cached for later getPayload calls.
    fn notifyForkchoiceUpdate(self: *BeaconNode, new_head_root: [32]u8) !void {
        self.notifyForkchoiceUpdateWithAttrs(new_head_root, null) catch |err| {
            std.log.warn("forkchoiceUpdated failed: {}", .{err});
        };
    }

    /// Inner forkchoiceUpdated with optional payload attributes.
    fn notifyForkchoiceUpdateWithAttrs(
        self: *BeaconNode,
        new_head_root: [32]u8,
        payload_attrs: ?PayloadAttributesV3,
    ) !void {
        const engine = self.engine_api orelse return;
        const fc = self.fork_choice orelse return;

        // Head block hash: from the imported block's execution payload.
        const head_node = fc.getBlock(new_head_root);
        const head_block_hash = if (head_node) |node|
            node.extra_meta.executionPayloadBlockHash() orelse return
        else
            return;

        // Safe block hash: from the justified checkpoint's block.
        const justified_cp = fc.getJustifiedCheckpoint();
        const safe_block_hash = if (fc.getBlock(justified_cp.root)) |node|
            node.extra_meta.executionPayloadBlockHash() orelse std.mem.zeroes([32]u8)
        else
            std.mem.zeroes([32]u8);

        // Finalized block hash: from the finalized checkpoint's block.
        const finalized_cp = fc.getFinalizedCheckpoint();
        const finalized_block_hash = if (fc.getBlock(finalized_cp.root)) |node|
            node.extra_meta.executionPayloadBlockHash() orelse std.mem.zeroes([32]u8)
        else
            std.mem.zeroes([32]u8);

        const fcu_state = ForkchoiceStateV1{
            .head_block_hash = head_block_hash,
            .safe_block_hash = safe_block_hash,
            .finalized_block_hash = finalized_block_hash,
        };

        const result = engine.forkchoiceUpdated(fcu_state, payload_attrs) catch |err| {
            std.log.warn("engine_forkchoiceUpdatedV3 failed: {}", .{err});
            self.el_offline = true;
            self.api_sync_status.el_offline = true;
            return err;
        };

        // EL responded — mark as online.
        self.el_offline = false;
        self.api_sync_status.el_offline = false;

        // Cache payload_id if the EL started building a payload.
        if (result.payload_id) |pid| {
            self.cached_payload_id = pid;
            std.log.info("forkchoiceUpdated: payload building started, id={s}", .{
                &std.fmt.bytesToHex(pid[0..8], .lower),
            });
        }

        std.log.info("forkchoiceUpdated: status={s} head={s}... safe={s}... finalized={s}...", .{
            @tagName(result.payload_status.status),
            &std.fmt.bytesToHex(head_block_hash[0..4], .lower),
            &std.fmt.bytesToHex(safe_block_hash[0..4], .lower),
            &std.fmt.bytesToHex(finalized_block_hash[0..4], .lower),
        });
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
        const attrs = PayloadAttributesV3{
            .timestamp = timestamp,
            .prev_randao = prev_randao,
            .suggested_fee_recipient = fee_recipient,
            .withdrawals = withdrawals_slice,
            .parent_beacon_block_root = parent_beacon_block_root,
        };
        try self.notifyForkchoiceUpdateWithAttrs(self.head_tracker.head_root, attrs);
    }

    /// Retrieve the execution payload built by the EL via engine_getPayloadV3.
    ///
    /// Must be called after preparePayload() has been called and the EL returned
    /// a payload_id. Returns the complete execution payload, block value, and
    /// blobs bundle for inclusion in the beacon block.
    pub fn getExecutionPayload(self: *BeaconNode) !GetPayloadResponse {
        const engine = self.engine_api orelse return error.NoEngineApi;
        const payload_id = self.cached_payload_id orelse return error.NoPayloadId;

        const result = engine.getPayload(payload_id) catch |err| {
            std.log.warn("engine_getPayloadV3 failed: {}", .{err});
            self.el_offline = true;
            self.api_sync_status.el_offline = true;
            return err;
        };

        // EL responded — mark as online.
        self.el_offline = false;
        self.api_sync_status.el_offline = false;

        // Clear the cached payload_id — it's a one-shot.
        self.cached_payload_id = null;

        std.log.info("getPayload: block_number={d} block_value={d} txs={d} blobs={d}", .{
            result.execution_payload.block_number,
            @as(u64, @truncate(result.block_value)),
            result.execution_payload.transactions.len,
            result.blobs_bundle.blobs.len,
        });

        return result;
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
                .is_syncing = ss.state == .syncing,
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
        return produceBlockBody(self.allocator, slot, self.op_pool);
    }

    /// Build a StatusMessage reflecting the current chain state.
    ///
    /// Used for req/resp Status exchanges with peers.
    pub fn getStatus(self: *const BeaconNode) StatusMessage.Type {
        // Always use head_tracker which is updated during range sync import.
        // Fork choice head isn't reliably updated during batch import.
        _ = self.fork_choice; // suppress unused
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

    /// Handle an incoming req/resp request.
    ///
    /// Dispatches to the appropriate handler based on method. Uses the node's
    /// database and state to service the request.
    ///
    /// Uses the EngineApi vtable pattern: a `RequestContext` wrapping `*BeaconNode`
    /// and a scratch arena is passed as `ptr: *anyopaque` to each callback.
    /// The scratch arena holds temporary allocations (block bytes from DB) that
    /// are only needed until `handleRequest` copies them into response chunks.
    pub fn onReqResp(
        self: *BeaconNode,
        method: Method,
        request_bytes: []const u8,
    ) ![]const ResponseChunk {
        // Scratch arena: freed after handleRequest returns.
        // All DB-fetched byte slices live here; the handler copies them out.
        var scratch = std.heap.ArenaAllocator.init(self.allocator);
        defer scratch.deinit();

        var req_ctx = RequestContext{
            .node = self,
            .scratch = scratch.allocator(),
        };

        const ctx = ReqRespContext{
            .ptr = &req_ctx,
            .getStatus = &reqRespGetStatus,
            .getMetadata = &reqRespGetMetadata,
            .getPingSequence = &reqRespGetPingSequence,
            .getBlockByRoot = &reqRespGetBlockByRoot,
            .getBlocksByRange = &reqRespGetBlocksByRange,
            .getBlobByRoot = &reqRespGetBlobByRoot,
            .getBlobsByRange = &reqRespGetBlobsByRange,
            .getDataColumnByRoot = &reqRespGetDataColumnByRoot,
            .getDataColumnsByRange = &reqRespGetDataColumnsByRange,
            .getForkDigest = &reqRespGetForkDigest,
            .onGoodbye = &reqRespOnGoodbye,
            .onPeerStatus = &reqRespOnPeerStatus,
        };
        return handleRequest(self.allocator, method, request_bytes, &ctx);
    }
};

// ---------------------------------------------------------------------------
// Gossip callbacks — wired into GossipHandler as function pointers.
// These bridge the type-erased *anyopaque back to *BeaconNode.
//
// For ptr-free vtable functions (getProposerIndex, isKnownBlockRoot,
// getValidatorCount), we use a module-level node pointer set during
// initGossipHandler. This is safe because there is exactly one
// BeaconNode instance per process.
// ---------------------------------------------------------------------------

/// Module-level BeaconNode pointer for ptr-free gossip callbacks.
/// Set once in initGossipHandler, read by the static vtable functions below.
var gossip_node: ?*BeaconNode = null;

fn gossipImportBlockFromGossip(ptr: *anyopaque, block_bytes: []const u8) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    // Decompress is already done by GossipHandler; block_bytes are raw SSZ.
    const raw_fork_seq = node.config.forkSeq(node.head_tracker.head_slot);
    const fork_seq = if (@intFromEnum(raw_fork_seq) > @intFromEnum(config_mod.ForkSeq.electra))
        config_mod.ForkSeq.electra
    else
        raw_fork_seq;
    const any_signed = AnySignedBeaconBlock.deserialize(
        node.allocator, .full, fork_seq, block_bytes,
    ) catch |err| {
        std.log.warn("Gossip block import deserialize: {}", .{err});
        return err;
    };
    defer any_signed.deinit(node.allocator);

    switch (any_signed) {
        .full_electra => |blk| {
            const result = node.importBlock(blk) catch |err| {
                if (err == error.UnknownParentBlock) {
                    node.queueOrphanBlock(blk, block_bytes);
                } else if (err != error.BlockAlreadyKnown and err != error.BlockAlreadyFinalized) {
                    std.log.warn("Gossip block import: {}", .{err});
                }
                return err;
            };
            node.processPendingChildren(result.block_root);
            std.log.info("GOSSIP BLOCK IMPORTED (via handler) slot={d}", .{result.slot});
        },
        else => {},
    }
}

fn gossipGetProposerIndex(slot: u64) ?u32 {
    const node = gossip_node orelse return null;
    const head_state_root = node.head_tracker.head_state_root;
    const cached = node.block_state_cache.get(head_state_root) orelse return null;
    const proposer = cached.getBeaconProposer(slot) catch return null;
    return @intCast(proposer);
}

fn gossipIsKnownBlockRoot(root: [32]u8) bool {
    const node = gossip_node orelse return true;
    // Check head tracker slot→root map (bounded, ~SLOTS_PER_EPOCH entries).
    var it = node.head_tracker.slot_roots.iterator();
    while (it.next()) |entry| {
        if (std.mem.eql(u8, entry.value_ptr, &root)) return true;
    }
    // Also check fork choice if available.
    if (node.chain.fork_choice) |fc| {
        return fc.hasBlock(root);
    }
    return false;
}

fn gossipGetValidatorCount() u32 {
    const node = gossip_node orelse return 0;
    const head_state_root = node.head_tracker.head_state_root;
    const cached = node.block_state_cache.get(head_state_root) orelse return 0;
    return @intCast(cached.epoch_cache.index_to_pubkey.items.len);
}

/// Import a validated attestation into fork choice and op pool.
///
/// Called by GossipHandler after Phase 1 validation passes.
fn gossipImportAttestation(
    ptr: *anyopaque,
    attestation_slot: u64,
    committee_index: u64,
    target_root: [32]u8,
    target_epoch: u64,
    validator_index: u64,
    beacon_block_root: [32]u8,
    source_epoch: u64,
    source_root: [32]u8,
) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));

    // Build a minimal Attestation for the op pool.
    const att = types.phase0.Attestation.Type{
        .aggregation_bits = .{ .data = std.ArrayListUnmanaged(u8).empty, .bit_len = 0 },
        .data = .{
            .slot = attestation_slot,
            .index = committee_index,
            .beacon_block_root = beacon_block_root,
            .source = .{ .epoch = source_epoch, .root = source_root },
            .target = .{ .epoch = target_epoch, .root = target_root },
        },
        .signature = [_]u8{0} ** 96,
    };

    try node.chain.importAttestation(
        attestation_slot,
        committee_index,
        target_root,
        target_epoch,
        validator_index,
        att,
    );
}

/// Import a validated voluntary exit into the op pool.
fn gossipImportVoluntaryExit(ptr: *anyopaque, validator_index: u64, epoch: u64) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    const exit = types.phase0.SignedVoluntaryExit.Type{
        .message = .{
            .epoch = epoch,
            .validator_index = validator_index,
        },
        .signature = [_]u8{0} ** 96,
    };
    try node.chain.op_pool.voluntary_exit_pool.add(exit);
}

/// Import a validated proposer slashing from raw SSZ bytes into the op pool.
fn gossipImportProposerSlashing(ptr: *anyopaque, ssz_bytes: []const u8) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    var slashing: types.phase0.ProposerSlashing.Type = undefined;
    types.phase0.ProposerSlashing.deserializeFromBytes(ssz_bytes, &slashing) catch |err| {
        std.log.warn("Proposer slashing SSZ decode failed: {}", .{err});
        return err;
    };
    try node.chain.op_pool.proposer_slashing_pool.add(slashing);
}

/// Import a validated attester slashing from raw SSZ bytes into the op pool.
fn gossipImportAttesterSlashing(ptr: *anyopaque, ssz_bytes: []const u8) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    var slashing: types.phase0.AttesterSlashing.Type = undefined;
    types.phase0.AttesterSlashing.deserializeFromBytes(node.allocator, ssz_bytes, &slashing) catch |err| {
        std.log.warn("Attester slashing SSZ decode failed: {}", .{err});
        return err;
    };
    try node.chain.op_pool.attester_slashing_pool.add(slashing);
}

/// Import a validated BLS-to-execution change from raw SSZ bytes into the op pool.
fn gossipImportBlsChange(ptr: *anyopaque, ssz_bytes: []const u8) anyerror!void {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    var change: types.capella.SignedBLSToExecutionChange.Type = undefined;
    types.capella.SignedBLSToExecutionChange.deserializeFromBytes(ssz_bytes, &change) catch |err| {
        std.log.warn("BLS change SSZ decode failed: {}", .{err});
        return err;
    };
    try node.chain.op_pool.bls_change_pool.add(change);
}

// ---------------------------------------------------------------------------
// RequestContext — wraps *BeaconNode + scratch arena for req/resp callbacks.
//
// Lives on the stack of BeaconNode.onReqResp(). Each callback receives this
// as ptr: *anyopaque and casts it back to access the node and scratch allocator.
// ---------------------------------------------------------------------------

const RequestContext = struct {
    node: *BeaconNode,
    /// Scratch allocator for temporary DB-fetched bytes.
    /// Freed by the arena after handleRequest returns.
    scratch: Allocator,
};

// ---------------------------------------------------------------------------
// Real ReqRespContext callbacks — cast ptr to *RequestContext, then read node.
// ---------------------------------------------------------------------------

fn reqRespGetStatus(ptr: *anyopaque) StatusMessage.Type {
    const ctx: *RequestContext = @ptrCast(@alignCast(ptr));
    const node = ctx.node;
    return .{
        .fork_digest = node.config.forkDigestAtSlot(node.head_tracker.head_slot, node.genesis_validators_root),
        .finalized_root = node.head_tracker.getBlockRoot(
            node.head_tracker.finalized_epoch * preset.SLOTS_PER_EPOCH,
        ) orelse [_]u8{0} ** 32,
        .finalized_epoch = node.head_tracker.finalized_epoch,
        .head_root = node.head_tracker.head_root,
        .head_slot = node.head_tracker.head_slot,
    };
}

fn reqRespGetMetadata(ptr: *anyopaque) networking.messages.MetadataV2.Type {
    _ = ptr;
    return .{
        .seq_number = 0,
        .attnets = .{ .data = std.mem.zeroes([8]u8) },
        .syncnets = .{ .data = std.mem.zeroes([1]u8) },
    };
}

fn reqRespGetPingSequence(ptr: *anyopaque) u64 {
    _ = ptr;
    return 0;
}

/// Look up a block by root. Returns a scratch-backed copy of the SSZ bytes,
/// or null if the block is not in the DB.
fn reqRespGetBlockByRoot(ptr: *anyopaque, root: [32]u8) ?[]const u8 {
    const ctx: *RequestContext = @ptrCast(@alignCast(ptr));
    const node = ctx.node;

    // getBlock allocates with node.allocator; copy to scratch then free.
    const maybe_bytes = node.db.getBlock(root) catch return null;
    const bytes = maybe_bytes orelse return null;
    defer node.allocator.free(bytes);

    const copy = ctx.scratch.alloc(u8, bytes.len) catch return null;
    @memcpy(copy, bytes);
    return copy;
}

/// Returns blocks for a slot range. Each element is scratch-backed SSZ bytes.
/// Iterates slots, looks up block roots from HeadTracker, then fetches from DB.
fn reqRespGetBlocksByRange(ptr: *anyopaque, start_slot: u64, count: u64) []const []const u8 {
    const ctx: *RequestContext = @ptrCast(@alignCast(ptr));
    const node = ctx.node;

    var results: std.ArrayList([]const u8) = .empty;
    // No defer deinit — scratch arena owns the memory.

    var slot: u64 = start_slot;
    while (slot < start_slot + count) : (slot += 1) {
        const root = node.head_tracker.getBlockRoot(slot) orelse continue;
        const maybe_bytes = node.db.getBlock(root) catch continue;
        const bytes = maybe_bytes orelse continue;
        defer node.allocator.free(bytes);

        const copy = ctx.scratch.alloc(u8, bytes.len) catch continue;
        @memcpy(copy, bytes);
        results.append(ctx.scratch, copy) catch continue;
    }

    return results.toOwnedSlice(ctx.scratch) catch &.{};
}

fn reqRespGetBlobByRoot(ptr: *anyopaque, root: [32]u8, index: u64) ?[]const u8 {
    const ctx: *RequestContext = @ptrCast(@alignCast(ptr));
    const node = ctx.node;

    // TODO: Per-index lookup requires deserializing the stored blob sidecar list.
    // For now, return the full sidecars blob only when index == 0.
    if (index != 0) return null;

    const maybe_bytes = node.db.getBlobSidecars(root) catch return null;
    const bytes = maybe_bytes orelse return null;
    defer node.allocator.free(bytes);

    const copy = ctx.scratch.alloc(u8, bytes.len) catch return null;
    @memcpy(copy, bytes);
    return copy;
}

fn reqRespGetDataColumnByRoot(ptr: *anyopaque, root: [32]u8, index: u64) ?[]const u8 {
    const ctx: *RequestContext = @ptrCast(@alignCast(ptr));
    const node = ctx.node;

    const maybe_bytes = node.db.getDataColumn(root, index) catch return null;
    const bytes = maybe_bytes orelse return null;
    defer node.allocator.free(bytes);

    const copy = ctx.scratch.alloc(u8, bytes.len) catch return null;
    @memcpy(copy, bytes);
    return copy;
}

fn reqRespGetDataColumnsByRange(ptr: *anyopaque, start_slot: u64, count: u64) []const []const u8 {
    const ctx: *RequestContext = @ptrCast(@alignCast(ptr));
    const node = ctx.node;

    var results: std.ArrayList([]const u8) = .empty;

    var slot: u64 = start_slot;
    while (slot < start_slot + count) : (slot += 1) {
        const root = node.head_tracker.getBlockRoot(slot) orelse continue;
        // Return all stored columns for this slot's block.
        var col_idx: u64 = 0;
        while (col_idx < 128) : (col_idx += 1) {
            const maybe_bytes = node.db.getDataColumn(root, col_idx) catch continue;
            const bytes = maybe_bytes orelse continue;
            defer node.allocator.free(bytes);

            const copy = ctx.scratch.alloc(u8, bytes.len) catch continue;
            @memcpy(copy, bytes);
            results.append(ctx.scratch, copy) catch continue;
        }
    }

    return results.toOwnedSlice(ctx.scratch) catch &.{};
}

fn reqRespGetBlobsByRange(ptr: *anyopaque, start_slot: u64, count: u64) []const []const u8 {
    const ctx: *RequestContext = @ptrCast(@alignCast(ptr));
    const node = ctx.node;

    var results: std.ArrayList([]const u8) = .empty;
    // No defer deinit — scratch arena owns the memory.

    var slot: u64 = start_slot;
    while (slot < start_slot + count) : (slot += 1) {
        const root = node.head_tracker.getBlockRoot(slot) orelse continue;
        const maybe_bytes = node.db.getBlobSidecars(root) catch continue;
        const bytes = maybe_bytes orelse continue;
        defer node.allocator.free(bytes);

        const copy = ctx.scratch.alloc(u8, bytes.len) catch continue;
        @memcpy(copy, bytes);
        results.append(ctx.scratch, copy) catch continue;
    }

    return results.toOwnedSlice(ctx.scratch) catch &.{};
}

fn reqRespGetForkDigest(ptr: *anyopaque, slot: u64) [4]u8 {
    const ctx: *RequestContext = @ptrCast(@alignCast(ptr));
    const node = ctx.node;
    return node.config.forkDigestAtSlot(slot, node.genesis_validators_root);
}

fn reqRespOnGoodbye(ptr: *anyopaque, reason: u64) void {
    _ = ptr;
    _ = reason;
    // TODO: log in future.
}

fn reqRespOnPeerStatus(ptr: *anyopaque, status: StatusMessage.Type) void {
    const ctx: *RequestContext = @ptrCast(@alignCast(ptr));
    if (ctx.node.sync_controller) |sc| {
        sc.onPeerConnected("unknown", status) catch |err| {
            std.log.warn("SyncController.onPeerConnected failed: {}", .{err});
        };
    }
}


// ---------------------------------------------------------------------------
// BlockImportCallbackCtx + importBlockCallback
// — glue between ApiContext.BlockImportCallback and BlockImporter
// ---------------------------------------------------------------------------

/// Wraps a BlockImporter pointer together with the BeaconConfig needed to
/// compute the active fork for SSZ deserialization. One instance per node,
/// owned by BeaconNode alongside api_context.
pub const BlockImportCallbackCtx = struct {
    importer: *BlockImporter,
    beacon_config: *const BeaconConfig,
};

// ---------------------------------------------------------------------------
// HeadStateCallbackCtx + getHeadStateCallback
// — glue between ApiContext.HeadStateCallback and BlockStateCache
// ---------------------------------------------------------------------------

/// Wraps the block_state_cache and head_tracker so the API layer can
/// retrieve the current head CachedBeaconState without a direct dep on
/// the full BeaconNode type.
pub const HeadStateCallbackCtx = struct {
    block_state_cache: *BlockStateCache,
    head_tracker: *HeadTracker,
};

/// API-layer head state callback.
///
/// Returns the CachedBeaconState for the current head state root, or null
/// if the state is not in the cache.
fn getHeadStateCallback(ptr: *anyopaque) ?*CachedBeaconState {
    const ctx: *HeadStateCallbackCtx = @ptrCast(@alignCast(ptr));
    return ctx.block_state_cache.get(ctx.head_tracker.head_state_root);
}

/// API-layer block import callback.
///
/// Receives raw SSZ bytes from the submitBlock handler, deserializes them
/// into the active-fork SignedBeaconBlock, and forwards to
/// BlockImporter.importBlock. Supports electra and older forks via
/// AnySignedBeaconBlock.
fn importBlockCallback(ptr: *anyopaque, block_bytes: []const u8) anyerror!void {
    const cb_ctx: *BlockImportCallbackCtx = @ptrCast(@alignCast(ptr));
    const importer = cb_ctx.importer;
    const allocator = importer.allocator;

    // Infer fork from head slot.
    const head_slot = importer.head_tracker.head_slot;
    const fork_seq = cb_ctx.beacon_config.forkSeq(head_slot);

    const any_signed = try AnySignedBeaconBlock.deserialize(allocator, .full, fork_seq, block_bytes);
    defer any_signed.deinit(allocator);

    // Dispatch to importBlock. BlockImporter accepts electra blocks;
    // for pre-electra forks we fall through to UnsupportedFork (future work).
    switch (any_signed) {
        .full_electra => |blk| _ = try importer.importBlock(blk),
        .full_fulu => |blk| {
            const electra_blk: *const types.electra.SignedBeaconBlock.Type = @ptrCast(blk);
            _ = try importer.importBlock(electra_blk);
        },
        else => return error.UnsupportedFork,
    }
}

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
    // finalized/justified epochs come from the genesis state; not necessarily 0
    // as long as the fork choice was properly initialized with the state's checkpoints.
    _ = head.finalized_epoch;
    _ = head.justified_epoch;

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

test "BeaconNode: onReqResp Status returns real head slot and root" {
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

    // Directly advance the head tracker to simulate an imported block.
    const expected_root = [_]u8{0xAB} ** 32;
    const expected_slot: u64 = 42;
    const state_root = [_]u8{0x11} ** 32;
    try node.head_tracker.onBlock(expected_root, expected_slot, state_root);

    // Build a dummy status request (peer's status — doesn't affect our response).
    const peer_status = StatusMessage.Type{
        .fork_digest = [_]u8{0} ** 4,
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .head_root = [_]u8{0} ** 32,
        .head_slot = 0,
    };
    var buf: [StatusMessage.fixed_size]u8 = undefined;
    _ = StatusMessage.serializeIntoBytes(&peer_status, &buf);

    const chunks = try node.onReqResp(.status, &buf);
    defer freeResponseChunks(allocator, chunks);

    try std.testing.expectEqual(@as(usize, 1), chunks.len);
    try std.testing.expectEqual(networking.protocol.ResponseCode.success, chunks[0].result);

    // Decode response and verify it reflects the real head state.
    var resp: StatusMessage.Type = undefined;
    try StatusMessage.deserializeFromBytes(chunks[0].ssz_payload, &resp);
    try std.testing.expectEqual(expected_slot, resp.head_slot);
    try std.testing.expectEqualSlices(u8, &expected_root, &resp.head_root);
}

test "BeaconNode: onReqResp BeaconBlocksByRoot returns stored block" {
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

    // Store a fake block in the DB.
    const known_root = [_]u8{0xCC} ** 32;
    const fake_block_bytes = [_]u8{0x01, 0x02, 0x03, 0x04} ** 8; // 32 bytes of fake SSZ
    try node.db.putBlock(known_root, &fake_block_bytes);

    // Also store a second block for extra coverage.
    const known_root_2 = [_]u8{0xDD} ** 32;
    const fake_block_bytes_2 = [_]u8{0x05, 0x06} ** 16;
    try node.db.putBlock(known_root_2, &fake_block_bytes_2);

    // Build request: 2 known roots + 1 unknown.
    const unknown_root = [_]u8{0xFF} ** 32;
    var request_bytes: [32 * 3]u8 = undefined;
    @memcpy(request_bytes[0..32], &known_root);
    @memcpy(request_bytes[32..64], &unknown_root);
    @memcpy(request_bytes[64..96], &known_root_2);

    const chunks = try node.onReqResp(.beacon_blocks_by_root, &request_bytes);
    defer freeResponseChunks(allocator, chunks);

    // Should return 2 chunks (unknown root silently skipped).
    try std.testing.expectEqual(@as(usize, 2), chunks.len);
    try std.testing.expectEqual(networking.protocol.ResponseCode.success, chunks[0].result);
    try std.testing.expectEqual(networking.protocol.ResponseCode.success, chunks[1].result);

    // Verify payloads match stored bytes.
    try std.testing.expectEqualSlices(u8, &fake_block_bytes, chunks[0].ssz_payload);
    try std.testing.expectEqualSlices(u8, &fake_block_bytes_2, chunks[1].ssz_payload);
}

test "BeaconNode: onReqResp Ping returns sequence 0" {
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

    // Send peer seq = 7.
    const peer_seq: networking.messages.Ping.Type = 7;
    var buf: [networking.messages.Ping.fixed_size]u8 = undefined;
    _ = networking.messages.Ping.serializeIntoBytes(&peer_seq, &buf);

    const chunks = try node.onReqResp(.ping, &buf);
    defer freeResponseChunks(allocator, chunks);

    try std.testing.expectEqual(@as(usize, 1), chunks.len);
    try std.testing.expectEqual(networking.protocol.ResponseCode.success, chunks[0].result);

    // Decode response sequence number — should be 0 (our current ping seq).
    var resp_seq: networking.messages.Ping.Type = undefined;
    try networking.messages.Ping.deserializeFromBytes(chunks[0].ssz_payload, &resp_seq);
    try std.testing.expectEqual(@as(u64, 0), resp_seq);
}

test "BeaconNode: onReqResp BeaconBlocksByRange returns blocks for known slots" {
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

    // Simulate two imported blocks at slots 10 and 11.
    const root_10 = [_]u8{0x10} ** 32;
    const root_11 = [_]u8{0x11} ** 32;
    const block_10 = [_]u8{0xAA} ** 20;
    const block_11 = [_]u8{0xBB} ** 20;

    try node.head_tracker.onBlock(root_10, 10, [_]u8{0} ** 32);
    try node.head_tracker.onBlock(root_11, 11, [_]u8{0} ** 32);
    try node.db.putBlock(root_10, &block_10);
    try node.db.putBlock(root_11, &block_11);

    // Request range [10, 3): slots 10, 11, 12. Slot 12 has no block.
    const request = networking.messages.BeaconBlocksByRangeRequest.Type{
        .start_slot = 10,
        .count = 3,
        .step = 1,
    };
    var buf: [networking.messages.BeaconBlocksByRangeRequest.fixed_size]u8 = undefined;
    _ = networking.messages.BeaconBlocksByRangeRequest.serializeIntoBytes(&request, &buf);

    const chunks = try node.onReqResp(.beacon_blocks_by_range, &buf);
    defer freeResponseChunks(allocator, chunks);

    // Only slots 10 and 11 have blocks; slot 12 is skipped.
    try std.testing.expectEqual(@as(usize, 2), chunks.len);
    try std.testing.expectEqualSlices(u8, &block_10, chunks[0].ssz_payload);
    try std.testing.expectEqualSlices(u8, &block_11, chunks[1].ssz_payload);
}

test "BeaconNode: importBlobSidecar and onReqResp BlobSidecarsByRoot returns stored blob" {
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

    // Store a fake blob sidecar blob via importBlobSidecar.
    const blob_root = [_]u8{0xBB} ** 32;
    const fake_blob_bytes = [_]u8{0xDE, 0xAD, 0xBE, 0xEF} ** 8;
    try node.importBlobSidecar(blob_root, &fake_blob_bytes);

    // Build a BlobSidecarsByRoot request: [root, index=0] pair.
    // The wire format for BlobSidecarsByRoot is a list of (root[32], index u64) pairs.
    var request_bytes: [32 + 8]u8 = undefined;
    @memcpy(request_bytes[0..32], &blob_root);
    std.mem.writeInt(u64, request_bytes[32..40], 0, .little); // index = 0

    const chunks = try node.onReqResp(.blob_sidecars_by_root, &request_bytes);
    defer freeResponseChunks(allocator, chunks);

    // Should return 1 chunk with the stored blob bytes.
    try std.testing.expectEqual(@as(usize, 1), chunks.len);
    try std.testing.expectEqual(networking.protocol.ResponseCode.success, chunks[0].result);
    try std.testing.expectEqualSlices(u8, &fake_blob_bytes, chunks[0].ssz_payload);
}

test "BeaconNode: importBlobSidecar index != 0 returns null" {
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

    // Store blob sidecar data.
    const blob_root = [_]u8{0xCC} ** 32;
    const fake_blob_bytes = [_]u8{0x01, 0x02, 0x03} ** 10;
    try node.importBlobSidecar(blob_root, &fake_blob_bytes);

    // Request index = 1 — should return no chunks (null skipped by handleRequest).
    var request_bytes: [32 + 8]u8 = undefined;
    @memcpy(request_bytes[0..32], &blob_root);
    std.mem.writeInt(u64, request_bytes[32..40], 1, .little); // index = 1

    const chunks = try node.onReqResp(.blob_sidecars_by_root, &request_bytes);
    defer freeResponseChunks(allocator, chunks);

    // index != 0: not returned (TODO: per-index deserialisation).
    try std.testing.expectEqual(@as(usize, 0), chunks.len);
}

test "BeaconNode: onReqResp BlobSidecarsByRange returns stored blobs" {
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

    // Register block roots for slots 5 and 6.
    const root_5 = [_]u8{0x05} ** 32;
    const root_6 = [_]u8{0x06} ** 32;
    try node.head_tracker.onBlock(root_5, 5, [_]u8{0} ** 32);
    try node.head_tracker.onBlock(root_6, 6, [_]u8{0} ** 32);

    // Store blob sidecars for both blocks.
    const blob_5 = [_]u8{0xA5} ** 16;
    const blob_6 = [_]u8{0xA6} ** 16;
    try node.importBlobSidecar(root_5, &blob_5);
    try node.importBlobSidecar(root_6, &blob_6);

    // Request range [5, 3): slots 5, 6, 7. Slot 7 has no blobs.
    const request = networking.messages.BlobSidecarsByRangeRequest.Type{
        .start_slot = 5,
        .count = 3,
    };
    var buf: [networking.messages.BlobSidecarsByRangeRequest.fixed_size]u8 = undefined;
    _ = networking.messages.BlobSidecarsByRangeRequest.serializeIntoBytes(&request, &buf);

    const chunks = try node.onReqResp(.blob_sidecars_by_range, &buf);
    defer freeResponseChunks(allocator, chunks);

    // Slots 5 and 6 have blobs; slot 7 has no block root → skipped.
    try std.testing.expectEqual(@as(usize, 2), chunks.len);
    try std.testing.expectEqualSlices(u8, &blob_5, chunks[0].ssz_payload);
    try std.testing.expectEqualSlices(u8, &blob_6, chunks[1].ssz_payload);
}

test "BeaconNode: archiveState stores state bytes in DB and retrieves them" {
    const TreeNode = @import("persistent_merkle_tree").Node;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try TreeNode.Pool.init(allocator, pool_size);
    defer pool.deinit();

    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    const node = try BeaconNode.init(allocator, test_state.cached_state.config, .{});
    defer node.deinit();

    // Place a state in the block cache with a known state root.
    const state = try test_state.cached_state.clone(allocator, .{});
    const state_root = try node.state_regen.onNewBlock(state, true);

    const slot: u64 = 32; // epoch 1 boundary

    // archiveState should serialize and store it.
    try node.archiveState(slot, state_root);

    // Verify the archive holds bytes for this slot.
    const retrieved = try node.db.getStateArchive(slot);
    try std.testing.expect(retrieved != null);
    if (retrieved) |bytes| {
        allocator.free(bytes);
    }
}

test "BeaconNode: archiveState is no-op for unknown state root" {
    const TreeNode = @import("persistent_merkle_tree").Node;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try TreeNode.Pool.init(allocator, pool_size);
    defer pool.deinit();

    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    const node = try BeaconNode.init(allocator, test_state.cached_state.config, .{});
    defer node.deinit();

    const missing_root = [_]u8{0xff} ** 32;
    // Should not error — state not found in cache is silently skipped.
    try node.archiveState(64, missing_root);

    // Nothing stored.
    const retrieved = try node.db.getStateArchive(64);
    try std.testing.expectEqual(@as(?[]const u8, null), retrieved);
}
