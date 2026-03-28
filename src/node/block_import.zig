//! BlockImporter: full block import pipeline (STFN → fork choice → persist → head).
//!
//! Extracted from beacon_node.zig. Owns:
//! - State transition + caching
//! - Execution payload verification via Engine API
//! - Fork choice update
//! - Block persistence in BeaconDB
//! - HeadTracker updates

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;
const state_transition = @import("state_transition");
const bls_mod = @import("bls");
const BatchVerifier = bls_mod.BatchVerifier;
const BlsThreadPool = bls_mod.ThreadPool;
const CachedBeaconState = state_transition.CachedBeaconState;
const BlockStateCache = state_transition.BlockStateCache;
const CheckpointStateCache = state_transition.CheckpointStateCache;
const StateRegen = state_transition.StateRegen;
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const db_mod = @import("db");
const BeaconDB = db_mod.BeaconDB;
const chain_mod = @import("chain");
pub const HeadTracker = chain_mod.HeadTracker;
pub const ImportResult = chain_mod.ImportResult;
const ImportError = chain_mod.ImportError;
const fork_choice_mod = @import("fork_choice");
const ForkChoice = fork_choice_mod.ForkChoiceStruct;
const ProtoBlock = fork_choice_mod.ProtoBlock;
const BlockExtraMeta = fork_choice_mod.BlockExtraMeta;
const LVHExecResponse = fork_choice_mod.LVHExecResponse;
const execution_mod = @import("execution");
const ExecutionPayloadStatus = execution_mod.ExecutionPayloadStatus;
const EngineApi = execution_mod.EngineApi;
const constants = @import("constants");
const Sha256 = std.crypto.hash.sha2.Sha256;
const fork_types = @import("fork_types");
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;

const metrics_mod = @import("metrics.zig");
const BeaconMetrics = metrics_mod.BeaconMetrics;

/// Dummy JustifiedBalancesGetter — returns empty balances.
/// Used for fork choice initialization; replace with real getter once
/// state regen cache integration is complete.
fn dummyBalancesGetterFn(_: ?*anyopaque, _: fork_choice_mod.CheckpointWithPayloadStatus, _: *CachedBeaconState) fork_choice_mod.JustifiedBalances {
    return fork_choice_mod.JustifiedBalances.init(std.heap.page_allocator);
}

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

    /// Optional BLS thread pool for parallel batch signature verification.
    /// When set, BatchVerifier dispatches to multiple threads (~3-10x speedup).
    /// Initialized by BeaconNode.setIo() once std.Io is available.
    bls_thread_pool: ?*BlsThreadPool = null,

    /// Optional metrics pointer for execution layer timing.
    metrics: ?*BeaconMetrics = null,

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

        // Use onBlockFromState for proper checkpoint extraction,
        // unrealized checkpoint computation, proposer boost, and target root.
        if (self.fork_choice) |fc| {
            // Map execution status to fork choice types.
            const fc_exec_status: fork_choice_mod.ExecutionStatus = switch (execution_status) {
                .valid => .valid,
                .syncing, .accepted => .syncing,
                .invalid, .invalid_block_hash => .invalid,
            };
            const fc_da_status: fork_choice_mod.DataAvailabilityStatus = if (self.isDataAvailableFn != null)
                (if (self.isDataAvailableFn.?(stfn_result.block_root)) .available else .pre_data)
            else
                .pre_data;

            // Build execution metadata.
            const extra_meta: BlockExtraMeta = switch (execution_status) {
                .valid, .syncing, .accepted => .{
                    .post_merge = BlockExtraMeta.PostMergeMeta.init(
                        signed_block.message.body.execution_payload.block_hash,
                        signed_block.message.body.execution_payload.block_number,
                        fc_exec_status,
                        fc_da_status,
                    ),
                },
                else => .{ .pre_merge = {} },
            };

            // Advance fork choice clock to at least the block's slot.
            if (block_slot > fc.getTime()) {
                fc.updateTime(self.allocator, block_slot) catch {};
            }

            _ = fork_choice_mod.onBlockFromState(
                fc,
                self.allocator,
                block_slot,
                stfn_result.block_root,
                parent_root,
                stfn_result.state_root,
                post_state,
                0, // block_delay_sec: 0 = timely (real delay tracking is TODO)
                fc.getTime(),
                extra_meta,
            ) catch |err| {
                std.log.warn("ForkChoice.onBlockFromState failed for slot {d}: {}", .{ block_slot, err });
            };
        }

        return .{
            .block_root = stfn_result.block_root,
            .state_root = stfn_result.state_root,
            .slot = block_slot,
            .epoch_transition = is_epoch_transition,
            .execution_optimistic = execution_status == .syncing or execution_status == .accepted,
        };
    }

    /// Verify the block's execution payload via the Engine API.
    fn verifyExecutionPayload(
        self: *BlockImporter,
        signed_block: *const types.electra.SignedBeaconBlock.Type,
        block_root: [32]u8,
    ) !ExecutionPayloadStatus {
        const engine = self.engine_api orelse return .valid;

        const payload = &signed_block.message.body.execution_payload;

        const ssz_txs = payload.transactions.items;
        const tx_slices = try self.allocator.alloc([]const u8, ssz_txs.len);
        defer self.allocator.free(tx_slices);
        for (ssz_txs, 0..) |tx, i| {
            tx_slices[i] = tx.items;
        }

        const commitments = signed_block.message.body.blob_kzg_commitments.items;
        const versioned_hashes = try self.allocator.alloc([32]u8, commitments.len);
        defer self.allocator.free(versioned_hashes);
        for (commitments, 0..) |commitment, i| {
            Sha256.hash(&commitment, &versioned_hashes[i], .{});
            versioned_hashes[i][0] = constants.VERSIONED_HASH_VERSION_KZG;
        }

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
            if (self.metrics) |m| m.execution_errors_total.incr();
            return .syncing;
        };

        if (self.metrics) |m| {
            switch (result.status) {
                .valid => m.execution_payload_valid_total.incr(),
                .invalid => m.execution_payload_invalid_total.incr(),
                .syncing, .accepted => m.execution_payload_syncing_total.incr(),
                else => {},
            }
        }

        std.log.info("Engine API newPayload slot {d}: status={s}", .{
            signed_block.message.slot, @tagName(result.status),
        });

        if (result.status == .invalid or result.status == .invalid_block_hash) {
            if (self.fork_choice) |fc| {
                const lvh_response = LVHExecResponse{
                    .invalid = .{
                        .latest_valid_exec_hash = result.latest_valid_hash,
                        .invalidate_from_parent_block_root = signed_block.message.parent_root,
                    },
                };
                fc.validateLatestHash(self.allocator, lvh_response, signed_block.message.slot);
                std.log.warn("Marked fork choice branch as INVALID: block_root={s}... lvh={s}", .{
                    &std.fmt.bytesToHex(block_root[0..4], .lower),
                    if (result.latest_valid_hash) |h| &std.fmt.bytesToHex(h[0..4], .lower) else "null",
                });
            }
        }

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
                        var batch = BatchVerifier.init(self.bls_thread_pool);
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

        if (!std.mem.eql(u8, &state_root, &signed_block.message.state_root)) {
            std.log.warn("STFN state_root mismatch at slot {d}: ours={s}... block={s}...", .{
                block_slot,
                &std.fmt.bytesToHex(state_root[0..8], .lower),
                &std.fmt.bytesToHex(signed_block.message.state_root[0..8], .lower),
            });
        } else {
            std.log.info("STFN state_root MATCHES at slot {d}", .{block_slot});
        }

        var br_body_root: [32]u8 = undefined;
        try types.electra.BeaconBlockBody.hashTreeRoot(self.allocator, &signed_block.message.body, &br_body_root);
        const hdr = types.phase0.BeaconBlockHeader.Type{
            .slot = block_slot,
            .proposer_index = signed_block.message.proposer_index,
            .parent_root = signed_block.message.parent_root,
            .state_root = state_root,
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
