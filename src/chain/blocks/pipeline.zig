//! Block import pipeline orchestrator.
//!
//! This is the main entry point for block processing. It runs all stages
//! in sequence, threading the output of each stage to the next:
//!
//! 1. verifySanity       — slot bounds, parent known, not duplicate
//! 2. getPreState        — retrieve pre-state via cache lookup
//! 3. verifyDA           — check data availability status
//! 4. stateTransition    — run STFN (includes batch sig verification)
//! 5. verifyExecution    — engine_newPayload (or optimistic)
//! 6. importBlock        — fork choice, DB, caches, notifications
//!
//! Each stage can fail independently. Early stages are cheap (microseconds),
//! later stages are expensive (state transition: ~100ms, EL call: ~50ms).
//!
//! For batch processing (range sync), blocks are processed sequentially
//! because each block's post-state is the next block's pre-state.
//!
//! Reference: Lodestar chain/blocks/index.ts (processBlocks)
//!           + chain/blocks/verifyBlock.ts (verifyBlocksInEpoch)

const std = @import("std");
const Allocator = std.mem.Allocator;
const BlsThreadPool = @import("bls").ThreadPool;

const consensus_types = @import("consensus_types");
const preset = @import("preset").preset;
const state_transition = @import("state_transition");
const regen_mod = @import("../regen/root.zig");
const CachedBeaconState = state_transition.CachedBeaconState;
const StateGraphGate = regen_mod.StateGraphGate;
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const SeenEpochValidators = @import("../seen_epoch_validators.zig").SeenEpochValidators;
const fork_choice_mod = @import("fork_choice");
const ForkChoice = fork_choice_mod.ForkChoiceStruct;

const pipeline_types = @import("types.zig");
const BlockInput = pipeline_types.BlockInput;
const ImportBlockOpts = pipeline_types.ImportBlockOpts;
const VerifiedBlock = pipeline_types.VerifiedBlock;
const ImportResult = pipeline_types.ImportResult;
const BatchBlockResult = pipeline_types.BatchBlockResult;
const ExecutionStatus = pipeline_types.ExecutionStatus;
const DataAvailabilityStatus = pipeline_types.DataAvailabilityStatus;
const BlockImportError = pipeline_types.BlockImportError;
const LVHExecResponse = fork_choice_mod.LVHExecResponse;

const verify_sanity = @import("verify_sanity.zig");
const SanityOutcome = verify_sanity.SanityOutcome;
const verify_da = @import("verify_data_availability.zig");
const execute_stf = @import("execute_state_transition.zig");
const verify_exec = @import("verify_execution.zig");
const ExecutionPort = @import("../ports/execution.zig").ExecutionPort;
const import_block = @import("import_block.zig");
const ImportContext = import_block.ImportContext;

const QueuedStateRegen = regen_mod.QueuedStateRegen;
const StateRegen = regen_mod.StateRegen;
const HeadTracker = @import("../block_import.zig").HeadTracker;
const ReprocessQueue = @import("../reprocess.zig").ReprocessQueue;

const Slot = consensus_types.primitive.Slot.Type;

// ---------------------------------------------------------------------------
// Pipeline context — everything needed to process a block
// ---------------------------------------------------------------------------

/// Pipeline configuration and dependencies.
///
/// Created once by the Chain and reused for each block import.
/// Contains references to all chain components needed by the pipeline.
///
/// Relationship to ImportContext (P1-9 note):
/// `ImportContext` is a strict subset of `PipelineContext`. The import stage
/// (import_block.zig) only needs the fields that appear in ImportContext —
/// it doesn't need `execution_port` (handled before import) or
/// `current_slot` (used only for sanity/DA checks). The conversion via
/// `toImportContext()` is intentional: it gives the import stage a focused
/// interface and avoids import_block.zig depending on the full pipeline type
/// (which would create a circular import). If import_block gains new deps,
/// they should be added to ImportContext and toImportContext(), not to the
/// full PipelineContext.
pub const PipelineContext = struct {
    allocator: Allocator,

    // -- State management --
    block_state_cache: *regen_mod.BlockStateCache,
    state_regen: *regen_mod.StateRegen,
    queued_regen: *QueuedStateRegen,

    // -- Fork choice --
    fork_choice: *ForkChoice,

    // -- Persistence --
    db: *@import("db").BeaconDB,

    // -- Head tracking --
    head_tracker: *HeadTracker,

    // -- Block root → state root mapping --
    block_to_state: *std.AutoArrayHashMap([32]u8, [32]u8),

    // -- Validator liveness caches --
    seen_block_attesters: *SeenEpochValidators,
    seen_block_proposers: *SeenEpochValidators,

    // -- Chain notifications --
    notification_sink: ?@import("../types.zig").NotificationSink,

    // -- Execution verification (optional) --
    execution_port: ?ExecutionPort,

    // -- Clock --
    current_slot: Slot,

    // -- Shared PMT mutation --
    state_graph_gate: *StateGraphGate,

    // -- BLS verification --
    block_bls_thread_pool: ?*BlsThreadPool = null,

    // -- Reprocessing -- (P1-10 fix)
    /// When set, blocks pending reprocessing are notified after successful import.
    reprocess_queue: ?*ReprocessQueue = null,

    // -- Finality callback -- (W2 fix)
    on_finalized_ptr: ?*anyopaque = null,
    on_finalized_fn: ?*const fn (ptr: *anyopaque, finalized_epoch: u64, finalized_root: [32]u8) void = null,

    /// Convert to ImportContext for the import stage.
    pub fn toImportContext(self: PipelineContext) ImportContext {
        return .{
            .allocator = self.allocator,
            .block_state_cache = self.block_state_cache,
            .queued_regen = self.queued_regen,
            .fork_choice = self.fork_choice,
            .db = self.db,
            .head_tracker = self.head_tracker,
            .block_to_state = self.block_to_state,
            .seen_block_attesters = self.seen_block_attesters,
            .seen_block_proposers = self.seen_block_proposers,
            .notification_sink = self.notification_sink,
            .reprocess_queue = self.reprocess_queue,
            .on_finalized_ptr = self.on_finalized_ptr,
            .on_finalized_fn = self.on_finalized_fn,
        };
    }
};

// ---------------------------------------------------------------------------
// Single block processing
// ---------------------------------------------------------------------------

pub const PlannedBlockImport = struct {
    block_input: BlockInput,
    parent_block_root: [32]u8,
    parent_state_root: [32]u8,
    pre_state: ?*CachedBeaconState,
    parent_slot: Slot,
    data_availability_status: DataAvailabilityStatus,
    precomputed_body_root: ?[32]u8,
    opts: ImportBlockOpts,

    pub fn deinit(self: *PlannedBlockImport, allocator: Allocator) void {
        self.block_input.block.deinit(allocator);
        self.* = undefined;
    }
};

pub const PreparedBlockImport = struct {
    block_input: BlockInput,
    post_state: *CachedBeaconState,
    block_root: [32]u8,
    state_root: [32]u8,
    parent_slot: Slot,
    data_availability_status: DataAvailabilityStatus,
    proposer_balance_delta: i64,
    opts: ImportBlockOpts,

    pub fn deinit(self: *PreparedBlockImport, allocator: Allocator) void {
        self.block_input.block.deinit(allocator);
        self.post_state.deinit();
        allocator.destroy(self.post_state);
        self.* = undefined;
    }
};

pub const BlockPlanResult = union(enum) {
    skipped: struct {
        result: ImportResult,
        reason: BlockImportError,
    },
    planned: PlannedBlockImport,
};

/// Process a single block through the full import pipeline.
///
/// This is the main entry point for gossip blocks and API submissions.
/// Runs all stages sequentially, returning the import result or error.
///
/// The error type is fine-grained so callers can react appropriately:
/// - ParentUnknown → trigger unknown block sync
/// - AlreadyKnown → ignore (with appropriate opts)
/// - InvalidSignature → reject and penalize peer
/// - DataUnavailable → quarantine and wait
pub fn processBlock(
    ctx: PipelineContext,
    block_input: BlockInput,
    opts: ImportBlockOpts,
) BlockImportError!ImportResult {
    const plan_result = try planBlockForImport(ctx, block_input, opts);
    return switch (plan_result) {
        .skipped => |skip| skip.result,
        .planned => |planned| {
            const prepared = try executePlannedBlockImport(
                ctx.allocator,
                ctx.state_regen,
                ctx.state_graph_gate,
                ctx.block_bls_thread_pool,
                planned,
            );
            const exec_status = try verify_exec.verifyExecutionPayload(
                ctx.allocator,
                prepared.block_input,
                ctx.execution_port,
                prepared.opts,
            );
            return finishPreparedBlockImport(ctx, prepared, exec_status);
        },
    };
}

pub fn planBlockForImport(
    ctx: PipelineContext,
    block_input: BlockInput,
    opts: ImportBlockOpts,
) BlockImportError!BlockPlanResult {
    const fc = ctx.fork_choice;

    // Stage 1: Sanity checks.
    // Note: verifySanity uses fork_choice for parent lookup. If the fork choice
    // doesn't have the parent (e.g., early in sync or for test states), the parent
    // check will fail. The block_to_state map is the authoritative fallback.
    const sanity_outcome = try verify_sanity.verifySanity(
        ctx.allocator,
        block_input,
        fc,
        ctx.current_slot,
        ctx.block_to_state,
        opts,
    );

    switch (sanity_outcome) {
        .skipped => |reason| {
            // Block was intentionally skipped (ignore_if_known/finalized).
            // Return a synthetic result plus the concrete skip reason.
            var block_root: [32]u8 = undefined;
            block_input.block.beaconBlock().hashTreeRoot(ctx.allocator, &block_root) catch
                return BlockImportError.InternalError;
            return .{ .skipped = .{
                .result = ImportResult{
                    .block_root = block_root,
                    .state_root = [_]u8{0} ** 32,
                    .slot = block_input.block.beaconBlock().slot(),
                    .epoch_transition = false,
                    .execution_optimistic = false,
                },
                .reason = reason,
            } };
        },
        .valid => |sanity| {
            const parent_state_root = ctx.block_to_state.get(sanity.parent_root) orelse
                return BlockImportError.PrestateMissing;
            // Stage 2: Fast pre-state cache lookup only.
            // Cold-path regen/replay now runs in executePlannedBlockImport so it
            // can be offloaded to the state worker.
            const pre_state = getCachedPreState(ctx, parent_state_root, sanity.block_slot) catch
                return BlockImportError.InternalError;

            // Stage 3: Data availability check.
            const da_status = try verify_da.verifyDataAvailability(block_input, opts);

            return .{ .planned = .{
                .block_input = block_input,
                .parent_block_root = sanity.parent_root,
                .parent_state_root = parent_state_root,
                .pre_state = pre_state,
                .parent_slot = sanity.parent_slot,
                .data_availability_status = da_status,
                .precomputed_body_root = sanity.body_root,
                .opts = opts,
            } };
        },
    }
}

pub fn executePlannedBlockImport(
    allocator: Allocator,
    state_regen: *StateRegen,
    state_graph_gate: *StateGraphGate,
    block_bls_thread_pool: ?*BlsThreadPool,
    planned: PlannedBlockImport,
) BlockImportError!PreparedBlockImport {
    var owned_pre_state: ?*CachedBeaconState = null;
    defer if (owned_pre_state) |state| {
        state_regen.destroyTransientState(state);
    };

    const pre_state = planned.pre_state orelse blk: {
        const cold_state = state_regen.loadPreStateUncached(
            planned.parent_block_root,
            planned.parent_state_root,
            planned.block_input.block.beaconBlock().slot(),
        ) catch return BlockImportError.PrestateMissing;
        owned_pre_state = cold_state;
        break :blk cold_state;
    };

    const stf_result = try execute_stf.executeStateTransition(
        allocator,
        planned.block_input,
        pre_state,
        planned.data_availability_status,
        planned.opts,
        planned.precomputed_body_root,
        state_graph_gate,
        block_bls_thread_pool,
    );
    return .{
        .block_input = planned.block_input,
        .post_state = stf_result.post_state,
        .block_root = stf_result.block_root,
        .state_root = stf_result.state_root,
        .parent_slot = planned.parent_slot,
        .data_availability_status = planned.data_availability_status,
        .proposer_balance_delta = stf_result.proposer_balance_delta,
        .opts = planned.opts,
    };
}

pub fn finishPreparedBlockImport(
    ctx: PipelineContext,
    prepared: PreparedBlockImport,
    exec_status: ExecutionStatus,
) BlockImportError!ImportResult {
    const verified = VerifiedBlock{
        .block_input = prepared.block_input,
        .post_state = prepared.post_state,
        .block_root = prepared.block_root,
        .state_root = prepared.state_root,
        .parent_slot = prepared.parent_slot,
        .execution_status = exec_status,
        .data_availability_status = prepared.data_availability_status,
        .proposer_balance_delta = prepared.proposer_balance_delta,
    };

    return import_block.importVerifiedBlock(ctx.toImportContext(), verified, prepared.opts);
}

/// Process a batch of blocks through the pipeline (for range sync).
///
/// Blocks are processed sequentially — each block's post-state becomes
/// the next block's pre-state context (via state cache).
///
/// Individual block failures don't abort the batch. The caller receives
/// a result per block and decides how to handle failures.
pub fn processBlockBatch(
    ctx: PipelineContext,
    block_inputs: []const BlockInput,
    opts: ImportBlockOpts,
) std.mem.Allocator.Error![]BatchBlockResult {
    if (block_inputs.len == 0) return &[_]BatchBlockResult{};

    const results = try ctx.allocator.alloc(BatchBlockResult, block_inputs.len);
    errdefer ctx.allocator.free(results);

    // Range sync opts: typically ignore_if_known and ignore_if_finalized.
    var batch_opts = opts;
    batch_opts.ignore_if_known = true;
    batch_opts.ignore_if_finalized = true;

    for (block_inputs, 0..) |block_input, i| {
        const plan_result = planBlockForImport(ctx, block_input, batch_opts) catch |err| {
            results[i] = classifyBatchError(err);
            continue;
        };

        switch (plan_result) {
            .skipped => |skip| {
                results[i] = .{ .skipped = skip.reason };
            },
            .planned => |planned| {
                const prepared = executePlannedBlockImport(
                    ctx.allocator,
                    ctx.state_regen,
                    ctx.state_graph_gate,
                    ctx.block_bls_thread_pool,
                    planned,
                ) catch |err| {
                    results[i] = classifyBatchError(err);
                    continue;
                };
                const exec_result = verify_exec.verifyExecutionPayloadDetailed(
                    ctx.allocator,
                    prepared.block_input,
                    ctx.execution_port,
                    prepared.opts,
                ) catch |err| {
                    results[i] = classifyBatchError(err);
                    continue;
                };

                switch (exec_result) {
                    .valid, .syncing, .pre_merge => {
                        results[i] = processPreparedBatchBlock(
                            ctx,
                            prepared,
                            exec_result.status(),
                        );
                    },
                    .invalid => |invalid| {
                        invalidateExecutionBranch(
                            ctx,
                            invalid.latest_valid_hash,
                            invalid.invalidate_from_parent_block_root,
                        );
                        results[i] = .{ .failed = BlockImportError.ExecutionPayloadInvalid };
                        for (i + 1..block_inputs.len) |j| {
                            results[j] = .{ .failed = BlockImportError.ExecutionPayloadInvalid };
                        }
                        break;
                    },
                }
            },
        }
    }

    return results;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn processPreparedBatchBlock(
    ctx: PipelineContext,
    prepared: PreparedBlockImport,
    exec_status: ExecutionStatus,
) BatchBlockResult {
    const result = finishPreparedBlockImport(ctx, prepared, exec_status) catch |err| switch (err) {
        BlockImportError.AlreadyKnown,
        BlockImportError.WouldRevertFinalizedSlot,
        BlockImportError.GenesisBlock,
        => return .{ .skipped = err },
        else => return .{ .failed = err },
    };
    return .{ .success = result };
}

fn classifyBatchError(err: BlockImportError) BatchBlockResult {
    return switch (err) {
        BlockImportError.AlreadyKnown,
        BlockImportError.WouldRevertFinalizedSlot,
        BlockImportError.GenesisBlock,
        => .{ .skipped = err },
        else => .{ .failed = err },
    };
}

fn invalidateExecutionBranch(
    ctx: PipelineContext,
    latest_valid_hash: ?[32]u8,
    invalidate_from_parent_block_root: [32]u8,
) void {
    const fc = ctx.fork_choice;
    fc.validateLatestHash(ctx.allocator, LVHExecResponse{ .invalid = .{
        .latest_valid_exec_hash = latest_valid_hash,
        .invalidate_from_parent_block_root = invalidate_from_parent_block_root,
    } }, fc.getTime());
    _ = fc.updateAndGetHead(ctx.allocator, .get_canonical_head) catch {};
}

/// Get the cached pre-state for a block without falling through to replay.
fn getCachedPreState(
    ctx: PipelineContext,
    parent_state_root: [32]u8,
    block_slot: Slot,
) !?*CachedBeaconState {
    return ctx.queued_regen.getCachedPreState(parent_state_root, block_slot);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "PipelineContext struct compiles" {
    _ = PipelineContext;
}

test "BatchBlockResult union layout" {
    const result = BatchBlockResult{ .skipped = BlockImportError.AlreadyKnown };
    try std.testing.expect(result == .skipped);
}
