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
const scoped_log = std.log.scoped(.pipeline);

const consensus_types = @import("consensus_types");
const preset = @import("preset").preset;
const ssz = @import("ssz");
const state_transition = @import("state_transition");
const regen_mod = @import("../regen/root.zig");
const CachedBeaconState = state_transition.CachedBeaconState;
const StateGraphGate = regen_mod.StateGraphGate;
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const SeenEpochValidators = @import("../seen_epoch_validators.zig").SeenEpochValidators;
const fork_choice_mod = @import("fork_choice");
const fork_types = @import("fork_types");
const ForkChoice = fork_choice_mod.ForkChoiceStruct;
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;

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
    io: std.Io,

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
    block_to_state: *std.array_hash_map.Auto([32]u8, [32]u8),

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
            .state_graph_gate = self.state_graph_gate,
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
    parent_slot: Slot,
    data_availability_status: DataAvailabilityStatus,
    precomputed_body_root: ?[32]u8,
    opts: ImportBlockOpts,

    pub fn deinit(self: *PlannedBlockImport, allocator: Allocator) void {
        self.block_input.block.deinit(allocator);
        self.* = undefined;
    }
};

pub const StateTransitionJob = struct {
    planned: PlannedBlockImport,
    transient_pre_state: *CachedBeaconState,

    pub fn deinit(self: *StateTransitionJob, allocator: Allocator, state_regen: *StateRegen) void {
        self.planned.deinit(allocator);
        state_regen.destroyTransientState(self.transient_pre_state);
        self.* = undefined;
    }

    pub fn releasePlanned(self: *StateTransitionJob) PlannedBlockImport {
        const planned = self.planned;
        self.planned = undefined;
        self.transient_pre_state = undefined;
        self.* = undefined;
        return planned;
    }
};

pub const PreparedBlockImport = struct {
    block_input: BlockInput,
    post_state: *CachedBeaconState,
    owns_post_state: bool = true,
    block_root: [32]u8,
    state_root: [32]u8,
    parent_slot: Slot,
    data_availability_status: DataAvailabilityStatus,
    proposer_balance_delta: i64,
    opts: ImportBlockOpts,

    pub fn deinit(self: *PreparedBlockImport, allocator: Allocator) void {
        self.block_input.block.deinit(allocator);
        if (self.owns_post_state) {
            self.post_state.deinit();
            allocator.destroy(self.post_state);
        }
        self.* = undefined;
    }

    pub fn relinquishPostState(self: *PreparedBlockImport) void {
        self.owns_post_state = false;
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
            var owned_planned = planned;
            var planned_consumed = false;
            errdefer if (!planned_consumed) owned_planned.deinit(ctx.allocator);
            const pre_state = try getPlannedBlockImportPreState(ctx, owned_planned);
            var prepared = try executePlannedBlockImport(
                ctx.allocator,
                ctx.io,
                ctx.state_graph_gate,
                ctx.block_bls_thread_pool,
                &owned_planned,
                pre_state,
            );
            planned_consumed = true;
            defer prepared.deinit(ctx.allocator);
            const exec_status = try verify_exec.verifyExecutionPayload(
                ctx.allocator,
                prepared.block_input,
                ctx.execution_port,
                prepared.opts,
            );
            return finishPreparedBlockImport(ctx, &prepared, exec_status);
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
            const parent_state_root = (getParentStateRoot(ctx, sanity.parent_root) catch
                return BlockImportError.InternalError) orelse
                return BlockImportError.PrestateMissing;
            // Stage 2: Fast pre-state cache lookup only.
            // Cold misses are resolved through queued regen immediately before
            // execution so cache publication stays on the chain side.
            _ = getCachedPreState(ctx, sanity.parent_root, parent_state_root, sanity.parent_slot, sanity.block_slot) catch
                return BlockImportError.InternalError;

            // Stage 3: Data availability check.
            const da_status = try verify_da.verifyDataAvailability(block_input, opts);

            return .{ .planned = .{
                .block_input = block_input,
                .parent_block_root = sanity.parent_root,
                .parent_state_root = parent_state_root,
                .parent_slot = sanity.parent_slot,
                .data_availability_status = da_status,
                .precomputed_body_root = sanity.body_root,
                .opts = opts,
            } };
        },
    }
}

pub fn getPlannedBlockImportPreState(
    ctx: PipelineContext,
    planned: PlannedBlockImport,
) BlockImportError!*CachedBeaconState {
    return ctx.queued_regen.getPreState(
        planned.parent_block_root,
        planned.parent_state_root,
        planned.parent_slot,
        planned.block_input.block.beaconBlock().slot(),
        .block_import,
    ) catch |err| switch (err) {
        error.NoPreStateAvailable => BlockImportError.PrestateMissing,
        else => blk: {
            scoped_log.warn(
                "queued pre-state resolution failed parent_slot={d} block_slot={d}: {}",
                .{ planned.parent_slot, planned.block_input.block.beaconBlock().slot(), err },
            );
            break :blk BlockImportError.InternalError;
        },
    };
}

pub fn executePlannedBlockImport(
    allocator: Allocator,
    io: std.Io,
    state_graph_gate: *StateGraphGate,
    block_bls_thread_pool: ?*BlsThreadPool,
    planned: *PlannedBlockImport,
    pre_state: *CachedBeaconState,
) BlockImportError!PreparedBlockImport {
    const stf_result = try execute_stf.executeStateTransition(
        allocator,
        io,
        planned.block_input,
        pre_state,
        planned.data_availability_status,
        planned.opts,
        planned.precomputed_body_root,
        state_graph_gate,
        block_bls_thread_pool,
    );

    const block_input = planned.block_input;
    const parent_slot = planned.parent_slot;
    const data_availability_status = planned.data_availability_status;
    const opts = planned.opts;
    planned.* = undefined;

    return .{
        .block_input = block_input,
        .post_state = stf_result.post_state,
        .block_root = stf_result.block_root,
        .state_root = stf_result.state_root,
        .parent_slot = parent_slot,
        .data_availability_status = data_availability_status,
        .proposer_balance_delta = stf_result.proposer_balance_delta,
        .opts = opts,
    };
}

pub fn captureStateTransitionJob(
    allocator: Allocator,
    state_graph_gate: *StateGraphGate,
    planned: PlannedBlockImport,
    pre_state: *CachedBeaconState,
) BlockImportError!StateTransitionJob {
    var state_graph_lease = state_graph_gate.acquire();
    defer state_graph_lease.release();

    const transient_pre_state = pre_state.clone(allocator, .{
        .transfer_cache = false,
    }) catch |err| {
        scoped_log.warn(
            "failed to clone queued pre-state parent_slot={d} block_slot={d}: {}",
            .{ planned.parent_slot, planned.block_input.block.beaconBlock().slot(), err },
        );
        return BlockImportError.InternalError;
    };
    return .{
        .planned = planned,
        .transient_pre_state = transient_pre_state,
    };
}

pub fn executeStateTransitionJob(
    allocator: Allocator,
    io: std.Io,
    state_regen: *StateRegen,
    state_graph_gate: *StateGraphGate,
    block_bls_thread_pool: ?*BlsThreadPool,
    job: *StateTransitionJob,
) BlockImportError!PreparedBlockImport {
    const transient_pre_state = job.transient_pre_state;
    defer {
        state_regen.destroyTransientState(transient_pre_state);
        job.transient_pre_state = undefined;
    }

    return executePlannedBlockImport(
        allocator,
        io,
        state_graph_gate,
        block_bls_thread_pool,
        &job.planned,
        transient_pre_state,
    );
}

pub fn finishPreparedBlockImport(
    ctx: PipelineContext,
    prepared: *PreparedBlockImport,
    exec_status: ExecutionStatus,
) BlockImportError!ImportResult {
    return finishPreparedBlockImportWithFn(import_block.importVerifiedBlock, ctx.toImportContext(), prepared, exec_status);
}

fn finishPreparedBlockImportWithFn(
    comptime import_fn: anytype,
    import_ctx: ImportContext,
    prepared: *PreparedBlockImport,
    exec_status: ExecutionStatus,
) BlockImportError!ImportResult {
    var verified = VerifiedBlock{
        .block_input = prepared.block_input,
        .post_state = prepared.post_state,
        .owns_post_state = prepared.owns_post_state,
        .block_root = prepared.block_root,
        .state_root = prepared.state_root,
        .parent_slot = prepared.parent_slot,
        .execution_status = exec_status,
        .data_availability_status = prepared.data_availability_status,
        .proposer_balance_delta = prepared.proposer_balance_delta,
    };
    defer prepared.owns_post_state = verified.owns_post_state;

    return import_fn(import_ctx, &verified, prepared.opts);
}

/// Process a batch of blocks through the pipeline (for range sync).
///
/// Blocks are processed sequentially — each block's post-state becomes
/// the next block's pre-state context (via state cache).
///
/// Ignored blocks (`already known`, `would revert finalized`, `genesis`) may
/// be skipped, but the first real failure aborts the rest of the linear
/// segment to match Lodestar's chain-segment semantics.
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
            if (pipeline_types.shouldAbortLinearRangeSyncSegment(err)) {
                fillRemainingFailedBatchResults(results, i + 1, err);
                break;
            }
            continue;
        };

        switch (plan_result) {
            .skipped => |skip| {
                results[i] = .{ .skipped = skip.reason };
            },
            .planned => |planned| {
                var owned_planned = planned;
                const pre_state = getPlannedBlockImportPreState(ctx, owned_planned) catch |err| {
                    owned_planned.deinit(ctx.allocator);
                    results[i] = classifyBatchError(err);
                    if (pipeline_types.shouldAbortLinearRangeSyncSegment(err)) {
                        fillRemainingFailedBatchResults(results, i + 1, err);
                        break;
                    }
                    continue;
                };
                var prepared = executePlannedBlockImport(
                    ctx.allocator,
                    ctx.io,
                    ctx.state_graph_gate,
                    ctx.block_bls_thread_pool,
                    &owned_planned,
                    pre_state,
                ) catch |err| {
                    owned_planned.deinit(ctx.allocator);
                    results[i] = classifyBatchError(err);
                    if (pipeline_types.shouldAbortLinearRangeSyncSegment(err)) {
                        fillRemainingFailedBatchResults(results, i + 1, err);
                        break;
                    }
                    continue;
                };
                const exec_result = verify_exec.verifyExecutionPayloadDetailed(
                    ctx.allocator,
                    prepared.block_input,
                    ctx.execution_port,
                    prepared.opts,
                ) catch |err| {
                    prepared.deinit(ctx.allocator);
                    results[i] = classifyBatchError(err);
                    if (pipeline_types.shouldAbortLinearRangeSyncSegment(err)) {
                        fillRemainingFailedBatchResults(results, i + 1, err);
                        break;
                    }
                    continue;
                };

                switch (exec_result) {
                    .valid, .syncing, .pre_merge => {
                        const batch_result = processPreparedBatchBlock(
                            ctx,
                            prepared,
                            exec_result.status(),
                        );
                        results[i] = batch_result;
                        switch (batch_result) {
                            .failed => |err| {
                                fillRemainingFailedBatchResults(results, i + 1, err);
                                break;
                            },
                            else => {},
                        }
                    },
                    .invalid => |invalid| {
                        prepared.deinit(ctx.allocator);
                        invalidateExecutionBranch(
                            ctx,
                            invalid.latest_valid_hash,
                            invalid.invalidate_from_parent_block_root,
                        );
                        const err = BlockImportError.ExecutionPayloadInvalid;
                        results[i] = .{ .failed = err };
                        fillRemainingFailedBatchResults(results, i + 1, err);
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
    var owned_prepared = prepared;
    defer owned_prepared.deinit(ctx.allocator);
    const result = finishPreparedBlockImport(ctx, &owned_prepared, exec_status) catch |err| switch (err) {
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

fn fillRemainingFailedBatchResults(results: []BatchBlockResult, start: usize, err: BlockImportError) void {
    for (start..results.len) |j| {
        results[j] = .{ .failed = err };
    }
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
    parent_block_root: [32]u8,
    parent_state_root: [32]u8,
    parent_slot: Slot,
    block_slot: Slot,
) !?*CachedBeaconState {
    return ctx.queued_regen.getCachedPreState(
        parent_block_root,
        parent_state_root,
        parent_slot,
        block_slot,
    );
}

fn getParentStateRoot(ctx: PipelineContext, parent_root: [32]u8) !?[32]u8 {
    if (ctx.block_to_state.get(parent_root)) |state_root| return state_root;

    const block_bytes = try readPersistedBlockBytes(ctx, parent_root) orelse return null;
    defer ctx.allocator.free(block_bytes);

    return deserializeSignedBlockStateRoot(ctx, block_bytes);
}

fn readPersistedBlockBytes(ctx: PipelineContext, root: [32]u8) !?[]const u8 {
    if (try ctx.db.getBlock(root)) |block_bytes| return block_bytes;
    return ctx.db.getBlockArchiveByRoot(root);
}

fn deserializeSignedBlockStateRoot(ctx: PipelineContext, block_bytes: []const u8) !?[32]u8 {
    if (block_bytes.len < 108) return null;

    const slot = std.mem.readInt(u64, block_bytes[100..108], .little);
    const fork_seq = ctx.state_regen.shared_state_graph.config.forkSeq(slot);
    const any_signed = try AnySignedBeaconBlock.deserialize(ctx.allocator, .full, fork_seq, block_bytes);
    defer any_signed.deinit(ctx.allocator);

    return any_signed.beaconBlock().stateRoot().*;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const RegenRuntimeFixture = @import("../regen/test_fixture.zig").RegenRuntimeFixture;

test "PipelineContext struct compiles" {
    _ = PipelineContext;
}

test "BatchBlockResult union layout" {
    const result = BatchBlockResult{ .skipped = BlockImportError.AlreadyKnown };
    try std.testing.expect(result == .skipped);
}

test "StateTransitionJob executes with transient worker-owned pre-state" {
    const allocator = std.testing.allocator;
    defer state_transition.deinitStateTransition();

    var fixture = try RegenRuntimeFixture.init(allocator, 64);
    defer fixture.deinit();

    const parent_state_root = try fixture.seedHeadState();
    const pre_state = fixture.block_cache.get(parent_state_root).?;

    var latest_header = try fixture.published_state.state.latestBlockHeader();
    const parent_block_root = (try latest_header.hashTreeRoot()).*;
    const parent_slot = try fixture.published_state.state.slot();
    const target_slot = parent_slot + 1;

    var generation_state = try fixture.clonePublishedState();
    defer {
        generation_state.deinit();
        allocator.destroy(generation_state);
    }
    try state_transition.processSlots(allocator, generation_state, target_slot, .{});

    const signed_block = try createTestSignedBlock(allocator, generation_state, target_slot);

    const planned = PlannedBlockImport{
        .block_input = .{
            .block = .{ .full_electra = signed_block },
            .source = .gossip,
            .da_status = .available,
        },
        .parent_block_root = parent_block_root,
        .parent_state_root = parent_state_root,
        .parent_slot = parent_slot,
        .data_availability_status = .available,
        .precomputed_body_root = null,
        .opts = .{
            .skip_future_slot = true,
            .skip_signatures = true,
        },
    };

    var job = try captureStateTransitionJob(
        allocator,
        fixture.shared_state_graph.gate,
        planned,
        pre_state,
    );
    try std.testing.expect(job.transient_pre_state != pre_state);

    var prepared = try executeStateTransitionJob(
        allocator,
        std.testing.io,
        fixture.regen,
        fixture.shared_state_graph.gate,
        null,
        &job,
    );
    defer prepared.deinit(allocator);

    try std.testing.expectEqual(target_slot, prepared.block_input.block.beaconBlock().slot());
    try std.testing.expectEqual(parent_slot, prepared.parent_slot);
}

test "finishPreparedBlockImport preserves ownership transfer on error" {
    const dummy_import = struct {
        fn run(
            _: ImportContext,
            verified: *VerifiedBlock,
            _: ImportBlockOpts,
        ) BlockImportError!ImportResult {
            std.debug.assert(verified.owns_post_state);
            verified.relinquishPostState();
            return BlockImportError.NotViableForHead;
        }
    }.run;

    var prepared = PreparedBlockImport{
        .block_input = undefined,
        .post_state = undefined,
        .owns_post_state = true,
        .block_root = [_]u8{0} ** 32,
        .state_root = [_]u8{0} ** 32,
        .parent_slot = 0,
        .data_availability_status = .available,
        .proposer_balance_delta = 0,
        .opts = .{},
    };

    const import_ctx = ImportContext{
        .allocator = std.testing.allocator,
        .block_state_cache = undefined,
        .queued_regen = undefined,
        .state_graph_gate = undefined,
        .fork_choice = undefined,
        .db = undefined,
        .head_tracker = undefined,
        .block_to_state = undefined,
        .seen_block_attesters = undefined,
        .seen_block_proposers = undefined,
        .notification_sink = null,
        .reprocess_queue = null,
        .on_finalized_ptr = null,
        .on_finalized_fn = null,
    };

    try std.testing.expectError(
        BlockImportError.NotViableForHead,
        finishPreparedBlockImportWithFn(dummy_import, import_ctx, &prepared, .valid),
    );
    try std.testing.expect(!prepared.owns_post_state);
}

fn createTestSignedBlock(
    allocator: Allocator,
    cached_state: *CachedBeaconState,
    target_slot: Slot,
) !*consensus_types.electra.SignedBeaconBlock.Type {
    const state = cached_state.state;
    const epoch_cache = cached_state.epoch_cache;

    const proposer_index = epoch_cache.getBeaconProposer(target_slot) catch 0;
    var latest_header = try state.latestBlockHeader();
    const parent_root = try latest_header.hashTreeRoot();

    const genesis_time = try state.genesisTime();
    const seconds_per_slot = cached_state.config.chain.SECONDS_PER_SLOT;
    const expected_timestamp = genesis_time + target_slot * seconds_per_slot;

    var execution_payload = consensus_types.electra.ExecutionPayload.default_value;
    execution_payload.timestamp = expected_timestamp;
    const latest_block_hash = state.latestExecutionPayloadHeaderBlockHash() catch &([_]u8{0} ** 32);
    execution_payload.parent_hash = latest_block_hash.*;

    const current_epoch = state_transition.computeEpochAtSlot(target_slot);
    const randao_mix = try state_transition.getRandaoMix(
        .electra,
        state.castToFork(.electra),
        current_epoch,
    );
    execution_payload.prev_randao = randao_mix.*;

    const signed_block = try allocator.create(consensus_types.electra.SignedBeaconBlock.Type);
    errdefer allocator.destroy(signed_block);

    signed_block.* = .{
        .message = .{
            .slot = target_slot,
            .proposer_index = proposer_index,
            .parent_root = parent_root.*,
            .state_root = [_]u8{0} ** 32,
            .body = .{
                .randao_reveal = [_]u8{0} ** 96,
                .eth1_data = consensus_types.phase0.Eth1Data.default_value,
                .graffiti = [_]u8{0} ** 32,
                .proposer_slashings = consensus_types.phase0.ProposerSlashings.default_value,
                .attester_slashings = consensus_types.phase0.AttesterSlashings.default_value,
                .attestations = consensus_types.electra.Attestations.default_value,
                .deposits = consensus_types.phase0.Deposits.default_value,
                .voluntary_exits = consensus_types.phase0.VoluntaryExits.default_value,
                .sync_aggregate = .{
                    .sync_committee_bits = ssz.BitVectorType(preset.SYNC_COMMITTEE_SIZE).default_value,
                    .sync_committee_signature = consensus_types.primitive.BLSSignature.default_value,
                },
                .execution_payload = execution_payload,
                .bls_to_execution_changes = consensus_types.capella.SignedBLSToExecutionChanges.default_value,
                .blob_kzg_commitments = consensus_types.electra.BlobKzgCommitments.default_value,
                .execution_requests = consensus_types.electra.ExecutionRequests.default_value,
            },
        },
        .signature = consensus_types.primitive.BLSSignature.default_value,
    };

    return signed_block;
}
