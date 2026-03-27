//! Block import pipeline orchestrator.
//!
//! This is the main entry point for block processing. It runs all stages
//! in sequence, threading the output of each stage to the next:
//!
//! 1. verifySanity       — slot bounds, parent known, not duplicate
//! 2. getPreState        — retrieve pre-state via queued regen
//! 3. verifyDA           — check data availability status
//! 4. stateTransition    — run STFN (includes batch sig verification)
//! 5. verifyExecution    — engine_newPayload (or optimistic)
//! 6. importBlock        — fork choice, DB, caches, events
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

const consensus_types = @import("consensus_types");
const preset = @import("preset").preset;
const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
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

const verify_sanity = @import("verify_sanity.zig");
const SanityOutcome = verify_sanity.SanityOutcome;
const verify_da = @import("verify_data_availability.zig");
const execute_stf = @import("execute_state_transition.zig");
const verify_exec = @import("verify_execution.zig");
const ExecutionVerifier = verify_exec.ExecutionVerifier;
const import_block = @import("import_block.zig");
const ImportContext = import_block.ImportContext;

const QueuedStateRegen = @import("../queued_regen.zig").QueuedStateRegen;
const HeadTracker = @import("../block_import.zig").HeadTracker;

const Slot = consensus_types.primitive.Slot.Type;

// ---------------------------------------------------------------------------
// Pipeline context — everything needed to process a block
// ---------------------------------------------------------------------------

/// Pipeline configuration and dependencies.
///
/// Created once by the Chain and reused for each block import.
/// Contains references to all chain components needed by the pipeline.
pub const PipelineContext = struct {
    allocator: Allocator,

    // -- State management --
    block_state_cache: *state_transition.BlockStateCache,
    state_regen: *state_transition.StateRegen,
    queued_regen: ?*QueuedStateRegen,

    // -- Fork choice --
    fork_choice: ?*ForkChoice,

    // -- Persistence --
    db: *@import("db").BeaconDB,

    // -- Head tracking --
    head_tracker: *HeadTracker,

    // -- Block root → state root mapping --
    block_to_state: *std.AutoArrayHashMap([32]u8, [32]u8),

    // -- Events --
    event_callback: ?@import("../types.zig").EventCallback,

    // -- Execution verification (optional) --
    execution_verifier: ?ExecutionVerifier,

    // -- Clock --
    current_slot: Slot,

    /// Convert to ImportContext for the import stage.
    pub fn toImportContext(self: PipelineContext) ImportContext {
        return .{
            .allocator = self.allocator,
            .block_state_cache = self.block_state_cache,
            .state_regen = self.state_regen,
            .queued_regen = self.queued_regen,
            .fork_choice = self.fork_choice,
            .db = self.db,
            .head_tracker = self.head_tracker,
            .block_to_state = self.block_to_state,
            .event_callback = self.event_callback,
        };
    }
};

// ---------------------------------------------------------------------------
// Single block processing
// ---------------------------------------------------------------------------

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
    const fc = ctx.fork_choice orelse return BlockImportError.InternalError;

    // Stage 1: Sanity checks.
    const sanity_outcome = try verify_sanity.verifySanity(
        ctx.allocator,
        block_input,
        fc,
        ctx.current_slot,
        opts,
    );

    switch (sanity_outcome) {
        .skipped => {
            // Block was intentionally skipped (ignore_if_known/finalized).
            // Return a synthetic result.
            var block_root: [32]u8 = undefined;
            block_input.block.beaconBlock().hashTreeRoot(ctx.allocator, &block_root) catch
                return BlockImportError.InternalError;
            return ImportResult{
                .block_root = block_root,
                .state_root = [_]u8{0} ** 32,
                .slot = block_input.block.beaconBlock().slot(),
                .epoch_transition = false,
                .execution_optimistic = false,
            };
        },
        .valid => |sanity| {
            // Stage 2: Get pre-state via queued regen.
            const pre_state = getPreState(ctx, sanity.parent_root, sanity.block_slot) orelse
                return BlockImportError.PrestateMissing;

            // Stage 3: Data availability check.
            const da_status = try verify_da.verifyDataAvailability(block_input, opts);

            // Stage 4: State transition (includes batch signature verification).
            const stf_result = try execute_stf.executeStateTransition(
                ctx.allocator,
                block_input,
                pre_state,
                da_status,
                opts,
            );

            // Stage 5: Execution payload verification.
            const exec_status = try verify_exec.verifyExecutionPayload(
                block_input,
                ctx.execution_verifier,
                opts,
            );

            // Stage 6: Import into chain.
            const verified = VerifiedBlock{
                .block_input = block_input,
                .post_state = stf_result.post_state,
                .block_root = stf_result.block_root,
                .state_root = stf_result.state_root,
                .parent_slot = sanity.parent_slot,
                .execution_status = exec_status,
                .data_availability_status = da_status,
                .proposer_balance_delta = stf_result.proposer_balance_delta,
            };

            return import_block.importVerifiedBlock(ctx.toImportContext(), verified, opts);
        },
    }
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
        results[i] = processSingleForBatch(ctx, block_input, batch_opts);
    }

    return results;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn processSingleForBatch(
    ctx: PipelineContext,
    block_input: BlockInput,
    opts: ImportBlockOpts,
) BatchBlockResult {
    const result = processBlock(ctx, block_input, opts) catch |err| {
        // Classify the error.
        switch (err) {
            BlockImportError.AlreadyKnown,
            BlockImportError.WouldRevertFinalizedSlot,
            BlockImportError.GenesisBlock,
            => return .{ .skipped = {} },
            else => return .{ .failed = err },
        }
    };
    return .{ .success = result };
}

/// Get the pre-state for a block, trying queued regen first.
fn getPreState(
    ctx: PipelineContext,
    parent_root: [32]u8,
    block_slot: Slot,
) ?*CachedBeaconState {
    // Try queued regen (with dedup + priority) first.
    if (ctx.queued_regen) |qr| {
        return qr.getPreState(parent_root, block_slot, .block_import) catch null;
    }

    // Fall back to direct state root lookup + block state cache.
    const state_root = ctx.block_to_state.get(parent_root) orelse return null;
    return ctx.block_state_cache.get(state_root);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "PipelineContext struct compiles" {
    _ = PipelineContext;
}

test "BatchBlockResult union layout" {
    const result = BatchBlockResult{ .skipped = {} };
    try std.testing.expect(result == .skipped);
}
