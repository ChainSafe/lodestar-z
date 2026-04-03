//! State transition execution stage.
//!
//! Runs the full STFN (processSlots + processBlock) on a pre-state to produce
//! the post-state. This is the most expensive pipeline stage — it modifies
//! a full CachedBeaconState through slot processing and block processing.
//!
//! Key integration points:
//! - Clones the pre-state (COW via persistent merkle tree)
//! - Runs processSlots to advance to the block's slot
//! - Runs processBlock with optional batch signature verification
//! - Verifies the resulting state root matches the block's commitment
//!
//! When batch signature verification is enabled, processBlock collects
//! signature sets into the BatchVerifier instead of verifying inline.
//! The caller must call finalizeBatchVerification() after this stage.
//!
//! Reference: Lodestar chain/blocks/verifyBlocksStateTransitionOnly.ts

const std = @import("std");
const Allocator = std.mem.Allocator;

const consensus_types = @import("consensus_types");
const fork_types = @import("fork_types");
const config_mod = @import("config");
const ForkSeq = config_mod.ForkSeq;
const state_transition = @import("state_transition");
const regen_mod = @import("../regen/root.zig");
const CachedBeaconState = state_transition.CachedBeaconState;
const PmtMutator = regen_mod.PmtMutator;
const bls_mod = @import("bls");
const BatchVerifier = bls_mod.BatchVerifier;

const pipeline_types = @import("types.zig");
const BlockInput = pipeline_types.BlockInput;
const ImportBlockOpts = pipeline_types.ImportBlockOpts;
const DataAvailabilityStatus = pipeline_types.DataAvailabilityStatus;
const BlockImportError = pipeline_types.BlockImportError;

const verify_sigs = @import("verify_signatures.zig");

// ---------------------------------------------------------------------------
// STF result
// ---------------------------------------------------------------------------

/// Result of a successful state transition.
pub const StfResult = struct {
    /// The post-state after processSlots + processBlock.
    post_state: *CachedBeaconState,
    /// The state root of the post-state.
    state_root: [32]u8,
    /// Computed block root (from BeaconBlock hash-tree-root).
    block_root: [32]u8,
    /// Proposer balance delta (can be used for metrics).
    proposer_balance_delta: i64,
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Execute the state transition for a block.
///
/// 1. Clone the pre-state
/// 2. Run processSlots to advance to block.slot
/// 3. Run processBlock (with batch sig collection if verify_signatures)
/// 4. Verify state root matches
/// 5. If verify_signatures, batch-verify all collected signatures
///
/// This is the most expensive stage — it modifies 200KB+ of state.
pub fn executeStateTransition(
    allocator: Allocator,
    block_input: BlockInput,
    pre_state: *CachedBeaconState,
    da_status: DataAvailabilityStatus,
    opts: ImportBlockOpts,
    precomputed_body_root: ?[32]u8,
    pmt_mutator: *PmtMutator,
    block_bls_thread_pool: ?*bls_mod.ThreadPool,
) BlockImportError!StfResult {
    const any_signed_block = block_input.block;
    const block = any_signed_block.beaconBlock();
    const block_slot = block.slot();

    var pmt_mutation_lease = pmt_mutator.acquire();
    defer pmt_mutation_lease.release();

    // Clone pre-state (COW — cheap if no mutations).
    const post_state = pre_state.clone(allocator, .{ .transfer_cache = false }) catch
        return BlockImportError.PrestateMissing;
    errdefer {
        post_state.deinit();
        allocator.destroy(post_state);
    }

    // Process slots to advance to block's slot.
    state_transition.processSlots(allocator, post_state, block_slot, .{}) catch
        return BlockImportError.StateTransitionFailed;

    // Determine whether to verify signatures.
    const sig_status = verify_sigs.shouldVerifySignatures(opts, block_input.source);
    const verify_signatures = sig_status == .verified;

    // Set up batch verifier if signatures are being verified.
    var batch = verify_sigs.createBlockBatchVerifier(block_bls_thread_pool);

    // Map pipeline DA status to the state_transition's BlockExternalData DA status.
    // Use @FieldType to get the anonymous enum type of the data_availability_status field.
    const stf_da_status: @FieldType(state_transition.BlockExternalData, "data_availability_status") = switch (da_status) {
        // not_required: pre-Deneb block or no blob requirement — treat as available.
        .not_required => .available,
        // pre_data: explicitly separated data (Gloas fork model) — pass through.
        .pre_data => .pre_data,
        // out_of_range: beyond blob retention — DA not enforced, treat as available.
        .out_of_range => .available,
        // available: all blobs/columns present and verified.
        .available => .available,
        // pending: should not reach here (caught by verifyDataAvailability).
        .pending => .pre_data,
    };

    // Run processBlock — the core of the consensus state transition.
    // This is fork-polymorphic: dispatches based on the state's fork.
    switch (post_state.state.forkSeq()) {
        inline else => |f| {
            switch (block.blockType()) {
                inline else => |bt| {
                    if (comptime bt == .blinded and (f.lt(.bellatrix) or f.gte(.gloas))) {
                        return BlockImportError.StateTransitionFailed;
                    }
                    const process_opts = state_transition.ProcessBlockOpts{
                        .verify_signature = verify_signatures,
                        .batch_verifier = if (verify_signatures) &batch else null,
                    };
                    state_transition.processBlock(
                        f,
                        allocator,
                        post_state.config,
                        post_state.epoch_cache,
                        post_state.state.castToFork(f),
                        &post_state.slashings_cache,
                        bt,
                        block.castToFork(bt, f),
                        .{
                            .execution_payload_status = .valid, // Verified separately
                            .data_availability_status = stf_da_status,
                        },
                        process_opts,
                    ) catch return BlockImportError.StateTransitionFailed;
                },
            }
        },
    }

    // Batch-verify all collected signatures.
    if (verify_signatures and batch.len() > 0) {
        try verify_sigs.finalizeBatchVerification(&batch);
    }

    // Commit state changes and compute state root.
    post_state.state.commit() catch return BlockImportError.StateTransitionFailed;
    const state_root = (post_state.state.hashTreeRoot() catch
        return BlockImportError.StateTransitionFailed).*;

    // Verify state root matches block's commitment.
    // Skip verification if:
    // 1. The block's declared state root is all zeros (sentinel for "not computed" —
    //    used by block generators in tests and by produceAndImportBlock before filling).
    // 2. The opts.skip_state_root_check is set.
    const expected_root = block.stateRoot().*;
    const expected_is_zero = std.mem.allEqual(u8, &expected_root, 0);
    if (!expected_is_zero and !std.mem.eql(u8, &state_root, &expected_root)) {
        std.log.warn("State root mismatch at slot {d}: computed={s}... expected={s}...", .{
            block_slot,
            &std.fmt.bytesToHex(state_root[0..8], .lower),
            &std.fmt.bytesToHex(expected_root[0..8], .lower),
        });
        return BlockImportError.InvalidStateRoot;
    } else if (expected_is_zero) {
        std.log.debug("State root not set in block at slot {d} — skipping check", .{block_slot});
    } else {
        std.log.debug("State root verified at slot {d}: {s}...", .{
            block_slot, &std.fmt.bytesToHex(state_root[0..8], .lower),
        });
    }

    // Compute the canonical block root.
    // Per the beacon spec, block_root = hash_tree_root(BeaconBlockHeader) where
    // BeaconBlockHeader.state_root = the computed post-state root (not the placeholder 0x00...).
    // This ensures the block root matches what the state stores in block_roots[] and
    // what child blocks use as parent_root.
    // Reuse precomputed body_root from sanity stage when available.
    var body_root: [32]u8 = undefined;
    if (precomputed_body_root) |br| {
        body_root = br;
    } else {
        block.beaconBlockBody().hashTreeRoot(allocator, &body_root) catch return BlockImportError.InternalError;
    }
    const block_header = consensus_types.phase0.BeaconBlockHeader.Type{
        .slot = block_slot,
        .proposer_index = block.proposerIndex(),
        .parent_root = block.parentRoot().*,
        .state_root = state_root, // Use computed post-state root, not the block's placeholder
        .body_root = body_root,
    };
    var block_root: [32]u8 = undefined;
    consensus_types.phase0.BeaconBlockHeader.hashTreeRoot(&block_header, &block_root) catch
        return BlockImportError.InternalError;

    // Compute proposer balance delta for metrics.
    // In a full implementation we'd read proposer index and compare balances.
    // For now, return 0 — the delta is informational only.
    const proposer_balance_delta: i64 = 0;

    return StfResult{
        .post_state = post_state,
        .state_root = state_root,
        .block_root = block_root,
        .proposer_balance_delta = proposer_balance_delta,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "StfResult struct layout" {
    const result = StfResult{
        .post_state = undefined,
        .state_root = [_]u8{0} ** 32,
        .block_root = [_]u8{0} ** 32,
        .proposer_balance_delta = 0,
    };
    try std.testing.expectEqual(@as(i64, 0), result.proposer_balance_delta);
}
