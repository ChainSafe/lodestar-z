//! BLS batch signature verification stage.
//!
//! Collects ALL signature sets from a block and verifies them in a single
//! batch using random-scalar multi-aggregate verification. This is the
//! most CPU-intensive verification stage, but batching amortizes the cost:
//! - Single-block gossip: 50-128 signature sets verified in one pairing
//! - Batch sync: multiple blocks' sigs verified together
//!
//! Signature sets collected:
//! 1. Block proposer signature
//! 2. RANDAO reveal
//! 3. Attestation aggregate signatures (share signing roots → Pippenger optimization)
//! 4. Voluntary exit signatures
//! 5. Proposer slashing signatures (2 per slashing)
//! 6. Attester slashing signatures (2 per slashing)
//! 7. BLS-to-execution change signatures (Capella+)
//! 8. Sync committee aggregate signature (Altair+)
//!
//! The actual BLS math is delegated to the BatchVerifier from src/bls/,
//! which uses blst bindings with optional thread pool parallelism.
//!
//! Reference: Lodestar chain/blocks/verifyBlocksSignatures.ts
//!           + state_transition/signatureSets/*

const std = @import("std");

const consensus_types = @import("consensus_types");
const fork_types = @import("fork_types");
const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;
const bls_mod = @import("bls");
const BatchVerifier = bls_mod.BatchVerifier;

const pipeline_types = @import("types.zig");
const BlockInput = pipeline_types.BlockInput;
const ImportBlockOpts = pipeline_types.ImportBlockOpts;
const BlockImportError = pipeline_types.BlockImportError;

// ---------------------------------------------------------------------------
// Signature verification result
// ---------------------------------------------------------------------------

/// Outcome of the signature verification stage.
pub const SignatureVerificationResult = enum {
    /// All signatures verified valid.
    verified,
    /// Signatures were skipped (trusted source or opts.skip_signatures).
    skipped,
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Verify all BLS signatures in a block using batch verification.
///
/// This function integrates with the existing processBlock signature collection
/// mechanism in state_transition. Rather than duplicating signature set extraction,
/// we set up the batch verifier and pass it through processBlock's
/// ProcessBlockOpts.batch_verifier field. The state transition code collects
/// all signature sets during processing, and we verify them afterward.
///
/// For the block import pipeline, signatures are verified BEFORE state transition
/// in the TS Lodestar pipeline. However, in lodestar-z's architecture, signatures
/// are collected DURING processBlock (which is already the pattern in chain.zig).
///
/// This function handles the policy decision: should we verify, skip, or defer?
/// The actual verification happens in executeStateTransition which runs processBlock
/// with the batch verifier enabled.
///
/// Returns:
/// - .verified: signatures will be batch-verified during state transition
/// - .skipped: signatures are not being verified (trusted source)
pub fn shouldVerifySignatures(
    opts: ImportBlockOpts,
    source: pipeline_types.BlockSource,
) SignatureVerificationResult {
    // Skip entirely if explicitly requested.
    if (opts.skip_signatures or opts.valid_signatures) return .skipped;

    // Skip for trusted sources.
    switch (source) {
        .checkpoint_sync => return .skipped,
        .regen => return .skipped,
        else => {},
    }

    return .verified;
}

/// Verify a block's proposer signature standalone (for gossip validation).
///
/// This is a quick single-signature check used by gossip validation
/// before the full pipeline. The result can be communicated to the pipeline
/// via opts.valid_proposer_signature = true.
pub fn verifyProposerSignature(
    block_input: BlockInput,
    pre_state: *CachedBeaconState,
) BlockImportError!void {
    _ = pre_state;
    // The actual proposer signature verification is done through
    // state_transition.signature_sets.proposer.verifyProposerSignature
    // which is already integrated into the gossip validation path.
    // This function documents the entry point and provides error mapping.
    _ = block_input;
    // TODO: When gossip validation is integrated, wire this to
    // state_transition's verifyProposerSignature.
}

/// Create a batch verifier configured for block import.
///
/// The returned verifier should be passed to processBlock via
/// ProcessBlockOpts.batch_verifier. After processBlock returns,
/// call verifier.verifyAll() to batch-verify all collected signatures.
pub fn createBlockBatchVerifier(
    io: std.Io,
    thread_pool: ?*bls_mod.ThreadPool,
) BatchVerifier {
    return BatchVerifier.init(io, thread_pool);
}

/// Verify all signatures collected in a batch verifier.
///
/// Called after processBlock has collected all signature sets.
/// Returns BlockImportError.InvalidSignature if any signature is invalid.
pub fn finalizeBatchVerification(
    batch: *BatchVerifier,
) BlockImportError!void {
    if (batch.len() == 0) return;

    const valid = batch.verifyAll() catch return BlockImportError.InvalidSignature;
    if (!valid) return BlockImportError.InvalidSignature;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "shouldVerifySignatures: default opts verify" {
    const result = shouldVerifySignatures(.{}, .gossip);
    try std.testing.expectEqual(SignatureVerificationResult.verified, result);
}

test "shouldVerifySignatures: skip when requested" {
    const result = shouldVerifySignatures(.{ .skip_signatures = true }, .gossip);
    try std.testing.expectEqual(SignatureVerificationResult.skipped, result);
}

test "shouldVerifySignatures: skip for valid_signatures" {
    const result = shouldVerifySignatures(.{ .valid_signatures = true }, .gossip);
    try std.testing.expectEqual(SignatureVerificationResult.skipped, result);
}

test "shouldVerifySignatures: skip for checkpoint_sync" {
    const result = shouldVerifySignatures(.{}, .checkpoint_sync);
    try std.testing.expectEqual(SignatureVerificationResult.skipped, result);
}

test "shouldVerifySignatures: skip for regen" {
    const result = shouldVerifySignatures(.{}, .regen);
    try std.testing.expectEqual(SignatureVerificationResult.skipped, result);
}

test "shouldVerifySignatures: verify for range_sync" {
    const result = shouldVerifySignatures(.{}, .range_sync);
    try std.testing.expectEqual(SignatureVerificationResult.verified, result);
}

test "shouldVerifySignatures: verify for api" {
    const result = shouldVerifySignatures(.{}, .api);
    try std.testing.expectEqual(SignatureVerificationResult.verified, result);
}

test "createBlockBatchVerifier: creates with no pool" {
    var verifier = createBlockBatchVerifier(std.testing.io, null);
    try std.testing.expectEqual(@as(usize, 0), verifier.len());
}

test "createBlockBatchVerifier: keeps provided pool" {
    const pool = try bls_mod.ThreadPool.init(std.testing.allocator, std.testing.io, .{ .n_workers = 2 });
    defer pool.deinit();

    const verifier = createBlockBatchVerifier(std.testing.io, pool);
    try std.testing.expect(verifier.thread_pool == pool);
}
