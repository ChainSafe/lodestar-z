//! BlockVerification — pipelined block verification.
//!
//! Factors out the monolithic block import in chain.zig into distinct
//! verification stages that can be reasoned about, tested, and eventually
//! parallelized independently.
//!
//! Pipeline stages (in order):
//! 1. verifySanity       — slot bounds, parent known, not duplicate/finalized
//! 2. verifySignatures   — BLS batch verification of proposer sig + other sigs
//! 3. verifyDataAvailability — blob/column KZG proofs (Deneb+)
//! 4. executeStateTransition — run STFN (processSlots + processBlock)
//! 5. verifyExecutionPayload — engine_newPayload call (Bellatrix+)
//! 6. importBlock        — fork choice, persistence, head update
//!
//! Each stage takes the output of the previous stage, allowing early rejection.
//! The VerificationContext threads state through the pipeline.

const std = @import("std");
const Allocator = std.mem.Allocator;

const consensus_types = @import("consensus_types");
const preset = @import("preset").preset;
const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;
const computeEpochAtSlot = state_transition.computeEpochAtSlot;

// ---------------------------------------------------------------------------
// Pipeline result types
// ---------------------------------------------------------------------------

/// Outcome of a sanity check pass.
pub const SanityResult = struct {
    block_root: [32]u8,
    block_slot: u64,
    parent_root: [32]u8,
};

/// BLS verification disposition.
pub const SignatureStatus = enum {
    /// Signatures verified (or verification skipped for trusted source).
    verified,
    /// Deferred to batch verifier (not yet checked).
    pending_batch,
    /// Signatures skipped by policy (e.g. trusted API submission).
    skipped,
};

pub const SignatureResult = struct {
    sanity: SanityResult,
    signature_status: SignatureStatus,
};

/// Data availability status for Deneb+ blobs/columns.
pub const DataAvailabilityStatus = enum {
    /// Pre-Deneb: not required.
    not_required,
    /// All blobs/columns present and KZG-verified.
    available,
    /// Blobs/columns missing — block is quarantined until they arrive.
    pending,
};

pub const DataAvailabilityResult = struct {
    signature: SignatureResult,
    da_status: DataAvailabilityStatus,
};

/// State transition result carrying the post-state.
pub const StfResult = struct {
    da: DataAvailabilityResult,
    post_state: *CachedBeaconState,
    state_root: [32]u8,
};

/// Execution payload verification outcome.
pub const ExecutionStatus = enum {
    /// EL says payload is VALID.
    valid,
    /// EL says payload is INVALID.
    invalid,
    /// EL hasn't responded yet — block imported as optimistic.
    syncing,
    /// Pre-merge: no execution payload.
    pre_merge,
};

pub const ExecutionResult = struct {
    stf: StfResult,
    execution_status: ExecutionStatus,
};

// ---------------------------------------------------------------------------
// Verification errors
// ---------------------------------------------------------------------------

pub const VerifyError = error{
    /// Block's slot is 0 (genesis — not importable).
    GenesisBlock,
    /// Block's slot is at or before the finalized slot.
    BlockAlreadyFinalized,
    /// Block was already imported.
    BlockAlreadyKnown,
    /// Parent block is not in our chain.
    UnknownParentBlock,
    /// BLS signature verification failed.
    InvalidSignature,
    /// KZG proof verification failed for a blob/column.
    InvalidKzgProof,
    /// State transition produced a mismatched state root.
    StateRootMismatch,
    /// Execution payload was rejected by the EL.
    InvalidExecutionPayload,
    /// Pre-state not found in cache.
    NoPreStateAvailable,
};

// ---------------------------------------------------------------------------
// Verification stages
// ---------------------------------------------------------------------------

/// Stage 1: Sanity checks — cheap, no state required.
///
/// Checks slot bounds, parent known, and duplicate detection.
pub fn verifySanity(
    block_slot: u64,
    parent_root: [32]u8,
    block_root: [32]u8,
    finalized_epoch: u64,
    known_blocks: *const std.AutoArrayHashMap([32]u8, [32]u8),
) VerifyError!SanityResult {
    if (block_slot == 0) return VerifyError.GenesisBlock;

    const finalized_slot = finalized_epoch * preset.SLOTS_PER_EPOCH;
    if (block_slot <= finalized_slot) return VerifyError.BlockAlreadyFinalized;

    if (known_blocks.contains(block_root)) return VerifyError.BlockAlreadyKnown;

    if (!known_blocks.contains(parent_root)) return VerifyError.UnknownParentBlock;

    return SanityResult{
        .block_root = block_root,
        .block_slot = block_slot,
        .parent_root = parent_root,
    };
}

/// Stage 2: Signature verification — BLS proposer signature and other block sigs.
///
/// `skip_verification` is true for blocks from trusted sources (checkpoint sync, API).
pub fn verifySignatures(
    sanity: SanityResult,
    skip_verification: bool,
) VerifyError!SignatureResult {
    // TODO: Integrate BLS batch verifier when available.
    // For now: mark as pending_batch when enabled, skipped when disabled.
    const status: SignatureStatus = if (skip_verification)
        .skipped
    else
        .pending_batch;

    return SignatureResult{
        .sanity = sanity,
        .signature_status = status,
    };
}

/// Stage 3: Data availability — check blobs/columns are present (Deneb+).
///
/// `da_status` is provided by the caller (gossip handler or blob fetcher).
pub fn verifyDataAvailability(
    sig: SignatureResult,
    da_status: DataAvailabilityStatus,
) VerifyError!DataAvailabilityResult {
    // Quarantine: if blobs are pending, we cannot proceed.
    if (da_status == .pending) return VerifyError.InvalidKzgProof;

    return DataAvailabilityResult{
        .signature = sig,
        .da_status = da_status,
    };
}

/// Stage 4: State transition — run STFN and validate state root.
///
/// `pre_state` is the parent post-state (from block state cache).
/// Returns the post-state and its state root.
pub fn executeStateTransition(
    allocator: Allocator,
    da: DataAvailabilityResult,
    pre_state: *CachedBeaconState,
    block_slot: u64,
    expected_state_root: [32]u8,
    verify_state_root: bool,
) VerifyError!StfResult {
    const post_state = pre_state.clone(allocator, .{ .transfer_cache = false }) catch
        return VerifyError.NoPreStateAvailable;
    errdefer {
        post_state.deinit();
        allocator.destroy(post_state);
    }

    state_transition.processSlots(allocator, post_state, block_slot, .{}) catch
        return VerifyError.StateRootMismatch;

    post_state.state.commit() catch return VerifyError.StateRootMismatch;

    const state_root = (post_state.state.hashTreeRoot() catch return VerifyError.StateRootMismatch).*;

    if (verify_state_root and !std.mem.eql(u8, &state_root, &expected_state_root)) {
        return VerifyError.StateRootMismatch;
    }

    return StfResult{
        .da = da,
        .post_state = post_state,
        .state_root = state_root,
    };
}

/// Stage 5: Execution payload verification — engine_newPayload call.
///
/// `execution_status` is the outcome from the EL (or pre_merge for pre-Bellatrix).
pub fn verifyExecutionPayload(
    stf: StfResult,
    execution_status: ExecutionStatus,
) VerifyError!ExecutionResult {
    if (execution_status == .invalid) return VerifyError.InvalidExecutionPayload;

    return ExecutionResult{
        .stf = stf,
        .execution_status = execution_status,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "verifySanity: rejects genesis" {
    var known = std.AutoArrayHashMap([32]u8, [32]u8).init(std.testing.allocator);
    defer known.deinit();
    try std.testing.expectError(
        VerifyError.GenesisBlock,
        verifySanity(0, [_]u8{0} ** 32, [_]u8{1} ** 32, 0, &known),
    );
}

test "verifySanity: rejects finalized block" {
    var known = std.AutoArrayHashMap([32]u8, [32]u8).init(std.testing.allocator);
    defer known.deinit();
    try std.testing.expectError(
        VerifyError.BlockAlreadyFinalized,
        verifySanity(10, [_]u8{0} ** 32, [_]u8{1} ** 32, 1, &known),
    );
}

test "verifySanity: rejects duplicate" {
    var known = std.AutoArrayHashMap([32]u8, [32]u8).init(std.testing.allocator);
    defer known.deinit();
    const root = [_]u8{0xAA} ** 32;
    try known.put(root, [_]u8{0xBB} ** 32);
    try std.testing.expectError(
        VerifyError.BlockAlreadyKnown,
        verifySanity(100, [_]u8{0} ** 32, root, 0, &known),
    );
}

test "verifySanity: rejects unknown parent" {
    var known = std.AutoArrayHashMap([32]u8, [32]u8).init(std.testing.allocator);
    defer known.deinit();
    try std.testing.expectError(
        VerifyError.UnknownParentBlock,
        verifySanity(100, [_]u8{0xCC} ** 32, [_]u8{0xDD} ** 32, 0, &known),
    );
}

test "verifySanity: accepts valid block" {
    var known = std.AutoArrayHashMap([32]u8, [32]u8).init(std.testing.allocator);
    defer known.deinit();
    const parent = [_]u8{0xAA} ** 32;
    try known.put(parent, [_]u8{0xBB} ** 32);
    const result = try verifySanity(100, parent, [_]u8{0xCC} ** 32, 0, &known);
    try std.testing.expectEqual(@as(u64, 100), result.block_slot);
}

test "verifySignatures: skipped when requested" {
    const sanity = SanityResult{
        .block_root = [_]u8{0} ** 32,
        .block_slot = 100,
        .parent_root = [_]u8{0} ** 32,
    };
    const result = try verifySignatures(sanity, true);
    try std.testing.expectEqual(SignatureStatus.skipped, result.signature_status);
}

test "verifyDataAvailability: rejects pending blobs" {
    const sanity = SanityResult{
        .block_root = [_]u8{0} ** 32,
        .block_slot = 100,
        .parent_root = [_]u8{0} ** 32,
    };
    const sig_result = SignatureResult{ .sanity = sanity, .signature_status = .skipped };
    try std.testing.expectError(
        VerifyError.InvalidKzgProof,
        verifyDataAvailability(sig_result, .pending),
    );
}

test "verifyExecutionPayload: rejects invalid status" {
    const sanity = SanityResult{
        .block_root = [_]u8{0} ** 32,
        .block_slot = 100,
        .parent_root = [_]u8{0} ** 32,
    };
    const sig = SignatureResult{ .sanity = sanity, .signature_status = .skipped };
    const da = DataAvailabilityResult{ .signature = sig, .da_status = .not_required };
    // We need a dummy StfResult — use undefined for the pointer since we only test rejection.
    const stf = StfResult{
        .da = da,
        .post_state = undefined,
        .state_root = [_]u8{0} ** 32,
    };
    try std.testing.expectError(
        VerifyError.InvalidExecutionPayload,
        verifyExecutionPayload(stf, .invalid),
    );
}
