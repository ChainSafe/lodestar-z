//! Block import pipeline types — the vocabulary shared across all pipeline stages.
//!
//! These types define the data flow through the block import pipeline:
//!   BlockInput → SanityResult → SignatureResult → ... → VerifiedBlock → ImportResult
//!
//! Design principles:
//! - Each stage produces a typed result that proves the check was run
//! - Errors are fine-grained so callers can react (ignore, penalize, queue)
//! - Compatible with both single-block gossip and multi-block range sync
//!
//! Reference: Lodestar chain/blocks/types.ts

const std = @import("std");
const consensus_types = @import("consensus_types");
const fork_types = @import("fork_types");
const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;
const fork_choice_mod = @import("fork_choice");
const ProtoBlock = fork_choice_mod.ProtoBlock;
const ProtoNode = fork_choice_mod.ProtoNode;

const Slot = consensus_types.primitive.Slot.Type;
const Epoch = consensus_types.primitive.Epoch.Type;
const Root = [32]u8;

// ---------------------------------------------------------------------------
// BlockInput — the atomic unit entering the pipeline
// ---------------------------------------------------------------------------

/// Where this block came from. Determines which checks can be skipped
/// and how errors should be handled.
pub const BlockSource = enum {
    /// Received via gossipsub — single block, needs full validation.
    gossip,
    /// Received via req/resp range sync — batch of blocks, sequential.
    range_sync,
    /// Received via req/resp after seeing an unknown parent — needs full validation.
    unknown_block_sync,
    /// Submitted via REST API — possibly pre-validated proposer sig.
    api,
    /// From checkpoint sync — trusted, skip most checks.
    checkpoint_sync,
    /// Replayed during state regeneration — skip sigs and execution.
    regen,
};

/// Data availability status for the block's associated blobs/columns.
///
/// Pre-Deneb blocks are `not_required`. Deneb+ blocks start as `pending`
/// until blobs arrive and are KZG-verified, at which point they become
/// `available`. Blocks older than MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS
/// are `out_of_range` — DA is not enforced.
pub const DataAvailabilityStatus = enum {
    /// Pre-Deneb: no data availability requirement.
    not_required,
    /// All blobs/columns are present and KZG proofs verified.
    available,
    /// Blobs/columns not yet available — block quarantined.
    pending,
    /// Block is beyond the blob retention window — DA not enforced.
    out_of_range,
    /// Pre-data: block type has no data (e.g. Gloas separated payload).
    pre_data,
};

/// The atomic unit entering the block import pipeline.
///
/// Contains the signed block plus any associated sidecar data (blobs,
/// data columns) and metadata about its origin.
pub const BlockInput = struct {
    /// The signed beacon block (fork-polymorphic wrapper).
    block: fork_types.AnySignedBeaconBlock,
    /// Where this block came from.
    source: BlockSource,
    /// Data availability status of associated blobs/columns.
    da_status: DataAvailabilityStatus,
    /// Wall-clock time when we first saw this block (seconds since epoch).
    /// Used for metrics (gossip block timing). 0 if unknown.
    seen_timestamp_sec: u64 = 0,
};

// ---------------------------------------------------------------------------
// Import options — per-block-or-batch configuration
// ---------------------------------------------------------------------------

/// Controls which checks to run and how to handle certain errors.
///
/// Different callers set different options:
/// - Gossip: full validation, all checks enabled
/// - Range sync: may ignore already-known, may skip some FC updates
/// - Regen: skip signatures, skip execution
/// - API: may have pre-validated proposer signature
pub const ImportBlockOpts = struct {
    /// When true, ignore blocks that would return ALREADY_KNOWN or GENESIS_BLOCK
    /// instead of erroring. Used by range sync and unknown block sync.
    ignore_if_known: bool = false,

    /// When true, ignore blocks that would return WOULD_REVERT_FINALIZED_SLOT.
    /// Used by range sync for blocks that are finalized on our chain.
    ignore_if_finalized: bool = false,

    /// Skip all BLS signature verification. Only safe for:
    /// - Blocks replayed during state regen (already verified on first import)
    /// - Checkpoint sync blocks (trusted source)
    skip_signatures: bool = false,

    /// Skip execution payload verification (engine_newPayload).
    /// Used when the execution engine is unavailable (optimistic sync).
    skip_execution: bool = false,

    /// The proposer signature has already been verified (e.g., during gossip).
    valid_proposer_signature: bool = false,

    /// ALL signatures have already been verified.
    valid_signatures: bool = false,

    /// Whether to update fork choice after import.
    update_fork_choice: bool = true,

    /// Whether to run head selection after import.
    update_head: bool = true,

    /// Whether this is from range sync (affects optimistic sync handling).
    from_range_sync: bool = false,

    /// Skip the future-slot check in sanity verification.
    /// Used when the caller has already validated timing or doesn't need
    /// clock-based rejection (e.g., Chain.importBlock, range sync, API).
    skip_future_slot: bool = false,
};

// ---------------------------------------------------------------------------
// Pipeline stage results
// ---------------------------------------------------------------------------

/// Result of the sanity check stage.
pub const SanityResult = struct {
    /// Computed body root (hash-tree-root of BeaconBlockBody).
    /// Threaded through the pipeline to avoid redundant recomputation.
    body_root: Root,
    /// Computed block root (hash-tree-root of BeaconBlockHeader).
    block_root: Root,
    /// The block's slot.
    block_slot: Slot,
    /// The block's parent root.
    parent_root: Root,
    /// The parent block node from fork choice (when available).
    parent_block: ?ProtoBlock,
    /// Parent block slot (from fork choice or chain state).
    parent_slot: Slot,
};

/// Execution payload verification outcome.
///
/// Post-Bellatrix blocks have an execution payload that must be validated
/// by the execution layer client via engine_newPayload.
pub const ExecutionStatus = enum {
    /// EL confirmed the payload is VALID.
    valid,
    /// EL rejected the payload as INVALID.
    invalid,
    /// EL is still syncing — import optimistically.
    syncing,
    /// Pre-Bellatrix: no execution payload.
    pre_merge,
};

/// A fully verified block, ready for import into the chain.
///
/// This is the pipeline's final output before the import stage.
/// Creating this struct is proof that all verification stages passed.
pub const VerifiedBlock = struct {
    /// The original block input.
    block_input: BlockInput,
    /// The post-state after state transition.
    post_state: *CachedBeaconState,
    /// Computed block root.
    block_root: Root,
    /// Post-state root (from state transition).
    state_root: Root,
    /// Parent block's slot.
    parent_slot: Slot,
    /// Execution payload validation status.
    execution_status: ExecutionStatus,
    /// Data availability status.
    data_availability_status: DataAvailabilityStatus,
    /// Proposer balance delta (post - pre).
    proposer_balance_delta: i64,
};

/// Outcome of a successful block import.
pub const ImportResult = struct {
    /// Hash-tree-root of the imported block.
    block_root: Root,
    /// State root of the post-state.
    state_root: Root,
    /// Slot of the imported block.
    slot: Slot,
    /// Whether this block crossed an epoch boundary.
    epoch_transition: bool,
    /// Whether the block was imported optimistically.
    execution_optimistic: bool,
};

// ---------------------------------------------------------------------------
// Pipeline errors — fine-grained for caller decision making
// ---------------------------------------------------------------------------

/// Errors that can occur during block import.
///
/// Callers match on these to decide whether to:
/// - Ignore (duplicate, finalized — during range sync)
/// - Penalize peer (invalid signature, bad state root)
/// - Queue for later (unknown parent — trigger sync)
/// - Log and continue (EL unavailable — optimistic import)
pub const BlockImportError = error{
    // -- Sanity check errors --
    /// Block slot is 0 — genesis blocks are not importable.
    GenesisBlock,
    /// Block slot is at or before the finalized slot.
    WouldRevertFinalizedSlot,
    /// Block has already been imported (known to fork choice).
    AlreadyKnown,
    /// Parent block is not known to fork choice.
    ParentUnknown,
    /// Block is from a future slot (beyond clock + tolerance).
    FutureSlot,
    /// Block or its parent is blacklisted.
    BlacklistedBlock,
    /// Proposer index is invalid or proposer is slashed.
    InvalidProposer,

    // -- Signature errors --
    /// BLS signature verification failed (batch or individual).
    InvalidSignature,

    // -- Data availability errors --
    /// Blobs/columns not available within timeout.
    DataUnavailable,
    /// KZG proof verification failed for blob or data column.
    InvalidKzgProof,

    // -- State transition errors --
    /// Pre-state not found in cache or DB.
    PrestateMissing,
    /// State transition (processSlots + processBlock) failed.
    StateTransitionFailed,
    /// Post-state root doesn't match the block's state_root field.
    InvalidStateRoot,

    // -- Execution errors --
    /// Execution payload rejected by the EL as INVALID.
    ExecutionPayloadInvalid,
    /// Execution engine is unavailable (connection error, timeout).
    ExecutionEngineUnavailable,

    // -- Import errors --
    /// Fork choice rejected the block during onBlock.
    ForkChoiceError,
    /// Internal error (allocation failure, etc.)
    InternalError,
};

// ---------------------------------------------------------------------------
// Batch processing types
// ---------------------------------------------------------------------------

/// Result for a single block in a batch import.
pub const BatchBlockResult = union(enum) {
    /// Block was successfully verified and imported.
    success: ImportResult,
    /// Block was skipped (already known, finalized, etc.), with the concrete
    /// import error preserved for metrics and caller accounting.
    skipped: BlockImportError,
    /// Block failed verification.
    failed: BlockImportError,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "BlockSource enum values" {
    try std.testing.expectEqual(@as(usize, 6), @typeInfo(BlockSource).@"enum".fields.len);
}

test "DataAvailabilityStatus enum values" {
    try std.testing.expectEqual(@as(usize, 5), @typeInfo(DataAvailabilityStatus).@"enum".fields.len);
}

test "ExecutionStatus enum values" {
    try std.testing.expectEqual(@as(usize, 4), @typeInfo(ExecutionStatus).@"enum".fields.len);
}

test "ImportBlockOpts defaults" {
    const opts = ImportBlockOpts{};
    try std.testing.expect(!opts.ignore_if_known);
    try std.testing.expect(!opts.ignore_if_finalized);
    try std.testing.expect(!opts.skip_signatures);
    try std.testing.expect(!opts.skip_execution);
    try std.testing.expect(!opts.valid_proposer_signature);
    try std.testing.expect(!opts.valid_signatures);
    try std.testing.expect(opts.update_fork_choice);
    try std.testing.expect(opts.update_head);
    try std.testing.expect(!opts.from_range_sync);
}

test "ImportBlockOpts range sync preset" {
    const opts = ImportBlockOpts{
        .ignore_if_known = true,
        .ignore_if_finalized = true,
        .from_range_sync = true,
        .update_head = false,
    };
    try std.testing.expect(opts.ignore_if_known);
    try std.testing.expect(opts.ignore_if_finalized);
    try std.testing.expect(opts.from_range_sync);
    try std.testing.expect(!opts.update_head);
}

test "BlockImportError can be used in error unions" {
    const E = BlockImportError;
    const result: E!void = E.ParentUnknown;
    try std.testing.expectError(E.ParentUnknown, result);
}
