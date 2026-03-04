const std = @import("std");
const testing = std.testing;

/// Errors from the ProtoArray (low-level DAG operations).
pub const ProtoArrayError = error{
    FinalizedNodeUnknown,
    JustifiedNodeUnknown,
    InvalidFinalizedRootChange,
    InvalidNodeIndex,
    InvalidParentIndex,
    InvalidBestChildIndex,
    InvalidJustifiedIndex,
    InvalidBestDescendantIndex,
    InvalidParentDelta,
    InvalidNodeDelta,
    IndexOverflow,
    InvalidDeltaLen,
    RevertedFinalizedEpoch,
    InvalidBestNode,
    InvalidBlockExecutionStatus,
    InvalidJustifiedExecutionStatus,
    InvalidLVHExecutionResponse,
};

/// LVH (Latest Valid Hash) execution status transition errors.
pub const LVHExecErrorCode = enum {
    /// Attempted to mark a pre-merge block as invalid.
    pre_merge_to_invalid,
    /// Attempted to mark a valid block as invalid (forbidden transition).
    valid_to_invalid,
    /// Attempted to mark an invalid block as valid (forbidden transition).
    invalid_to_valid,
};

/// Reasons a block can be rejected by fork choice.
pub const InvalidBlockCode = enum {
    unknown_parent,
    future_slot,
    finalized_slot,
    not_finalized_descendant,
};

/// Reasons an attestation can be rejected by fork choice.
pub const InvalidAttestationCode = enum {
    empty_aggregation_bitfield,
    unknown_head_block,
    bad_target_epoch,
    unknown_target_root,
    future_epoch,
    past_epoch,
    invalid_target,
    attests_to_future_block,
    future_slot,
};

/// High-level fork choice errors.
pub const ForkChoiceError = error{
    InvalidAttestation,
    InvalidBlock,
    ProtoArrayErr,
    InvalidProtoArrayBytes,
    MissingProtoArrayBlock,
    UnknownAncestor,
    InconsistentOnTick,
    BeaconStateErr,
    AttemptToRevertJustification,
    ForkChoiceStoreErr,
    UnableToSetJustifiedCheckpoint,
    AfterBlockFailed,
};

// ── Tests ──

test "ProtoArrayError is an error set" {
    const err: ProtoArrayError = error.FinalizedNodeUnknown;
    try testing.expect(err == error.FinalizedNodeUnknown);
}

test "ForkChoiceError is an error set" {
    const err: ForkChoiceError = error.InvalidBlock;
    try testing.expect(err == error.InvalidBlock);
}
