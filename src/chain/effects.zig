//! Typed chain-side effects and snapshots.
//!
//! These types form the boundary between the synchronous chain state machine
//! and outer runtime adapters such as the node, API, sync, and networking.

const std = @import("std");
const consensus_types = @import("consensus_types");
const networking = @import("networking");
const chain_types = @import("types.zig");
const blocks = @import("blocks/root.zig");
const block_types = @import("blocks/types.zig");
const execution_ports = @import("ports/execution.zig");

const Slot = consensus_types.primitive.Slot.Type;
const Epoch = consensus_types.primitive.Epoch.Type;
const Root = [32]u8;
const NewPayloadRequest = execution_ports.NewPayloadRequest;

pub const CheckpointSnapshot = struct {
    epoch: Epoch,
    slot: Slot,
    root: Root,
};

pub const ChainSnapshot = struct {
    head: chain_types.HeadInfo,
    justified: CheckpointSnapshot,
    finalized: CheckpointSnapshot,
    status: networking.messages.StatusMessage.Type,
};

pub const ExecutionForkchoiceUpdate = struct {
    beacon_block_root: Root,
    state: chain_types.ForkchoiceUpdateState,
};

pub const ImportEffects = struct {
    /// Execution-layer forkchoice update to run after the import completes.
    forkchoice_update: ?ExecutionForkchoiceUpdate = null,
    /// Finalized checkpoint snapshot after the import, when relevant.
    finalized_checkpoint: ?CheckpointSnapshot = null,
};

pub const ImportOutcome = struct {
    result: blocks.ImportResult,
    snapshot: ChainSnapshot,
    effects: ImportEffects,
};

pub const BlockImportErrorCounts = struct {
    genesis_block: usize = 0,
    would_revert_finalized: usize = 0,
    already_known: usize = 0,
    parent_unknown: usize = 0,
    future_slot: usize = 0,
    blacklisted_block: usize = 0,
    invalid_proposer: usize = 0,
    invalid_signature: usize = 0,
    data_unavailable: usize = 0,
    invalid_kzg_proof: usize = 0,
    prestate_missing: usize = 0,
    state_transition_failed: usize = 0,
    invalid_state_root: usize = 0,
    execution_payload_invalid: usize = 0,
    execution_engine_unavailable: usize = 0,
    forkchoice_error: usize = 0,
    internal_error: usize = 0,

    pub fn incr(self: *BlockImportErrorCounts, err: block_types.BlockImportError) void {
        switch (err) {
            error.GenesisBlock => self.genesis_block += 1,
            error.WouldRevertFinalizedSlot => self.would_revert_finalized += 1,
            error.AlreadyKnown => self.already_known += 1,
            error.ParentUnknown => self.parent_unknown += 1,
            error.FutureSlot => self.future_slot += 1,
            error.BlacklistedBlock => self.blacklisted_block += 1,
            error.InvalidProposer => self.invalid_proposer += 1,
            error.InvalidSignature => self.invalid_signature += 1,
            error.DataUnavailable => self.data_unavailable += 1,
            error.InvalidKzgProof => self.invalid_kzg_proof += 1,
            error.PrestateMissing => self.prestate_missing += 1,
            error.StateTransitionFailed => self.state_transition_failed += 1,
            error.InvalidStateRoot => self.invalid_state_root += 1,
            error.ExecutionPayloadInvalid => self.execution_payload_invalid += 1,
            error.ExecutionEngineUnavailable => self.execution_engine_unavailable += 1,
            error.ForkChoiceError => self.forkchoice_error += 1,
            error.InternalError => self.internal_error += 1,
        }
    }
};

pub const SegmentImportEffects = struct {
    /// Execution-layer forkchoice update to run after the segment completes.
    forkchoice_update: ?ExecutionForkchoiceUpdate = null,
    /// Finalized checkpoint snapshot after the segment, when relevant.
    finalized_checkpoint: ?CheckpointSnapshot = null,
};

pub const SegmentImportOutcome = struct {
    imported_count: usize,
    skipped_count: usize,
    failed_count: usize,
    optimistic_imported_count: usize = 0,
    epoch_transition_count: usize = 0,
    error_counts: BlockImportErrorCounts = .{},
    snapshot: ChainSnapshot,
    effects: SegmentImportEffects,
};

pub const ExecutionRevalidationOutcome = struct {
    snapshot: ChainSnapshot,
    head_changed: bool,
    forkchoice_update: ?ExecutionForkchoiceUpdate = null,
};

pub const PendingExecutionRevalidation = struct {
    target_head_root: Root,
    invalidate_from_parent_block_root: Root,
};

pub const PreparedExecutionRevalidation = struct {
    pending: PendingExecutionRevalidation,
    request: NewPayloadRequest,

    pub fn deinit(self: *PreparedExecutionRevalidation, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        self.* = undefined;
    }
};

pub const BootstrapOutcome = struct {
    snapshot: ChainSnapshot,
    genesis_time: u64,
    genesis_validators_root: Root,
    earliest_available_slot: Slot,
};
