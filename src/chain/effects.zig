//! Typed chain-side effects and snapshots.
//!
//! These types form the boundary between the synchronous chain state machine
//! and outer runtime adapters such as the node, API, sync, and networking.

const std = @import("std");
const consensus_types = @import("consensus_types");
const networking = @import("networking");
const chain_types = @import("types.zig");
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
    result: chain_types.ImportResult,
    snapshot: ChainSnapshot,
    effects: ImportEffects,
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
