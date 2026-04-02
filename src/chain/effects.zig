//! Typed chain-side effects and snapshots.
//!
//! These types form the boundary between the synchronous chain state machine
//! and outer runtime adapters such as the node, API, sync, and networking.

const consensus_types = @import("consensus_types");
const networking = @import("networking");
const chain_types = @import("types.zig");

const Slot = consensus_types.primitive.Slot.Type;
const Epoch = consensus_types.primitive.Epoch.Type;
const Root = [32]u8;

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

pub const ArchiveStateRequest = struct {
    slot: Slot,
    state_root: Root,
};

pub const ExecutionForkchoiceUpdate = struct {
    beacon_block_root: Root,
    state: chain_types.ForkchoiceUpdateState,
};

pub const ImportEffects = struct {
    /// Execution-layer forkchoice update to run after the import completes.
    forkchoice_update: ?ExecutionForkchoiceUpdate = null,
    /// Archive this post-state on epoch boundaries.
    archive_state: ?ArchiveStateRequest = null,
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
    /// Archive any epoch-transition post-states imported in the segment.
    archive_states: []const ArchiveStateRequest = &.{},
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

pub const BootstrapOutcome = struct {
    snapshot: ChainSnapshot,
    genesis_time: u64,
    genesis_validators_root: Root,
};
