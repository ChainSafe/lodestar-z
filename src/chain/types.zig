//! Chain-level types for the block import pipeline and chain state queries.
//!
//! These types define the boundaries between the Chain struct and its
//! consumers (BeaconNode, BeaconProcessor, API, P2P).

const std = @import("std");
const consensus_types = @import("consensus_types");
const fork_types = @import("fork_types");

const Slot = consensus_types.primitive.Slot.Type;
const Epoch = consensus_types.primitive.Epoch.Type;
const Root = [32]u8;

// ---------------------------------------------------------------------------
// BlockInput — the atomic unit entering the block import pipeline.
// ---------------------------------------------------------------------------

pub const BlockInput = struct {
    /// The signed beacon block (any fork).
    block: fork_types.AnySignedBeaconBlock,
    /// Where the block came from.
    source: Source,
    /// Data availability status.
    da_status: DataAvailabilityStatus,

    pub const Source = enum {
        /// Received via gossipsub.
        gossip,
        /// Received via req/resp range sync.
        range_sync,
        /// Received via req/resp unknown block sync.
        unknown_block_sync,
        /// Submitted via REST API.
        api,
        /// From checkpoint sync.
        checkpoint_sync,
    };

    pub const DataAvailabilityStatus = enum {
        /// Pre-Deneb: no DA required.
        not_required,
        /// All blobs/columns present and KZG-verified.
        available,
        /// Waiting for blobs/columns — block is quarantined.
        pending,
    };
};

// ---------------------------------------------------------------------------
// ImportResult — outcome of a successful block import.
// ---------------------------------------------------------------------------

pub const ImportResult = struct {
    /// Hash-tree-root of the imported block.
    block_root: Root,
    /// State root of the post-state.
    state_root: Root,
    /// Slot of the imported block.
    slot: Slot,
    /// Whether this block crossed an epoch boundary.
    epoch_transition: bool,
    /// Whether the block was imported with optimistic execution status.
    execution_optimistic: bool = false,
};

// ---------------------------------------------------------------------------
// HeadInfo — current chain head summary.
// ---------------------------------------------------------------------------

pub const HeadInfo = struct {
    /// Slot of the head block.
    slot: Slot,
    /// Block root of the head.
    root: Root,
    /// State root of the head post-state.
    state_root: Root,
    /// Finalized epoch.
    finalized_epoch: Epoch,
    /// Justified epoch.
    justified_epoch: Epoch,
};

// ---------------------------------------------------------------------------
// SyncStatus — node sync health.
// ---------------------------------------------------------------------------

pub const SyncStatus = struct {
    head_slot: Slot,
    sync_distance: u64,
    is_syncing: bool,
    is_optimistic: bool,
    el_offline: bool,
};

// ---------------------------------------------------------------------------
// SSE Events — chain events for SSE subscribers.
//
// These mirror the API event types but are defined here so the chain
// module has no dependency on the API module. The wiring layer (BeaconNode)
// adapts these to the API EventBus.
// ---------------------------------------------------------------------------

pub const SseEventType = enum {
    head,
    block,
    finalized_checkpoint,
    chain_reorg,
};

pub const SseEvent = union(SseEventType) {
    head: HeadEvent,
    block: BlockEvent,
    finalized_checkpoint: FinalizedCheckpointEvent,
    chain_reorg: ChainReorgEvent,
};

pub const HeadEvent = struct {
    slot: Slot,
    block_root: Root,
    state_root: Root,
    epoch_transition: bool,
    /// Whether the block was imported with optimistic execution status.
    execution_optimistic: bool = false,
};

pub const BlockEvent = struct {
    slot: Slot,
    block_root: Root,
};

pub const FinalizedCheckpointEvent = struct {
    epoch: Epoch,
    root: Root,
    state_root: Root,
};

pub const ChainReorgEvent = struct {
    slot: Slot,
    depth: u64,
    old_head_root: Root,
    new_head_root: Root,
};

// ---------------------------------------------------------------------------
// EventCallback — vtable for SSE event emission.
//
// Chain calls this on import success. BeaconNode provides the implementation
// that forwards to the API EventBus.
// ---------------------------------------------------------------------------

pub const EventCallback = struct {
    ptr: *anyopaque,
    emitFn: *const fn (ptr: *anyopaque, event: SseEvent) void,

    pub fn emit(self: EventCallback, event: SseEvent) void {
        self.emitFn(self.ptr, event);
    }
};
