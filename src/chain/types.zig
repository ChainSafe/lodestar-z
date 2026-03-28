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
// BlockInput — re-export from blocks/types.zig (P1-7 consolidation fix).
//
// The pipeline's BlockInput (blocks/types.zig) is the single canonical type.
// This alias keeps backward compatibility for callers using chain-level types.
// ---------------------------------------------------------------------------

const blocks_types = @import("blocks/types.zig");
pub const BlockInput = blocks_types.BlockInput;
pub const BlockSource = blocks_types.BlockSource;

// ---------------------------------------------------------------------------
// ImportResult — re-export from blocks/types.zig (P1-8 consolidation fix).
//
// The pipeline's ImportResult (blocks/types.zig) is the single canonical type.
// This alias keeps backward compatibility for callers using chain-level types.
// ---------------------------------------------------------------------------

pub const ImportResult = blocks_types.ImportResult;

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
    /// State root of the old head (before reorg).
    old_state_root: Root,
    /// State root of the new head (after reorg).
    new_state_root: Root,
    /// Epoch of the new head slot.
    epoch: Epoch,
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
