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

const blocks_types = @import("blocks/types.zig");
const BlockSource = blocks_types.BlockSource;
const DataAvailabilityStatus = blocks_types.DataAvailabilityStatus;

pub const ReadyBlockInput = struct {
    block: fork_types.AnySignedBeaconBlock,
    source: BlockSource,
    block_root: Root,
    slot: Slot,
    da_status: DataAvailabilityStatus,
    block_data_plan: BlockDataFetchPlan = .none,
    seen_timestamp_sec: u64 = 0,

    pub fn deinit(self: *ReadyBlockInput, allocator: std.mem.Allocator) void {
        self.block_data_plan.deinit(allocator);
        self.block.deinit(allocator);
        self.* = undefined;
    }
};

pub const RawBlockBytes = struct {
    slot: Slot,
    bytes: []const u8,
};

pub const PlannedBlockIngress = struct {
    any_signed: fork_types.AnySignedBeaconBlock,
    block_root: Root,
    slot: Slot,
    block_data_plan: BlockDataFetchPlan,

    pub fn deinit(self: *PlannedBlockIngress, allocator: std.mem.Allocator) void {
        self.block_data_plan.deinit(allocator);
        self.any_signed.deinit(allocator);
        self.* = undefined;
    }
};

pub const BlockDataRequirement = enum {
    /// Attachments required before the beacon block itself can be imported.
    /// Gloas payload envelopes are modeled separately from block ingress.
    none,
    blobs,
    columns,
};

pub const BlockIngressReadiness = struct {
    da_status: DataAvailabilityStatus,
    data_requirement: BlockDataRequirement,
};

pub const BlockDataFetchPlan = union(enum) {
    none,
    blobs: []const u64,
    columns: []const u64,

    pub fn deinit(self: *BlockDataFetchPlan, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .none => {},
            .blobs => |indices| if (indices.len > 0) allocator.free(indices),
            .columns => |indices| if (indices.len > 0) allocator.free(indices),
        }
        self.* = undefined;
    }
};

pub const BlockIngressResult = union(enum) {
    ready: ReadyBlockInput,
    pending_block_data: Root,
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

pub const ForkchoiceUpdateState = struct {
    head_block_hash: Root,
    safe_block_hash: Root,
    finalized_block_hash: Root,
};

// ---------------------------------------------------------------------------
// Chain notifications.
//
// These describe state-machine notifications emitted by the chain runtime.
// Outer adapters such as the API event bus are responsible for translating
// them into transport-specific formats like SSE.
// ---------------------------------------------------------------------------

pub const ChainNotificationTag = enum {
    head,
    block,
    finalized_checkpoint,
    chain_reorg,
    attestation,
    voluntary_exit,
    contribution_and_proof,
    payload_attributes,
    blob_sidecar,
};

pub const ChainNotification = union(ChainNotificationTag) {
    head: HeadNotification,
    block: BlockNotification,
    finalized_checkpoint: FinalizedCheckpointNotification,
    chain_reorg: ChainReorgNotification,
    attestation: AttestationNotification,
    voluntary_exit: VoluntaryExitNotification,
    contribution_and_proof: ContributionAndProofNotification,
    payload_attributes: PayloadAttributesNotification,
    blob_sidecar: BlobSidecarNotification,
};

pub const HeadNotification = struct {
    slot: Slot,
    block_root: Root,
    state_root: Root,
    epoch_transition: bool,
    /// Whether the block was imported with optimistic execution status.
    execution_optimistic: bool = false,
};

pub const BlockNotification = struct {
    slot: Slot,
    block_root: Root,
};

pub const FinalizedCheckpointNotification = struct {
    epoch: Epoch,
    root: Root,
    state_root: Root,
};

pub const ChainReorgNotification = struct {
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

/// Published when a new attestation is received (gossip or API).
pub const AttestationNotification = struct {
    aggregation_bits: [8]u8,
    slot: Slot,
    committee_index: u64,
    beacon_block_root: Root,
    source_epoch: Epoch,
    source_root: Root,
    target_epoch: Epoch,
    target_root: Root,
    signature: [96]u8,
};

/// Published when a signed voluntary exit is received.
pub const VoluntaryExitNotification = struct {
    epoch: Epoch,
    validator_index: u64,
    signature: [96]u8,
};

/// Published when a sync committee contribution and proof is received.
pub const ContributionAndProofNotification = struct {
    aggregator_index: u64,
    slot: Slot,
    beacon_block_root: Root,
    subcommittee_index: u64,
    aggregation_bits: [16]u8,
    contribution_signature: [96]u8,
    selection_proof: [96]u8,
};

/// Published when forkchoiceUpdated provides payload attributes.
pub const PayloadAttributesNotification = struct {
    proposer_index: u64,
    proposal_slot: Slot,
    parent_block_number: u64,
    parent_block_root: Root,
    parent_block_hash: Root,
    timestamp: u64,
    prev_randao: Root,
    suggested_fee_recipient: [20]u8,
};

/// Published when a blob sidecar is received.
pub const BlobSidecarNotification = struct {
    block_root: Root,
    index: u64,
    slot: Slot,
    kzg_commitment: [48]u8,
    versioned_hash: Root,
};

// ---------------------------------------------------------------------------
// NotificationSink — vtable for publishing chain notifications.
//
// Chain publishes notifications here when external adapters need to observe
// internal state-machine events. BeaconNode provides the implementation that
// forwards them to the API EventBus.
// ---------------------------------------------------------------------------

pub const NotificationSink = struct {
    ptr: *anyopaque,
    publishFn: *const fn (ptr: *anyopaque, notification: ChainNotification) void,

    pub fn publish(self: NotificationSink, notification: ChainNotification) void {
        self.publishFn(self.ptr, notification);
    }
};
