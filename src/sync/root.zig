//! Sync subsystem: range sync, checkpoint sync, unknown block sync.
//!
//! Coordinates the download and import of blocks to bring the node
//! from genesis (or a checkpoint) to the head of the chain.
//!
//! Architecture (two layers only):
//!   BeaconNode → SyncService → RangeSync (finalized + head chains)
//!                            → UnknownBlockSync (active parent fetch)
//!                            → CheckpointSync (bootstrap from checkpoint)
//!
//! No SyncController intermediary — SyncService is the single entry point.

const std = @import("std");
const testing = std.testing;

pub const sync_types = @import("sync_types.zig");
pub const batch = @import("batch.zig");
pub const sync_chain = @import("sync_chain.zig");
pub const range_sync = @import("range_sync.zig");
pub const sync_service = @import("sync_service.zig");
pub const unknown_block = @import("unknown_block.zig");
pub const checkpoint_sync = @import("checkpoint_sync.zig");
pub const unknown_chain = @import("unknown_chain/root.zig");

// Re-export key types for convenience.
pub const SyncState = sync_types.SyncState;
pub const SyncStatus = sync_types.SyncStatus;
pub const PeerSyncInfo = sync_types.PeerSyncInfo;
pub const ChainTarget = sync_types.ChainTarget;
pub const RangeSyncType = sync_types.RangeSyncType;
pub const SyncPeerReportReason = sync_types.SyncPeerReportReason;

pub const Batch = batch.Batch;
pub const BatchStatus = batch.BatchStatus;
pub const BatchBlock = batch.BatchBlock;
pub const BatchId = batch.BatchId;

pub const SyncChain = sync_chain.SyncChain;
pub const SyncChainStatus = sync_chain.SyncChainStatus;
pub const SyncChainCallbacks = sync_chain.SyncChainCallbacks;

pub const RangeSync = range_sync.RangeSync;
pub const RangeSyncCallbacks = range_sync.RangeSyncCallbacks;
pub const RangeSyncStatus = range_sync.RangeSyncStatus;

pub const SyncService = sync_service.SyncService;
pub const SyncMode = sync_service.SyncMode;
pub const SyncServiceCallbacks = sync_service.SyncServiceCallbacks;
pub const GossipState = sync_service.GossipState;

pub const UnknownBlockSync = unknown_block.UnknownBlockSync;
pub const PendingBlock = unknown_block.PendingBlock;
pub const UnknownBlockCallbacks = unknown_block.UnknownBlockCallbacks;

pub const CheckpointSync = checkpoint_sync.CheckpointSync;
pub const CheckpointSyncResult = checkpoint_sync.CheckpointSyncResult;
pub const CheckpointSyncError = checkpoint_sync.CheckpointSyncError;

pub const UnknownChainSync = unknown_chain.UnknownChainSync;
pub const BackwardsChain = unknown_chain.BackwardsChain;
pub const MinimalHeader = unknown_chain.MinimalHeader;
pub const ChainState = unknown_chain.ChainState;

test {
    testing.refAllDecls(@This());
}
