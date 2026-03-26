//! Sync subsystem: initial sync, checkpoint sync, and peer tracking.
//!
//! Coordinates the download and import of blocks to bring the node
//! from genesis (or a checkpoint) to the head of the chain.
//!
//! Components:
//! - `sync_types` — shared types (SyncState, PeerSyncInfo, SyncStatus)
//! - `peer_manager` — tracks connected peer chain status
//! - `range_sync` — sequential block-by-range download and import
//! - `checkpoint_sync` — bootstrap from a trusted finalized state
//! - `sync_service` — top-level sync coordinator

const std = @import("std");
const testing = std.testing;

pub const sync_types = @import("sync_types.zig");
pub const peer_manager = @import("peer_manager.zig");
pub const range_sync = @import("range_sync.zig");
pub const checkpoint_sync = @import("checkpoint_sync.zig");
pub const sync_service = @import("sync_service.zig");
pub const unknown_block_sync = @import("unknown_block_sync.zig");

// Re-export key types for convenience.
pub const SyncState = sync_types.SyncState;
pub const SyncStatus = sync_types.SyncStatus;
pub const PeerSyncInfo = sync_types.PeerSyncInfo;

pub const PeerManager = peer_manager.PeerManager;

pub const RangeSync = range_sync.RangeSync;
pub const RangeSyncBatch = range_sync.RangeSyncBatch;
pub const BatchResult = range_sync.BatchResult;
pub const BlockEntry = range_sync.BlockEntry;
pub const RangeSyncManager = range_sync.RangeSyncManager;
pub const BlockImporterCallback = range_sync.BlockImporterCallback;
pub const BatchRequestCallback = range_sync.BatchRequestCallback;
pub const BatchBlock = range_sync.BatchBlock;
pub const Batch = range_sync.Batch;
pub const BatchStatus = range_sync.BatchStatus;

pub const CheckpointSync = checkpoint_sync.CheckpointSync;
pub const CheckpointSyncResult = checkpoint_sync.CheckpointSyncResult;
pub const CheckpointSyncError = checkpoint_sync.CheckpointSyncError;

pub const SyncService = sync_service.SyncService;
pub const SyncMode = sync_service.SyncMode;

pub const UnknownBlockSync = unknown_block_sync.UnknownBlockSync;
pub const PendingBlock = unknown_block_sync.PendingBlock;

test {
    testing.refAllDecls(@This());
}
