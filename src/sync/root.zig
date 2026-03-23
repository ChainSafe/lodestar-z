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

const std = @import("std");
const testing = std.testing;

pub const sync_types = @import("sync_types.zig");
pub const peer_manager = @import("peer_manager.zig");
pub const range_sync = @import("range_sync.zig");
pub const checkpoint_sync = @import("checkpoint_sync.zig");

// Re-export key types for convenience.
pub const SyncState = sync_types.SyncState;
pub const SyncStatus = sync_types.SyncStatus;
pub const PeerSyncInfo = sync_types.PeerSyncInfo;

pub const PeerManager = peer_manager.PeerManager;

pub const RangeSync = range_sync.RangeSync;
pub const RangeSyncBatch = range_sync.RangeSyncBatch;
pub const BatchResult = range_sync.BatchResult;
pub const BlockEntry = range_sync.BlockEntry;

pub const CheckpointSync = checkpoint_sync.CheckpointSync;
pub const CheckpointSyncResult = checkpoint_sync.CheckpointSyncResult;
pub const CheckpointSyncError = checkpoint_sync.CheckpointSyncError;

test {
    testing.refAllDecls(@This());
}
