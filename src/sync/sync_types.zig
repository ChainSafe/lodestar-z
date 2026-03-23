//! Sync status types and peer sync information.
//!
//! Defines the high-level sync state machine and the per-peer sync metadata
//! used throughout the sync subsystem.

/// High-level sync state. Drives the sync manager's main loop.
pub const SyncState = enum {
    /// Waiting for enough peers to begin syncing.
    awaiting_peers,
    /// Actively downloading and importing blocks.
    syncing,
    /// Head is within acceptable distance of the network.
    synced,
    /// No progress for an extended period despite having peers.
    stalled,
};

/// Per-peer view of the chain, extracted from Status handshakes.
pub const PeerSyncInfo = struct {
    peer_id: []const u8,
    head_slot: u64,
    head_root: [32]u8,
    finalized_epoch: u64,
    finalized_root: [32]u8,
};

/// Aggregate sync status for the node API and internal consumers.
pub const SyncStatus = struct {
    state: SyncState,
    head_slot: u64,
    /// How many slots behind the best known peer we are.
    sync_distance: u64,
    /// Whether the execution layer is running optimistic sync.
    is_optimistic: bool,
};
