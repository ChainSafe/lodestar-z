//! Sync status types, peer sync information, and shared constants.
//!
//! Defines the high-level sync state machine, per-peer sync metadata with
//! owned memory, and constants used across the sync subsystem.
//!
//! Reference: Lodestar `packages/beacon-node/src/sync/interface.ts`

const std = @import("std");
const Allocator = std.mem.Allocator;
const preset = @import("preset").preset;

// ── Constants ────────────────────────────────────────────────────────────

/// If our head is within this many slots of the best known peer, we consider
/// ourselves synced. One full epoch gives headroom for fork-choice oscillation.
pub const SYNC_DISTANCE_THRESHOLD: u64 = 32;

/// Minimum number of connected peers before we begin syncing.
///
/// Keep this at one so range sync can keep retrying across rotating peers;
/// partial PeerDAS column downloads are retained between attempts.
pub const MIN_PEERS_TO_SYNC: usize = 1;

/// Default batch size — one epoch per range request.
///
/// Mirrors Lodestar's EPOCHS_PER_BATCH=1 and BATCH_SLOT_OFFSET=0 semantics:
/// range-sync batches are epoch-aligned so finalized sync can process the
/// finalized checkpoint epoch and then switch cleanly to head sync.
pub const BATCH_SIZE: u64 = preset.SLOTS_PER_EPOCH;

/// Maximum number of pending batches per sync chain.
pub const MAX_PENDING_BATCHES: usize = 10;

/// Maximum download retry attempts per batch before skipping.
pub const MAX_BATCH_DOWNLOAD_ATTEMPTS: u8 = 5;

/// Maximum processing retry attempts per batch.
pub const MAX_BATCH_PROCESSING_ATTEMPTS: u8 = 3;

/// Maximum pending blocks in unknown block sync.
pub const MAX_PENDING_BLOCKS: usize = 64;

/// Maximum fetch attempts per unknown parent root.
pub const MAX_UNKNOWN_PARENT_ATTEMPTS: u8 = 5;

/// Maximum concurrent unknown-block-by-root requests.
pub const MAX_CONCURRENT_UNKNOWN_REQUESTS: usize = 2;

/// Minimum validated epochs on a finalized chain before switching to
/// another chain with more peers (prevents chain-hopping).
pub const MIN_FINALIZED_CHAIN_VALIDATED_EPOCHS: u64 = 10;

// ── Sync state ────────────────────────────────────────────────────────

/// High-level sync state. Drives the sync service's main loop and gossip gating.
pub const SyncState = enum {
    /// Waiting for enough peers to begin syncing.
    awaiting_peers,
    /// Long-range finalized chain sync in progress.
    syncing_finalized,
    /// Head chain sync in progress (finalized is caught up).
    syncing_head,
    /// Head is within acceptable distance of the network.
    synced,
};

/// Aggregate peer-relative sync-service status for diagnostics and internal consumers.
pub const SyncStatus = struct {
    state: SyncState,
    head_slot: u64,
    /// How many slots behind the best known peer we are.
    sync_distance: u64,
    /// Whether the execution layer is running optimistic sync.
    is_optimistic: bool,
};

// ── Chain target ──────────────────────────────────────────────────────

/// Target for a sync chain — the slot and root we're syncing towards.
pub const ChainTarget = struct {
    slot: u64,
    root: [32]u8,

    pub fn eql(a: ChainTarget, b: ChainTarget) bool {
        return a.slot == b.slot and std.mem.eql(u8, &a.root, &b.root);
    }
};

// ── Range sync type ──────────────────────────────────────────────────

/// Whether a peer requires finalized or head chain sync.
pub const RangeSyncType = enum {
    /// Peer's finalized epoch is ahead of ours and we haven't seen the root.
    finalized,
    /// Peer's head is ahead but finalized is the same or close.
    head,
};

// ── Per-peer sync info ───────────────────────────────────────────────

/// Per-peer view of the chain, extracted from Status handshakes.
/// Owns its `peer_id` buffer — copy on insert, free on remove.
pub const PeerSyncInfo = struct {
    /// Heap-allocated copy of the peer's ID string.
    peer_id: []u8,
    head_slot: u64,
    head_root: [32]u8,
    finalized_epoch: u64,
    finalized_root: [32]u8,

    /// Create a PeerSyncInfo that owns a copy of peer_id.
    pub fn initOwned(
        allocator: Allocator,
        peer_id: []const u8,
        head_slot: u64,
        head_root: [32]u8,
        finalized_epoch: u64,
        finalized_root: [32]u8,
    ) !PeerSyncInfo {
        const id_copy = try allocator.dupe(u8, peer_id);
        return .{
            .peer_id = id_copy,
            .head_slot = head_slot,
            .head_root = head_root,
            .finalized_epoch = finalized_epoch,
            .finalized_root = finalized_root,
        };
    }

    /// Free the owned peer_id.
    pub fn deinit(self: *PeerSyncInfo, allocator: Allocator) void {
        if (self.peer_id.len > 0) allocator.free(self.peer_id);
        self.peer_id = &.{};
    }

    pub fn peerIdSlice(self: *const PeerSyncInfo) []const u8 {
        return self.peer_id;
    }

    /// The finalized slot (epoch * SLOTS_PER_EPOCH).
    pub fn finalizedSlot(self: *const PeerSyncInfo) u64 {
        return self.finalized_epoch * preset.SLOTS_PER_EPOCH;
    }

    /// Derive the ChainTarget for finalized sync.
    pub fn finalizedTarget(self: *const PeerSyncInfo) ChainTarget {
        return .{
            .slot = self.finalizedSlot(),
            .root = self.finalized_root,
        };
    }

    /// Derive the ChainTarget for head sync.
    pub fn headTarget(self: *const PeerSyncInfo) ChainTarget {
        return .{
            .slot = self.head_slot,
            .root = self.head_root,
        };
    }
};

// ── Tests ────────────────────────────────────────────────────────────

test "PeerSyncInfo: owned lifetime" {
    const allocator = std.testing.allocator;
    var info = try PeerSyncInfo.initOwned(
        allocator,
        "peer_abc",
        100,
        [_]u8{0xAA} ** 32,
        3,
        [_]u8{0xBB} ** 32,
    );
    defer info.deinit(allocator);

    try std.testing.expectEqualStrings("peer_abc", info.peerIdSlice());
    try std.testing.expectEqual(@as(u64, 100), info.head_slot);
    try std.testing.expectEqual(@as(u64, 96), info.finalizedSlot());
}

test "ChainTarget: equality" {
    const a = ChainTarget{ .slot = 100, .root = [_]u8{1} ** 32 };
    const b = ChainTarget{ .slot = 100, .root = [_]u8{1} ** 32 };
    const c = ChainTarget{ .slot = 200, .root = [_]u8{1} ** 32 };
    try std.testing.expect(a.eql(b));
    try std.testing.expect(!a.eql(c));
}
