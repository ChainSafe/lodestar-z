//! SyncService: top-level sync coordinator.
//!
//! Sits above RangeSyncManager and PeerManager. Receives peer Status
//! messages, decides when and how to sync (range vs checkpoint), and
//! drives the sync loop via periodic tick() calls.
//!
//! Reference: Lodestar `packages/beacon-node/src/sync/sync.ts`

const std = @import("std");
const Allocator = std.mem.Allocator;
const sync_types = @import("sync_types.zig");
const SyncState = sync_types.SyncState;
const SyncStatus = sync_types.SyncStatus;
const PeerSyncInfo = sync_types.PeerSyncInfo;
const PeerManager = @import("peer_manager.zig").PeerManager;
const range_sync = @import("range_sync.zig");
const RangeSyncManager = range_sync.RangeSyncManager;
const BlockImporterCallback = range_sync.BlockImporterCallback;
const BatchRequestCallback = range_sync.BatchRequestCallback;

/// Minimum number of connected peers before we begin syncing.
const MIN_PEERS_TO_SYNC: usize = 1;

/// If our head is within this many slots of the network head, we consider
/// ourselves synced (avoids thrashing on the boundary).
const SYNC_DISTANCE_THRESHOLD: u64 = 2;

/// The sync mode / state machine state.
pub const SyncMode = enum {
    /// No peers connected, waiting for connections.
    idle,
    /// Checkpoint sync in progress (downloading finalized state).
    checkpoint_sync,
    /// Range sync in progress (downloading blocks slot-by-slot).
    range_sync,
    /// Head is close enough to the network head.
    synced,
};

pub const SyncService = struct {
    allocator: Allocator,
    mode: SyncMode,
    range_sync_mgr: RangeSyncManager,
    peer_manager: *PeerManager,

    /// Local head slot — kept in sync with the range sync manager.
    local_head_slot: u64,

    pub fn init(
        allocator: Allocator,
        importer: BlockImporterCallback,
        requester: BatchRequestCallback,
        peer_manager: *PeerManager,
        local_head_slot: u64,
    ) SyncService {
        return .{
            .allocator = allocator,
            .mode = .idle,
            .range_sync_mgr = RangeSyncManager.init(
                allocator,
                importer,
                requester,
                peer_manager,
                local_head_slot,
            ),
            .peer_manager = peer_manager,
            .local_head_slot = local_head_slot,
        };
    }

    /// Called when a peer Status message is received.
    ///
    /// Updates the peer manager and evaluates whether we should start,
    /// continue, or stop syncing.
    pub fn onPeerStatus(self: *SyncService, peer_id: []const u8, status: @import("networking").messages.StatusMessage.Type) !void {
        try self.peer_manager.updatePeerStatus(peer_id, status);
        try self.evaluateMode();
    }

    /// Called when a peer disconnects.
    pub fn onPeerDisconnect(self: *SyncService, peer_id: []const u8) void {
        self.peer_manager.removePeer(peer_id);
    }

    /// Periodic tick — advance the sync state machine.
    pub fn tick(self: *SyncService) !void {
        switch (self.mode) {
            .idle => {
                // Check if we now have peers and should start syncing.
                try self.evaluateMode();
            },
            .range_sync => {
                const status = try self.range_sync_mgr.tick();
                self.local_head_slot = status.head_slot;

                if (status.state == .synced) {
                    self.mode = .synced;
                }

                // Re-evaluate in case we need to extend the target.
                try self.evaluateMode();
            },
            .checkpoint_sync => {
                // Checkpoint sync is driven externally (see checkpoint_sync.zig).
                // Once it completes the caller should call start(slot) and we
                // transition to range_sync.
            },
            .synced => {
                // Periodically re-check whether a new peer extends our target.
                try self.evaluateMode();
            },
        }
    }

    /// Returns true when our head slot is within SYNC_DISTANCE_THRESHOLD of the
    /// best known peer.
    pub fn isSynced(self: *const SyncService) bool {
        return self.mode == .synced;
    }

    /// Return the current sync status for the API.
    pub fn getSyncStatus(self: *const SyncService) SyncStatus {
        const best_slot = self.peer_manager.getHighestPeerSlot();
        const sync_distance = if (best_slot > self.local_head_slot)
            best_slot - self.local_head_slot
        else
            0;
        return .{
            .state = switch (self.mode) {
                .idle => .awaiting_peers,
                .checkpoint_sync, .range_sync => .syncing,
                .synced => .synced,
            },
            .head_slot = self.local_head_slot,
            .sync_distance = sync_distance,
            .is_optimistic = false,
        };
    }

    // ── Internal helpers ────────────────────────────────────────────

    /// Re-evaluate sync mode based on current peer set and head slot.
    fn evaluateMode(self: *SyncService) !void {
        const peer_count = self.peer_manager.peerCount();
        if (peer_count < MIN_PEERS_TO_SYNC) {
            self.mode = .idle;
            return;
        }

        const best_slot = self.peer_manager.getHighestPeerSlot();
        const sync_distance = if (best_slot > self.local_head_slot)
            best_slot - self.local_head_slot
        else
            0;

        if (sync_distance <= SYNC_DISTANCE_THRESHOLD) {
            self.mode = .synced;
            return;
        }

        // Need to range-sync.
        if (self.mode != .range_sync) {
            self.mode = .range_sync;
            self.range_sync_mgr.start(best_slot);
        } else {
            // Extend target if a better peer appeared.
            if (best_slot > self.range_sync_mgr.target_slot) {
                self.range_sync_mgr.start(best_slot);
            }
        }
    }
};

// ── Tests ────────────────────────────────────────────────────────────

const networking = @import("networking");
const StatusMessage = networking.messages.StatusMessage;

/// Minimal no-op importer/requester for service-level tests.
const NoopHarness = struct {
    fn importFn(ptr: *anyopaque, block_bytes: []const u8) anyerror!void {
        _ = ptr;
        _ = block_bytes;
    }
    fn requestFn(ptr: *anyopaque, batch_id: u32, start_slot: u64, count: u64, peer_id: []const u8) void {
        _ = ptr;
        _ = batch_id;
        _ = start_slot;
        _ = count;
        _ = peer_id;
    }
    var dummy: u8 = 0;
    fn importer() BlockImporterCallback {
        return .{ .ptr = &dummy, .importFn = &importFn };
    }
    fn requester() BatchRequestCallback {
        return .{ .ptr = &dummy, .requestFn = &requestFn };
    }
};

test "SyncService: idle with no peers" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator);
    defer pm.deinit();

    var svc = SyncService.init(allocator, NoopHarness.importer(), NoopHarness.requester(), &pm, 0);
    try std.testing.expectEqual(SyncMode.idle, svc.mode);
    try std.testing.expect(!svc.isSynced());

    try svc.tick();
    try std.testing.expectEqual(SyncMode.idle, svc.mode);
}

test "SyncService: transitions idle -> range_sync on peer arrival" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator);
    defer pm.deinit();

    var svc = SyncService.init(allocator, NoopHarness.importer(), NoopHarness.requester(), &pm, 0);

    // Add a peer well ahead of us.
    try svc.onPeerStatus("p1", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .head_root = [_]u8{0} ** 32,
        .head_slot = 500,
    });

    try std.testing.expectEqual(SyncMode.range_sync, svc.mode);
    try std.testing.expect(!svc.isSynced());
}

test "SyncService: transitions range_sync -> synced when caught up" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator);
    defer pm.deinit();

    // Start with a peer at slot 10; we're at slot 9 (within threshold of 2).
    var svc = SyncService.init(allocator, NoopHarness.importer(), NoopHarness.requester(), &pm, 9);

    try svc.onPeerStatus("p1", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .head_root = [_]u8{0} ** 32,
        .head_slot = 10,
    });

    // sync_distance = 1 <= threshold(2), so should be synced immediately.
    try std.testing.expectEqual(SyncMode.synced, svc.mode);
    try std.testing.expect(svc.isSynced());
}

test "SyncService: peer disconnect removes from manager" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator);
    defer pm.deinit();

    var svc = SyncService.init(allocator, NoopHarness.importer(), NoopHarness.requester(), &pm, 0);

    try svc.onPeerStatus("p1", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .head_root = [_]u8{0} ** 32,
        .head_slot = 500,
    });
    try std.testing.expectEqual(@as(usize, 1), pm.peerCount());

    svc.onPeerDisconnect("p1");
    try std.testing.expectEqual(@as(usize, 0), pm.peerCount());
}

test "SyncService: getSyncStatus reports correct distance" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator);
    defer pm.deinit();

    var svc = SyncService.init(allocator, NoopHarness.importer(), NoopHarness.requester(), &pm, 100);

    try svc.onPeerStatus("p1", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .head_root = [_]u8{0} ** 32,
        .head_slot = 500,
    });

    const status = svc.getSyncStatus();
    try std.testing.expectEqual(SyncState.syncing, status.state);
    try std.testing.expectEqual(@as(u64, 400), status.sync_distance);
    try std.testing.expectEqual(@as(u64, 100), status.head_slot);
}
