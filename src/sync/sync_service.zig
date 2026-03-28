//! SyncService: top-level sync coordinator.
//!
//! The single entry point for the sync subsystem. Manages:
//! - Mode state machine (idle → syncing_finalized/syncing_head → synced)
//! - RangeSync (finalized + head chains)
//! - UnknownBlockSync (active parent fetch)
//! - Gossip topic subscription gating (don't gossip while range syncing)
//!
//! Sits directly below BeaconNode — no SyncController intermediary.
//!
//! Reference: Lodestar `packages/beacon-node/src/sync/sync.ts`

const std = @import("std");
const Allocator = std.mem.Allocator;
const networking = @import("networking");
const StatusMessage = networking.messages.StatusMessage;
const NetPeerManager = networking.peer_manager.PeerManager;

const sync_types = @import("sync_types.zig");
const SyncState = sync_types.SyncState;
const SyncStatus = sync_types.SyncStatus;
const ChainTarget = sync_types.ChainTarget;
const RangeSyncType = sync_types.RangeSyncType;

const range_sync_mod = @import("range_sync.zig");
const RangeSync = range_sync_mod.RangeSync;
const RangeSyncCallbacks = range_sync_mod.RangeSyncCallbacks;
const RangeSyncStatus = range_sync_mod.RangeSyncStatus;

const unknown_block_mod = @import("unknown_block.zig");
const UnknownBlockSync = unknown_block_mod.UnknownBlockSync;
const UnknownBlockCallbacks = unknown_block_mod.UnknownBlockCallbacks;

const batch_mod = @import("batch.zig");
const BatchBlock = batch_mod.BatchBlock;
const BatchId = batch_mod.BatchId;

/// Gossip gating state — whether gossip topics should be subscribed.
pub const GossipState = enum {
    /// Gossip is disabled — we're range syncing far from head.
    disabled,
    /// Gossip is enabled — we're synced or close enough.
    enabled,
};

/// The sync service mode.
pub const SyncMode = enum {
    /// No peers connected, waiting.
    idle,
    /// Checkpoint sync in progress.
    checkpoint_sync,
    /// Range sync (finalized or head chains active).
    range_sync,
    /// Synced with the network.
    synced,
};

/// Callback vtable provided by BeaconNode.
pub const SyncServiceCallbacks = struct {
    ptr: *anyopaque,

    /// Import a block through the chain pipeline.
    importBlockFn: *const fn (ptr: *anyopaque, block_bytes: []const u8) anyerror!void,

    /// Request blocks by range from a peer.
    requestBlocksByRangeFn: *const fn (
        ptr: *anyopaque,
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
        peer_id: []const u8,
        start_slot: u64,
        count: u64,
    ) void,

    /// Request a block by root from a peer.
    requestBlockByRootFn: *const fn (
        ptr: *anyopaque,
        root: [32]u8,
        peer_id: []const u8,
    ) void,

    /// Report a peer for bad behavior.
    reportPeerFn: *const fn (ptr: *anyopaque, peer_id: []const u8) void,

    /// Get connected peer IDs.
    getConnectedPeersFn: *const fn (ptr: *anyopaque) []const []const u8,

    /// Enable/disable gossip subscriptions.
    setGossipEnabledFn: ?*const fn (ptr: *anyopaque, enabled: bool) void,

    pub fn importBlock(self: SyncServiceCallbacks, block_bytes: []const u8) !void {
        return self.importBlockFn(self.ptr, block_bytes);
    }

    pub fn requestBlocksByRange(
        self: SyncServiceCallbacks,
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
        peer_id: []const u8,
        start_slot: u64,
        count: u64,
    ) void {
        self.requestBlocksByRangeFn(self.ptr, chain_id, batch_id, generation, peer_id, start_slot, count);
    }

    pub fn reportPeer(self: SyncServiceCallbacks, peer_id: []const u8) void {
        self.reportPeerFn(self.ptr, peer_id);
    }

    pub fn setGossipEnabled(self: SyncServiceCallbacks, enabled: bool) void {
        if (self.setGossipEnabledFn) |f| f(self.ptr, enabled);
    }
};

/// Top-level sync service.
pub const SyncService = struct {
    allocator: Allocator,
    mode: SyncMode,
    gossip_state: GossipState,

    /// Range sync — manages finalized and head chains.
    range_sync: RangeSync,
    /// Unknown block sync — active parent fetch.
    unknown_block_sync: UnknownBlockSync,
    /// Callbacks provided by BeaconNode.
    callbacks: SyncServiceCallbacks,

    /// Our local head slot.
    local_head_slot: u64,
    /// Our local finalized epoch.
    local_finalized_epoch: u64,
    /// Set of known connected peers (deduplicated by peer_id string key).
    /// Heap-allocated string keys; freed on remove/deinit.
    known_peers: std.StringHashMap(void),
    /// Number of connected peers — derived from known_peers.count().
    peer_count: usize,
    /// Highest known peer slot.
    best_peer_slot: u64,

    pub fn init(
        allocator: Allocator,
        callbacks: SyncServiceCallbacks,
        local_head_slot: u64,
        local_finalized_epoch: u64,
    ) SyncService {
        // Build range sync callbacks. processChainSegmentImpl is kept as a
        // compatibility shim but importBlockFn is called directly in SyncChain.
        const range_callbacks = RangeSyncCallbacks{
            .ptr = callbacks.ptr,
            .importBlockFn = callbacks.importBlockFn,
            .processChainSegmentFn = &processChainSegmentImpl,
            .downloadByRangeFn = callbacks.requestBlocksByRangeFn,
            .reportPeerFn = callbacks.reportPeerFn,
        };

        const unknown_block_callbacks = UnknownBlockCallbacks{
            .ptr = callbacks.ptr,
            .requestBlockByRootFn = callbacks.requestBlockByRootFn,
            .importBlockFn = callbacks.importBlockFn,
            .getConnectedPeersFn = callbacks.getConnectedPeersFn,
        };

        var svc: SyncService = .{
            .allocator = allocator,
            .mode = .idle,
            .gossip_state = .enabled,
            .range_sync = RangeSync.init(allocator, range_callbacks),
            .unknown_block_sync = UnknownBlockSync.init(allocator),
            .callbacks = callbacks,
            .local_head_slot = local_head_slot,
            .local_finalized_epoch = local_finalized_epoch,
            .known_peers = std.StringHashMap(void).init(allocator),
            .peer_count = 0,
            .best_peer_slot = 0,
        };
        svc.unknown_block_sync.setCallbacks(unknown_block_callbacks);
        return svc;
    }

    pub fn deinit(self: *SyncService) void {
        self.range_sync.deinit();
        self.unknown_block_sync.deinit();
        var it = self.known_peers.keyIterator();
        while (it.next()) |k| self.allocator.free(k.*);
        self.known_peers.deinit();
    }

    /// Called when a peer Status message is received.
    pub fn onPeerStatus(
        self: *SyncService,
        peer_id: []const u8,
        status: StatusMessage.Type,
    ) !void {
        // Track peers in a set to avoid double-counting repeated Status messages.
        if (!self.known_peers.contains(peer_id)) {
            const owned_key = try self.allocator.dupe(u8, peer_id);
            try self.known_peers.put(owned_key, {});
        }
        self.peer_count = @intCast(self.known_peers.count());
        if (status.head_slot > self.best_peer_slot) {
            self.best_peer_slot = status.head_slot;
        }

        // Determine if this peer is "advanced" (worth syncing from).
        const sync_distance = if (status.head_slot > self.local_head_slot)
            status.head_slot - self.local_head_slot
        else
            0;

        if (sync_distance > sync_types.SYNC_DISTANCE_THRESHOLD) {
            // Peer is sufficiently ahead — add to range sync.
            try self.range_sync.addPeer(
                peer_id,
                self.local_finalized_epoch,
                status.finalized_epoch,
                status.finalized_root,
                status.head_slot,
                status.head_root,
            );
        }

        self.updateMode();
    }

    /// Called when a peer disconnects.
    pub fn onPeerDisconnect(self: *SyncService, peer_id: []const u8) void {
        if (self.known_peers.fetchRemove(peer_id)) |kv| {
            self.allocator.free(kv.key);
        }
        self.peer_count = @intCast(self.known_peers.count());
        self.range_sync.removePeer(peer_id);
        self.updateMode();
    }

    /// Called when local head advances (block imported).
    pub fn onHeadUpdate(self: *SyncService, head_slot: u64) void {
        self.local_head_slot = head_slot;
        self.updateMode();
    }

    /// Called when finalized checkpoint advances.
    pub fn onFinalizedUpdate(self: *SyncService, finalized_epoch: u64) void {
        self.local_finalized_epoch = finalized_epoch;
    }

    /// Periodic tick — drive range sync and unknown block sync.
    pub fn tick(self: *SyncService) !void {
        // Drive range sync.
        try self.range_sync.tick();

        // Drive unknown block sync (active fetch loop).
        self.unknown_block_sync.tick();

        // Re-evaluate mode.
        self.updateMode();
    }

    /// Route a batch response from the network to the correct sync chain.
    pub fn onBatchResponse(
        self: *SyncService,
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
        blocks: []const BatchBlock,
    ) void {
        self.range_sync.onBatchResponse(chain_id, batch_id, generation, blocks);
    }

    /// Route a batch error from the network.
    pub fn onBatchError(
        self: *SyncService,
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
        peer_id: []const u8,
    ) void {
        self.range_sync.onBatchError(chain_id, batch_id, generation, peer_id);
    }

    /// Add a pending unknown block (unknown parent).
    pub fn addUnknownBlock(
        self: *SyncService,
        block_root: [32]u8,
        parent_root: [32]u8,
        slot: u64,
        block_bytes: []const u8,
    ) !bool {
        return self.unknown_block_sync.addPendingBlock(block_root, parent_root, slot, block_bytes);
    }

    /// Whether we're synced with the network.
    pub fn isSynced(self: *const SyncService) bool {
        return self.mode == .synced;
    }

    /// Return the current sync status for the API.
    pub fn getSyncStatus(self: *const SyncService) SyncStatus {
        const sync_distance = if (self.best_peer_slot > self.local_head_slot)
            self.best_peer_slot - self.local_head_slot
        else
            0;
        return .{
            .state = switch (self.mode) {
                .idle => .awaiting_peers,
                .checkpoint_sync => .syncing_finalized,
                .range_sync => blk: {
                    const rs = self.range_sync.getState();
                    break :blk switch (rs.status) {
                        .finalized => .syncing_finalized,
                        .head => .syncing_head,
                        .idle => .synced,
                    };
                },
                .synced => .synced,
            },
            .head_slot = self.local_head_slot,
            .sync_distance = sync_distance,
            .is_optimistic = false,
        };
    }

    /// Whether gossip should be enabled.
    pub fn shouldEnableGossip(self: *const SyncService) bool {
        return self.mode == .synced or self.mode == .idle;
    }

    // ── Internal ────────────────────────────────────────────────────

    fn updateMode(self: *SyncService) void {
        if (self.peer_count < sync_types.MIN_PEERS_TO_SYNC) {
            self.setMode(.idle);
            return;
        }

        const sync_distance = if (self.best_peer_slot > self.local_head_slot)
            self.best_peer_slot - self.local_head_slot
        else
            0;

        if (sync_distance <= sync_types.SYNC_DISTANCE_THRESHOLD) {
            self.setMode(.synced);
            return;
        }

        const rs = self.range_sync.getState();
        if (rs.status != .idle) {
            self.setMode(.range_sync);
        } else {
            // We have peers ahead but no range sync chain is running.
            // This can happen if all chains completed but peers are still
            // ahead (e.g., gossip will catch up).
            self.setMode(.synced);
        }
    }

    fn setMode(self: *SyncService, new_mode: SyncMode) void {
        if (self.mode == new_mode) return;

        const old_mode = self.mode;
        self.mode = new_mode;

        // Gossip gating: disable during range sync, enable otherwise.
        const new_gossip: GossipState = if (self.shouldEnableGossip()) .enabled else .disabled;
        if (new_gossip != self.gossip_state) {
            self.gossip_state = new_gossip;
            self.callbacks.setGossipEnabled(new_gossip == .enabled);
        }

        _ = old_mode;
    }

    /// Compatibility shim for RangeSyncCallbacks.processChainSegmentFn.
    /// Block import is done directly by SyncChain.processNextBatch via importBlockFn.
    fn processChainSegmentImpl(_: *anyopaque, _: []const BatchBlock, _: RangeSyncType) anyerror!void {}
};

// ── Tests ────────────────────────────────────────────────────────────

const TestSyncServiceCallbacks = struct {
    imported_count: u32 = 0,
    requested_count: u32 = 0,
    reported_count: u32 = 0,
    gossip_enabled: ?bool = null,

    fn importBlockFn(ptr: *anyopaque, _: []const u8) anyerror!void {
        const self: *TestSyncServiceCallbacks = @ptrCast(@alignCast(ptr));
        self.imported_count += 1;
    }

    fn requestBlocksByRangeFn(ptr: *anyopaque, _: u32, _: BatchId, _: u32, _: []const u8, _: u64, _: u64) void {
        const self: *TestSyncServiceCallbacks = @ptrCast(@alignCast(ptr));
        self.requested_count += 1;
    }

    fn requestBlockByRootFn(_: *anyopaque, _: [32]u8, _: []const u8) void {}

    fn reportPeerFn(ptr: *anyopaque, _: []const u8) void {
        const self: *TestSyncServiceCallbacks = @ptrCast(@alignCast(ptr));
        self.reported_count += 1;
    }

    fn getConnectedPeersFn(_: *anyopaque) []const []const u8 {
        return &.{};
    }

    fn setGossipEnabledFn(ptr: *anyopaque, enabled: bool) void {
        const self: *TestSyncServiceCallbacks = @ptrCast(@alignCast(ptr));
        self.gossip_enabled = enabled;
    }

    fn callbacks(self: *TestSyncServiceCallbacks) SyncServiceCallbacks {
        return .{
            .ptr = self,
            .importBlockFn = &importBlockFn,
            .requestBlocksByRangeFn = &requestBlocksByRangeFn,
            .requestBlockByRootFn = &requestBlockByRootFn,
            .reportPeerFn = &reportPeerFn,
            .getConnectedPeersFn = &getConnectedPeersFn,
            .setGossipEnabledFn = &setGossipEnabledFn,
        };
    }
};

test "SyncService: idle with no peers" {
    const allocator = std.testing.allocator;
    var tc = TestSyncServiceCallbacks{};
    var svc = SyncService.init(allocator, tc.callbacks(), 0, 0);
    defer svc.deinit();

    try std.testing.expectEqual(SyncMode.idle, svc.mode);
    try std.testing.expect(!svc.isSynced());

    try svc.tick();
    try std.testing.expectEqual(SyncMode.idle, svc.mode);
}

test "SyncService: transitions to range_sync on advanced peer" {
    const allocator = std.testing.allocator;
    var tc = TestSyncServiceCallbacks{};
    var svc = SyncService.init(allocator, tc.callbacks(), 0, 0);
    defer svc.deinit();

    try svc.onPeerStatus("p1", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 10,
        .head_root = [_]u8{0xAA} ** 32,
        .head_slot = 500,
    });

    try std.testing.expectEqual(SyncMode.range_sync, svc.mode);
    try std.testing.expect(!svc.isSynced());
}

test "SyncService: synced when peer is within threshold" {
    const allocator = std.testing.allocator;
    var tc = TestSyncServiceCallbacks{};
    // Local head at 490, threshold is 32.
    var svc = SyncService.init(allocator, tc.callbacks(), 490, 15);
    defer svc.deinit();

    try svc.onPeerStatus("p1", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 15,
        .head_root = [_]u8{0xAA} ** 32,
        .head_slot = 500,
    });

    // Distance = 10 <= 32, so synced.
    try std.testing.expectEqual(SyncMode.synced, svc.mode);
    try std.testing.expect(svc.isSynced());
}

test "SyncService: peer disconnect" {
    const allocator = std.testing.allocator;
    var tc = TestSyncServiceCallbacks{};
    var svc = SyncService.init(allocator, tc.callbacks(), 0, 0);
    defer svc.deinit();

    try svc.onPeerStatus("p1", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 10,
        .head_root = [_]u8{0xAA} ** 32,
        .head_slot = 500,
    });

    svc.onPeerDisconnect("p1");
    try std.testing.expectEqual(@as(usize, 0), svc.peer_count);
}

test "SyncService: gossip gating" {
    const allocator = std.testing.allocator;
    var tc = TestSyncServiceCallbacks{};
    var svc = SyncService.init(allocator, tc.callbacks(), 0, 0);
    defer svc.deinit();

    // Initially idle — gossip should be enabled (we're not range syncing).
    try std.testing.expect(svc.shouldEnableGossip());

    // Add far peer — triggers range sync → gossip disabled.
    try svc.onPeerStatus("p1", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 100,
        .head_root = [_]u8{0xBB} ** 32,
        .head_slot = 5000,
    });

    try std.testing.expectEqual(SyncMode.range_sync, svc.mode);
    try std.testing.expect(!svc.shouldEnableGossip());
    try std.testing.expectEqual(@as(?bool, false), tc.gossip_enabled);
}

test "SyncService: getSyncStatus reports correct state" {
    const allocator = std.testing.allocator;
    var tc = TestSyncServiceCallbacks{};
    var svc = SyncService.init(allocator, tc.callbacks(), 100, 3);
    defer svc.deinit();

    try svc.onPeerStatus("p1", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 20,
        .head_root = [_]u8{0xCC} ** 32,
        .head_slot = 700,
    });

    const status = svc.getSyncStatus();
    try std.testing.expectEqual(@as(u64, 600), status.sync_distance);
    try std.testing.expectEqual(@as(u64, 100), status.head_slot);
}
