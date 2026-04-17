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
const scoped_log = std.log.scoped(.sync_service);
const Allocator = std.mem.Allocator;
const networking = @import("networking");
const StatusMessage = networking.messages.StatusMessage;
const NetPeerManager = networking.peer_manager.PeerManager;

const sync_types = @import("sync_types.zig");
const SyncState = sync_types.SyncState;
const SyncStatus = sync_types.SyncStatus;
const ChainTarget = sync_types.ChainTarget;
const RangeSyncType = sync_types.RangeSyncType;
const PeerSyncType = sync_types.PeerSyncType;
const SyncPeerReportReason = sync_types.SyncPeerReportReason;

const range_sync_mod = @import("range_sync.zig");
const RangeSync = range_sync_mod.RangeSync;
const RangeSyncCallbacks = range_sync_mod.RangeSyncCallbacks;
const RangeSyncStatus = range_sync_mod.RangeSyncStatus;
const RangeSyncMetricsSnapshot = range_sync_mod.MetricsSnapshot;

const unknown_block_mod = @import("unknown_block.zig");
const UnknownBlockSync = unknown_block_mod.UnknownBlockSync;
const UnknownBlockCallbacks = unknown_block_mod.UnknownBlockCallbacks;
const UnknownBlockMetricsSnapshot = unknown_block_mod.MetricsSnapshot;
const PreparedBlockInput = @import("prepared_block").PreparedBlockInput;

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

pub const MetricsSnapshot = struct {
    mode: SyncMode,
    gossip_state: GossipState,
    peer_count: u64,
    best_peer_slot: u64,
    local_head_slot: u64,
    local_finalized_epoch: u64,
    unknown_block_pending: u64,
    unknown_block: UnknownBlockMetricsSnapshot,
    range_sync: RangeSyncMetricsSnapshot,
};

/// Callback vtable provided by BeaconNode.
pub const SyncServiceCallbacks = struct {
    ptr: *anyopaque,

    /// Import a single block through the chain pipeline.
    importBlockFn: *const fn (ptr: *anyopaque, block_bytes: []const u8) anyerror!void,
    importPreparedBlockFn: *const fn (ptr: *anyopaque, prepared: PreparedBlockInput) anyerror!void,

    /// Import a contiguous range-sync segment through the chain pipeline.
    processChainSegmentFn: *const fn (
        ptr: *anyopaque,
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
        blocks: []const BatchBlock,
        sync_type: RangeSyncType,
    ) anyerror!void,

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

    /// Report a peer for bad behavior. The reason is kept sync-local so the
    /// bridge can map it onto the production networking scoring policy.
    reportPeerFn: *const fn (ptr: *anyopaque, peer_id: []const u8, reason: SyncPeerReportReason) void,

    /// Return whether fork choice already knows a block root.
    hasBlockFn: ?*const fn (ptr: *anyopaque, root: [32]u8) bool = null,

    /// Return whether a peer is eligible to serve a batch range.
    /// Used for fork-specific constraints such as Fulu custody overlap.
    peerCanServeRangeFn: ?*const fn (
        ptr: *anyopaque,
        peer_id: []const u8,
        start_slot: u64,
        count: u64,
    ) bool = null,

    /// Get connected peer IDs.
    getConnectedPeersFn: *const fn (ptr: *anyopaque) []const []const u8,

    /// Request a fresh Status exchange for specific peers.
    reStatusPeersFn: ?*const fn (ptr: *anyopaque, peer_ids: []const []const u8) void = null,

    /// Enable/disable gossip subscriptions.
    setGossipEnabledFn: ?*const fn (ptr: *anyopaque, enabled: bool) void,

    pub fn importBlock(self: SyncServiceCallbacks, block_bytes: []const u8) !void {
        return self.importBlockFn(self.ptr, block_bytes);
    }

    pub fn importPreparedBlock(self: SyncServiceCallbacks, prepared: PreparedBlockInput) !void {
        return self.importPreparedBlockFn(self.ptr, prepared);
    }

    pub fn processChainSegment(
        self: SyncServiceCallbacks,
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
        blocks: []const BatchBlock,
        sync_type: RangeSyncType,
    ) !void {
        return self.processChainSegmentFn(self.ptr, chain_id, batch_id, generation, blocks, sync_type);
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

    pub fn reportPeer(self: SyncServiceCallbacks, peer_id: []const u8, reason: SyncPeerReportReason) void {
        self.reportPeerFn(self.ptr, peer_id, reason);
    }

    pub fn hasBlock(self: SyncServiceCallbacks, root: [32]u8) bool {
        if (self.hasBlockFn) |f| return f(self.ptr, root);
        return false;
    }

    pub fn reStatusPeers(self: SyncServiceCallbacks, peer_ids: []const []const u8) void {
        if (self.reStatusPeersFn) |f| f(self.ptr, peer_ids);
    }

    pub fn setGossipEnabled(self: SyncServiceCallbacks, enabled: bool) void {
        if (self.setGossipEnabledFn) |f| f(self.ptr, enabled);
    }
};

fn unknownBlockHasBlockFalse(_: *anyopaque, _: [32]u8) bool {
    return false;
}

/// Top-level sync service.
pub const SyncService = struct {
    const KnownPeer = struct {
        head_slot: u64,
        sync_type: PeerSyncType,
    };

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
    /// Latest wall-clock slot observed by the runtime.
    current_slot: u64,
    /// Our local finalized epoch.
    local_finalized_epoch: u64,
    /// Peers that are not behind our current finalized/head view.
    known_peers: std.StringHashMap(KnownPeer),
    /// Number of non-behind peers — derived from known_peers.count().
    peer_count: usize,
    /// Highest advanced peer slot — recomputed from known_peers on status changes.
    best_peer_slot: u64,
    /// When true, skip the peer-count gate and declare synced immediately.
    /// Used for single-node devnets where there are no peers to sync from.
    is_single_node: bool,

    pub fn init(
        allocator: Allocator,
        io: std.Io,
        callbacks: SyncServiceCallbacks,
        local_head_slot: u64,
        local_finalized_epoch: u64,
    ) SyncService {
        const range_callbacks = RangeSyncCallbacks{
            .ptr = callbacks.ptr,
            .importBlockFn = callbacks.importBlockFn,
            .processChainSegmentFn = callbacks.processChainSegmentFn,
            .downloadByRangeFn = callbacks.requestBlocksByRangeFn,
            .reportPeerFn = callbacks.reportPeerFn,
            .hasBlockFn = callbacks.hasBlockFn,
            .reStatusPeersFn = callbacks.reStatusPeersFn,
            .peerCanServeRangeFn = callbacks.peerCanServeRangeFn,
        };

        const unknown_block_callbacks = UnknownBlockCallbacks{
            .ptr = callbacks.ptr,
            .requestBlockByRootFn = callbacks.requestBlockByRootFn,
            .importBlockFn = callbacks.importPreparedBlockFn,
            .hasBlockFn = callbacks.hasBlockFn orelse &unknownBlockHasBlockFalse,
            .getConnectedPeersFn = callbacks.getConnectedPeersFn,
        };

        var svc: SyncService = .{
            .allocator = allocator,
            .mode = .idle,
            .gossip_state = .enabled,
            .range_sync = RangeSync.init(allocator, io, range_callbacks),
            .unknown_block_sync = UnknownBlockSync.init(allocator),
            .callbacks = callbacks,
            .local_head_slot = local_head_slot,
            .current_slot = local_head_slot,
            .local_finalized_epoch = local_finalized_epoch,
            .known_peers = std.StringHashMap(KnownPeer).init(allocator),
            .peer_count = 0,
            .best_peer_slot = 0,
            .is_single_node = false,
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
        earliest_available_slot: ?u64,
    ) !void {
        const peer_sync_type = sync_types.getPeerSyncType(
            self.local_head_slot,
            self.local_finalized_epoch,
            status.head_slot,
            self.callbacks.hasBlock(status.head_root),
            status.finalized_epoch,
        );

        switch (peer_sync_type) {
            .behind => {
                if (self.known_peers.fetchRemove(peer_id)) |kv| {
                    self.allocator.free(kv.key);
                }
                self.range_sync.removePeer(peer_id);
            },
            .fully_synced, .advanced => {
                if (self.known_peers.getPtr(peer_id)) |peer_ptr| {
                    peer_ptr.* = .{
                        .head_slot = status.head_slot,
                        .sync_type = peer_sync_type,
                    };
                } else {
                    const owned_key = try self.allocator.dupe(u8, peer_id);
                    errdefer self.allocator.free(owned_key);
                    try self.known_peers.put(owned_key, .{
                        .head_slot = status.head_slot,
                        .sync_type = peer_sync_type,
                    });
                }

                if (peer_sync_type != .advanced) {
                    self.range_sync.removePeer(peer_id);
                }
            },
        }
        self.recomputePeerSummary();

        // Determine if this peer is "advanced" (worth syncing from).
        const sync_distance = if (status.head_slot > self.local_head_slot)
            status.head_slot - self.local_head_slot
        else
            0;
        scoped_log.debug(
            "SyncService peer status: peer={s} local_head={d} local_finalized={d} peer_head={d} peer_finalized={d} earliest={any} distance={d} sync_type={s} known_peers={d}",
            .{
                peer_id,
                self.local_head_slot,
                self.local_finalized_epoch,
                status.head_slot,
                status.finalized_epoch,
                earliest_available_slot,
                sync_distance,
                @tagName(peer_sync_type),
                self.peer_count,
            },
        );

        if (peer_sync_type == .advanced) {
            // Peer is sufficiently ahead — add to range sync.
            scoped_log.debug("SyncService adding peer to range sync: peer={s} distance={d}", .{ peer_id, sync_distance });
            try self.range_sync.addPeer(
                peer_id,
                self.local_finalized_epoch,
                status.finalized_epoch,
                status.finalized_root,
                status.head_slot,
                status.head_root,
                earliest_available_slot,
            );
        }

        self.updateMode();
    }

    /// Called when a peer disconnects.
    pub fn onPeerDisconnect(self: *SyncService, peer_id: []const u8) void {
        if (self.known_peers.fetchRemove(peer_id)) |kv| {
            self.allocator.free(kv.key);
        }
        self.recomputePeerSummary();
        self.range_sync.removePeer(peer_id);
        self.updateMode();
    }

    /// Called on each runtime tick with the latest wall-clock slot.
    pub fn onClockSlot(self: *SyncService, current_slot: u64) void {
        if (current_slot <= self.current_slot) return;
        self.current_slot = current_slot;
        self.updateMode();
    }

    /// Called when local head advances (block imported).
    pub fn onHeadUpdate(self: *SyncService, head_slot: u64) void {
        self.local_head_slot = head_slot;
        if (head_slot > self.current_slot) self.current_slot = head_slot;
        self.updateMode();
    }

    /// Called when finalized checkpoint advances.
    pub fn onFinalizedUpdate(self: *SyncService, finalized_epoch: u64) void {
        self.local_finalized_epoch = finalized_epoch;
        self.range_sync.onFinalizedUpdate(finalized_epoch);
        self.updateMode();
    }

    /// Periodic tick — drive range sync and unknown block sync.
    pub fn tick(self: *SyncService) !void {
        try self.pruneDisconnectedPeers();

        const range_state = self.range_sync.getState();

        // Require a minimum peer count to start syncing, but keep driving an
        // active chain so already-downloaded batches still import during peer churn.
        if (self.peer_count >= sync_types.MIN_PEERS_TO_SYNC or range_state.status != .idle) {
            try self.range_sync.tick();
        }

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

    /// Route a deferred/incomplete batch from the network. Unlike a batch
    /// error, this does not penalize the peer or consume retry budget.
    pub fn onBatchDeferred(
        self: *SyncService,
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
        blocks: []const BatchBlock,
    ) void {
        self.range_sync.onBatchDeferred(chain_id, batch_id, generation, blocks);
        self.updateMode();
    }

    pub fn getBatchBlocks(
        self: *const SyncService,
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
    ) ?[]const BatchBlock {
        return self.range_sync.getBatchBlocks(chain_id, batch_id, generation);
    }

    pub fn onSegmentProcessingSuccess(
        self: *SyncService,
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
    ) void {
        self.range_sync.onSegmentProcessingSuccess(chain_id, batch_id, generation);
        self.updateMode();
    }

    pub fn onSegmentProcessingError(
        self: *SyncService,
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
    ) void {
        self.range_sync.onSegmentProcessingError(chain_id, batch_id, generation);
        self.updateMode();
    }

    /// Add a pending unknown block (unknown parent).
    pub fn addUnknownBlock(
        self: *SyncService,
        prepared: PreparedBlockInput,
    ) !bool {
        return self.unknown_block_sync.addPendingBlock(prepared);
    }

    /// Whether we're synced with the network.
    pub fn isSynced(self: *const SyncService) bool {
        return self.mode == .synced;
    }

    /// Return the current sync-service status.
    pub fn getSyncStatus(self: *const SyncService) SyncStatus {
        const sync_distance = if (self.mode == .synced) 0 else self.currentHeadLag();
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
        if (self.mode == .synced) return true;
        return self.currentHeadLag() <= sync_types.SYNC_DISTANCE_THRESHOLD * 2;
    }

    pub fn metricsSnapshot(self: *const SyncService) MetricsSnapshot {
        const unknown_block = self.unknown_block_sync.metricsSnapshot();
        return .{
            .mode = self.mode,
            .gossip_state = self.gossip_state,
            .peer_count = @intCast(self.peer_count),
            .best_peer_slot = self.best_peer_slot,
            .local_head_slot = self.local_head_slot,
            .local_finalized_epoch = self.local_finalized_epoch,
            .unknown_block_pending = unknown_block.pending_blocks,
            .unknown_block = unknown_block,
            .range_sync = self.range_sync.metricsSnapshot(),
        };
    }

    // ── Internal ────────────────────────────────────────────────────

    fn pruneDisconnectedPeers(self: *SyncService) !void {
        if (self.known_peers.count() == 0) return;

        const connected_peers = self.callbacks.getConnectedPeersFn(self.callbacks.ptr);

        var stale_peers: std.ArrayListUnmanaged([]u8) = .empty;
        defer {
            for (stale_peers.items) |peer_id| self.allocator.free(peer_id);
            stale_peers.deinit(self.allocator);
        }

        var it = self.known_peers.keyIterator();
        while (it.next()) |peer_id| {
            if (containsPeerId(connected_peers, peer_id.*)) continue;

            const owned_peer_id = try self.allocator.dupe(u8, peer_id.*);
            stale_peers.append(self.allocator, owned_peer_id) catch |err| {
                self.allocator.free(owned_peer_id);
                return err;
            };
        }

        for (stale_peers.items) |peer_id| {
            scoped_log.debug("SyncService pruning disconnected peer: peer={s}", .{peer_id});
            self.onPeerDisconnect(peer_id);
        }
    }

    fn containsPeerId(peer_ids: []const []const u8, peer_id: []const u8) bool {
        for (peer_ids) |candidate| {
            if (std.mem.eql(u8, candidate, peer_id)) return true;
        }
        return false;
    }

    fn recomputePeerSummary(self: *SyncService) void {
        self.peer_count = @intCast(self.known_peers.count());

        var best: u64 = 0;
        var it = self.known_peers.valueIterator();
        while (it.next()) |peer| {
            if (peer.sync_type == .advanced and peer.head_slot > best) {
                best = peer.head_slot;
            }
        }
        self.best_peer_slot = best;
    }

    fn updateMode(self: *SyncService) void {
        if (self.is_single_node) {
            self.setMode(.synced);
            return;
        }
        if (self.peer_count < sync_types.MIN_PEERS_TO_SYNC) {
            self.setMode(.idle);
            return;
        }

        if (self.currentHeadLag() <= sync_types.SYNC_DISTANCE_THRESHOLD) {
            self.setMode(.synced);
            return;
        }

        const rs = self.range_sync.getState();
        if (rs.status != .idle) {
            self.setMode(.range_sync);
            return;
        }

        // We still have peers ahead but currently lack an active sync chain.
        // Treat this as an awaiting-peers / retry state rather than claiming
        // sync success.
        self.setMode(.idle);
    }

    fn setMode(self: *SyncService, new_mode: SyncMode) void {
        const old_mode = self.mode;
        const mode_changed = old_mode != new_mode;
        if (mode_changed) {
            self.mode = new_mode;

            const range_state = self.range_sync.getState();
            scoped_log.info(
                "mode transition old={s} new={s} peer_count={d} local_head={d} best_peer={d} head_lag={d} range_status={s}",
                .{
                    @tagName(old_mode),
                    @tagName(new_mode),
                    self.peer_count,
                    self.local_head_slot,
                    self.best_peer_slot,
                    self.currentHeadLag(),
                    @tagName(range_state.status),
                },
            );
        }

        // Gossip gating follows Lodestar: stay subscribed while near head,
        // even if a head sync chain is still finishing in the background.
        const new_gossip: GossipState = if (self.shouldEnableGossip()) .enabled else .disabled;
        if (new_gossip != self.gossip_state) {
            self.gossip_state = new_gossip;
            scoped_log.info("gossip subscriptions {s}", .{@tagName(new_gossip)});
            self.callbacks.setGossipEnabled(new_gossip == .enabled);
        }
    }

    fn currentHeadLag(self: *const SyncService) u64 {
        return self.current_slot -| self.local_head_slot;
    }
};

// ── Tests ────────────────────────────────────────────────────────────

const TestSyncServiceCallbacks = struct {
    imported_count: u32 = 0,
    processed_segments: u32 = 0,
    requested_count: u32 = 0,
    reported_count: u32 = 0,
    restatus_peer_count: u32 = 0,
    gossip_enabled: ?bool = null,
    has_block: bool = false,
    connected_peers: []const []const u8 = &.{},

    fn importBlockFn(ptr: *anyopaque, _: []const u8) anyerror!void {
        const self: *TestSyncServiceCallbacks = @ptrCast(@alignCast(ptr));
        self.imported_count += 1;
    }

    fn importPreparedBlockFn(ptr: *anyopaque, prepared: PreparedBlockInput) anyerror!void {
        const self: *TestSyncServiceCallbacks = @ptrCast(@alignCast(ptr));
        self.imported_count += 1;
        var owned = prepared;
        owned.deinit(std.testing.allocator);
    }

    fn processChainSegmentFn(ptr: *anyopaque, _: u32, _: BatchId, _: u32, blocks: []const BatchBlock, _: RangeSyncType) anyerror!void {
        const self: *TestSyncServiceCallbacks = @ptrCast(@alignCast(ptr));
        self.processed_segments += 1;
        self.imported_count += @intCast(blocks.len);
    }

    fn requestBlocksByRangeFn(ptr: *anyopaque, _: u32, _: BatchId, _: u32, _: []const u8, _: u64, _: u64) void {
        const self: *TestSyncServiceCallbacks = @ptrCast(@alignCast(ptr));
        self.requested_count += 1;
    }

    fn requestBlockByRootFn(_: *anyopaque, _: [32]u8, _: []const u8) void {}

    fn reportPeerFn(ptr: *anyopaque, _: []const u8, _: SyncPeerReportReason) void {
        const self: *TestSyncServiceCallbacks = @ptrCast(@alignCast(ptr));
        self.reported_count += 1;
    }

    fn hasBlockFn(ptr: *anyopaque, _: [32]u8) bool {
        const self: *TestSyncServiceCallbacks = @ptrCast(@alignCast(ptr));
        return self.has_block;
    }

    fn getConnectedPeersFn(ptr: *anyopaque) []const []const u8 {
        const self: *TestSyncServiceCallbacks = @ptrCast(@alignCast(ptr));
        return self.connected_peers;
    }

    fn reStatusPeersFn(ptr: *anyopaque, peer_ids: []const []const u8) void {
        const self: *TestSyncServiceCallbacks = @ptrCast(@alignCast(ptr));
        self.restatus_peer_count += @intCast(peer_ids.len);
    }

    fn setGossipEnabledFn(ptr: *anyopaque, enabled: bool) void {
        const self: *TestSyncServiceCallbacks = @ptrCast(@alignCast(ptr));
        self.gossip_enabled = enabled;
    }

    fn callbacks(self: *TestSyncServiceCallbacks) SyncServiceCallbacks {
        return .{
            .ptr = self,
            .importBlockFn = &importBlockFn,
            .importPreparedBlockFn = &importPreparedBlockFn,
            .processChainSegmentFn = &processChainSegmentFn,
            .requestBlocksByRangeFn = &requestBlocksByRangeFn,
            .requestBlockByRootFn = &requestBlockByRootFn,
            .reportPeerFn = &reportPeerFn,
            .hasBlockFn = &hasBlockFn,
            .getConnectedPeersFn = &getConnectedPeersFn,
            .reStatusPeersFn = &reStatusPeersFn,
            .setGossipEnabledFn = &setGossipEnabledFn,
        };
    }
};

test "SyncService: idle with no peers" {
    const allocator = std.testing.allocator;
    var tc = TestSyncServiceCallbacks{};
    var svc = SyncService.init(allocator, std.testing.io, tc.callbacks(), 0, 0);
    defer svc.deinit();

    try std.testing.expectEqual(SyncMode.idle, svc.mode);
    try std.testing.expect(!svc.isSynced());

    try svc.tick();
    try std.testing.expectEqual(SyncMode.idle, svc.mode);
}

test "SyncService: transitions to range_sync on advanced peer" {
    const allocator = std.testing.allocator;
    var tc = TestSyncServiceCallbacks{};
    var svc = SyncService.init(allocator, std.testing.io, tc.callbacks(), 0, 0);
    defer svc.deinit();

    try svc.onPeerStatus("p1", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 10,
        .head_root = [_]u8{0xAA} ** 32,
        .head_slot = 500,
    }, null);

    try std.testing.expectEqual(SyncMode.range_sync, svc.mode);
    try std.testing.expect(!svc.isSynced());
}

test "SyncService: synced when peer is within threshold" {
    const allocator = std.testing.allocator;
    var tc = TestSyncServiceCallbacks{};
    // Local head at 490, threshold is 32.
    var svc = SyncService.init(allocator, std.testing.io, tc.callbacks(), 490, 15);
    defer svc.deinit();

    try svc.onPeerStatus("p1", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 15,
        .head_root = [_]u8{0xAA} ** 32,
        .head_slot = 500,
    }, null);

    // Distance = 10 <= 32, so synced.
    try std.testing.expectEqual(SyncMode.synced, svc.mode);
    try std.testing.expect(svc.isSynced());
}

test "SyncService: peer disconnect" {
    const allocator = std.testing.allocator;
    var tc = TestSyncServiceCallbacks{};
    var svc = SyncService.init(allocator, std.testing.io, tc.callbacks(), 0, 0);
    defer svc.deinit();

    try svc.onPeerStatus("p1", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 10,
        .head_root = [_]u8{0xAA} ** 32,
        .head_slot = 500,
    }, null);

    svc.onPeerDisconnect("p1");
    try std.testing.expectEqual(@as(usize, 0), svc.peer_count);
}

test "SyncService: tick prunes peers no longer connected" {
    const allocator = std.testing.allocator;
    var tc = TestSyncServiceCallbacks{};
    const connected = [_][]const u8{"p1"};
    tc.connected_peers = connected[0..];

    var svc = SyncService.init(allocator, std.testing.io, tc.callbacks(), 0, 0);
    defer svc.deinit();

    try svc.onPeerStatus("p1", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 10,
        .head_root = [_]u8{0xAA} ** 32,
        .head_slot = 500,
    }, null);

    try std.testing.expectEqual(@as(usize, 1), svc.peer_count);
    try std.testing.expectEqual(SyncMode.range_sync, svc.mode);
    try std.testing.expect(svc.range_sync.getState().status != .idle);

    tc.connected_peers = &.{};
    try svc.tick();

    try std.testing.expectEqual(@as(usize, 0), svc.peer_count);
    try std.testing.expectEqual(@as(u64, 0), svc.best_peer_slot);
    try std.testing.expectEqual(SyncMode.idle, svc.mode);
    try std.testing.expectEqual(RangeSyncStatus.idle, svc.range_sync.getState().status);
}

test "SyncService: gossip gating" {
    const allocator = std.testing.allocator;
    var tc = TestSyncServiceCallbacks{};
    var svc = SyncService.init(allocator, std.testing.io, tc.callbacks(), 0, 0);
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
    }, null);

    try std.testing.expectEqual(SyncMode.range_sync, svc.mode);
    try std.testing.expect(!svc.shouldEnableGossip());
    try std.testing.expectEqual(@as(?bool, false), tc.gossip_enabled);
}

test "SyncService: getSyncStatus reports correct state" {
    const allocator = std.testing.allocator;
    var tc = TestSyncServiceCallbacks{};
    var svc = SyncService.init(allocator, std.testing.io, tc.callbacks(), 100, 3);
    defer svc.deinit();

    try svc.onPeerStatus("p1", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 20,
        .head_root = [_]u8{0xCC} ** 32,
        .head_slot = 700,
    }, null);

    const status = svc.getSyncStatus();
    try std.testing.expectEqual(@as(u64, 600), status.sync_distance);
    try std.testing.expectEqual(@as(u64, 100), status.head_slot);
}

test "SyncService: stores earliest available slot for range sync peers" {
    const allocator = std.testing.allocator;
    var tc = TestSyncServiceCallbacks{};
    var svc = SyncService.init(allocator, std.testing.io, tc.callbacks(), 0, 0);
    defer svc.deinit();

    try svc.onPeerStatus("p1", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 10,
        .head_root = [_]u8{0xDD} ** 32,
        .head_slot = 500,
    }, 128);

    const chain = svc.range_sync.finalized_chain orelse return error.TestUnexpectedResult;
    const peer = chain.peers.get("p1") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?u64, 128), peer.earliest_available_slot);
}

test "SyncService: lower finalized peer does not trigger range sync" {
    const allocator = std.testing.allocator;
    var tc = TestSyncServiceCallbacks{};
    var svc = SyncService.init(allocator, std.testing.io, tc.callbacks(), 100, 10);
    defer svc.deinit();

    try svc.onPeerStatus("p1", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 9,
        .head_root = [_]u8{0xEE} ** 32,
        .head_slot = 500,
    }, null);

    try std.testing.expectEqual(@as(usize, 0), svc.peer_count);
    try std.testing.expectEqual(@as(u64, 0), svc.best_peer_slot);
    try std.testing.expectEqual(SyncMode.idle, svc.mode);
    try std.testing.expectEqual(RangeSyncStatus.idle, svc.range_sync.getState().status);
    try std.testing.expect(svc.shouldEnableGossip());
}

test "SyncService: known remote head is fully synced, not advanced" {
    const allocator = std.testing.allocator;
    var tc = TestSyncServiceCallbacks{ .has_block = true };
    var svc = SyncService.init(allocator, std.testing.io, tc.callbacks(), 100, 10);
    defer svc.deinit();

    try svc.onPeerStatus("p1", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 11,
        .head_root = [_]u8{0xAB} ** 32,
        .head_slot = 500,
    }, null);

    try std.testing.expectEqual(@as(usize, 1), svc.peer_count);
    try std.testing.expectEqual(@as(u64, 0), svc.best_peer_slot);
    try std.testing.expectEqual(SyncMode.synced, svc.mode);
    try std.testing.expectEqual(RangeSyncStatus.idle, svc.range_sync.getState().status);
}

test "SyncService: modestly ahead peer in next finalized epoch remains fully synced" {
    const allocator = std.testing.allocator;
    var tc = TestSyncServiceCallbacks{};
    var svc = SyncService.init(allocator, std.testing.io, tc.callbacks(), 100, 10);
    defer svc.deinit();

    svc.onClockSlot(104);

    try svc.onPeerStatus("p1", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 11,
        .head_root = [_]u8{0xBC} ** 32,
        .head_slot = 105,
    }, null);

    try std.testing.expectEqual(@as(usize, 1), svc.peer_count);
    try std.testing.expectEqual(@as(u64, 0), svc.best_peer_slot);
    try std.testing.expectEqual(SyncMode.synced, svc.mode);
    try std.testing.expectEqual(RangeSyncStatus.idle, svc.range_sync.getState().status);
}

test "SyncService: head lag beyond tolerance keeps gossip until two epochs" {
    const allocator = std.testing.allocator;
    var tc = TestSyncServiceCallbacks{};
    var svc = SyncService.init(allocator, std.testing.io, tc.callbacks(), 100, 10);
    defer svc.deinit();

    try svc.onPeerStatus("p1", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 10,
        .head_root = [_]u8{0xAC} ** 32,
        .head_slot = 100,
    }, null);

    svc.onClockSlot(133);

    try std.testing.expectEqual(SyncMode.idle, svc.mode);
    try std.testing.expect(svc.shouldEnableGossip());
}

test "SyncService: head lag past two epochs disables gossip" {
    const allocator = std.testing.allocator;
    var tc = TestSyncServiceCallbacks{};
    var svc = SyncService.init(allocator, std.testing.io, tc.callbacks(), 100, 10);
    defer svc.deinit();

    try svc.onPeerStatus("p1", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 10,
        .head_root = [_]u8{0xAD} ** 32,
        .head_slot = 100,
    }, null);

    svc.onClockSlot(165);

    try std.testing.expectEqual(SyncMode.idle, svc.mode);
    try std.testing.expect(!svc.shouldEnableGossip());
}
