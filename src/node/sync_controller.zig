//! SyncController: glue that connects P2P events to the sync pipeline.
//!
//! Sits between the network layer and the sync subsystem:
//!   P2P peer connected + Status → onPeerConnected → PeerManager + SyncService
//!   Slot clock tick           → tick              → SyncService.tick
//!   Blocks arrived from peer  → onBlocksReceived  → BeaconNode.importBlock
//!
//! The SyncController deliberately does NOT hold a P2P handle — instead it
//! relies on callbacks so it can be instantiated and tested without a live
//! network stack.
//!
//! Reference: Lodestar `packages/beacon-node/src/sync/`

const std = @import("std");
const Allocator = std.mem.Allocator;

const networking = @import("networking");
const StatusMessage = networking.messages.StatusMessage;

const sync_mod = @import("sync");
const SyncService = sync_mod.SyncService;
const SyncMode = sync_mod.SyncMode;
const PeerManager = sync_mod.PeerManager;
const BatchBlock = sync_mod.BatchBlock;
const RangeSyncManager = sync_mod.RangeSyncManager;
const BlockImporterCallback = sync_mod.BlockImporterCallback;
const BatchRequestCallback = sync_mod.BatchRequestCallback;

const node_mod = @import("beacon_node.zig");
const BeaconNode = node_mod.BeaconNode;
const HeadInfo = node_mod.HeadInfo;

// ---------------------------------------------------------------------------
// BlockRequester — opaque callback used by the sync pipeline to request
// blocks from the transport layer without a direct P2P dependency.
// ---------------------------------------------------------------------------

/// Opaque block request interface. The P2P layer (or a test stub) implements
/// this to satisfy range-sync batch requests.
pub const BlockRequester = struct {
    ptr: *anyopaque,
    requestFn: *const fn (ptr: *anyopaque, start_slot: u64, count: u64) void,

    pub fn request(self: BlockRequester, start_slot: u64, count: u64) void {
        self.requestFn(self.ptr, start_slot, count);
    }
};

// ---------------------------------------------------------------------------
// SyncController
// ---------------------------------------------------------------------------

pub const SyncController = struct {
    allocator: Allocator,
    node: *BeaconNode,
    sync_service: *SyncService,
    peer_manager: *PeerManager,

    /// Create a SyncController that owns neither the node nor the sync
    /// components — it just orchestrates them.
    pub fn init(
        allocator: Allocator,
        node: *BeaconNode,
        sync_service: *SyncService,
        peer_manager: *PeerManager,
    ) SyncController {
        return .{
            .allocator = allocator,
            .node = node,
            .sync_service = sync_service,
            .peer_manager = peer_manager,
        };
    }

    /// Called when a peer connects and sends us their Status message.
    ///
    /// - Registers the peer in the PeerManager.
    /// - Delegates to SyncService.onPeerStatus which evaluates whether to
    ///   start / extend range sync.
    pub fn onPeerConnected(
        self: *SyncController,
        peer_id: []const u8,
        status: StatusMessage.Type,
    ) !void {
        // Let the sync service update peer state and drive the mode machine.
        try self.sync_service.onPeerStatus(peer_id, status);

        const our_head = self.node.getHead();
        std.log.debug(
            "SyncController.onPeerConnected peer={s} peer_slot={d} our_slot={d}",
            .{ peer_id, status.head_slot, our_head.slot },
        );
    }

    /// Called when a peer disconnects.
    pub fn onPeerDisconnected(self: *SyncController, peer_id: []const u8) void {
        self.sync_service.onPeerDisconnect(peer_id);
    }

    /// Called periodically from the slot clock loop.
    ///
    /// Drives the SyncService state machine forward. When no peers are
    /// connected this is a no-op (idle mode).
    pub fn tick(self: *SyncController) !void {
        try self.sync_service.tick();
    }

    /// Process a batch of raw SSZ block bytes received from a peer.
    ///
    /// For each block:
    ///   1. Forward to SyncService's range sync manager (updates batch state).
    ///   2. The range sync manager's BlockImporterCallback handles actual import.
    ///
    /// `batch_id` must match an outstanding batch request.
    /// `blocks` is a slice of BatchBlock (slot + raw SSZ bytes).
    pub fn onBlocksReceived(
        self: *SyncController,
        batch_id: u32,
        blocks: []const BatchBlock,
    ) !void {
        std.log.debug(
            "SyncController.onBlocksReceived batch_id={d} blocks={d}",
            .{ batch_id, blocks.len },
        );
        try self.sync_service.range_sync_mgr.onBatchResponse(batch_id, blocks);
    }

    /// Report that a batch request failed (timeout / peer error).
    pub fn onBatchError(self: *SyncController, batch_id: u32) void {
        self.sync_service.range_sync_mgr.onBatchError(batch_id);
    }

    /// Returns true when we consider ourselves synced to the head.
    pub fn isSynced(self: *const SyncController) bool {
        return self.sync_service.isSynced();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Minimal harness: noop block importer + noop batch requester.
const TestHarness = struct {
    imported: u32 = 0,
    requested: u32 = 0,

    fn importFn(ptr: *anyopaque, _block_bytes: []const u8) anyerror!void {
        const h: *TestHarness = @ptrCast(@alignCast(ptr));
        h.imported += 1;
        _ = _block_bytes;
    }

    fn requestFn(ptr: *anyopaque, _batch_id: u32, _start: u64, _count: u64, _peer: []const u8) void {
        const h: *TestHarness = @ptrCast(@alignCast(ptr));
        h.requested += 1;
        _ = _batch_id;
        _ = _start;
        _ = _count;
        _ = _peer;
    }

    fn importer(self: *TestHarness) BlockImporterCallback {
        return .{ .ptr = self, .importFn = &importFn };
    }

    fn requester(self: *TestHarness) BatchRequestCallback {
        return .{ .ptr = self, .requestFn = &requestFn };
    }
};

test "SyncController: onPeerConnected with peer ahead triggers range sync" {
    const allocator = testing.allocator;

    var harness = TestHarness{};
    var pm = PeerManager.init(allocator);
    defer pm.deinit();

    var svc = SyncService.init(
        allocator,
        harness.importer(),
        harness.requester(),
        &pm,
        0, // local head at slot 0
    );

    // We don't need a real BeaconNode for this test — create a minimal one.
    const state_transition = @import("state_transition");
    const Node = @import("persistent_merkle_tree").Node;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 4);
    defer test_state.deinit();

    const options_mod = @import("options.zig");
    const node = try BeaconNode.init(allocator, test_state.cached_state.config, .{});
    defer node.deinit();
    _ = options_mod;

    var sc = SyncController.init(allocator, node, &svc, &pm);

    // Peer is 500 slots ahead — should trigger range sync.
    try sc.onPeerConnected("peer_a", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .head_root = [_]u8{0xAA} ** 32,
        .head_slot = 500,
    });

    try testing.expectEqual(SyncMode.range_sync, svc.mode);
    try testing.expect(!sc.isSynced());
    // Peer should be registered.
    try testing.expectEqual(@as(usize, 1), pm.peerCount());
}

test "SyncController: tick with no peers is a no-op" {
    const allocator = testing.allocator;

    var harness = TestHarness{};
    var pm = PeerManager.init(allocator);
    defer pm.deinit();

    var svc = SyncService.init(allocator, harness.importer(), harness.requester(), &pm, 0);

    const state_transition = @import("state_transition");
    const Node = @import("persistent_merkle_tree").Node;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();
    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 4);
    defer test_state.deinit();

    const node = try BeaconNode.init(allocator, test_state.cached_state.config, .{});
    defer node.deinit();

    var sc = SyncController.init(allocator, node, &svc, &pm);

    // No peers — tick should stay idle, no error.
    try sc.tick();
    try sc.tick();

    try testing.expectEqual(SyncMode.idle, svc.mode);
    try testing.expect(!sc.isSynced());
}

test "SyncController: peer disconnect removes from manager" {
    const allocator = testing.allocator;

    var harness = TestHarness{};
    var pm = PeerManager.init(allocator);
    defer pm.deinit();

    var svc = SyncService.init(allocator, harness.importer(), harness.requester(), &pm, 0);

    const state_transition = @import("state_transition");
    const Node = @import("persistent_merkle_tree").Node;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();
    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 4);
    defer test_state.deinit();

    const node = try BeaconNode.init(allocator, test_state.cached_state.config, .{});
    defer node.deinit();

    var sc = SyncController.init(allocator, node, &svc, &pm);

    try sc.onPeerConnected("peer_a", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .head_root = [_]u8{0xBB} ** 32,
        .head_slot = 100,
    });
    try testing.expectEqual(@as(usize, 1), pm.peerCount());

    sc.onPeerDisconnected("peer_a");
    try testing.expectEqual(@as(usize, 0), pm.peerCount());
}

test "SyncController: already synced when peer is close" {
    const allocator = testing.allocator;

    var harness = TestHarness{};
    var pm = PeerManager.init(allocator);
    defer pm.deinit();

    // Local head at slot 99, peer at slot 100 (distance = 1 <= threshold 2).
    var svc = SyncService.init(allocator, harness.importer(), harness.requester(), &pm, 99);

    const state_transition = @import("state_transition");
    const Node = @import("persistent_merkle_tree").Node;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();
    const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 4);
    defer test_state.deinit();

    const node = try BeaconNode.init(allocator, test_state.cached_state.config, .{});
    defer node.deinit();

    var sc = SyncController.init(allocator, node, &svc, &pm);

    try sc.onPeerConnected("peer_a", .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .head_root = [_]u8{0xCC} ** 32,
        .head_slot = 100,
    });

    // Distance <= threshold so we should be synced immediately.
    try testing.expectEqual(SyncMode.synced, svc.mode);
    try testing.expect(sc.isSynced());
}
