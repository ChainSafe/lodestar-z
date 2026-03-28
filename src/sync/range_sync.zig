//! Range sync manager: coordinates finalized and head sync chains.
//!
//! Groups peers by their status into sync chains:
//! - Finalized chain: peer's finalized epoch > ours → sync from our finalized
//!   to their finalized checkpoint. Only one finalized chain at a time.
//! - Head chains: peer's head is ahead but finalized is close → sync from our
//!   finalized to their head. Multiple head chains can run in parallel.
//!
//! The manager dispatches requests via callbacks and processes responses
//! by routing them to the correct sync chain.
//!
//! Reference: Lodestar `packages/beacon-node/src/sync/range/range.ts`

const std = @import("std");
const Allocator = std.mem.Allocator;
const sync_types = @import("sync_types.zig");
const RangeSyncType = sync_types.RangeSyncType;
const ChainTarget = sync_types.ChainTarget;
const SyncState = sync_types.SyncState;
const sync_chain_mod = @import("sync_chain.zig");
const SyncChain = sync_chain_mod.SyncChain;
const SyncChainStatus = sync_chain_mod.SyncChainStatus;
const SyncChainCallbacks = sync_chain_mod.SyncChainCallbacks;
const batch_mod = @import("batch.zig");
const BatchId = batch_mod.BatchId;
const BatchBlock = batch_mod.BatchBlock;

/// Callback vtable for the range sync manager's network/import needs.
/// The SyncService provides these.
pub const RangeSyncCallbacks = struct {
    ptr: *anyopaque,

    /// Import a single block. ptr is the same as RangeSyncCallbacks.ptr.
    importBlockFn: *const fn (ptr: *anyopaque, block_bytes: []const u8) anyerror!void,

    processChainSegmentFn: *const fn (
        ptr: *anyopaque,
        blocks: []const BatchBlock,
        sync_type: RangeSyncType,
    ) anyerror!void,

    downloadByRangeFn: *const fn (
        ptr: *anyopaque,
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
        peer_id: []const u8,
        start_slot: u64,
        count: u64,
    ) void,

    reportPeerFn: *const fn (ptr: *anyopaque, peer_id: []const u8) void,

    fn toSyncChainCallbacks(self: *const RangeSyncCallbacks) SyncChainCallbacks {
        return .{
            .ptr = self.ptr,
            .importBlockFn = self.importBlockFn,
            .processChainSegmentFn = self.processChainSegmentFn,
            .downloadByRangeFn = self.downloadByRangeFn,
            .reportPeerFn = self.reportPeerFn,
        };
    }
};

/// Range sync status — used by SyncService to determine the sync state.
pub const RangeSyncStatus = enum {
    /// A finalized chain is being synced.
    finalized,
    /// No finalized chains; one or more head chains syncing.
    head,
    /// No chains active.
    idle,
};

/// The current state of range sync.
pub const RangeSyncState = struct {
    status: RangeSyncStatus,
    /// Best finalized target slot (if syncing finalized).
    finalized_target: ?u64 = null,
};

/// Maximum number of head chains to maintain.
const MAX_HEAD_CHAINS: usize = 4;

/// Range sync manager.
pub const RangeSync = struct {
    allocator: Allocator,
    callbacks: RangeSyncCallbacks,

    /// The single active finalized sync chain (if any).
    finalized_chain: ?SyncChain,
    /// Active head sync chains.
    head_chains: std.ArrayListUnmanaged(SyncChain),

    /// Our local finalized epoch (updated externally).
    local_finalized_epoch: u64,
    /// Monotonically-increasing chain ID counter. Owned here to avoid
    /// the data-race footgun of a file-scope mutable var.
    next_chain_id: u32,

    pub fn init(allocator: Allocator, callbacks: RangeSyncCallbacks) RangeSync {
        return .{
            .allocator = allocator,
            .callbacks = callbacks,
            .finalized_chain = null,
            .head_chains = .empty,
            .local_finalized_epoch = 0,
            .next_chain_id = 0,
        };
    }

    /// Allocate the next chain ID.
    fn allocChainId(self: *RangeSync) u32 {
        const id = self.next_chain_id;
        self.next_chain_id +%= 1;
        return id;
    }

    pub fn deinit(self: *RangeSync) void {
        if (self.finalized_chain) |*fc| fc.deinit();
        for (self.head_chains.items) |*hc| hc.deinit();
        self.head_chains.deinit(self.allocator);
    }

    /// Add a peer with a relevant (Advanced) status.
    /// Determines whether this is a finalized or head sync peer and
    /// adds them to the appropriate chain.
    pub fn addPeer(
        self: *RangeSync,
        peer_id: []const u8,
        local_finalized_epoch: u64,
        peer_finalized_epoch: u64,
        peer_finalized_root: [32]u8,
        peer_head_slot: u64,
        peer_head_root: [32]u8,
    ) !void {
        self.local_finalized_epoch = local_finalized_epoch;

        const sync_type = getRangeSyncType(local_finalized_epoch, peer_finalized_epoch);
        const start_epoch = local_finalized_epoch;

        switch (sync_type) {
            .finalized => {
                const target = ChainTarget{
                    .slot = peer_finalized_epoch * 32,
                    .root = peer_finalized_root,
                };
                if (self.finalized_chain) |*fc| {
                    try fc.addPeer(peer_id, target);
                } else {
                    var fc = SyncChain.init(
                        self.allocator,
                        self.allocChainId(),
                        .finalized,
                        start_epoch,
                        target,
                        self.callbacks.toSyncChainCallbacks(),
                    );
                    try fc.addPeer(peer_id, target);
                    self.finalized_chain = fc;
                }
            },
            .head => {
                const target = ChainTarget{
                    .slot = peer_head_slot,
                    .root = peer_head_root,
                };
                // Try to find an existing head chain with a matching target root.
                for (self.head_chains.items) |*hc| {
                    if (std.mem.eql(u8, &hc.target.root, &target.root)) {
                        try hc.addPeer(peer_id, target);
                        return;
                    }
                }
                // Create new head chain (if under limit).
                if (self.head_chains.items.len < MAX_HEAD_CHAINS) {
                    var hc = SyncChain.init(
                        self.allocator,
                        self.allocChainId(),
                        .head,
                        start_epoch,
                        target,
                        self.callbacks.toSyncChainCallbacks(),
                    );
                    try hc.addPeer(peer_id, target);
                    try self.head_chains.append(self.allocator, hc);
                }
            },
        }

        self.update();
    }

    /// Remove a peer from all chains.
    pub fn removePeer(self: *RangeSync, peer_id: []const u8) void {
        if (self.finalized_chain) |*fc| {
            _ = fc.removePeer(peer_id);
            if (fc.peerCount() == 0 and fc.status != .syncing) {
                fc.deinit();
                self.finalized_chain = null;
            }
        }

        // Remove from head chains; drop empty ones.
        var i: usize = 0;
        while (i < self.head_chains.items.len) {
            _ = self.head_chains.items[i].removePeer(peer_id);
            if (self.head_chains.items[i].peerCount() == 0 and
                !self.head_chains.items[i].isSyncing())
            {
                self.head_chains.items[i].deinit();
                _ = self.head_chains.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Get the current range sync state.
    pub fn getState(self: *const RangeSync) RangeSyncState {
        if (self.finalized_chain) |fc| {
            if (fc.isSyncing()) {
                return .{ .status = .finalized, .finalized_target = fc.target.slot };
            }
        }

        for (self.head_chains.items) |hc| {
            if (hc.isSyncing()) {
                return .{ .status = .head };
            }
        }

        return .{ .status = .idle };
    }

    /// Periodic tick — advance active chains.
    pub fn tick(self: *RangeSync) !void {
        // Tick finalized chain first (priority).
        if (self.finalized_chain) |*fc| {
            if (fc.isSyncing()) {
                const done = fc.tick() catch false;
                if (done or fc.status == .done) {
                    fc.deinit();
                    self.finalized_chain = null;
                    self.update();
                }
                // While finalized is syncing, don't tick head chains.
                return;
            }
        }

        // Tick head chains.
        var i: usize = 0;
        while (i < self.head_chains.items.len) {
            if (self.head_chains.items[i].isSyncing()) {
                const done = self.head_chains.items[i].tick() catch false;
                if (done or self.head_chains.items[i].status == .done) {
                    self.head_chains.items[i].deinit();
                    _ = self.head_chains.swapRemove(i);
                    continue;
                }
            }
            i += 1;
        }
    }

    /// Route a batch response to the correct chain.
    pub fn onBatchResponse(
        self: *RangeSync,
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
        blocks: []const BatchBlock,
    ) void {
        if (self.finalized_chain) |*fc| {
            if (fc.id == chain_id) {
                fc.onBatchResponse(batch_id, generation, blocks);
                return;
            }
        }
        for (self.head_chains.items) |*hc| {
            if (hc.id == chain_id) {
                hc.onBatchResponse(batch_id, generation, blocks);
                return;
            }
        }
    }

    /// Route a batch error to the correct chain.
    pub fn onBatchError(
        self: *RangeSync,
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
        peer_id: []const u8,
    ) void {
        if (self.finalized_chain) |*fc| {
            if (fc.id == chain_id) {
                fc.onBatchError(batch_id, generation, peer_id);
                return;
            }
        }
        for (self.head_chains.items) |*hc| {
            if (hc.id == chain_id) {
                hc.onBatchError(batch_id, generation, peer_id);
                return;
            }
        }
    }

    // ── Internal ────────────────────────────────────────────────────

    /// Update chain states — start/stop based on priority.
    fn update(self: *RangeSync) void {
        // Finalized chain has priority. If active, stop head chains.
        if (self.finalized_chain) |*fc| {
            if (fc.peerCount() > 0) {
                fc.startSyncing();
                for (self.head_chains.items) |*hc| {
                    hc.stopSyncing();
                }
                return;
            }
        }

        // No finalized chain — start head chains.
        for (self.head_chains.items) |*hc| {
            if (hc.peerCount() > 0) {
                hc.startSyncing();
            }
        }
    }
};

/// Determine if a peer requires finalized or head sync.
pub fn getRangeSyncType(
    local_finalized_epoch: u64,
    remote_finalized_epoch: u64,
) RangeSyncType {
    if (remote_finalized_epoch > local_finalized_epoch) {
        return .finalized;
    }
    return .head;
}

// ── Tests ────────────────────────────────────────────────────────────

const TestCallbacks = struct {
    processed: u32 = 0,
    downloaded: u32 = 0,
    reported: u32 = 0,

    fn importBlockFn(_: *anyopaque, _: []const u8) anyerror!void {}

    fn processChainSegmentFn(ptr: *anyopaque, _: []const BatchBlock, _: RangeSyncType) anyerror!void {
        const self: *TestCallbacks = @ptrCast(@alignCast(ptr));
        self.processed += 1;
    }

    fn downloadByRangeFn(ptr: *anyopaque, _: u32, _: BatchId, _: u32, _: []const u8, _: u64, _: u64) void {
        const self: *TestCallbacks = @ptrCast(@alignCast(ptr));
        self.downloaded += 1;
    }

    fn reportPeerFn(ptr: *anyopaque, _: []const u8) void {
        const self: *TestCallbacks = @ptrCast(@alignCast(ptr));
        self.reported += 1;
    }

    fn rangeSyncCallbacks(self: *TestCallbacks) RangeSyncCallbacks {
        return .{
            .ptr = self,
            .importBlockFn = &importBlockFn,
            .processChainSegmentFn = &processChainSegmentFn,
            .downloadByRangeFn = &downloadByRangeFn,
            .reportPeerFn = &reportPeerFn,
        };
    }
};

test "RangeSync: finalized peer creates finalized chain" {
    const allocator = std.testing.allocator;
    var tc = TestCallbacks{};
    var rs = RangeSync.init(allocator, tc.rangeSyncCallbacks());
    defer rs.deinit();

    // Peer with finalized epoch 10 vs our 0.
    try rs.addPeer("p1", 0, 10, [_]u8{0xAA} ** 32, 350, [_]u8{0xBB} ** 32);

    try std.testing.expect(rs.finalized_chain != null);
    try std.testing.expectEqual(RangeSyncStatus.finalized, rs.getState().status);
}

test "RangeSync: head peer creates head chain" {
    const allocator = std.testing.allocator;
    var tc = TestCallbacks{};
    var rs = RangeSync.init(allocator, tc.rangeSyncCallbacks());
    defer rs.deinit();

    // Peer with same finalized epoch but ahead head.
    try rs.addPeer("p1", 5, 5, [_]u8{0} ** 32, 200, [_]u8{0xCC} ** 32);

    try std.testing.expect(rs.finalized_chain == null);
    try std.testing.expectEqual(@as(usize, 1), rs.head_chains.items.len);
    try std.testing.expectEqual(RangeSyncStatus.head, rs.getState().status);
}

test "RangeSync: finalized chain has priority over head" {
    const allocator = std.testing.allocator;
    var tc = TestCallbacks{};
    var rs = RangeSync.init(allocator, tc.rangeSyncCallbacks());
    defer rs.deinit();

    // Add head peer first.
    try rs.addPeer("p_head", 0, 0, [_]u8{0} ** 32, 200, [_]u8{0xCC} ** 32);
    try std.testing.expectEqual(RangeSyncStatus.head, rs.getState().status);

    // Add finalized peer — should take priority.
    try rs.addPeer("p_fin", 0, 10, [_]u8{0xAA} ** 32, 500, [_]u8{0xBB} ** 32);
    try std.testing.expectEqual(RangeSyncStatus.finalized, rs.getState().status);
}

test "RangeSync: idle when no chains" {
    const allocator = std.testing.allocator;
    var tc = TestCallbacks{};
    var rs = RangeSync.init(allocator, tc.rangeSyncCallbacks());
    defer rs.deinit();

    try std.testing.expectEqual(RangeSyncStatus.idle, rs.getState().status);
}

test "getRangeSyncType: finalized vs head" {
    try std.testing.expectEqual(RangeSyncType.finalized, getRangeSyncType(0, 10));
    try std.testing.expectEqual(RangeSyncType.head, getRangeSyncType(10, 10));
    try std.testing.expectEqual(RangeSyncType.head, getRangeSyncType(10, 5));
}
