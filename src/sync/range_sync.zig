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
const scoped_log = std.log.scoped(.range_sync);
const Allocator = std.mem.Allocator;
const sync_types = @import("sync_types.zig");
const preset = @import("preset").preset;
const RangeSyncType = sync_types.RangeSyncType;
const ChainTarget = sync_types.ChainTarget;
const SyncState = sync_types.SyncState;
const sync_chain_mod = @import("sync_chain.zig");
const SyncChain = sync_chain_mod.SyncChain;
const SyncChainStatus = sync_chain_mod.SyncChainStatus;
const SyncChainCallbacks = sync_chain_mod.SyncChainCallbacks;
const SyncChainBatchStatusCounts = sync_chain_mod.BatchStatusCounts;
const SyncChainCumulativeMetrics = sync_chain_mod.CumulativeMetrics;
const SyncChainMetricsSnapshot = sync_chain_mod.MetricsSnapshot;
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
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
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

    hasBlockFn: ?*const fn (ptr: *anyopaque, root: [32]u8) bool = null,

    peerCanServeRangeFn: ?*const fn (
        ptr: *anyopaque,
        peer_id: []const u8,
        start_slot: u64,
        count: u64,
    ) bool = null,

    fn toSyncChainCallbacks(self: *const RangeSyncCallbacks) SyncChainCallbacks {
        return .{
            .ptr = self.ptr,
            .importBlockFn = self.importBlockFn,
            .processChainSegmentFn = self.processChainSegmentFn,
            .downloadByRangeFn = self.downloadByRangeFn,
            .reportPeerFn = self.reportPeerFn,
            .peerCanServeRangeFn = self.peerCanServeRangeFn,
        };
    }

    fn hasBlock(self: RangeSyncCallbacks, root: [32]u8) bool {
        if (self.hasBlockFn) |f| return f(self.ptr, root);
        return false;
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

pub const TypeMetricsSnapshot = struct {
    active_chains: u64 = 0,
    peer_count: u64 = 0,
    highest_target_slot: u64 = 0,
    validated_epochs: u64 = 0,
    batches_total: u64 = 0,
    batch_statuses: SyncChainBatchStatusCounts = .{},
    cumulative: SyncChainCumulativeMetrics = .{},
};

pub const MetricsSnapshot = struct {
    finalized: TypeMetricsSnapshot = .{},
    head: TypeMetricsSnapshot = .{},
};

/// Maximum number of head chains to maintain.
const MAX_HEAD_CHAINS: usize = 4;

/// Range sync manager.
pub const RangeSync = struct {
    allocator: Allocator,
    io: std.Io,
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
    completed_finalized_metrics: SyncChainCumulativeMetrics,
    completed_head_metrics: SyncChainCumulativeMetrics,

    pub fn init(allocator: Allocator, io: std.Io, callbacks: RangeSyncCallbacks) RangeSync {
        return .{
            .allocator = allocator,
            .io = io,
            .callbacks = callbacks,
            .finalized_chain = null,
            .head_chains = .empty,
            .local_finalized_epoch = 0,
            .next_chain_id = 0,
            .completed_finalized_metrics = .{},
            .completed_head_metrics = .{},
        };
    }

    /// Allocate the next chain ID.
    fn allocChainId(self: *RangeSync) u32 {
        const id = self.next_chain_id;
        self.next_chain_id +%= 1;
        return id;
    }

    pub fn deinit(self: *RangeSync) void {
        if (self.finalized_chain) |*fc| {
            self.foldCompletedChainMetrics(fc.sync_type, fc.cumulativeMetricsSnapshot());
            fc.deinit();
        }
        for (self.head_chains.items) |*hc| {
            self.foldCompletedChainMetrics(hc.sync_type, hc.cumulativeMetricsSnapshot());
            hc.deinit();
        }
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
        earliest_available_slot: ?u64,
    ) !void {
        self.local_finalized_epoch = local_finalized_epoch;

        const sync_type = getRangeSyncType(
            local_finalized_epoch,
            peer_finalized_epoch,
            self.callbacks.hasBlock(peer_finalized_root),
        );
        const start_epoch = local_finalized_epoch;
        scoped_log.debug(
            "RangeSync addPeer: peer={s} type={s} local_finalized={d} peer_finalized={d} peer_head={d} earliest={any}",
            .{
                peer_id,
                @tagName(sync_type),
                local_finalized_epoch,
                peer_finalized_epoch,
                peer_head_slot,
                earliest_available_slot,
            },
        );

        switch (sync_type) {
            .finalized => {
                const target = ChainTarget{
                    .slot = peer_finalized_epoch * preset.SLOTS_PER_EPOCH,
                    .root = peer_finalized_root,
                };
                if (self.finalized_chain) |*fc| {
                    try fc.addPeer(peer_id, target, earliest_available_slot);
                } else {
                    var fc = SyncChain.init(
                        self.allocator,
                        self.io,
                        self.allocChainId(),
                        .finalized,
                        start_epoch,
                        target,
                        self.callbacks.toSyncChainCallbacks(),
                    );
                    try fc.addPeer(peer_id, target, earliest_available_slot);
                    self.finalized_chain = fc;
                }
            },
            .head => {
                const target = ChainTarget{
                    .slot = peer_head_slot,
                    .root = peer_head_root,
                };
                // Lodestar keeps a single head sync chain and lets all advanced
                // head peers contribute to it. Import semantics remain the
                // correctness gate if a peer returns blocks from a different fork.
                if (self.head_chains.items.len > 0) {
                    try self.head_chains.items[0].addPeer(peer_id, target, earliest_available_slot);
                    return;
                }
                if (self.head_chains.items.len < MAX_HEAD_CHAINS) {
                    var hc = SyncChain.init(
                        self.allocator,
                        self.io,
                        self.allocChainId(),
                        .head,
                        start_epoch,
                        target,
                        self.callbacks.toSyncChainCallbacks(),
                    );
                    try hc.addPeer(peer_id, target, earliest_available_slot);
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
        }

        // Lodestar removes peers without running RangeSync.update()
        // immediately; already-downloaded/in-flight batches may still finish.
        var i: usize = 0;
        while (i < self.head_chains.items.len) {
            _ = self.head_chains.items[i].removePeer(peer_id);
            i += 1;
        }
    }

    pub fn onFinalizedUpdate(self: *RangeSync, finalized_epoch: u64) void {
        self.local_finalized_epoch = finalized_epoch;
        self.update();
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
        if (self.pruneUnusableChains()) {
            self.update();
        }

        // Tick finalized chain first (priority).
        if (self.finalized_chain) |*fc| {
            if (fc.isSyncing()) {
                const done = fc.tick() catch false;
                if (done or fc.status == .done) {
                    self.foldCompletedChainMetrics(fc.sync_type, fc.cumulativeMetricsSnapshot());
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
                    self.foldCompletedChainMetrics(
                        self.head_chains.items[i].sync_type,
                        self.head_chains.items[i].cumulativeMetricsSnapshot(),
                    );
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

    /// Route a deferred batch to the correct chain.
    pub fn onBatchDeferred(
        self: *RangeSync,
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
    ) void {
        if (self.finalized_chain) |*fc| {
            if (fc.id == chain_id) {
                fc.onBatchDeferred(batch_id, generation);
                return;
            }
        }
        for (self.head_chains.items) |*hc| {
            if (hc.id == chain_id) {
                hc.onBatchDeferred(batch_id, generation);
                return;
            }
        }
    }

    pub fn onSegmentProcessingSuccess(
        self: *RangeSync,
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
    ) void {
        if (self.finalized_chain) |*fc| {
            if (fc.id == chain_id) {
                fc.onProcessingSuccess(batch_id, generation);
                return;
            }
        }
        for (self.head_chains.items) |*hc| {
            if (hc.id == chain_id) {
                hc.onProcessingSuccess(batch_id, generation);
                return;
            }
        }
    }

    pub fn onSegmentProcessingError(
        self: *RangeSync,
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
    ) void {
        if (self.finalized_chain) |*fc| {
            if (fc.id == chain_id) {
                fc.onProcessingError(batch_id, generation);
                return;
            }
        }
        for (self.head_chains.items) |*hc| {
            if (hc.id == chain_id) {
                hc.onProcessingError(batch_id, generation);
                return;
            }
        }
    }

    pub fn metricsSnapshot(self: *const RangeSync) MetricsSnapshot {
        var snapshot: MetricsSnapshot = .{
            .finalized = .{ .cumulative = self.completed_finalized_metrics },
            .head = .{ .cumulative = self.completed_head_metrics },
        };

        if (self.finalized_chain) |fc| {
            accumulateTypeMetrics(&snapshot.finalized, fc.metricsSnapshot());
        }
        for (self.head_chains.items) |hc| {
            accumulateTypeMetrics(&snapshot.head, hc.metricsSnapshot());
        }

        return snapshot;
    }

    // ── Internal ────────────────────────────────────────────────────

    /// Drop chains that cannot make further network progress. A peer-empty
    /// chain is kept while it still has downloaded, downloading, processing,
    /// or validation work because Lodestar does not abort the already-triggered
    /// batch processor when a peer leaves the peer set.
    fn pruneUnusableChains(self: *RangeSync) bool {
        const local_finalized_slot = self.local_finalized_epoch * preset.SLOTS_PER_EPOCH;
        var removed = false;

        if (self.finalized_chain) |*fc| {
            if (fc.status == .err or
                fc.status == .done or
                (fc.peerCount() == 0 and !fc.hasInFlightWork()) or
                fc.target.slot < local_finalized_slot or
                self.callbacks.hasBlock(fc.target.root))
            {
                self.foldCompletedChainMetrics(fc.sync_type, fc.cumulativeMetricsSnapshot());
                fc.deinit();
                self.finalized_chain = null;
                removed = true;
            }
        }

        var i: usize = 0;
        while (i < self.head_chains.items.len) {
            if (self.head_chains.items[i].status == .err or
                self.head_chains.items[i].status == .done or
                (self.head_chains.items[i].peerCount() == 0 and !self.head_chains.items[i].hasInFlightWork()) or
                self.head_chains.items[i].target.slot < local_finalized_slot or
                self.callbacks.hasBlock(self.head_chains.items[i].target.root))
            {
                self.foldCompletedChainMetrics(
                    self.head_chains.items[i].sync_type,
                    self.head_chains.items[i].cumulativeMetricsSnapshot(),
                );
                self.head_chains.items[i].deinit();
                _ = self.head_chains.swapRemove(i);
                removed = true;
            } else {
                i += 1;
            }
        }
        return removed;
    }

    /// Update chain states — start/stop based on priority.
    fn update(self: *RangeSync) void {
        _ = self.pruneUnusableChains();

        // Finalized chain has priority. If active, stop head chains.
        if (self.finalized_chain) |*fc| {
            if (fc.peerCount() > 0 or fc.hasInFlightWork()) {
                fc.startSyncing();
                for (self.head_chains.items) |*hc| {
                    hc.stopSyncing();
                }
                return;
            }
        }

        // No finalized chain — start head chains.
        for (self.head_chains.items) |*hc| {
            if (hc.peerCount() > 0 or hc.hasInFlightWork()) {
                hc.startSyncing();
            }
        }
    }

    fn foldCompletedChainMetrics(
        self: *RangeSync,
        sync_type: RangeSyncType,
        metrics: SyncChainCumulativeMetrics,
    ) void {
        switch (sync_type) {
            .finalized => SyncChain.accumulateCumulativeMetrics(&self.completed_finalized_metrics, metrics),
            .head => SyncChain.accumulateCumulativeMetrics(&self.completed_head_metrics, metrics),
        }
    }
};

fn accumulateTypeMetrics(dst: *TypeMetricsSnapshot, src: SyncChainMetricsSnapshot) void {
    dst.active_chains +|= 1;
    dst.peer_count +|= src.peer_count;
    dst.highest_target_slot = @max(dst.highest_target_slot, src.target_slot);
    dst.validated_epochs +|= src.validated_epochs;
    dst.batches_total +|= src.batches_total;
    dst.batch_statuses.awaiting_download +|= src.batch_statuses.awaiting_download;
    dst.batch_statuses.downloading +|= src.batch_statuses.downloading;
    dst.batch_statuses.awaiting_processing +|= src.batch_statuses.awaiting_processing;
    dst.batch_statuses.processing +|= src.batch_statuses.processing;
    dst.batch_statuses.awaiting_validation +|= src.batch_statuses.awaiting_validation;
    SyncChain.accumulateCumulativeMetrics(&dst.cumulative, src.cumulative);
}

/// Determine if a peer requires finalized or head sync.
pub fn getRangeSyncType(
    local_finalized_epoch: u64,
    remote_finalized_epoch: u64,
    remote_finalized_root_known: bool,
) RangeSyncType {
    if (remote_finalized_epoch > local_finalized_epoch and !remote_finalized_root_known) {
        return .finalized;
    }
    return .head;
}

// ── Tests ────────────────────────────────────────────────────────────

const TestCallbacks = struct {
    processed: u32 = 0,
    downloaded: u32 = 0,
    reported: u32 = 0,
    known_root: ?[32]u8 = null,

    fn importBlockFn(_: *anyopaque, _: []const u8) anyerror!void {}

    fn processChainSegmentFn(ptr: *anyopaque, _: u32, _: BatchId, _: u32, _: []const BatchBlock, _: RangeSyncType) anyerror!void {
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

    fn hasBlockFn(ptr: *anyopaque, root: [32]u8) bool {
        const self: *TestCallbacks = @ptrCast(@alignCast(ptr));
        const known_root = self.known_root orelse return false;
        return std.mem.eql(u8, &known_root, &root);
    }

    fn rangeSyncCallbacks(self: *TestCallbacks) RangeSyncCallbacks {
        return .{
            .ptr = self,
            .importBlockFn = &importBlockFn,
            .processChainSegmentFn = &processChainSegmentFn,
            .downloadByRangeFn = &downloadByRangeFn,
            .reportPeerFn = &reportPeerFn,
            .hasBlockFn = &hasBlockFn,
        };
    }
};

test "RangeSync: finalized peer creates finalized chain" {
    const allocator = std.testing.allocator;
    var tc = TestCallbacks{};
    var rs = RangeSync.init(allocator, std.testing.io, tc.rangeSyncCallbacks());
    defer rs.deinit();

    // Peer with finalized epoch 10 vs our 0.
    try rs.addPeer("p1", 0, 10, [_]u8{0xAA} ** 32, 350, [_]u8{0xBB} ** 32, null);

    try std.testing.expect(rs.finalized_chain != null);
    try std.testing.expectEqual(RangeSyncStatus.finalized, rs.getState().status);
}

test "RangeSync: head peer creates head chain" {
    const allocator = std.testing.allocator;
    var tc = TestCallbacks{};
    var rs = RangeSync.init(allocator, std.testing.io, tc.rangeSyncCallbacks());
    defer rs.deinit();

    // Peer with same finalized epoch but ahead head.
    try rs.addPeer("p1", 5, 5, [_]u8{0} ** 32, 200, [_]u8{0xCC} ** 32, null);

    try std.testing.expect(rs.finalized_chain == null);
    try std.testing.expectEqual(@as(usize, 1), rs.head_chains.items.len);
    try std.testing.expectEqual(RangeSyncStatus.head, rs.getState().status);
}

test "RangeSync: head peers share one chain" {
    const allocator = std.testing.allocator;
    var tc = TestCallbacks{};
    var rs = RangeSync.init(allocator, std.testing.io, tc.rangeSyncCallbacks());
    defer rs.deinit();

    try rs.addPeer("p1", 5, 5, [_]u8{0} ** 32, 200, [_]u8{0xAA} ** 32, null);
    try rs.addPeer("p2", 5, 5, [_]u8{0} ** 32, 300, [_]u8{0xBB} ** 32, null);

    try std.testing.expectEqual(@as(usize, 1), rs.head_chains.items.len);
    try std.testing.expectEqual(@as(usize, 2), rs.head_chains.items[0].peerCount());
    try std.testing.expectEqual(@as(u64, 300), rs.head_chains.items[0].target.slot);
}

test "RangeSync: finalized chain has priority over head" {
    const allocator = std.testing.allocator;
    var tc = TestCallbacks{};
    var rs = RangeSync.init(allocator, std.testing.io, tc.rangeSyncCallbacks());
    defer rs.deinit();

    // Add head peer first.
    try rs.addPeer("p_head", 0, 0, [_]u8{0} ** 32, 200, [_]u8{0xCC} ** 32, null);
    try std.testing.expectEqual(RangeSyncStatus.head, rs.getState().status);

    // Add finalized peer — should take priority.
    try rs.addPeer("p_fin", 0, 10, [_]u8{0xAA} ** 32, 500, [_]u8{0xBB} ** 32, null);
    try std.testing.expectEqual(RangeSyncStatus.finalized, rs.getState().status);
}

test "RangeSync: peer-empty finalized chain yields priority back to head" {
    const allocator = std.testing.allocator;
    var tc = TestCallbacks{};
    var rs = RangeSync.init(allocator, std.testing.io, tc.rangeSyncCallbacks());
    defer rs.deinit();

    try rs.addPeer("p_head", 0, 0, [_]u8{0} ** 32, 200, [_]u8{0xCC} ** 32, null);
    try rs.addPeer("p_fin", 0, 10, [_]u8{0xAA} ** 32, 500, [_]u8{0xBB} ** 32, null);
    try std.testing.expectEqual(RangeSyncStatus.finalized, rs.getState().status);

    rs.removePeer("p_fin");

    try std.testing.expect(rs.finalized_chain != null);
    try std.testing.expectEqual(RangeSyncStatus.finalized, rs.getState().status);

    try rs.tick();

    try std.testing.expect(rs.finalized_chain == null);
    try std.testing.expectEqual(RangeSyncStatus.head, rs.getState().status);

    try std.testing.expect(tc.downloaded > 0);
}

test "RangeSync: peer-empty finalized chain keeps in-flight downloaded work" {
    const allocator = std.testing.allocator;
    var tc = TestCallbacks{};
    var rs = RangeSync.init(allocator, std.testing.io, tc.rangeSyncCallbacks());
    defer rs.deinit();

    try rs.addPeer("p_fin", 0, 10, [_]u8{0xAA} ** 32, 500, [_]u8{0xBB} ** 32, null);
    try rs.tick();

    const chain_id = rs.finalized_chain.?.id;
    const batch_id = rs.finalized_chain.?.batches.items[0].id;
    const generation = rs.finalized_chain.?.batches.items[0].generation;
    const block_bytes = [_]u8{ 0x11, 0x22, 0x33 };
    var blocks = [_]BatchBlock{.{ .slot = 0, .block_bytes = &block_bytes }};
    rs.onBatchResponse(chain_id, batch_id, generation, blocks[0..]);

    rs.removePeer("p_fin");

    try std.testing.expect(rs.finalized_chain != null);
    try std.testing.expectEqual(@as(usize, 0), rs.finalized_chain.?.peerCount());
    try std.testing.expect(rs.finalized_chain.?.hasInFlightWork());
}

test "RangeSync: known remote finalized root creates head chain" {
    const allocator = std.testing.allocator;
    const finalized_root = [_]u8{0xAA} ** 32;
    const head_root = [_]u8{0xBB} ** 32;
    var tc = TestCallbacks{ .known_root = finalized_root };
    var rs = RangeSync.init(allocator, std.testing.io, tc.rangeSyncCallbacks());
    defer rs.deinit();

    try rs.addPeer("p_known", 0, 10, finalized_root, 500, head_root, null);

    try std.testing.expect(rs.finalized_chain == null);
    try std.testing.expectEqual(@as(usize, 1), rs.head_chains.items.len);
    try std.testing.expectEqual(RangeSyncType.head, rs.head_chains.items[0].sync_type);
}

test "RangeSync: idle when no chains" {
    const allocator = std.testing.allocator;
    var tc = TestCallbacks{};
    var rs = RangeSync.init(allocator, std.testing.io, tc.rangeSyncCallbacks());
    defer rs.deinit();

    try std.testing.expectEqual(RangeSyncStatus.idle, rs.getState().status);
}

test "getRangeSyncType: finalized vs head" {
    try std.testing.expectEqual(RangeSyncType.finalized, getRangeSyncType(0, 10, false));
    try std.testing.expectEqual(RangeSyncType.head, getRangeSyncType(0, 10, true));
    try std.testing.expectEqual(RangeSyncType.head, getRangeSyncType(10, 10, false));
    try std.testing.expectEqual(RangeSyncType.head, getRangeSyncType(10, 5, false));
}
