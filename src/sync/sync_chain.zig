//! SyncChain: ordered batch pipeline per sync chain target.
//!
//! Manages a sliding window of Batch objects that download, process, and
//! validate blocks sequentially. Supports both finalized and head chain
//! sync with dynamic target updates as peers are added/removed.
//!
//! The chain tracks its own peer set and computes its target as the
//! highest target among its peers (for head chains) or the agreed
//! finalized checkpoint (for finalized chains).
//!
//! Reference: Lodestar `packages/beacon-node/src/sync/range/chain.ts`

const std = @import("std");
const Allocator = std.mem.Allocator;
const sync_types = @import("sync_types.zig");
const ChainTarget = sync_types.ChainTarget;
const RangeSyncType = sync_types.RangeSyncType;
const batch_mod = @import("batch.zig");
const Batch = batch_mod.Batch;
const BatchStatus = batch_mod.BatchStatus;
const BatchBlock = batch_mod.BatchBlock;
const BatchId = batch_mod.BatchId;

/// Callback vtable for sync chain operations.
pub const SyncChainCallbacks = struct {
    ptr: *anyopaque,

    /// Import a single block into the chain. Returns error on failure.
    importBlockFn: *const fn (ptr: *anyopaque, block_bytes: []const u8) anyerror!void,

    /// Import a segment of blocks. Returns error on failure.
    processChainSegmentFn: *const fn (
        ptr: *anyopaque,
        blocks: []const BatchBlock,
        sync_type: RangeSyncType,
    ) anyerror!void,

    /// Request blocks by range from a peer.
    downloadByRangeFn: *const fn (
        ptr: *anyopaque,
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
        peer_id: []const u8,
        start_slot: u64,
        count: u64,
    ) void,

    /// Report a peer for negative behavior.
    reportPeerFn: *const fn (ptr: *anyopaque, peer_id: []const u8) void,

    pub fn processChainSegment(
        self: SyncChainCallbacks,
        blocks: []const BatchBlock,
        sync_type: RangeSyncType,
    ) !void {
        return self.processChainSegmentFn(self.ptr, blocks, sync_type);
    }

    pub fn downloadByRange(
        self: SyncChainCallbacks,
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
        peer_id: []const u8,
        start_slot: u64,
        count: u64,
    ) void {
        self.downloadByRangeFn(self.ptr, chain_id, batch_id, generation, peer_id, start_slot, count);
    }

    pub fn reportPeer(self: SyncChainCallbacks, peer_id: []const u8) void {
        self.reportPeerFn(self.ptr, peer_id);
    }
};

/// Status of a SyncChain.
pub const SyncChainStatus = enum {
    stopped,
    syncing,
    done,
    err,
};

/// A chain of batches being downloaded towards a target.
pub const SyncChain = struct {
    const ChainPeer = struct {
        target: ChainTarget,
        earliest_available_slot: ?u64 = null,
    };

    allocator: Allocator,
    /// Unique ID for this chain.
    id: u32,
    /// Finalized or head chain.
    sync_type: RangeSyncType,
    /// Current target — highest among our peers.
    target: ChainTarget,
    /// Status of this chain.
    status: SyncChainStatus,
    /// The epoch at which validated processing starts.
    start_epoch: u64,
    /// Number of fully validated epochs (used to gate chain switching).
    validated_epochs: u64,
    /// Callbacks for network/import operations.
    callbacks: SyncChainCallbacks,

    // ── Batch management ────────────────────────────────────────────

    /// Sorted list of batches (by start_slot, ascending).
    batches: std.ArrayListUnmanaged(Batch),
    /// Next batch ID to assign.
    next_batch_id: BatchId,
    /// Next start slot for a new batch.
    next_batch_start: u64,

    // ── Peer set ────────────────────────────────────────────────────

    /// Peers assigned to this chain, including the serving limits that affect
    /// batch eligibility for this peer.
    peers: std.StringArrayHashMap(ChainPeer),

    /// Global chain ID counter.
    pub fn init(
        allocator: Allocator,
        id: u32,
        sync_type: RangeSyncType,
        start_epoch: u64,
        target: ChainTarget,
        callbacks: SyncChainCallbacks,
    ) SyncChain {
        const start_slot = start_epoch * 32;
        return .{
            .allocator = allocator,
            .id = id,
            .sync_type = sync_type,
            .target = target,
            .status = .stopped,
            .start_epoch = start_epoch,
            .validated_epochs = 0,
            .callbacks = callbacks,
            .batches = .empty,
            .next_batch_id = 0,
            .next_batch_start = start_slot,
            .peers = std.StringArrayHashMap(ChainPeer).init(allocator),
        };
    }

    pub fn deinit(self: *SyncChain) void {
        self.batches.deinit(self.allocator);
        // Free owned peer_id keys before deiniting the map.
        for (self.peers.keys()) |k| self.allocator.free(k);
        self.peers.deinit();
    }

    /// Add a peer and update the chain target.
    ///
    /// The peer_id string is deep-copied into owned memory so the caller's
    /// buffer can be freed or reused after this call.
    pub fn addPeer(
        self: *SyncChain,
        peer_id: []const u8,
        target: ChainTarget,
        earliest_available_slot: ?u64,
    ) !void {
        // If the key already exists, update value only — keep the owned key.
        if (self.peers.getPtr(peer_id)) |value_ptr| {
            value_ptr.* = .{
                .target = target,
                .earliest_available_slot = earliest_available_slot,
            };
            self.computeTarget();
            return;
        }
        const owned_id = try self.allocator.dupe(u8, peer_id);
        errdefer self.allocator.free(owned_id);
        try self.peers.put(owned_id, .{
            .target = target,
            .earliest_available_slot = earliest_available_slot,
        });
        self.computeTarget();
    }

    /// Remove a peer and recompute the chain target.
    pub fn removePeer(self: *SyncChain, peer_id: []const u8) bool {
        // Free the owned key before removing.
        const idx = self.peers.getIndex(peer_id) orelse return false;
        self.allocator.free(self.peers.keys()[idx]);
        self.peers.swapRemoveAt(idx);
        self.computeTarget();
        return true;
    }

    /// Number of peers on this chain.
    pub fn peerCount(self: *const SyncChain) usize {
        return self.peers.count();
    }

    /// Whether this chain is actively syncing.
    pub fn isSyncing(self: *const SyncChain) bool {
        return self.status == .syncing;
    }

    /// Start syncing — requests new batches if needed.
    pub fn startSyncing(self: *SyncChain) void {
        if (self.status == .syncing) return;
        if (self.status == .done or self.status == .err) return;
        self.status = .syncing;
    }

    /// Stop syncing — batches remain but no new downloads.
    pub fn stopSyncing(self: *SyncChain) void {
        self.status = .stopped;
    }

    /// Advance the chain: dispatch downloads, process ready batches, drain validated.
    /// Returns true if the chain completed (reached target).
    pub fn tick(self: *SyncChain) !bool {
        if (self.status != .syncing) return false;

        // Check completion.
        if (self.next_batch_start > self.target.slot and self.batches.items.len == 0) {
            self.status = .done;
            return true;
        }

        // 1. Fill the batch window with new batches.
        self.fillBatchWindow();

        // 2. Dispatch downloads for awaiting_download batches.
        self.dispatchDownloads();

        // 3. Process the next ready batch (front of the queue).
        try self.processNextBatch();

        // 4. Drain validated batches from the front.
        self.drainValidated();

        return self.status == .done;
    }

    /// Called when a batch download response arrives.
    pub fn onBatchResponse(
        self: *SyncChain,
        batch_id: BatchId,
        generation: u32,
        blocks: []const BatchBlock,
    ) void {
        for (self.batches.items) |*b| {
            if (b.id == batch_id) {
                if (!b.onDownloadSuccess(generation, blocks)) return;
                return;
            }
        }
    }

    /// Called when a batch download fails.
    pub fn onBatchError(
        self: *SyncChain,
        batch_id: BatchId,
        generation: u32,
        peer_id: []const u8,
    ) void {
        for (self.batches.items) |*b| {
            if (b.id == batch_id) {
                if (b.onDownloadError(generation)) {
                    // Report the peer that failed.
                    self.callbacks.reportPeer(peer_id);
                }
                return;
            }
        }
    }

    // ── Internal helpers ────────────────────────────────────────────

    /// Recompute target as the highest slot among peers.
    ///
    /// Initialized from peers only so that when the highest-target peer disconnects,
    /// the target correctly decreases (instead of sticking at the stale watermark).
    fn computeTarget(self: *SyncChain) void {
        var best: ?ChainTarget = null;
        for (self.peers.values()) |peer| {
            const t = peer.target;
            if (best == null or t.slot > best.?.slot) best = t;
        }
        if (best) |b| self.target = b;
    }

    /// Select the most suitable peer for the given batch.
    ///
    /// Eligibility rules follow the serving constraints we already know:
    /// - a peer whose target is behind the batch start cannot help
    /// - a peer whose earliest_available_slot is after the batch start cannot help
    ///
    /// Among eligible peers, prefer the one with the fewest active downloads,
    /// then the highest target slot as a tiebreaker.
    fn selectPeer(self: *const SyncChain, batch: *const Batch) ?[]const u8 {
        if (self.peers.count() == 0) return null;

        var best_peer: ?[]const u8 = null;
        var best_active_downloads: usize = std.math.maxInt(usize);
        var best_target_slot: u64 = 0;

        for (self.peers.keys(), self.peers.values()) |peer_id, peer| {
            if (peer.target.slot < batch.start_slot) continue;
            if (self.sync_type == .head) {
                if (batch.last_downloaded_slot) |last_downloaded_slot| {
                    if (peer.target.slot < last_downloaded_slot) continue;
                }
            }
            if (peer.earliest_available_slot) |earliest_available_slot| {
                if (earliest_available_slot > batch.start_slot) continue;
            }

            const active_downloads = self.activeDownloadsForPeer(peer_id);
            if (best_peer == null or
                active_downloads < best_active_downloads or
                (active_downloads == best_active_downloads and peer.target.slot > best_target_slot))
            {
                best_peer = peer_id;
                best_active_downloads = active_downloads;
                best_target_slot = peer.target.slot;
            }
        }

        return best_peer;
    }

    fn activeDownloadsForPeer(self: *const SyncChain, peer_id: []const u8) usize {
        var active_downloads: usize = 0;
        for (self.batches.items) |batch| {
            if (batch.status != .downloading) continue;
            const download_peer = batch.download_peer orelse continue;
            if (std.mem.eql(u8, download_peer, peer_id)) active_downloads += 1;
        }
        return active_downloads;
    }

    /// Dispatch download requests for all awaiting_download batches.
    fn dispatchDownloads(self: *SyncChain) void {
        for (self.batches.items) |*b| {
            if (b.status == .awaiting_download) {
                if (b.isDownloadExhausted()) {
                    // Skip this batch — mark as validated (empty) to drain.
                    b.status = .awaiting_validation;
                    continue;
                }
                const peer = self.selectPeer(b) orelse continue;
                b.startDownload(peer);
                self.callbacks.downloadByRange(
                    self.id,
                    b.id,
                    b.generation,
                    peer,
                    b.start_slot,
                    b.count,
                );
            }
        }
    }

    /// Fill the batch window up to MAX_PENDING_BATCHES.
    fn fillBatchWindow(self: *SyncChain) void {
        while (self.batches.items.len < sync_types.MAX_PENDING_BATCHES and
            self.next_batch_start <= self.target.slot)
        {
            const remaining = self.target.slot - self.next_batch_start + 1;
            const count = @min(sync_types.BATCH_SIZE, remaining);

            const id = self.next_batch_id;
            self.next_batch_id +%= 1;

            self.batches.append(self.allocator, Batch.init(id, self.next_batch_start, count, self.allocator)) catch return;
            self.next_batch_start += count;
        }
    }

    /// Process the first batch that is awaiting_processing (must be at front).
    fn processNextBatch(self: *SyncChain) !void {
        if (self.batches.items.len == 0) return;

        const front = &self.batches.items[0];
        if (front.status != .awaiting_processing) return;

        front.startProcessing();
        self.callbacks.processChainSegment(front.blocks, self.sync_type) catch |err| {
            std.log.warn("SyncChain: failed to import segment {d}..{d}: {}", .{
                front.start_slot,
                front.endSlot(),
                err,
            });
            front.onProcessingError();
            if (front.isProcessingExhausted()) {
                if (front.download_peer) |p| self.callbacks.reportPeer(p);
                self.status = .err;
            }
            return err;
        };
        front.onProcessingSuccess();

        // If a previous batch was awaiting validation, it's now validated
        // since this batch imported successfully (proving continuity).
    }

    /// Drain validated/completed batches from the front.
    ///
    /// Previous implementation used `orderedRemove(0)` in a loop, which is O(n)
    /// per removal (shifts the entire slice each time), yielding O(n²) total for
    /// a run of n validated batches.
    ///
    /// This version counts validated batches first, then removes them in a single
    /// bulk `replaceRange` call — O(n) total regardless of how many are drained.
    fn drainValidated(self: *SyncChain) void {
        // Count how many leading batches are validated.
        var drain_count: usize = 0;
        for (self.batches.items) |batch| {
            if (batch.status != .awaiting_validation) break;
            self.validated_epochs += batch.count / 32;
            drain_count += 1;
        }

        // Bulk-remove the first drain_count elements in one shift (O(n)).
        if (drain_count > 0) {
            self.batches.replaceRangeAssumeCapacity(0, drain_count, &.{});
        }

        // Check if we're done after draining.
        if (self.next_batch_start > self.target.slot and self.batches.items.len == 0) {
            self.status = .done;
        }
    }
};

// ── Tests ────────────────────────────────────────────────────────────

const TestSyncCallbacks = struct {
    processed_count: u32 = 0,
    downloaded_count: u32 = 0,
    reported_count: u32 = 0,
    last_chain_id: u32 = 0,
    last_batch_id: BatchId = 0,
    last_generation: u32 = 0,
    last_peer_id_buf: [64]u8 = undefined,
    last_peer_id_len: usize = 0,
    should_fail_processing: bool = false,

    fn processChainSegmentFn(ptr: *anyopaque, blocks: []const BatchBlock, _: RangeSyncType) anyerror!void {
        const self: *TestSyncCallbacks = @ptrCast(@alignCast(ptr));
        if (self.should_fail_processing) return error.ProcessingFailed;
        self.processed_count += @intCast(blocks.len);
    }

    fn downloadByRangeFn(
        ptr: *anyopaque,
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
        peer_id: []const u8,
        _: u64,
        _: u64,
    ) void {
        const self: *TestSyncCallbacks = @ptrCast(@alignCast(ptr));
        self.downloaded_count += 1;
        self.last_chain_id = chain_id;
        self.last_batch_id = batch_id;
        self.last_generation = generation;
        self.last_peer_id_len = @min(peer_id.len, self.last_peer_id_buf.len);
        @memcpy(self.last_peer_id_buf[0..self.last_peer_id_len], peer_id[0..self.last_peer_id_len]);
    }

    fn reportPeerFn(ptr: *anyopaque, _: []const u8) void {
        const self: *TestSyncCallbacks = @ptrCast(@alignCast(ptr));
        self.reported_count += 1;
    }

    fn importBlockFnTest(ptr: *anyopaque, _: []const u8) anyerror!void {
        const self: *TestSyncCallbacks = @ptrCast(@alignCast(ptr));
        if (self.should_fail_processing) return error.ProcessingFailed;
    }

    fn callbacks(self: *TestSyncCallbacks) SyncChainCallbacks {
        return .{
            .ptr = self,
            .importBlockFn = &importBlockFnTest,
            .processChainSegmentFn = &processChainSegmentFn,
            .downloadByRangeFn = &downloadByRangeFn,
            .reportPeerFn = &reportPeerFn,
        };
    }

    fn lastPeerId(self: *const TestSyncCallbacks) []const u8 {
        return self.last_peer_id_buf[0..self.last_peer_id_len];
    }
};

test "SyncChain: basic batch pipeline" {
    const allocator = std.testing.allocator;
    var tc = TestSyncCallbacks{};
    var chain = SyncChain.init(
        allocator,
        0, // chain id
        .finalized,
        0, // start epoch 0
        .{ .slot = 128, .root = [_]u8{0xFF} ** 32 },
        tc.callbacks(),
    );
    defer chain.deinit();

    try chain.addPeer("peer_a", .{ .slot = 128, .root = [_]u8{0xFF} ** 32 }, null);
    chain.startSyncing();

    // First tick fills batches and dispatches downloads.
    _ = try chain.tick();
    try std.testing.expect(tc.downloaded_count > 0);
    try std.testing.expect(chain.batches.items.len > 0);
}

test "SyncChain: peer management" {
    const allocator = std.testing.allocator;
    var tc = TestSyncCallbacks{};
    var chain = SyncChain.init(
        allocator,
        0, // chain id
        .head,
        0,
        .{ .slot = 100, .root = [_]u8{0xAA} ** 32 },
        tc.callbacks(),
    );
    defer chain.deinit();

    try chain.addPeer("p1", .{ .slot = 100, .root = [_]u8{0xAA} ** 32 }, null);
    try chain.addPeer("p2", .{ .slot = 200, .root = [_]u8{0xBB} ** 32 }, null);
    try std.testing.expectEqual(@as(usize, 2), chain.peerCount());
    try std.testing.expectEqual(@as(u64, 200), chain.target.slot);

    _ = chain.removePeer("p2");
    try std.testing.expectEqual(@as(usize, 1), chain.peerCount());
    try std.testing.expectEqual(@as(u64, 100), chain.target.slot);
    // Target should decrease to p1's slot (100) since p2 was removed.
    // computeTarget now initializes from peers only, so removal of the highest peer reduces target.
}

test "SyncChain: completes when all batches processed" {
    const allocator = std.testing.allocator;
    var tc = TestSyncCallbacks{};
    // Small target — just 2 slots.
    var chain = SyncChain.init(
        allocator,
        0, // chain id
        .finalized,
        0,
        .{ .slot = 2, .root = [_]u8{0} ** 32 },
        tc.callbacks(),
    );
    defer chain.deinit();

    try chain.addPeer("p1", .{ .slot = 2, .root = [_]u8{0} ** 32 }, null);
    chain.startSyncing();

    // Tick to create batches and dispatch download.
    _ = try chain.tick();
    try std.testing.expectEqual(@as(usize, 1), chain.batches.items.len);

    // Simulate download response.
    const blocks = [_]BatchBlock{
        .{ .slot = 1, .block_bytes = "b1" },
        .{ .slot = 2, .block_bytes = "b2" },
    };
    chain.onBatchResponse(tc.last_batch_id, tc.last_generation, &blocks);

    // Tick to process.
    const done = try chain.tick();
    try std.testing.expect(done);
    try std.testing.expectEqual(SyncChainStatus.done, chain.status);
    // 2 blocks were imported through the segment callback.
    try std.testing.expectEqual(@as(u32, 2), tc.processed_count);
}

test "SyncChain: skips peers that cannot serve the batch start slot" {
    const allocator = std.testing.allocator;
    var tc = TestSyncCallbacks{};
    var chain = SyncChain.init(
        allocator,
        0,
        .head,
        0,
        .{ .slot = 0, .root = [_]u8{0x11} ** 32 },
        tc.callbacks(),
    );
    defer chain.deinit();

    try chain.addPeer("too_new", .{ .slot = 0, .root = [_]u8{0x11} ** 32 }, 32);
    try chain.addPeer("usable", .{ .slot = 0, .root = [_]u8{0x11} ** 32 }, 0);
    chain.startSyncing();

    _ = try chain.tick();

    try std.testing.expectEqual(@as(u32, 1), tc.downloaded_count);
    try std.testing.expectEqualStrings("usable", tc.lastPeerId());
}

test "SyncChain: head retries avoid peers behind known batch progress" {
    const allocator = std.testing.allocator;
    var tc = TestSyncCallbacks{};
    var chain = SyncChain.init(
        allocator,
        0,
        .head,
        0,
        .{ .slot = 20, .root = [_]u8{0x33} ** 32 },
        tc.callbacks(),
    );
    defer chain.deinit();

    try chain.addPeer("stale", .{ .slot = 5, .root = [_]u8{0x33} ** 32 }, null);
    try chain.addPeer("fresh", .{ .slot = 20, .root = [_]u8{0x33} ** 32 }, null);
    chain.startSyncing();

    _ = try chain.tick();
    try std.testing.expectEqualStrings("fresh", tc.lastPeerId());

    const blocks = [_]BatchBlock{
        .{ .slot = 0, .block_bytes = "b0" },
        .{ .slot = 10, .block_bytes = "b10" },
    };
    chain.onBatchResponse(tc.last_batch_id, tc.last_generation, &blocks);

    tc.should_fail_processing = true;
    try std.testing.expectError(error.ProcessingFailed, chain.tick());
    tc.should_fail_processing = false;

    _ = try chain.tick();
    try std.testing.expectEqual(@as(u32, 2), tc.downloaded_count);
    try std.testing.expectEqualStrings("fresh", tc.lastPeerId());
}
