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
const scoped_log = std.log.scoped(.sync_chain);
const Allocator = std.mem.Allocator;
const sync_types = @import("sync_types.zig");
const ChainTarget = sync_types.ChainTarget;
const RangeSyncType = sync_types.RangeSyncType;
const SyncPeerReportReason = sync_types.SyncPeerReportReason;
const preset = @import("preset").preset;
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
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
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
    reportPeerFn: *const fn (ptr: *anyopaque, peer_id: []const u8, reason: SyncPeerReportReason) void,

    /// Return whether a peer is eligible for this slot range.
    peerCanServeRangeFn: ?*const fn (
        ptr: *anyopaque,
        peer_id: []const u8,
        start_slot: u64,
        count: u64,
    ) bool = null,

    pub fn processChainSegment(
        self: SyncChainCallbacks,
        chain_id: u32,
        batch_id: BatchId,
        generation: u32,
        blocks: []const BatchBlock,
        sync_type: RangeSyncType,
    ) !void {
        return self.processChainSegmentFn(self.ptr, chain_id, batch_id, generation, blocks, sync_type);
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

    pub fn reportPeer(self: SyncChainCallbacks, peer_id: []const u8, reason: SyncPeerReportReason) void {
        self.reportPeerFn(self.ptr, peer_id, reason);
    }

    pub fn peerCanServeRange(
        self: SyncChainCallbacks,
        peer_id: []const u8,
        start_slot: u64,
        count: u64,
    ) bool {
        if (self.peerCanServeRangeFn) |f| {
            return f(self.ptr, peer_id, start_slot, count);
        }
        return true;
    }
};

/// Status of a SyncChain.
pub const SyncChainStatus = enum {
    stopped,
    syncing,
    done,
    err,
};

pub const BatchStatusCounts = struct {
    awaiting_download: u64 = 0,
    downloading: u64 = 0,
    awaiting_processing: u64 = 0,
    processing: u64 = 0,
    awaiting_validation: u64 = 0,
};

pub const CumulativeMetrics = struct {
    download_requests_total: u64 = 0,
    download_success_total: u64 = 0,
    download_error_total: u64 = 0,
    download_deferred_total: u64 = 0,
    download_time_ns_total: u64 = 0,
    processing_success_total: u64 = 0,
    processing_error_total: u64 = 0,
    processing_time_ns_total: u64 = 0,
    processed_blocks_total: u64 = 0,
};

pub const MetricsSnapshot = struct {
    peer_count: u64,
    target_slot: u64,
    validated_epochs: u64,
    batches_total: u64,
    batch_statuses: BatchStatusCounts,
    cumulative: CumulativeMetrics,
};

/// A chain of batches being downloaded towards a target.
pub const SyncChain = struct {
    const ChainPeer = struct {
        target: ChainTarget,
        earliest_available_slot: ?u64 = null,
    };

    allocator: Allocator,
    io: std.Io,
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
    cumulative_metrics: CumulativeMetrics,

    /// Global chain ID counter.
    pub fn init(
        allocator: Allocator,
        io: std.Io,
        id: u32,
        sync_type: RangeSyncType,
        start_epoch: u64,
        target: ChainTarget,
        callbacks: SyncChainCallbacks,
    ) SyncChain {
        // Lodestar starts each range-sync batch at the epoch boundary. This
        // intentionally re-requests a known checkpoint block when present so
        // finalized sync can process the whole finalized checkpoint epoch.
        const start_slot = start_epoch * preset.SLOTS_PER_EPOCH;
        return .{
            .allocator = allocator,
            .io = io,
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
            .cumulative_metrics = .{},
        };
    }

    pub fn deinit(self: *SyncChain) void {
        for (self.batches.items) |*batch| batch.deinit();
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

    /// Whether this chain has work that can still complete without selecting
    /// another peer. Lodestar does not abort an already-triggered batch
    /// processor just because the serving peer left the peer set.
    pub fn hasInFlightWork(self: *const SyncChain) bool {
        for (self.batches.items) |batch| {
            if (batch.status != .awaiting_download) return true;
        }
        return false;
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

    /// Advance the chain: dispatch downloads and process the next ready batch.
    /// Returns true if the chain completed (reached target).
    pub fn tick(self: *SyncChain) !bool {
        if (self.status == .done) return true;
        if (self.status != .syncing) return false;

        self.markDoneIfComplete();
        if (self.status == .done) return true;

        // 1. Fill the batch window with new batches.
        self.fillBatchWindow();

        // 2. Dispatch downloads for awaiting_download batches.
        self.dispatchDownloads();

        // 3. Process the next ready batch after any awaiting-validation prefix.
        try self.processNextBatch();

        self.markDoneIfComplete();

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
                self.cumulative_metrics.download_success_total += 1;
                self.cumulative_metrics.download_time_ns_total += b.finishDownloadTiming();
                self.processNextBatch() catch {};
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
                    self.cumulative_metrics.download_error_total += 1;
                    self.cumulative_metrics.download_time_ns_total += b.finishDownloadTiming();
                    // Report the peer that failed.
                    self.callbacks.reportPeer(peer_id, .download_error);
                }
                return;
            }
        }
    }

    /// Called when a batch download produced usable blocks but is waiting for
    /// required side data from an eligible peer. This mirrors Lodestar's
    /// partial-download path: return the batch to AwaitingDownload without
    /// consuming download retry budget or reporting the block peer.
    pub fn onBatchDeferred(
        self: *SyncChain,
        batch_id: BatchId,
        generation: u32,
        blocks: []const BatchBlock,
    ) void {
        for (self.batches.items) |*b| {
            if (b.id == batch_id) {
                if (!b.onDownloadDeferred(generation, blocks)) return;
                self.cumulative_metrics.download_deferred_total += 1;
                self.cumulative_metrics.download_time_ns_total += b.finishDownloadTiming();
                return;
            }
        }
    }

    pub fn getBatchBlocks(self: *const SyncChain, batch_id: BatchId, generation: u32) ?[]const BatchBlock {
        for (self.batches.items) |batch| {
            if (batch.id != batch_id) continue;
            if (batch.generation != generation) return null;
            return batch.getBlocks();
        }
        return null;
    }

    pub fn onProcessingSuccess(self: *SyncChain, batch_id: BatchId, generation: u32) void {
        for (self.batches.items, 0..) |*b, index| {
            if (b.id != batch_id) continue;
            if (b.generation != generation) return;
            if (b.status != .processing) return;
            const processed_blocks = b.blocks.len;
            const elapsed_ns = b.finishProcessingTiming();
            b.onProcessingSuccess();
            self.cumulative_metrics.processing_success_total += 1;
            self.cumulative_metrics.processing_time_ns_total += elapsed_ns;
            self.cumulative_metrics.processed_blocks_total += @intCast(processed_blocks);
            if (processed_blocks > 0 and index > 0) self.drainValidatedPrefix(index);
            self.markDoneIfComplete();
            return;
        }
    }

    pub fn onProcessingError(self: *SyncChain, batch_id: BatchId, generation: u32) void {
        for (self.batches.items, 0..) |*b, index| {
            if (b.id != batch_id) continue;
            if (b.generation != generation) return;
            if (b.status != .processing) return;
            const elapsed_ns = b.finishProcessingTiming();
            b.onProcessingError();
            self.cumulative_metrics.processing_error_total += 1;
            self.cumulative_metrics.processing_time_ns_total += elapsed_ns;
            var exhausted = false;
            if (index > 0) exhausted = self.rewindValidatedPrefix(index);
            if (b.isProcessingExhausted()) exhausted = true;
            if (exhausted) {
                self.failForProcessingExhaustion();
            }
            return;
        }
    }

    // ── Internal helpers ────────────────────────────────────────────

    /// Recompute target from the current peer set.
    ///
    /// Lodestar selects the highest slot and, when multiple peers advertise the
    /// same highest slot on different forks, prefers the most common target
    /// root among that slot cohort. This prevents the chain target from
    /// drifting arbitrarily across same-slot forks.
    fn computeTarget(self: *SyncChain) void {
        var highest_slot: ?u64 = null;
        for (self.peers.values()) |peer| {
            const t = peer.target;
            if (highest_slot == null or t.slot > highest_slot.?) {
                highest_slot = t.slot;
            }
        }
        const slot = highest_slot orelse return;

        var best: ?ChainTarget = null;
        var best_count: usize = 0;
        for (self.peers.values()) |peer| {
            const candidate = peer.target;
            if (candidate.slot != slot) continue;

            var count: usize = 0;
            for (self.peers.values()) |other| {
                if (other.target.slot != slot) continue;
                if (other.target.eql(candidate)) count += 1;
            }

            if (best == null or count > best_count) {
                best = candidate;
                best_count = count;
            }
        }

        if (best) |target| self.target = target;
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

        const last_failed_peer = batch.last_failed_peer;

        var pass: u8 = 0;
        while (pass < 2) : (pass += 1) {
            var best_peer: ?[]const u8 = null;
            var best_active_downloads: usize = std.math.maxInt(usize);
            var best_target_slot: u64 = 0;

            for (self.peers.keys(), self.peers.values()) |peer_id, peer| {
                if (batch.hasDeferredPeer(peer_id)) continue;
                if (pass == 0) {
                    if (last_failed_peer) |skip_peer| {
                        if (std.mem.eql(u8, peer_id, skip_peer)) continue;
                    }
                    if (batch.hasFailedProcessingPeer(peer_id)) continue;
                }

                if (peer.target.slot < batch.start_slot) continue;
                if (self.sync_type == .head) {
                    if (batch.last_downloaded_slot) |last_downloaded_slot| {
                        if (peer.target.slot < last_downloaded_slot) continue;
                    }
                }
                if (peer.earliest_available_slot) |earliest_available_slot| {
                    if (earliest_available_slot > batch.start_slot) continue;
                }
                if (!self.callbacks.peerCanServeRange(peer_id, batch.start_slot, batch.count)) continue;

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

            if (best_peer != null) return best_peer;
            if (last_failed_peer == null and !batch.hasFailedProcessingPeers()) break;
        }

        return null;
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
                scoped_log.debug("SyncChain dispatch: chain={d} batch={d} gen={d} slots={d}..{d} peer={s}", .{
                    self.id,
                    b.id,
                    b.generation +% 1,
                    b.start_slot,
                    b.endSlot(),
                    peer,
                });
                b.startDownload(peer);
                self.cumulative_metrics.download_requests_total += 1;
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

            self.batches.append(self.allocator, Batch.init(self.io, id, self.next_batch_start, count, self.allocator)) catch return;
            self.next_batch_start += count;
        }
    }

    fn nextProcessableBatchIndex(self: *const SyncChain) ?usize {
        for (self.batches.items, 0..) |batch, index| {
            switch (batch.status) {
                .awaiting_validation => {},
                .awaiting_processing => return index,
                .awaiting_download,
                .downloading,
                .processing,
                => return null,
            }
        }
        return null;
    }

    fn drainValidatedPrefix(self: *SyncChain, drain_count: usize) void {
        if (drain_count == 0) return;
        for (self.batches.items[0..drain_count]) |*batch| {
            std.debug.assert(batch.status == .awaiting_validation);
            self.validated_epochs += batch.count / preset.SLOTS_PER_EPOCH;
            batch.deinit();
        }
        self.batches.replaceRangeAssumeCapacity(0, drain_count, &.{});
    }

    fn rewindValidatedPrefix(self: *SyncChain, rewind_count: usize) bool {
        if (rewind_count == 0) return false;
        var exhausted = false;
        for (self.batches.items[0..rewind_count]) |*batch| {
            std.debug.assert(batch.status == .awaiting_validation);
            batch.onValidationError();
            if (batch.isProcessingExhausted()) {
                exhausted = true;
            }
        }
        return exhausted;
    }

    fn markDoneIfComplete(self: *SyncChain) void {
        if (self.next_batch_start <= self.target.slot) return;
        if (self.batches.items.len == 0) {
            self.status = .done;
            return;
        }
        for (self.batches.items) |batch| {
            if (batch.status != .awaiting_validation) return;
        }
        self.status = .done;
    }

    fn failForProcessingExhaustion(self: *SyncChain) void {
        // Lodestar reports every peer in the chain when a batch reaches
        // MAX_PROCESSING_ATTEMPTS. At that point the whole chain peer-set is
        // considered suspect, not only the most recent download peer.
        for (self.peers.keys()) |peer_id| {
            self.callbacks.reportPeer(peer_id, .processing_exhausted);
        }
        self.status = .err;
    }

    /// Process the next batch that is awaiting_processing after any awaiting-validation prefix.
    fn processNextBatch(self: *SyncChain) !void {
        const index = self.nextProcessableBatchIndex() orelse return;
        const front = &self.batches.items[index];

        front.startProcessing();
        self.callbacks.processChainSegment(
            self.id,
            front.id,
            front.generation,
            front.blocks,
            self.sync_type,
        ) catch |err| {
            if (err == error.ProcessingPending) {
                return;
            }
            scoped_log.debug("sync chain: failed to import segment {d}..{d}: {}", .{
                front.start_slot,
                front.endSlot(),
                err,
            });
            self.cumulative_metrics.processing_error_total += 1;
            self.cumulative_metrics.processing_time_ns_total += front.finishProcessingTiming();
            front.onProcessingError();
            var exhausted = false;
            if (index > 0) exhausted = self.rewindValidatedPrefix(index);
            if (front.isProcessingExhausted()) exhausted = true;
            if (exhausted) {
                self.failForProcessingExhaustion();
            }
            return err;
        };
        const processed_blocks = front.blocks.len;
        const elapsed_ns = front.finishProcessingTiming();
        front.onProcessingSuccess();
        self.cumulative_metrics.processing_success_total += 1;
        self.cumulative_metrics.processing_time_ns_total += elapsed_ns;
        self.cumulative_metrics.processed_blocks_total += @intCast(processed_blocks);
        if (processed_blocks > 0 and index > 0) self.drainValidatedPrefix(index);
        self.markDoneIfComplete();
    }

    pub fn cumulativeMetricsSnapshot(self: *const SyncChain) CumulativeMetrics {
        return self.cumulative_metrics;
    }

    pub fn metricsSnapshot(self: *const SyncChain) MetricsSnapshot {
        var batch_statuses: BatchStatusCounts = .{};
        for (self.batches.items) |batch| {
            switch (batch.status) {
                .awaiting_download => batch_statuses.awaiting_download += 1,
                .downloading => batch_statuses.downloading += 1,
                .awaiting_processing => batch_statuses.awaiting_processing += 1,
                .processing => batch_statuses.processing += 1,
                .awaiting_validation => batch_statuses.awaiting_validation += 1,
            }
        }

        return .{
            .peer_count = @intCast(self.peerCount()),
            .target_slot = self.target.slot,
            .validated_epochs = self.validated_epochs,
            .batches_total = @intCast(self.batches.items.len),
            .batch_statuses = batch_statuses,
            .cumulative = self.cumulative_metrics,
        };
    }

    pub fn accumulateCumulativeMetrics(dst: *CumulativeMetrics, src: CumulativeMetrics) void {
        dst.download_requests_total +|= src.download_requests_total;
        dst.download_success_total +|= src.download_success_total;
        dst.download_error_total +|= src.download_error_total;
        dst.download_deferred_total +|= src.download_deferred_total;
        dst.download_time_ns_total +|= src.download_time_ns_total;
        dst.processing_success_total +|= src.processing_success_total;
        dst.processing_error_total +|= src.processing_error_total;
        dst.processing_time_ns_total +|= src.processing_time_ns_total;
        dst.processed_blocks_total +|= src.processed_blocks_total;
    }
};

// ── Tests ────────────────────────────────────────────────────────────

const TestSyncCallbacks = struct {
    processed_count: u32 = 0,
    downloaded_count: u32 = 0,
    reported_count: u32 = 0,
    reported_download_count: u32 = 0,
    reported_processing_exhausted_count: u32 = 0,
    last_chain_id: u32 = 0,
    last_batch_id: BatchId = 0,
    last_generation: u32 = 0,
    last_peer_id_buf: [64]u8 = undefined,
    last_peer_id_len: usize = 0,
    should_fail_processing: bool = false,

    fn processChainSegmentFn(ptr: *anyopaque, _: u32, _: BatchId, _: u32, blocks: []const BatchBlock, _: RangeSyncType) anyerror!void {
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

    fn reportPeerFn(ptr: *anyopaque, _: []const u8, reason: SyncPeerReportReason) void {
        const self: *TestSyncCallbacks = @ptrCast(@alignCast(ptr));
        self.reported_count += 1;
        switch (reason) {
            .download_error => self.reported_download_count += 1,
            .processing_exhausted => self.reported_processing_exhausted_count += 1,
        }
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
        std.testing.io,
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
        std.testing.io,
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
        std.testing.io,
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

test "SyncChain: deferred batch retains blocks for retry" {
    const allocator = std.testing.allocator;
    var tc = TestSyncCallbacks{};
    var chain = SyncChain.init(
        allocator,
        std.testing.io,
        0,
        .finalized,
        0,
        .{ .slot = 2, .root = [_]u8{0x11} ** 32 },
        tc.callbacks(),
    );
    defer chain.deinit();

    try chain.addPeer("p1", .{ .slot = 2, .root = [_]u8{0x11} ** 32 }, null);
    chain.startSyncing();

    _ = try chain.tick();

    const blocks = [_]BatchBlock{
        .{ .slot = 1, .block_bytes = "b1" },
        .{ .slot = 2, .block_bytes = "b2" },
    };
    chain.onBatchDeferred(tc.last_batch_id, tc.last_generation, &blocks);

    const retained = chain.getBatchBlocks(tc.last_batch_id, tc.last_generation) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 2), retained.len);
    try std.testing.expectEqual(BatchStatus.awaiting_download, chain.batches.items[0].status);
}

test "SyncChain: pending processing waits for completion callback" {
    const PendingCallbacks = struct {
        download_count: u32 = 0,
        processing_requests: u32 = 0,
        last_batch_id: BatchId = 0,
        last_generation: u32 = 0,

        fn processChainSegmentFn(ptr: *anyopaque, _: u32, _: BatchId, _: u32, _: []const BatchBlock, _: RangeSyncType) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.processing_requests += 1;
            return error.ProcessingPending;
        }

        fn downloadByRangeFn(ptr: *anyopaque, _: u32, batch_id: BatchId, generation: u32, _: []const u8, _: u64, _: u64) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.download_count += 1;
            self.last_batch_id = batch_id;
            self.last_generation = generation;
        }

        fn reportPeerFn(_: *anyopaque, _: []const u8, _: SyncPeerReportReason) void {}

        fn importBlockFn(_: *anyopaque, _: []const u8) anyerror!void {}

        fn callbacks(self: *@This()) SyncChainCallbacks {
            return .{
                .ptr = self,
                .importBlockFn = &importBlockFn,
                .processChainSegmentFn = &processChainSegmentFn,
                .downloadByRangeFn = &downloadByRangeFn,
                .reportPeerFn = &reportPeerFn,
            };
        }
    };

    const allocator = std.testing.allocator;
    var tc = PendingCallbacks{};
    var chain = SyncChain.init(
        allocator,
        std.testing.io,
        0,
        .finalized,
        0,
        .{ .slot = 2, .root = [_]u8{0} ** 32 },
        tc.callbacks(),
    );
    defer chain.deinit();

    try chain.addPeer("p1", .{ .slot = 2, .root = [_]u8{0} ** 32 }, null);
    chain.startSyncing();

    _ = try chain.tick();
    try std.testing.expectEqual(@as(usize, 1), chain.batches.items.len);
    try std.testing.expectEqual(@as(u32, 1), tc.download_count);

    const blocks = [_]BatchBlock{
        .{ .slot = 1, .block_bytes = "b1" },
        .{ .slot = 2, .block_bytes = "b2" },
    };
    chain.onBatchResponse(tc.last_batch_id, tc.last_generation, &blocks);

    try std.testing.expectEqual(@as(u32, 1), tc.processing_requests);
    try std.testing.expectEqual(BatchStatus.processing, chain.batches.items[0].status);

    const done = try chain.tick();
    try std.testing.expect(!done);
    try std.testing.expectEqual(@as(u32, 1), tc.processing_requests);
    try std.testing.expectEqual(BatchStatus.processing, chain.batches.items[0].status);

    chain.onProcessingSuccess(tc.last_batch_id, tc.last_generation);
    const done_after_completion = try chain.tick();
    try std.testing.expect(done_after_completion);
    try std.testing.expectEqual(SyncChainStatus.done, chain.status);
}

test "SyncChain: later batch validates earlier batch" {
    const allocator = std.testing.allocator;
    var tc = TestSyncCallbacks{};
    var chain = SyncChain.init(
        allocator,
        std.testing.io,
        0,
        .finalized,
        0,
        .{ .slot = 40, .root = [_]u8{0x44} ** 32 },
        tc.callbacks(),
    );
    defer chain.deinit();

    try chain.addPeer("p1", .{ .slot = 40, .root = [_]u8{0x44} ** 32 }, null);
    chain.startSyncing();

    _ = try chain.tick();
    try std.testing.expectEqual(@as(usize, 2), chain.batches.items.len);

    const batch0_id = chain.batches.items[0].id;
    const batch0_gen = chain.batches.items[0].generation;
    const batch1_id = chain.batches.items[1].id;
    const batch1_gen = chain.batches.items[1].generation;
    const blocks0 = [_]BatchBlock{.{ .slot = 1, .block_bytes = "b1" }};
    const blocks1 = [_]BatchBlock{.{ .slot = 33, .block_bytes = "b33" }};

    chain.onBatchResponse(batch0_id, batch0_gen, &blocks0);
    try std.testing.expectEqual(BatchStatus.awaiting_validation, chain.batches.items[0].status);
    try std.testing.expectEqual(@as(usize, 2), chain.batches.items.len);

    chain.onBatchResponse(batch1_id, batch1_gen, &blocks1);
    try std.testing.expectEqual(SyncChainStatus.done, chain.status);
    try std.testing.expectEqual(@as(usize, 1), chain.batches.items.len);
    try std.testing.expectEqual(@as(u64, 32), chain.batches.items[0].start_slot);
    try std.testing.expectEqual(@as(u64, 1), chain.validated_epochs);
}

test "SyncChain: processing error rewinds awaiting-validation prefix" {
    const allocator = std.testing.allocator;
    var tc = TestSyncCallbacks{};
    var chain = SyncChain.init(
        allocator,
        std.testing.io,
        0,
        .finalized,
        0,
        .{ .slot = 40, .root = [_]u8{0x55} ** 32 },
        tc.callbacks(),
    );
    defer chain.deinit();

    try chain.addPeer("p1", .{ .slot = 40, .root = [_]u8{0x55} ** 32 }, null);
    chain.startSyncing();

    _ = try chain.tick();
    try std.testing.expectEqual(@as(usize, 2), chain.batches.items.len);

    const batch0_id = chain.batches.items[0].id;
    const batch0_gen = chain.batches.items[0].generation;
    const batch1_id = chain.batches.items[1].id;
    const batch1_gen = chain.batches.items[1].generation;
    const blocks0 = [_]BatchBlock{.{ .slot = 1, .block_bytes = "b1" }};
    const blocks1 = [_]BatchBlock{.{ .slot = 33, .block_bytes = "b33" }};

    chain.onBatchResponse(batch0_id, batch0_gen, &blocks0);
    try std.testing.expectEqual(BatchStatus.awaiting_validation, chain.batches.items[0].status);

    tc.should_fail_processing = true;
    chain.onBatchResponse(batch1_id, batch1_gen, &blocks1);
    tc.should_fail_processing = false;

    try std.testing.expectEqual(BatchStatus.awaiting_download, chain.batches.items[0].status);
    try std.testing.expectEqual(BatchStatus.awaiting_download, chain.batches.items[1].status);
    try std.testing.expectEqual(@as(u8, 1), chain.batches.items[0].processing_failures);
    try std.testing.expectEqual(@as(u8, 1), chain.batches.items[1].processing_failures);
}

test "SyncChain: processing retry avoids prior invalid batch peer when alternative exists" {
    const allocator = std.testing.allocator;
    var tc = TestSyncCallbacks{};
    var chain = SyncChain.init(
        allocator,
        std.testing.io,
        0,
        .finalized,
        0,
        .{ .slot = 2, .root = [_]u8{0x77} ** 32 },
        tc.callbacks(),
    );
    defer chain.deinit();

    try chain.addPeer("bad", .{ .slot = 10, .root = [_]u8{0x77} ** 32 }, null);
    try chain.addPeer("good", .{ .slot = 2, .root = [_]u8{0x77} ** 32 }, null);
    chain.startSyncing();

    _ = try chain.tick();
    try std.testing.expectEqualStrings("bad", tc.lastPeerId());

    const blocks = [_]BatchBlock{
        .{ .slot = 1, .block_bytes = "b1" },
        .{ .slot = 2, .block_bytes = "b2" },
    };
    tc.should_fail_processing = true;
    chain.onBatchResponse(tc.last_batch_id, tc.last_generation, &blocks);
    tc.should_fail_processing = false;

    _ = try chain.tick();
    try std.testing.expectEqual(@as(u32, 2), tc.downloaded_count);
    try std.testing.expectEqualStrings("good", tc.lastPeerId());
}

test "SyncChain: computeTarget chooses most common root among highest-slot peers" {
    const allocator = std.testing.allocator;
    var tc = TestSyncCallbacks{};
    var chain = SyncChain.init(
        allocator,
        std.testing.io,
        0,
        .head,
        0,
        .{ .slot = 0, .root = [_]u8{0x11} ** 32 },
        tc.callbacks(),
    );
    defer chain.deinit();

    const root_a = [_]u8{0xAA} ** 32;
    const root_b = [_]u8{0xBB} ** 32;

    try chain.addPeer("p1", .{ .slot = 64, .root = root_a }, null);
    try chain.addPeer("p2", .{ .slot = 64, .root = root_b }, null);
    try chain.addPeer("p3", .{ .slot = 64, .root = root_b }, null);

    try std.testing.expectEqual(@as(u64, 64), chain.target.slot);
    try std.testing.expectEqual(root_b, chain.target.root);
}

test "SyncChain: skips peers that cannot serve the batch start slot" {
    const allocator = std.testing.allocator;
    var tc = TestSyncCallbacks{};
    var chain = SyncChain.init(
        allocator,
        std.testing.io,
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
        std.testing.io,
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
    tc.should_fail_processing = true;
    chain.onBatchResponse(tc.last_batch_id, tc.last_generation, &blocks);

    tc.should_fail_processing = false;

    _ = try chain.tick();
    try std.testing.expectEqual(@as(u32, 2), tc.downloaded_count);
    try std.testing.expectEqualStrings("fresh", tc.lastPeerId());
}

test "SyncChain: processing exhaustion reports all chain peers once" {
    const allocator = std.testing.allocator;
    var tc = TestSyncCallbacks{};
    var chain = SyncChain.init(
        allocator,
        std.testing.io,
        0,
        .finalized,
        0,
        .{ .slot = 2, .root = [_]u8{0x66} ** 32 },
        tc.callbacks(),
    );
    defer chain.deinit();

    try chain.addPeer("p1", .{ .slot = 2, .root = [_]u8{0x66} ** 32 }, null);
    try chain.addPeer("p2", .{ .slot = 2, .root = [_]u8{0x66} ** 32 }, null);
    chain.startSyncing();
    tc.should_fail_processing = true;

    var attempts: u8 = 0;
    while (chain.status != .err) {
        _ = try chain.tick();
        const blocks = [_]BatchBlock{
            .{ .slot = 1, .block_bytes = "b1" },
            .{ .slot = 2, .block_bytes = "b2" },
        };
        chain.onBatchResponse(tc.last_batch_id, tc.last_generation, &blocks);
        attempts += 1;
        try std.testing.expect(attempts <= sync_types.MAX_BATCH_PROCESSING_ATTEMPTS);
    }

    try std.testing.expectEqual(sync_types.MAX_BATCH_PROCESSING_ATTEMPTS, attempts);
    try std.testing.expectEqual(SyncChainStatus.err, chain.status);
    try std.testing.expectEqual(@as(u32, 2), tc.reported_count);
    try std.testing.expectEqual(@as(u32, 0), tc.reported_download_count);
    try std.testing.expectEqual(@as(u32, 2), tc.reported_processing_exhausted_count);
}
