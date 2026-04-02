//! Batch: a slot range being downloaded from a specific peer.
//!
//! Each batch tracks its lifecycle through a state machine:
//!   AwaitingDownload → Downloading → AwaitingProcessing → Processing → AwaitingValidation
//!
//! A generation counter prevents stale responses from being applied — if a
//! batch is re-assigned to a new peer, the old response is ignored.
//!
//! Reference: Lodestar `packages/beacon-node/src/sync/range/batch.ts`

const std = @import("std");
const sync_types = @import("sync_types.zig");

/// Status of a batch in its lifecycle.
pub const BatchStatus = enum {
    /// Ready to be dispatched to a peer.
    awaiting_download,
    /// Request sent, waiting for response.
    downloading,
    /// Response received, ready for import.
    awaiting_processing,
    /// Being imported into the chain.
    processing,
    /// Processed successfully, waiting for next batch to validate.
    awaiting_validation,
};

/// A block delivered by a peer response.
pub const BatchBlock = struct {
    slot: u64,
    block_bytes: []const u8,
};

/// Unique identifier for a batch within a sync chain.
pub const BatchId = u32;

/// Batch: a contiguous slot range being synced.
///
/// The generation counter increments on every download attempt, ensuring
/// that stale responses (from a previous peer or retry) are discarded.
pub const Batch = struct {
    id: BatchId,
    /// Epoch-aligned start slot for this batch.
    start_slot: u64,
    /// Number of slots in this batch.
    count: u64,
    /// Current status.
    status: BatchStatus,
    /// Generation counter — incremented on each download attempt.
    generation: u32,
    /// Peer currently downloading this batch (valid when status == downloading).
    download_peer: ?[]const u8,
    /// Highest slot ever returned for this batch by a successful download.
    /// Used to avoid retrying against a head peer that is already behind known progress.
    last_downloaded_slot: ?u64,
    /// Number of failed download attempts.
    download_failures: u8,
    /// Number of failed processing attempts.
    processing_failures: u8,
    /// Blocks received (valid when status >= awaiting_processing).
    blocks: []const BatchBlock,
    /// The hash of the block content for this attempt (for duplicate detection).
    blocks_hash: u64,
    /// Allocator used to own deep-copied block data.
    allocator: std.mem.Allocator,

    pub fn init(id: BatchId, start_slot: u64, count: u64, allocator: std.mem.Allocator) Batch {
        return .{
            .id = id,
            .start_slot = start_slot,
            .count = count,
            .status = .awaiting_download,
            .generation = 0,
            .download_peer = null,
            .last_downloaded_slot = null,
            .download_failures = 0,
            .processing_failures = 0,
            .blocks = &.{},
            .blocks_hash = 0,
            .allocator = allocator,
        };
    }

    /// Free owned block data.
    fn freeBlocks(self: *Batch) void {
        if (self.blocks.len == 0) return;
        for (self.blocks) |blk| {
            self.allocator.free(blk.block_bytes);
        }
        self.allocator.free(self.blocks);
        self.blocks = &.{};
    }

    /// Release all owned resources.
    pub fn deinit(self: *Batch) void {
        self.freeBlocks();
    }

    /// The last slot covered by this batch (inclusive).
    pub fn endSlot(self: *const Batch) u64 {
        if (self.count == 0) return self.start_slot;
        return self.start_slot + self.count - 1;
    }

    /// Transition to downloading state — assigns a peer and bumps generation.
    pub fn startDownload(self: *Batch, peer_id: []const u8) void {
        self.status = .downloading;
        self.download_peer = peer_id;
        self.generation +%= 1;
    }

    /// Called when download succeeds. Checks generation to reject stale responses.
    /// Returns true if the response was accepted.
    pub fn onDownloadSuccess(self: *Batch, generation: u32, blocks: []const BatchBlock) bool {
        if (generation != self.generation) return false;
        if (self.status != .downloading) return false;

        // Deep-copy blocks into owned memory so the caller can free the
        // network buffer immediately.
        const owned = self.allocator.alloc(BatchBlock, blocks.len) catch return false;
        for (blocks, 0..) |blk, i| {
            const bytes = self.allocator.dupe(u8, blk.block_bytes) catch {
                // Rollback already-duped entries.
                for (owned[0..i]) |prev| self.allocator.free(prev.block_bytes);
                self.allocator.free(owned);
                return false;
            };
            owned[i] = .{ .slot = blk.slot, .block_bytes = bytes };
        }
        self.freeBlocks(); // free any previous attempt's data
        self.blocks = owned;
        self.blocks_hash = hashBlocks(blocks);
        if (blocks.len > 0) {
            var highest_slot = blocks[0].slot;
            for (blocks[1..]) |blk| {
                highest_slot = @max(highest_slot, blk.slot);
            }
            self.last_downloaded_slot = highest_slot;
        }
        self.status = .awaiting_processing;
        return true;
    }

    /// Called when download fails (timeout, error, bad data).
    /// Returns true if the response was accepted.
    pub fn onDownloadError(self: *Batch, generation: u32) bool {
        if (generation != self.generation) return false;
        if (self.status != .downloading) return false;
        self.download_failures += 1;
        self.download_peer = null;
        self.status = .awaiting_download;
        return true;
    }

    /// Transition to processing state.
    pub fn startProcessing(self: *Batch) void {
        std.debug.assert(self.status == .awaiting_processing);
        self.status = .processing;
    }

    /// Called when processing succeeds — move to awaiting_validation.
    pub fn onProcessingSuccess(self: *Batch) void {
        std.debug.assert(self.status == .processing);
        self.freeBlocks();
        self.status = .awaiting_validation;
    }

    /// Called when processing fails.
    pub fn onProcessingError(self: *Batch) void {
        std.debug.assert(self.status == .processing);
        self.processing_failures += 1;
        self.freeBlocks();
        self.status = .awaiting_download;
        self.download_peer = null;
    }

    /// Whether this batch has exceeded download retry limits.
    pub fn isDownloadExhausted(self: *const Batch) bool {
        return self.download_failures >= sync_types.MAX_BATCH_DOWNLOAD_ATTEMPTS;
    }

    /// Whether this batch has exceeded processing retry limits.
    pub fn isProcessingExhausted(self: *const Batch) bool {
        return self.processing_failures >= sync_types.MAX_BATCH_PROCESSING_ATTEMPTS;
    }

    /// Whether this batch can be retried (either download or processing).
    pub fn canRetry(self: *const Batch) bool {
        return !self.isDownloadExhausted() and !self.isProcessingExhausted();
    }
};

/// Simple hash of block contents for duplicate detection between attempts.
fn hashBlocks(blocks: []const BatchBlock) u64 {
    var h: u64 = 0;
    for (blocks) |blk| {
        h = h *% 31 +% blk.slot;
        for (blk.block_bytes) |b| {
            h = h *% 31 +% b;
        }
    }
    return h;
}

// ── Tests ────────────────────────────────────────────────────────────

test "Batch: lifecycle" {
    var b = Batch.init(0, 100, 64, std.testing.allocator);
    try std.testing.expectEqual(BatchStatus.awaiting_download, b.status);
    try std.testing.expectEqual(@as(u64, 163), b.endSlot());

    // Start download — generation bumps to 1.
    b.startDownload("peer_a");
    try std.testing.expectEqual(BatchStatus.downloading, b.status);
    try std.testing.expectEqual(@as(u32, 1), b.generation);

    // Stale response with wrong generation is rejected.
    try std.testing.expect(!b.onDownloadSuccess(0, &.{}));
    try std.testing.expectEqual(BatchStatus.downloading, b.status);

    // Correct generation succeeds.
    const blocks = [_]BatchBlock{.{ .slot = 100, .block_bytes = "blk" }};
    try std.testing.expect(b.onDownloadSuccess(1, &blocks));
    try std.testing.expectEqual(BatchStatus.awaiting_processing, b.status);

    // Process.
    b.startProcessing();
    try std.testing.expectEqual(BatchStatus.processing, b.status);

    b.onProcessingSuccess();
    try std.testing.expectEqual(BatchStatus.awaiting_validation, b.status);
}

test "Batch: download error retry" {
    var b = Batch.init(1, 0, 32, std.testing.allocator);
    b.startDownload("peer_b");
    const gen = b.generation;
    try std.testing.expect(b.onDownloadError(gen));
    try std.testing.expectEqual(BatchStatus.awaiting_download, b.status);
    try std.testing.expectEqual(@as(u8, 1), b.download_failures);
}

test "Batch: generation prevents stale error" {
    var b = Batch.init(2, 50, 10, std.testing.allocator);
    b.startDownload("peer_c");
    const old_gen = b.generation;

    // Re-assign to new peer — new generation.
    b.startDownload("peer_d");
    const new_gen = b.generation;
    try std.testing.expect(old_gen != new_gen);

    // Old generation error is rejected.
    try std.testing.expect(!b.onDownloadError(old_gen));
    try std.testing.expectEqual(BatchStatus.downloading, b.status);
}
