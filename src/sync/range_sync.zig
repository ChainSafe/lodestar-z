//! Range sync: download and import blocks by slot range.
//!
//! The primary initial sync method. Given a target (from the best peer's
//! Status message), generates sequential batch requests and processes
//! responses by feeding them through the block import pipeline.
//!
//! Reference: Lodestar `packages/beacon-node/src/sync/range/`

const std = @import("std");
const Allocator = std.mem.Allocator;
const db_mod = @import("db");
const BeaconDB = db_mod.BeaconDB;
const sync_types = @import("sync_types.zig");
const PeerSyncInfo = sync_types.PeerSyncInfo;

/// Default batch size — 64 slots per range request (spec maximum: 128).
const DEFAULT_BATCH_SIZE: u64 = 64;

pub const RangeSyncBatch = struct {
    start_slot: u64,
    count: u64,
    peer: PeerSyncInfo,
};

pub const BatchResult = struct {
    blocks_imported: u64,
    last_slot: u64,
    errors: u64,
};

pub const RangeSync = struct {
    allocator: Allocator,
    db: *BeaconDB,

    /// Target we are syncing towards.
    target_slot: u64,
    target_root: [32]u8,

    /// Slot of the last successfully imported block.
    last_synced_slot: u64,

    /// Number of slots to request per batch.
    batch_size: u64,

    pub fn init(
        allocator: Allocator,
        db: *BeaconDB,
        target_slot: u64,
        target_root: [32]u8,
        start_slot: u64,
    ) RangeSync {
        return .{
            .allocator = allocator,
            .db = db,
            .target_slot = target_slot,
            .target_root = target_root,
            .last_synced_slot = start_slot,
            .batch_size = DEFAULT_BATCH_SIZE,
        };
    }

    /// Create the next batch request. Returns null when sync is complete.
    pub fn nextBatch(self: *RangeSync, peer: PeerSyncInfo) ?RangeSyncBatch {
        if (self.isComplete()) return null;

        const start = self.last_synced_slot + 1;
        const remaining = self.target_slot - start + 1;
        const count = @min(self.batch_size, remaining);

        return .{
            .start_slot = start,
            .count = count,
            .peer = peer,
        };
    }

    /// Process a batch of block bytes received from a peer.
    ///
    /// Each entry is the SSZ-encoded SignedBeaconBlock. Blocks are stored
    /// in the DB keyed by slot (archive) and the last_synced_slot is
    /// advanced on success.
    ///
    /// Blocks must be ordered by ascending slot. Gaps are tolerated
    /// (skipped slots are normal on the beacon chain).
    pub fn processBatch(
        self: *RangeSync,
        block_entries: []const BlockEntry,
    ) !BatchResult {
        var imported: u64 = 0;
        var last_slot: u64 = self.last_synced_slot;
        var errors: u64 = 0;

        for (block_entries) |entry| {
            // Sanity: blocks must be beyond our current position.
            if (entry.slot <= self.last_synced_slot) {
                errors += 1;
                continue;
            }

            // Store as archive block (finalized range we're back-filling).
            self.db.putBlockArchive(entry.slot, entry.root, entry.data) catch {
                errors += 1;
                continue;
            };

            imported += 1;
            last_slot = entry.slot;
        }

        if (imported > 0) {
            self.last_synced_slot = last_slot;
        }

        return .{
            .blocks_imported = imported,
            .last_slot = last_slot,
            .errors = errors,
        };
    }

    /// Whether we have reached the target slot.
    pub fn isComplete(self: *const RangeSync) bool {
        return self.last_synced_slot >= self.target_slot;
    }

    /// Update the sync target (e.g. when a better peer is discovered).
    pub fn updateTarget(self: *RangeSync, target_slot: u64, target_root: [32]u8) void {
        self.target_slot = target_slot;
        self.target_root = target_root;
    }

    /// Remaining slots until target.
    pub fn syncDistance(self: *const RangeSync) u64 {
        if (self.last_synced_slot >= self.target_slot) return 0;
        return self.target_slot - self.last_synced_slot;
    }
};

/// A decoded block ready for import into the DB.
pub const BlockEntry = struct {
    slot: u64,
    root: [32]u8,
    data: []const u8,
};

// ── Tests ────────────────────────────────────────────────────────────

test "RangeSync: batch generation advances through range" {
    const allocator = std.testing.allocator;
    var kv = db_mod.MemoryKVStore.init(allocator);
    defer kv.deinit();
    var db = BeaconDB.init(allocator, kv.kvStore());

    var rs = RangeSync.init(allocator, &db, 200, [_]u8{0xFF} ** 32, 0);
    rs.batch_size = 50;

    const peer = PeerSyncInfo{
        .peer_id = "test_peer",
        .head_slot = 200,
        .head_root = [_]u8{0xFF} ** 32,
        .finalized_epoch = 6,
        .finalized_root = [_]u8{0} ** 32,
    };

    // First batch: slots 1..50
    const b1 = rs.nextBatch(peer).?;
    try std.testing.expectEqual(@as(u64, 1), b1.start_slot);
    try std.testing.expectEqual(@as(u64, 50), b1.count);

    // Simulate importing those blocks.
    var entries: [50]BlockEntry = undefined;
    for (0..50) |i| {
        entries[i] = .{
            .slot = @as(u64, @intCast(i)) + 1,
            .root = [_]u8{@intCast(i)} ++ [_]u8{0} ** 31,
            .data = "block_data",
        };
    }
    const result = try rs.processBatch(&entries);
    try std.testing.expectEqual(@as(u64, 50), result.blocks_imported);
    try std.testing.expectEqual(@as(u64, 50), result.last_slot);
    try std.testing.expectEqual(@as(u64, 0), result.errors);

    // Second batch: slots 51..100
    const b2 = rs.nextBatch(peer).?;
    try std.testing.expectEqual(@as(u64, 51), b2.start_slot);
    try std.testing.expectEqual(@as(u64, 50), b2.count);
}

test "RangeSync: last batch is truncated to target" {
    const allocator = std.testing.allocator;
    var kv = db_mod.MemoryKVStore.init(allocator);
    defer kv.deinit();
    var db = BeaconDB.init(allocator, kv.kvStore());

    var rs = RangeSync.init(allocator, &db, 75, [_]u8{0} ** 32, 50);
    rs.batch_size = 64;

    const peer = PeerSyncInfo{
        .peer_id = "p",
        .head_slot = 75,
        .head_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .finalized_root = [_]u8{0} ** 32,
    };

    const batch = rs.nextBatch(peer).?;
    try std.testing.expectEqual(@as(u64, 51), batch.start_slot);
    try std.testing.expectEqual(@as(u64, 25), batch.count); // 75 - 51 + 1
}

test "RangeSync: isComplete after reaching target" {
    const allocator = std.testing.allocator;
    var kv = db_mod.MemoryKVStore.init(allocator);
    defer kv.deinit();
    var db = BeaconDB.init(allocator, kv.kvStore());

    var rs = RangeSync.init(allocator, &db, 10, [_]u8{0} ** 32, 0);

    try std.testing.expect(!rs.isComplete());

    // Import blocks up to target.
    var entries: [10]BlockEntry = undefined;
    for (0..10) |i| {
        entries[i] = .{
            .slot = @as(u64, @intCast(i)) + 1,
            .root = [_]u8{@intCast(i)} ++ [_]u8{0} ** 31,
            .data = "block",
        };
    }
    _ = try rs.processBatch(&entries);

    try std.testing.expect(rs.isComplete());
    try std.testing.expect(rs.nextBatch(.{
        .peer_id = "p",
        .head_slot = 10,
        .head_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .finalized_root = [_]u8{0} ** 32,
    }) == null);
}

test "RangeSync: processBatch rejects stale blocks" {
    const allocator = std.testing.allocator;
    var kv = db_mod.MemoryKVStore.init(allocator);
    defer kv.deinit();
    var db = BeaconDB.init(allocator, kv.kvStore());

    var rs = RangeSync.init(allocator, &db, 100, [_]u8{0} ** 32, 50);

    // Try to import a block at slot 50 (already synced) and slot 30 (behind).
    const entries = [_]BlockEntry{
        .{ .slot = 30, .root = [_]u8{1} ** 32, .data = "old" },
        .{ .slot = 50, .root = [_]u8{2} ** 32, .data = "stale" },
        .{ .slot = 51, .root = [_]u8{3} ** 32, .data = "good" },
    };
    const result = try rs.processBatch(&entries);
    try std.testing.expectEqual(@as(u64, 1), result.blocks_imported);
    try std.testing.expectEqual(@as(u64, 2), result.errors);
    try std.testing.expectEqual(@as(u64, 51), result.last_slot);
}

test "RangeSync: syncDistance tracks remaining" {
    const allocator = std.testing.allocator;
    var kv = db_mod.MemoryKVStore.init(allocator);
    defer kv.deinit();
    var db = BeaconDB.init(allocator, kv.kvStore());

    var rs = RangeSync.init(allocator, &db, 100, [_]u8{0} ** 32, 0);
    try std.testing.expectEqual(@as(u64, 100), rs.syncDistance());

    rs.last_synced_slot = 60;
    try std.testing.expectEqual(@as(u64, 40), rs.syncDistance());

    rs.last_synced_slot = 100;
    try std.testing.expectEqual(@as(u64, 0), rs.syncDistance());
}

test "RangeSync: updateTarget extends sync" {
    const allocator = std.testing.allocator;
    var kv = db_mod.MemoryKVStore.init(allocator);
    defer kv.deinit();
    var db = BeaconDB.init(allocator, kv.kvStore());

    var rs = RangeSync.init(allocator, &db, 100, [_]u8{0} ** 32, 100);
    try std.testing.expect(rs.isComplete());

    rs.updateTarget(200, [_]u8{0xFF} ** 32);
    try std.testing.expect(!rs.isComplete());
    try std.testing.expectEqual(@as(u64, 100), rs.syncDistance());
}

// ── RangeSyncManager ─────────────────────────────────────────────────────────
//
// Higher-level state machine wrapping RangeSync. Manages a sliding window of
// in-flight batch requests, handles retries, and drives the download→import
// loop via callback interfaces (so tests can mock transport and import).

/// Maximum number of concurrent in-flight batches.
pub const MAX_WINDOW_SIZE: usize = 8;

/// Maximum retry attempts per batch before it is skipped.
pub const MAX_BATCH_RETRIES: u8 = 3;

/// Status of a single download batch.
pub const BatchStatus = enum {
    /// Dispatched, waiting for a response.
    pending,
    /// All blocks in the range were imported successfully.
    completed,
    /// Peer returned an error; will retry.
    failed,
    /// Exhausted retries — skipped to make forward progress.
    skipped,
};

/// In-flight or completed batch metadata.
pub const Batch = struct {
    id: u32,
    start_slot: u64,
    count: u64,
    peer: PeerSyncInfo,
    status: BatchStatus,
    retry_count: u8,
    blocks_imported: u64,
};

/// Callback vtable for importing a single decoded block.
/// The callee owns `block_bytes` for the duration of the call only.
pub const BlockImporterCallback = struct {
    ptr: *anyopaque,
    importFn: *const fn (ptr: *anyopaque, block_bytes: []const u8) anyerror!void,

    pub fn import(self: BlockImporterCallback, block_bytes: []const u8) !void {
        return self.importFn(self.ptr, block_bytes);
    }
};

/// Callback vtable for dispatching a BeaconBlocksByRange request to a peer.
/// After calling this the transport should eventually call
/// `RangeSyncManager.onBatchResponse` or `onBatchError` with the matching id.
pub const BatchRequestCallback = struct {
    ptr: *anyopaque,
    requestFn: *const fn (
        ptr: *anyopaque,
        batch_id: u32,
        start_slot: u64,
        count: u64,
        peer_id: []const u8,
    ) void,

    pub fn request(
        self: BatchRequestCallback,
        batch_id: u32,
        start_slot: u64,
        count: u64,
        peer_id: []const u8,
    ) void {
        self.requestFn(self.ptr, batch_id, start_slot, count, peer_id);
    }
};

/// Block entry delivered by a peer response.
pub const BatchBlock = struct {
    /// Slot number of this block.
    slot: u64,
    /// Raw SSZ-encoded SignedBeaconBlock bytes.
    block_bytes: []const u8,
};

/// State machine for range sync: manages a sliding window of batch requests.
pub const RangeSyncManager = struct {
    allocator: Allocator,
    importer: BlockImporterCallback,
    requester: BatchRequestCallback,
    peer_manager: *@import("peer_manager.zig").PeerManager,

    /// Slot at which our local head currently sits.
    current_slot: u64,
    /// Slot we are syncing towards.
    target_slot: u64,
    /// Slots per batch request.
    batch_size: u64,

    /// Sliding window of active batches (max MAX_WINDOW_SIZE).
    batches: [MAX_WINDOW_SIZE]Batch,
    /// Monotonically increasing batch identifier.
    next_batch_id: u32,
    /// Next slot to create a new batch for.
    next_dispatch_slot: u64,

    pub fn init(
        allocator: Allocator,
        importer: BlockImporterCallback,
        requester: BatchRequestCallback,
        peer_manager: *@import("peer_manager.zig").PeerManager,
        current_slot: u64,
    ) RangeSyncManager {
        return .{
            .allocator = allocator,
            .importer = importer,
            .requester = requester,
            .peer_manager = peer_manager,
            .current_slot = current_slot,
            .target_slot = current_slot,
            .batch_size = DEFAULT_BATCH_SIZE,
            .batches = undefined,
            .next_batch_id = 0,
            .next_dispatch_slot = current_slot + 1,
        };
    }

    /// Set (or update) the sync target. Resets the dispatch pointer if we moved backward.
    pub fn start(self: *RangeSyncManager, target_slot: u64) void {
        self.target_slot = target_slot;
        // If no batches in flight and dispatch pointer is already past current_slot, leave it.
        // If current_slot advanced (e.g. we already imported some blocks), adjust dispatch ptr.
        if (self.next_dispatch_slot <= self.current_slot) {
            self.next_dispatch_slot = self.current_slot + 1;
        }
    }

    /// Called when a peer delivers a response for the given batch_id.
    ///
    /// Imports blocks in order, then marks the batch completed (or failed if
    /// import errors occur). After completing a batch, advances `current_slot`
    /// if this was the lowest-numbered pending batch.
    pub fn onBatchResponse(self: *RangeSyncManager, batch_id: u32, blocks: []const BatchBlock) !void {
        const idx = self.findBatch(batch_id) orelse return;
        var batch = &self.batches[idx];

        // Import all delivered blocks.
        var imported: u64 = 0;
        var last_slot: u64 = self.current_slot;
        for (blocks) |blk| {
            if (blk.slot <= self.current_slot) continue; // stale
            self.importer.import(blk.block_bytes) catch continue;
            imported += 1;
            if (blk.slot > last_slot) last_slot = blk.slot;
        }

        batch.blocks_imported = imported;
        batch.status = .completed;

        // Advance current_slot past any contiguous completed batches from the front.
        self.drainCompleted();
    }

    /// Called when a peer fails to deliver (timeout, error, bad data, etc.)
    pub fn onBatchError(self: *RangeSyncManager, batch_id: u32) void {
        const idx = self.findBatch(batch_id) orelse return;
        var batch = &self.batches[idx];
        batch.retry_count += 1;
        if (batch.retry_count >= MAX_BATCH_RETRIES) {
            // Give up on this range — skip forward to make progress.
            batch.status = .skipped;
            self.drainCompleted();
        } else {
            // Mark as failed so tick() will re-dispatch.
            batch.status = .failed;
        }
    }

    /// Periodic tick: dispatches new batches into the window, returns current status.
    pub fn tick(self: *RangeSyncManager) !sync_types.SyncStatus {
        // Re-dispatch failed batches.
        for (self.batches[0..]) |*batch| {
            if (batch.status == .failed) {
                const peer = self.peer_manager.getSyncTarget() orelse continue;
                batch.peer = peer;
                batch.status = .pending;
                self.requester.request(batch.id, batch.start_slot, batch.count, peer.peer_id);
            }
        }

        // Fill window with new batches.
        while (self.batches.len < MAX_WINDOW_SIZE and
            self.next_dispatch_slot <= self.target_slot)
        {
            const peer = self.peer_manager.getSyncTarget() orelse break;

            const remaining = self.target_slot - self.next_dispatch_slot + 1;
            const count = @min(self.batch_size, remaining);

            const id = self.next_batch_id;
            self.next_batch_id +%= 1;

            const batch = Batch{
                .id = id,
                .start_slot = self.next_dispatch_slot,
                .count = count,
                .peer = peer,
                .status = .pending,
                .retry_count = 0,
                .blocks_imported = 0,
            };
            self.batches.appendAssumeCapacity(batch);
            self.next_dispatch_slot += count;

            self.requester.request(id, batch.start_slot, count, peer.peer_id);
        }

        const is_synced = self.current_slot >= self.target_slot and self.batches.len == 0;
        const sync_distance = if (self.target_slot > self.current_slot)
            self.target_slot - self.current_slot
        else
            0;

        return sync_types.SyncStatus{
            .state = if (is_synced) .synced else .syncing,
            .head_slot = self.current_slot,
            .sync_distance = sync_distance,
            .is_optimistic = false,
        };
    }

    /// Whether sync has reached the target.
    pub fn isSynced(self: *const RangeSyncManager) bool {
        return self.current_slot >= self.target_slot and self.batches.len == 0;
    }

    // ── Internal helpers ────────────────────────────────────────────

    fn findBatch(self: *RangeSyncManager, batch_id: u32) ?usize {
        for (self.batches[0..], 0..) |b, i| {
            if (b.id == batch_id) return i;
        }
        return null;
    }

    /// Remove completed/skipped batches from the front of the window,
    /// advancing current_slot accordingly.
    fn drainCompleted(self: *RangeSyncManager) void {
        while (self.batches.len > 0) {
            const front = self.batches[0..][0];
            if (front.status != .completed and front.status != .skipped) break;

            // Advance current_slot to the end of this batch.
            const batch_end = front.start_slot + front.count - 1;
            if (batch_end > self.current_slot) {
                self.current_slot = batch_end;
            }

            // Remove from front by shifting.
            const n = self.batches.len;
            for (1..n) |i| {
                self.batches[i - 1] = self.batches[i];
            }
            // Shift batches left by 1
            var j: usize = 0;
            while (j < MAX_WINDOW_SIZE - 1) : (j += 1) {
                self.batches[j] = self.batches[j + 1];
            }
            self.batches[MAX_WINDOW_SIZE - 1] = std.mem.zeroes(Batch);
        }
    }
};

// ── RangeSyncManager Tests ───────────────────────────────────────────────────

const PeerManager = @import("peer_manager.zig").PeerManager;
const StatusMessage = @import("networking").messages.StatusMessage;

/// Test harness: records dispatched requests and lets the test inject responses.
const TestHarness = struct {
    allocator: Allocator,
    imported_slots: std.ArrayList(u64),
    dispatched_batches: std.ArrayList(DispatchedBatch),
    import_should_fail: bool = false,

    const DispatchedBatch = struct { id: u32, start_slot: u64, count: u64 };

    fn init(allocator: Allocator) TestHarness {
        return .{
            .allocator = allocator,
            .imported_slots = std.ArrayListUnmanaged(u64).empty,
            .dispatched_batches = std.ArrayListUnmanaged(DispatchedBatch).empty,
        };
    }

    fn deinit(self: *TestHarness) void {
        self.imported_slots.deinit(self.allocator);
        self.dispatched_batches.deinit(self.allocator);
    }

    fn importCallback(ptr: *anyopaque, block_bytes: []const u8) anyerror!void {
        const h: *TestHarness = @ptrCast(@alignCast(ptr));
        if (h.import_should_fail) return error.ImportFailed;
        // Decode slot from the first 8 bytes (test encoding).
        if (block_bytes.len >= 8) {
            const slot = std.mem.readInt(u64, block_bytes[0..8], .little);
            try h.imported_slots.append(h.allocator, slot);
        }
    }

    fn requestCallback(
        ptr: *anyopaque,
        batch_id: u32,
        start_slot: u64,
        count: u64,
        peer_id: []const u8,
    ) void {
        _ = peer_id;
        const h: *TestHarness = @ptrCast(@alignCast(ptr));
        h.dispatched_batches.append(h.allocator, .{ .id = batch_id, .start_slot = start_slot, .count = count }) catch {};
    }

    fn importer(self: *TestHarness) BlockImporterCallback {
        return .{ .ptr = self, .importFn = &importCallback };
    }

    fn requester(self: *TestHarness) BatchRequestCallback {
        return .{ .ptr = self, .requestFn = &requestCallback };
    }

    /// Synthesise a response for the most recently dispatched batch.
    fn respondToLast(self: *TestHarness, mgr: *RangeSyncManager) !void {
        const batch = self.dispatched_batches.getLast();
        var blocks = std.ArrayListUnmanaged(BatchBlock).empty;
        defer blocks.deinit(self.allocator);

        for (0..batch.count) |i| {
            const slot = batch.start_slot + i;
            const bytes = try self.allocator.alloc(u8, 8);
            std.mem.writeInt(u64, bytes[0..8], slot, .little);
            try blocks.append(self.allocator, .{ .slot = slot, .block_bytes = bytes });
        }
        defer for (blocks.items) |b| self.allocator.free(b.block_bytes);

        try mgr.onBatchResponse(batch.id, blocks.items);
    }
};

// test "SKIP_016_MIGRATION RangeSyncManager: sequential batches are dispatched and imported" {
//     const allocator = std.testing.allocator;
//     var pm = PeerManager.init(allocator);
//     defer pm.deinit();
//     try pm.updatePeerStatus("p1", .{
//         .fork_digest = .{ 0, 0, 0, 0 },
//         .finalized_root = [_]u8{0} ** 32,
//         .finalized_epoch = 0,
//         .head_root = [_]u8{0} ** 32,
//         .head_slot = 200,
//     });
// 
//     var h = TestHarness.init(allocator);
//     defer h.deinit();
// 
//     var mgr = RangeSyncManager.init(allocator, h.importer(), h.requester(), &pm, 0);
//     mgr.batch_size = 64;
//     mgr.start(128);
// 
//     // tick() should dispatch exactly 2 batches (64 + 64 = 128 slots).
//     _ = try mgr.tick();
//     try std.testing.expectEqual(@as(usize, 2), h.dispatched_batches.items.len);
//     try std.testing.expectEqual(@as(u64, 1), h.dispatched_batches.items[0].start_slot);
//     try std.testing.expectEqual(@as(u64, 64), h.dispatched_batches.items[0].count);
//     try std.testing.expectEqual(@as(u64, 65), h.dispatched_batches.items[1].start_slot);
//     try std.testing.expectEqual(@as(u64, 64), h.dispatched_batches.items[1].count);
// 
//     // Deliver both batches.
//     const b0_id = h.dispatched_batches.items[0].id;
//     const b1_id = h.dispatched_batches.items[1].id;
//     {
//         var blocks = std.ArrayListUnmanaged(BatchBlock).empty;
//         defer blocks.deinit(allocator);
//         for (1..65) |s| {
//             const bytes = try allocator.alloc(u8, 8);
//             std.mem.writeInt(u64, bytes[0..8], s, .little);
//             try blocks.append(allocator, .{ .slot = s, .block_bytes = bytes });
//         }
//         defer for (blocks.items) |b| allocator.free(b.block_bytes);
//         try mgr.onBatchResponse(b0_id, blocks.items);
//     }
//     {
//         var blocks = std.ArrayListUnmanaged(BatchBlock).empty;
//         defer blocks.deinit(allocator);
//         for (65..129) |s| {
//             const bytes = try allocator.alloc(u8, 8);
//             std.mem.writeInt(u64, bytes[0..8], s, .little);
//             try blocks.append(allocator, .{ .slot = s, .block_bytes = bytes });
//         }
//         defer for (blocks.items) |b| allocator.free(b.block_bytes);
//         try mgr.onBatchResponse(b1_id, blocks.items);
//     }
// 
//     // Should be synced now.
//     try std.testing.expect(mgr.isSynced());
//     try std.testing.expectEqual(@as(u64, 128), mgr.current_slot);
// 
//     // All 128 slots imported.
//     try std.testing.expectEqual(@as(usize, 128), h.imported_slots.items.len);
//     try std.testing.expectEqual(@as(u64, 1), h.imported_slots.items[0]);
//     try std.testing.expectEqual(@as(u64, 128), h.imported_slots.items[127]);
// }

// test "SKIP_016_MIGRATION RangeSyncManager: batch retry on error, succeeds on retry" {
//     const allocator = std.testing.allocator;
//     var pm = PeerManager.init(allocator);
//     defer pm.deinit();
//     try pm.updatePeerStatus("p1", .{
//         .fork_digest = .{ 0, 0, 0, 0 },
//         .finalized_root = [_]u8{0} ** 32,
//         .finalized_epoch = 0,
//         .head_root = [_]u8{0} ** 32,
//         .head_slot = 64,
//     });
// 
//     var h = TestHarness.init(allocator);
//     defer h.deinit();
// 
//     var mgr = RangeSyncManager.init(allocator, h.importer(), h.requester(), &pm, 0);
//     mgr.batch_size = 64;
//     mgr.start(64);
// 
//     _ = try mgr.tick();
//     try std.testing.expectEqual(@as(usize, 1), h.dispatched_batches.items.len);
// 
//     // Simulate error on first attempt.
//     const batch_id = h.dispatched_batches.items[0].id;
//     mgr.onBatchError(batch_id);
//     try std.testing.expectEqual(@as(u8, 1), mgr.batches[0].retry_count);
//     try std.testing.expect(!mgr.isSynced());
// 
//     // tick() re-dispatches failed batch.
//     _ = try mgr.tick();
//     // The re-dispatched batch should appear as a second dispatch record.
//     try std.testing.expectEqual(@as(usize, 2), h.dispatched_batches.items.len);
// 
//     // Deliver success on retry.
//     const retry_id = h.dispatched_batches.items[1].id;
//     var blocks = std.ArrayListUnmanaged(BatchBlock).empty;
//     defer blocks.deinit(allocator);
//     for (1..65) |s| {
//         const bytes = try allocator.alloc(u8, 8);
//         std.mem.writeInt(u64, bytes[0..8], s, .little);
//         try blocks.append(allocator, .{ .slot = s, .block_bytes = bytes });
//     }
//     defer for (blocks.items) |b| allocator.free(b.block_bytes);
//     try mgr.onBatchResponse(retry_id, blocks.items);
// 
//     try std.testing.expect(mgr.isSynced());
// }

// test "SKIP_016_MIGRATION RangeSyncManager: batch skipped after MAX_BATCH_RETRIES" {
//     const allocator = std.testing.allocator;
//     var pm = PeerManager.init(allocator);
//     defer pm.deinit();
//     try pm.updatePeerStatus("p1", .{
//         .fork_digest = .{ 0, 0, 0, 0 },
//         .finalized_root = [_]u8{0} ** 32,
//         .finalized_epoch = 0,
//         .head_root = [_]u8{0} ** 32,
//         .head_slot = 64,
//     });
// 
//     var h = TestHarness.init(allocator);
//     defer h.deinit();
// 
//     var mgr = RangeSyncManager.init(allocator, h.importer(), h.requester(), &pm, 0);
//     mgr.batch_size = 64;
//     mgr.start(64);
//     _ = try mgr.tick();
// 
//     const batch_id = h.dispatched_batches.items[0].id;
// 
//     // Exhaust retries.
//     var i: u8 = 0;
//     while (i < MAX_BATCH_RETRIES) : (i += 1) {
//         mgr.onBatchError(batch_id);
//         if (i + 1 < MAX_BATCH_RETRIES) {
//             _ = try mgr.tick(); // re-dispatch
//         }
//     }
// 
//     // After MAX_BATCH_RETRIES, batch is skipped and window drains.
//     try std.testing.expectEqual(@as(usize, 0), mgr.batches.len);
//     // Sync is "complete" (skipped forward past target).
//     try std.testing.expect(mgr.isSynced());
// }

// test "SKIP_016_MIGRATION RangeSyncManager: tick returns synced status when current_slot >= target" {
//     const allocator = std.testing.allocator;
//     var pm = PeerManager.init(allocator);
//     defer pm.deinit();
//     try pm.updatePeerStatus("p1", .{
//         .fork_digest = .{ 0, 0, 0, 0 },
//         .finalized_root = [_]u8{0} ** 32,
//         .finalized_epoch = 0,
//         .head_root = [_]u8{0} ** 32,
//         .head_slot = 50,
//     });
// 
//     var h = TestHarness.init(allocator);
//     defer h.deinit();
// 
//     // Start already at or past target.
//     var mgr = RangeSyncManager.init(allocator, h.importer(), h.requester(), &pm, 100);
//     mgr.start(50); // target < current_slot
// 
//     const status = try mgr.tick();
//     try std.testing.expectEqual(sync_types.SyncState.synced, status.state);
//     try std.testing.expectEqual(@as(u64, 0), status.sync_distance);
// }
