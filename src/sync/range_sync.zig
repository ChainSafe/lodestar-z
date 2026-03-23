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
