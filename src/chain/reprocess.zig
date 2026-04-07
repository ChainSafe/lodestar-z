//! Reprocess — queue for blocks that arrived before their parent.
//!
//! When a block's parent root is unknown, we can't import it immediately.
//! We queue it here (keyed by parent root) and when the parent arrives via
//! onBlockImported(), we trigger reprocessing of all queued children.
//!
//! This handles the common case of out-of-order block delivery on the P2P
//! layer (gossip) and is the Zig equivalent of Lodestar's
//! `ReprocessController` in chain/reprocess/reprocessController.ts.
//!
//! Design:
//! - Blocks are queued by parent_root (the missing dependency)
//! - Max queue size prevents memory exhaustion
//! - prune(finalized_slot) removes stale entries
//! - onBlockImported() returns all children waiting on that parent

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const DEFAULT_MAX_QUEUE_SIZE: u32 = 128;

/// Why a block was queued for reprocessing.
pub const PendingReason = enum {
    /// Parent block is unknown — waiting for it to arrive.
    unknown_parent,
    /// Data availability check is pending (blobs not yet received).
    data_availability_pending,
    /// Block arrived before the validator was ready (early block).
    early_block,
};

/// A queued block awaiting reprocessing.
pub const PendingBlock = struct {
    /// Block root of the pending block.
    block_root: [32]u8,
    /// Slot of the pending block.
    slot: u64,
    /// Parent root this block is waiting for.
    parent_root: [32]u8,
    /// Why it was queued.
    reason: PendingReason,
    /// Monotonic time when it was queued (for timeout eviction).
    queued_at_slot: u64,
};

pub const MetricsSnapshot = struct {
    queued_total: u64 = 0,
    released_total: u64 = 0,
    dropped_total: u64 = 0,
    pruned_total: u64 = 0,
};

pub const ReprocessQueue = struct {
    allocator: Allocator,

    /// parent_root -> list of pending blocks waiting for that parent.
    pending: std.AutoArrayHashMap([32]u8, std.ArrayListUnmanaged(PendingBlock)),

    /// Total number of pending blocks across all parents.
    total_count: u32,

    /// Maximum total pending blocks before we start dropping.
    max_size: u32,

    metrics: MetricsSnapshot = .{},

    pub fn init(allocator: Allocator, max_size: u32) ReprocessQueue {
        return .{
            .allocator = allocator,
            .pending = std.AutoArrayHashMap([32]u8, std.ArrayListUnmanaged(PendingBlock)).init(allocator),
            .total_count = 0,
            .max_size = max_size,
        };
    }

    pub fn deinit(self: *ReprocessQueue) void {
        var it = self.pending.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.pending.deinit();
    }

    /// Queue a block pending reprocessing.
    ///
    /// Queues the block under its parent_root. If the queue is full,
    /// the oldest entry (by slot) is dropped to make room.
    pub fn addPendingBlock(
        self: *ReprocessQueue,
        block: PendingBlock,
    ) !void {
        // Drop oldest entry if at capacity.
        if (self.total_count >= self.max_size) {
            self.dropOldest();
        }

        const gop = try self.pending.getOrPut(block.parent_root);
        if (!gop.found_existing) {
            gop.value_ptr.* = std.ArrayListUnmanaged(PendingBlock).empty;
        }
        try gop.value_ptr.append(self.allocator, block);
        self.total_count += 1;
        self.metrics.queued_total += 1;

        std.log.debug("reprocess queue: queued block root={s}... (reason={s}, total={d})", .{
            &std.fmt.bytesToHex(block.block_root[0..4], .lower),
            @tagName(block.reason),
            self.total_count,
        });
    }

    /// Called when a block with `imported_root` has been successfully imported.
    ///
    /// Returns the list of pending blocks that were waiting on this parent.
    /// Caller is responsible for reprocessing them (and deiniting the returned list).
    pub fn onBlockImported(
        self: *ReprocessQueue,
        imported_root: [32]u8,
    ) std.ArrayListUnmanaged(PendingBlock) {
        var result = std.ArrayListUnmanaged(PendingBlock).empty;

        if (self.pending.fetchSwapRemove(imported_root)) |kv| {
            result = kv.value;
            self.total_count -= @intCast(result.items.len);
            self.metrics.released_total += @intCast(result.items.len);
            std.log.debug("reprocess queue: released {d} block(s) for parent {s}...", .{
                result.items.len,
                &std.fmt.bytesToHex(imported_root[0..4], .lower),
            });
        }

        return result;
    }

    /// Remove all pending blocks with slot < finalized_slot.
    ///
    /// These blocks are behind the finality horizon and can never be imported.
    pub fn prune(self: *ReprocessQueue, finalized_slot: u64) void {
        if (finalized_slot == 0) return;

        var parents_to_remove = std.ArrayListUnmanaged([32]u8).empty;
        defer parents_to_remove.deinit(self.allocator);

        var it = self.pending.iterator();
        while (it.next()) |entry| {
            var i: usize = 0;
            while (i < entry.value_ptr.items.len) {
                if (entry.value_ptr.items[i].slot < finalized_slot) {
                    _ = entry.value_ptr.swapRemove(i);
                    self.total_count -= 1;
                    self.metrics.pruned_total += 1;
                } else {
                    i += 1;
                }
            }
            if (entry.value_ptr.items.len == 0) {
                parents_to_remove.append(self.allocator, entry.key_ptr.*) catch {};
            }
        }

        for (parents_to_remove.items) |parent| {
            if (self.pending.fetchSwapRemove(parent)) |kv| {
                var list = kv.value;
                list.deinit(self.allocator);
            }
        }
    }

    /// Number of pending blocks currently queued.
    pub fn len(self: *const ReprocessQueue) u32 {
        return self.total_count;
    }

    pub fn metricsSnapshot(self: *const ReprocessQueue) MetricsSnapshot {
        return self.metrics;
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn dropOldest(self: *ReprocessQueue) void {
        // Find the entry with the lowest slot across all queued blocks.
        var oldest_parent: ?[32]u8 = null;
        var oldest_slot: u64 = std.math.maxInt(u64);
        var oldest_idx: usize = 0;

        var it = self.pending.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items, 0..) |block, idx| {
                if (block.slot < oldest_slot) {
                    oldest_slot = block.slot;
                    oldest_parent = entry.key_ptr.*;
                    oldest_idx = idx;
                }
            }
        }

        if (oldest_parent) |parent| {
            const list = self.pending.getPtr(parent).?;
            _ = list.swapRemove(oldest_idx);
            self.total_count -= 1;
            self.metrics.dropped_total += 1;
            if (list.items.len == 0) {
                if (self.pending.fetchSwapRemove(parent)) |kv| {
                    var l = kv.value;
                    l.deinit(self.allocator);
                }
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ReprocessQueue: add and retrieve on import" {
    var q = ReprocessQueue.init(std.testing.allocator, 32);
    defer q.deinit();

    const parent = [_]u8{0xAA} ** 32;
    const child1 = PendingBlock{
        .block_root = [_]u8{0x01} ** 32,
        .slot = 10,
        .parent_root = parent,
        .reason = .unknown_parent,
        .queued_at_slot = 10,
    };
    const child2 = PendingBlock{
        .block_root = [_]u8{0x02} ** 32,
        .slot = 11,
        .parent_root = parent,
        .reason = .unknown_parent,
        .queued_at_slot = 10,
    };

    try q.addPendingBlock(child1);
    try q.addPendingBlock(child2);
    try std.testing.expectEqual(@as(u32, 2), q.len());

    var released = q.onBlockImported(parent);
    defer released.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), released.items.len);
    try std.testing.expectEqual(@as(u32, 0), q.len());
}

test "ReprocessQueue: prune removes old entries" {
    var q = ReprocessQueue.init(std.testing.allocator, 32);
    defer q.deinit();

    const parent = [_]u8{0xBB} ** 32;

    try q.addPendingBlock(.{
        .block_root = [_]u8{0x01} ** 32,
        .slot = 5,
        .parent_root = parent,
        .reason = .unknown_parent,
        .queued_at_slot = 5,
    });
    try q.addPendingBlock(.{
        .block_root = [_]u8{0x02} ** 32,
        .slot = 100,
        .parent_root = parent,
        .reason = .unknown_parent,
        .queued_at_slot = 5,
    });

    q.prune(50); // Remove blocks with slot < 50.
    try std.testing.expectEqual(@as(u32, 1), q.len());
}

test "ReprocessQueue: max size drops oldest" {
    var q = ReprocessQueue.init(std.testing.allocator, 2);
    defer q.deinit();

    const parent = [_]u8{0xCC} ** 32;

    try q.addPendingBlock(.{
        .block_root = [_]u8{0x01} ** 32,
        .slot = 1,
        .parent_root = parent,
        .reason = .unknown_parent,
        .queued_at_slot = 1,
    });
    try q.addPendingBlock(.{
        .block_root = [_]u8{0x02} ** 32,
        .slot = 2,
        .parent_root = parent,
        .reason = .unknown_parent,
        .queued_at_slot = 2,
    });
    // This should evict slot=1 (oldest).
    try q.addPendingBlock(.{
        .block_root = [_]u8{0x03} ** 32,
        .slot = 3,
        .parent_root = parent,
        .reason = .unknown_parent,
        .queued_at_slot = 3,
    });

    try std.testing.expectEqual(@as(u32, 2), q.len());
}

test "ReprocessQueue: no-op on unknown import" {
    var q = ReprocessQueue.init(std.testing.allocator, 32);
    defer q.deinit();

    var result = q.onBlockImported([_]u8{0xFF} ** 32);
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), result.items.len);
}
