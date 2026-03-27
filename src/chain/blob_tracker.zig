//! Blob receipt tracking for Deneb data availability.
//!
//! Tracks which blobs have been received and verified for each block,
//! enabling the DA manager to determine when a block's blob data is
//! complete.
//!
//! Reference:
//!   consensus-specs/specs/deneb/p2p-interface.md
//!   Lodestar chain/seenCache/seenGossipBlockInput.ts

const std = @import("std");
const Allocator = std.mem.Allocator;

const preset = @import("preset").preset;

/// Maximum blobs per block for bitset tracking.
/// Deneb mainnet: 6, but preset allows up to MAX_BLOB_COMMITMENTS_PER_BLOCK.
/// We use a small bitset since practical blob counts are low.
pub const MAX_BLOBS_PER_BLOCK: usize = 6;

/// Root type (32-byte hash).
pub const Root = [32]u8;

/// Per-block blob tracking state.
pub const BlobState = struct {
    /// Number of blobs expected (from block's blob_kzg_commitments length).
    expected_count: u32,
    /// Slot of the block (for pruning).
    slot: u64,
    /// Bitset tracking which blob indices have been received.
    received: std.StaticBitSet(MAX_BLOBS_PER_BLOCK),
    /// Bitset tracking which blob indices have been KZG-verified.
    verified: std.StaticBitSet(MAX_BLOBS_PER_BLOCK),

    pub fn init(expected_count: u32, slot: u64) BlobState {
        return .{
            .expected_count = expected_count,
            .slot = slot,
            .received = std.StaticBitSet(MAX_BLOBS_PER_BLOCK).initEmpty(),
            .verified = std.StaticBitSet(MAX_BLOBS_PER_BLOCK).initEmpty(),
        };
    }

    /// Check if all expected blobs have been received.
    pub fn isComplete(self: *const BlobState) bool {
        for (0..self.expected_count) |i| {
            if (!self.received.isSet(i)) return false;
        }
        return true;
    }

    /// Check if all received blobs have been verified.
    pub fn isVerified(self: *const BlobState) bool {
        for (0..self.expected_count) |i| {
            if (self.received.isSet(i) and !self.verified.isSet(i)) return false;
        }
        return true;
    }

    /// Count of received blobs.
    pub fn receivedCount(self: *const BlobState) u32 {
        var count: u32 = 0;
        for (0..self.expected_count) |i| {
            if (self.received.isSet(i)) count += 1;
        }
        return count;
    }
};

/// Tracks blob receipt and verification status across multiple blocks.
///
/// Used by the DataAvailabilityManager to know when all blobs for a
/// block have been received and verified, making the block fully available
/// for the Deneb fork.
pub const BlobTracker = struct {
    allocator: Allocator,

    /// Map: block_root → BlobState
    tracking: std.AutoHashMap(Root, BlobState),

    pub fn init(allocator: Allocator) BlobTracker {
        return .{
            .allocator = allocator,
            .tracking = std.AutoHashMap(Root, BlobState).init(allocator),
        };
    }

    pub fn deinit(self: *BlobTracker) void {
        self.tracking.deinit();
    }

    /// Register a new block that expects `commitment_count` blobs.
    /// If already tracked, this is a no-op.
    pub fn onBlock(self: *BlobTracker, block_root: Root, commitment_count: u32, slot: u64) void {
        const gop = self.tracking.getOrPut(block_root) catch return;
        if (!gop.found_existing) {
            gop.value_ptr.* = BlobState.init(commitment_count, slot);
        }
    }

    /// Mark a blob index as received for a block.
    pub fn onBlob(self: *BlobTracker, block_root: Root, index: u64) void {
        if (self.tracking.getPtr(block_root)) |state| {
            if (index < MAX_BLOBS_PER_BLOCK) {
                state.received.set(index);
            }
        }
    }

    /// Mark a blob index as KZG-verified.
    pub fn markVerified(self: *BlobTracker, block_root: Root, index: u64) void {
        if (self.tracking.getPtr(block_root)) |state| {
            if (index < MAX_BLOBS_PER_BLOCK) {
                state.verified.set(index);
            }
        }
    }

    /// Check if all expected blobs for a block have been received.
    pub fn isComplete(self: *const BlobTracker, block_root: Root) bool {
        if (self.tracking.get(block_root)) |state| {
            return state.isComplete();
        }
        return false;
    }

    /// Get the indices of missing (not yet received) blobs for a block.
    /// Caller owns the returned slice.
    pub fn getMissing(self: *const BlobTracker, allocator: Allocator, block_root: Root) ![]u64 {
        const state = self.tracking.get(block_root) orelse return allocator.alloc(u64, 0);

        var missing_count: usize = 0;
        for (0..state.expected_count) |i| {
            if (!state.received.isSet(i)) missing_count += 1;
        }

        const result = try allocator.alloc(u64, missing_count);
        var idx: usize = 0;
        for (0..state.expected_count) |i| {
            if (!state.received.isSet(i)) {
                result[idx] = @intCast(i);
                idx += 1;
            }
        }
        return result;
    }

    /// Get blob state for a block, if tracked.
    pub fn getState(self: *const BlobTracker, block_root: Root) ?BlobState {
        return self.tracking.get(block_root);
    }

    /// Remove a specific block from tracking.
    pub fn remove(self: *BlobTracker, block_root: Root) void {
        _ = self.tracking.remove(block_root);
    }

    /// Prune all entries with slot < min_slot.
    pub fn prune(self: *BlobTracker, min_slot: u64) void {
        var to_remove: [256]Root = undefined;
        var remove_count: usize = 0;

        var it = self.tracking.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.slot < min_slot) {
                if (remove_count < to_remove.len) {
                    to_remove[remove_count] = entry.key_ptr.*;
                    remove_count += 1;
                }
            }
        }

        for (to_remove[0..remove_count]) |root| {
            _ = self.tracking.remove(root);
        }
    }

    /// Number of blocks currently being tracked.
    pub fn count(self: *const BlobTracker) usize {
        return self.tracking.count();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "BlobTracker: basic tracking and completion" {
    const allocator = std.testing.allocator;
    var tracker = BlobTracker.init(allocator);
    defer tracker.deinit();

    const root = [_]u8{0xAA} ** 32;

    // Register block expecting 3 blobs.
    tracker.onBlock(root, 3, 100);

    // Not complete yet.
    try std.testing.expect(!tracker.isComplete(root));

    // Receive blobs 0 and 2.
    tracker.onBlob(root, 0);
    tracker.onBlob(root, 2);
    try std.testing.expect(!tracker.isComplete(root));

    // Check missing.
    const missing = try tracker.getMissing(allocator, root);
    defer allocator.free(missing);
    try std.testing.expectEqual(@as(usize, 1), missing.len);
    try std.testing.expectEqual(@as(u64, 1), missing[0]);

    // Receive blob 1 → complete.
    tracker.onBlob(root, 1);
    try std.testing.expect(tracker.isComplete(root));
}

test "BlobTracker: zero blobs means immediately complete" {
    const allocator = std.testing.allocator;
    var tracker = BlobTracker.init(allocator);
    defer tracker.deinit();

    const root = [_]u8{0xBB} ** 32;
    tracker.onBlock(root, 0, 50);
    try std.testing.expect(tracker.isComplete(root));
}

test "BlobTracker: unknown block returns false/empty" {
    const allocator = std.testing.allocator;
    var tracker = BlobTracker.init(allocator);
    defer tracker.deinit();

    const root = [_]u8{0xCC} ** 32;
    try std.testing.expect(!tracker.isComplete(root));

    const missing = try tracker.getMissing(allocator, root);
    defer allocator.free(missing);
    try std.testing.expectEqual(@as(usize, 0), missing.len);
}

test "BlobTracker: prune removes old entries" {
    const allocator = std.testing.allocator;
    var tracker = BlobTracker.init(allocator);
    defer tracker.deinit();

    const old_root = [_]u8{0x01} ** 32;
    const new_root = [_]u8{0x02} ** 32;

    tracker.onBlock(old_root, 2, 10);
    tracker.onBlock(new_root, 2, 100);

    try std.testing.expectEqual(@as(usize, 2), tracker.count());

    tracker.prune(50);

    try std.testing.expectEqual(@as(usize, 1), tracker.count());
    try std.testing.expect(tracker.getState(old_root) == null);
    try std.testing.expect(tracker.getState(new_root) != null);
}

test "BlobTracker: verification tracking" {
    const allocator = std.testing.allocator;
    var tracker = BlobTracker.init(allocator);
    defer tracker.deinit();

    const root = [_]u8{0xDD} ** 32;
    tracker.onBlock(root, 2, 100);

    tracker.onBlob(root, 0);
    tracker.onBlob(root, 1);

    const state = tracker.getState(root).?;
    try std.testing.expect(!state.isVerified());

    tracker.markVerified(root, 0);
    tracker.markVerified(root, 1);

    const state2 = tracker.getState(root).?;
    try std.testing.expect(state2.isVerified());
}
