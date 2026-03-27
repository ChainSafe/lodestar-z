//! Column receipt tracking for PeerDAS (Fulu) data availability.
//!
//! Tracks which data columns have been received and verified for each block,
//! relative to the node's custody set. Used to determine when a block has
//! sufficient column data for import or reconstruction.
//!
//! Reference:
//!   consensus-specs/specs/fulu/p2p-interface.md
//!   Lodestar chain/seenCache/seenGossipBlockInput.ts

const std = @import("std");
const Allocator = std.mem.Allocator;

const preset_root = @import("preset");

/// Total number of data columns (128 on mainnet).
pub const NUMBER_OF_COLUMNS: u64 = preset_root.NUMBER_OF_COLUMNS;

/// Minimum fraction of columns needed for reconstruction (50%).
pub const RECONSTRUCTION_THRESHOLD: u64 = NUMBER_OF_COLUMNS / 2;

/// Root type (32-byte hash).
pub const Root = [32]u8;

/// Per-block column tracking state.
pub const ColumnState = struct {
    /// Bitset tracking which columns have been received.
    received: std.StaticBitSet(NUMBER_OF_COLUMNS),
    /// Bitset tracking which columns have been cell-proof verified.
    verified: std.StaticBitSet(NUMBER_OF_COLUMNS),
    /// Slot of the block (for pruning).
    slot: u64,

    pub fn init(slot: u64) ColumnState {
        return .{
            .received = std.StaticBitSet(NUMBER_OF_COLUMNS).initEmpty(),
            .verified = std.StaticBitSet(NUMBER_OF_COLUMNS).initEmpty(),
            .slot = slot,
        };
    }

    /// Count of total received columns.
    pub fn receivedCount(self: *const ColumnState) u64 {
        var count: u64 = 0;
        for (0..NUMBER_OF_COLUMNS) |i| {
            if (self.received.isSet(i)) count += 1;
        }
        return count;
    }

    /// Whether ≥50% of columns have been received (enough for reconstruction).
    pub fn canReconstruct(self: *const ColumnState) bool {
        return self.receivedCount() >= RECONSTRUCTION_THRESHOLD;
    }
};

/// Tracks data column receipt and verification across multiple blocks.
///
/// Used by the DataAvailabilityManager to determine when a block's
/// custody columns are complete or when reconstruction is possible.
pub const ColumnTracker = struct {
    allocator: Allocator,

    /// Map: block_root → ColumnState
    tracking: std.AutoHashMap(Root, ColumnState),

    /// Our custody column set (sorted).
    custody_columns: []const u64,

    pub fn init(allocator: Allocator, custody_columns: []const u64) ColumnTracker {
        return .{
            .allocator = allocator,
            .tracking = std.AutoHashMap(Root, ColumnState).init(allocator),
            .custody_columns = custody_columns,
        };
    }

    pub fn deinit(self: *ColumnTracker) void {
        self.tracking.deinit();
    }

    /// Register a new block for column tracking.
    pub fn onBlock(self: *ColumnTracker, block_root: Root, slot: u64) void {
        const gop = self.tracking.getOrPut(block_root) catch return;
        if (!gop.found_existing) {
            gop.value_ptr.* = ColumnState.init(slot);
        }
    }

    /// Mark a column as received for a block.
    pub fn onColumn(self: *ColumnTracker, block_root: Root, column_index: u64) void {
        if (self.tracking.getPtr(block_root)) |state| {
            if (column_index < NUMBER_OF_COLUMNS) {
                state.received.set(column_index);
            }
        }
    }

    /// Mark a column as cell-proof verified.
    pub fn markVerified(self: *ColumnTracker, block_root: Root, column_index: u64) void {
        if (self.tracking.getPtr(block_root)) |state| {
            if (column_index < NUMBER_OF_COLUMNS) {
                state.verified.set(column_index);
            }
        }
    }

    /// Check if ALL custody columns have been received for a block.
    pub fn custodyComplete(self: *const ColumnTracker, block_root: Root) bool {
        const state = self.tracking.get(block_root) orelse return false;
        for (self.custody_columns) |col| {
            if (!state.received.isSet(col)) return false;
        }
        return true;
    }

    /// Get the custody column indices that have NOT been received.
    /// Caller owns the returned slice.
    pub fn getMissingCustody(self: *const ColumnTracker, allocator: Allocator, block_root: Root) ![]u64 {
        const state = self.tracking.get(block_root) orelse {
            // If block is not tracked, all custody columns are missing.
            const result = try allocator.alloc(u64, self.custody_columns.len);
            @memcpy(result, self.custody_columns);
            return result;
        };

        // Count missing first.
        var missing_count: usize = 0;
        for (self.custody_columns) |col| {
            if (!state.received.isSet(col)) missing_count += 1;
        }

        const result = try allocator.alloc(u64, missing_count);
        var idx: usize = 0;
        for (self.custody_columns) |col| {
            if (!state.received.isSet(col)) {
                result[idx] = col;
                idx += 1;
            }
        }
        return result;
    }

    /// Check if ≥50% of ALL columns (not just custody) have been received.
    /// This means reconstruction of missing columns is possible.
    pub fn canReconstruct(self: *const ColumnTracker, block_root: Root) bool {
        const state = self.tracking.get(block_root) orelse return false;
        return state.canReconstruct();
    }

    /// Get column state for a block, if tracked.
    pub fn getState(self: *const ColumnTracker, block_root: Root) ?ColumnState {
        return self.tracking.get(block_root);
    }

    /// Remove a specific block from tracking.
    pub fn remove(self: *ColumnTracker, block_root: Root) void {
        _ = self.tracking.remove(block_root);
    }

    /// Prune all entries with slot < min_slot.
    pub fn prune(self: *ColumnTracker, min_slot: u64) void {
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
    pub fn count(self: *const ColumnTracker) usize {
        return self.tracking.count();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ColumnTracker: custody completion" {
    const allocator = std.testing.allocator;

    const custody = [_]u64{ 10, 20, 30, 40 };
    var tracker = ColumnTracker.init(allocator, &custody);
    defer tracker.deinit();

    const root = [_]u8{0xAA} ** 32;
    tracker.onBlock(root, 100);

    try std.testing.expect(!tracker.custodyComplete(root));

    tracker.onColumn(root, 10);
    tracker.onColumn(root, 20);
    tracker.onColumn(root, 30);
    try std.testing.expect(!tracker.custodyComplete(root));

    tracker.onColumn(root, 40);
    try std.testing.expect(tracker.custodyComplete(root));
}

test "ColumnTracker: non-custody columns don't affect custody completion" {
    const allocator = std.testing.allocator;

    const custody = [_]u64{ 5, 15 };
    var tracker = ColumnTracker.init(allocator, &custody);
    defer tracker.deinit();

    const root = [_]u8{0xBB} ** 32;
    tracker.onBlock(root, 50);

    for (0..NUMBER_OF_COLUMNS) |i| {
        if (i != 5 and i != 15) {
            tracker.onColumn(root, @intCast(i));
        }
    }
    try std.testing.expect(!tracker.custodyComplete(root));
}

test "ColumnTracker: reconstruction threshold" {
    const allocator = std.testing.allocator;

    const custody = [_]u64{0};
    var tracker = ColumnTracker.init(allocator, &custody);
    defer tracker.deinit();

    const root = [_]u8{0xCC} ** 32;
    tracker.onBlock(root, 100);

    for (0..RECONSTRUCTION_THRESHOLD - 1) |i| {
        tracker.onColumn(root, @intCast(i));
    }
    try std.testing.expect(!tracker.canReconstruct(root));

    tracker.onColumn(root, @intCast(RECONSTRUCTION_THRESHOLD - 1));
    try std.testing.expect(tracker.canReconstruct(root));
}

test "ColumnTracker: getMissingCustody" {
    const allocator = std.testing.allocator;

    const custody = [_]u64{ 3, 7, 11 };
    var tracker = ColumnTracker.init(allocator, &custody);
    defer tracker.deinit();

    const root = [_]u8{0xDD} ** 32;
    tracker.onBlock(root, 200);

    tracker.onColumn(root, 7);

    const missing = try tracker.getMissingCustody(allocator, root);
    defer allocator.free(missing);

    try std.testing.expectEqual(@as(usize, 2), missing.len);
    try std.testing.expectEqual(@as(u64, 3), missing[0]);
    try std.testing.expectEqual(@as(u64, 11), missing[1]);
}

test "ColumnTracker: prune old entries" {
    const allocator = std.testing.allocator;

    const custody = [_]u64{0};
    var tracker = ColumnTracker.init(allocator, &custody);
    defer tracker.deinit();

    tracker.onBlock([_]u8{0x01} ** 32, 10);
    tracker.onBlock([_]u8{0x02} ** 32, 100);
    tracker.onBlock([_]u8{0x03} ** 32, 200);

    try std.testing.expectEqual(@as(usize, 3), tracker.count());

    tracker.prune(100);

    try std.testing.expectEqual(@as(usize, 2), tracker.count());
}

test "ColumnTracker: unknown block returns all custody as missing" {
    const allocator = std.testing.allocator;

    const custody = [_]u64{ 1, 2, 3 };
    var tracker = ColumnTracker.init(allocator, &custody);
    defer tracker.deinit();

    const root = [_]u8{0xEE} ** 32;
    const missing = try tracker.getMissingCustody(allocator, root);
    defer allocator.free(missing);

    try std.testing.expectEqual(@as(usize, 3), missing.len);
}
