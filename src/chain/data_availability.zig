//! Data Availability Manager — central coordinator for DA in the block pipeline.
//!
//! Ties together blob tracking (Deneb), column tracking (Fulu/PeerDAS),
//! KZG verification, and column reconstruction into a unified DA layer.
//!
//! The block import pipeline consults the DA manager before accepting a
//! block. If DA is incomplete, the block is quarantined until its data
//! arrives (via gossip or req/resp), at which point the DA manager
//! notifies the chain to retry import.
//!
//! Architecture:
//!   Gossip/ReqResp → DA Manager → {BlobTracker, ColumnTracker}
//!       ↓                              ↓
//!   Block pipeline ← checkBlockDataAvailability()
//!
//! Reference:
//!   Lodestar chain/blocks/verifyBlocksDataAvailability.ts
//!   Lodestar chain/seenCache/seenGossipBlockInput.ts
//!   consensus-specs/specs/deneb/fork-choice.md#is_data_available
//!   consensus-specs/specs/fulu/das-core.md

const std = @import("std");
const Allocator = std.mem.Allocator;

const ForkSeq = @import("config").ForkSeq;
const preset = @import("preset").preset;

const blob_tracker_mod = @import("blob_tracker.zig");
const BlobTracker = blob_tracker_mod.BlobTracker;

const column_tracker_mod = @import("column_tracker.zig");
const ColumnTracker = column_tracker_mod.ColumnTracker;
const NUMBER_OF_COLUMNS = column_tracker_mod.NUMBER_OF_COLUMNS;

/// Root type.
pub const Root = [32]u8;

/// Data availability status for a block.
pub const DaStatus = enum {
    /// All data present and verified — block can proceed through pipeline.
    available,
    /// Pre-Deneb block — no DA required.
    not_required,
    /// Some blobs not yet received (Deneb).
    missing_blobs,
    /// Some custody columns not yet received (Fulu/PeerDAS).
    missing_columns,
    /// Enough columns received for erasure recovery (≥50%).
    reconstruction_possible,
};

/// DA check result with additional context.
pub const DaCheckResult = struct {
    status: DaStatus,
    /// Number of missing items (blobs or custody columns).
    missing_count: u32,
};

/// Configuration values the DA manager needs.
pub const DaConfig = struct {
    /// MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS from ChainConfig.
    min_epochs_for_blob_sidecars_requests: u64,
};

/// Callbacks for DA events (block becoming available, etc.).
pub const DaEventCallback = *const fn (block_root: Root) void;

/// Central data availability coordinator.
///
/// Owns blob and column trackers and provides the interface for:
/// - Checking DA status during block import
/// - Tracking received blobs/columns
/// - Triggering reconstruction
/// - Pruning old data
pub const DataAvailabilityManager = struct {
    allocator: Allocator,
    da_config: DaConfig,

    /// Blob tracker (Deneb).
    blob_tracker: BlobTracker,

    /// Column tracker (Fulu/PeerDAS).
    column_tracker: ColumnTracker,

    /// Callback when a block transitions to DA-available.
    on_available: ?DaEventCallback,

    /// Blocks pending DA completion: block_root → slot.
    /// When DA becomes complete, these are signaled for reprocessing.
    pending_blocks: std.AutoHashMap(Root, u64),

    pub fn init(
        allocator: Allocator,
        da_config: DaConfig,
        custody_columns: []const u64,
    ) DataAvailabilityManager {
        return .{
            .allocator = allocator,
            .da_config = da_config,
            .blob_tracker = BlobTracker.init(allocator),
            .column_tracker = ColumnTracker.init(allocator, custody_columns),
            .on_available = null,
            .pending_blocks = std.AutoHashMap(Root, u64).init(allocator),
        };
    }

    pub fn deinit(self: *DataAvailabilityManager) void {
        self.blob_tracker.deinit();
        self.column_tracker.deinit();
        self.pending_blocks.deinit();
    }

    /// Check data availability for a block.
    ///
    /// Determines whether a block's associated data (blobs for Deneb,
    /// columns for Fulu) is fully available.
    ///
    /// `fork` indicates which fork the block belongs to.
    /// `blob_commitment_count` is the number of blob_kzg_commitments in the block body.
    pub fn checkBlockDataAvailability(
        self: *DataAvailabilityManager,
        block_root: Root,
        slot: u64,
        fork: ForkSeq,
        blob_commitment_count: u32,
    ) DaCheckResult {
        // Pre-Deneb: no DA required.
        if (fork.lt(.deneb)) {
            return .{ .status = .not_required, .missing_count = 0 };
        }

        // No blob commitments → trivially available.
        if (blob_commitment_count == 0) {
            return .{ .status = .available, .missing_count = 0 };
        }

        // Fulu (PeerDAS): check column availability.
        if (fork.gte(.fulu)) {
            return self.checkColumnAvailability(block_root, slot);
        }

        // Deneb/Electra: check blob availability.
        return self.checkBlobAvailability(block_root, slot, blob_commitment_count);
    }

    fn checkBlobAvailability(
        self: *DataAvailabilityManager,
        block_root: Root,
        slot: u64,
        blob_commitment_count: u32,
    ) DaCheckResult {
        // Ensure tracking is initialized.
        self.blob_tracker.onBlock(block_root, blob_commitment_count, slot);

        if (self.blob_tracker.isComplete(block_root)) {
            return .{ .status = .available, .missing_count = 0 };
        }

        const state = self.blob_tracker.getState(block_root).?;
        const received = state.receivedCount();
        return .{
            .status = .missing_blobs,
            .missing_count = blob_commitment_count - received,
        };
    }

    fn checkColumnAvailability(
        self: *DataAvailabilityManager,
        block_root: Root,
        slot: u64,
    ) DaCheckResult {
        self.column_tracker.onBlock(block_root, slot);

        if (self.column_tracker.custodyComplete(block_root)) {
            return .{ .status = .available, .missing_count = 0 };
        }

        // Check if reconstruction is possible.
        if (self.column_tracker.canReconstruct(block_root)) {
            return .{ .status = .reconstruction_possible, .missing_count = 0 };
        }

        // Count missing custody columns.
        const missing = self.column_tracker.getMissingCustody(self.allocator, block_root) catch
            return .{ .status = .missing_columns, .missing_count = @intCast(self.column_tracker.custody_columns.len) };
        defer self.allocator.free(missing);

        return .{
            .status = .missing_columns,
            .missing_count = @intCast(missing.len),
        };
    }

    // -- Event handlers for received data ------------------------------------

    /// Called when a blob sidecar is received (gossip or req/resp).
    /// Returns true if this blob completed the block's DA.
    pub fn onBlobSidecar(
        self: *DataAvailabilityManager,
        block_root: Root,
        blob_index: u64,
        slot: u64,
    ) bool {
        _ = slot;
        self.blob_tracker.onBlob(block_root, blob_index);

        if (self.blob_tracker.isComplete(block_root)) {
            self.onBlockAvailable(block_root);
            return true;
        }
        return false;
    }

    /// Called when a data column sidecar is received (gossip or req/resp).
    /// Returns true if this column completed the block's DA (custody complete).
    pub fn onDataColumnSidecar(
        self: *DataAvailabilityManager,
        block_root: Root,
        column_index: u64,
        slot: u64,
    ) bool {
        self.column_tracker.onBlock(block_root, slot);
        self.column_tracker.onColumn(block_root, column_index);

        if (self.column_tracker.custodyComplete(block_root) or self.column_tracker.canReconstruct(block_root)) {
            self.onBlockAvailable(block_root);
            return true;
        }
        return false;
    }

    /// Mark a block as pending DA completion.
    /// When DA becomes available, the on_available callback will fire.
    pub fn markPending(self: *DataAvailabilityManager, block_root: Root, slot: u64) !void {
        try self.pending_blocks.put(block_root, slot);
    }

    /// Check if a block is pending DA.
    pub fn isPending(self: *const DataAvailabilityManager, block_root: Root) bool {
        return self.pending_blocks.contains(block_root);
    }

    fn onBlockAvailable(self: *DataAvailabilityManager, block_root: Root) void {
        _ = self.pending_blocks.remove(block_root);
        if (self.on_available) |cb| {
            cb(block_root);
        }
    }

    // -- Blob/column state queries ------------------------------------------

    /// Get missing blob indices for a block.
    pub fn getMissingBlobs(self: *const DataAvailabilityManager, allocator: Allocator, block_root: Root) ![]u64 {
        return self.blob_tracker.getMissing(allocator, block_root);
    }

    /// Get missing custody column indices for a block.
    pub fn getMissingColumns(self: *const DataAvailabilityManager, allocator: Allocator, block_root: Root) ![]u64 {
        return self.column_tracker.getMissingCustody(allocator, block_root);
    }

    /// Check if reconstruction is possible for a block.
    pub fn canReconstruct(self: *const DataAvailabilityManager, block_root: Root) bool {
        return self.column_tracker.canReconstruct(block_root);
    }

    // -- Pruning -------------------------------------------------------------

    /// Prune old tracking data below the given slot.
    ///
    /// Should be called on finalization: anything older than
    /// finalized_slot - DA_WINDOW_SLOTS can be safely removed.
    pub fn pruneOldData(self: *DataAvailabilityManager, min_slot: u64) void {
        self.blob_tracker.prune(min_slot);
        self.column_tracker.prune(min_slot);

        // Also prune pending blocks.
        var to_remove: [256]Root = undefined;
        var remove_count: usize = 0;

        var it = self.pending_blocks.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* < min_slot) {
                if (remove_count < to_remove.len) {
                    to_remove[remove_count] = entry.key_ptr.*;
                    remove_count += 1;
                }
            }
        }

        for (to_remove[0..remove_count]) |root| {
            _ = self.pending_blocks.remove(root);
        }
    }

    /// Compute the minimum slot for the DA window.
    ///
    /// Data older than this can be pruned.
    pub fn daWindowMinSlot(self: *const DataAvailabilityManager, current_slot: u64) u64 {
        const window_slots = self.da_config.min_epochs_for_blob_sidecars_requests * preset.SLOTS_PER_EPOCH;
        if (current_slot > window_slots) {
            return current_slot - window_slots;
        }
        return 0;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_config = DaConfig{
    .min_epochs_for_blob_sidecars_requests = 4096,
};

test "DataAvailabilityManager: pre-Deneb returns not_required" {
    const allocator = std.testing.allocator;
    const custody = [_]u64{0};

    var dam = DataAvailabilityManager.init(allocator, test_config, &custody);
    defer dam.deinit();

    const root = [_]u8{0xAA} ** 32;
    const result = dam.checkBlockDataAvailability(root, 100, .capella, 0);
    try std.testing.expectEqual(DaStatus.not_required, result.status);
}

test "DataAvailabilityManager: Deneb with zero commitments is available" {
    const allocator = std.testing.allocator;
    const custody = [_]u64{0};

    var dam = DataAvailabilityManager.init(allocator, test_config, &custody);
    defer dam.deinit();

    const root = [_]u8{0xBB} ** 32;
    const result = dam.checkBlockDataAvailability(root, 100, .deneb, 0);
    try std.testing.expectEqual(DaStatus.available, result.status);
}

test "DataAvailabilityManager: Deneb blob tracking" {
    const allocator = std.testing.allocator;
    const custody = [_]u64{0};

    var dam = DataAvailabilityManager.init(allocator, test_config, &custody);
    defer dam.deinit();

    const root = [_]u8{0xCC} ** 32;

    // Block with 3 blobs — not available initially.
    const r1 = dam.checkBlockDataAvailability(root, 100, .deneb, 3);
    try std.testing.expectEqual(DaStatus.missing_blobs, r1.status);
    try std.testing.expectEqual(@as(u32, 3), r1.missing_count);

    // Receive blobs.
    try std.testing.expect(!dam.onBlobSidecar(root, 0, 100));
    try std.testing.expect(!dam.onBlobSidecar(root, 1, 100));
    try std.testing.expect(dam.onBlobSidecar(root, 2, 100)); // completes DA

    // Now available.
    const r2 = dam.checkBlockDataAvailability(root, 100, .deneb, 3);
    try std.testing.expectEqual(DaStatus.available, r2.status);
}

test "DataAvailabilityManager: Fulu column tracking" {
    const allocator = std.testing.allocator;
    const custody = [_]u64{ 5, 10, 15 };

    var dam = DataAvailabilityManager.init(allocator, test_config, &custody);
    defer dam.deinit();

    const root = [_]u8{0xDD} ** 32;

    // Block — missing columns initially.
    const r1 = dam.checkBlockDataAvailability(root, 200, .fulu, 1);
    try std.testing.expectEqual(DaStatus.missing_columns, r1.status);
    try std.testing.expectEqual(@as(u32, 3), r1.missing_count);

    // Receive custody columns.
    try std.testing.expect(!dam.onDataColumnSidecar(root, 5, 200));
    try std.testing.expect(!dam.onDataColumnSidecar(root, 10, 200));
    try std.testing.expect(dam.onDataColumnSidecar(root, 15, 200)); // completes

    const r2 = dam.checkBlockDataAvailability(root, 200, .fulu, 1);
    try std.testing.expectEqual(DaStatus.available, r2.status);
}

test "DataAvailabilityManager: Fulu reconstruction also completes availability" {
    const allocator = std.testing.allocator;
    const custody = [_]u64{ 100, 110 };

    var dam = DataAvailabilityManager.init(allocator, test_config, &custody);
    defer dam.deinit();

    const root = [_]u8{0xDE} ** 32;

    const r1 = dam.checkBlockDataAvailability(root, 220, .fulu, 1);
    try std.testing.expectEqual(DaStatus.missing_columns, r1.status);

    var i: u64 = 0;
    while (i < NUMBER_OF_COLUMNS / 2) : (i += 1) {
        const completed = dam.onDataColumnSidecar(root, i, 220);
        if (i + 1 < NUMBER_OF_COLUMNS / 2) {
            try std.testing.expect(!completed);
        } else {
            try std.testing.expect(completed);
        }
    }

    const r2 = dam.checkBlockDataAvailability(root, 220, .fulu, 1);
    try std.testing.expectEqual(DaStatus.reconstruction_possible, r2.status);
}

test "DataAvailabilityManager: pending blocks cleared on availability" {
    const allocator = std.testing.allocator;
    const custody = [_]u64{0};

    var dam = DataAvailabilityManager.init(allocator, test_config, &custody);
    defer dam.deinit();

    const root = [_]u8{0xEE} ** 32;

    // Register block expecting 1 blob, mark pending.
    dam.blob_tracker.onBlock(root, 1, 100);
    try dam.markPending(root, 100);
    try std.testing.expect(dam.isPending(root));

    // Receive the blob → DA available → pending cleared.
    _ = dam.onBlobSidecar(root, 0, 100);
    try std.testing.expect(!dam.isPending(root));
}

test "DataAvailabilityManager: prune old data" {
    const allocator = std.testing.allocator;
    const custody = [_]u64{0};

    var dam = DataAvailabilityManager.init(allocator, test_config, &custody);
    defer dam.deinit();

    const old_root = [_]u8{0x01} ** 32;
    const new_root = [_]u8{0x02} ** 32;

    dam.blob_tracker.onBlock(old_root, 2, 10);
    dam.blob_tracker.onBlock(new_root, 2, 100);
    try dam.markPending(old_root, 10);

    dam.pruneOldData(50);

    try std.testing.expect(dam.blob_tracker.getState(old_root) == null);
    try std.testing.expect(dam.blob_tracker.getState(new_root) != null);
    try std.testing.expect(!dam.isPending(old_root));
}

test "DataAvailabilityManager: DA window calculation" {
    const allocator = std.testing.allocator;
    const custody = [_]u64{0};

    var dam = DataAvailabilityManager.init(allocator, test_config, &custody);
    defer dam.deinit();

    const window = test_config.min_epochs_for_blob_sidecars_requests * preset.SLOTS_PER_EPOCH;
    const current_slot: u64 = 200000;
    const min_slot = dam.daWindowMinSlot(current_slot);

    try std.testing.expectEqual(current_slot - window, min_slot);
}
