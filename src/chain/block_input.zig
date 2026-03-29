//! GossipBlockInput — assembles blocks with their associated data (blobs/columns).
//!
//! On gossip, blocks and their blobs/columns arrive independently and
//! potentially out of order. This module provides the async waiting layer:
//!
//!   1. Block arrives → check if data needed → wait with timeout
//!   2. Blob/column arrives → check if it completes a pending block
//!   3. Timeout → mark data-unavailable
//!
//! Completion signaling uses `std.Io.Event` — a one-shot futex-based
//! primitive that integrates with the Io event loop. For mutual exclusion
//! of internal state, the module assumes single-fiber access (consistent
//! with the BeaconProcessor model). If multi-fiber access is needed later,
//! callers should serialize via `Io.Mutex`.
//!
//! See BLOCK_INPUT_DESIGN.md for design rationale.
//!
//! Architecture:
//! ```
//!   gossip block  ──▶ GossipBlockInput.onBlock()            ──▶ AvailableBlockInput or null
//!   gossip blob   ──▶ GossipBlockInput.onBlobSidecar()      ──▶ AvailableBlockInput if complete
//!   gossip column ──▶ GossipBlockInput.onDataColumnSidecar() ──▶ AvailableBlockInput if complete
//! ```
//!
//! Reference:
//!   - Lodestar chain/blocks/blockInput.ts
//!   - consensus-specs/specs/deneb/p2p-interface.md
//!   - consensus-specs/specs/fulu/das-core.md

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const consensus_types = @import("consensus_types");
const fork_types = @import("fork_types");
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const preset_root = @import("preset");

const blob_tracker_mod = @import("blob_tracker.zig");
const MAX_BLOBS_PER_BLOCK = blob_tracker_mod.MAX_BLOBS_PER_BLOCK;

const column_tracker_mod = @import("column_tracker.zig");
const NUMBER_OF_COLUMNS = column_tracker_mod.NUMBER_OF_COLUMNS;

const pipeline_types = @import("blocks/types.zig");
const BlockSource = pipeline_types.BlockSource;

const log = std.log.scoped(.block_input);

/// Root type (32-byte hash).
pub const Root = [32]u8;

/// Default data timeout: 6 seconds (half a slot).
/// Matches TS Lodestar's BLOCK_INPUT_TIMEOUT_MS = 6000.
pub const DEFAULT_DATA_TIMEOUT_NS: u64 = 6 * std.time.ns_per_s;

/// Maximum number of pending blocks tracked simultaneously.
pub const MAX_PENDING_BLOCKS: u32 = 32;

// ---------------------------------------------------------------------------
// AvailableBlockInput — a block with all data ready for import
// ---------------------------------------------------------------------------

/// A fully assembled block input ready for the import pipeline.
///
/// Contains the block and metadata about its data availability.
/// Blobs and columns are tracked by the BlobTracker/ColumnTracker;
/// this struct confirms that tracking is complete.
pub const AvailableBlockInput = struct {
    /// The signed beacon block.
    block: AnySignedBeaconBlock,
    /// Where the block came from.
    source: BlockSource,
    /// Block root (hash-tree-root of the block).
    block_root: Root,
    /// Slot of the block.
    slot: u64,
    /// Number of blob sidecars associated with this block.
    blob_count: u32,
    /// Whether this block has associated data columns (Fulu/PeerDAS).
    has_columns: bool,
};

// ---------------------------------------------------------------------------
// PendingBlock — internal state for a block awaiting data
// ---------------------------------------------------------------------------

/// Internal tracking for a block whose data hasn't fully arrived yet.
pub const PendingBlock = struct {
    /// The signed beacon block.
    block: AnySignedBeaconBlock,
    /// Block root.
    block_root: Root,
    /// Where the block came from.
    source: BlockSource,
    /// Slot of the block.
    slot: u64,
    /// Number of blobs expected (from blob_kzg_commitments length).
    expected_blobs: u32,
    /// Whether we need custody columns (Fulu/PeerDAS).
    needs_columns: bool,
    /// Bitset of received blob indices.
    received_blobs: std.StaticBitSet(MAX_BLOBS_PER_BLOCK),
    /// Bitset of received custody column indices.
    received_columns: std.StaticBitSet(NUMBER_OF_COLUMNS),
    /// Custody columns this node is responsible for.
    custody_columns: []const u64,
    /// Timestamp when this pending block was created (monotonic ns).
    created_at_ns: i128,
    /// Completion signal — set when all data arrives.
    /// Uses std.Io.Event: one-shot futex-based, supports waitTimeout.
    completion: Io.Event,

    /// Check if all required data has been received.
    pub fn isComplete(self: *const PendingBlock) bool {
        // Check blobs
        if (self.expected_blobs > 0) {
            for (0..self.expected_blobs) |i| {
                if (!self.received_blobs.isSet(i)) return false;
            }
        }
        // Check custody columns
        if (self.needs_columns) {
            for (self.custody_columns) |col_idx| {
                if (!self.received_columns.isSet(col_idx)) return false;
            }
        }
        return true;
    }

    /// Convert to an AvailableBlockInput.
    pub fn toAvailable(self: *const PendingBlock) AvailableBlockInput {
        return .{
            .block = self.block,
            .source = self.source,
            .block_root = self.block_root,
            .slot = self.slot,
            .blob_count = self.expected_blobs,
            .has_columns = self.needs_columns,
        };
    }

    /// Count of missing blobs.
    pub fn missingBlobCount(self: *const PendingBlock) u32 {
        if (self.expected_blobs == 0) return 0;
        var count: u32 = 0;
        for (0..self.expected_blobs) |i| {
            if (!self.received_blobs.isSet(i)) count += 1;
        }
        return count;
    }

    /// Count of missing custody columns.
    pub fn missingColumnCount(self: *const PendingBlock) u32 {
        if (!self.needs_columns) return 0;
        var count: u32 = 0;
        for (self.custody_columns) |col_idx| {
            if (!self.received_columns.isSet(col_idx)) count += 1;
        }
        return count;
    }
};

// ---------------------------------------------------------------------------
// WaitResult — outcome of waiting for block data
// ---------------------------------------------------------------------------

/// Result of waiting for a pending block's data.
pub const WaitResult = union(enum) {
    /// All data arrived — block is available.
    available: AvailableBlockInput,
    /// Timed out waiting for data.
    timed_out: Root,
    /// Block was not found in pending set (already resolved or unknown).
    not_found,
};

// ---------------------------------------------------------------------------
// GossipBlockInput — the manager
// ---------------------------------------------------------------------------

/// Assembles blocks with their associated data from gossip.
///
/// Designed for single-fiber access from the BeaconProcessor loop.
/// If multi-fiber access is needed, callers must serialize externally.
pub const GossipBlockInput = struct {
    allocator: Allocator,

    /// Pending blocks keyed by block root.
    pending: std.AutoHashMap(Root, *PendingBlock),

    /// Data timeout in nanoseconds.
    data_timeout_ns: u64,

    /// Custody columns for this node (PeerDAS).
    custody_columns: []const u64,

    /// Metrics.
    blocks_immediately_available: u64,
    blocks_completed_by_data: u64,
    blocks_timed_out: u64,

    pub fn init(
        allocator: Allocator,
        custody_columns: []const u64,
        data_timeout_ns: ?u64,
    ) GossipBlockInput {
        return .{
            .allocator = allocator,
            .pending = std.AutoHashMap(Root, *PendingBlock).init(allocator),
            .data_timeout_ns = data_timeout_ns orelse DEFAULT_DATA_TIMEOUT_NS,
            .custody_columns = custody_columns,
            .blocks_immediately_available = 0,
            .blocks_completed_by_data = 0,
            .blocks_timed_out = 0,
        };
    }

    pub fn deinit(self: *GossipBlockInput) void {
        var it = self.pending.valueIterator();
        while (it.next()) |pending_ptr| {
            self.allocator.destroy(pending_ptr.*);
        }
        self.pending.deinit();
    }

    /// A block arrived from gossip.
    ///
    /// If all required data is already available (0 blobs, pre-Deneb, etc.),
    /// returns the `AvailableBlockInput` immediately.
    ///
    /// If data is needed, creates a pending entry and returns `null`.
    /// The caller should then call `waitForBlock()` to wait with timeout,
    /// or poll via `getAvailable()`.
    pub fn onBlock(
        self: *GossipBlockInput,
        block: AnySignedBeaconBlock,
        block_root: Root,
        slot: u64,
        source: BlockSource,
        expected_blobs: u32,
        needs_columns: bool,
        now_ns: i128,
    ) !?AvailableBlockInput {
        // If no data needed, immediately available.
        if (expected_blobs == 0 and !needs_columns) {
            self.blocks_immediately_available += 1;
            return AvailableBlockInput{
                .block = block,
                .source = source,
                .block_root = block_root,
                .slot = slot,
                .blob_count = 0,
                .has_columns = false,
            };
        }

        // Check if we already have a pending entry (block received twice).
        if (self.pending.get(block_root)) |existing| {
            // Check if it was completed by data arriving before the block.
            if (existing.isComplete()) {
                const result = existing.toAvailable();
                _ = self.pending.remove(block_root);
                self.allocator.destroy(existing);
                self.blocks_completed_by_data += 1;
                return result;
            }
            // Already pending, return null (caller should wait).
            return null;
        }

        // Create pending entry.
        const pending = try self.allocator.create(PendingBlock);
        pending.* = .{
            .block = block,
            .block_root = block_root,
            .source = source,
            .slot = slot,
            .expected_blobs = expected_blobs,
            .needs_columns = needs_columns,
            .received_blobs = std.StaticBitSet(MAX_BLOBS_PER_BLOCK).initEmpty(),
            .received_columns = std.StaticBitSet(NUMBER_OF_COLUMNS).initEmpty(),
            .custody_columns = self.custody_columns,
            .created_at_ns = now_ns,
            .completion = .unset,
        };

        try self.pending.put(block_root, pending);

        log.debug("block pending data slot={d} blobs={d} columns={}", .{
            slot,
            expected_blobs,
            needs_columns,
        });

        return null;
    }

    /// A blob sidecar arrived from gossip.
    ///
    /// If this blob completes a pending block, returns the `AvailableBlockInput`
    /// and signals the completion event.
    ///
    /// Returns `null` if:
    /// - No pending block for this root (blob arrived before block)
    /// - Block still needs more data
    pub fn onBlobSidecar(
        self: *GossipBlockInput,
        block_root: Root,
        blob_index: u64,
        io: ?Io,
    ) ?AvailableBlockInput {
        const pending = self.pending.get(block_root) orelse return null;

        if (blob_index >= MAX_BLOBS_PER_BLOCK) return null;
        pending.received_blobs.set(blob_index);

        if (pending.isComplete()) {
            // Signal any waiter.
            if (io) |io_ctx| {
                pending.completion.set(io_ctx);
            }
            self.blocks_completed_by_data += 1;
            log.debug("block data complete (blob) slot={d}", .{pending.slot});
            return pending.toAvailable();
        }

        return null;
    }

    /// A data column sidecar arrived from gossip.
    ///
    /// Same logic as `onBlobSidecar` but for PeerDAS columns.
    pub fn onDataColumnSidecar(
        self: *GossipBlockInput,
        block_root: Root,
        column_index: u64,
        io: ?Io,
    ) ?AvailableBlockInput {
        const pending = self.pending.get(block_root) orelse return null;

        if (column_index >= NUMBER_OF_COLUMNS) return null;
        pending.received_columns.set(column_index);

        if (pending.isComplete()) {
            if (io) |io_ctx| {
                pending.completion.set(io_ctx);
            }
            self.blocks_completed_by_data += 1;
            log.debug("block data complete (column) slot={d}", .{pending.slot});
            return pending.toAvailable();
        }

        return null;
    }

    /// Wait for a pending block's data to arrive, with timeout.
    ///
    /// This is the async integration point. The calling fiber suspends
    /// on the `Io.Event` until either:
    /// - All data arrives (event is set) → returns `.available`
    /// - Timeout expires → returns `.timed_out`
    /// - Block not found → returns `.not_found`
    ///
    /// **Requires `std.Io` context** — only callable from an Io fiber.
    /// After returning `.available` or `.timed_out`, the caller should
    /// call `resolve()` to remove the pending entry and get the result.
    pub fn waitForBlock(
        self: *GossipBlockInput,
        block_root: Root,
        io: Io,
    ) WaitResult {
        const pending = self.pending.get(block_root) orelse return .not_found;

        // Quick check: already complete?
        if (pending.isComplete()) {
            const result = pending.toAvailable();
            _ = self.pending.remove(block_root);
            self.allocator.destroy(pending);
            return .{ .available = result };
        }

        // Wait on the event with timeout.
        const timeout: Io.Timeout = .{
            .duration = .{
                .raw = .{ .nanoseconds = @intCast(self.data_timeout_ns) },
                .clock = .real,
            },
        };
        pending.completion.waitTimeout(io, timeout) catch |err| switch (err) {
            error.Timeout => {
                // Timed out — clean up.
                if (self.pending.fetchRemove(block_root)) |kv| {
                    self.allocator.destroy(kv.value);
                }
                self.blocks_timed_out += 1;
                log.debug("block data timeout slot={d}", .{pending.slot});
                return .{ .timed_out = block_root };
            },
            error.Canceled => {
                if (self.pending.fetchRemove(block_root)) |kv| {
                    self.allocator.destroy(kv.value);
                }
                return .{ .timed_out = block_root };
            },
        };

        // Event was set — data is complete.
        if (self.pending.fetchRemove(block_root)) |kv| {
            const result = kv.value.toAvailable();
            self.allocator.destroy(kv.value);
            return .{ .available = result };
        }
        return .not_found;
    }

    /// Check if a pending block is now complete and return it.
    ///
    /// Non-blocking alternative to `waitForBlock`. Returns null if the
    /// block is still pending or not found.
    pub fn getAvailable(
        self: *GossipBlockInput,
        block_root: Root,
    ) ?AvailableBlockInput {
        const pending = self.pending.get(block_root) orelse return null;
        if (!pending.isComplete()) return null;

        const result = pending.toAvailable();
        _ = self.pending.remove(block_root);
        self.allocator.destroy(pending);
        return result;
    }

    /// Remove and return roots of pending blocks that have timed out.
    ///
    /// Called periodically (e.g., every slot) to clean up stale entries
    /// that nobody is actively waiting on.
    pub fn pruneTimedOut(
        self: *GossipBlockInput,
        now_ns: i128,
        io: ?Io,
    ) ![]Root {
        var timed_out: std.ArrayListUnmanaged(Root) = .empty;
        errdefer timed_out.deinit(self.allocator);

        var to_remove: std.ArrayListUnmanaged(Root) = .empty;
        defer to_remove.deinit(self.allocator);

        var it = self.pending.iterator();
        while (it.next()) |entry| {
            const pending = entry.value_ptr.*;
            const age_ns = now_ns - pending.created_at_ns;
            if (age_ns > @as(i128, self.data_timeout_ns)) {
                try timed_out.append(self.allocator, entry.key_ptr.*);
                try to_remove.append(self.allocator, entry.key_ptr.*);
            }
        }

        for (to_remove.items) |root| {
            if (self.pending.fetchRemove(root)) |kv| {
                // Signal waiters so they don't hang forever.
                if (io) |io_ctx| {
                    kv.value.completion.set(io_ctx);
                }
                self.allocator.destroy(kv.value);
                self.blocks_timed_out += 1;
            }
        }

        return timed_out.toOwnedSlice(self.allocator);
    }

    /// Get the number of pending blocks.
    pub fn pendingCount(self: *const GossipBlockInput) usize {
        return self.pending.count();
    }

    /// Get a read-only reference to a pending block for inspection.
    pub fn getPending(self: *const GossipBlockInput, block_root: Root) ?*const PendingBlock {
        const ptr = self.pending.get(block_root) orelse return null;
        return ptr;
    }

    /// Remove a pending block (e.g., if imported via another path).
    pub fn removePending(self: *GossipBlockInput, block_root: Root) void {
        if (self.pending.fetchRemove(block_root)) |kv| {
            self.allocator.destroy(kv.value);
        }
    }

    /// Assemble a block input from range sync (blocks + blobs fetched together).
    ///
    /// No waiting needed — data is always available from range sync.
    pub fn assembleFromRangeSync(
        block: AnySignedBeaconBlock,
        block_root: Root,
        slot: u64,
        blob_count: u32,
    ) AvailableBlockInput {
        return .{
            .block = block,
            .source = .range_sync,
            .block_root = block_root,
            .slot = slot,
            .blob_count = blob_count,
            .has_columns = false,
        };
    }

    /// Assemble a block input for pre-Deneb blocks or blocks with no data requirements.
    pub fn assembleNoData(
        block: AnySignedBeaconBlock,
        block_root: Root,
        slot: u64,
        source: BlockSource,
    ) AvailableBlockInput {
        return .{
            .block = block,
            .source = source,
            .block_root = block_root,
            .slot = slot,
            .blob_count = 0,
            .has_columns = false,
        };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "GossipBlockInput: block with no data is immediately available" {
    const allocator = std.testing.allocator;
    var manager = GossipBlockInput.init(allocator, &.{}, null);
    defer manager.deinit();

    const root = [_]u8{0xAA} ** 32;
    const result = try manager.onBlock(
        undefined, // block not inspected in this path
        root,
        100,
        .gossip,
        0, // no blobs
        false, // no columns
        1000,
    );

    try std.testing.expect(result != null);
    try std.testing.expectEqual(root, result.?.block_root);
    try std.testing.expectEqual(@as(u64, 100), result.?.slot);
    try std.testing.expectEqual(@as(u32, 0), result.?.blob_count);
    try std.testing.expectEqual(@as(u64, 1), manager.blocks_immediately_available);
}

test "GossipBlockInput: block with blobs starts pending" {
    const allocator = std.testing.allocator;
    var manager = GossipBlockInput.init(allocator, &.{}, null);
    defer manager.deinit();

    const root = [_]u8{0xBB} ** 32;
    const result = try manager.onBlock(
        undefined,
        root,
        200,
        .gossip,
        3, // needs 3 blobs
        false,
        2000,
    );

    try std.testing.expect(result == null);
    try std.testing.expectEqual(@as(usize, 1), manager.pendingCount());
}

test "GossipBlockInput: blobs complete a pending block" {
    const allocator = std.testing.allocator;
    var manager = GossipBlockInput.init(allocator, &.{}, null);
    defer manager.deinit();

    const root = [_]u8{0xCC} ** 32;

    // Block arrives needing 2 blobs.
    _ = try manager.onBlock(undefined, root, 300, .gossip, 2, false, 3000);
    try std.testing.expectEqual(@as(usize, 1), manager.pendingCount());

    // First blob arrives — not complete yet.
    const r1 = manager.onBlobSidecar(root, 0, null);
    try std.testing.expect(r1 == null);

    // Second blob arrives — completes!
    const r2 = manager.onBlobSidecar(root, 1, null);
    try std.testing.expect(r2 != null);
    try std.testing.expectEqual(root, r2.?.block_root);
    try std.testing.expectEqual(@as(u32, 2), r2.?.blob_count);
}

test "GossipBlockInput: blob for unknown block returns null" {
    const allocator = std.testing.allocator;
    var manager = GossipBlockInput.init(allocator, &.{}, null);
    defer manager.deinit();

    const root = [_]u8{0xDD} ** 32;
    const result = manager.onBlobSidecar(root, 0, null);
    try std.testing.expect(result == null);
}

test "GossipBlockInput: column completes pending block" {
    const allocator = std.testing.allocator;
    const custody = [_]u64{ 5, 10, 20 };
    var manager = GossipBlockInput.init(allocator, &custody, null);
    defer manager.deinit();

    const root = [_]u8{0xEE} ** 32;

    // Block needing columns.
    _ = try manager.onBlock(undefined, root, 400, .gossip, 0, true, 4000);

    // Send columns for custody set.
    _ = manager.onDataColumnSidecar(root, 5, null);
    _ = manager.onDataColumnSidecar(root, 10, null);
    const result = manager.onDataColumnSidecar(root, 20, null);

    try std.testing.expect(result != null);
    try std.testing.expect(result.?.has_columns);
}

test "GossipBlockInput: prune timed out blocks" {
    const allocator = std.testing.allocator;
    var manager = GossipBlockInput.init(allocator, &.{}, 1_000_000_000); // 1s timeout
    defer manager.deinit();

    const root1 = [_]u8{0x11} ** 32;
    const root2 = [_]u8{0x22} ** 32;

    // Two pending blocks at different times.
    _ = try manager.onBlock(undefined, root1, 500, .gossip, 1, false, 0); // t=0
    _ = try manager.onBlock(undefined, root2, 501, .gossip, 1, false, 500_000_000); // t=0.5s

    try std.testing.expectEqual(@as(usize, 2), manager.pendingCount());

    // Prune at t=1.5s — root1 should timeout, root2 should not.
    const timed_out = try manager.pruneTimedOut(1_500_000_000, null);
    defer allocator.free(timed_out);

    try std.testing.expectEqual(@as(usize, 1), timed_out.len);
    try std.testing.expectEqual(root1, timed_out[0]);
    try std.testing.expectEqual(@as(usize, 1), manager.pendingCount());
}

test "GossipBlockInput: duplicate block returns null (already pending)" {
    const allocator = std.testing.allocator;
    var manager = GossipBlockInput.init(allocator, &.{}, null);
    defer manager.deinit();

    const root = [_]u8{0xFF} ** 32;

    // First block arrives.
    _ = try manager.onBlock(undefined, root, 600, .gossip, 2, false, 5000);
    // Same block again — should return null (already pending).
    const result = try manager.onBlock(undefined, root, 600, .gossip, 2, false, 5100);
    try std.testing.expect(result == null);
    try std.testing.expectEqual(@as(usize, 1), manager.pendingCount());
}

test "GossipBlockInput: out of bounds blob index ignored" {
    const allocator = std.testing.allocator;
    var manager = GossipBlockInput.init(allocator, &.{}, null);
    defer manager.deinit();

    const root = [_]u8{0xAB} ** 32;
    _ = try manager.onBlock(undefined, root, 700, .gossip, 2, false, 6000);

    // Blob index beyond MAX_BLOBS_PER_BLOCK — should be ignored.
    const result = manager.onBlobSidecar(root, MAX_BLOBS_PER_BLOCK + 1, null);
    try std.testing.expect(result == null);
}

test "GossipBlockInput: removePending cleans up" {
    const allocator = std.testing.allocator;
    var manager = GossipBlockInput.init(allocator, &.{}, null);
    defer manager.deinit();

    const root = [_]u8{0xCD} ** 32;
    _ = try manager.onBlock(undefined, root, 800, .gossip, 3, false, 7000);
    try std.testing.expectEqual(@as(usize, 1), manager.pendingCount());

    manager.removePending(root);
    try std.testing.expectEqual(@as(usize, 0), manager.pendingCount());
}

test "GossipBlockInput: assembleFromRangeSync creates available input" {
    const result = GossipBlockInput.assembleFromRangeSync(
        undefined,
        [_]u8{0x01} ** 32,
        1000,
        4,
    );
    try std.testing.expectEqual(BlockSource.range_sync, result.source);
    try std.testing.expectEqual(@as(u32, 4), result.blob_count);
    try std.testing.expectEqual(@as(u64, 1000), result.slot);
}

test "GossipBlockInput: assembleNoData creates available input" {
    const result = GossipBlockInput.assembleNoData(
        undefined,
        [_]u8{0x02} ** 32,
        2000,
        .api,
    );
    try std.testing.expectEqual(BlockSource.api, result.source);
    try std.testing.expectEqual(@as(u32, 0), result.blob_count);
    try std.testing.expect(!result.has_columns);
}

test "GossipBlockInput: multiple pending blocks with interleaved blobs" {
    const allocator = std.testing.allocator;
    var manager = GossipBlockInput.init(allocator, &.{}, null);
    defer manager.deinit();

    const root_a = [_]u8{0xA0} ** 32;
    const root_b = [_]u8{0xB0} ** 32;

    // Two blocks, each needing 2 blobs.
    _ = try manager.onBlock(undefined, root_a, 900, .gossip, 2, false, 8000);
    _ = try manager.onBlock(undefined, root_b, 901, .gossip, 2, false, 8100);
    try std.testing.expectEqual(@as(usize, 2), manager.pendingCount());

    // Interleaved blobs.
    _ = manager.onBlobSidecar(root_b, 0, null); // B blob 0
    _ = manager.onBlobSidecar(root_a, 0, null); // A blob 0

    // A blob 1 — completes A (returns available inline, but pending map keeps entry until resolve)
    const result_a = manager.onBlobSidecar(root_a, 1, null);
    try std.testing.expect(result_a != null);
    try std.testing.expectEqual(root_a, result_a.?.block_root);

    // Complete B.
    const result_b = manager.onBlobSidecar(root_b, 1, null);
    try std.testing.expect(result_b != null);
    try std.testing.expectEqual(root_b, result_b.?.block_root);
}

test "GossipBlockInput: block needing both blobs and columns" {
    const allocator = std.testing.allocator;
    const custody = [_]u64{3};
    var manager = GossipBlockInput.init(allocator, &custody, null);
    defer manager.deinit();

    const root = [_]u8{0xFC} ** 32;
    _ = try manager.onBlock(undefined, root, 1000, .gossip, 1, true, 9000);

    // Blob arrives but columns still missing.
    const r1 = manager.onBlobSidecar(root, 0, null);
    try std.testing.expect(r1 == null);

    // Column arrives — now complete.
    const r2 = manager.onDataColumnSidecar(root, 3, null);
    try std.testing.expect(r2 != null);
    try std.testing.expectEqual(root, r2.?.block_root);
}

test "GossipBlockInput: getAvailable returns null for incomplete block" {
    const allocator = std.testing.allocator;
    var manager = GossipBlockInput.init(allocator, &.{}, null);
    defer manager.deinit();

    const root = [_]u8{0xDE} ** 32;
    _ = try manager.onBlock(undefined, root, 1100, .gossip, 2, false, 10000);

    // Not complete yet.
    try std.testing.expect(manager.getAvailable(root) == null);

    // Add one blob.
    _ = manager.onBlobSidecar(root, 0, null);
    try std.testing.expect(manager.getAvailable(root) == null);

    // Complete it.
    _ = manager.onBlobSidecar(root, 1, null);
    const avail = manager.getAvailable(root);
    try std.testing.expect(avail != null);
    try std.testing.expectEqual(root, avail.?.block_root);

    // After getAvailable consumed it, pendingCount should be reduced.
    // (But the entry is still in the map because onBlobSidecar doesn't remove it.)
    // Let's verify getPending returns null after getAvailable.
    try std.testing.expect(manager.getPending(root) == null);
}

test "GossipBlockInput: getPending returns pending block info" {
    const allocator = std.testing.allocator;
    var manager = GossipBlockInput.init(allocator, &.{}, null);
    defer manager.deinit();

    const root = [_]u8{0xAC} ** 32;
    _ = try manager.onBlock(undefined, root, 1200, .gossip, 3, false, 11000);

    const pending = manager.getPending(root);
    try std.testing.expect(pending != null);
    try std.testing.expectEqual(@as(u32, 3), pending.?.expected_blobs);
    try std.testing.expectEqual(@as(u32, 3), pending.?.missingBlobCount());
    try std.testing.expectEqual(@as(u64, 1200), pending.?.slot);
}

test "GossipBlockInput: metrics tracking" {
    const allocator = std.testing.allocator;
    var manager = GossipBlockInput.init(allocator, &.{}, null);
    defer manager.deinit();

    // Block with no data — immediately available.
    _ = try manager.onBlock(undefined, [_]u8{0x01} ** 32, 1, .gossip, 0, false, 0);
    try std.testing.expectEqual(@as(u64, 1), manager.blocks_immediately_available);

    // Block with blobs — pending, then completed.
    const root = [_]u8{0x02} ** 32;
    _ = try manager.onBlock(undefined, root, 2, .gossip, 1, false, 0);
    _ = manager.onBlobSidecar(root, 0, null);
    try std.testing.expectEqual(@as(u64, 1), manager.blocks_completed_by_data);
}
