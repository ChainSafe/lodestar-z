//! Seen-message caches for gossip de-duplication.
//!
//! These caches track already-processed messages so the node can quickly
//! reject duplicates received over gossipsub without repeating full
//! validation.  Each cache is a simple hash-set keyed by a message-
//! specific identifier.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;

const Slot = types.primitive.Slot.Type;
const Epoch = types.primitive.Epoch.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;

/// Key for data column sidecar deduplication: (block_root, column_index).
pub const DataColumnKey = struct {
    block_root: [32]u8,
    column_index: u64,
};

/// Caches for messages already seen on the gossip network.
///
/// Used to short-circuit gossip validation: if a message has been seen,
/// it can be dropped immediately.
pub const SeenCache = struct {
    allocator: Allocator,

    /// Seen beacon block roots.
    seen_blocks: std.AutoHashMap([32]u8, Slot),

    /// Seen aggregate attestation selection proofs.
    /// Key: { index: u64, epoch: u64 } — struct avoids truncation for index > 2^32.
    seen_aggregators: std.AutoHashMap(AggregatorKey, void),

    /// Seen voluntary exits, keyed by validator index.
    seen_exits: std.AutoHashMap(ValidatorIndex, void),

    /// Seen proposer slashings, keyed by proposer index.
    seen_proposer_slashings: std.AutoHashMap(ValidatorIndex, void),

    /// Seen attester slashings, keyed by hash-tree-root of the slashing.
    seen_attester_slashings: std.AutoHashMap([32]u8, void),

    /// Seen BLS-to-execution changes, keyed by validator index.
    seen_bls_changes: std.AutoHashMap(ValidatorIndex, void),

    /// Seen data column sidecars, keyed by (block_root, column_index).
    /// Used for PeerDAS / Fulu deduplication.
    seen_data_columns: std.AutoHashMap(DataColumnKey, void),

    pub fn init(allocator: Allocator) SeenCache {
        return .{
            .allocator = allocator,
            .seen_blocks = std.AutoHashMap([32]u8, Slot).init(allocator),
            .seen_aggregators = std.AutoHashMap(AggregatorKey, void).init(allocator),
            .seen_exits = std.AutoHashMap(ValidatorIndex, void).init(allocator),
            .seen_proposer_slashings = std.AutoHashMap(ValidatorIndex, void).init(allocator),
            .seen_attester_slashings = std.AutoHashMap([32]u8, void).init(allocator),
            .seen_bls_changes = std.AutoHashMap(ValidatorIndex, void).init(allocator),
            .seen_data_columns = std.AutoHashMap(DataColumnKey, void).init(allocator),
        };
    }

    pub fn deinit(self: *SeenCache) void {
        self.seen_blocks.deinit();
        self.seen_aggregators.deinit();
        self.seen_exits.deinit();
        self.seen_proposer_slashings.deinit();
        self.seen_attester_slashings.deinit();
        self.seen_bls_changes.deinit();
        self.seen_data_columns.deinit();
    }

    // -- Blocks ---------------------------------------------------------------

    pub fn hasSeenBlock(self: *const SeenCache, root: [32]u8) bool {
        return self.seen_blocks.contains(root);
    }

    pub fn markBlockSeen(self: *SeenCache, root: [32]u8, slot: Slot) !void {
        try self.seen_blocks.put(root, slot);
    }

    /// Prune block entries older than `min_slot`.
    ///
    /// Uses a dynamic list to avoid the 256-entry silent truncation bug.
    pub fn pruneBlocks(self: *SeenCache, min_slot: Slot) void {
        var to_remove = std.array_list.Managed([32]u8).init(self.allocator);
        defer to_remove.deinit();

        var it = self.seen_blocks.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* < min_slot) {
                to_remove.append(entry.key_ptr.*) catch continue;
            }
        }
        for (to_remove.items) |key| {
            _ = self.seen_blocks.remove(key);
        }
    }

    // -- Aggregators ----------------------------------------------------------

    /// Encode an aggregator key from validator index and epoch.
    const AggregatorKey = struct { index: u64, epoch: u64 };

    fn aggregatorKey(aggregator_index: ValidatorIndex, epoch: Epoch) AggregatorKey {
        return .{ .index = aggregator_index, .epoch = epoch };
    }

    pub fn hasSeenAggregator(self: *const SeenCache, aggregator_index: ValidatorIndex, epoch: Epoch) bool {
        return self.seen_aggregators.contains(aggregatorKey(aggregator_index, epoch));
    }

    pub fn markAggregatorSeen(self: *SeenCache, aggregator_index: ValidatorIndex, epoch: Epoch) !void {
        try self.seen_aggregators.put(aggregatorKey(aggregator_index, epoch), {});
    }

    // -- Voluntary exits ------------------------------------------------------

    pub fn hasSeenExit(self: *const SeenCache, validator_index: ValidatorIndex) bool {
        return self.seen_exits.contains(validator_index);
    }

    pub fn markExitSeen(self: *SeenCache, validator_index: ValidatorIndex) !void {
        try self.seen_exits.put(validator_index, {});
    }

    // -- Proposer slashings ---------------------------------------------------

    pub fn hasSeenProposerSlashing(self: *const SeenCache, proposer_index: ValidatorIndex) bool {
        return self.seen_proposer_slashings.contains(proposer_index);
    }

    pub fn markProposerSlashingSeen(self: *SeenCache, proposer_index: ValidatorIndex) !void {
        try self.seen_proposer_slashings.put(proposer_index, {});
    }

    // -- Attester slashings ---------------------------------------------------

    pub fn hasSeenAttesterSlashing(self: *const SeenCache, root: [32]u8) bool {
        return self.seen_attester_slashings.contains(root);
    }

    pub fn markAttesterSlashingSeen(self: *SeenCache, root: [32]u8) !void {
        try self.seen_attester_slashings.put(root, {});
    }

    // -- BLS-to-execution changes ---------------------------------------------

    pub fn hasSeenBlsChange(self: *const SeenCache, validator_index: ValidatorIndex) bool {
        return self.seen_bls_changes.contains(validator_index);
    }

    pub fn markBlsChangeSeen(self: *SeenCache, validator_index: ValidatorIndex) !void {
        try self.seen_bls_changes.put(validator_index, {});
    }

    // -- Data columns (PeerDAS / Fulu) ----------------------------------------

    pub fn hasSeenDataColumn(self: *const SeenCache, block_root: [32]u8, column_index: u64) bool {
        return self.seen_data_columns.contains(.{ .block_root = block_root, .column_index = column_index });
    }

    pub fn markDataColumnSeen(self: *SeenCache, block_root: [32]u8, column_index: u64) !void {
        try self.seen_data_columns.put(.{ .block_root = block_root, .column_index = column_index }, {});
    }

    /// Prune data column entries for a given block root (e.g. when finalized).
    ///
    /// Uses a dynamic list to avoid the 256-entry silent truncation bug.
    pub fn pruneDataColumns(self: *SeenCache, block_root: [32]u8) void {
        // Remove all column entries for this block root.
        // Since AutoHashMap doesn't support prefix deletion, we collect then remove.
        var to_remove: std.ArrayListUnmanaged(DataColumnKey) = .empty;
        defer to_remove.deinit(self.allocator);

        var it = self.seen_data_columns.iterator();
        while (it.next()) |entry| {
            if (std.mem.eql(u8, &entry.key_ptr.block_root, &block_root)) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }
        for (to_remove.items) |key| {
            _ = self.seen_data_columns.remove(key);
        }
    }

    // -- Bulk prune -----------------------------------------------------------

    /// Prune operation dedup caches on finalization.
    ///
    /// These maps (exits, BLS changes, proposer/attester slashings) track already-seen
    /// gossip messages to avoid re-processing duplicates. They are NOT authoritative
    /// state — the canonical record is in the beacon state. Clearing them on finalization
    /// is safe and prevents unbounded memory growth over days/weeks.
    ///
    /// After finalization, validators that exited or were slashed pre-finalization will
    /// never send new gossip for those operations, so the dedup entries are stale anyway.
    pub fn pruneOnFinalization(self: *SeenCache) void {
        self.seen_exits.clearRetainingCapacity();
        self.seen_bls_changes.clearRetainingCapacity();
        self.seen_proposer_slashings.clearRetainingCapacity();
        self.seen_attester_slashings.clearRetainingCapacity();
    }

    /// Clear all aggregator entries (call at epoch boundaries).
    pub fn pruneAggregators(self: *SeenCache) void {
        self.seen_aggregators.clearRetainingCapacity();
    }

    /// Clear the entire cache (useful in tests).
    pub fn reset(self: *SeenCache) void {
        self.seen_blocks.clearRetainingCapacity();
        self.seen_aggregators.clearRetainingCapacity();
        self.seen_exits.clearRetainingCapacity();
        self.seen_proposer_slashings.clearRetainingCapacity();
        self.seen_attester_slashings.clearRetainingCapacity();
        self.seen_bls_changes.clearRetainingCapacity();
        self.seen_data_columns.clearRetainingCapacity();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "SeenCache: block dedup" {
    const allocator = std.testing.allocator;
    var cache = SeenCache.init(allocator);
    defer cache.deinit();

    const root = [_]u8{0xAB} ** 32;
    try std.testing.expect(!cache.hasSeenBlock(root));

    try cache.markBlockSeen(root, 42);
    try std.testing.expect(cache.hasSeenBlock(root));

    // Different root not seen.
    const root2 = [_]u8{0xCD} ** 32;
    try std.testing.expect(!cache.hasSeenBlock(root2));
}

test "SeenCache: aggregator dedup" {
    const allocator = std.testing.allocator;
    var cache = SeenCache.init(allocator);
    defer cache.deinit();

    try std.testing.expect(!cache.hasSeenAggregator(5, 10));
    try cache.markAggregatorSeen(5, 10);
    try std.testing.expect(cache.hasSeenAggregator(5, 10));

    // Same validator, different epoch → not seen.
    try std.testing.expect(!cache.hasSeenAggregator(5, 11));
}

test "SeenCache: exit dedup" {
    const allocator = std.testing.allocator;
    var cache = SeenCache.init(allocator);
    defer cache.deinit();

    try std.testing.expect(!cache.hasSeenExit(99));
    try cache.markExitSeen(99);
    try std.testing.expect(cache.hasSeenExit(99));
}

test "SeenCache: proposer slashing dedup" {
    const allocator = std.testing.allocator;
    var cache = SeenCache.init(allocator);
    defer cache.deinit();

    try std.testing.expect(!cache.hasSeenProposerSlashing(7));
    try cache.markProposerSlashingSeen(7);
    try std.testing.expect(cache.hasSeenProposerSlashing(7));
}

test "SeenCache: BLS change dedup" {
    const allocator = std.testing.allocator;
    var cache = SeenCache.init(allocator);
    defer cache.deinit();

    try std.testing.expect(!cache.hasSeenBlsChange(42));
    try cache.markBlsChangeSeen(42);
    try std.testing.expect(cache.hasSeenBlsChange(42));
}

test "SeenCache: prune blocks" {
    const allocator = std.testing.allocator;
    var cache = SeenCache.init(allocator);
    defer cache.deinit();

    try cache.markBlockSeen([_]u8{1} ** 32, 10);
    try cache.markBlockSeen([_]u8{2} ** 32, 50);

    cache.pruneBlocks(30);
    try std.testing.expect(!cache.hasSeenBlock([_]u8{1} ** 32));
    try std.testing.expect(cache.hasSeenBlock([_]u8{2} ** 32));
}

test "SeenCache: reset clears all" {
    const allocator = std.testing.allocator;
    var cache = SeenCache.init(allocator);
    defer cache.deinit();

    try cache.markBlockSeen([_]u8{1} ** 32, 10);
    try cache.markExitSeen(5);
    try cache.markProposerSlashingSeen(9);

    cache.reset();
    try std.testing.expect(!cache.hasSeenBlock([_]u8{1} ** 32));
    try std.testing.expect(!cache.hasSeenExit(5));
    try std.testing.expect(!cache.hasSeenProposerSlashing(9));
}

test "SeenCache: data column dedup" {
    const allocator = std.testing.allocator;
    var cache = SeenCache.init(allocator);
    defer cache.deinit();

    const root = [_]u8{0xAB} ** 32;
    try std.testing.expect(!cache.hasSeenDataColumn(root, 0));
    try std.testing.expect(!cache.hasSeenDataColumn(root, 1));

    try cache.markDataColumnSeen(root, 0);
    try std.testing.expect(cache.hasSeenDataColumn(root, 0));
    try std.testing.expect(!cache.hasSeenDataColumn(root, 1));

    // Different root, same index → not seen.
    const root2 = [_]u8{0xCD} ** 32;
    try std.testing.expect(!cache.hasSeenDataColumn(root2, 0));
}

test "SeenCache: prune data columns by root" {
    const allocator = std.testing.allocator;
    var cache = SeenCache.init(allocator);
    defer cache.deinit();

    const root1 = [_]u8{0x01} ** 32;
    const root2 = [_]u8{0x02} ** 32;

    try cache.markDataColumnSeen(root1, 0);
    try cache.markDataColumnSeen(root1, 5);
    try cache.markDataColumnSeen(root2, 3);

    cache.pruneDataColumns(root1);
    try std.testing.expect(!cache.hasSeenDataColumn(root1, 0));
    try std.testing.expect(!cache.hasSeenDataColumn(root1, 5));
    try std.testing.expect(cache.hasSeenDataColumn(root2, 3));
}
