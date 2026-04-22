//! Seen-message caches for gossip de-duplication.
//!
//! These caches track already-processed messages so the node can quickly
//! reject duplicates received over gossipsub without repeating full
//! validation.  Each cache is a simple hash-set keyed by a message-
//! specific identifier.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const constants = @import("constants");
const preset = @import("preset").preset;

const Root = types.primitive.Root.Type;
const Slot = types.primitive.Slot.Type;
const Epoch = types.primitive.Epoch.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const ContributionAndProof = types.altair.ContributionAndProof.Type;
const SyncCommitteeContribution = types.altair.SyncCommitteeContribution.Type;

const SYNC_SUBCOMMITTEE_BYTES: usize = @divExact(
    preset.SYNC_COMMITTEE_SIZE / constants.SYNC_COMMITTEE_SUBNET_COUNT,
    8,
);
const MAX_SYNC_CONTRIBUTION_SLOTS: Slot = 8;

/// Key for data column sidecar deduplication: (block_root, column_index).
pub const DataColumnKey = struct {
    block_root: [32]u8,
    column_index: u64,
};

pub const SyncContributionAggregatorKey = struct {
    slot: Slot,
    subcommittee_index: u64,
    aggregator_index: ValidatorIndex,
};

pub const SyncContributionDataKey = struct {
    slot: Slot,
    beacon_block_root: Root,
    subcommittee_index: u64,
};

pub const AggregatedAttestationKey = struct {
    epoch: Epoch,
    committee_index: u64,
    attestation_data_root: Root,
};

const SyncContributionAggregationInfo = struct {
    aggregation_bits: [SYNC_SUBCOMMITTEE_BYTES]u8,
    true_bit_count: u32,
};

const AggregatedAttestationInfo = struct {
    aggregation_bits: []u8,
    true_bit_count: u32,
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

    /// Seen aggregate attestation participant supersets keyed by epoch + committee + attestation data root.
    seen_aggregated_attestations: std.AutoHashMap(AggregatedAttestationKey, std.ArrayListUnmanaged(AggregatedAttestationInfo)),

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

    /// Seen sync committee contribution aggregators, keyed by (slot, subnet, aggregator).
    seen_sync_contribution_aggregators: std.AutoHashMap(SyncContributionAggregatorKey, void),

    /// Seen sync committee contribution participant sets, keyed by (slot, root, subnet).
    seen_sync_contributions: std.AutoHashMap(SyncContributionDataKey, std.ArrayListUnmanaged(SyncContributionAggregationInfo)),

    pub fn init(allocator: Allocator) SeenCache {
        return .{
            .allocator = allocator,
            .seen_blocks = std.AutoHashMap([32]u8, Slot).init(allocator),
            .seen_aggregators = std.AutoHashMap(AggregatorKey, void).init(allocator),
            .seen_aggregated_attestations = std.AutoHashMap(AggregatedAttestationKey, std.ArrayListUnmanaged(AggregatedAttestationInfo)).init(allocator),
            .seen_exits = std.AutoHashMap(ValidatorIndex, void).init(allocator),
            .seen_proposer_slashings = std.AutoHashMap(ValidatorIndex, void).init(allocator),
            .seen_attester_slashings = std.AutoHashMap([32]u8, void).init(allocator),
            .seen_bls_changes = std.AutoHashMap(ValidatorIndex, void).init(allocator),
            .seen_data_columns = std.AutoHashMap(DataColumnKey, void).init(allocator),
            .seen_sync_contribution_aggregators = std.AutoHashMap(SyncContributionAggregatorKey, void).init(allocator),
            .seen_sync_contributions = std.AutoHashMap(SyncContributionDataKey, std.ArrayListUnmanaged(SyncContributionAggregationInfo)).init(allocator),
        };
    }

    pub fn deinit(self: *SeenCache) void {
        self.seen_blocks.deinit();
        self.seen_aggregators.deinit();
        self.deinitAggregatedAttestationLists();
        self.seen_aggregated_attestations.deinit();
        self.seen_exits.deinit();
        self.seen_proposer_slashings.deinit();
        self.seen_attester_slashings.deinit();
        self.seen_bls_changes.deinit();
        self.seen_data_columns.deinit();
        self.seen_sync_contribution_aggregators.deinit();
        self.deinitSyncContributionLists();
        self.seen_sync_contributions.deinit();
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

    fn aggregatedAttestationKey(
        epoch: Epoch,
        committee_index: u64,
        attestation_data_root: Root,
    ) AggregatedAttestationKey {
        return .{
            .epoch = epoch,
            .committee_index = committee_index,
            .attestation_data_root = attestation_data_root,
        };
    }

    pub fn aggregatedAttestationParticipantsKnown(
        self: *const SeenCache,
        epoch: Epoch,
        committee_index: u64,
        attestation_data_root: Root,
        aggregation_bits: []const u8,
    ) bool {
        const seen = self.seen_aggregated_attestations.get(
            aggregatedAttestationKey(epoch, committee_index, attestation_data_root),
        ) orelse return false;

        for (seen.items) |entry| {
            if (entry.aggregation_bits.len != aggregation_bits.len) continue;
            if (isBitSupersetOrEqual(entry.aggregation_bits, aggregation_bits)) return true;
        }

        return false;
    }

    pub fn markAggregatedAttestationSeen(
        self: *SeenCache,
        epoch: Epoch,
        committee_index: u64,
        attestation_data_root: Root,
        aggregation_bits: []const u8,
        true_bit_count: u32,
    ) !void {
        const gop = try self.seen_aggregated_attestations.getOrPut(
            aggregatedAttestationKey(epoch, committee_index, attestation_data_root),
        );
        if (!gop.found_existing) {
            gop.value_ptr.* = .empty;
        }

        const owned_bits = try self.allocator.dupe(u8, aggregation_bits);
        errdefer self.allocator.free(owned_bits);

        const entry: AggregatedAttestationInfo = .{
            .aggregation_bits = owned_bits,
            .true_bit_count = true_bit_count,
        };

        var insert_index: usize = 0;
        while (insert_index < gop.value_ptr.items.len) : (insert_index += 1) {
            if (true_bit_count > gop.value_ptr.items[insert_index].true_bit_count) break;
        }
        try gop.value_ptr.insert(self.allocator, insert_index, entry);
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

    // -- Sync committee contributions ----------------------------------------

    fn syncContributionAggregatorKey(
        slot: Slot,
        subcommittee_index: u64,
        aggregator_index: ValidatorIndex,
    ) SyncContributionAggregatorKey {
        return .{
            .slot = slot,
            .subcommittee_index = subcommittee_index,
            .aggregator_index = aggregator_index,
        };
    }

    fn syncContributionDataKey(contribution: *const SyncCommitteeContribution) SyncContributionDataKey {
        return .{
            .slot = contribution.slot,
            .beacon_block_root = contribution.beacon_block_root,
            .subcommittee_index = contribution.subcommittee_index,
        };
    }

    fn isBitSupersetOrEqual(superset: []const u8, subset: []const u8) bool {
        std.debug.assert(superset.len == subset.len);
        for (superset, subset) |lhs, rhs| {
            if ((rhs & ~lhs) != 0) return false;
        }
        return true;
    }

    pub fn isSyncContributionAggregatorKnown(
        self: *const SeenCache,
        slot: Slot,
        subcommittee_index: u64,
        aggregator_index: ValidatorIndex,
    ) bool {
        return self.seen_sync_contribution_aggregators.contains(
            syncContributionAggregatorKey(slot, subcommittee_index, aggregator_index),
        );
    }

    pub fn syncContributionParticipantsKnown(
        self: *const SeenCache,
        contribution: *const SyncCommitteeContribution,
    ) bool {
        const seen = self.seen_sync_contributions.get(syncContributionDataKey(contribution)) orelse return false;
        const aggregation_bits = contribution.aggregation_bits.data[0..];

        for (seen.items) |entry| {
            if (isBitSupersetOrEqual(entry.aggregation_bits[0..], aggregation_bits)) return true;
        }

        return false;
    }

    pub fn markSyncContributionSeen(
        self: *SeenCache,
        contribution_and_proof: *const ContributionAndProof,
        true_bit_count: u32,
    ) !void {
        const contribution = &contribution_and_proof.contribution;
        try self.seen_sync_contribution_aggregators.put(
            syncContributionAggregatorKey(
                contribution.slot,
                contribution.subcommittee_index,
                contribution_and_proof.aggregator_index,
            ),
            {},
        );

        const gop = try self.seen_sync_contributions.getOrPut(syncContributionDataKey(contribution));
        if (!gop.found_existing) {
            gop.value_ptr.* = .empty;
        }

        const entry: SyncContributionAggregationInfo = .{
            .aggregation_bits = contribution.aggregation_bits.data,
            .true_bit_count = true_bit_count,
        };

        var insert_index: usize = 0;
        while (insert_index < gop.value_ptr.items.len) : (insert_index += 1) {
            if (true_bit_count > gop.value_ptr.items[insert_index].true_bit_count) break;
        }
        try gop.value_ptr.insert(self.allocator, insert_index, entry);
    }

    pub fn pruneSyncContributions(self: *SeenCache, head_slot: Slot) void {
        const cutoff = if (head_slot > MAX_SYNC_CONTRIBUTION_SLOTS)
            head_slot - MAX_SYNC_CONTRIBUTION_SLOTS
        else
            0;

        var aggregator_keys: std.ArrayListUnmanaged(SyncContributionAggregatorKey) = .empty;
        defer aggregator_keys.deinit(self.allocator);

        var aggregator_it = self.seen_sync_contribution_aggregators.iterator();
        while (aggregator_it.next()) |entry| {
            if (entry.key_ptr.slot < cutoff) {
                aggregator_keys.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }
        for (aggregator_keys.items) |key| {
            _ = self.seen_sync_contribution_aggregators.remove(key);
        }

        var contribution_keys: std.ArrayListUnmanaged(SyncContributionDataKey) = .empty;
        defer contribution_keys.deinit(self.allocator);

        var contribution_it = self.seen_sync_contributions.iterator();
        while (contribution_it.next()) |entry| {
            if (entry.key_ptr.slot < cutoff) {
                contribution_keys.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }
        for (contribution_keys.items) |key| {
            if (self.seen_sync_contributions.fetchRemove(key)) |kv| {
                var infos = kv.value;
                infos.deinit(self.allocator);
            }
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

    /// Clear all aggregate-related dedup state at epoch boundaries.
    pub fn pruneAggregators(self: *SeenCache) void {
        self.seen_aggregators.clearRetainingCapacity();
        self.clearAggregatedAttestationListsRetainingCapacity();
        self.seen_aggregated_attestations.clearRetainingCapacity();
    }

    /// Clear the entire cache (useful in tests).
    pub fn reset(self: *SeenCache) void {
        self.seen_blocks.clearRetainingCapacity();
        self.seen_aggregators.clearRetainingCapacity();
        self.clearAggregatedAttestationListsRetainingCapacity();
        self.seen_aggregated_attestations.clearRetainingCapacity();
        self.seen_exits.clearRetainingCapacity();
        self.seen_proposer_slashings.clearRetainingCapacity();
        self.seen_attester_slashings.clearRetainingCapacity();
        self.seen_bls_changes.clearRetainingCapacity();
        self.seen_data_columns.clearRetainingCapacity();
        self.seen_sync_contribution_aggregators.clearRetainingCapacity();
        self.clearSyncContributionListsRetainingCapacity();
        self.seen_sync_contributions.clearRetainingCapacity();
    }

    fn deinitAggregatedAttestationLists(self: *SeenCache) void {
        var it = self.seen_aggregated_attestations.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |info| {
                self.allocator.free(info.aggregation_bits);
            }
            entry.value_ptr.deinit(self.allocator);
        }
    }

    fn clearAggregatedAttestationListsRetainingCapacity(self: *SeenCache) void {
        var it = self.seen_aggregated_attestations.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |info| {
                self.allocator.free(info.aggregation_bits);
            }
            entry.value_ptr.deinit(self.allocator);
        }
    }

    fn deinitSyncContributionLists(self: *SeenCache) void {
        var it = self.seen_sync_contributions.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
    }

    fn clearSyncContributionListsRetainingCapacity(self: *SeenCache) void {
        var it = self.seen_sync_contributions.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
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

test "SeenCache: aggregate participant superset dedup" {
    const allocator = std.testing.allocator;
    var cache = SeenCache.init(allocator);
    defer cache.deinit();

    const epoch: Epoch = 10;
    const committee_index: u64 = 2;
    const attestation_data_root = [_]u8{0xAB} ** 32;

    try std.testing.expect(!cache.aggregatedAttestationParticipantsKnown(epoch, committee_index, attestation_data_root, &[_]u8{0x01}));
    try cache.markAggregatedAttestationSeen(epoch, committee_index, attestation_data_root, &[_]u8{0x03}, 2);
    try std.testing.expect(cache.aggregatedAttestationParticipantsKnown(epoch, committee_index, attestation_data_root, &[_]u8{0x01}));
    try std.testing.expect(cache.aggregatedAttestationParticipantsKnown(epoch, committee_index, attestation_data_root, &[_]u8{0x03}));
    try std.testing.expect(!cache.aggregatedAttestationParticipantsKnown(epoch, committee_index, attestation_data_root, &[_]u8{0x04}));
}

test "SeenCache: pruneAggregators clears aggregate superset dedup" {
    const allocator = std.testing.allocator;
    var cache = SeenCache.init(allocator);
    defer cache.deinit();

    const epoch: Epoch = 10;
    const committee_index: u64 = 2;
    const attestation_data_root = [_]u8{0xCD} ** 32;

    try cache.markAggregatorSeen(5, epoch);
    try cache.markAggregatedAttestationSeen(epoch, committee_index, attestation_data_root, &[_]u8{0x03}, 2);
    cache.pruneAggregators();

    try std.testing.expect(!cache.hasSeenAggregator(5, epoch));
    try std.testing.expect(!cache.aggregatedAttestationParticipantsKnown(epoch, committee_index, attestation_data_root, &[_]u8{0x01}));
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

test "SeenCache: sync contribution aggregator dedup" {
    const allocator = std.testing.allocator;
    var cache = SeenCache.init(allocator);
    defer cache.deinit();

    var contribution_and_proof = types.altair.ContributionAndProof.default_value;
    contribution_and_proof.aggregator_index = 100;
    contribution_and_proof.contribution.slot = 10;
    contribution_and_proof.contribution.subcommittee_index = 2;

    try std.testing.expect(!cache.isSyncContributionAggregatorKnown(10, 2, 100));
    try cache.markSyncContributionSeen(&contribution_and_proof, 0);
    try std.testing.expect(cache.isSyncContributionAggregatorKnown(10, 2, 100));
    try std.testing.expect(!cache.isSyncContributionAggregatorKnown(11, 2, 100));
    try std.testing.expect(!cache.isSyncContributionAggregatorKnown(10, 3, 100));
    try std.testing.expect(!cache.isSyncContributionAggregatorKnown(10, 2, 101));
}

test "SeenCache: sync contribution participants known if seen superset exists" {
    const allocator = std.testing.allocator;
    var cache = SeenCache.init(allocator);
    defer cache.deinit();

    var contribution_and_proof = types.altair.ContributionAndProof.default_value;
    contribution_and_proof.aggregator_index = 100;
    contribution_and_proof.contribution.slot = 10;
    contribution_and_proof.contribution.subcommittee_index = 2;
    contribution_and_proof.contribution.aggregation_bits.data[0] = 0b11110001;
    try cache.markSyncContributionSeen(&contribution_and_proof, 5);

    var subset = contribution_and_proof.contribution;
    subset.aggregation_bits.data[0] = 0b11010001;
    try std.testing.expect(cache.syncContributionParticipantsKnown(&subset));

    var not_subset = contribution_and_proof.contribution;
    not_subset.aggregation_bits.data[0] = 0b11111110;
    try std.testing.expect(!cache.syncContributionParticipantsKnown(&not_subset));
}

test "SeenCache: prune sync contributions by slot" {
    const allocator = std.testing.allocator;
    var cache = SeenCache.init(allocator);
    defer cache.deinit();

    var old = types.altair.ContributionAndProof.default_value;
    old.aggregator_index = 1;
    old.contribution.slot = 5;
    old.contribution.subcommittee_index = 0;
    old.contribution.aggregation_bits.data[0] = 0x01;
    try cache.markSyncContributionSeen(&old, 1);

    var current = types.altair.ContributionAndProof.default_value;
    current.aggregator_index = 2;
    current.contribution.slot = 20;
    current.contribution.subcommittee_index = 0;
    current.contribution.aggregation_bits.data[0] = 0x03;
    try cache.markSyncContributionSeen(&current, 2);

    cache.pruneSyncContributions(20);

    try std.testing.expect(!cache.isSyncContributionAggregatorKnown(5, 0, 1));
    try std.testing.expect(cache.isSyncContributionAggregatorKnown(20, 0, 2));
    try std.testing.expect(!cache.syncContributionParticipantsKnown(&old.contribution));
    try std.testing.expect(cache.syncContributionParticipantsKnown(&current.contribution));
}
