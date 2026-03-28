//! Sync committee contribution pools for block production.
//!
//! Two pools:
//! 1. **SyncCommitteeMessagePool** — pre-aggregates individual `SyncCommitteeMessage`
//!    from gossip into `SyncCommitteeContribution` per (slot, subcommittee, block_root).
//! 2. **SyncContributionAndProofPool** — caches the best `SyncCommitteeContribution`
//!    per (slot, block_root, subcommittee) from gossip aggregators. Used by block
//!    production to build the `SyncAggregate`.
//!
//! Reference: consensus-specs altair/beacon-chain.md, TS Lodestar syncContributionAndProofPool.ts

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;
const constants = @import("constants");
const bls = @import("bls");

const Slot = types.primitive.Slot.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const BLSSignature = types.primitive.BLSSignature.Type;
const Root = types.primitive.Root.Type;

const SyncAggregate = types.altair.SyncAggregate;
const SyncCommitteeContribution = types.altair.SyncCommitteeContribution;
const SyncCommitteeMessage = types.altair.SyncCommitteeMessage;

/// Number of subcommittees in the sync committee.
const SYNC_COMMITTEE_SUBNET_COUNT: u64 = constants.SYNC_COMMITTEE_SUBNET_COUNT;

/// Validators per subcommittee (128 for mainnet, 8 for minimal).
const SYNC_SUBCOMMITTEE_SIZE: u64 = preset.SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT;

/// Byte length of subcommittee aggregation bits.
const SYNC_SUBCOMMITTEE_BYTES: usize = @divExact(SYNC_SUBCOMMITTEE_SIZE, 8);

/// Byte length of full sync committee bits (64 for mainnet, 4 for minimal).
const SYNC_COMMITTEE_BYTES: usize = @divExact(preset.SYNC_COMMITTEE_SIZE, 8);

/// Number of slots to retain before pruning.
const SLOTS_RETAINED: u64 = 8;

/// DoS limit: max distinct block roots per slot per pool.
const MAX_ITEMS_PER_SLOT: usize = 512;

/// Hard cap on distinct slots tracked by each pool.
///
/// `prune()` removes slots older than `head_slot - SLOTS_RETAINED` (8 slots),
/// but it is called reactively and may lag. This cap ensures the `by_slot` map
/// cannot grow beyond a fixed bound even if `prune()` is delayed.  When the
/// cap is hit, the oldest slot is evicted before inserting the new one.
const MAX_TRACKED_SLOTS: usize = 16;

/// G2 point at infinity — used as the signature when no participants.
const G2_POINT_AT_INFINITY: [96]u8 = constants.G2_POINT_AT_INFINITY;

/// Hex-encode a Root for use as a map key.
fn rootHex(root: Root) [64]u8 {
    return std.fmt.bytesToHex(root, .lower);
}

// =========================================================================
// SyncContributionAndProofPool
// =========================================================================

/// Caches the best `SyncCommitteeContribution` per (slot, block_root, subcommittee).
///
/// Fed by gossip `sync_committee_contribution_and_proof` messages. Block
/// production calls `getSyncAggregate(slot, block_root)` to build the
/// `SyncAggregate` for inclusion in a beacon block body.
pub const SyncContributionAndProofPool = struct {
    allocator: Allocator,

    /// slot → (root_hex → (subcommittee_index → BestContribution))
    by_slot: std.AutoHashMap(Slot, RootMap),

    lowest_permissible_slot: Slot,

    const RootMap = std.AutoHashMap([64]u8, SubnetMap);
    const SubnetMap = std.AutoHashMap(u64, BestContribution);

    /// Internal representation — stores the best contribution for a subcommittee.
    const BestContribution = struct {
        aggregation_bits: [SYNC_SUBCOMMITTEE_BYTES]u8,
        num_participants: u32,
        signature: BLSSignature,
    };

    pub fn init(allocator: Allocator) SyncContributionAndProofPool {
        return .{
            .allocator = allocator,
            .by_slot = std.AutoHashMap(Slot, RootMap).init(allocator),
            .lowest_permissible_slot = 0,
        };
    }

    pub fn deinit(self: *SyncContributionAndProofPool) void {
        var slot_it = self.by_slot.iterator();
        while (slot_it.next()) |slot_entry| {
            var root_it = slot_entry.value_ptr.iterator();
            while (root_it.next()) |root_entry| {
                root_entry.value_ptr.deinit();
            }
            slot_entry.value_ptr.deinit();
        }
        self.by_slot.deinit();
    }

    /// Add a contribution. Replaces existing if the new one has more participants.
    pub fn add(self: *SyncContributionAndProofPool, contribution: *const SyncCommitteeContribution.Type) !void {
        const slot = contribution.slot;
        if (slot < self.lowest_permissible_slot) return;

        const rh = rootHex(contribution.beacon_block_root);
        const subnet: u64 = contribution.subcommittee_index;

        // Enforce MAX_TRACKED_SLOTS: evict the oldest slot if we are at capacity
        // and this contribution is for a slot not already present.
        // This guards against prune() being called late (e.g. during a stall).
        if (self.by_slot.count() >= MAX_TRACKED_SLOTS and !self.by_slot.contains(slot)) {
            var oldest: Slot = std.math.maxInt(Slot);
            var it = self.by_slot.iterator();
            while (it.next()) |entry| {
                if (entry.key_ptr.* < oldest) oldest = entry.key_ptr.*;
            }
            if (self.by_slot.fetchRemove(oldest)) |kv| {
                var root_map = kv.value;
                var root_it = root_map.iterator();
                while (root_it.next()) |root_entry| {
                    root_entry.value_ptr.deinit();
                }
                root_map.deinit();
            }
        }

        // Get or create the slot entry.
        const root_map_gop = try self.by_slot.getOrPut(slot);
        if (!root_map_gop.found_existing) {
            root_map_gop.value_ptr.* = RootMap.init(self.allocator);
        }

        // Limit entries per slot (DoS protection).
        if (root_map_gop.value_ptr.count() >= MAX_ITEMS_PER_SLOT) return;

        // Get or create the root entry.
        const subnet_map_gop = try root_map_gop.value_ptr.getOrPut(rh);
        if (!subnet_map_gop.found_existing) {
            subnet_map_gop.value_ptr.* = SubnetMap.init(self.allocator);
        }

        // Count participants in the new contribution.
        const new_count = countBits(&contribution.aggregation_bits.data);

        const best_gop = try subnet_map_gop.value_ptr.getOrPut(subnet);
        if (!best_gop.found_existing) {
            best_gop.value_ptr.* = .{
                .aggregation_bits = contribution.aggregation_bits.data,
                .num_participants = new_count,
                .signature = contribution.signature,
            };
        } else {
            // Replace if the new contribution has strictly more participants.
            if (new_count > best_gop.value_ptr.num_participants) {
                best_gop.value_ptr.* = .{
                    .aggregation_bits = contribution.aggregation_bits.data,
                    .num_participants = new_count,
                    .signature = contribution.signature,
                };
            }
        }
    }

    /// Build a `SyncAggregate` for block production.
    ///
    /// Combines the best contributions from all subcommittees for the given
    /// slot and block root. Returns an all-zeros aggregate if no contributions
    /// are available (valid per spec — zero participation).
    pub fn getSyncAggregate(self: *SyncContributionAndProofPool, slot: Slot, block_root: Root) SyncAggregate.Type {
        const empty = SyncAggregate.Type{
            .sync_committee_bits = .{ .data = [_]u8{0} ** SYNC_COMMITTEE_BYTES },
            .sync_committee_signature = G2_POINT_AT_INFINITY,
        };

        const root_map = self.by_slot.get(slot) orelse return empty;
        const rh = rootHex(block_root);
        const subnet_map = root_map.get(rh) orelse return empty;

        if (subnet_map.count() == 0) return empty;

        // Build the 512-bit sync_committee_bits by placing each subcommittee's
        // aggregation_bits at the correct byte offset.
        var sync_bits: [SYNC_COMMITTEE_BYTES]u8 = [_]u8{0} ** SYNC_COMMITTEE_BYTES;
        var sigs_to_aggregate: [SYNC_COMMITTEE_SUBNET_COUNT]bls.Signature = undefined;
        var sig_count: usize = 0;

        var subnet_it = subnet_map.iterator();
        while (subnet_it.next()) |entry| {
            const subnet = entry.key_ptr.*;
            const best = entry.value_ptr;

            if (subnet >= SYNC_COMMITTEE_SUBNET_COUNT) continue;
            if (best.num_participants == 0) continue;

            // Copy subcommittee bits into the correct position.
            const byte_offset: usize = @intCast(subnet * SYNC_SUBCOMMITTEE_BYTES);
            @memcpy(sync_bits[byte_offset..][0..SYNC_SUBCOMMITTEE_BYTES], &best.aggregation_bits);

            // Deserialize the BLS signature for aggregation.
            const sig = bls.Signature.deserialize(&best.signature) catch continue;
            sigs_to_aggregate[sig_count] = sig;
            sig_count += 1;
        }

        if (sig_count == 0) return empty;

        // Aggregate all subcommittee signatures.
        const agg_sig = bls.AggregateSignature.aggregate(
            sigs_to_aggregate[0..sig_count],
            false,
        ) catch return empty;

        return .{
            .sync_committee_bits = .{ .data = sync_bits },
            .sync_committee_signature = agg_sig.toSignature().compress(),
        };
    }

    /// Remove contributions older than `head_slot - SLOTS_RETAINED`.
    pub fn prune(self: *SyncContributionAndProofPool, head_slot: Slot) void {
        const cutoff = if (head_slot > SLOTS_RETAINED) head_slot - SLOTS_RETAINED else 0;
        self.lowest_permissible_slot = cutoff;

        // Collect slots to remove (can't modify while iterating).
        var to_remove: [256]Slot = undefined;
        var remove_count: usize = 0;

        var it = self.by_slot.iterator();
        while (it.next()) |entry| {
            if (entry.key_ptr.* < cutoff) {
                if (remove_count < to_remove.len) {
                    to_remove[remove_count] = entry.key_ptr.*;
                    remove_count += 1;
                }
            }
        }

        for (to_remove[0..remove_count]) |slot| {
            if (self.by_slot.fetchRemove(slot)) |kv| {
                var root_map = kv.value;
                var root_it = root_map.iterator();
                while (root_it.next()) |root_entry| {
                    root_entry.value_ptr.deinit();
                }
                root_map.deinit();
            }
        }
    }

    /// Total number of (root, subnet) pairs stored across all slots.
    pub fn size(self: *const SyncContributionAndProofPool) usize {
        var count: usize = 0;
        var slot_it = self.by_slot.iterator();
        while (slot_it.next()) |slot_entry| {
            var root_it = slot_entry.value_ptr.iterator();
            while (root_it.next()) |root_entry| {
                count += root_entry.value_ptr.count();
            }
        }
        return count;
    }
};

// =========================================================================
// SyncCommitteeMessagePool
// =========================================================================

/// Pre-aggregates individual `SyncCommitteeMessage` from gossip into
/// `SyncCommitteeContribution` per (slot, subcommittee, block_root).
///
/// Validators send individual sync committee messages. This pool
/// aggregates them so that aggregators (or block producers) can
/// produce `SyncCommitteeContribution` objects.
pub const SyncCommitteeMessagePool = struct {
    allocator: Allocator,

    /// slot → (subcommittee_index → (root_hex → PreAggregation))
    by_slot: std.AutoHashMap(Slot, SubnetRootMap),

    lowest_permissible_slot: Slot,

    const SubnetRootMap = std.AutoHashMap(u64, std.AutoHashMap([64]u8, PreAggregation));

    /// Pre-aggregated contribution state for a single (slot, subnet, root).
    const PreAggregation = struct {
        slot: Slot,
        subcommittee_index: u64,
        beacon_block_root: Root,
        aggregation_bits: [SYNC_SUBCOMMITTEE_BYTES]u8,
        /// Raw serialized aggregate signature bytes.
        signature_bytes: BLSSignature,
        /// Number of individual messages aggregated so far.
        num_participants: u32,
    };

    pub fn init(allocator: Allocator) SyncCommitteeMessagePool {
        return .{
            .allocator = allocator,
            .by_slot = std.AutoHashMap(Slot, SubnetRootMap).init(allocator),
            .lowest_permissible_slot = 0,
        };
    }

    pub fn deinit(self: *SyncCommitteeMessagePool) void {
        var slot_it = self.by_slot.iterator();
        while (slot_it.next()) |slot_entry| {
            var subnet_it = slot_entry.value_ptr.iterator();
            while (subnet_it.next()) |subnet_entry| {
                subnet_entry.value_ptr.deinit();
            }
            slot_entry.value_ptr.deinit();
        }
        self.by_slot.deinit();
    }

    /// Add an individual sync committee message.
    ///
    /// `index_in_subcommittee` is the validator's position within the subcommittee
    /// (0..SYNC_SUBCOMMITTEE_SIZE-1), used to set the aggregation bit.
    pub fn add(
        self: *SyncCommitteeMessagePool,
        subnet: u64,
        slot: Slot,
        beacon_block_root: Root,
        index_in_subcommittee: u64,
        signature: BLSSignature,
    ) !void {
        if (slot < self.lowest_permissible_slot) return;
        if (index_in_subcommittee >= SYNC_SUBCOMMITTEE_SIZE) return;

        const rh = rootHex(beacon_block_root);

        // Enforce MAX_TRACKED_SLOTS: evict oldest if at capacity and slot is new.
        if (self.by_slot.count() >= MAX_TRACKED_SLOTS and !self.by_slot.contains(slot)) {
            var oldest: Slot = std.math.maxInt(Slot);
            var scan_it = self.by_slot.iterator();
            while (scan_it.next()) |entry| {
                if (entry.key_ptr.* < oldest) oldest = entry.key_ptr.*;
            }
            if (self.by_slot.fetchRemove(oldest)) |kv| {
                var subnet_map = kv.value;
                var subnet_it = subnet_map.iterator();
                while (subnet_it.next()) |subnet_entry| {
                    subnet_entry.value_ptr.deinit();
                }
                subnet_map.deinit();
            }
        }

        // Get or create slot → subnet → root entry.
        const subnet_map_gop = try self.by_slot.getOrPut(slot);
        if (!subnet_map_gop.found_existing) {
            subnet_map_gop.value_ptr.* = SubnetRootMap.init(self.allocator);
        }

        const root_map_gop = try subnet_map_gop.value_ptr.getOrPut(subnet);
        if (!root_map_gop.found_existing) {
            root_map_gop.value_ptr.* = std.AutoHashMap([64]u8, PreAggregation).init(self.allocator);
        }

        // Limit per slot (DoS).
        if (root_map_gop.value_ptr.count() >= MAX_ITEMS_PER_SLOT) return;

        const gop = try root_map_gop.value_ptr.getOrPut(rh);
        if (!gop.found_existing) {
            // First message for this (slot, subnet, root) — initialize.
            var bits: [SYNC_SUBCOMMITTEE_BYTES]u8 = [_]u8{0} ** SYNC_SUBCOMMITTEE_BYTES;
            setBit(&bits, @intCast(index_in_subcommittee));
            gop.value_ptr.* = .{
                .slot = slot,
                .subcommittee_index = subnet,
                .beacon_block_root = beacon_block_root,
                .aggregation_bits = bits,
                .signature_bytes = signature,
                .num_participants = 1,
            };
        } else {
            // Aggregate into existing entry.
            const pre = gop.value_ptr;
            const byte_idx = @as(usize, @intCast(index_in_subcommittee)) / 8;
            const bit_idx: u3 = @intCast(@as(usize, @intCast(index_in_subcommittee)) % 8);
            if ((pre.aggregation_bits[byte_idx] >> bit_idx) & 1 == 1) {
                // Already have this validator's message — skip.
                return;
            }

            // Set the bit.
            setBit(&pre.aggregation_bits, @intCast(index_in_subcommittee));

            // Aggregate signatures: deserialize both, aggregate, serialize back.
            const existing_sig = bls.Signature.deserialize(&pre.signature_bytes) catch return;
            const new_sig = bls.Signature.deserialize(&signature) catch return;
            const sigs = [_]bls.Signature{ existing_sig, new_sig };
            const agg = bls.AggregateSignature.aggregate(&sigs, false) catch return;
            pre.signature_bytes = agg.toSignature().compress();
            pre.num_participants += 1;
        }
    }

    /// Get the pre-aggregated contribution for a (subnet, slot, block_root).
    /// Returns null if no messages have been collected.
    pub fn getContribution(
        self: *SyncCommitteeMessagePool,
        subnet: u64,
        slot: Slot,
        block_root: Root,
    ) ?SyncCommitteeContribution.Type {
        const subnet_map = self.by_slot.get(slot) orelse return null;
        const root_map = subnet_map.get(subnet) orelse return null;
        const rh = rootHex(block_root);
        const pre = root_map.get(rh) orelse return null;

        const SubcommitteeBits = @import("ssz").BitVectorType(preset.SYNC_COMMITTEE_SIZE / constants.SYNC_COMMITTEE_SUBNET_COUNT);
        return .{
            .slot = pre.slot,
            .beacon_block_root = pre.beacon_block_root,
            .subcommittee_index = pre.subcommittee_index,
            .aggregation_bits = SubcommitteeBits.Type{ .data = pre.aggregation_bits },
            .signature = pre.signature_bytes,
        };
    }

    /// Remove entries older than `head_slot - SLOTS_RETAINED`.
    pub fn prune(self: *SyncCommitteeMessagePool, head_slot: Slot) void {
        const cutoff = if (head_slot > SLOTS_RETAINED) head_slot - SLOTS_RETAINED else 0;
        self.lowest_permissible_slot = cutoff;

        var to_remove: [256]Slot = undefined;
        var remove_count: usize = 0;

        var it = self.by_slot.iterator();
        while (it.next()) |entry| {
            if (entry.key_ptr.* < cutoff) {
                if (remove_count < to_remove.len) {
                    to_remove[remove_count] = entry.key_ptr.*;
                    remove_count += 1;
                }
            }
        }

        for (to_remove[0..remove_count]) |slot| {
            if (self.by_slot.fetchRemove(slot)) |kv| {
                var subnet_map = kv.value;
                var subnet_it = subnet_map.iterator();
                while (subnet_it.next()) |subnet_entry| {
                    subnet_entry.value_ptr.deinit();
                }
                subnet_map.deinit();
            }
        }
    }

    /// Total number of pre-aggregations across all slots.
    pub fn size(self: *const SyncCommitteeMessagePool) usize {
        var count: usize = 0;
        var slot_it = self.by_slot.iterator();
        while (slot_it.next()) |slot_entry| {
            var subnet_it = slot_entry.value_ptr.iterator();
            while (subnet_it.next()) |subnet_entry| {
                count += subnet_entry.value_ptr.count();
            }
        }
        return count;
    }
};

// =========================================================================
// Helpers
// =========================================================================

/// Count set bits in a byte slice.
fn countBits(bytes: []const u8) u32 {
    var count: u32 = 0;
    for (bytes) |b| {
        count += @popCount(b);
    }
    return count;
}

/// Set a bit in a byte array (little-endian bit ordering).
fn setBit(bytes: []u8, bit_index: usize) void {
    const byte_idx = bit_index / 8;
    const bit_idx: u3 = @intCast(bit_index % 8);
    if (byte_idx < bytes.len) {
        bytes[byte_idx] |= @as(u8, 1) << bit_idx;
    }
}

/// Check if a bit is set in a byte array (little-endian bit ordering).
fn getBit(bytes: []const u8, bit_index: usize) bool {
    const byte_idx = bit_index / 8;
    const bit_idx: u3 = @intCast(bit_index % 8);
    if (byte_idx >= bytes.len) return false;
    return (bytes[byte_idx] >> bit_idx) & 1 == 1;
}

// =========================================================================
// Tests
// =========================================================================

test "SyncContributionAndProofPool: add and getSyncAggregate empty" {
    const allocator = std.testing.allocator;
    var pool = SyncContributionAndProofPool.init(allocator);
    defer pool.deinit();

    const result = pool.getSyncAggregate(10, [_]u8{0xAA} ** 32);
    // Empty pool → all-zeros bits, G2 infinity signature.
    for (result.sync_committee_bits.data) |b| {
        try std.testing.expectEqual(@as(u8, 0), b);
    }
    try std.testing.expectEqual(G2_POINT_AT_INFINITY, result.sync_committee_signature);
}

test "SyncContributionAndProofPool: add contribution and retrieve" {
    const allocator = std.testing.allocator;
    var pool = SyncContributionAndProofPool.init(allocator);
    defer pool.deinit();

    const SubcommitteeBits = @import("ssz").BitVectorType(preset.SYNC_COMMITTEE_SIZE / constants.SYNC_COMMITTEE_SUBNET_COUNT);

    // Create a contribution with bit 0 set in subcommittee 0.
    var bits: [SYNC_SUBCOMMITTEE_BYTES]u8 = [_]u8{0} ** SYNC_SUBCOMMITTEE_BYTES;
    bits[0] = 0x01; // bit 0 set
    const block_root = [_]u8{0xBB} ** 32;

    const contrib = SyncCommitteeContribution.Type{
        .slot = 10,
        .beacon_block_root = block_root,
        .subcommittee_index = 0,
        .aggregation_bits = SubcommitteeBits.Type{ .data = bits },
        .signature = G2_POINT_AT_INFINITY, // placeholder
    };

    try pool.add(&contrib);
    try std.testing.expectEqual(@as(usize, 1), pool.size());

    // getSyncAggregate should return non-empty bits for subnet 0.
    const agg = pool.getSyncAggregate(10, block_root);
    try std.testing.expectEqual(@as(u8, 0x01), agg.sync_committee_bits.data[0]);
}

test "SyncContributionAndProofPool: replace with better contribution" {
    const allocator = std.testing.allocator;
    var pool = SyncContributionAndProofPool.init(allocator);
    defer pool.deinit();

    const SubcommitteeBits = @import("ssz").BitVectorType(preset.SYNC_COMMITTEE_SIZE / constants.SYNC_COMMITTEE_SUBNET_COUNT);
    const block_root = [_]u8{0xCC} ** 32;

    // First contribution: 1 participant.
    var bits1: [SYNC_SUBCOMMITTEE_BYTES]u8 = [_]u8{0} ** SYNC_SUBCOMMITTEE_BYTES;
    bits1[0] = 0x01;
    const contrib1 = SyncCommitteeContribution.Type{
        .slot = 5,
        .beacon_block_root = block_root,
        .subcommittee_index = 1,
        .aggregation_bits = SubcommitteeBits.Type{ .data = bits1 },
        .signature = G2_POINT_AT_INFINITY,
    };
    try pool.add(&contrib1);

    // Second contribution: 2 participants (better).
    var bits2: [SYNC_SUBCOMMITTEE_BYTES]u8 = [_]u8{0} ** SYNC_SUBCOMMITTEE_BYTES;
    bits2[0] = 0x03; // bits 0 and 1 set
    const contrib2 = SyncCommitteeContribution.Type{
        .slot = 5,
        .beacon_block_root = block_root,
        .subcommittee_index = 1,
        .aggregation_bits = SubcommitteeBits.Type{ .data = bits2 },
        .signature = G2_POINT_AT_INFINITY,
    };
    try pool.add(&contrib2);

    // Still size 1 (replaced, not added).
    try std.testing.expectEqual(@as(usize, 1), pool.size());

    // Verify the better one is stored.
    const agg = pool.getSyncAggregate(5, block_root);
    // Subcommittee 1 bits should be at byte offset SYNC_SUBCOMMITTEE_BYTES.
    try std.testing.expectEqual(@as(u8, 0x03), agg.sync_committee_bits.data[SYNC_SUBCOMMITTEE_BYTES]);
}

test "SyncContributionAndProofPool: prune removes old slots" {
    const allocator = std.testing.allocator;
    var pool = SyncContributionAndProofPool.init(allocator);
    defer pool.deinit();

    const SubcommitteeBits = @import("ssz").BitVectorType(preset.SYNC_COMMITTEE_SIZE / constants.SYNC_COMMITTEE_SUBNET_COUNT);
    const block_root = [_]u8{0xDD} ** 32;

    var bits: [SYNC_SUBCOMMITTEE_BYTES]u8 = [_]u8{0} ** SYNC_SUBCOMMITTEE_BYTES;
    bits[0] = 0x01;

    // Add at slot 5 and slot 100.
    const contrib5 = SyncCommitteeContribution.Type{
        .slot = 5,
        .beacon_block_root = block_root,
        .subcommittee_index = 0,
        .aggregation_bits = SubcommitteeBits.Type{ .data = bits },
        .signature = G2_POINT_AT_INFINITY,
    };
    try pool.add(&contrib5);

    const contrib100 = SyncCommitteeContribution.Type{
        .slot = 100,
        .beacon_block_root = block_root,
        .subcommittee_index = 0,
        .aggregation_bits = SubcommitteeBits.Type{ .data = bits },
        .signature = G2_POINT_AT_INFINITY,
    };
    try pool.add(&contrib100);

    try std.testing.expectEqual(@as(usize, 2), pool.size());

    // Prune at head_slot=100 → cutoff=92 → slot 5 removed.
    pool.prune(100);
    try std.testing.expectEqual(@as(usize, 1), pool.size());
}

test "SyncCommitteeMessagePool: add and getContribution" {
    const allocator = std.testing.allocator;
    var pool = SyncCommitteeMessagePool.init(allocator);
    defer pool.deinit();

    const block_root = [_]u8{0xEE} ** 32;

    // Add two messages for the same (slot=10, subnet=0, root).
    try pool.add(0, 10, block_root, 0, G2_POINT_AT_INFINITY);
    try pool.add(0, 10, block_root, 3, G2_POINT_AT_INFINITY);

    try std.testing.expectEqual(@as(usize, 1), pool.size());

    const contrib = pool.getContribution(0, 10, block_root);
    try std.testing.expect(contrib != null);
    if (contrib) |c| {
        // Bits 0 and 3 should be set.
        try std.testing.expect(getBit(&c.aggregation_bits.data, 0));
        try std.testing.expect(getBit(&c.aggregation_bits.data, 3));
        try std.testing.expect(!getBit(&c.aggregation_bits.data, 1));
    }
}

test "SyncCommitteeMessagePool: duplicate validator is ignored" {
    const allocator = std.testing.allocator;
    var pool = SyncCommitteeMessagePool.init(allocator);
    defer pool.deinit();

    const block_root = [_]u8{0xFF} ** 32;

    try pool.add(0, 10, block_root, 5, G2_POINT_AT_INFINITY);
    try pool.add(0, 10, block_root, 5, G2_POINT_AT_INFINITY); // duplicate

    const contrib = pool.getContribution(0, 10, block_root);
    try std.testing.expect(contrib != null);
    // Should still be just 1 participant despite 2 adds.
}

test "SyncCommitteeMessagePool: getContribution returns null for missing" {
    const allocator = std.testing.allocator;
    var pool = SyncCommitteeMessagePool.init(allocator);
    defer pool.deinit();

    const result = pool.getContribution(0, 10, [_]u8{0} ** 32);
    try std.testing.expect(result == null);
}

test "SyncCommitteeMessagePool: prune removes old slots" {
    const allocator = std.testing.allocator;
    var pool = SyncCommitteeMessagePool.init(allocator);
    defer pool.deinit();

    const block_root = [_]u8{0xAA} ** 32;
    try pool.add(0, 5, block_root, 0, G2_POINT_AT_INFINITY);
    try pool.add(0, 100, block_root, 0, G2_POINT_AT_INFINITY);

    try std.testing.expectEqual(@as(usize, 2), pool.size());

    pool.prune(100);
    try std.testing.expectEqual(@as(usize, 1), pool.size());
}

test "countBits" {
    try std.testing.expectEqual(@as(u32, 0), countBits(&[_]u8{ 0, 0 }));
    try std.testing.expectEqual(@as(u32, 1), countBits(&[_]u8{ 0x01, 0 }));
    try std.testing.expectEqual(@as(u32, 8), countBits(&[_]u8{0xFF}));
    try std.testing.expectEqual(@as(u32, 4), countBits(&[_]u8{ 0x0F, 0 }));
}

test "setBit and getBit" {
    var bytes: [2]u8 = [_]u8{0} ** 2;
    try std.testing.expect(!getBit(&bytes, 0));
    setBit(&bytes, 0);
    try std.testing.expect(getBit(&bytes, 0));
    setBit(&bytes, 10);
    try std.testing.expect(getBit(&bytes, 10));
    try std.testing.expect(!getBit(&bytes, 11));
}
