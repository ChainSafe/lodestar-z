//! Aggregated Attestation Pool
//!
//! An optimized attestation pool for block production that groups attestations
//! by their AttestationData root and aggregates bitlists to maximize coverage.
//!
//! Key concepts:
//! - Attestations with identical (source, target, head) are grouped together
//! - Within each group, non-overlapping attestations are merged (pre-aggregation)
//! - Block production uses a greedy algorithm: pick attestations covering the
//!   most NEW validator positions first
//! - Attestations older than 2 epochs are pruned
//!
//! This directly mirrors Lodestar TS: packages/beacon-node/src/chain/opPools/aggregatedAttestationPool.ts

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;
const state_transition = @import("state_transition");
const fork_types = @import("fork_types");

const Slot = types.primitive.Slot.Type;
const Epoch = types.primitive.Epoch.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;

const AttestationData = types.phase0.AttestationData;
const Phase0Attestation = types.phase0.Attestation;
const ElectraAttestation = types.electra.Attestation;
const AnyAttestation = fork_types.AnyAttestation;

const CachedBeaconState = state_transition.CachedBeaconState;
const computeEpochAtSlot = state_transition.computeEpochAtSlot;

// Max attestations retained per data-root group.
// Bounded to keep memory and CPU under control.
const MAX_RETAINED_PER_GROUP: usize = 4;

// ---------------------------------------------------------------------------
// InsertOutcome
// ---------------------------------------------------------------------------

pub const InsertOutcome = enum {
    /// Attestation was added as a new entry.
    NewData,
    /// Attestation was merged into an existing entry (bits OR-ed).
    Aggregated,
    /// Attestation is a subset of an existing entry — dropped.
    AlreadyKnown,
    /// Attestation is too old.
    Old,
};

// ---------------------------------------------------------------------------
// Bitlist helpers
// ---------------------------------------------------------------------------

/// Bitlist type for per-slot aggregation bits.
/// bit_len tracks the logical length; data stores the bytes.
const Bitlist = Phase0Attestation.Type.aggregation_bits;

/// Count set bits in a bitlist.
fn countBits(bits: []const u8) u32 {
    var count: u32 = 0;
    for (bits) |byte| {
        count += @popCount(byte);
    }
    return count;
}

/// Check whether `a` is a subset of `b` (all set bits in `a` are also set in `b`).
/// Both slices must have the same length.
fn isSubset(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |byte_a, byte_b| {
        if ((byte_a & byte_b) != byte_a) return false;
    }
    return true;
}

/// Returns true if `a` and `b` share no set bits.
fn isExclusive(a: []const u8, b: []const u8) bool {
    const min_len = @min(a.len, b.len);
    for (a[0..min_len], b[0..min_len]) |byte_a, byte_b| {
        if ((byte_a & byte_b) != 0) return false;
    }
    return true;
}

/// OR `src` bits into `dst` (in-place). Both must have the same length.
fn orBitsInto(dst: []u8, src: []const u8) void {
    const min_len = @min(dst.len, src.len);
    for (dst[0..min_len], src[0..min_len]) |*d, s| {
        d.* |= s;
    }
}

/// Count bits in `a` that are NOT set in `already_covered`.
fn countNewBits(a: []const u8, already_covered: []const u8) u32 {
    var count: u32 = 0;
    const min_len = @min(a.len, already_covered.len);
    for (a[0..min_len], already_covered[0..min_len]) |byte_a, byte_c| {
        count += @popCount(byte_a & ~byte_c);
    }
    // Any bits beyond `already_covered` length are all new
    if (a.len > already_covered.len) {
        for (a[already_covered.len..]) |byte_a| {
            count += @popCount(byte_a);
        }
    }
    return count;
}

// ---------------------------------------------------------------------------
// AttestationWithBits — pool entry
// ---------------------------------------------------------------------------

/// An attestation plus a cached bit count for fast sorting.
const AttestationEntry = struct {
    attestation: Phase0Attestation.Type,
    /// Cached count of set bits in aggregation_bits.
    bit_count: u32,

    fn deinit(self: *AttestationEntry, allocator: Allocator) void {
        self.attestation.aggregation_bits.data.deinit(allocator);
    }
};

// ---------------------------------------------------------------------------
// AttestationGroup
// ---------------------------------------------------------------------------

/// All attestations sharing the same AttestationData (same source + target + head + slot + index).
///
/// Internally pre-aggregates: when a new non-overlapping attestation arrives, it is merged
/// into an existing entry. Supersets replace subsets. Overlapping attestations are stored
/// separately (up to MAX_RETAINED_PER_GROUP).
pub const AttestationGroup = struct {
    allocator: Allocator,
    data: AttestationData.Type,
    entries: std.ArrayListUnmanaged(AttestationEntry),

    pub fn init(allocator: Allocator, data: AttestationData.Type) AttestationGroup {
        return .{
            .allocator = allocator,
            .data = data,
            .entries = .empty,
        };
    }

    pub fn deinit(self: *AttestationGroup) void {
        for (self.entries.items) |*entry| {
            entry.deinit(self.allocator);
        }
        self.entries.deinit(self.allocator);
    }

    /// Add an attestation to this group.
    ///
    /// Pre-aggregation strategy (mirrors Lodestar TS MatchingDataAttestationGroup.add):
    /// 1. If new bits ⊆ existing: drop (AlreadyKnown)
    /// 2. If existing ⊆ new bits: remove existing, continue
    /// 3. If exclusive: merge bits into existing (Aggregated)
    /// 4. Otherwise (partial overlap): store separately
    pub fn add(self: *AttestationGroup, attestation: Phase0Attestation.Type) !InsertOutcome {
        const new_bytes = attestation.aggregation_bits.data.items;
        const new_bits = countBits(new_bytes);

        // Indices to remove (existing entries subsumed by new attestation)
        var to_remove = std.ArrayListUnmanaged(usize).empty;
        defer to_remove.deinit(self.allocator);

        for (self.entries.items, 0..) |*entry, i| {
            const existing_bytes = entry.attestation.aggregation_bits.data.items;

            // Case 1: new is subset of existing → drop
            if (isSubset(new_bytes, existing_bytes)) {
                return .AlreadyKnown;
            }

            // Case 2: existing is subset of new → mark for removal
            if (isSubset(existing_bytes, new_bytes)) {
                try to_remove.append(self.allocator, i);
                continue;
            }

            // Case 3: exclusive — store separately until BLS sig aggregation is implemented.
            // Merging aggregation_bits without aggregating the BLS signature produces an
            // invalid attestation that will fail verification on block proposal.
            // TODO: implement BLS aggregate_signatures() via blst bindings, then re-enable
            // actual aggregation (OR bits + aggregate sigs).
            // For now, exclusive attestations are stored as separate entries and the
            // greedy selector in getAttestationsForBlock picks the best coverage.
            if (isExclusive(new_bytes, existing_bytes)) {
                continue;
            }
        }

        // Remove subsumed entries (in reverse order to preserve indices)
        var idx: usize = to_remove.items.len;
        while (idx > 0) {
            idx -= 1;
            const i = to_remove.items[idx];
            var removed = self.entries.swapRemove(i);
            removed.deinit(self.allocator);
        }

        // Clone the attestation before storing
        const cloned = try cloneAttestation(self.allocator, attestation);
        const entry = AttestationEntry{
            .attestation = cloned,
            .bit_count = new_bits,
        };
        try self.entries.append(self.allocator, entry);

        // Trim to MAX_RETAINED_PER_GROUP (keep highest bit counts)
        if (self.entries.items.len > MAX_RETAINED_PER_GROUP) {
            // Sort descending by bit_count, drop the tail
            std.sort.pdq(AttestationEntry, self.entries.items, {}, struct {
                fn lessThan(_: void, a: AttestationEntry, b: AttestationEntry) bool {
                    return a.bit_count > b.bit_count;
                }
            }.lessThan);
            var tail_idx: usize = MAX_RETAINED_PER_GROUP;
            while (tail_idx < self.entries.items.len) {
                self.entries.items[tail_idx].deinit(self.allocator);
                tail_idx += 1;
            }
            self.entries.shrinkRetainingCapacity(MAX_RETAINED_PER_GROUP);
        }

        return .NewData;
    }

    /// Get the single best aggregate (most bits set). For GET /validator/aggregate_attestation.
    pub fn getBestAggregate(self: *const AttestationGroup) ?Phase0Attestation.Type {
        if (self.entries.items.len == 0) return null;
        var best_idx: usize = 0;
        var best_count: u32 = 0;
        for (self.entries.items, 0..) |*entry, i| {
            if (entry.bit_count > best_count) {
                best_count = entry.bit_count;
                best_idx = i;
            }
        }
        return self.entries.items[best_idx].attestation;
    }

    /// Greedy selection for block production.
    ///
    /// Selects attestations from this group that cover the most new validator
    /// positions not already in `already_covered`. Updates `already_covered`
    /// in-place as bits are selected.
    ///
    /// Returns a slice of Phase0Attestation references into our storage.
    /// The `out` ArrayList receives the selected attestations (caller owns the list).
    pub fn greedySelect(
        self: *const AttestationGroup,
        allocator: Allocator,
        already_covered: []u8,
        max: u32,
        out: *std.ArrayListUnmanaged(Phase0Attestation.Type),
    ) !void {
        var remaining: u32 = max;
        // Clone already_covered so we can track within this group too
        var local_covered = try allocator.dupe(u8, already_covered);
        defer allocator.free(local_covered);

        while (remaining > 0) {
            // Find the entry with the most new bits
            var best_idx: ?usize = null;
            var best_new_bits: u32 = 0;

            for (self.entries.items, 0..) |*entry, i| {
                const new_bits = countNewBits(entry.attestation.aggregation_bits.data.items, local_covered);
                if (new_bits > best_new_bits) {
                    best_new_bits = new_bits;
                    best_idx = i;
                }
            }

            if (best_idx == null or best_new_bits == 0) break;

            const best = &self.entries.items[best_idx.?];
            try out.append(allocator, best.attestation);

            // Update local_covered
            const bits = best.attestation.aggregation_bits.data.items;
            const min_len = @min(bits.len, local_covered.len);
            for (local_covered[0..min_len], bits[0..min_len]) |*c, b| {
                c.* |= b;
            }

            remaining -= 1;
        }

        // Also update the caller's already_covered for cross-group tracking
        const min_len = @min(already_covered.len, local_covered.len);
        @memcpy(already_covered[0..min_len], local_covered[0..min_len]);
    }

    pub fn count(self: *const AttestationGroup) usize {
        return self.entries.items.len;
    }

    /// Total bit coverage across all entries (rough measure of validator coverage).
    pub fn totalBits(self: *const AttestationGroup) u32 {
        var total: u32 = 0;
        for (self.entries.items) |*entry| {
            total += entry.bit_count;
        }
        return total;
    }
};

// ---------------------------------------------------------------------------
// AggregatedAttestationPool
// ---------------------------------------------------------------------------

/// Optimized attestation pool for block production.
///
/// Attestations are indexed by:
///   slot → data_root → AttestationGroup
///
/// This matches the TS Lodestar structure exactly.
pub const AggregatedAttestationPool = struct {
    allocator: Allocator,

    /// Outer map: slot → inner map
    by_slot: std.AutoHashMap(Slot, SlotMap),

    /// Lowest permissible slot. Attestations older than this are rejected.
    lowest_permissible_slot: Slot,

    const SlotMap = std.AutoHashMap([32]u8, AttestationGroup);

    pub fn init(allocator: Allocator) AggregatedAttestationPool {
        return .{
            .allocator = allocator,
            .by_slot = std.AutoHashMap(Slot, SlotMap).init(allocator),
            .lowest_permissible_slot = 0,
        };
    }

    pub fn deinit(self: *AggregatedAttestationPool) void {
        var it = self.by_slot.iterator();
        while (it.next()) |slot_entry| {
            var group_it = slot_entry.value_ptr.iterator();
            while (group_it.next()) |group_entry| {
                group_entry.value_ptr.deinit();
            }
            slot_entry.value_ptr.deinit();
        }
        self.by_slot.deinit();
    }

    /// Add an attestation (from gossip or block).
    ///
    /// Returns InsertOutcome describing what happened.
    pub fn add(self: *AggregatedAttestationPool, attestation: Phase0Attestation.Type) !InsertOutcome {
        const slot = attestation.data.slot;

        if (slot < self.lowest_permissible_slot) {
            return .Old;
        }

        // Compute data root
        var data_root: [32]u8 = undefined;
        try AttestationData.hashTreeRoot(&attestation.data, &data_root);

        // Get or create slot map
        const slot_gop = try self.by_slot.getOrPut(slot);
        if (!slot_gop.found_existing) {
            slot_gop.value_ptr.* = SlotMap.init(self.allocator);
        }

        // Get or create group
        const group_gop = try slot_gop.value_ptr.getOrPut(data_root);
        if (!group_gop.found_existing) {
            group_gop.value_ptr.* = AttestationGroup.init(self.allocator, attestation.data);
        }

        return group_gop.value_ptr.add(attestation);
    }

    /// Add an attestation in any fork format.
    pub fn addAny(self: *AggregatedAttestationPool, attestation: AnyAttestation) !InsertOutcome {
        return switch (attestation) {
            .phase0 => |att| self.add(att),
            .electra => |att| self.addElectra(att),
        };
    }

    /// Add an Electra-format attestation.
    ///
    /// Electra attestations use committee_bits to identify the committee(s)
    /// and have wider aggregation_bits spanning all committees in the slot.
    /// We convert to phase0 format for storage (extracting committee index
    /// from committee_bits) since the pool grouping is by AttestationData root.
    pub fn addElectra(self: *AggregatedAttestationPool, attestation: ElectraAttestation.Type) !InsertOutcome {
        const slot = attestation.data.slot;
        if (slot < self.lowest_permissible_slot) {
            return .Old;
        }

        // For Electra, data.index is always 0.  Extract the real committee
        // index from committee_bits and set it in the data for hashing,
        // so attestations for different committees get different data roots.
        var modified_data = attestation.data;
        var committee_index: u64 = 0;
        for (0..preset.MAX_COMMITTEES_PER_SLOT) |i| {
            if (attestation.committee_bits.get(i) catch false) {
                committee_index = @intCast(i);
                break;
            }
        }
        modified_data.index = committee_index;

        var data_root: [32]u8 = undefined;
        try AttestationData.hashTreeRoot(&modified_data, &data_root);

        const slot_gop = try self.by_slot.getOrPut(slot);
        if (!slot_gop.found_existing) {
            slot_gop.value_ptr.* = SlotMap.init(self.allocator);
        }

        const group_gop = try slot_gop.value_ptr.getOrPut(data_root);
        if (!group_gop.found_existing) {
            group_gop.value_ptr.* = AttestationGroup.init(self.allocator, modified_data);
        }

        // Convert to phase0 format for the group.
        const src = attestation.aggregation_bits.data.items;
        var new_data: std.ArrayListUnmanaged(u8) = .empty;
        if (src.len > 0) {
            new_data = try std.ArrayListUnmanaged(u8).initCapacity(self.allocator, src.len);
            new_data.appendSliceAssumeCapacity(src);
        }

        const phase0_att = Phase0Attestation.Type{
            .aggregation_bits = .{ .data = new_data, .bit_len = attestation.aggregation_bits.bit_len },
            .data = modified_data,
            .signature = attestation.signature,
        };
        return group_gop.value_ptr.add(phase0_att);
    }

    /// Get the best attestations for block production.
    ///
    /// Returns up to `max_attestations`, greedily selected for maximum coverage.
    /// Considers attestations from the current epoch and previous epoch only
    /// (inclusion delay of 1 slot minimum).
    ///
    /// The `state_slot` parameter is the slot of the block being produced.
    /// Caller owns the returned slice.
    pub fn getAttestationsForBlock(
        self: *AggregatedAttestationPool,
        allocator: Allocator,
        state_slot: Slot,
        max_attestations: u32,
    ) ![]Phase0Attestation.Type {
        if (max_attestations == 0) return allocator.alloc(Phase0Attestation.Type, 0);

        const state_epoch = computeEpochAtSlot(state_slot);
        const prev_epoch = if (state_epoch > 0) state_epoch - 1 else 0;

        // Collect (group_total_bits, slot, data_root) for sorting
        const GroupRef = struct {
            total_bits: u32,
            slot: Slot,
            data_root: [32]u8,
        };

        var group_refs = std.ArrayListUnmanaged(GroupRef).empty;
        defer group_refs.deinit(allocator);

        var slot_it = self.by_slot.iterator();
        while (slot_it.next()) |slot_entry| {
            const att_slot = slot_entry.key_ptr.*;
            const att_epoch = computeEpochAtSlot(att_slot);

            // Only valid slots: current epoch or previous epoch
            if (att_epoch != state_epoch and att_epoch != prev_epoch) continue;
            // Inclusion delay: attestation must be from before current slot
            if (att_slot >= state_slot) continue;

            var group_it = slot_entry.value_ptr.iterator();
            while (group_it.next()) |group_entry| {
                try group_refs.append(allocator, .{
                    .total_bits = group_entry.value_ptr.totalBits(),
                    .slot = att_slot,
                    .data_root = group_entry.key_ptr.*,
                });
            }
        }

        // Sort by total_bits descending (most coverage first)
        std.sort.pdq(GroupRef, group_refs.items, {}, struct {
            fn lessThan(_: void, a: GroupRef, b: GroupRef) bool {
                return a.total_bits > b.total_bits;
            }
        }.lessThan);

        // Greedy selection across groups
        var result = std.ArrayListUnmanaged(Phase0Attestation.Type).empty;
        errdefer result.deinit(allocator);

        // Track coverage per committee (slot+index) using a simple bitset.
        // We use a dynamically sized buffer; MAX_VALIDATORS_PER_COMMITTEE / 8 bytes per slot-committee.
        // For simplicity, use a HashMap from (slot, committee_index) → covered_bytes.
        const CoverageKey = struct { slot: Slot, index: u64 };
        var coverage = std.HashMap(CoverageKey, []u8, struct {
            pub fn hash(_: @This(), k: CoverageKey) u64 {
                return k.slot *% 0x9e3779b97f4a7c15 +% k.index;
            }
            pub fn eql(_: @This(), a: CoverageKey, b: CoverageKey) bool {
                return a.slot == b.slot and a.index == b.index;
            }
        }, std.hash_map.default_max_load_percentage).init(allocator);
        defer {
            var cov_it = coverage.iterator();
            while (cov_it.next()) |entry| {
                allocator.free(entry.value_ptr.*);
            }
            coverage.deinit();
        }

        for (group_refs.items) |ref| {
            if (result.items.len >= max_attestations) break;

            const slot_map = self.by_slot.getPtr(ref.slot) orelse continue;
            const group = slot_map.getPtr(ref.data_root) orelse continue;

            const committee_index = group.data.index;
            const cov_key = CoverageKey{ .slot = ref.slot, .index = committee_index };

            // Get or create coverage buffer for this (slot, committee_index)
            const cov_gop = try coverage.getOrPut(cov_key);
            if (!cov_gop.found_existing) {
                // Allocate a zero buffer sized for MAX_VALIDATORS_PER_COMMITTEE bits
                const byte_len = (preset.MAX_VALIDATORS_PER_COMMITTEE + 7) / 8;
                const buf = try allocator.alloc(u8, byte_len);
                @memset(buf, 0);
                cov_gop.value_ptr.* = buf;
            }
            const covered = cov_gop.value_ptr.*;

            const remaining = max_attestations - @as(u32, @intCast(result.items.len));
            try group.greedySelect(allocator, covered, remaining, &result);
        }

        return result.toOwnedSlice(allocator);
    }

    /// Remove attestations older than `min_slot`.
    pub fn prune(self: *AggregatedAttestationPool, min_slot: Slot) void {
        var slots_to_remove = std.ArrayListUnmanaged(Slot).empty;
        defer slots_to_remove.deinit(self.allocator);

        var it = self.by_slot.iterator();
        while (it.next()) |entry| {
            if (entry.key_ptr.* < min_slot) {
                slots_to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (slots_to_remove.items) |slot| {
            if (self.by_slot.getPtr(slot)) |slot_map| {
                var group_it = slot_map.iterator();
                while (group_it.next()) |group_entry| {
                    group_entry.value_ptr.deinit();
                }
                slot_map.deinit();
            }
            _ = self.by_slot.remove(slot);
        }

        self.lowest_permissible_slot = min_slot;
    }

    /// Prune attestations based on the current clock slot.
    ///
    /// Retains attestations from the current and previous epoch only.
    pub fn pruneBySlot(self: *AggregatedAttestationPool, clock_slot: Slot) void {
        const epoch = computeEpochAtSlot(clock_slot);
        const min_slot: Slot = if (epoch > 1)
            epoch * preset.SLOTS_PER_EPOCH - preset.SLOTS_PER_EPOCH
        else
            0;
        self.prune(min_slot);
    }

    /// Get the best aggregate for a specific data root (for GET /validator/aggregate_attestation).
    ///
    /// `data_root` is the hash-tree-root of the AttestationData.
    pub fn getAggregate(self: *AggregatedAttestationPool, slot: Slot, data_root: [32]u8) ?Phase0Attestation.Type {
        const slot_map = self.by_slot.getPtr(slot) orelse return null;
        const group = slot_map.getPtr(data_root) orelse return null;
        return group.getBestAggregate();
    }

    /// Total number of groups across all slots.
    pub fn groupCount(self: *const AggregatedAttestationPool) usize {
        var count: usize = 0;
        var it = self.by_slot.iterator();
        while (it.next()) |entry| {
            count += entry.value_ptr.count();
        }
        return count;
    }

    /// Total number of attestation entries across all groups.
    pub fn entryCount(self: *const AggregatedAttestationPool) usize {
        var count: usize = 0;
        var it = self.by_slot.iterator();
        while (it.next()) |slot_entry| {
            var group_it = slot_entry.value_ptr.iterator();
            while (group_it.next()) |group_entry| {
                count += group_entry.value_ptr.count();
            }
        }
        return count;
    }
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Clone a Phase0Attestation, duplicating the aggregation_bits data.
fn cloneAttestation(allocator: Allocator, att: Phase0Attestation.Type) !Phase0Attestation.Type {
    var cloned = att;
    const src = att.aggregation_bits.data.items;
    var new_data = try std.ArrayListUnmanaged(u8).initCapacity(allocator, src.len);
    new_data.appendSliceAssumeCapacity(src);
    cloned.aggregation_bits.data = new_data;
    return cloned;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn makeTestAttAlloc(allocator: Allocator, slot: Slot, index: u64, bits: []const u8, bit_len: usize) !Phase0Attestation.Type {
    var list = try std.ArrayListUnmanaged(u8).initCapacity(allocator, bits.len);
    list.appendSliceAssumeCapacity(bits);
    return .{
        .aggregation_bits = .{
            .data = list,
            .bit_len = bit_len,
        },
        .data = .{
            .slot = slot,
            .index = index,
            .beacon_block_root = [_]u8{0} ** 32,
            .source = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
            .target = .{ .epoch = @divFloor(slot, preset.SLOTS_PER_EPOCH), .root = [_]u8{0} ** 32 },
        },
        .signature = [_]u8{0} ** 96,
    };
}

fn freeTestAtt(allocator: Allocator, att: *Phase0Attestation.Type) void {
    att.aggregation_bits.data.deinit(allocator);
}

test "AggregatedAttestationPool: add single attestation" {
    const allocator = std.testing.allocator;
    var pool = AggregatedAttestationPool.init(allocator);
    defer pool.deinit();

    var att = try makeTestAttAlloc(allocator, 10, 0, &[_]u8{0b00000001}, 8);
    defer freeTestAtt(allocator, &att);

    const outcome = try pool.add(att);
    try std.testing.expectEqual(InsertOutcome.NewData, outcome);
    try std.testing.expectEqual(@as(usize, 1), pool.groupCount());
    try std.testing.expectEqual(@as(usize, 1), pool.entryCount());
}

test "AggregatedAttestationPool: add duplicate is AlreadyKnown" {
    const allocator = std.testing.allocator;
    var pool = AggregatedAttestationPool.init(allocator);
    defer pool.deinit();

    var att1 = try makeTestAttAlloc(allocator, 10, 0, &[_]u8{0b00000011}, 8);
    defer freeTestAtt(allocator, &att1);
    var att2 = try makeTestAttAlloc(allocator, 10, 0, &[_]u8{0b00000001}, 8);
    defer freeTestAtt(allocator, &att2);

    _ = try pool.add(att1);
    const outcome = try pool.add(att2);
    try std.testing.expectEqual(InsertOutcome.AlreadyKnown, outcome);
    try std.testing.expectEqual(@as(usize, 1), pool.entryCount());
}

test "AggregatedAttestationPool: exclusive attestations stored separately" {
    const allocator = std.testing.allocator;
    var pool = AggregatedAttestationPool.init(allocator);
    defer pool.deinit();

    // Validator 0 attests
    var att1 = try makeTestAttAlloc(allocator, 10, 0, &[_]u8{0b00000001}, 8);
    defer freeTestAtt(allocator, &att1);
    // Validator 1 attests (exclusive)
    var att2 = try makeTestAttAlloc(allocator, 10, 0, &[_]u8{0b00000010}, 8);
    defer freeTestAtt(allocator, &att2);

    _ = try pool.add(att1);
    const outcome = try pool.add(att2);
    // Without BLS signature aggregation, exclusive attestations are stored as
    // separate entries (NewData). Once BLS aggregate_signatures is implemented,
    // they should be merged and the outcome should be Aggregated.
    try std.testing.expectEqual(InsertOutcome.NewData, outcome);
    // Two separate entries (not merged — BLS aggregation not yet available)
    try std.testing.expectEqual(@as(usize, 2), pool.entryCount());
}

test "AggregatedAttestationPool: superset replaces subset" {
    const allocator = std.testing.allocator;
    var pool = AggregatedAttestationPool.init(allocator);
    defer pool.deinit();

    var att1 = try makeTestAttAlloc(allocator, 10, 0, &[_]u8{0b00000001}, 8);
    defer freeTestAtt(allocator, &att1);
    // Superset: includes validator 0 + more
    var att2 = try makeTestAttAlloc(allocator, 10, 0, &[_]u8{0b00000111}, 8);
    defer freeTestAtt(allocator, &att2);

    _ = try pool.add(att1);
    const outcome = try pool.add(att2);
    try std.testing.expectEqual(InsertOutcome.NewData, outcome);
    // Subsumed entry removed, new one added
    try std.testing.expectEqual(@as(usize, 1), pool.entryCount());

    var data_root: [32]u8 = undefined;
    try AttestationData.hashTreeRoot(&att1.data, &data_root);
    const best = pool.getAggregate(10, data_root).?;
    try std.testing.expectEqual(@as(u32, 3), countBits(best.aggregation_bits.data.items));
}

test "AggregatedAttestationPool: prune removes old attestations" {
    const allocator = std.testing.allocator;
    var pool = AggregatedAttestationPool.init(allocator);
    defer pool.deinit();

    var att5 = try makeTestAttAlloc(allocator, 5, 0, &[_]u8{0b00000001}, 8);
    defer freeTestAtt(allocator, &att5);
    var att100 = try makeTestAttAlloc(allocator, 100, 0, &[_]u8{0b00000001}, 8);
    defer freeTestAtt(allocator, &att100);

    _ = try pool.add(att5);
    _ = try pool.add(att100);
    try std.testing.expectEqual(@as(usize, 2), pool.groupCount());

    pool.prune(50);
    try std.testing.expectEqual(@as(usize, 1), pool.groupCount());

    // New attestations at slot 5 should be rejected as Old
    var att5b = try makeTestAttAlloc(allocator, 5, 0, &[_]u8{0b00000010}, 8);
    defer freeTestAtt(allocator, &att5b);
    const outcome = try pool.add(att5b);
    try std.testing.expectEqual(InsertOutcome.Old, outcome);
}

test "AggregatedAttestationPool: getAttestationsForBlock greedy" {
    const allocator = std.testing.allocator;
    var pool = AggregatedAttestationPool.init(allocator);
    defer pool.deinit();

    // Slot 10 is in epoch 0 (SLOTS_PER_EPOCH = 8 for minimal preset, 32 for mainnet)
    // We produce at slot 11 so attestations from slot 10 are eligible
    // Use different committee indices so they don't merge

    // Committee 0: validators 0-3 attested
    var att0 = try makeTestAttAlloc(allocator, 10, 0, &[_]u8{0b00001111}, 8);
    defer freeTestAtt(allocator, &att0);
    // Committee 1: validators 0-1 attested
    var att1 = try makeTestAttAlloc(allocator, 10, 1, &[_]u8{0b00000011}, 8);
    defer freeTestAtt(allocator, &att1);

    _ = try pool.add(att0);
    _ = try pool.add(att1);

    const selected = try pool.getAttestationsForBlock(allocator, 11, 10);
    defer allocator.free(selected);

    // Should get both attestations (different committees = different groups)
    try std.testing.expectEqual(@as(usize, 2), selected.len);
}

test "AggregatedAttestationPool: getAttestationsForBlock respects max" {
    const allocator = std.testing.allocator;
    var pool = AggregatedAttestationPool.init(allocator);
    defer pool.deinit();

    // Add 5 attestations from different committees
    for (0..5) |i| {
        var att = try makeTestAttAlloc(allocator, 10, @intCast(i), &[_]u8{0b00000001}, 8);
        defer freeTestAtt(allocator, &att);
        _ = try pool.add(att);
    }

    const selected = try pool.getAttestationsForBlock(allocator, 11, 2);
    defer allocator.free(selected);

    try std.testing.expect(selected.len <= 2);
}

test "AggregatedAttestationPool: old attestations not returned for block" {
    const allocator = std.testing.allocator;
    var pool = AggregatedAttestationPool.init(allocator);
    defer pool.deinit();

    // Add a very old attestation (epoch 0) and current one
    const current_slot: Slot = 3 * preset.SLOTS_PER_EPOCH;
    const old_slot: Slot = 0;
    const current_epoch_slot: Slot = current_slot - 1;

    var old_att = try makeTestAttAlloc(allocator, old_slot, 0, &[_]u8{0b11111111}, 8);
    defer freeTestAtt(allocator, &old_att);
    var curr_att = try makeTestAttAlloc(allocator, current_epoch_slot, 1, &[_]u8{0b11111111}, 8);
    defer freeTestAtt(allocator, &curr_att);

    _ = try pool.add(old_att);
    _ = try pool.add(curr_att);

    const selected = try pool.getAttestationsForBlock(allocator, current_slot, 10);
    defer allocator.free(selected);

    // Only the current-epoch attestation should be selected
    try std.testing.expectEqual(@as(usize, 1), selected.len);
    try std.testing.expectEqual(current_epoch_slot, selected[0].data.slot);
}

test "AggregatedAttestationPool: getAggregate returns best" {
    const allocator = std.testing.allocator;
    var pool = AggregatedAttestationPool.init(allocator);
    defer pool.deinit();

    // Add a superset attestation — bits 0,1,2 set
    var att1 = try makeTestAttAlloc(allocator, 10, 0, &[_]u8{0b00000111}, 8);
    defer freeTestAtt(allocator, &att1);
    // Add a subset attestation — only bit 0 set
    var att2 = try makeTestAttAlloc(allocator, 10, 0, &[_]u8{0b00000001}, 8);
    defer freeTestAtt(allocator, &att2);

    _ = try pool.add(att1);
    _ = try pool.add(att2);

    var data_root: [32]u8 = undefined;
    try AttestationData.hashTreeRoot(&att1.data, &data_root);

    const best = pool.getAggregate(10, data_root);
    try std.testing.expect(best != null);
    // Best should have 3 bits (the superset)
    try std.testing.expectEqual(@as(u32, 3), countBits(best.?.aggregation_bits.data.items));
}
