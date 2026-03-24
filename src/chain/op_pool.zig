//! Operation pools for pending consensus-layer operations.
//!
//! Maintains pools of attestations, voluntary exits, proposer slashings,
//! attester slashings, and BLS-to-execution changes waiting to be included
//! in beacon blocks.
//!
//! The `AttestationPool` is the most complex — it groups attestations by
//! `AttestationData` hash and supports best-selection for block packing
//! and slot-based pruning.  The remaining pools deduplicate by a natural
//! key (validator index, slashing root, etc.) and return pending items up
//! to the per-block maximum.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;

const Slot = types.primitive.Slot.Type;
const Epoch = types.primitive.Epoch.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;

const AttestationData = types.phase0.AttestationData;
const Phase0Attestation = types.phase0.Attestation;
const ProposerSlashing = types.phase0.ProposerSlashing;
const SignedVoluntaryExit = types.phase0.SignedVoluntaryExit;

const capella = @import("consensus_types").capella;
const SignedBLSToExecutionChange = capella.SignedBLSToExecutionChange;

// ---------------------------------------------------------------------------
// AttestationPool
// ---------------------------------------------------------------------------

/// Pool of pending attestations keyed by `AttestationData` hash.
///
/// Attestations with identical data are stored together so they can be
/// selected for block inclusion.  `getForBlock` picks the groups with the
/// most entries (rough proxy for coverage) up to `max_attestations`.
pub const AttestationPool = struct {
    allocator: Allocator,
    pool: std.AutoHashMap([32]u8, std.ArrayListUnmanaged(Phase0Attestation.Type)),

    pub fn init(allocator: Allocator) AttestationPool {
        return .{
            .allocator = allocator,
            .pool = std.AutoHashMap([32]u8, std.ArrayListUnmanaged(Phase0Attestation.Type)).init(allocator),
        };
    }

    pub fn deinit(self: *AttestationPool) void {
        var it = self.pool.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |*att| {
                att.aggregation_bits.data.deinit(self.allocator);
            }
            entry.value_ptr.deinit(self.allocator);
        }
        self.pool.deinit();
    }

    /// Add an attestation to the pool.
    ///
    /// Grouped by hash-tree-root of `AttestationData`.
    pub fn add(self: *AttestationPool, attestation: Phase0Attestation.Type) !void {
        var data_root: [32]u8 = undefined;
        try AttestationData.hashTreeRoot(&attestation.data, &data_root);

        const gop = try self.pool.getOrPut(data_root);
        if (!gop.found_existing) {
            gop.value_ptr.* = std.ArrayListUnmanaged(Phase0Attestation.Type).empty;
        }

        // Clone aggregation bits so the pool owns the memory.
        var cloned = attestation;
        const src = attestation.aggregation_bits.data.items;
        if (src.len > 0) {
            var new_data = try std.ArrayListUnmanaged(u8).initCapacity(self.allocator, src.len);
            new_data.appendSliceAssumeCapacity(src);
            cloned.aggregation_bits.data = new_data;
        } else {
            cloned.aggregation_bits.data = std.ArrayListUnmanaged(u8).empty;
        }
        try gop.value_ptr.append(self.allocator, cloned);
    }

    /// Select the best attestations for block inclusion.
    ///
    /// Returns up to `max_attestations` entries.  Caller owns the returned
    /// slice.
    pub fn getForBlock(self: *AttestationPool, allocator: Allocator, max_attestations: u32) ![]Phase0Attestation.Type {
        const Group = struct {
            key: [32]u8,
            len: usize,
        };
        var groups = std.ArrayListUnmanaged(Group).empty;
        defer groups.deinit(allocator);

        var it = self.pool.iterator();
        while (it.next()) |entry| {
            try groups.append(allocator, .{
                .key = entry.key_ptr.*,
                .len = entry.value_ptr.items.len,
            });
        }

        // Sort descending by group size (best coverage first).
        const Sort = struct {
            pub fn lessThan(_: void, a: Group, b_val: Group) bool {
                return a.len > b_val.len;
            }
        };
        std.sort.pdq(Group, groups.items, {}, Sort.lessThan);

        var result = std.ArrayListUnmanaged(Phase0Attestation.Type).empty;
        errdefer result.deinit(allocator);

        for (groups.items) |group| {
            if (result.items.len >= max_attestations) break;
            if (self.pool.get(group.key)) |atts| {
                for (atts.items) |att| {
                    if (result.items.len >= max_attestations) break;
                    try result.append(allocator, att);
                }
            }
        }
        return result.toOwnedSlice(allocator);
    }

    /// Remove attestations older than one epoch before `current_slot`.
    pub fn prune(self: *AttestationPool, current_slot: Slot) void {
        const cutoff = if (current_slot >= preset.SLOTS_PER_EPOCH)
            current_slot - preset.SLOTS_PER_EPOCH
        else
            0;

        var to_remove = std.ArrayListUnmanaged([32]u8).empty;
        defer to_remove.deinit(self.allocator);

        var it = self.pool.iterator();
        while (it.next()) |entry| {
            const items = entry.value_ptr.items;
            if (items.len > 0 and items[0].data.slot < cutoff) {
                for (items) |*att| {
                    att.aggregation_bits.data.deinit(self.allocator);
                }
                entry.value_ptr.deinit(self.allocator);
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }
        for (to_remove.items) |key| {
            _ = self.pool.remove(key);
        }
    }

    /// Number of distinct attestation-data groups in the pool.
    pub fn groupCount(self: *const AttestationPool) usize {
        return self.pool.count();
    }
};

// ---------------------------------------------------------------------------
// VoluntaryExitPool
// ---------------------------------------------------------------------------

/// Pool of pending signed voluntary exits, keyed by validator index.
pub const VoluntaryExitPool = struct {
    pool: std.AutoHashMap(ValidatorIndex, SignedVoluntaryExit.Type),

    pub fn init(allocator: Allocator) VoluntaryExitPool {
        return .{
            .pool = std.AutoHashMap(ValidatorIndex, SignedVoluntaryExit.Type).init(allocator),
        };
    }

    pub fn deinit(self: *VoluntaryExitPool) void {
        self.pool.deinit();
    }

    /// Insert a voluntary exit. Duplicate validator indices are silently
    /// replaced (latest wins).
    pub fn add(self: *VoluntaryExitPool, exit: SignedVoluntaryExit.Type) !void {
        try self.pool.put(exit.message.validator_index, exit);
    }

    /// Return up to `max` pending exits. Caller owns the returned slice.
    ///
    /// Sorted by validator_index for deterministic block ordering.
    pub fn getForBlock(self: *VoluntaryExitPool, allocator: Allocator, max: u32) ![]SignedVoluntaryExit.Type {
        var all = std.ArrayListUnmanaged(SignedVoluntaryExit.Type).empty;
        defer all.deinit(allocator);

        var it = self.pool.iterator();
        while (it.next()) |entry| {
            try all.append(allocator, entry.value_ptr.*);
        }

        // Sort by validator_index for deterministic block production (DST requirement).
        std.sort.pdq(SignedVoluntaryExit.Type, all.items, {}, struct {
            pub fn lessThan(_: void, a: SignedVoluntaryExit.Type, b: SignedVoluntaryExit.Type) bool {
                return a.message.validator_index < b.message.validator_index;
            }
        }.lessThan);

        const take = @min(all.items.len, max);
        var result = std.ArrayListUnmanaged(SignedVoluntaryExit.Type).empty;
        errdefer result.deinit(allocator);
        try result.appendSlice(allocator, all.items[0..take]);
        return result.toOwnedSlice(allocator);
    }

    /// Remove exits whose epoch is at or before `finalized_epoch`.
    pub fn prune(self: *VoluntaryExitPool, finalized_epoch: Epoch) void {
        var remove_buf: [256]ValidatorIndex = undefined;
        var remove_len: usize = 0;

        var it = self.pool.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.message.epoch <= finalized_epoch) {
                if (remove_len < remove_buf.len) {
                    remove_buf[remove_len] = entry.key_ptr.*;
                    remove_len += 1;
                }
            }
        }
        for (remove_buf[0..remove_len]) |key| {
            _ = self.pool.remove(key);
        }
    }

    pub fn size(self: *const VoluntaryExitPool) usize {
        return self.pool.count();
    }
};

// ---------------------------------------------------------------------------
// ProposerSlashingPool
// ---------------------------------------------------------------------------

/// Pool of pending proposer slashings, keyed by proposer index.
pub const ProposerSlashingPool = struct {
    pool: std.AutoHashMap(ValidatorIndex, ProposerSlashing.Type),

    pub fn init(allocator: Allocator) ProposerSlashingPool {
        return .{
            .pool = std.AutoHashMap(ValidatorIndex, ProposerSlashing.Type).init(allocator),
        };
    }

    pub fn deinit(self: *ProposerSlashingPool) void {
        self.pool.deinit();
    }

    /// Insert a proposer slashing. The proposer index is extracted from the
    /// first signed header.
    pub fn add(self: *ProposerSlashingPool, slashing: ProposerSlashing.Type) !void {
        const proposer_index = slashing.signed_header_1.message.proposer_index;
        try self.pool.put(proposer_index, slashing);
    }

    /// Return up to `max` pending slashings. Caller owns the returned slice.
    ///
    /// Sorted by proposer_index for deterministic block ordering.
    pub fn getForBlock(self: *ProposerSlashingPool, allocator: Allocator, max: u32) ![]ProposerSlashing.Type {
        var all = std.ArrayListUnmanaged(ProposerSlashing.Type).empty;
        defer all.deinit(allocator);

        var it = self.pool.iterator();
        while (it.next()) |entry| {
            try all.append(allocator, entry.value_ptr.*);
        }

        // Sort by proposer_index for deterministic block production (DST requirement).
        std.sort.pdq(ProposerSlashing.Type, all.items, {}, struct {
            pub fn lessThan(_: void, a: ProposerSlashing.Type, b: ProposerSlashing.Type) bool {
                return a.signed_header_1.message.proposer_index < b.signed_header_1.message.proposer_index;
            }
        }.lessThan);

        const take = @min(all.items.len, max);
        var result = std.ArrayListUnmanaged(ProposerSlashing.Type).empty;
        errdefer result.deinit(allocator);
        try result.appendSlice(allocator, all.items[0..take]);
        return result.toOwnedSlice(allocator);
    }

    /// Remove slashings whose header slot maps to an epoch <= finalized.
    pub fn pruneFinalized(self: *ProposerSlashingPool, finalized_epoch: Epoch) void {
        var remove_buf: [256]ValidatorIndex = undefined;
        var remove_len: usize = 0;

        var it = self.pool.iterator();
        while (it.next()) |entry| {
            const slot = entry.value_ptr.signed_header_1.message.slot;
            const epoch = @divFloor(slot, preset.SLOTS_PER_EPOCH);
            if (epoch <= finalized_epoch) {
                if (remove_len < remove_buf.len) {
                    remove_buf[remove_len] = entry.key_ptr.*;
                    remove_len += 1;
                }
            }
        }
        for (remove_buf[0..remove_len]) |key| {
            _ = self.pool.remove(key);
        }
    }

    pub fn size(self: *const ProposerSlashingPool) usize {
        return self.pool.count();
    }
};

// ---------------------------------------------------------------------------
// AttesterSlashingPool
// ---------------------------------------------------------------------------

/// Pool of pending attester slashings, keyed by hash-tree-root.
pub const AttesterSlashingPool = struct {
    allocator: Allocator,
    pool: std.AutoHashMap([32]u8, Phase0AttesterSlashing),

    const Phase0AttesterSlashing = types.phase0.AttesterSlashing.Type;

    pub fn init(allocator: Allocator) AttesterSlashingPool {
        return .{
            .allocator = allocator,
            .pool = std.AutoHashMap([32]u8, Phase0AttesterSlashing).init(allocator),
        };
    }

    pub fn deinit(self: *AttesterSlashingPool) void {
        self.pool.deinit();
    }

    /// Insert an attester slashing.
    pub fn add(self: *AttesterSlashingPool, slashing: Phase0AttesterSlashing) !void {
        var root: [32]u8 = undefined;
        try types.phase0.AttesterSlashing.hashTreeRoot(self.allocator, &slashing, &root);
        try self.pool.put(root, slashing);
    }

    /// Return up to `max` pending attester slashings. Caller owns the
    /// returned slice.
    ///
    /// Sorted by hash-tree-root for deterministic block ordering.
    pub fn getForBlock(self: *AttesterSlashingPool, allocator: Allocator, max: u32) ![]Phase0AttesterSlashing {
        const Entry = struct { root: [32]u8, slashing: Phase0AttesterSlashing };
        var all = std.ArrayListUnmanaged(Entry).empty;
        defer all.deinit(allocator);

        var it = self.pool.iterator();
        while (it.next()) |entry| {
            try all.append(allocator, .{ .root = entry.key_ptr.*, .slashing = entry.value_ptr.* });
        }

        // Sort by hash-tree-root (lexicographic) for deterministic block production (DST requirement).
        std.sort.pdq(Entry, all.items, {}, struct {
            pub fn lessThan(_: void, a: Entry, b: Entry) bool {
                return std.mem.lessThan(u8, &a.root, &b.root);
            }
        }.lessThan);

        const take = @min(all.items.len, max);
        var result = std.ArrayListUnmanaged(Phase0AttesterSlashing).empty;
        errdefer result.deinit(allocator);
        for (all.items[0..take]) |e| {
            try result.append(allocator, e.slashing);
        }
        return result.toOwnedSlice(allocator);
    }

    /// Remove all entries (simple reset after finalization).
    pub fn pruneAll(self: *AttesterSlashingPool) void {
        self.pool.clearAndFree();
    }

    pub fn size(self: *const AttesterSlashingPool) usize {
        return self.pool.count();
    }
};

// ---------------------------------------------------------------------------
// BlsChangePool
// ---------------------------------------------------------------------------

/// Pool of pending `SignedBLSToExecutionChange` messages, keyed by
/// validator index.
pub const BlsChangePool = struct {
    pool: std.AutoHashMap(ValidatorIndex, SignedBLSToExecutionChange.Type),

    pub fn init(allocator: Allocator) BlsChangePool {
        return .{
            .pool = std.AutoHashMap(ValidatorIndex, SignedBLSToExecutionChange.Type).init(allocator),
        };
    }

    pub fn deinit(self: *BlsChangePool) void {
        self.pool.deinit();
    }

    pub fn add(self: *BlsChangePool, change: SignedBLSToExecutionChange.Type) !void {
        try self.pool.put(change.message.validator_index, change);
    }

    /// Sorted by validator_index for deterministic block ordering.
    pub fn getForBlock(self: *BlsChangePool, allocator: Allocator, max: u32) ![]SignedBLSToExecutionChange.Type {
        var all = std.ArrayListUnmanaged(SignedBLSToExecutionChange.Type).empty;
        defer all.deinit(allocator);

        var it = self.pool.iterator();
        while (it.next()) |entry| {
            try all.append(allocator, entry.value_ptr.*);
        }

        // Sort by validator_index for deterministic block production (DST requirement).
        std.sort.pdq(SignedBLSToExecutionChange.Type, all.items, {}, struct {
            pub fn lessThan(_: void, a: SignedBLSToExecutionChange.Type, b: SignedBLSToExecutionChange.Type) bool {
                return a.message.validator_index < b.message.validator_index;
            }
        }.lessThan);

        const take = @min(all.items.len, max);
        var result = std.ArrayListUnmanaged(SignedBLSToExecutionChange.Type).empty;
        errdefer result.deinit(allocator);
        try result.appendSlice(allocator, all.items[0..take]);
        return result.toOwnedSlice(allocator);
    }

    /// Remove entries whose validator index was already processed.
    pub fn remove(self: *BlsChangePool, validator_index: ValidatorIndex) void {
        _ = self.pool.remove(validator_index);
    }

    pub fn size(self: *const BlsChangePool) usize {
        return self.pool.count();
    }
};

// ---------------------------------------------------------------------------
// OpPool — aggregate of all sub-pools
// ---------------------------------------------------------------------------

/// Aggregate operation pool holding all sub-pools for pending consensus
/// operations.
pub const OpPool = struct {
    allocator: Allocator,

    attestation_pool: AttestationPool,
    voluntary_exit_pool: VoluntaryExitPool,
    proposer_slashing_pool: ProposerSlashingPool,
    attester_slashing_pool: AttesterSlashingPool,
    bls_change_pool: BlsChangePool,

    pub fn init(allocator: Allocator) OpPool {
        return .{
            .allocator = allocator,
            .attestation_pool = AttestationPool.init(allocator),
            .voluntary_exit_pool = VoluntaryExitPool.init(allocator),
            .proposer_slashing_pool = ProposerSlashingPool.init(allocator),
            .attester_slashing_pool = AttesterSlashingPool.init(allocator),
            .bls_change_pool = BlsChangePool.init(allocator),
        };
    }

    pub fn deinit(self: *OpPool) void {
        self.attestation_pool.deinit();
        self.voluntary_exit_pool.deinit();
        self.proposer_slashing_pool.deinit();
        self.attester_slashing_pool.deinit();
        self.bls_change_pool.deinit();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "AttestationPool: add and groupCount" {
    const allocator = std.testing.allocator;
    var pool = AttestationPool.init(allocator);
    defer pool.deinit();

    const att = makeTestAttestation(10, 0);
    try pool.add(att);
    try std.testing.expectEqual(@as(usize, 1), pool.groupCount());

    // Same data → same group.
    try pool.add(att);
    try std.testing.expectEqual(@as(usize, 1), pool.groupCount());

    // Different slot → different group.
    const att2 = makeTestAttestation(11, 0);
    try pool.add(att2);
    try std.testing.expectEqual(@as(usize, 2), pool.groupCount());
}

test "AttestationPool: getForBlock respects max" {
    const allocator = std.testing.allocator;
    var pool = AttestationPool.init(allocator);
    defer pool.deinit();

    for (0..5) |i| {
        try pool.add(makeTestAttestation(@intCast(i), 0));
    }
    try std.testing.expectEqual(@as(usize, 5), pool.groupCount());

    const selected = try pool.getForBlock(allocator, 3);
    defer allocator.free(selected);
    try std.testing.expect(selected.len <= 3);
}

test "AttestationPool: prune removes old attestations" {
    const allocator = std.testing.allocator;
    var pool = AttestationPool.init(allocator);
    defer pool.deinit();

    try pool.add(makeTestAttestation(5, 0));
    try pool.add(makeTestAttestation(100, 0));
    try std.testing.expectEqual(@as(usize, 2), pool.groupCount());

    pool.prune(100);
    // slot 5 is older than 100 - SLOTS_PER_EPOCH (= 68 for mainnet), so pruned.
    try std.testing.expectEqual(@as(usize, 1), pool.groupCount());
}

test "VoluntaryExitPool: add dedup and getForBlock" {
    const allocator = std.testing.allocator;
    var pool = VoluntaryExitPool.init(allocator);
    defer pool.deinit();

    const exit1 = makeTestExit(42, 10);
    const exit2 = makeTestExit(42, 11); // same validator
    const exit3 = makeTestExit(99, 10);

    try pool.add(exit1);
    try pool.add(exit2); // replaces exit1
    try pool.add(exit3);
    try std.testing.expectEqual(@as(usize, 2), pool.size());

    const selected = try pool.getForBlock(allocator, 1);
    defer allocator.free(selected);
    try std.testing.expectEqual(@as(usize, 1), selected.len);
}

test "VoluntaryExitPool: prune" {
    const allocator = std.testing.allocator;
    var pool = VoluntaryExitPool.init(allocator);
    defer pool.deinit();

    try pool.add(makeTestExit(1, 5));
    try pool.add(makeTestExit(2, 15));
    pool.prune(10);
    try std.testing.expectEqual(@as(usize, 1), pool.size());
}

test "ProposerSlashingPool: add and getForBlock" {
    const allocator = std.testing.allocator;
    var pool = ProposerSlashingPool.init(allocator);
    defer pool.deinit();

    try pool.add(makeTestProposerSlashing(7, 100));
    try pool.add(makeTestProposerSlashing(8, 200));
    try std.testing.expectEqual(@as(usize, 2), pool.size());

    const selected = try pool.getForBlock(allocator, 10);
    defer allocator.free(selected);
    try std.testing.expectEqual(@as(usize, 2), selected.len);
}

test "BlsChangePool: add, getForBlock, remove" {
    const allocator = std.testing.allocator;
    var pool = BlsChangePool.init(allocator);
    defer pool.deinit();

    try pool.add(makeTestBlsChange(10));
    try pool.add(makeTestBlsChange(20));
    try std.testing.expectEqual(@as(usize, 2), pool.size());

    pool.remove(10);
    try std.testing.expectEqual(@as(usize, 1), pool.size());

    const selected = try pool.getForBlock(allocator, 5);
    defer allocator.free(selected);
    try std.testing.expectEqual(@as(usize, 1), selected.len);
}

test "OpPool: init and deinit" {
    const allocator = std.testing.allocator;
    var pool = OpPool.init(allocator);
    defer pool.deinit();

    try pool.attestation_pool.add(makeTestAttestation(10, 0));
    try pool.voluntary_exit_pool.add(makeTestExit(1, 5));
    try std.testing.expectEqual(@as(usize, 1), pool.attestation_pool.groupCount());
}

// ---------------------------------------------------------------------------
// Test helpers (pub for cross-module testing in produce_block.zig)
// ---------------------------------------------------------------------------

pub fn makeTestAttestation(slot: Slot, index: u64) Phase0Attestation.Type {
    return .{
        .aggregation_bits = .{ .data = std.ArrayListUnmanaged(u8).empty, .bit_len = 0 },
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

pub fn makeTestExit(validator_index: ValidatorIndex, epoch: Epoch) SignedVoluntaryExit.Type {
    return .{
        .message = .{
            .epoch = epoch,
            .validator_index = validator_index,
        },
        .signature = [_]u8{0} ** 96,
    };
}

pub fn makeTestProposerSlashing(proposer_index: ValidatorIndex, slot: Slot) ProposerSlashing.Type {
    const header = types.phase0.BeaconBlockHeader.Type{
        .slot = slot,
        .proposer_index = proposer_index,
        .parent_root = [_]u8{0} ** 32,
        .state_root = [_]u8{0} ** 32,
        .body_root = [_]u8{0} ** 32,
    };
    return .{
        .signed_header_1 = .{ .message = header, .signature = [_]u8{0} ** 96 },
        .signed_header_2 = .{ .message = header, .signature = [_]u8{1} ** 96 },
    };
}

pub fn makeTestBlsChange(validator_index: ValidatorIndex) SignedBLSToExecutionChange.Type {
    return .{
        .message = .{
            .validator_index = validator_index,
            .from_bls_pubkey = [_]u8{0} ** 48,
            .to_execution_address = [_]u8{0} ** 20,
        },
        .signature = [_]u8{0} ** 96,
    };
}
