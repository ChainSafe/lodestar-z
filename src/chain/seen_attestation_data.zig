//! Cached attestation validation data.
//!
//! Gossip attestations in the same slot and committee frequently share the
//! same attestation data. This cache stores the resolved committee metadata
//! and signing root so validation and processor import do not recompute them
//! for every arrival.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");

const Slot = types.primitive.Slot.Type;
const Root = types.primitive.Root.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;

pub const DEFAULT_CACHE_SLOT_DISTANCE: Slot = 2;
pub const DEFAULT_MAX_CACHE_SIZE_PER_SLOT: usize = 200;

pub const InsertResult = enum {
    inserted,
    already_known,
    too_old,
    reached_limit,
};

pub const AttestationDataCacheEntry = struct {
    committee_validator_indices: []ValidatorIndex,
    signing_root: Root,
    expected_subnet: u8,

    pub fn deinit(self: *AttestationDataCacheEntry, allocator: Allocator) void {
        allocator.free(self.committee_validator_indices);
        self.* = undefined;
    }
};

const CommitteeEntries = std.AutoHashMap(Root, AttestationDataCacheEntry);
const SlotEntries = std.AutoArrayHashMap(u64, CommitteeEntries);

pub const SeenAttestationData = struct {
    allocator: Allocator,
    cache_slot_distance: Slot,
    max_cache_size_per_slot: usize,
    lowest_permissible_slot: Slot = 0,
    entries_by_slot: std.AutoArrayHashMap(Slot, SlotEntries),

    pub fn init(allocator: Allocator) SeenAttestationData {
        return initWithConfig(
            allocator,
            DEFAULT_CACHE_SLOT_DISTANCE,
            DEFAULT_MAX_CACHE_SIZE_PER_SLOT,
        );
    }

    pub fn initWithConfig(
        allocator: Allocator,
        cache_slot_distance: Slot,
        max_cache_size_per_slot: usize,
    ) SeenAttestationData {
        return .{
            .allocator = allocator,
            .cache_slot_distance = cache_slot_distance,
            .max_cache_size_per_slot = max_cache_size_per_slot,
            .entries_by_slot = std.AutoArrayHashMap(Slot, SlotEntries).init(allocator),
        };
    }

    pub fn deinit(self: *SeenAttestationData) void {
        var slot_index: usize = 0;
        while (slot_index < self.entries_by_slot.count()) : (slot_index += 1) {
            deinitSlotEntries(self.allocator, &self.entries_by_slot.values()[slot_index]);
        }
        self.entries_by_slot.deinit();
    }

    pub fn get(
        self: *const SeenAttestationData,
        slot: Slot,
        committee_index_lookup: u64,
        attestation_data_root: Root,
    ) ?*const AttestationDataCacheEntry {
        const slot_entries = self.entries_by_slot.getPtr(slot) orelse return null;
        const committee_entries = slot_entries.getPtr(committee_index_lookup) orelse return null;
        return committee_entries.getPtr(attestation_data_root);
    }

    pub fn insert(
        self: *SeenAttestationData,
        slot: Slot,
        committee_index_lookup: u64,
        attestation_data_root: Root,
        committee_validator_indices: []const ValidatorIndex,
        signing_root: Root,
        expected_subnet: u8,
    ) !InsertResult {
        if (slot < self.lowest_permissible_slot) return .too_old;

        const slot_gop = try self.entries_by_slot.getOrPut(slot);
        if (!slot_gop.found_existing) {
            slot_gop.value_ptr.* = SlotEntries.init(self.allocator);
        }

        const committee_gop = try slot_gop.value_ptr.getOrPut(committee_index_lookup);
        if (!committee_gop.found_existing) {
            committee_gop.value_ptr.* = CommitteeEntries.init(self.allocator);
        }

        if (committee_gop.value_ptr.contains(attestation_data_root)) return .already_known;
        if (committee_gop.value_ptr.count() >= self.max_cache_size_per_slot) return .reached_limit;

        try committee_gop.value_ptr.put(attestation_data_root, .{
            .committee_validator_indices = try self.allocator.dupe(ValidatorIndex, committee_validator_indices),
            .signing_root = signing_root,
            .expected_subnet = expected_subnet,
        });
        return .inserted;
    }

    pub fn onSlot(self: *SeenAttestationData, clock_slot: Slot) void {
        self.lowest_permissible_slot = if (clock_slot > self.cache_slot_distance)
            clock_slot - self.cache_slot_distance
        else
            0;

        var slot_index: usize = self.entries_by_slot.count();
        while (slot_index > 0) {
            slot_index -= 1;
            if (self.entries_by_slot.keys()[slot_index] < self.lowest_permissible_slot) {
                deinitSlotEntries(self.allocator, &self.entries_by_slot.values()[slot_index]);
                _ = self.entries_by_slot.orderedRemoveAt(slot_index);
            }
        }
    }

    pub fn reset(self: *SeenAttestationData) void {
        var slot_index: usize = 0;
        while (slot_index < self.entries_by_slot.count()) : (slot_index += 1) {
            deinitSlotEntries(self.allocator, &self.entries_by_slot.values()[slot_index]);
        }
        self.entries_by_slot.clearRetainingCapacity();
        self.lowest_permissible_slot = 0;
    }
};

fn deinitSlotEntries(allocator: Allocator, slot_entries: *SlotEntries) void {
    var committee_index: usize = 0;
    while (committee_index < slot_entries.count()) : (committee_index += 1) {
        var committee_entries = &slot_entries.values()[committee_index];
        var it = committee_entries.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(allocator);
        }
        committee_entries.deinit();
    }
    slot_entries.deinit();
}

const testing = std.testing;

test "SeenAttestationData insert get and prune" {
    var cache = SeenAttestationData.initWithConfig(testing.allocator, 2, 4);
    defer cache.deinit();

    const committee = [_]ValidatorIndex{ 10, 20, 30 };
    const signing_root = [_]u8{0xAA} ** 32;
    const attestation_data_root = [_]u8{0x11} ** 32;

    try testing.expectEqual(
        InsertResult.inserted,
        try cache.insert(100, 3, attestation_data_root, &committee, signing_root, 7),
    );

    const entry = cache.get(100, 3, attestation_data_root) orelse return error.TestExpectedEqual;
    try testing.expectEqual(@as(usize, 3), entry.committee_validator_indices.len);
    try testing.expectEqual(@as(u8, 7), entry.expected_subnet);
    try testing.expectEqual(signing_root, entry.signing_root);

    cache.onSlot(103);
    try testing.expect(cache.get(100, 3, attestation_data_root) == null);
}

test "SeenAttestationData enforces duplicate and age limits" {
    var cache = SeenAttestationData.initWithConfig(testing.allocator, 1, 1);
    defer cache.deinit();

    const committee = [_]ValidatorIndex{42};
    const signing_root = [_]u8{0xBB} ** 32;
    const root_a = [_]u8{0x01} ** 32;
    const root_b = [_]u8{0x02} ** 32;

    try testing.expectEqual(
        InsertResult.inserted,
        try cache.insert(10, 0, root_a, &committee, signing_root, 0),
    );
    try testing.expectEqual(
        InsertResult.already_known,
        try cache.insert(10, 0, root_a, &committee, signing_root, 0),
    );
    try testing.expectEqual(
        InsertResult.reached_limit,
        try cache.insert(10, 0, root_b, &committee, signing_root, 0),
    );

    cache.onSlot(20);
    try testing.expectEqual(
        InsertResult.too_old,
        try cache.insert(10, 0, root_b, &committee, signing_root, 0),
    );
}
