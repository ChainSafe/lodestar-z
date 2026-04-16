//! Seen-attester cache for unaggregated attestation deduplication.
//!
//! Tracks validators that already produced a valid unaggregated attestation
//! for a target epoch. This is separate from `seen_cache.zig` because the
//! retention and semantics are epoch-bound rather than message-root-bound.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");

const Epoch = types.primitive.Epoch.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;

/// Keep previous, current, and tolerated future-epoch attestations bounded.
const EPOCH_LOOKBACK_LIMIT: Epoch = 2;

pub const SeenAttesters = struct {
    allocator: Allocator,
    validator_indexes_by_epoch: std.array_hash_map.Auto(Epoch, std.AutoHashMap(ValidatorIndex, void)),
    lowest_permissible_epoch: Epoch = 0,

    pub fn init(allocator: Allocator) SeenAttesters {
        return .{
            .allocator = allocator,
            .validator_indexes_by_epoch = .empty,
        };
    }

    pub fn deinit(self: *SeenAttesters) void {
        for (self.validator_indexes_by_epoch.values()) |*validator_indexes| {
            validator_indexes.deinit();
        }
        self.validator_indexes_by_epoch.deinit(self.allocator);
    }

    pub fn isKnown(self: *const SeenAttesters, target_epoch: Epoch, validator_index: ValidatorIndex) bool {
        const validator_indexes = self.validator_indexes_by_epoch.getPtr(target_epoch) orelse return false;
        return validator_indexes.contains(validator_index);
    }

    pub fn add(self: *SeenAttesters, target_epoch: Epoch, validator_index: ValidatorIndex) !void {
        if (target_epoch < self.lowest_permissible_epoch) return error.EpochTooLow;

        const gop = try self.validator_indexes_by_epoch.getOrPut(self.allocator, target_epoch);
        if (!gop.found_existing) {
            gop.value_ptr.* = std.AutoHashMap(ValidatorIndex, void).init(self.allocator);
        }
        try gop.value_ptr.put(validator_index, {});
    }

    pub fn prune(self: *SeenAttesters, current_epoch: Epoch) void {
        self.lowest_permissible_epoch = if (current_epoch > EPOCH_LOOKBACK_LIMIT)
            current_epoch - EPOCH_LOOKBACK_LIMIT
        else
            0;

        var index: usize = self.validator_indexes_by_epoch.count();
        while (index > 0) {
            index -= 1;
            if (self.validator_indexes_by_epoch.keys()[index] < self.lowest_permissible_epoch) {
                self.validator_indexes_by_epoch.values()[index].deinit();
                _ = self.validator_indexes_by_epoch.orderedRemoveAt(index);
            }
        }
    }

    pub fn reset(self: *SeenAttesters) void {
        for (self.validator_indexes_by_epoch.values()) |*validator_indexes| {
            validator_indexes.deinit();
        }
        self.validator_indexes_by_epoch.clearRetainingCapacity();
        self.lowest_permissible_epoch = 0;
    }
};

const testing = std.testing;

test "SeenAttesters add and prune" {
    var cache = SeenAttesters.init(testing.allocator);
    defer cache.deinit();

    try cache.add(10, 1);
    try cache.add(11, 2);
    try testing.expect(cache.isKnown(10, 1));
    try testing.expect(cache.isKnown(11, 2));

    cache.prune(12);
    try testing.expect(!cache.isKnown(9, 1));
    try testing.expect(cache.isKnown(10, 1));
    try testing.expect(cache.isKnown(11, 2));

    cache.prune(13);
    try testing.expect(!cache.isKnown(10, 1));
    try testing.expect(cache.isKnown(11, 2));
}

test "SeenAttesters rejects epochs below prune floor" {
    var cache = SeenAttesters.init(testing.allocator);
    defer cache.deinit();

    cache.prune(6);
    try testing.expectError(error.EpochTooLow, cache.add(3, 1));
}
