//! Epoch-keyed validator-index cache for lightweight liveness tracking.
//!
//! Tracks validators seen at a given epoch. This is used for non-authoritative
//! short-horizon queries like validator liveness and dedup-related heuristics.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");

const Epoch = types.primitive.Epoch.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;

/// Keep previous, current, and tolerated future-epoch activity bounded.
const EPOCH_LOOKBACK_LIMIT: Epoch = 2;

pub const SeenEpochValidators = struct {
    allocator: Allocator,
    validator_indexes_by_epoch: std.AutoArrayHashMap(Epoch, std.AutoHashMap(ValidatorIndex, void)),
    lowest_permissible_epoch: Epoch = 0,

    pub fn init(allocator: Allocator) SeenEpochValidators {
        return .{
            .allocator = allocator,
            .validator_indexes_by_epoch = std.AutoArrayHashMap(Epoch, std.AutoHashMap(ValidatorIndex, void)).init(allocator),
        };
    }

    pub fn deinit(self: *SeenEpochValidators) void {
        for (self.validator_indexes_by_epoch.values()) |*validator_indexes| {
            validator_indexes.deinit();
        }
        self.validator_indexes_by_epoch.deinit();
    }

    pub fn isKnown(self: *const SeenEpochValidators, epoch: Epoch, validator_index: ValidatorIndex) bool {
        const validator_indexes = self.validator_indexes_by_epoch.getPtr(epoch) orelse return false;
        return validator_indexes.contains(validator_index);
    }

    pub fn add(self: *SeenEpochValidators, epoch: Epoch, validator_index: ValidatorIndex) !void {
        if (epoch < self.lowest_permissible_epoch) return error.EpochTooLow;

        const gop = try self.validator_indexes_by_epoch.getOrPut(epoch);
        if (!gop.found_existing) {
            gop.value_ptr.* = std.AutoHashMap(ValidatorIndex, void).init(self.allocator);
        }
        try gop.value_ptr.put(validator_index, {});
    }

    pub fn prune(self: *SeenEpochValidators, current_epoch: Epoch) void {
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

    pub fn reset(self: *SeenEpochValidators) void {
        for (self.validator_indexes_by_epoch.values()) |*validator_indexes| {
            validator_indexes.deinit();
        }
        self.validator_indexes_by_epoch.clearRetainingCapacity();
        self.lowest_permissible_epoch = 0;
    }
};

const testing = std.testing;

test "SeenEpochValidators add and prune" {
    var cache = SeenEpochValidators.init(testing.allocator);
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

test "SeenEpochValidators rejects epochs below prune floor" {
    var cache = SeenEpochValidators.init(testing.allocator);
    defer cache.deinit();

    cache.prune(6);
    try testing.expectError(error.EpochTooLow, cache.add(3, 1));
}
