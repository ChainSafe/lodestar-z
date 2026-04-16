//! BeaconProposerCache — validator-index keyed proposer registrations.
//!
//! Mirrors Lodestar's production behavior more closely than the earlier
//! `(epoch, validator_index)` map. `prepare_beacon_proposer` updates the latest
//! known fee recipient for a validator index and tags it with the epoch when it
//! was last refreshed. The cache retains entries for a short rolling window so
//! the proposer-preparation and block-production paths can share one coherent
//! source of truth.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Fee recipient address (20 bytes, EVM address).
pub const FeeRecipient = [20]u8;

/// Proposer registration info submitted via prepare_beacon_proposer.
pub const ProposerInfo = struct {
    epoch: u64,
    fee_recipient: FeeRecipient,
};

pub const ProposerPreparation = struct {
    validator_index: u64,
    fee_recipient: FeeRecipient,
};

pub const PROPOSER_PRESERVE_EPOCHS: u64 = 2;

pub const BeaconProposerCache = struct {
    allocator: Allocator,
    /// validator_index -> latest proposer info
    entries: std.array_hash_map.Auto(u64, ProposerInfo),

    pub fn init(allocator: Allocator) BeaconProposerCache {
        return .{
            .allocator = allocator,
            .entries = .empty,
        };
    }

    pub fn deinit(self: *BeaconProposerCache) void {
        self.entries.deinit(self.allocator);
    }

    /// Register or refresh a proposer's fee recipient for the given epoch.
    pub fn add(
        self: *BeaconProposerCache,
        epoch: u64,
        validator_index: u64,
        fee_recipient: FeeRecipient,
    ) !void {
        try self.entries.put(self.allocator, validator_index, .{
            .epoch = epoch,
            .fee_recipient = fee_recipient,
        });
    }

    /// Look up the latest cached proposer info for a validator.
    pub fn get(self: *const BeaconProposerCache, validator_index: u64) ?ProposerInfo {
        return self.entries.get(validator_index);
    }

    pub fn getFeeRecipient(self: *const BeaconProposerCache, validator_index: u64) ?FeeRecipient {
        return if (self.get(validator_index)) |info| info.fee_recipient else null;
    }

    pub fn getOrDefault(
        self: *const BeaconProposerCache,
        validator_index: u64,
        default_fee_recipient: ?FeeRecipient,
    ) ?FeeRecipient {
        return self.getFeeRecipient(validator_index) orelse default_fee_recipient;
    }

    /// Remove entries that have not been refreshed in the last two epochs.
    pub fn prune(self: *BeaconProposerCache, current_epoch: u64) void {
        var indices_to_remove = std.ArrayListUnmanaged(usize).empty;
        defer indices_to_remove.deinit(self.allocator);

        for (self.entries.keys(), self.entries.values(), 0..) |_, info, index| {
            if (info.epoch + PROPOSER_PRESERVE_EPOCHS < current_epoch) {
                indices_to_remove.append(self.allocator, index) catch continue;
            }
        }

        var i = indices_to_remove.items.len;
        while (i > 0) : (i -= 1) {
            self.entries.swapRemoveAt(indices_to_remove.items[i - 1]);
        }
    }

    /// Number of tracked validators with proposer data.
    pub fn len(self: *const BeaconProposerCache) usize {
        return self.entries.count();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "BeaconProposerCache: add and get" {
    var cache = BeaconProposerCache.init(std.testing.allocator);
    defer cache.deinit();

    try cache.add(10, 42, [_]u8{0xAB} ** 20);
    const result = cache.get(42);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u64, 10), result.?.epoch);
    try std.testing.expectEqualSlices(u8, &([_]u8{0xAB} ** 20), &result.?.fee_recipient);

    try std.testing.expect(cache.get(43) == null);
}

test "BeaconProposerCache: prune removes stale entries" {
    var cache = BeaconProposerCache.init(std.testing.allocator);
    defer cache.deinit();

    try cache.add(5, 1, [_]u8{0x01} ** 20);
    try cache.add(6, 2, [_]u8{0x02} ** 20);
    try cache.add(8, 3, [_]u8{0x03} ** 20);

    cache.prune(8);
    try std.testing.expect(cache.get(1) == null);
    try std.testing.expect(cache.get(2) != null);
    try std.testing.expect(cache.get(3) != null);
}

test "BeaconProposerCache: update existing entry" {
    var cache = BeaconProposerCache.init(std.testing.allocator);
    defer cache.deinit();

    try cache.add(10, 42, [_]u8{0x01} ** 20);
    try cache.add(11, 42, [_]u8{0x02} ** 20);

    const result = cache.get(42);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u64, 11), result.?.epoch);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x02} ** 20), &result.?.fee_recipient);
    try std.testing.expectEqual(@as(usize, 1), cache.len());
}
