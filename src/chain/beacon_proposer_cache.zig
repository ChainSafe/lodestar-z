//! BeaconProposerCache — per-epoch proposer duty registrations.
//!
//! Caches proposer duties and fee recipient registrations submitted via the
//! `prepare_beacon_proposer` API endpoint (Bellatrix+). The validator client
//! submits (epoch, validator_index) → ProposerInfo{fee_recipient, gas_limit}
//! prior to the epoch, and the block production pipeline reads it back when
//! building execution payloads.
//!
//! Key: (epoch, validator_index)
//! Value: ProposerInfo{fee_recipient: [20]u8, gas_limit: u64}
//!
//! Entries are pruned when epochs fall below the finalized checkpoint.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Fee recipient address (20 bytes, EVM address).
pub const FeeRecipient = [20]u8;

/// Proposer registration info submitted via prepare_beacon_proposer.
pub const ProposerInfo = struct {
    fee_recipient: FeeRecipient,
    gas_limit: u64,
};

/// Composite key for the proposer cache.
const ProposerKey = struct {
    epoch: u64,
    validator_index: u64,
};

/// Hash+equality context for ProposerKey.
const ProposerKeyContext = struct {
    pub fn hash(_: ProposerKeyContext, key: ProposerKey) u32 {
        var h = std.hash.Wyhash.init(0);
        h.update(std.mem.asBytes(&key.epoch));
        h.update(std.mem.asBytes(&key.validator_index));
        return @truncate(h.final());
    }

    pub fn eql(_: ProposerKeyContext, a: ProposerKey, b: ProposerKey, _: usize) bool {
        return a.epoch == b.epoch and a.validator_index == b.validator_index;
    }
};

pub const BeaconProposerCache = struct {
    allocator: Allocator,
    /// (epoch, validator_index) -> ProposerInfo
    entries: std.ArrayHashMap(ProposerKey, ProposerInfo, ProposerKeyContext, true),
    /// epoch -> count of registered validators (for bulk prune)
    epoch_counts: std.AutoArrayHashMap(u64, u32),

    pub fn init(allocator: Allocator) BeaconProposerCache {
        return .{
            .allocator = allocator,
            .entries = std.ArrayHashMap(ProposerKey, ProposerInfo, ProposerKeyContext, true).init(allocator),
            .epoch_counts = std.AutoArrayHashMap(u64, u32).init(allocator),
        };
    }

    pub fn deinit(self: *BeaconProposerCache) void {
        self.entries.deinit();
        self.epoch_counts.deinit();
    }

    /// Register a proposer's fee recipient and gas limit for an epoch.
    pub fn add(self: *BeaconProposerCache, epoch: u64, validator_index: u64, info: ProposerInfo) !void {
        const key = ProposerKey{ .epoch = epoch, .validator_index = validator_index };
        const was_new = !self.entries.contains(key);
        try self.entries.put(key, info);

        if (was_new) {
            const gop = try self.epoch_counts.getOrPut(epoch);
            if (!gop.found_existing) {
                gop.value_ptr.* = 0;
            }
            gop.value_ptr.* += 1;
        }
    }

    /// Look up the ProposerInfo for a (epoch, validator_index) pair.
    /// Returns null if not registered.
    pub fn get(self: *const BeaconProposerCache, epoch: u64, validator_index: u64) ?ProposerInfo {
        const key = ProposerKey{ .epoch = epoch, .validator_index = validator_index };
        return self.entries.get(key);
    }

    /// Remove all registrations for epochs strictly below finalized_epoch.
    pub fn prune(self: *BeaconProposerCache, finalized_epoch: u64) void {
        if (finalized_epoch == 0) return;

        var epochs_to_remove = std.ArrayListUnmanaged(u64).empty;
        defer epochs_to_remove.deinit(self.allocator);

        var it = self.epoch_counts.iterator();
        while (it.next()) |entry| {
            if (entry.key_ptr.* < finalized_epoch) {
                epochs_to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (epochs_to_remove.items) |epoch| {
            // Remove all entries for this epoch.
            var keys_to_remove = std.ArrayListUnmanaged(ProposerKey).empty;
            defer keys_to_remove.deinit(self.allocator);

            var entry_it = self.entries.iterator();
            while (entry_it.next()) |e| {
                if (e.key_ptr.epoch == epoch) {
                    keys_to_remove.append(self.allocator, e.key_ptr.*) catch continue;
                }
            }
            for (keys_to_remove.items) |key| {
                _ = self.entries.swapRemove(key);
            }
            _ = self.epoch_counts.swapRemove(epoch);
        }
    }

    /// Number of registered (epoch, validator_index) pairs.
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

    const info = ProposerInfo{
        .fee_recipient = [_]u8{0xAB} ** 20,
        .gas_limit = 30_000_000,
    };

    try cache.add(10, 42, info);
    const result = cache.get(10, 42);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u64, 30_000_000), result.?.gas_limit);
    try std.testing.expectEqualSlices(u8, &([_]u8{0xAB} ** 20), &result.?.fee_recipient);

    try std.testing.expect(cache.get(10, 43) == null);
    try std.testing.expect(cache.get(11, 42) == null);
}

test "BeaconProposerCache: prune removes old epochs" {
    var cache = BeaconProposerCache.init(std.testing.allocator);
    defer cache.deinit();

    const info = ProposerInfo{ .fee_recipient = [_]u8{0} ** 20, .gas_limit = 1 };
    try cache.add(5, 1, info);
    try cache.add(5, 2, info);
    try cache.add(8, 3, info);
    try cache.add(10, 4, info);

    cache.prune(8); // Remove epochs < 8.
    try std.testing.expect(cache.get(5, 1) == null);
    try std.testing.expect(cache.get(5, 2) == null);
    try std.testing.expect(cache.get(8, 3) != null);
    try std.testing.expect(cache.get(10, 4) != null);
}

test "BeaconProposerCache: update existing entry" {
    var cache = BeaconProposerCache.init(std.testing.allocator);
    defer cache.deinit();

    const info1 = ProposerInfo{ .fee_recipient = [_]u8{0x01} ** 20, .gas_limit = 1 };
    const info2 = ProposerInfo{ .fee_recipient = [_]u8{0x02} ** 20, .gas_limit = 2 };

    try cache.add(10, 42, info1);
    try cache.add(10, 42, info2); // Update.

    const result = cache.get(10, 42);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u64, 2), result.?.gas_limit);
    try std.testing.expectEqual(@as(usize, 1), cache.len());
}
