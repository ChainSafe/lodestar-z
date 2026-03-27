//! ShufflingCache — LRU cache of committee shufflings indexed by epoch.
//!
//! Caches EpochShuffling structs so that committee lookups within the same
//! epoch don't require re-computing the shuffling from scratch.
//!
//! Design:
//! - Keyed by epoch number (u64)
//! - LRU eviction with configurable capacity (default 4 epochs)
//! - prune(finalized_epoch) evicts all epochs below finalized
//!
//! The EpochShuffling type uses reference counting (EpochShufflingRc) so
//! ownership is safe to share across consumers.

const std = @import("std");
const Allocator = std.mem.Allocator;

const state_transition = @import("state_transition");
const EpochShuffling = state_transition.EpochShuffling;

pub const DEFAULT_SHUFFLING_CACHE_SIZE: u32 = 4;

pub const ShufflingCache = struct {
    allocator: Allocator,
    /// Epoch -> EpochShuffling pointer (not owned — caller manages lifetime via RC).
    cache: std.AutoArrayHashMap(u64, *EpochShuffling),
    /// LRU order: index 0 = most recently used.
    lru_order: std.ArrayListUnmanaged(u64),
    /// Max epochs to retain.
    capacity: u32,

    pub fn init(allocator: Allocator, capacity: u32) ShufflingCache {
        return .{
            .allocator = allocator,
            .cache = std.AutoArrayHashMap(u64, *EpochShuffling).init(allocator),
            .lru_order = .empty,
            .capacity = capacity,
        };
    }

    pub fn deinit(self: *ShufflingCache) void {
        // We don't own the EpochShuffling pointers — caller is responsible.
        self.cache.deinit();
        self.lru_order.deinit(self.allocator);
    }

    /// Get the shuffling for an epoch, or null if not cached.
    /// Moves the accessed epoch to the front of the LRU order.
    pub fn get(self: *ShufflingCache, epoch: u64) ?*EpochShuffling {
        const shuffling = self.cache.get(epoch) orelse return null;
        self.touchLru(epoch);
        return shuffling;
    }

    /// Insert or replace a shuffling for an epoch.
    /// Evicts the least-recently-used entry if over capacity.
    pub fn put(self: *ShufflingCache, epoch: u64, shuffling: *EpochShuffling) !void {
        const already_present = self.cache.contains(epoch);
        try self.cache.put(epoch, shuffling);

        if (already_present) {
            self.touchLru(epoch);
            return;
        }

        // New entry: prepend to LRU order.
        try self.lru_order.insert(self.allocator, 0, epoch);

        // Evict LRU entries if over capacity.
        while (self.lru_order.items.len > self.capacity) {
            const evict_epoch = self.lru_order.pop() orelse break;
            _ = self.cache.swapRemove(evict_epoch);
        }
    }

    /// Remove all shufflings for epochs strictly below finalized_epoch.
    pub fn prune(self: *ShufflingCache, finalized_epoch: u64) void {
        if (finalized_epoch == 0) return;
        var i: usize = 0;
        while (i < self.lru_order.items.len) {
            const epoch = self.lru_order.items[i];
            if (epoch < finalized_epoch) {
                _ = self.cache.swapRemove(epoch);
                _ = self.lru_order.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Number of entries currently cached.
    pub fn len(self: *const ShufflingCache) usize {
        return self.cache.count();
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn touchLru(self: *ShufflingCache, epoch: u64) void {
        // Find and remove existing position, then prepend.
        for (self.lru_order.items, 0..) |e, idx| {
            if (e == epoch) {
                _ = self.lru_order.orderedRemove(idx);
                break;
            }
        }
        self.lru_order.insert(self.allocator, 0, epoch) catch {};
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ShufflingCache: basic put and get" {
    var cache = ShufflingCache.init(std.testing.allocator, 4);
    defer cache.deinit();

    try std.testing.expect(cache.get(0) == null);
    try std.testing.expectEqual(@as(usize, 0), cache.len());
}

test "ShufflingCache: LRU eviction" {
    var cache = ShufflingCache.init(std.testing.allocator, 2);
    defer cache.deinit();

    // We need real EpochShuffling instances to pass non-null pointers.
    // Use a dummy struct-sized allocation to avoid calling EpochShuffling.init.
    // (The cache doesn't dereference these in tests.)
    var dummy1 = EpochShuffling{ .allocator = std.testing.allocator, .epoch = 1, .active_indices = &.{}, .shuffling = &.{}, .committees = undefined, .committees_per_slot = 0 };
    var dummy2 = EpochShuffling{ .allocator = std.testing.allocator, .epoch = 2, .active_indices = &.{}, .shuffling = &.{}, .committees = undefined, .committees_per_slot = 0 };
    var dummy3 = EpochShuffling{ .allocator = std.testing.allocator, .epoch = 3, .active_indices = &.{}, .shuffling = &.{}, .committees = undefined, .committees_per_slot = 0 };

    try cache.put(1, &dummy1);
    try cache.put(2, &dummy2);
    try std.testing.expectEqual(@as(usize, 2), cache.len());

    // Insert epoch 3 → evicts LRU (epoch 1).
    try cache.put(3, &dummy3);
    try std.testing.expectEqual(@as(usize, 2), cache.len());
    try std.testing.expect(cache.get(1) == null);
    try std.testing.expect(cache.get(2) != null);
    try std.testing.expect(cache.get(3) != null);
}

test "ShufflingCache: prune removes old epochs" {
    var cache = ShufflingCache.init(std.testing.allocator, 4);
    defer cache.deinit();

    var dummy1 = EpochShuffling{ .allocator = std.testing.allocator, .epoch = 1, .active_indices = &.{}, .shuffling = &.{}, .committees = undefined, .committees_per_slot = 0 };
    var dummy2 = EpochShuffling{ .allocator = std.testing.allocator, .epoch = 2, .active_indices = &.{}, .shuffling = &.{}, .committees = undefined, .committees_per_slot = 0 };
    var dummy5 = EpochShuffling{ .allocator = std.testing.allocator, .epoch = 5, .active_indices = &.{}, .shuffling = &.{}, .committees = undefined, .committees_per_slot = 0 };

    try cache.put(1, &dummy1);
    try cache.put(2, &dummy2);
    try cache.put(5, &dummy5);

    cache.prune(3); // Remove epochs < 3.
    try std.testing.expect(cache.get(1) == null);
    try std.testing.expect(cache.get(2) == null);
    try std.testing.expect(cache.get(5) != null);
}
