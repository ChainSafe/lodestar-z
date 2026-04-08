//! CheckpointStateCache: cache of epoch boundary states with disk persistence.
//!
//! Recent epochs kept in memory, older ones persisted to disk via CPStateDatastore.
//! On reload, uses loadCachedBeaconState with a seed from BlockStateCache for fast
//! tree-sharing deserialization.
//!
//! Design mirrors Lodestar's PersistentCheckpointStateCache.
const std = @import("std");
const Allocator = std.mem.Allocator;
const preset = @import("preset").preset;
const state_transition = @import("state_transition");
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const computeStartSlotAtEpoch = state_transition.computeStartSlotAtEpoch;
const getBlockRootAtSlot = state_transition.getBlockRootAtSlot;

const CachedBeaconState = state_transition.CachedBeaconState;
const BlockStateCache = @import("block_state_cache.zig").BlockStateCache;
const StateGraphGate = @import("state_graph_gate.zig").StateGraphGate;
const StateDisposer = @import("state_disposer.zig").StateDisposer;
const datastore_mod = @import("datastore.zig");
const CPStateDatastore = datastore_mod.CPStateDatastore;
const CheckpointKey = datastore_mod.CheckpointKey;

pub const DEFAULT_MAX_EPOCHS_IN_MEMORY: u32 = 3;

pub const InMemoryCacheItem = struct {
    state: *CachedBeaconState,
    /// Preserved datastore key when a persisted checkpoint is reloaded into
    /// memory. This matches Lodestar's model and lets pruning / re-persisting
    /// retain disk provenance instead of forgetting it.
    persisted_key: ?[]const u8 = null,
};

pub const CacheItem = union(enum) {
    in_memory: InMemoryCacheItem,
    /// Datastore key for the persisted state bytes.
    persisted: []const u8,
};

/// Hash + equality context for CheckpointKey in std.ArrayHashMap.
const CheckpointKeyContext = struct {
    pub fn hash(_: CheckpointKeyContext, key: CheckpointKey) u32 {
        var h = std.hash.Wyhash.init(0);
        h.update(std.mem.asBytes(&key.epoch));
        h.update(&key.root);
        return @truncate(h.final());
    }

    pub fn eql(_: CheckpointKeyContext, a: CheckpointKey, b: CheckpointKey, _: usize) bool {
        return a.epoch == b.epoch and std.mem.eql(u8, &a.root, &b.root);
    }
};

pub const CheckpointStateCache = struct {
    allocator: Allocator,
    /// In-memory + persisted cache
    cache: std.ArrayHashMap(CheckpointKey, CacheItem, CheckpointKeyContext, true),
    /// Epoch -> list of roots that have checkpoint states at that epoch
    epoch_index: std.AutoArrayHashMap(u64, std.ArrayListUnmanaged([32]u8)),
    /// Disk persistence backend
    datastore: CPStateDatastore,
    /// Block state cache (for seed states on reload)
    block_cache: *BlockStateCache,
    /// Max epochs to keep in memory
    max_epochs_in_memory: u32,
    state_disposer: *StateDisposer,
    state_graph_gate: *StateGraphGate,

    pub fn init(
        allocator: Allocator,
        ds: CPStateDatastore,
        block_cache: *BlockStateCache,
        max_epochs: u32,
        state_disposer: *StateDisposer,
        state_graph_gate: *StateGraphGate,
    ) CheckpointStateCache {
        return .{
            .allocator = allocator,
            .cache = std.ArrayHashMap(CheckpointKey, CacheItem, CheckpointKeyContext, true).init(allocator),
            .epoch_index = std.AutoArrayHashMap(u64, std.ArrayListUnmanaged([32]u8)).init(allocator),
            .datastore = ds,
            .block_cache = block_cache,
            .max_epochs_in_memory = max_epochs,
            .state_disposer = state_disposer,
            .state_graph_gate = state_graph_gate,
        };
    }

    pub fn deinit(self: *CheckpointStateCache) void {
        // Free in-memory states and persisted keys
        for (self.cache.values()) |item| {
            switch (item) {
                .in_memory => |entry| {
                    self.disposeState(entry.state);
                    if (entry.persisted_key) |key| self.allocator.free(key);
                },
                .persisted => |key| {
                    self.allocator.free(key);
                },
            }
        }
        self.cache.deinit();

        // Free epoch index
        for (self.epoch_index.values()) |*list| {
            list.deinit(self.allocator);
        }
        self.epoch_index.deinit();
    }

    /// Get from memory only (fast path). Returns null if not present or persisted.
    pub fn get(self: *CheckpointStateCache, cp: CheckpointKey) ?*CachedBeaconState {
        const item = self.cache.get(cp) orelse return null;
        return switch (item) {
            .in_memory => |entry| entry.state,
            .persisted => null,
        };
    }

    /// Get from memory or reload from disk (slow path).
    /// Uses loadCachedBeaconState with a seed from block_cache for fast reload.
    pub fn getOrReload(self: *CheckpointStateCache, cp: CheckpointKey) !?*CachedBeaconState {
        // Fast path: check memory
        if (self.get(cp)) |state| return state;

        // Check if persisted
        const item = self.cache.get(cp) orelse return null;
        const persisted_key = switch (item) {
            .persisted => |key| key,
            .in_memory => |entry| return entry.state,
        };

        // Read from disk
        const state_bytes = try self.loadPersistedStateBytes(persisted_key) orelse return null;
        defer self.allocator.free(state_bytes);

        // Get seed state for tree-sharing reload.
        const seed_state = self.findSeedStateToReload(cp) orelse return null;

        const loadCachedBeaconState = state_transition.loadCachedBeaconState;
        const Node = @import("persistent_merkle_tree").Node;

        // Use the seed state's fork for now — loadCachedBeaconState uses the seed state's fork
        const fork_seq = seed_state.state.forkSeq();

        // Get the node pool from the seed state
        const pool: *Node.Pool = switch (seed_state.state.*) {
            inline else => |s| s.pool,
        };

        var state_graph_lease = self.state_graph_gate.acquire();
        defer state_graph_lease.release();

        const new_state = try loadCachedBeaconState(
            self.allocator,
            pool,
            seed_state,
            fork_seq,
            state_bytes,
            null,
        );
        errdefer {
            new_state.deinit();
            self.allocator.destroy(new_state);
        }

        try sealReloadedState(new_state);
        return try self.publishReloaded(cp, new_state);
    }

    pub fn clonePersistedKey(self: *CheckpointStateCache, allocator: Allocator, cp: CheckpointKey) !?[]u8 {
        const item = self.cache.get(cp) orelse return null;
        return switch (item) {
            .persisted => |key| try allocator.dupe(u8, key),
            .in_memory => null,
        };
    }

    pub fn loadPersistedStateBytes(
        self: *CheckpointStateCache,
        persisted_key: []const u8,
    ) !?[]const u8 {
        return self.datastore.read(persisted_key);
    }

    pub fn findSeedStateToReload(self: *CheckpointStateCache, reloaded_cp: CheckpointKey) ?*CachedBeaconState {
        const max_epoch = blk: {
            var best: ?u64 = null;
            for (self.epoch_index.keys()) |epoch| {
                if (best == null or epoch > best.?) best = epoch;
            }
            break :blk best orelse return self.block_cache.getSeedState();
        };

        const min_epoch = max_epoch -| @as(u64, self.max_epochs_in_memory -| 1);
        const reloaded_cp_slot = computeStartSlotAtEpoch(reloaded_cp.epoch);
        var first_state: ?*CachedBeaconState = null;

        var epoch = min_epoch;
        while (epoch <= max_epoch) : (epoch += 1) {
            if (first_state) |state| return state;

            const roots = self.epoch_index.get(epoch) orelse continue;
            for (roots.items) |root| {
                const item = self.cache.get(.{ .epoch = epoch, .root = root }) orelse continue;
                const state = switch (item) {
                    .in_memory => |entry| entry.state,
                    .persisted => continue,
                };

                if (first_state == null) first_state = state;

                const state_slot = state.state.slot() catch continue;
                if (reloaded_cp_slot >= state_slot) continue;

                const actual_root = switch (state.state.forkSeq()) {
                    inline else => |fork| getBlockRootAtSlot(
                        fork,
                        state.state.castToFork(fork),
                        reloaded_cp_slot,
                    ) catch continue,
                };
                if (std.mem.eql(u8, actual_root, &reloaded_cp.root)) {
                    return state;
                }
            }
        }

        return first_state orelse self.block_cache.getSeedState();
    }

    pub fn publishReloaded(
        self: *CheckpointStateCache,
        cp: CheckpointKey,
        state: *CachedBeaconState,
    ) !?*CachedBeaconState {
        const item = self.cache.get(cp) orelse {
            self.disposeState(state);
            return null;
        };

        switch (item) {
            .in_memory => |entry| {
                self.disposeState(state);
                return entry.state;
            },
            .persisted => |persisted_key| {
                try self.cache.put(cp, .{ .in_memory = .{
                    .state = state,
                    .persisted_key = persisted_key,
                } });
                return state;
            },
        }
    }

    /// Add a checkpoint state to the cache.
    pub fn add(self: *CheckpointStateCache, cp: CheckpointKey, state: *CachedBeaconState) !void {
        // If already in cache, free the old entry
        var persisted_key_to_keep: ?[]const u8 = null;
        if (self.cache.get(cp)) |old_item| {
            switch (old_item) {
                .persisted => |key| persisted_key_to_keep = key,
                .in_memory => |entry| {
                    persisted_key_to_keep = entry.persisted_key;
                    self.disposeState(entry.state);
                },
            }
        }

        try self.cache.put(cp, .{ .in_memory = .{
            .state = state,
            .persisted_key = persisted_key_to_keep,
        } });
        try self.addToEpochIndex(cp.epoch, cp.root);
    }

    /// Get the latest checkpoint state for a root, up to max_epoch (in-memory only).
    pub fn getLatest(self: *CheckpointStateCache, root: [32]u8, max_epoch: u64) ?*CachedBeaconState {
        var best_state: ?*CachedBeaconState = null;
        var best_epoch: u64 = 0;

        var it = self.cache.iterator();
        while (it.next()) |entry| {
            const cp = entry.key_ptr.*;
            if (!std.mem.eql(u8, &cp.root, &root)) continue;
            if (cp.epoch > max_epoch) continue;

            switch (entry.value_ptr.*) {
                .in_memory => |cached_entry| {
                    const state = cached_entry.state;
                    if (best_state == null or cp.epoch > best_epoch) {
                        best_state = state;
                        best_epoch = cp.epoch;
                    }
                },
                .persisted => {},
            }
        }

        return best_state;
    }

    /// Find the latest checkpoint key for a root, including persisted entries.
    pub fn findLatestKey(self: *CheckpointStateCache, root: [32]u8, max_epoch: u64) ?CheckpointKey {
        var best_cp: ?CheckpointKey = null;
        var best_epoch: u64 = 0;

        var it = self.cache.iterator();
        while (it.next()) |entry| {
            const cp = entry.key_ptr.*;
            if (!std.mem.eql(u8, &cp.root, &root)) continue;
            if (cp.epoch > max_epoch) continue;
            if (best_cp == null or cp.epoch > best_epoch) {
                best_cp = cp;
                best_epoch = cp.epoch;
            }
        }

        return best_cp;
    }

    /// Get the latest checkpoint state for a root, reloading from disk if needed.
    pub fn getOrReloadLatest(self: *CheckpointStateCache, root: [32]u8, max_epoch: u64) !?*CachedBeaconState {
        const cp = self.findLatestKey(root, max_epoch) orelse return null;
        return self.getOrReload(cp);
    }

    /// Process a state: persist epochs older than max_epochs_in_memory, prune from memory.
    /// Returns the number of states persisted.
    pub fn processState(self: *CheckpointStateCache, block_root: [32]u8, state: *CachedBeaconState) !u32 {
        _ = block_root;
        _ = state;

        var persist_count: u32 = 0;

        // Collect all epochs and sort ascending
        var epochs: std.ArrayListUnmanaged(u64) = .empty;
        defer epochs.deinit(self.allocator);

        for (self.epoch_index.keys()) |epoch| {
            try epochs.append(self.allocator, epoch);
        }

        std.mem.sort(u64, epochs.items, {}, std.sort.asc(u64));

        if (epochs.items.len <= self.max_epochs_in_memory) return 0;

        // Persist epochs that are too old
        const persist_count_target = epochs.items.len - self.max_epochs_in_memory;
        for (epochs.items[0..persist_count_target]) |epoch| {
            persist_count += try self.persistEpoch(epoch);
        }

        return persist_count;
    }

    /// Prune everything before finalized epoch: remove from memory and disk.
    pub fn pruneFinalized(self: *CheckpointStateCache, finalized_epoch: u64) !void {
        var epochs_to_prune: std.ArrayListUnmanaged(u64) = .empty;
        defer epochs_to_prune.deinit(self.allocator);

        for (self.epoch_index.keys()) |epoch| {
            if (epoch < finalized_epoch) {
                try epochs_to_prune.append(self.allocator, epoch);
            }
        }

        for (epochs_to_prune.items) |epoch| {
            try self.deleteAllEpochItems(epoch);
        }
    }

    /// Number of items in the cache (memory + persisted).
    pub fn size(self: *const CheckpointStateCache) usize {
        return self.cache.count();
    }

    // -- Internal helpers --

    fn addToEpochIndex(self: *CheckpointStateCache, epoch: u64, root: [32]u8) !void {
        const gop = try self.epoch_index.getOrPut(epoch);
        if (!gop.found_existing) {
            gop.value_ptr.* = .empty;
        }
        // Don't add duplicate roots
        for (gop.value_ptr.items) |existing| {
            if (std.mem.eql(u8, &existing, &root)) return;
        }
        try gop.value_ptr.append(self.allocator, root);
    }

    fn removeFromEpochIndex(self: *CheckpointStateCache, epoch: u64, root: [32]u8) void {
        const entry = self.epoch_index.getPtr(epoch) orelse return;
        var i: usize = 0;
        while (i < entry.items.len) {
            if (std.mem.eql(u8, &entry.items[i], &root)) {
                _ = entry.orderedRemove(i);
            } else {
                i += 1;
            }
        }
        if (entry.items.len == 0) {
            entry.deinit(self.allocator);
            _ = self.epoch_index.orderedRemove(epoch);
        }
    }

    /// Persist all in-memory states for an epoch to disk, replacing with persisted keys.
    fn persistEpoch(self: *CheckpointStateCache, epoch: u64) !u32 {
        var persist_count: u32 = 0;
        const roots = self.epoch_index.get(epoch) orelse return 0;

        for (roots.items) |root| {
            const cp = CheckpointKey{ .epoch = epoch, .root = root };
            const item = self.cache.get(cp) orelse continue;

            switch (item) {
                .in_memory => |entry| {
                    const persisted_key = blk: {
                        if (entry.persisted_key) |key| break :blk key;

                        const state_bytes = try entry.state.state.serialize(self.allocator);
                        defer self.allocator.free(state_bytes);
                        break :blk try self.datastore.write(cp, state_bytes);
                    };

                    self.cache.put(cp, .{ .persisted = persisted_key }) catch |err| {
                        if (entry.persisted_key == null) self.allocator.free(persisted_key);
                        return err;
                    };

                    self.disposeState(entry.state);

                    persist_count += 1;
                },
                .persisted => {},
            }
        }

        return persist_count;
    }

    /// Delete all items for an epoch from both memory/cache and disk.
    fn deleteAllEpochItems(self: *CheckpointStateCache, epoch: u64) !void {
        const roots = self.epoch_index.get(epoch) orelse return;

        // Copy roots since we'll modify the cache
        const roots_copy = try self.allocator.alloc([32]u8, roots.items.len);
        defer self.allocator.free(roots_copy);
        @memcpy(roots_copy, roots.items);

        for (roots_copy) |root| {
            const cp = CheckpointKey{ .epoch = epoch, .root = root };
            if (self.cache.fetchOrderedRemove(cp)) |kv| {
                switch (kv.value) {
                    .in_memory => |entry| {
                        self.disposeState(entry.state);
                        if (entry.persisted_key) |key| {
                            self.datastore.remove(key) catch {};
                            self.allocator.free(key);
                        }
                    },
                    .persisted => |key| {
                        self.datastore.remove(key) catch {};
                        self.allocator.free(key);
                    },
                }
            }
        }

        // Remove epoch from index
        if (self.epoch_index.getPtr(epoch)) |list| {
            list.deinit(self.allocator);
            _ = self.epoch_index.orderedRemove(epoch);
        }
    }

    fn disposeState(self: *CheckpointStateCache, state: *CachedBeaconState) void {
        self.state_disposer.dispose(state) catch @panic("OOM deferring checkpoint-state disposal");
    }

    fn sealReloadedState(state: *CachedBeaconState) !void {
        try state.state.commit();
        _ = try state.state.hashTreeRoot();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "CheckpointStateCache: add and get" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    const MemoryCPStateDatastore = datastore_mod.MemoryCPStateDatastore;

    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var mem_store = MemoryCPStateDatastore.init(allocator);
    defer mem_store.deinit();
    const ds = mem_store.datastore();

    var state_disposer = StateDisposer.init(allocator, std.testing.io);
    defer state_disposer.deinit();
    var state_graph_gate = StateGraphGate.init(std.testing.io, &state_disposer);

    var block_cache = BlockStateCache.init(allocator, 4, &state_disposer);
    defer block_cache.deinit();

    // Add seed to block cache
    const seed = try test_state.cached_state.clone(allocator, .{});
    _ = try block_cache.add(seed, true);

    var cp_cache = CheckpointStateCache.init(allocator, ds, &block_cache, 3, &state_disposer, &state_graph_gate);
    defer cp_cache.deinit();

    const state1 = try test_state.cached_state.clone(allocator, .{});
    const cp1 = CheckpointKey{ .epoch = 10, .root = [_]u8{0x01} ** 32 };
    try cp_cache.add(cp1, state1);

    // Get should find it
    try std.testing.expect(cp_cache.get(cp1) != null);
    try std.testing.expectEqual(@as(usize, 1), cp_cache.size());
}

test "CheckpointStateCache: getLatest" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    const MemoryCPStateDatastore = datastore_mod.MemoryCPStateDatastore;

    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var mem_store = MemoryCPStateDatastore.init(allocator);
    defer mem_store.deinit();
    const ds = mem_store.datastore();

    var state_disposer = StateDisposer.init(allocator, std.testing.io);
    defer state_disposer.deinit();
    var state_graph_gate = StateGraphGate.init(std.testing.io, &state_disposer);

    var block_cache = BlockStateCache.init(allocator, 4, &state_disposer);
    defer block_cache.deinit();

    var cp_cache = CheckpointStateCache.init(allocator, ds, &block_cache, 3, &state_disposer, &state_graph_gate);
    defer cp_cache.deinit();

    const root = [_]u8{0x42} ** 32;

    // Add states at epochs 5, 10, 15
    const state5 = try test_state.cached_state.clone(allocator, .{});
    try cp_cache.add(CheckpointKey{ .epoch = 5, .root = root }, state5);

    const state10 = try test_state.cached_state.clone(allocator, .{});
    try cp_cache.add(CheckpointKey{ .epoch = 10, .root = root }, state10);

    const state15 = try test_state.cached_state.clone(allocator, .{});
    try cp_cache.add(CheckpointKey{ .epoch = 15, .root = root }, state15);

    // getLatest with max_epoch=12 should find epoch 10
    const latest = cp_cache.getLatest(root, 12);
    try std.testing.expect(latest != null);
    try std.testing.expectEqual(state10, latest.?);

    // getLatest with max_epoch=4 should find nothing
    const none = cp_cache.getLatest(root, 4);
    try std.testing.expect(none == null);
}

test "CheckpointStateCache: processState persists old epochs" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    const MemoryCPStateDatastore = datastore_mod.MemoryCPStateDatastore;

    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var mem_store = MemoryCPStateDatastore.init(allocator);
    defer mem_store.deinit();
    const ds = mem_store.datastore();

    var state_disposer = StateDisposer.init(allocator, std.testing.io);
    defer state_disposer.deinit();
    var state_graph_gate = StateGraphGate.init(std.testing.io, &state_disposer);

    var block_cache = BlockStateCache.init(allocator, 4, &state_disposer);
    defer block_cache.deinit();

    // max 2 epochs in memory
    var cp_cache = CheckpointStateCache.init(allocator, ds, &block_cache, 2, &state_disposer, &state_graph_gate);
    defer cp_cache.deinit();

    // Add states at epochs 1, 2, 3, 4
    for (1..5) |epoch_val| {
        const epoch: u64 = @intCast(epoch_val);
        const state = try test_state.cached_state.clone(allocator, .{});
        const root = [_]u8{@intCast(epoch_val)} ** 32;
        try cp_cache.add(CheckpointKey{ .epoch = epoch, .root = root }, state);
    }

    try std.testing.expectEqual(@as(usize, 4), cp_cache.size());

    // processState should persist epochs 1 and 2 (keeping 3 and 4 in memory)
    const dummy_root = [_]u8{0xff} ** 32;
    const persist_count = try cp_cache.processState(dummy_root, test_state.cached_state);
    try std.testing.expectEqual(@as(u32, 2), persist_count);

    // Epoch 1 and 2 should now be persisted (get returns null for persisted)
    const cp1 = CheckpointKey{ .epoch = 1, .root = [_]u8{0x01} ** 32 };
    try std.testing.expect(cp_cache.get(cp1) == null);

    // Epoch 3 should still be in memory
    const cp3 = CheckpointKey{ .epoch = 3, .root = [_]u8{0x03} ** 32 };
    try std.testing.expect(cp_cache.get(cp3) != null);

    // Datastore should have 2 entries
    try std.testing.expectEqual(@as(usize, 2), mem_store.count());
}

test "CheckpointStateCache: pruneFinalized" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    const MemoryCPStateDatastore = datastore_mod.MemoryCPStateDatastore;

    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var mem_store = MemoryCPStateDatastore.init(allocator);
    defer mem_store.deinit();
    const ds = mem_store.datastore();

    var state_disposer = StateDisposer.init(allocator, std.testing.io);
    defer state_disposer.deinit();
    var state_graph_gate = StateGraphGate.init(std.testing.io, &state_disposer);

    var block_cache = BlockStateCache.init(allocator, 4, &state_disposer);
    defer block_cache.deinit();

    var cp_cache = CheckpointStateCache.init(allocator, ds, &block_cache, 3, &state_disposer, &state_graph_gate);
    defer cp_cache.deinit();

    // Add states at epochs 5, 10, 15
    for ([_]u64{ 5, 10, 15 }) |epoch| {
        const state = try test_state.cached_state.clone(allocator, .{});
        try cp_cache.add(CheckpointKey{ .epoch = epoch, .root = [_]u8{@intCast(epoch)} ** 32 }, state);
    }

    try std.testing.expectEqual(@as(usize, 3), cp_cache.size());

    // Prune before epoch 12 — should remove epochs 5 and 10
    try cp_cache.pruneFinalized(12);
    try std.testing.expectEqual(@as(usize, 1), cp_cache.size());

    // Epoch 15 should remain
    const cp15 = CheckpointKey{ .epoch = 15, .root = [_]u8{15} ** 32 };
    try std.testing.expect(cp_cache.get(cp15) != null);
}

test "CheckpointStateCache: multiple roots per epoch" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    const MemoryCPStateDatastore = datastore_mod.MemoryCPStateDatastore;

    const allocator = std.testing.allocator;
    const pool_size = 256 * 10;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var mem_store = MemoryCPStateDatastore.init(allocator);
    defer mem_store.deinit();
    const ds = mem_store.datastore();

    var state_disposer = StateDisposer.init(allocator, std.testing.io);
    defer state_disposer.deinit();
    var state_graph_gate = StateGraphGate.init(std.testing.io, &state_disposer);

    var block_cache = BlockStateCache.init(allocator, 4, &state_disposer);
    defer block_cache.deinit();

    var cp_cache = CheckpointStateCache.init(allocator, ds, &block_cache, 3, &state_disposer, &state_graph_gate);
    defer cp_cache.deinit();

    // Add two different roots at the same epoch
    const root_a = [_]u8{0xaa} ** 32;
    const root_b = [_]u8{0xbb} ** 32;

    const state_a = try test_state.cached_state.clone(allocator, .{});
    try cp_cache.add(CheckpointKey{ .epoch = 10, .root = root_a }, state_a);

    const state_b = try test_state.cached_state.clone(allocator, .{});
    try cp_cache.add(CheckpointKey{ .epoch = 10, .root = root_b }, state_b);

    try std.testing.expectEqual(@as(usize, 2), cp_cache.size());
    try std.testing.expect(cp_cache.get(CheckpointKey{ .epoch = 10, .root = root_a }) != null);
    try std.testing.expect(cp_cache.get(CheckpointKey{ .epoch = 10, .root = root_b }) != null);

    // Different root should return null
    try std.testing.expect(cp_cache.get(CheckpointKey{ .epoch = 10, .root = [_]u8{0xcc} ** 32 }) == null);
}

test "CheckpointStateCache: persist and prune full cycle" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    const MemoryCPStateDatastore = datastore_mod.MemoryCPStateDatastore;

    const allocator = std.testing.allocator;
    const pool_size = 256 * 10;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var mem_store = MemoryCPStateDatastore.init(allocator);
    defer mem_store.deinit();
    const ds = mem_store.datastore();

    var state_disposer = StateDisposer.init(allocator, std.testing.io);
    defer state_disposer.deinit();
    var state_graph_gate = StateGraphGate.init(std.testing.io, &state_disposer);

    var block_cache = BlockStateCache.init(allocator, 4, &state_disposer);
    defer block_cache.deinit();

    // max 1 epoch in memory for aggressive testing
    var cp_cache = CheckpointStateCache.init(allocator, ds, &block_cache, 1, &state_disposer, &state_graph_gate);
    defer cp_cache.deinit();

    // Add epoch 1, 2, 3
    for (1..4) |epoch_val| {
        const epoch: u64 = @intCast(epoch_val);
        const state = try test_state.cached_state.clone(allocator, .{});
        try cp_cache.add(CheckpointKey{ .epoch = epoch, .root = [_]u8{@intCast(epoch_val)} ** 32 }, state);
    }

    try std.testing.expectEqual(@as(usize, 3), cp_cache.size());

    // processState should persist epochs 1 and 2 (only epoch 3 stays in memory)
    const dummy_root = [_]u8{0xff} ** 32;
    const persist_count = try cp_cache.processState(dummy_root, test_state.cached_state);
    try std.testing.expectEqual(@as(u32, 2), persist_count);
    try std.testing.expectEqual(@as(usize, 2), mem_store.count());

    // Epoch 3 still in memory
    const cp3 = CheckpointKey{ .epoch = 3, .root = [_]u8{0x03} ** 32 };
    try std.testing.expect(cp_cache.get(cp3) != null);

    // Epoch 1 persisted (not in memory)
    const cp1 = CheckpointKey{ .epoch = 1, .root = [_]u8{0x01} ** 32 };
    try std.testing.expect(cp_cache.get(cp1) == null);

    // Prune finalized — removes epoch 1 and 2 from disk
    try cp_cache.pruneFinalized(3);
    try std.testing.expectEqual(@as(usize, 1), cp_cache.size());

    // Only epoch 3 remains
    try std.testing.expect(cp_cache.get(cp3) != null);
}

test "CheckpointStateCache: add replaces existing in-memory state" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    const MemoryCPStateDatastore = datastore_mod.MemoryCPStateDatastore;

    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var mem_store = MemoryCPStateDatastore.init(allocator);
    defer mem_store.deinit();
    const ds = mem_store.datastore();

    var state_disposer = StateDisposer.init(allocator, std.testing.io);
    defer state_disposer.deinit();
    var state_graph_gate = StateGraphGate.init(std.testing.io, &state_disposer);

    var block_cache = BlockStateCache.init(allocator, 4, &state_disposer);
    defer block_cache.deinit();

    var cp_cache = CheckpointStateCache.init(allocator, ds, &block_cache, 3, &state_disposer, &state_graph_gate);
    defer cp_cache.deinit();

    const cp = CheckpointKey{ .epoch = 5, .root = [_]u8{0x55} ** 32 };

    // Add first state
    const state1 = try test_state.cached_state.clone(allocator, .{});
    try cp_cache.add(cp, state1);

    // Replace with second state — should deinit first
    const state2 = try test_state.cached_state.clone(allocator, .{});
    try cp_cache.add(cp, state2);

    try std.testing.expectEqual(@as(usize, 1), cp_cache.size());
    try std.testing.expectEqual(state2, cp_cache.get(cp).?);
}

test "CheckpointStateCache: replacement can defer state teardown" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    const MemoryCPStateDatastore = datastore_mod.MemoryCPStateDatastore;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var mem_store = MemoryCPStateDatastore.init(allocator);
    defer mem_store.deinit();
    const ds = mem_store.datastore();

    var state_disposer = StateDisposer.init(allocator, std.testing.io);
    defer state_disposer.deinit();
    var state_graph_gate = StateGraphGate.init(std.testing.io, &state_disposer);

    var block_cache = BlockStateCache.init(allocator, 4, &state_disposer);
    defer block_cache.deinit();

    var cp_cache = CheckpointStateCache.init(
        allocator,
        ds,
        &block_cache,
        3,
        &state_disposer,
        &state_graph_gate,
    );
    defer cp_cache.deinit();

    const cp = CheckpointKey{ .epoch = 5, .root = [_]u8{0x55} ** 32 };

    const state1 = try test_state.cached_state.clone(allocator, .{});
    try cp_cache.add(cp, state1);

    state_disposer.beginDeferral();
    const state2 = try test_state.cached_state.clone(allocator, .{});
    try state2.state.setSlot((try state2.state.slot()) + 1);
    try cp_cache.add(cp, state2);

    try std.testing.expectEqual(@as(usize, 1), state_disposer.pendingCount());

    try state_disposer.endDeferral();
    try std.testing.expectEqual(@as(usize, 0), state_disposer.pendingCount());
}

test "CheckpointStateCache: reload preserves persisted provenance for later pruning" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    const MemoryCPStateDatastore = datastore_mod.MemoryCPStateDatastore;

    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var mem_store = MemoryCPStateDatastore.init(allocator);
    defer mem_store.deinit();

    var state_disposer = StateDisposer.init(allocator, std.testing.io);
    defer state_disposer.deinit();
    var state_graph_gate = StateGraphGate.init(std.testing.io, &state_disposer);

    var block_cache = BlockStateCache.init(allocator, 4, &state_disposer);
    defer block_cache.deinit();

    const seed = try test_state.cached_state.clone(allocator, .{});
    _ = try block_cache.add(seed, true);

    var cp_cache = CheckpointStateCache.init(
        allocator,
        mem_store.datastore(),
        &block_cache,
        1,
        &state_disposer,
        &state_graph_gate,
    );
    defer cp_cache.deinit();

    const cp1 = CheckpointKey{ .epoch = 1, .root = [_]u8{0x11} ** 32 };
    const cp2 = CheckpointKey{ .epoch = 2, .root = [_]u8{0x22} ** 32 };
    try cp_cache.add(cp1, try test_state.cached_state.clone(allocator, .{}));
    try cp_cache.add(cp2, try test_state.cached_state.clone(allocator, .{}));

    _ = try cp_cache.processState([_]u8{0xff} ** 32, test_state.cached_state);
    try std.testing.expectEqual(@as(usize, 1), mem_store.count());
    try std.testing.expect(cp_cache.get(cp1) == null);

    const reloaded = try cp_cache.getOrReload(cp1);
    try std.testing.expect(reloaded != null);
    try std.testing.expectEqual(reloaded, cp_cache.get(cp1));
    try std.testing.expectEqual(@as(usize, 1), mem_store.count());

    try cp_cache.pruneFinalized(2);
    try std.testing.expectEqual(@as(usize, 1), cp_cache.size());
    try std.testing.expectEqual(@as(usize, 0), mem_store.count());
}
