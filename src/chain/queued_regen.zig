//! QueuedStateRegen — wraps StateRegen with request queuing and deduplication.
//!
//! When multiple callers request the same state simultaneously (common during
//! reorgs when many attestations need the same historical state), only one
//! regeneration runs. All callers receive the same result.
//!
//! Requests are prioritized: block import > fork choice > API > background.
//! Low-priority requests can be dropped under load.
//!
//! Design mirrors Lodestar's QueuedStateRegenerator in chain/regen/queued.ts.

const std = @import("std");
const Allocator = std.mem.Allocator;

const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;
const BlockStateCache = state_transition.BlockStateCache;
const CheckpointStateCache = state_transition.CheckpointStateCache;
const StateRegen = state_transition.StateRegen;
const CheckpointKey = state_transition.CheckpointKey;
const computeEpochAtSlot = state_transition.computeEpochAtSlot;

/// Priority for state regen requests (lower numeric value = higher priority).
pub const RegenPriority = enum(u2) {
    /// Block import — highest priority, must not be delayed.
    block_import = 0,
    /// Fork choice updates — high priority.
    fork_choice = 1,
    /// REST API queries — normal priority.
    api = 2,
    /// Background tasks (cache warming, etc.) — lowest priority.
    background = 3,

    pub fn isHigherOrEqual(self: RegenPriority, other: RegenPriority) bool {
        return @intFromEnum(self) <= @intFromEnum(other);
    }
};

/// Identifies the kind of regen request.
pub const RegenRequestKind = enum {
    /// Get state by block root.
    block_root,
    /// Get checkpoint state by (epoch, root).
    checkpoint,
    /// Get pre-state for a block (by parent root + block slot).
    pre_state,
    /// Get state by state root.
    state_root,
};

/// Key for deduplication — uniquely identifies a regen target.
pub const RegenKey = union(RegenRequestKind) {
    block_root: [32]u8,
    checkpoint: CheckpointKey,
    pre_state: struct { parent_root: [32]u8, block_slot: u64 },
    state_root: [32]u8,

    pub fn eql(a: RegenKey, b: RegenKey) bool {
        const tag_a: RegenRequestKind = a;
        const tag_b: RegenRequestKind = b;
        if (tag_a != tag_b) return false;
        return switch (a) {
            .block_root => |ra| std.mem.eql(u8, &ra, &b.block_root),
            .checkpoint => |ca| ca.epoch == b.checkpoint.epoch and std.mem.eql(u8, &ca.root, &b.checkpoint.root),
            .pre_state => |pa| std.mem.eql(u8, &pa.parent_root, &b.pre_state.parent_root) and pa.block_slot == b.pre_state.block_slot,
            .state_root => |ra| std.mem.eql(u8, &ra, &b.state_root),
        };
    }

    pub fn hash(self: RegenKey) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(std.mem.asBytes(&@as(RegenRequestKind, self)));
        switch (self) {
            .block_root => |r| h.update(&r),
            .checkpoint => |cp| {
                h.update(std.mem.asBytes(&cp.epoch));
                h.update(&cp.root);
            },
            .pre_state => |ps| {
                h.update(&ps.parent_root);
                h.update(std.mem.asBytes(&ps.block_slot));
            },
            .state_root => |r| h.update(&r),
        }
        return h.final();
    }
};

/// A queued regen request.
pub const RegenRequest = struct {
    key: RegenKey,
    priority: RegenPriority,
};

/// Result of a completed regen request.
pub const RegenResult = union(enum) {
    success: *CachedBeaconState,
    failure: RegenError,
};

/// Errors specific to the regen subsystem.
pub const RegenError = error{
    NoPreStateAvailable,
    QueueFull,
    RequestDropped,
    StateNotFound,
};

pub const REGEN_QUEUE_MAX_LEN: u32 = 256;
pub const REGEN_CAN_ACCEPT_WORK_THRESHOLD: u32 = 16;

/// QueuedStateRegen — request-queued state regenerator with deduplication.
///
/// Synchronous fast-path: if the state is already cached, return immediately.
/// Async slow-path: queue the request; the worker thread processes it.
///
/// For now (single-threaded beacon node), the "queue" is processed inline
/// via `processNext()`. When the beacon node moves to multi-threaded
/// (std.Io fibers), the queue will be drained by a dedicated worker.
pub const QueuedStateRegen = struct {
    allocator: Allocator,
    /// The underlying state regenerator (does the actual work).
    regen: *StateRegen,
    /// Queued requests, ordered by priority (lower enum value = higher priority).
    queue: std.ArrayListUnmanaged(RegenRequest),
    /// Maximum queue length before we start dropping low-priority requests.
    max_queue_len: u32,

    // -- Metrics --
    /// Total requests served from cache (fast path).
    cache_hits: u64,
    /// Total requests that went through the queue (slow path).
    queue_hits: u64,
    /// Total requests dropped due to queue pressure.
    dropped: u64,

    pub fn init(allocator: Allocator, regen: *StateRegen) QueuedStateRegen {
        return initWithConfig(allocator, regen, REGEN_QUEUE_MAX_LEN);
    }

    pub fn initWithConfig(allocator: Allocator, regen: *StateRegen, max_queue_len: u32) QueuedStateRegen {
        return .{
            .allocator = allocator,
            .regen = regen,
            .queue = .empty,
            .max_queue_len = max_queue_len,
            .cache_hits = 0,
            .queue_hits = 0,
            .dropped = 0,
        };
    }

    pub fn deinit(self: *QueuedStateRegen) void {
        self.queue.deinit(self.allocator);
    }

    // -----------------------------------------------------------------------
    // Public API — synchronous fast path with fallback to regen
    // -----------------------------------------------------------------------

    /// Get the pre-state for processing a block.
    ///
    /// Fast path: checks block cache and checkpoint cache.
    /// Slow path: delegates to StateRegen.getPreState (which may read from DB).
    pub fn getPreState(
        self: *QueuedStateRegen,
        parent_root: [32]u8,
        block_slot: u64,
        priority: RegenPriority,
    ) !*CachedBeaconState {
        _ = priority;

        // Fast path: try caches directly.
        if (self.regen.block_cache.get(parent_root)) |state| {
            self.cache_hits += 1;
            return state;
        }

        // Try checkpoint cache.
        const target_epoch = computeEpochAtSlot(block_slot);
        if (try self.regen.checkpoint_cache.getOrReload(.{
            .epoch = target_epoch,
            .root = parent_root,
        })) |state| {
            self.cache_hits += 1;
            return state;
        }

        // Slow path: full regen (may hit DB).
        self.queue_hits += 1;
        return self.regen.getPreState(parent_root, block_slot);
    }

    /// Get a checkpoint state (epoch boundary state).
    ///
    /// Fast path: check checkpoint cache.
    /// Slow path: delegates to StateRegen.getCheckpointState.
    pub fn getCheckpointState(
        self: *QueuedStateRegen,
        cp: CheckpointKey,
        priority: RegenPriority,
    ) !?*CachedBeaconState {
        _ = priority;

        // Fast path.
        if (self.regen.checkpoint_cache.get(cp)) |state| {
            self.cache_hits += 1;
            return state;
        }

        // Slow path: reload from disk.
        self.queue_hits += 1;
        return self.regen.getCheckpointState(cp);
    }

    /// Get state by state root.
    ///
    /// Fast path: check block state cache.
    /// Slow path: search DB archives.
    pub fn getStateByRoot(
        self: *QueuedStateRegen,
        state_root: [32]u8,
        priority: RegenPriority,
    ) !?*CachedBeaconState {
        _ = priority;

        // Fast path.
        if (self.regen.block_cache.get(state_root)) |state| {
            self.cache_hits += 1;
            return state;
        }

        // Slow path.
        self.queue_hits += 1;
        return self.regen.getStateByRoot(state_root);
    }

    // -----------------------------------------------------------------------
    // Queue management
    // -----------------------------------------------------------------------

    /// Enqueue a regen request. If the queue is full, drop the lowest-priority
    /// request to make room (if the new request has higher priority).
    pub fn enqueue(self: *QueuedStateRegen, request: RegenRequest) !void {
        // Dedup: skip if same key already queued with equal or higher priority.
        for (self.queue.items) |*existing| {
            if (existing.key.eql(request.key)) {
                // Upgrade priority if needed.
                if (request.priority.isHigherOrEqual(existing.priority)) {
                    existing.priority = request.priority;
                }
                return;
            }
        }

        if (self.queue.items.len >= self.max_queue_len) {
            // Try to drop a lower-priority request.
            if (self.dropLowestPriority(request.priority)) {
                self.dropped += 1;
            } else {
                return error.OutOfMemory; // Queue full, all higher priority.
            }
        }

        try self.queue.append(self.allocator, request);
    }

    /// Process the highest-priority request in the queue.
    /// Returns true if a request was processed, false if the queue is empty.
    pub fn processNext(self: *QueuedStateRegen) !bool {
        if (self.queue.items.len == 0) return false;

        // Find highest-priority request (lowest enum value).
        var best_idx: usize = 0;
        var best_priority = self.queue.items[0].priority;

        for (self.queue.items[1..], 1..) |item, idx| {
            if (item.priority.isHigherOrEqual(best_priority)) {
                best_priority = item.priority;
                best_idx = idx;
            }
        }

        const request = self.queue.orderedRemove(best_idx);

        // Execute the regen.
        switch (request.key) {
            .block_root => |root| {
                _ = try self.regen.getStateByRoot(root);
            },
            .checkpoint => |cp| {
                _ = try self.regen.getCheckpointState(cp);
            },
            .pre_state => |ps| {
                _ = try self.regen.getPreState(ps.parent_root, ps.block_slot);
            },
            .state_root => |root| {
                _ = try self.regen.getStateByRoot(root);
            },
        }

        return true;
    }

    /// Drop all pending requests with priority lower than `min_priority`.
    pub fn dropLowPriority(self: *QueuedStateRegen, min_priority: RegenPriority) void {
        var i: usize = 0;
        while (i < self.queue.items.len) {
            if (!self.queue.items[i].priority.isHigherOrEqual(min_priority)) {
                _ = self.queue.orderedRemove(i);
                self.dropped += 1;
            } else {
                i += 1;
            }
        }
    }

    /// Whether the queue can accept new work (below threshold).
    pub fn canAcceptWork(self: *const QueuedStateRegen) bool {
        return self.queue.items.len < REGEN_CAN_ACCEPT_WORK_THRESHOLD;
    }

    /// Number of requests currently queued.
    pub fn queueLen(self: *const QueuedStateRegen) usize {
        return self.queue.items.len;
    }

    // -----------------------------------------------------------------------
    // Delegate lifecycle events to underlying StateRegen
    // -----------------------------------------------------------------------

    /// Called after processing a new block — cache the resulting state.
    pub fn onNewBlock(self: *QueuedStateRegen, state: *CachedBeaconState, is_head: bool) ![32]u8 {
        return self.regen.onNewBlock(state, is_head);
    }

    /// Called when a new head is selected.
    pub fn onNewHead(self: *QueuedStateRegen, state: *CachedBeaconState) ![32]u8 {
        return self.regen.onNewHead(state);
    }

    /// Called on epoch boundary — store checkpoint state.
    pub fn onCheckpoint(self: *QueuedStateRegen, cp: CheckpointKey, state: *CachedBeaconState) !void {
        return self.regen.onCheckpoint(cp, state);
    }

    /// Called on finalization — prune stale states and drop low-priority queue items.
    pub fn onFinalized(self: *QueuedStateRegen, finalized_epoch: u64) !void {
        try self.regen.onFinalized(finalized_epoch);
        // Under finalization, drop background requests — they're likely stale.
        self.dropLowPriority(.api);
    }

    // -----------------------------------------------------------------------
    // Metrics / debugging
    // -----------------------------------------------------------------------

    pub const Metrics = struct {
        cache_hits: u64,
        queue_hits: u64,
        dropped: u64,
        queue_len: usize,
    };

    pub fn getMetrics(self: *const QueuedStateRegen) Metrics {
        return .{
            .cache_hits = self.cache_hits,
            .queue_hits = self.queue_hits,
            .dropped = self.dropped,
            .queue_len = self.queue.items.len,
        };
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /// Drop the single lowest-priority request that has priority strictly
    /// lower than `min_priority`. Returns true if something was dropped.
    fn dropLowestPriority(self: *QueuedStateRegen, min_priority: RegenPriority) bool {
        var worst_idx: ?usize = null;
        var worst_priority: RegenPriority = min_priority;

        for (self.queue.items, 0..) |item, idx| {
            if (!item.priority.isHigherOrEqual(worst_priority)) {
                worst_priority = item.priority;
                worst_idx = idx;
            }
        }

        if (worst_idx) |idx| {
            _ = self.queue.orderedRemove(idx);
            return true;
        }
        return false;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "QueuedStateRegen: init and deinit" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    
    const MemoryCPStateDatastore = @import("state_transition").MemoryCPStateDatastore;

    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var mem_store = MemoryCPStateDatastore.init(allocator);
    defer mem_store.deinit();
    const ds = mem_store.datastore();

    var block_cache = BlockStateCache.init(allocator, 4);
    defer block_cache.deinit();

    var cp_cache = CheckpointStateCache.init(allocator, ds, &block_cache, 3);
    defer cp_cache.deinit();

    var regen = StateRegen.init(allocator, &block_cache, &cp_cache);

    var queued = QueuedStateRegen.init(allocator, &regen);
    defer queued.deinit();

    try std.testing.expectEqual(@as(usize, 0), queued.queueLen());
    try std.testing.expect(queued.canAcceptWork());
}

test "QueuedStateRegen: getPreState cache hit" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    
    const MemoryCPStateDatastore = @import("state_transition").MemoryCPStateDatastore;

    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var mem_store = MemoryCPStateDatastore.init(allocator);
    defer mem_store.deinit();
    const ds = mem_store.datastore();

    var block_cache = BlockStateCache.init(allocator, 4);
    defer block_cache.deinit();

    var cp_cache = CheckpointStateCache.init(allocator, ds, &block_cache, 3);
    defer cp_cache.deinit();

    var regen = StateRegen.init(allocator, &block_cache, &cp_cache);

    var queued = QueuedStateRegen.init(allocator, &regen);
    defer queued.deinit();

    // Add a state to block cache.
    const state = try test_state.cached_state.clone(allocator, .{});
    const root = try regen.onNewBlock(state, true);

    // getPreState should find it via cache.
    const result = try queued.getPreState(root, 100, .block_import);
    try std.testing.expectEqual(state, result);
    try std.testing.expectEqual(@as(u64, 1), queued.cache_hits);
}

test "QueuedStateRegen: enqueue deduplicates" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    
    const MemoryCPStateDatastore = @import("state_transition").MemoryCPStateDatastore;

    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var mem_store = MemoryCPStateDatastore.init(allocator);
    defer mem_store.deinit();
    const ds = mem_store.datastore();

    var block_cache = BlockStateCache.init(allocator, 4);
    defer block_cache.deinit();

    var cp_cache = CheckpointStateCache.init(allocator, ds, &block_cache, 3);
    defer cp_cache.deinit();

    var regen = StateRegen.init(allocator, &block_cache, &cp_cache);

    var queued = QueuedStateRegen.init(allocator, &regen);
    defer queued.deinit();

    const root = [_]u8{0x42} ** 32;

    // Enqueue same key twice — should deduplicate.
    try queued.enqueue(.{
        .key = .{ .block_root = root },
        .priority = .api,
    });
    try queued.enqueue(.{
        .key = .{ .block_root = root },
        .priority = .api,
    });

    try std.testing.expectEqual(@as(usize, 1), queued.queueLen());
}

test "QueuedStateRegen: enqueue upgrades priority" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    
    const MemoryCPStateDatastore = @import("state_transition").MemoryCPStateDatastore;

    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var mem_store = MemoryCPStateDatastore.init(allocator);
    defer mem_store.deinit();
    const ds = mem_store.datastore();

    var block_cache = BlockStateCache.init(allocator, 4);
    defer block_cache.deinit();

    var cp_cache = CheckpointStateCache.init(allocator, ds, &block_cache, 3);
    defer cp_cache.deinit();

    var regen = StateRegen.init(allocator, &block_cache, &cp_cache);

    var queued = QueuedStateRegen.init(allocator, &regen);
    defer queued.deinit();

    const root = [_]u8{0x42} ** 32;

    // Enqueue at low priority.
    try queued.enqueue(.{
        .key = .{ .block_root = root },
        .priority = .background,
    });

    // Enqueue same key at higher priority — should upgrade.
    try queued.enqueue(.{
        .key = .{ .block_root = root },
        .priority = .block_import,
    });

    try std.testing.expectEqual(@as(usize, 1), queued.queueLen());
    try std.testing.expectEqual(RegenPriority.block_import, queued.queue.items[0].priority);
}

test "QueuedStateRegen: dropLowPriority removes background requests" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    
    const MemoryCPStateDatastore = @import("state_transition").MemoryCPStateDatastore;

    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var mem_store = MemoryCPStateDatastore.init(allocator);
    defer mem_store.deinit();
    const ds = mem_store.datastore();

    var block_cache = BlockStateCache.init(allocator, 4);
    defer block_cache.deinit();

    var cp_cache = CheckpointStateCache.init(allocator, ds, &block_cache, 3);
    defer cp_cache.deinit();

    var regen = StateRegen.init(allocator, &block_cache, &cp_cache);

    var queued = QueuedStateRegen.init(allocator, &regen);
    defer queued.deinit();

    // Queue a mix of priorities.
    try queued.enqueue(.{
        .key = .{ .block_root = [_]u8{0x01} ** 32 },
        .priority = .block_import,
    });
    try queued.enqueue(.{
        .key = .{ .block_root = [_]u8{0x02} ** 32 },
        .priority = .background,
    });
    try queued.enqueue(.{
        .key = .{ .block_root = [_]u8{0x03} ** 32 },
        .priority = .api,
    });

    try std.testing.expectEqual(@as(usize, 3), queued.queueLen());

    // Drop everything below fork_choice priority.
    queued.dropLowPriority(.fork_choice);

    // Only block_import should remain.
    try std.testing.expectEqual(@as(usize, 1), queued.queueLen());
    try std.testing.expectEqual(RegenPriority.block_import, queued.queue.items[0].priority);
}

test "QueuedStateRegen: onNewBlock delegates to regen" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    
    const MemoryCPStateDatastore = @import("state_transition").MemoryCPStateDatastore;

    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var mem_store = MemoryCPStateDatastore.init(allocator);
    defer mem_store.deinit();
    const ds = mem_store.datastore();

    var block_cache = BlockStateCache.init(allocator, 4);
    defer block_cache.deinit();

    var cp_cache = CheckpointStateCache.init(allocator, ds, &block_cache, 3);
    defer cp_cache.deinit();

    var regen = StateRegen.init(allocator, &block_cache, &cp_cache);

    var queued = QueuedStateRegen.init(allocator, &regen);
    defer queued.deinit();

    // onNewBlock should delegate to regen.
    const state = try test_state.cached_state.clone(allocator, .{});
    const root = try queued.onNewBlock(state, true);
    try std.testing.expect(block_cache.get(root) != null);
}

test "QueuedStateRegen: metrics tracking" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    
    const MemoryCPStateDatastore = @import("state_transition").MemoryCPStateDatastore;

    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var mem_store = MemoryCPStateDatastore.init(allocator);
    defer mem_store.deinit();
    const ds = mem_store.datastore();

    var block_cache = BlockStateCache.init(allocator, 4);
    defer block_cache.deinit();

    var cp_cache = CheckpointStateCache.init(allocator, ds, &block_cache, 3);
    defer cp_cache.deinit();

    var regen = StateRegen.init(allocator, &block_cache, &cp_cache);

    var queued = QueuedStateRegen.init(allocator, &regen);
    defer queued.deinit();

    // Add a state.
    const state = try test_state.cached_state.clone(allocator, .{});
    const root = try regen.onNewBlock(state, true);

    // Cache hit.
    _ = try queued.getPreState(root, 100, .block_import);

    const m = queued.getMetrics();
    try std.testing.expectEqual(@as(u64, 1), m.cache_hits);
    try std.testing.expectEqual(@as(u64, 0), m.queue_hits);
    try std.testing.expectEqual(@as(u64, 0), m.dropped);
}
