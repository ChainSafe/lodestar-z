//! BlockStateCache: FIFO cache of recent block states keyed by state root.
//!
//! Design mirrors Lodestar's FIFOBlockStateCache:
//! - Maintains a FIFO ordering with special head handling
//! - Head state is always kept and never evicted
//! - Prune from tail (oldest) when over capacity
//! - Provides getSeedState() for loadCachedBeaconState reloads
const std = @import("std");
const Allocator = std.mem.Allocator;
const preset = @import("preset").preset;
const state_transition = @import("state_transition");
const computeEpochAtSlot = state_transition.computeEpochAtSlot;

const CachedBeaconState = state_transition.CachedBeaconState;
const StateDisposer = @import("state_disposer.zig").StateDisposer;

pub const DEFAULT_MAX_STATES: u32 = 64;

pub const BlockStateCache = struct {
    allocator: Allocator,
    /// State root (32 bytes) -> CachedBeaconState
    cache: std.AutoArrayHashMap([32]u8, *CachedBeaconState),
    /// Key order for FIFO eviction (index 0 = head/newest, last = oldest/tail)
    key_order: std.ArrayListUnmanaged([32]u8),
    /// Max states to keep
    max_states: u32,
    /// Head state root (always kept, never evicted)
    head_root: ?[32]u8,
    state_disposer: *StateDisposer,

    pub fn init(
        allocator: Allocator,
        max_states: u32,
        state_disposer: *StateDisposer,
    ) BlockStateCache {
        return .{
            .allocator = allocator,
            .cache = std.AutoArrayHashMap([32]u8, *CachedBeaconState).init(allocator),
            .key_order = .empty,
            .max_states = max_states,
            .head_root = null,
            .state_disposer = state_disposer,
        };
    }

    pub fn deinit(self: *BlockStateCache) void {
        // Deinit and free all cached states
        for (self.cache.values()) |state| {
            self.disposeState(state);
        }
        self.cache.deinit();
        self.key_order.deinit(self.allocator);
    }

    /// Get a state by its root.
    pub fn get(self: *BlockStateCache, root: [32]u8) ?*CachedBeaconState {
        return self.cache.get(root);
    }

    /// Add a state to the cache. Returns the state root used as key.
    /// If the state already exists, it is updated in-place and moved to second position.
    /// New states are inserted after the head. Prunes oldest if over capacity.
    pub fn add(self: *BlockStateCache, state: *CachedBeaconState, is_head: bool) ![32]u8 {
        const root = (try state.state.hashTreeRoot()).*;

        if (self.cache.get(root)) |existing| {
            // Already exists — keep the published cached state and drop any
            // duplicate transient copy handed in by the caller.
            if (existing != state) {
                self.disposeState(state);
            }
            if (is_head) {
                self.moveToHead(root);
            } else {
                self.moveToSecond(root);
            }
            return root;
        }

        // New state
        try self.cache.put(root, state);
        errdefer _ = self.cache.orderedRemove(root);

        if (is_head) {
            try self.key_order.insert(self.allocator, 0, root);
            self.head_root = root;
        } else {
            // Insert after head (position 1), or at front if empty
            const insert_pos: usize = if (self.key_order.items.len > 0) 1 else 0;
            try self.key_order.insert(self.allocator, insert_pos, root);
        }

        self.prune(root);
        return root;
    }

    /// Set the head state root. The head is moved to front and never pruned.
    pub fn setHeadState(self: *BlockStateCache, state: *CachedBeaconState) ![32]u8 {
        return self.add(state, true);
    }

    /// Get any available state as a seed for loadCachedBeaconState.
    /// Prefer the head state if available, otherwise return the first cached state.
    pub fn getSeedState(self: *BlockStateCache) ?*CachedBeaconState {
        if (self.head_root) |hr| {
            if (self.cache.get(hr)) |state| return state;
        }
        // Return first value in the cache
        const values = self.cache.values();
        if (values.len > 0) return values[0];
        return null;
    }

    /// Prune states whose epoch is strictly before `finalized_epoch`.
    /// Never prunes the head state.
    pub fn pruneBeforeEpoch(self: *BlockStateCache, finalized_epoch: u64) void {
        var i: usize = 0;
        while (i < self.key_order.items.len) {
            const root = self.key_order.items[i];

            // Never prune the head
            if (self.head_root) |hr| {
                if (std.mem.eql(u8, &root, &hr)) {
                    i += 1;
                    continue;
                }
            }

            const state = self.cache.get(root) orelse {
                // Stale key_order entry — remove it
                _ = self.key_order.orderedRemove(i);
                continue;
            };

            const slot = state.state.slot() catch {
                i += 1;
                continue;
            };
            const epoch = computeEpochAtSlot(slot);

            if (epoch < finalized_epoch) {
                _ = self.key_order.orderedRemove(i);
                _ = self.cache.orderedRemove(root);
                self.disposeState(state);
            } else {
                i += 1;
            }
        }
    }

    /// Number of cached states.
    pub fn size(self: *const BlockStateCache) usize {
        return self.cache.count();
    }

    // -- Internal helpers --

    fn moveToHead(self: *BlockStateCache, root: [32]u8) void {
        self.removeFromKeyOrder(root);
        self.key_order.insert(self.allocator, 0, root) catch {};
        self.head_root = root;
    }

    fn moveToSecond(self: *BlockStateCache, root: [32]u8) void {
        self.removeFromKeyOrder(root);
        const pos: usize = if (self.key_order.items.len > 0) 1 else 0;
        self.key_order.insert(self.allocator, pos, root) catch {};
    }

    fn removeFromKeyOrder(self: *BlockStateCache, root: [32]u8) void {
        for (self.key_order.items, 0..) |k, idx| {
            if (std.mem.eql(u8, &k, &root)) {
                _ = self.key_order.orderedRemove(idx);
                return;
            }
        }
    }

    /// Prune from tail until at or under max_states. Never prunes `last_added_key` or the head.
    fn prune(self: *BlockStateCache, last_added_key: [32]u8) void {
        while (self.key_order.items.len > self.max_states) {
            const tail = self.key_order.items[self.key_order.items.len - 1];

            // Don't prune the key we just added
            if (std.mem.eql(u8, &tail, &last_added_key)) break;

            // Don't prune the head
            if (self.head_root) |hr| {
                if (std.mem.eql(u8, &tail, &hr)) break;
            }

            _ = self.key_order.pop();

            if (self.cache.fetchOrderedRemove(tail)) |kv| {
                self.disposeState(kv.value);
            }
        }
    }

    fn disposeState(self: *BlockStateCache, state: *CachedBeaconState) void {
        self.state_disposer.dispose(state) catch @panic("OOM deferring block-state disposal");
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "BlockStateCache: add, get, FIFO eviction" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    // Create a state to use as a seed
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var state_disposer = StateDisposer.init(allocator, std.testing.io);
    defer state_disposer.deinit();

    var cache = BlockStateCache.init(allocator, 2, &state_disposer);
    defer cache.deinit();

    // Clone and add first state
    const state1 = try test_state.cached_state.clone(allocator, .{});
    const root1 = try cache.add(state1, false);

    try std.testing.expect(cache.get(root1) != null);
    try std.testing.expectEqual(@as(usize, 1), cache.size());

    // Clone and add second state — modify slot so roots differ
    const state2 = try test_state.cached_state.clone(allocator, .{});
    try state2.state.setSlot((try state2.state.slot()) + 1);
    const root2 = try cache.add(state2, false);

    try std.testing.expectEqual(@as(usize, 2), cache.size());

    // Clone and add third — should evict oldest (state1 is at tail)
    const state3 = try test_state.cached_state.clone(allocator, .{});
    try state3.state.setSlot((try state3.state.slot()) + 2);
    const root3 = try cache.add(state3, false);

    try std.testing.expectEqual(@as(usize, 2), cache.size());
    // state2 (tail, oldest non-first) should be evicted
    try std.testing.expect(cache.get(root2) == null);
    try std.testing.expect(cache.get(root1) != null);
    try std.testing.expect(cache.get(root3) != null);
}

test "BlockStateCache: head state is never evicted" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var state_disposer = StateDisposer.init(allocator, std.testing.io);
    defer state_disposer.deinit();

    var cache = BlockStateCache.init(allocator, 2, &state_disposer);
    defer cache.deinit();

    // Add as head
    const state1 = try test_state.cached_state.clone(allocator, .{});
    const root1 = try cache.setHeadState(state1);
    cache.head_root = root1;

    // Add second
    const state2 = try test_state.cached_state.clone(allocator, .{});
    try state2.state.setSlot((try state2.state.slot()) + 1);
    _ = try cache.add(state2, false);

    // Add third — should evict state2 (tail), NOT state1 (head, at front)
    const state3 = try test_state.cached_state.clone(allocator, .{});
    try state3.state.setSlot((try state3.state.slot()) + 2);
    _ = try cache.add(state3, false);

    try std.testing.expectEqual(@as(usize, 2), cache.size());
    // Head should still be there
    try std.testing.expect(cache.get(root1) != null);
}

test "BlockStateCache: eviction can defer state teardown" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var state_disposer = StateDisposer.init(allocator, std.testing.io);
    defer state_disposer.deinit();

    var cache = BlockStateCache.init(allocator, 2, &state_disposer);
    defer cache.deinit();

    const state1 = try test_state.cached_state.clone(allocator, .{});
    try state1.state.setSlot((try state1.state.slot()) + 1);
    const root1 = try cache.add(state1, false);

    const state2 = try test_state.cached_state.clone(allocator, .{});
    try state2.state.setSlot((try state2.state.slot()) + 2);
    const root2 = try cache.add(state2, false);

    state_disposer.beginDeferral();
    const state3 = try test_state.cached_state.clone(allocator, .{});
    try state3.state.setSlot((try state3.state.slot()) + 3);
    _ = try cache.add(state3, false);

    try std.testing.expect(cache.get(root1) != null);
    try std.testing.expect(cache.get(root2) == null);
    try std.testing.expectEqual(@as(usize, 1), state_disposer.pendingCount());

    try state_disposer.endDeferral();
    try std.testing.expectEqual(@as(usize, 0), state_disposer.pendingCount());
}

test "BlockStateCache: getSeedState" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var state_disposer = StateDisposer.init(allocator, std.testing.io);
    defer state_disposer.deinit();

    var cache = BlockStateCache.init(allocator, 4, &state_disposer);
    defer cache.deinit();

    // Empty cache
    try std.testing.expect(cache.getSeedState() == null);

    // Add one state
    const state1 = try test_state.cached_state.clone(allocator, .{});
    _ = try cache.add(state1, false);

    try std.testing.expect(cache.getSeedState() != null);
}

test "BlockStateCache: head state survives multiple evictions" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 10;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    // Cache capacity of 3
    var state_disposer = StateDisposer.init(allocator, std.testing.io);
    defer state_disposer.deinit();

    var cache = BlockStateCache.init(allocator, 3, &state_disposer);
    defer cache.deinit();

    // Set first state as head
    const head = try test_state.cached_state.clone(allocator, .{});
    const head_root = try cache.setHeadState(head);

    // Add 5 more states, each should trigger eviction but head survives
    var i: u64 = 1;
    while (i <= 5) : (i += 1) {
        const s = try test_state.cached_state.clone(allocator, .{});
        try s.state.setSlot((try s.state.slot()) + i);
        _ = try cache.add(s, false);
    }

    // Head should still be present
    try std.testing.expect(cache.get(head_root) != null);
    // Cache size should be at max (head + 2 others)
    try std.testing.expectEqual(@as(usize, 3), cache.size());
}

test "BlockStateCache: pruneBeforeEpoch removes old states" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 10;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var state_disposer = StateDisposer.init(allocator, std.testing.io);
    defer state_disposer.deinit();

    var cache = BlockStateCache.init(allocator, 10, &state_disposer);
    defer cache.deinit();

    // Set head at high slot
    const head = try test_state.cached_state.clone(allocator, .{});
    try head.state.setSlot(1024); // epoch 32 (with SLOTS_PER_EPOCH=32)
    const head_root = try cache.setHeadState(head);

    // Add state at slot 0 (epoch 0)
    const old_state = try test_state.cached_state.clone(allocator, .{});
    try old_state.state.setSlot(0);
    _ = try cache.add(old_state, false);

    try std.testing.expectEqual(@as(usize, 2), cache.size());

    // Prune before epoch 10 — should remove slot 0 state
    cache.pruneBeforeEpoch(10);

    // Head (epoch 32) survives, old (epoch 0) pruned
    try std.testing.expect(cache.get(head_root) != null);
    try std.testing.expectEqual(@as(usize, 1), cache.size());
}

test "BlockStateCache: re-adding existing state moves position" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var state_disposer = StateDisposer.init(allocator, std.testing.io);
    defer state_disposer.deinit();

    var cache = BlockStateCache.init(allocator, 3, &state_disposer);
    defer cache.deinit();

    const state1 = try test_state.cached_state.clone(allocator, .{});
    const root1 = try cache.add(state1, false);

    const state2 = try test_state.cached_state.clone(allocator, .{});
    try state2.state.setSlot((try state2.state.slot()) + 1);
    _ = try cache.add(state2, false);

    const state3 = try test_state.cached_state.clone(allocator, .{});
    try state3.state.setSlot((try state3.state.slot()) + 2);
    _ = try cache.add(state3, false);

    // Re-add state1 — should not increase size, just move position
    _ = try cache.add(state1, false);
    try std.testing.expectEqual(@as(usize, 3), cache.size());
    try std.testing.expect(cache.get(root1) != null);
}

test "BlockStateCache: duplicate root disposes incoming transient state" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var state_disposer = StateDisposer.init(allocator, std.testing.io);
    defer state_disposer.deinit();

    var cache = BlockStateCache.init(allocator, 2, &state_disposer);
    defer cache.deinit();

    const state1 = try test_state.cached_state.clone(allocator, .{});
    const root1 = try cache.add(state1, false);

    const duplicate = try test_state.cached_state.clone(allocator, .{});
    const root2 = try cache.add(duplicate, true);

    try std.testing.expectEqual(root1, root2);
    try std.testing.expectEqual(@as(usize, 1), cache.size());
    try std.testing.expect(cache.get(root1) == state1);
    try std.testing.expectEqual(root1, cache.head_root.?);
}
