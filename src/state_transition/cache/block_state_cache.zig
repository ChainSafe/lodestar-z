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
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;

const CachedBeaconState = @import("state_cache.zig").CachedBeaconState;

pub const DEFAULT_MAX_STATES: u32 = 64;

pub const BlockStateCache = struct {
    allocator: Allocator,
    /// State root (32 bytes) -> CachedBeaconState
    cache: std.AutoArrayHashMap([32]u8, *CachedBeaconState),
    /// Key order for FIFO eviction (index 0 = head/newest, last = oldest/tail)
    key_order: std.ArrayList([32]u8),
    /// Max states to keep
    max_states: u32,
    /// Head state root (always kept, never evicted)
    head_root: ?[32]u8,

    pub fn init(allocator: Allocator, max_states: u32) BlockStateCache {
        return .{
            .allocator = allocator,
            .cache = std.AutoArrayHashMap([32]u8, *CachedBeaconState).init(allocator),
            .key_order = std.ArrayList([32]u8).init(allocator),
            .max_states = max_states,
            .head_root = null,
        };
    }

    pub fn deinit(self: *BlockStateCache) void {
        // Deinit and free all cached states
        for (self.cache.values()) |state| {
            state.deinit();
            self.allocator.destroy(state);
        }
        self.cache.deinit();
        self.key_order.deinit();
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

        if (self.cache.get(root) != null) {
            // Already exists — update position
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
            try self.key_order.insert(0, root);
        } else {
            // Insert after head (position 1), or at front if empty
            const insert_pos: usize = if (self.key_order.items.len > 0) 1 else 0;
            try self.key_order.insert(insert_pos, root);
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
                state.deinit();
                self.allocator.destroy(state);
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
        self.key_order.insert(0, root) catch {};
        self.head_root = root;
    }

    fn moveToSecond(self: *BlockStateCache, root: [32]u8) void {
        self.removeFromKeyOrder(root);
        const pos: usize = if (self.key_order.items.len > 0) 1 else 0;
        self.key_order.insert(pos, root) catch {};
    }

    fn removeFromKeyOrder(self: *BlockStateCache, root: [32]u8) void {
        for (self.key_order.items, 0..) |k, idx| {
            if (std.mem.eql(u8, &k, &root)) {
                _ = self.key_order.orderedRemove(idx);
                return;
            }
        }
    }

    /// Prune from tail until at or under max_states. Never prunes `last_added_key`.
    fn prune(self: *BlockStateCache, last_added_key: [32]u8) void {
        while (self.key_order.items.len > self.max_states) {
            const tail = self.key_order.items[self.key_order.items.len - 1];

            // Don't prune the key we just added
            if (std.mem.eql(u8, &tail, &last_added_key)) break;

            _ = self.key_order.pop();

            if (self.cache.fetchOrderedRemove(tail)) |kv| {
                kv.value.deinit();
                self.allocator.destroy(kv.value);
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "BlockStateCache: add, get, FIFO eviction" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    // Create a state to use as a seed
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var cache = BlockStateCache.init(allocator, 2);
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
    // state1 (tail) should be evicted
    try std.testing.expect(cache.get(root1) == null);
    try std.testing.expect(cache.get(root2) != null);
    try std.testing.expect(cache.get(root3) != null);
}

test "BlockStateCache: head state is never evicted" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var cache = BlockStateCache.init(allocator, 2);
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

test "BlockStateCache: getSeedState" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
    const allocator = std.testing.allocator;
    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var cache = BlockStateCache.init(allocator, 4);
    defer cache.deinit();

    // Empty cache
    try std.testing.expect(cache.getSeedState() == null);

    // Add one state
    const state1 = try test_state.cached_state.clone(allocator, .{});
    _ = try cache.add(state1, false);

    try std.testing.expect(cache.getSeedState() != null);
}
