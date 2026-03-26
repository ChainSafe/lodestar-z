//! Unknown block sync: fetch missing parent blocks via BeaconBlocksByRoot.
//!
//! When a gossip block arrives with an unknown parent root, the block is
//! queued as a "pending block". This module tracks pending blocks and
//! provides the logic to:
//!
//! 1. Queue orphan blocks (blocks whose parent is not in our chain)
//! 2. Identify which parent roots need to be fetched
//! 3. Process fetched parents and re-try pending children
//! 4. Expire stale entries to prevent unbounded growth
//!
//! The actual network requests (BeaconBlocksByRoot) are driven by the
//! caller (BeaconNode), not by this module — this module is pure state
//! management and scheduling.
//!
//! Reference: TS Lodestar's sync/unknownBlock.ts

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Maximum number of pending blocks before we start evicting oldest.
const MAX_PENDING_BLOCKS: usize = 64;

/// Maximum fetch attempts per parent root before giving up.
const MAX_ATTEMPTS: u8 = 5;

/// A block waiting for its parent to be imported.
pub const PendingBlock = struct {
    /// The block's own root (hash_tree_root of BeaconBlockHeader).
    block_root: [32]u8,
    /// The parent root this block references (what we need to fetch).
    parent_root: [32]u8,
    /// The block's slot.
    slot: u64,
    /// Raw SSZ bytes of the signed block (caller-owned copy).
    block_bytes: []const u8,
    /// Number of times we've tried to fetch the parent.
    attempts: u8,
};

/// List of block roots waiting on a specific parent.
const ChildList = std.ArrayList([32]u8);

/// Manages the set of blocks waiting for unknown parents.
///
/// Thread-safety: NOT thread-safe. Caller must synchronize.
pub const UnknownBlockSync = struct {
    allocator: Allocator,

    /// Pending blocks keyed by their own block_root.
    pending: std.AutoArrayHashMap([32]u8, PendingBlock),

    /// Set of parent roots that we need to fetch.
    /// Each entry maps parent_root → list of child block_roots waiting on it.
    parents_needed: std.AutoArrayHashMap([32]u8, ChildList),

    /// Roots known to be bad — avoid re-fetching.
    bad_roots: std.AutoArrayHashMap([32]u8, void),

    pub fn init(allocator: Allocator) UnknownBlockSync {
        return .{
            .allocator = allocator,
            .pending = std.AutoArrayHashMap([32]u8, PendingBlock).init(allocator),
            .parents_needed = std.AutoArrayHashMap([32]u8, ChildList).init(allocator),
            .bad_roots = std.AutoArrayHashMap([32]u8, void).init(allocator),
        };
    }

    pub fn deinit(self: *UnknownBlockSync) void {
        // Free block_bytes copies.
        var it = self.pending.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.value_ptr.block_bytes);
        }
        self.pending.deinit();

        // Free children lists.
        var pit = self.parents_needed.iterator();
        while (pit.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.parents_needed.deinit();
        self.bad_roots.deinit();
    }

    /// Add a block with an unknown parent to the pending set.
    ///
    /// Returns true if the block was added, false if already pending
    /// or the parent is known-bad.
    pub fn addPendingBlock(
        self: *UnknownBlockSync,
        block_root: [32]u8,
        parent_root: [32]u8,
        slot: u64,
        block_bytes: []const u8,
    ) !bool {
        if (self.bad_roots.contains(parent_root)) return false;
        if (self.pending.contains(block_root)) return false;

        // Evict oldest if at capacity.
        if (self.pending.count() >= MAX_PENDING_BLOCKS) {
            self.evictOldest();
        }

        // Copy block bytes — we own them.
        const bytes_copy = try self.allocator.dupe(u8, block_bytes);
        errdefer self.allocator.free(bytes_copy);

        try self.pending.put(block_root, .{
            .block_root = block_root,
            .parent_root = parent_root,
            .slot = slot,
            .block_bytes = bytes_copy,
            .attempts = 0,
        });

        // Track this parent as needed.
        const gop = try self.parents_needed.getOrPut(parent_root);
        if (!gop.found_existing) {
            gop.value_ptr.* = .empty;
        }
        try gop.value_ptr.append(self.allocator, block_root);

        return true;
    }

    /// Get the list of parent roots that need to be fetched.
    pub fn getNeededParents(self: *const UnknownBlockSync, out: *std.ArrayList([32]u8)) !void {
        var it = self.parents_needed.iterator();
        while (it.next()) |entry| {
            const parent = entry.key_ptr.*;
            var any_live = false;
            for (entry.value_ptr.items) |child_root| {
                if (self.pending.get(child_root)) |pb| {
                    if (pb.attempts < MAX_ATTEMPTS) {
                        any_live = true;
                        break;
                    }
                }
            }
            if (any_live) {
                try out.append(self.allocator, parent);
            }
        }
    }

    /// Called when a parent root was successfully fetched and imported.
    ///
    /// Returns the list of pending blocks that were waiting on this parent.
    /// The caller must free both the returned slice and each entry's block_bytes.
    pub fn onParentImported(
        self: *UnknownBlockSync,
        parent_root: [32]u8,
    ) ![]PendingBlock {
        // Remove the children list for this parent.
        const removed = self.parents_needed.fetchSwapRemove(parent_root) orelse return &.{};
        var children_list = removed.value;
        defer children_list.deinit(self.allocator);

        var result: std.ArrayList(PendingBlock) = .empty;
        for (children_list.items) |child_root| {
            if (self.pending.fetchSwapRemove(child_root)) |kv| {
                try result.append(self.allocator, kv.value);
            }
        }

        return try result.toOwnedSlice(self.allocator);
    }

    /// Increment the attempt counter for all children of a parent root.
    pub fn onFetchFailed(self: *UnknownBlockSync, parent_root: [32]u8) void {
        if (self.parents_needed.get(parent_root)) |children| {
            for (children.items) |child_root| {
                if (self.pending.getPtr(child_root)) |pb| {
                    pb.attempts +|= 1;
                }
            }
        }
    }

    /// Mark a root as bad.
    pub fn markBad(self: *UnknownBlockSync, root: [32]u8) !void {
        try self.bad_roots.put(root, {});
    }

    /// Number of pending blocks.
    pub fn pendingCount(self: *const UnknownBlockSync) usize {
        return self.pending.count();
    }

    /// Evict the oldest pending block (by slot).
    fn evictOldest(self: *UnknownBlockSync) void {
        var oldest_slot: u64 = std.math.maxInt(u64);
        var oldest_root: ?[32]u8 = null;

        var it = self.pending.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.slot < oldest_slot) {
                oldest_slot = entry.value_ptr.slot;
                oldest_root = entry.key_ptr.*;
            }
        }

        if (oldest_root) |root| {
            if (self.pending.fetchSwapRemove(root)) |kv| {
                self.allocator.free(kv.value.block_bytes);
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "UnknownBlockSync: add and retrieve pending block" {
    const alloc = std.testing.allocator;
    var sync = UnknownBlockSync.init(alloc);
    defer sync.deinit();

    const block_root = [_]u8{0x01} ** 32;
    const parent_root = [_]u8{0x02} ** 32;
    const bytes = [_]u8{ 0xDE, 0xAD };

    const added = try sync.addPendingBlock(block_root, parent_root, 42, &bytes);
    try std.testing.expect(added);
    try std.testing.expectEqual(@as(usize, 1), sync.pendingCount());

    // Duplicate is rejected.
    const dup = try sync.addPendingBlock(block_root, parent_root, 42, &bytes);
    try std.testing.expect(!dup);
    try std.testing.expectEqual(@as(usize, 1), sync.pendingCount());
}

test "UnknownBlockSync: getNeededParents returns unfetched parents" {
    const alloc = std.testing.allocator;
    var sync = UnknownBlockSync.init(alloc);
    defer sync.deinit();

    const parent = [_]u8{0xAA} ** 32;
    _ = try sync.addPendingBlock([_]u8{0x01} ** 32, parent, 10, &[_]u8{0});

    var needed: std.ArrayList([32]u8) = .empty;
    defer needed.deinit(alloc);
    try sync.getNeededParents(&needed);

    try std.testing.expectEqual(@as(usize, 1), needed.items.len);
    try std.testing.expectEqualSlices(u8, &parent, &needed.items[0]);
}

test "UnknownBlockSync: onParentImported returns children" {
    const alloc = std.testing.allocator;
    var sync = UnknownBlockSync.init(alloc);
    defer sync.deinit();

    const parent = [_]u8{0xAA} ** 32;
    const child1 = [_]u8{0x01} ** 32;
    const child2 = [_]u8{0x02} ** 32;
    _ = try sync.addPendingBlock(child1, parent, 10, &[_]u8{0x10});
    _ = try sync.addPendingBlock(child2, parent, 11, &[_]u8{0x11});

    try std.testing.expectEqual(@as(usize, 2), sync.pendingCount());

    const children = try sync.onParentImported(parent);
    defer alloc.free(children);
    defer for (children) |c| alloc.free(c.block_bytes);

    try std.testing.expectEqual(@as(usize, 2), children.len);
    try std.testing.expectEqual(@as(usize, 0), sync.pendingCount());
}

test "UnknownBlockSync: bad root blocks future adds" {
    const alloc = std.testing.allocator;
    var sync = UnknownBlockSync.init(alloc);
    defer sync.deinit();

    const bad_parent = [_]u8{0xFF} ** 32;
    try sync.markBad(bad_parent);

    const added = try sync.addPendingBlock([_]u8{0x01} ** 32, bad_parent, 5, &[_]u8{0});
    try std.testing.expect(!added);
    try std.testing.expectEqual(@as(usize, 0), sync.pendingCount());
}

test "UnknownBlockSync: evicts oldest when at capacity" {
    const alloc = std.testing.allocator;
    var sync = UnknownBlockSync.init(alloc);
    defer sync.deinit();

    // Fill to capacity.
    for (0..MAX_PENDING_BLOCKS) |i| {
        var root: [32]u8 = [_]u8{0} ** 32;
        root[0] = @intCast(i);
        var parent: [32]u8 = [_]u8{0xFF} ** 32;
        parent[0] = @intCast(i);
        _ = try sync.addPendingBlock(root, parent, @as(u64, @intCast(i)) + 100, &[_]u8{0});
    }
    try std.testing.expectEqual(MAX_PENDING_BLOCKS, sync.pendingCount());

    // Adding one more evicts the oldest (slot 100).
    const new_root: [32]u8 = [_]u8{0xEE} ** 32;
    const new_parent: [32]u8 = [_]u8{0xDD} ** 32;
    _ = try sync.addPendingBlock(new_root, new_parent, 999, &[_]u8{0});
    try std.testing.expectEqual(MAX_PENDING_BLOCKS, sync.pendingCount());
}
