//! Unknown block sync: active orphan resolution with parent fetch loop.
//!
//! When a gossip block arrives with an unknown parent root, it is queued as
//! a "pending block". This module actively walks the parent chain, requesting
//! blocks by root until it connects to our known chain or gives up.
//!
//! Key improvements over the previous implementation:
//! - Active fetch loop (tick-driven) — no external driver needed
//! - Recursive parent chain walking
//! - Peer balancing for root requests
//! - Proper cleanup of resolved/expired entries
//!
//! ## Split with unknown_chain/
//!
//! There are TWO mechanisms for handling unknown block roots. They serve
//! distinct use cases and should not be merged:
//!
//! ### UnknownBlockSync (this module)
//! - Triggered by: gossip blocks with an unknown *parent* root
//! - Has full block bytes in hand; only the parent chain is missing
//! - Stores: full block bytes ([]const u8) per pending block
//! - Resolves by: walking the parent chain by root until reaching a known block,
//!   then recursively importing children
//! - Use case: filling in the gap for a gossip block that arrived out of order
//!
//! ### UnknownChainSync (unknown_chain/)
//! - Triggered by: unknown roots from attestations, peer status, getHeader
//! - Has only the root; no block bytes at all
//! - Stores: minimal headers (slot + parent_root) to reconstruct chain order
//! - Resolves by: building a backward header chain until it links to fork choice,
//!   then triggering forward range sync via SyncService
//! - Use case: bootstrapping from a completely unknown chain tip (e.g. attestations
//!   to a block we have never seen)
//!
//! The key distinction: UnknownBlockSync has the block, UnknownChainSync does not.
//! TS Lodestar is migrating from the former to the latter (PR #8221), but both
//! co-exist here as they address different edge cases.
//!
//! Reference: Lodestar `packages/beacon-node/src/sync/unknownBlock.ts`

const std = @import("std");
const Allocator = std.mem.Allocator;
const sync_types = @import("sync_types.zig");

/// Status of a pending block entry.
pub const PendingStatus = enum {
    /// Waiting for parent to be fetched.
    pending,
    /// Actively being fetched (request in flight).
    fetching,
};

/// A block waiting for its parent chain to be resolved.
pub const PendingBlock = struct {
    /// The block's own root.
    block_root: [32]u8,
    /// The parent root this block references (what we need).
    parent_root: [32]u8,
    /// The block's slot.
    slot: u64,
    /// Raw SSZ bytes of the signed block (owned copy).
    block_bytes: []const u8,
    /// Number of fetch attempts for this block's parent.
    attempts: u8,
    /// Current status.
    status: PendingStatus,
};

/// Callback vtable for unknown block sync operations.
pub const UnknownBlockCallbacks = struct {
    ptr: *anyopaque,

    /// Request a block by root from a peer.
    requestBlockByRootFn: *const fn (
        ptr: *anyopaque,
        root: [32]u8,
        peer_id: []const u8,
    ) void,

    /// Import a block. Returns error on failure.
    importBlockFn: *const fn (
        ptr: *anyopaque,
        block_bytes: []const u8,
    ) anyerror!void,

    /// Get a list of connected peer IDs for balancing.
    getConnectedPeersFn: *const fn (
        ptr: *anyopaque,
    ) []const []const u8,

    pub fn requestBlockByRoot(self: UnknownBlockCallbacks, root: [32]u8, peer_id: []const u8) void {
        self.requestBlockByRootFn(self.ptr, root, peer_id);
    }

    pub fn importBlock(self: UnknownBlockCallbacks, block_bytes: []const u8) !void {
        return self.importBlockFn(self.ptr, block_bytes);
    }

    pub fn getConnectedPeers(self: UnknownBlockCallbacks) []const []const u8 {
        return self.getConnectedPeersFn(self.ptr);
    }
};

/// Manages the set of blocks waiting for unknown parents.
///
/// NOT thread-safe — caller must synchronize.
pub const UnknownBlockSync = struct {
    allocator: Allocator,

    /// Pending blocks keyed by their own block_root.
    pending: std.AutoArrayHashMap([32]u8, PendingBlock),

    /// Parent roots → list of child block roots waiting on them.
    parents_needed: std.AutoArrayHashMap([32]u8, std.ArrayListUnmanaged([32]u8)),

    /// Roots known to be bad — avoid re-fetching.
    bad_roots: std.AutoArrayHashMap([32]u8, void),

    /// Number of currently in-flight requests.
    in_flight: usize,

    /// Peer index for round-robin balancing.
    peer_index: usize,

    /// Callbacks for network/import operations.
    callbacks: ?UnknownBlockCallbacks,

    pub fn init(allocator: Allocator) UnknownBlockSync {
        return .{
            .allocator = allocator,
            .pending = std.AutoArrayHashMap([32]u8, PendingBlock).init(allocator),
            .parents_needed = std.AutoArrayHashMap([32]u8, std.ArrayListUnmanaged([32]u8)).init(allocator),
            .bad_roots = std.AutoArrayHashMap([32]u8, void).init(allocator),
            .in_flight = 0,
            .peer_index = 0,
            .callbacks = null,
        };
    }

    pub fn deinit(self: *UnknownBlockSync) void {
        var it = self.pending.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.value_ptr.block_bytes);
        }
        self.pending.deinit();

        var pit = self.parents_needed.iterator();
        while (pit.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.parents_needed.deinit();
        self.bad_roots.deinit();
    }

    /// Set callbacks (called once after init, when network is available).
    pub fn setCallbacks(self: *UnknownBlockSync, callbacks: UnknownBlockCallbacks) void {
        self.callbacks = callbacks;
    }

    /// Add a block with an unknown parent to the pending set.
    /// Returns true if the block was added.
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
        if (self.pending.count() >= sync_types.MAX_PENDING_BLOCKS) {
            self.evictOldest();
        }

        const bytes_copy = try self.allocator.dupe(u8, block_bytes);
        errdefer self.allocator.free(bytes_copy);

        try self.pending.put(block_root, .{
            .block_root = block_root,
            .parent_root = parent_root,
            .slot = slot,
            .block_bytes = bytes_copy,
            .attempts = 0,
            .status = .pending,
        });

        // Track parent.
        const gop = try self.parents_needed.getOrPut(parent_root);
        if (!gop.found_existing) {
            gop.value_ptr.* = .empty;
        }
        try gop.value_ptr.append(self.allocator, block_root);

        return true;
    }

    /// Active tick: walk parent chains, dispatch fetch requests.
    /// This is the active fetch loop — called periodically by SyncService.
    pub fn tick(self: *UnknownBlockSync) void {
        const cbs = self.callbacks orelse return;

        // Get peers for balancing.
        const peers = cbs.getConnectedPeers();
        if (peers.len == 0) return;

        // Walk needed parents and dispatch fetches.
        var pit = self.parents_needed.iterator();
        while (pit.next()) |entry| {
            if (self.in_flight >= sync_types.MAX_CONCURRENT_UNKNOWN_REQUESTS) break;

            const parent_root = entry.key_ptr.*;

            // Check if any child still needs this parent.
            var any_live = false;
            for (entry.value_ptr.items) |child_root| {
                if (self.pending.getPtr(child_root)) |pb| {
                    if (pb.attempts < sync_types.MAX_UNKNOWN_PARENT_ATTEMPTS and
                        pb.status == .pending)
                    {
                        any_live = true;
                        break;
                    }
                }
            }
            if (!any_live) continue;

            // Select peer via round-robin.
            const peer = peers[self.peer_index % peers.len];
            self.peer_index +%= 1;

            // Mark children as fetching and bump attempt count.
            for (entry.value_ptr.items) |child_root| {
                if (self.pending.getPtr(child_root)) |pb| {
                    if (pb.status == .pending) {
                        pb.status = .fetching;
                        pb.attempts += 1;
                    }
                }
            }

            cbs.requestBlockByRoot(parent_root, peer);
            self.in_flight += 1;
        }
    }

    /// Called when a parent block was successfully fetched.
    /// Imports the parent, then attempts to import waiting children.
    /// Recursively checks if any imported child has its own children waiting.
    pub fn onParentFetched(
        self: *UnknownBlockSync,
        parent_root: [32]u8,
        parent_block_bytes: []const u8,
    ) !void {
        self.in_flight -|= 1;
        const cbs = self.callbacks orelse return;

        // Import the fetched parent.
        cbs.importBlock(parent_block_bytes) catch |err| {
            // If import fails, mark the root as bad.
            try self.markBad(parent_root);
            return err;
        };

        // Resolve children waiting on this parent.
        try self.resolveChildren(parent_root);
    }

    /// Called when a parent fetch fails.
    pub fn onFetchFailed(self: *UnknownBlockSync, parent_root: [32]u8) void {
        self.in_flight -|= 1;
        if (self.parents_needed.get(parent_root)) |children| {
            for (children.items) |child_root| {
                if (self.pending.getPtr(child_root)) |pb| {
                    pb.status = .pending; // Reset to pending for retry.
                }
            }
        }
    }

    /// Mark a root as bad — removes all descendants.
    pub fn markBad(self: *UnknownBlockSync, root: [32]u8) !void {
        try self.bad_roots.put(root, {});
        // Remove any pending blocks with this as parent.
        if (self.parents_needed.fetchSwapRemove(root)) |kv| {
            var children = kv.value;
            for (children.items) |child_root| {
                if (self.pending.fetchSwapRemove(child_root)) |ckv| {
                    self.allocator.free(ckv.value.block_bytes);
                }
            }
            children.deinit(self.allocator);
        }
    }

    /// Called when a block is imported by any path (not just unknown block sync).
    /// Checks if any pending children were waiting on this block root and
    /// resolves them.
    pub fn notifyBlockImported(self: *UnknownBlockSync, block_root: [32]u8) !void {
        try self.resolveChildren(block_root);
    }

    /// Number of pending blocks.
    pub fn pendingCount(self: *const UnknownBlockSync) usize {
        return self.pending.count();
    }

    /// Get needed parent roots (for external use / debugging).
    pub fn getNeededParents(self: *const UnknownBlockSync, out: *std.ArrayListUnmanaged([32]u8)) !void {
        var it = self.parents_needed.iterator();
        while (it.next()) |entry| {
            var any_live = false;
            for (entry.value_ptr.items) |child_root| {
                if (self.pending.get(child_root)) |pb| {
                    if (pb.attempts < sync_types.MAX_UNKNOWN_PARENT_ATTEMPTS) {
                        any_live = true;
                        break;
                    }
                }
            }
            if (any_live) {
                try out.append(self.allocator, entry.key_ptr.*);
            }
        }
    }

    // ── Internal ────────────────────────────────────────────────────

    /// Resolve children of a now-known parent root. Recursive.
    fn resolveChildren(self: *UnknownBlockSync, parent_root: [32]u8) !void {
        const removed = self.parents_needed.fetchSwapRemove(parent_root) orelse return;
        var children_list = removed.value;
        defer children_list.deinit(self.allocator);

        const cbs = self.callbacks orelse return;

        for (children_list.items) |child_root| {
            if (self.pending.fetchSwapRemove(child_root)) |kv| {
                const child = kv.value;
                defer self.allocator.free(child.block_bytes);

                // Try to import the child — its parent is now known.
                cbs.importBlock(child.block_bytes) catch {
                    // Child failed import — don't propagate, just drop.
                    continue;
                };

                // This child is now imported — resolve ITS children recursively.
                self.resolveChildren(child.block_root) catch {};
            }
        }
    }

    /// Evict the oldest pending block (lowest slot).
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

// ── Tests ────────────────────────────────────────────────────────────

test "UnknownBlockSync: add and retrieve pending block" {
    const alloc = std.testing.allocator;
    var sync = UnknownBlockSync.init(alloc);
    defer sync.deinit();

    const block_root = [_]u8{0x01} ** 32;
    const parent_root = [_]u8{0x02} ** 32;

    const added = try sync.addPendingBlock(block_root, parent_root, 42, &[_]u8{ 0xDE, 0xAD });
    try std.testing.expect(added);
    try std.testing.expectEqual(@as(usize, 1), sync.pendingCount());

    // Duplicate rejected.
    const dup = try sync.addPendingBlock(block_root, parent_root, 42, &[_]u8{ 0xDE, 0xAD });
    try std.testing.expect(!dup);
}

test "UnknownBlockSync: getNeededParents" {
    const alloc = std.testing.allocator;
    var sync = UnknownBlockSync.init(alloc);
    defer sync.deinit();

    const parent = [_]u8{0xAA} ** 32;
    _ = try sync.addPendingBlock([_]u8{0x01} ** 32, parent, 10, &[_]u8{0});

    var needed = std.ArrayListUnmanaged([32]u8).empty;
    defer needed.deinit(alloc);
    try sync.getNeededParents(&needed);
    try std.testing.expectEqual(@as(usize, 1), needed.items.len);
}

test "UnknownBlockSync: bad root blocks adds" {
    const alloc = std.testing.allocator;
    var sync = UnknownBlockSync.init(alloc);
    defer sync.deinit();

    const bad_parent = [_]u8{0xFF} ** 32;
    try sync.markBad(bad_parent);

    const added = try sync.addPendingBlock([_]u8{0x01} ** 32, bad_parent, 5, &[_]u8{0});
    try std.testing.expect(!added);
}

test "UnknownBlockSync: evicts oldest at capacity" {
    const alloc = std.testing.allocator;
    var sync = UnknownBlockSync.init(alloc);
    defer sync.deinit();

    for (0..sync_types.MAX_PENDING_BLOCKS) |i| {
        var root: [32]u8 = [_]u8{0} ** 32;
        root[0] = @intCast(i);
        var parent: [32]u8 = [_]u8{0xFF} ** 32;
        parent[0] = @intCast(i);
        _ = try sync.addPendingBlock(root, parent, @as(u64, @intCast(i)) + 100, &[_]u8{0});
    }
    try std.testing.expectEqual(sync_types.MAX_PENDING_BLOCKS, sync.pendingCount());

    const new_root: [32]u8 = [_]u8{0xEE} ** 32;
    const new_parent: [32]u8 = [_]u8{0xDD} ** 32;
    _ = try sync.addPendingBlock(new_root, new_parent, 999, &[_]u8{0});
    try std.testing.expectEqual(sync_types.MAX_PENDING_BLOCKS, sync.pendingCount());
}
