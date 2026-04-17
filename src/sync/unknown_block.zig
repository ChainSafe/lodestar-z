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
//! The header-only unknown-chain mechanism still exists as an experiment, but
//! the live beacon node currently disables it and relies on this module for
//! orphan gossip recovery. That matches Lodestar's current production path
//! more closely while the experimental header-only flow is re-evaluated.
//!
//! There are TWO mechanisms for handling unknown block roots. They serve
//! distinct use cases and should not be merged:
//!
//! ### UnknownBlockSync (this module)
//! - Triggered by: gossip blocks with an unknown *parent* root
//! - Has the full block in hand; only the parent chain is missing
//! - Stores: parsed block plus canonical metadata per pending block
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
const prepared_block_mod = @import("prepared_block");
const sync_types = @import("sync_types.zig");
const PeerSet = @import("unknown_chain/backwards_chain.zig").PeerSet;
const PreparedBlockInput = prepared_block_mod.PreparedBlockInput;

/// Status of a pending block entry.
pub const PendingStatus = enum {
    /// Waiting for parent to be fetched.
    pending,
    /// Actively being fetched (request in flight).
    fetching,
};

/// A block waiting for its parent chain to be resolved.
pub const PendingBlock = struct {
    /// The parsed block plus canonical metadata.
    prepared: PreparedBlockInput,
    /// Preferred peer to ask first for the missing parent, if gossip gave us one.
    preferred_peer_id_buf: [128]u8,
    preferred_peer_id_len: u8,
    /// Number of fetch attempts for this block's parent.
    attempts: u8,
    /// Current status.
    status: PendingStatus,

    pub fn preferredPeerId(self: *const PendingBlock) ?[]const u8 {
        if (self.preferred_peer_id_len == 0) return null;
        return self.preferred_peer_id_buf[0..self.preferred_peer_id_len];
    }

    fn setPreferredPeer(self: *PendingBlock, peer_id: ?[]const u8) void {
        const peer = peer_id orelse return;
        self.preferred_peer_id_len = @intCast(@min(peer.len, self.preferred_peer_id_buf.len));
        @memcpy(self.preferred_peer_id_buf[0..self.preferred_peer_id_len], peer[0..self.preferred_peer_id_len]);
    }

    fn slot(self: *const PendingBlock) u64 {
        return self.prepared.slot();
    }
};

const ParentWaiters = struct {
    child_roots: std.ArrayListUnmanaged([32]u8),
    excluded_peers: PeerSet,

    pub const empty: ParentWaiters = .{
        .child_roots = .empty,
        .excluded_peers = .empty,
    };

    fn deinit(self: *ParentWaiters, allocator: Allocator) void {
        self.child_roots.deinit(allocator);
        self.excluded_peers.deinit(allocator);
        self.* = empty;
    }

    fn clearExcludedPeers(self: *ParentWaiters, allocator: Allocator) void {
        self.excluded_peers.deinit(allocator);
        self.excluded_peers = .empty;
    }
};

pub const MetricsSnapshot = struct {
    pending_blocks: u64 = 0,
    pending_parents: u64 = 0,
    fetching_blocks: u64 = 0,
    in_flight_requests: u64 = 0,
    bad_roots: u64 = 0,
    exhausted_blocks: u64 = 0,
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
        prepared: PreparedBlockInput,
    ) anyerror!void,

    /// Returns true when a block root is already known to fork choice.
    hasBlockFn: *const fn (
        ptr: *anyopaque,
        root: [32]u8,
    ) bool,

    /// Get a list of connected peer IDs for balancing.
    getConnectedPeersFn: *const fn (
        ptr: *anyopaque,
    ) []const []const u8,

    pub fn requestBlockByRoot(self: UnknownBlockCallbacks, root: [32]u8, peer_id: []const u8) void {
        self.requestBlockByRootFn(self.ptr, root, peer_id);
    }

    pub fn importBlock(self: UnknownBlockCallbacks, prepared: PreparedBlockInput) !void {
        return self.importBlockFn(self.ptr, prepared);
    }

    pub fn hasBlock(self: UnknownBlockCallbacks, root: [32]u8) bool {
        return self.hasBlockFn(self.ptr, root);
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
    pending: std.array_hash_map.Auto([32]u8, PendingBlock),

    /// Parent roots → waiting children plus peers already tried in this session.
    parents_needed: std.array_hash_map.Auto([32]u8, ParentWaiters),

    /// Roots known to be bad — avoid re-fetching.
    bad_roots: std.array_hash_map.Auto([32]u8, void),

    /// Number of currently in-flight requests.
    in_flight: usize,

    /// Peer index for round-robin balancing.
    peer_index: usize,

    /// Callbacks for network/import operations.
    callbacks: ?UnknownBlockCallbacks,

    pub fn init(allocator: Allocator) UnknownBlockSync {
        return .{
            .allocator = allocator,
            .pending = .empty,
            .parents_needed = .empty,
            .bad_roots = .empty,
            .in_flight = 0,
            .peer_index = 0,
            .callbacks = null,
        };
    }

    pub fn deinit(self: *UnknownBlockSync) void {
        var it = self.pending.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.prepared.deinit(self.allocator);
        }
        self.pending.deinit(self.allocator);

        var pit = self.parents_needed.iterator();
        while (pit.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.parents_needed.deinit(self.allocator);
        self.bad_roots.deinit(self.allocator);
    }

    /// Set callbacks (called once after init, when network is available).
    pub fn setCallbacks(self: *UnknownBlockSync, callbacks: UnknownBlockCallbacks) void {
        self.callbacks = callbacks;
    }

    /// Add a block with an unknown parent to the pending set.
    /// Returns true if the block was added.
    pub fn addPendingBlock(
        self: *UnknownBlockSync,
        prepared: PreparedBlockInput,
    ) !bool {
        return self.addPendingBlockWithPeer(prepared, null);
    }

    pub fn addPendingBlockWithPeer(
        self: *UnknownBlockSync,
        prepared: PreparedBlockInput,
        peer_id: ?[]const u8,
    ) !bool {
        var owned = prepared;
        var inserted = false;
        defer if (!inserted) owned.deinit(self.allocator);

        const block_root = owned.block_root;
        const parent_root = owned.block.beaconBlock().parentRoot().*;

        if (self.bad_roots.contains(parent_root)) return false;
        if (self.pending.getPtr(block_root)) |pending| {
            pending.setPreferredPeer(peer_id);
            return false;
        }

        // Evict oldest if at capacity.
        if (self.pending.count() >= sync_types.MAX_PENDING_BLOCKS) {
            self.evictOldest();
        }

        try self.pending.put(self.allocator, block_root, .{
            .prepared = owned,
            .preferred_peer_id_buf = undefined,
            .preferred_peer_id_len = 0,
            .attempts = 0,
            .status = .pending,
        });
        inserted = true;
        if (self.pending.getPtr(block_root)) |pending| {
            pending.setPreferredPeer(peer_id);
        }

        // Track parent.
        const gop = try self.parents_needed.getOrPut(self.allocator, parent_root);
        if (!gop.found_existing) {
            gop.value_ptr.* = .empty;
        }
        try gop.value_ptr.child_roots.append(self.allocator, block_root);

        return true;
    }

    /// Active tick: walk parent chains, dispatch fetch requests.
    /// This is the active fetch loop — called periodically by SyncService.
    pub fn tick(self: *UnknownBlockSync) void {
        const cbs = self.callbacks orelse return;

        // Lodestar processes pending "ancestor" blocks once their parent is
        // already known, even if there is no live by-root fetch to drive the
        // transition. Do the same here to recover orphan gossip blocks after a
        // range-sync import or a previously queued unknown-block import.
        self.resolveKnownParentChildren(cbs);

        // Get peers for balancing.
        const peers = cbs.getConnectedPeers();
        if (peers.len == 0) return;

        // Walk needed parents and dispatch fetches.
        var pit = self.parents_needed.iterator();
        while (pit.next()) |entry| {
            if (self.in_flight >= sync_types.MAX_CONCURRENT_UNKNOWN_REQUESTS) break;

            const parent_root = entry.key_ptr.*;
            const waiters = entry.value_ptr;

            // Check if any child still needs this parent.
            var any_live = false;
            for (waiters.child_roots.items) |child_root| {
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

            const peer = self.selectPeerForParent(waiters, peers) orelse continue;

            // Mark children as fetching and bump attempt count.
            for (waiters.child_roots.items) |child_root| {
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
        prepared: PreparedBlockInput,
    ) !void {
        self.in_flight -|= 1;
        const cbs = self.callbacks orelse return;
        var owned_prepared = prepared;

        // Import the fetched parent.
        cbs.importBlock(owned_prepared) catch |err| {
            owned_prepared = undefined;
            if (err == error.ImportPending) {
                return;
            }
            // If import fails, mark the root as bad.
            try self.markBad(parent_root);
            return err;
        };
        owned_prepared = undefined;

        // Resolve children waiting on this parent.
        try self.resolveChildren(parent_root);
    }

    /// Called when a parent fetch fails.
    pub fn onFetchFailed(self: *UnknownBlockSync, parent_root: [32]u8, failed_peer_id: ?[]const u8) void {
        self.in_flight -|= 1;
        if (self.parents_needed.getPtr(parent_root)) |waiters| {
            if (failed_peer_id) |peer_id| {
                _ = waiters.excluded_peers.add(self.allocator, peer_id) catch {};
            }
            var exhausted_roots: [sync_types.MAX_PENDING_BLOCKS][32]u8 = undefined;
            var exhausted_count: usize = 0;
            for (waiters.child_roots.items) |child_root| {
                if (self.pending.getPtr(child_root)) |pb| {
                    if (pb.attempts >= sync_types.MAX_UNKNOWN_PARENT_ATTEMPTS) {
                        if (exhausted_count < exhausted_roots.len) {
                            exhausted_roots[exhausted_count] = child_root;
                            exhausted_count += 1;
                        }
                        continue;
                    }
                    pb.status = .pending; // Reset to pending for retry.
                }
            }
            for (exhausted_roots[0..exhausted_count]) |child_root| {
                self.removePendingTree(child_root);
            }
        }
    }

    /// Mark a root as bad — removes all descendants.
    pub fn markBad(self: *UnknownBlockSync, root: [32]u8) !void {
        try self.bad_roots.put(self.allocator, root, {});
        if (self.parents_needed.get(root)) |waiters| {
            var child_roots: [sync_types.MAX_PENDING_BLOCKS][32]u8 = undefined;
            var child_count: usize = 0;
            for (waiters.child_roots.items) |child_root| {
                if (child_count < child_roots.len) {
                    child_roots[child_count] = child_root;
                    child_count += 1;
                }
            }
            for (child_roots[0..child_count]) |child_root| {
                self.removePendingTree(child_root);
            }
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

    pub fn metricsSnapshot(self: *const UnknownBlockSync) MetricsSnapshot {
        var snapshot: MetricsSnapshot = .{
            .pending_blocks = @intCast(self.pending.count()),
            .pending_parents = @intCast(self.parents_needed.count()),
            .in_flight_requests = @intCast(self.in_flight),
            .bad_roots = @intCast(self.bad_roots.count()),
        };

        var it = self.pending.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.status == .fetching) snapshot.fetching_blocks += 1;
            if (entry.value_ptr.attempts >= sync_types.MAX_UNKNOWN_PARENT_ATTEMPTS) snapshot.exhausted_blocks += 1;
        }

        return snapshot;
    }

    /// Get needed parent roots (for external use / debugging).
    pub fn getNeededParents(self: *const UnknownBlockSync, out: *std.ArrayListUnmanaged([32]u8)) !void {
        var it = self.parents_needed.iterator();
        while (it.next()) |entry| {
            var any_live = false;
            for (entry.value_ptr.child_roots.items) |child_root| {
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
        var waiters = removed.value;
        defer waiters.deinit(self.allocator);

        const cbs = self.callbacks orelse return;

        for (waiters.child_roots.items) |child_root| {
            if (self.pending.fetchSwapRemove(child_root)) |kv| {
                var child = kv.value;
                const child_block_root = child.prepared.block_root;

                // Try to import the child — its parent is now known.
                var owned_child = child.prepared;
                cbs.importBlock(owned_child) catch |err| switch (err) {
                    error.ImportPending => continue,
                    else => {
                        // Child failed import — drop the entire descendant subtree.
                        self.removePendingTree(child_block_root);
                        continue;
                    },
                };
                owned_child = undefined;
                child = undefined;

                // This child is now imported — resolve ITS children recursively.
                self.resolveChildren(child_block_root) catch {};
            }
        }
    }

    fn preferredPeerForChildren(
        self: *UnknownBlockSync,
        waiters: *const ParentWaiters,
        peers: []const []const u8,
    ) ?[]const u8 {
        for (waiters.child_roots.items) |child_root| {
            const pending = self.pending.getPtr(child_root) orelse continue;
            const preferred = pending.preferredPeerId() orelse continue;
            if (isPeerExcluded(waiters, preferred)) continue;
            for (peers) |peer| {
                if (std.mem.eql(u8, peer, preferred)) return peer;
            }
        }
        return null;
    }

    fn selectPeerForParent(
        self: *UnknownBlockSync,
        waiters: *ParentWaiters,
        peers: []const []const u8,
    ) ?[]const u8 {
        if (self.preferredPeerForChildren(waiters, peers)) |peer| return peer;
        if (self.nextEligiblePeer(waiters, peers)) |peer| return peer;
        if (waiters.excluded_peers.isEmpty()) return null;

        // Every currently connected peer for this parent has been tried once.
        // Start a new round instead of pinning the session forever.
        waiters.clearExcludedPeers(self.allocator);
        return self.preferredPeerForChildren(waiters, peers) orelse self.nextEligiblePeer(waiters, peers);
    }

    fn nextEligiblePeer(
        self: *UnknownBlockSync,
        waiters: *const ParentWaiters,
        peers: []const []const u8,
    ) ?[]const u8 {
        if (peers.len == 0) return null;

        for (0..peers.len) |offset| {
            const idx = (self.peer_index + offset) % peers.len;
            const peer = peers[idx];
            if (isPeerExcluded(waiters, peer)) continue;
            self.peer_index = (idx + 1) % peers.len;
            return peer;
        }
        return null;
    }

    fn resolveKnownParentChildren(self: *UnknownBlockSync, cbs: UnknownBlockCallbacks) void {
        var ready_parents = std.ArrayListUnmanaged([32]u8).empty;
        defer ready_parents.deinit(self.allocator);

        var pit = self.parents_needed.iterator();
        while (pit.next()) |entry| {
            const parent_root = entry.key_ptr.*;
            if (!cbs.hasBlock(parent_root)) continue;
            ready_parents.append(self.allocator, parent_root) catch return;
        }

        for (ready_parents.items) |parent_root| {
            self.resolveChildren(parent_root) catch {};
        }
    }

    /// Evict the oldest pending block (lowest slot).
    fn evictOldest(self: *UnknownBlockSync) void {
        var oldest_slot: u64 = std.math.maxInt(u64);
        var oldest_root: ?[32]u8 = null;

        var it = self.pending.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.slot() < oldest_slot) {
                oldest_slot = entry.value_ptr.slot();
                oldest_root = entry.key_ptr.*;
            }
        }

        if (oldest_root) |root| {
            self.removePendingTree(root);
        }
    }

    fn removePendingTree(self: *UnknownBlockSync, root: [32]u8) void {
        if (self.parents_needed.fetchSwapRemove(root)) |kv| {
            var waiters = kv.value;
            defer waiters.deinit(self.allocator);
            for (waiters.child_roots.items) |child_root| {
                self.removePendingTree(child_root);
            }
        }

        if (self.pending.fetchSwapRemove(root)) |kv| {
            const parent_root = kv.value.prepared.block.beaconBlock().parentRoot().*;
            var removed = kv.value;
            removed.prepared.deinit(self.allocator);
            self.removeChildReference(parent_root, root);
        }
    }

    fn removeChildReference(self: *UnknownBlockSync, parent_root: [32]u8, child_root: [32]u8) void {
        const waiters = self.parents_needed.getPtr(parent_root) orelse return;
        const children = &waiters.child_roots;

        var i: usize = 0;
        while (i < children.items.len) : (i += 1) {
            if (std.mem.eql(u8, &children.items[i], &child_root)) {
                _ = children.swapRemove(i);
                break;
            }
        }

        if (children.items.len == 0) {
            if (self.parents_needed.fetchSwapRemove(parent_root)) |kv| {
                var removed = kv.value;
                removed.deinit(self.allocator);
            }
        }
    }
};

fn isPeerExcluded(waiters: *const ParentWaiters, peer_id: []const u8) bool {
    for (waiters.excluded_peers.peers.items) |*entry| {
        if (std.mem.eql(u8, entry.id(), peer_id)) return true;
    }
    return false;
}

// ── Tests ────────────────────────────────────────────────────────────

fn makeTestPreparedBlock(
    allocator: Allocator,
    slot: u64,
    parent_root: [32]u8,
    block_root: [32]u8,
) !PreparedBlockInput {
    const consensus_types = @import("consensus_types");
    const fork_types = @import("fork_types");

    var block: consensus_types.phase0.SignedBeaconBlock.Type = consensus_types.phase0.SignedBeaconBlock.default_value;
    block.message.slot = slot;
    block.message.parent_root = parent_root;

    const ssz_size = consensus_types.phase0.SignedBeaconBlock.serializedSize(&block);
    const ssz_bytes = try allocator.alloc(u8, ssz_size);
    defer allocator.free(ssz_bytes);
    _ = consensus_types.phase0.SignedBeaconBlock.serializeIntoBytes(&block, ssz_bytes);

    return .{
        .block = try fork_types.AnySignedBeaconBlock.deserialize(allocator, .full, .phase0, ssz_bytes),
        .source = .gossip,
        .block_root = block_root,
        .seen_timestamp_sec = 0,
    };
}

test "UnknownBlockSync: add and retrieve pending block" {
    const alloc = std.testing.allocator;
    var sync = UnknownBlockSync.init(alloc);
    defer sync.deinit();

    const block_root = [_]u8{0x01} ** 32;
    const parent_root = [_]u8{0x02} ** 32;

    const added = try sync.addPendingBlock(try makeTestPreparedBlock(alloc, 42, parent_root, block_root));
    try std.testing.expect(added);
    try std.testing.expectEqual(@as(usize, 1), sync.pendingCount());

    // Duplicate rejected.
    const dup = try sync.addPendingBlock(try makeTestPreparedBlock(alloc, 42, parent_root, block_root));
    try std.testing.expect(!dup);
}

test "UnknownBlockSync: getNeededParents" {
    const alloc = std.testing.allocator;
    var sync = UnknownBlockSync.init(alloc);
    defer sync.deinit();

    const parent = [_]u8{0xAA} ** 32;
    _ = try sync.addPendingBlock(try makeTestPreparedBlock(alloc, 10, parent, [_]u8{0x01} ** 32));

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

    const added = try sync.addPendingBlock(try makeTestPreparedBlock(alloc, 5, bad_parent, [_]u8{0x01} ** 32));
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
        _ = try sync.addPendingBlock(try makeTestPreparedBlock(alloc, @as(u64, @intCast(i)) + 100, parent, root));
    }
    try std.testing.expectEqual(sync_types.MAX_PENDING_BLOCKS, sync.pendingCount());

    const new_root: [32]u8 = [_]u8{0xEE} ** 32;
    const new_parent: [32]u8 = [_]u8{0xDD} ** 32;
    _ = try sync.addPendingBlock(try makeTestPreparedBlock(alloc, 999, new_parent, new_root));
    try std.testing.expectEqual(sync_types.MAX_PENDING_BLOCKS, sync.pendingCount());
}

test "UnknownBlockSync: prefers gossip peer for parent fetch" {
    const TestCallbacks = struct {
        requested_peer: ?[]const u8 = null,

        fn requestBlockByRootFn(ptr: *anyopaque, _: [32]u8, peer_id: []const u8) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.requested_peer = peer_id;
        }

        fn importBlockFn(_: *anyopaque, prepared: PreparedBlockInput) anyerror!void {
            var owned = prepared;
            owned.deinit(std.testing.allocator);
        }

        fn hasBlockFn(_: *anyopaque, _: [32]u8) bool {
            return false;
        }

        fn getConnectedPeersFn(_: *anyopaque) []const []const u8 {
            return &.{ "peer-a", "peer-b" };
        }

        fn callbacks(self: *@This()) UnknownBlockCallbacks {
            return .{
                .ptr = self,
                .requestBlockByRootFn = &requestBlockByRootFn,
                .importBlockFn = &importBlockFn,
                .hasBlockFn = &hasBlockFn,
                .getConnectedPeersFn = &getConnectedPeersFn,
            };
        }
    };

    const alloc = std.testing.allocator;
    var sync = UnknownBlockSync.init(alloc);
    defer sync.deinit();

    var callbacks = TestCallbacks{};
    sync.setCallbacks(callbacks.callbacks());

    const parent_root = [_]u8{0xAA} ** 32;
    const child_root = [_]u8{0xBB} ** 32;
    _ = try sync.addPendingBlockWithPeer(try makeTestPreparedBlock(alloc, 42, parent_root, child_root), "peer-b");

    sync.tick();
    try std.testing.expectEqualStrings("peer-b", callbacks.requested_peer.?);
}

test "UnknownBlockSync: fetch failure excludes failed peer for current parent session" {
    const TestCallbacks = struct {
        requested_peer: ?[]const u8 = null,

        fn requestBlockByRootFn(ptr: *anyopaque, _: [32]u8, peer_id: []const u8) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.requested_peer = peer_id;
        }

        fn importBlockFn(_: *anyopaque, prepared: PreparedBlockInput) anyerror!void {
            var owned = prepared;
            owned.deinit(std.testing.allocator);
        }

        fn hasBlockFn(_: *anyopaque, _: [32]u8) bool {
            return false;
        }

        fn getConnectedPeersFn(_: *anyopaque) []const []const u8 {
            return &.{ "peer-a", "peer-b", "peer-c" };
        }

        fn callbacks(self: *@This()) UnknownBlockCallbacks {
            return .{
                .ptr = self,
                .requestBlockByRootFn = &requestBlockByRootFn,
                .importBlockFn = &importBlockFn,
                .hasBlockFn = &hasBlockFn,
                .getConnectedPeersFn = &getConnectedPeersFn,
            };
        }
    };

    const alloc = std.testing.allocator;
    var sync = UnknownBlockSync.init(alloc);
    defer sync.deinit();

    var callbacks = TestCallbacks{};
    sync.setCallbacks(callbacks.callbacks());

    const parent_root = [_]u8{0xAB} ** 32;
    const child_root = [_]u8{0xBC} ** 32;
    _ = try sync.addPendingBlockWithPeer(try makeTestPreparedBlock(alloc, 42, parent_root, child_root), "peer-b");

    sync.tick();
    try std.testing.expectEqualStrings("peer-b", callbacks.requested_peer.?);

    callbacks.requested_peer = null;
    sync.onFetchFailed(parent_root, "peer-b");
    sync.tick();
    try std.testing.expectEqualStrings("peer-a", callbacks.requested_peer.?);
}

test "UnknownBlockSync: exhausted peer session resets exclusions and starts new round" {
    const TestCallbacks = struct {
        requested_peer: ?[]const u8 = null,

        fn requestBlockByRootFn(ptr: *anyopaque, _: [32]u8, peer_id: []const u8) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.requested_peer = peer_id;
        }

        fn importBlockFn(_: *anyopaque, prepared: PreparedBlockInput) anyerror!void {
            var owned = prepared;
            owned.deinit(std.testing.allocator);
        }

        fn hasBlockFn(_: *anyopaque, _: [32]u8) bool {
            return false;
        }

        fn getConnectedPeersFn(_: *anyopaque) []const []const u8 {
            return &.{ "peer-a", "peer-b" };
        }

        fn callbacks(self: *@This()) UnknownBlockCallbacks {
            return .{
                .ptr = self,
                .requestBlockByRootFn = &requestBlockByRootFn,
                .importBlockFn = &importBlockFn,
                .hasBlockFn = &hasBlockFn,
                .getConnectedPeersFn = &getConnectedPeersFn,
            };
        }
    };

    const alloc = std.testing.allocator;
    var sync = UnknownBlockSync.init(alloc);
    defer sync.deinit();

    var callbacks = TestCallbacks{};
    sync.setCallbacks(callbacks.callbacks());

    const parent_root = [_]u8{0xCD} ** 32;
    const child_root = [_]u8{0xDE} ** 32;
    _ = try sync.addPendingBlock(try makeTestPreparedBlock(alloc, 42, parent_root, child_root));

    sync.tick();
    try std.testing.expectEqualStrings("peer-a", callbacks.requested_peer.?);

    callbacks.requested_peer = null;
    sync.onFetchFailed(parent_root, "peer-a");
    sync.tick();
    try std.testing.expectEqualStrings("peer-b", callbacks.requested_peer.?);

    callbacks.requested_peer = null;
    sync.onFetchFailed(parent_root, "peer-b");
    sync.tick();
    try std.testing.expectEqualStrings("peer-a", callbacks.requested_peer.?);
}

test "UnknownBlockSync: import pending defers child resolution until notify" {
    const TestCallbacks = struct {
        import_pending: bool = true,
        import_calls: usize = 0,

        fn requestBlockByRootFn(_: *anyopaque, _: [32]u8, _: []const u8) void {}

        fn importBlockFn(ptr: *anyopaque, prepared: PreparedBlockInput) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.import_calls += 1;
            if (self.import_pending) {
                var owned = prepared;
                owned.deinit(std.testing.allocator);
                return error.ImportPending;
            }
            var owned = prepared;
            owned.deinit(std.testing.allocator);
        }

        fn hasBlockFn(_: *anyopaque, _: [32]u8) bool {
            return false;
        }

        fn getConnectedPeersFn(_: *anyopaque) []const []const u8 {
            return &.{};
        }

        fn callbacks(self: *@This()) UnknownBlockCallbacks {
            return .{
                .ptr = self,
                .requestBlockByRootFn = &requestBlockByRootFn,
                .importBlockFn = &importBlockFn,
                .hasBlockFn = &hasBlockFn,
                .getConnectedPeersFn = &getConnectedPeersFn,
            };
        }
    };

    const alloc = std.testing.allocator;
    var sync = UnknownBlockSync.init(alloc);
    defer sync.deinit();

    var callbacks = TestCallbacks{};
    sync.setCallbacks(callbacks.callbacks());

    const parent_root = [_]u8{0xAA} ** 32;
    const child_root = [_]u8{0xBB} ** 32;
    _ = try sync.addPendingBlock(try makeTestPreparedBlock(alloc, 42, parent_root, child_root));

    try sync.onParentFetched(parent_root, try makeTestPreparedBlock(alloc, 41, [_]u8{0x09} ** 32, parent_root));
    try std.testing.expectEqual(@as(usize, 1), sync.pendingCount());
    try std.testing.expectEqual(@as(usize, 1), callbacks.import_calls);

    callbacks.import_pending = false;
    try sync.notifyBlockImported(parent_root);
    try std.testing.expectEqual(@as(usize, 0), sync.pendingCount());
    try std.testing.expectEqual(@as(usize, 2), callbacks.import_calls);
}

test "UnknownBlockSync: exhausted fetch drops pending subtree" {
    const TestCallbacks = struct {
        fn requestBlockByRootFn(_: *anyopaque, _: [32]u8, _: []const u8) void {}

        fn importBlockFn(_: *anyopaque, prepared: PreparedBlockInput) anyerror!void {
            var owned = prepared;
            owned.deinit(std.testing.allocator);
        }

        fn hasBlockFn(_: *anyopaque, _: [32]u8) bool {
            return false;
        }

        fn getConnectedPeersFn(_: *anyopaque) []const []const u8 {
            return &.{"peer-1"};
        }

        fn callbacks(self: *@This()) UnknownBlockCallbacks {
            return .{
                .ptr = self,
                .requestBlockByRootFn = &requestBlockByRootFn,
                .importBlockFn = &importBlockFn,
                .hasBlockFn = &hasBlockFn,
                .getConnectedPeersFn = &getConnectedPeersFn,
            };
        }
    };

    const alloc = std.testing.allocator;
    var sync = UnknownBlockSync.init(alloc);
    defer sync.deinit();

    var callbacks = TestCallbacks{};
    sync.setCallbacks(callbacks.callbacks());

    const parent_root = [_]u8{0x10} ** 32;
    const child_root = [_]u8{0x11} ** 32;
    const grandchild_root = [_]u8{0x12} ** 32;

    _ = try sync.addPendingBlock(try makeTestPreparedBlock(alloc, 42, parent_root, child_root));
    _ = try sync.addPendingBlock(try makeTestPreparedBlock(alloc, 43, child_root, grandchild_root));

    for (0..sync_types.MAX_UNKNOWN_PARENT_ATTEMPTS) |_| {
        sync.tick();
        sync.onFetchFailed(parent_root, "peer-1");
    }

    try std.testing.expectEqual(@as(usize, 0), sync.pendingCount());
    try std.testing.expectEqual(@as(usize, 0), sync.parents_needed.count());
    try std.testing.expectEqual(@as(u64, 0), sync.metricsSnapshot().exhausted_blocks);
}

test "UnknownBlockSync: failed child import drops descendants" {
    const TestCallbacks = struct {
        fn requestBlockByRootFn(_: *anyopaque, _: [32]u8, _: []const u8) void {}

        fn importBlockFn(ptr: *anyopaque, prepared: PreparedBlockInput) anyerror!void {
            const should_fail_child: *bool = @ptrCast(@alignCast(ptr));
            const slot = prepared.slot();
            var owned = prepared;
            defer owned.deinit(std.testing.allocator);

            if (slot == 42 and should_fail_child.*) return error.InvalidBlock;
        }

        fn hasBlockFn(_: *anyopaque, _: [32]u8) bool {
            return false;
        }

        fn getConnectedPeersFn(_: *anyopaque) []const []const u8 {
            return &.{};
        }

        fn callbacks(self: *bool) UnknownBlockCallbacks {
            return .{
                .ptr = self,
                .requestBlockByRootFn = &requestBlockByRootFn,
                .importBlockFn = &importBlockFn,
                .hasBlockFn = &hasBlockFn,
                .getConnectedPeersFn = &getConnectedPeersFn,
            };
        }
    };

    const alloc = std.testing.allocator;
    var sync = UnknownBlockSync.init(alloc);
    defer sync.deinit();

    var fail_child = true;
    sync.setCallbacks(TestCallbacks.callbacks(&fail_child));

    const parent_root = [_]u8{0x20} ** 32;
    const child_root = [_]u8{0x21} ** 32;
    const grandchild_root = [_]u8{0x22} ** 32;

    _ = try sync.addPendingBlock(try makeTestPreparedBlock(alloc, 42, parent_root, child_root));
    _ = try sync.addPendingBlock(try makeTestPreparedBlock(alloc, 43, child_root, grandchild_root));

    try sync.onParentFetched(parent_root, try makeTestPreparedBlock(alloc, 41, [_]u8{0x23} ** 32, parent_root));

    try std.testing.expectEqual(@as(usize, 0), sync.pendingCount());
    try std.testing.expectEqual(@as(usize, 0), sync.parents_needed.count());
}

test "UnknownBlockSync: tick imports pending child when parent is already known" {
    const TestCallbacks = struct {
        imported: usize = 0,
        requested: usize = 0,
        known_parent: [32]u8,

        fn requestBlockByRootFn(ptr: *anyopaque, _: [32]u8, _: []const u8) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.requested += 1;
        }

        fn importBlockFn(ptr: *anyopaque, prepared: PreparedBlockInput) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.imported += 1;
            var owned = prepared;
            owned.deinit(std.testing.allocator);
        }

        fn hasBlockFn(ptr: *anyopaque, root: [32]u8) bool {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return std.mem.eql(u8, &self.known_parent, &root);
        }

        fn getConnectedPeersFn(_: *anyopaque) []const []const u8 {
            return &.{"peer-a"};
        }

        fn callbacks(self: *@This()) UnknownBlockCallbacks {
            return .{
                .ptr = self,
                .requestBlockByRootFn = &requestBlockByRootFn,
                .importBlockFn = &importBlockFn,
                .hasBlockFn = &hasBlockFn,
                .getConnectedPeersFn = &getConnectedPeersFn,
            };
        }
    };

    const alloc = std.testing.allocator;
    var sync = UnknownBlockSync.init(alloc);
    defer sync.deinit();

    const parent_root = [_]u8{0x31} ** 32;
    const child_root = [_]u8{0x32} ** 32;

    var callbacks = TestCallbacks{ .known_parent = parent_root };
    sync.setCallbacks(callbacks.callbacks());

    _ = try sync.addPendingBlock(try makeTestPreparedBlock(alloc, 42, parent_root, child_root));
    try std.testing.expectEqual(@as(usize, 1), sync.pendingCount());

    sync.tick();

    try std.testing.expectEqual(@as(usize, 1), callbacks.imported);
    try std.testing.expectEqual(@as(usize, 0), callbacks.requested);
    try std.testing.expectEqual(@as(usize, 0), sync.pendingCount());
    try std.testing.expectEqual(@as(usize, 0), sync.parents_needed.count());
}
