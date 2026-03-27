//! UnknownChainSync: coordinator for backwards header chain sync.
//!
//! Manages a set of BackwardsChain objects, each tracking an unknown chain
//! of headers. When we encounter unknown block roots (from gossip, peer
//! status, attestations), we create a new chain and build it backwards
//! parent-by-parent until it links to our known chain (fork choice).
//!
//! Key design:
//! - Headers only — no full blocks stored. Prevents OOM during non-finality.
//! - Multiple chains tracked independently (forky networks).
//! - On link, delegates to forward sync for actual block fetching.
//! - Prunes chains that fall behind finalization or exceed attempts.
//!
//! Reference: Lodestar TS PR #8221 — `sync/unknownChain/unknownChain.ts`

const std = @import("std");
const Allocator = std.mem.Allocator;
const backwards_chain = @import("backwards_chain.zig");
const BackwardsChain = backwards_chain.BackwardsChain;
const MinimalHeader = backwards_chain.MinimalHeader;
const State = backwards_chain.State;

/// Maximum number of concurrent backwards chains.
const MAX_CHAINS: usize = 64;

/// Callback vtable for external dependencies.
///
/// The sync coordinator doesn't do I/O directly — it invokes these
/// callbacks for network requests and chain processing. This keeps
/// the core logic testable and decoupled from the P2P layer.
pub const Callbacks = struct {
    /// Opaque context pointer passed to all callbacks.
    ptr: *anyopaque,

    /// Request a block header by root from a specific peer.
    /// The response should be fed back via `onUnknownBlockInput()`.
    fetchBlockByRootFn: *const fn (
        ptr: *anyopaque,
        root: [32]u8,
        peer_id: []const u8,
    ) void,

    /// Called when a chain becomes linked — push to forward sync.
    /// The chain's headers are in forward order (oldest first).
    /// The linking root (in fork choice) is the parent of headers[0].
    processLinkedChainFn: *const fn (
        ptr: *anyopaque,
        linking_root: [32]u8,
        headers: []const MinimalHeader,
    ) void,

    pub fn fetchBlockByRoot(self: *const Callbacks, root: [32]u8, peer_id: []const u8) void {
        self.fetchBlockByRootFn(self.ptr, root, peer_id);
    }

    pub fn processLinkedChain(self: *const Callbacks, linking_root: [32]u8, headers: []const MinimalHeader) void {
        self.processLinkedChainFn(self.ptr, linking_root, headers);
    }
};

/// Fork choice query interface — abstracted for testability.
pub const ForkChoiceQuery = struct {
    ptr: *anyopaque,
    hasBlockFn: *const fn (ptr: *anyopaque, root: [32]u8) bool,

    pub fn hasBlock(self: *const ForkChoiceQuery, root: [32]u8) bool {
        return self.hasBlockFn(self.ptr, root);
    }
};

/// Manages multiple BackwardsChain instances.
pub const UnknownChainSync = struct {
    allocator: Allocator,

    /// Active backwards chains.
    chains: std.ArrayListUnmanaged(BackwardsChain),

    /// Set of roots we've already seen — prevents duplicate chain creation.
    /// Maps head_root → chain index.
    known_roots: std.AutoArrayHashMap([32]u8, usize),

    /// Callbacks for external I/O.
    callbacks: ?Callbacks,

    /// Fork choice query interface.
    fork_choice: ?ForkChoiceQuery,

    /// Count of linked chains processed (for metrics/logging).
    linked_chains_processed: u64,

    /// Count of chains pruned as irrelevant.
    chains_pruned: u64,

    pub fn init(allocator: Allocator) UnknownChainSync {
        return .{
            .allocator = allocator,
            .chains = .empty,
            .known_roots = std.AutoArrayHashMap([32]u8, usize).init(allocator),
            .callbacks = null,
            .fork_choice = null,
            .linked_chains_processed = 0,
            .chains_pruned = 0,
        };
    }

    pub fn deinit(self: *UnknownChainSync) void {
        for (self.chains.items) |*chain| {
            chain.deinit();
        }
        self.chains.deinit(self.allocator);
        self.known_roots.deinit();
    }

    /// Set the callback vtable. Must be called before tick().
    pub fn setCallbacks(self: *UnknownChainSync, callbacks: Callbacks) void {
        self.callbacks = callbacks;
    }

    /// Set the fork choice query interface.
    pub fn setForkChoice(self: *UnknownChainSync, fc: ForkChoiceQuery) void {
        self.fork_choice = fc;
    }

    /// Feed an unknown block root (e.g., from peer status, attestation).
    ///
    /// Creates a new chain in unknown_head state if we haven't seen this root.
    /// Optionally associates a peer with the chain.
    pub fn onUnknownBlockRoot(self: *UnknownChainSync, root: [32]u8, peer_id: ?[]const u8) !void {
        // Check if this root is already in fork choice — no need to track.
        if (self.fork_choice) |fc| {
            if (fc.hasBlock(root)) return;
        }

        // Check if we're already tracking this root.
        if (self.known_roots.get(root)) |idx| {
            // Chain exists — just add the peer.
            if (peer_id) |pid| {
                if (idx < self.chains.items.len) {
                    _ = try self.chains.items[idx].peers.add(self.allocator, pid);
                }
            }
            return;
        }

        // Evict oldest chain if at capacity.
        if (self.chains.items.len >= MAX_CHAINS) {
            self.evictOldest();
        }

        // Create new chain.
        var chain = BackwardsChain.initFromRoot(self.allocator, root);
        if (peer_id) |pid| {
            _ = try chain.peers.add(self.allocator, pid);
        }

        const idx = self.chains.items.len;
        try self.chains.append(self.allocator, chain);
        try self.known_roots.put(root, idx);
    }

    /// Feed a block header for an unknown chain.
    ///
    /// Looks up which chain needs this root and advances it. Then checks
    /// if the chain's new ancestor is in fork choice (→ link).
    pub fn onUnknownBlockInput(
        self: *UnknownChainSync,
        slot: u64,
        root: [32]u8,
        parent_root: [32]u8,
        peer_id: ?[]const u8,
    ) !void {
        const header = MinimalHeader{
            .slot = slot,
            .root = root,
            .parent_root = parent_root,
        };

        // Find the chain expecting this root.
        var target_idx: ?usize = null;
        for (self.chains.items, 0..) |*chain, i| {
            if (chain.state != .linked and
                std.mem.eql(u8, &chain.ancestor_root, &root))
            {
                target_idx = i;
                break;
            }
        }

        const idx = target_idx orelse return; // No chain waiting for this root.
        const chain = &self.chains.items[idx];

        // Add peer if provided.
        if (peer_id) |pid| {
            _ = try chain.peers.add(self.allocator, pid);
        }

        // Advance the chain.
        chain.advance(header) catch |err| {
            switch (err) {
                error.AlreadyLinked, error.RootMismatch => return,
                error.ChainTooLong => {
                    // Chain is too long — remove it.
                    self.removeChain(idx);
                    return;
                },
                else => return err,
            }
        };

        // Check if the new ancestor is in fork choice.
        self.checkAndLink(idx);
    }

    /// Called when a block has been successfully imported.
    ///
    /// Checks if any chain's ancestor_root matches the imported block root.
    /// If so, the chain can be linked.
    pub fn onBlockImported(self: *UnknownChainSync, root: [32]u8) void {
        // Check all chains — the imported block might link one.
        var i: usize = 0;
        while (i < self.chains.items.len) {
            const chain = &self.chains.items[i];
            if (chain.state != .linked and
                std.mem.eql(u8, &chain.ancestor_root, &root))
            {
                self.checkAndLink(i);
            }
            i += 1;
        }
    }

    /// Called when a new epoch is finalized.
    ///
    /// Prunes chains that are no longer relevant (oldest header is before
    /// the finalized slot).
    pub fn onFinalized(self: *UnknownChainSync, finalized_slot: u64) void {
        var i: usize = 0;
        while (i < self.chains.items.len) {
            if (!self.chains.items[i].isRelevant(finalized_slot)) {
                self.removeChain(i);
                self.chains_pruned += 1;
                // Don't increment i — removeChain swaps, so check same index.
            } else {
                i += 1;
            }
        }
    }

    /// Called when a peer connects.
    pub fn onPeerConnected(self: *UnknownChainSync, peer_id: []const u8, head_root: [32]u8) !void {
        // If the peer's head root matches any chain, add the peer.
        for (self.chains.items) |*chain| {
            if (std.mem.eql(u8, &chain.head_root, &head_root)) {
                _ = try chain.peers.add(self.allocator, peer_id);
            }
        }

        // Also check if this is a new unknown root.
        try self.onUnknownBlockRoot(head_root, peer_id);
    }

    /// Called when a peer disconnects.
    pub fn onPeerDisconnected(self: *UnknownChainSync, peer_id: []const u8) void {
        for (self.chains.items) |*chain| {
            _ = chain.peers.remove(peer_id);
        }
    }

    /// Tick: advance chains that need it.
    ///
    /// For each chain in unknown_head or unknown_ancestor state, requests
    /// the next needed parent from an available peer. Also processes any
    /// newly linked chains.
    pub fn tick(self: *UnknownChainSync) void {
        const callbacks = self.callbacks orelse return;

        // First, process any linked chains.
        var i: usize = 0;
        while (i < self.chains.items.len) {
            const chain = &self.chains.items[i];
            if (chain.state == .linked) {
                // Deliver to forward sync.
                callbacks.processLinkedChain(
                    chain.ancestor_root,
                    chain.headers.items,
                );
                self.linked_chains_processed += 1;
                self.removeChain(i);
                // Don't increment — removeChain swaps.
            } else {
                i += 1;
            }
        }

        // Then, advance chains that need a parent fetched.
        for (self.chains.items) |*chain| {
            if (!chain.needsAdvance()) continue;
            if (chain.peers.isEmpty()) continue;

            const needed_root = chain.nextNeededRoot() orelse continue;

            // Pick a peer (first available — can be made smarter later).
            if (chain.peers.peers.items.len > 0) {
                const peer = chain.peers.peers.items[0].id();
                callbacks.fetchBlockByRoot(needed_root, peer);
                chain.recordAttempt();
            }
        }
    }

    // -- Internal helpers --

    /// Check if a chain's ancestor is in fork choice and link it.
    fn checkAndLink(self: *UnknownChainSync, chain_idx: usize) void {
        const fc = self.fork_choice orelse return;
        const chain = &self.chains.items[chain_idx];

        if (chain.state == .linked) return;

        if (fc.hasBlock(chain.ancestor_root)) {
            // The ancestor's slot doesn't matter for the linking logic;
            // use 0 as placeholder. The important thing is the state transition.
            chain.link(0);
        }
    }

    /// Remove a chain by index (swap-remove).
    fn removeChain(self: *UnknownChainSync, idx: usize) void {
        // Remove from known_roots.
        const chain = &self.chains.items[idx];
        _ = self.known_roots.swapRemove(chain.head_root);

        // Clean up the chain.
        var removed = self.chains.swapRemove(idx);
        removed.deinit();

        // Fix up known_roots index for the chain that was swapped in.
        if (idx < self.chains.items.len) {
            const swapped = &self.chains.items[idx];
            if (self.known_roots.getPtr(swapped.head_root)) |idx_ptr| {
                idx_ptr.* = idx;
            }
        }
    }

    /// Evict the oldest chain (by creation time).
    fn evictOldest(self: *UnknownChainSync) void {
        if (self.chains.items.len == 0) return;

        var oldest_idx: usize = 0;
        var oldest_seq: u64 = self.chains.items[0].creation_seq;

        for (self.chains.items[1..], 1..) |*chain, i| {
            if (chain.creation_seq < oldest_seq) {
                oldest_seq = chain.creation_seq;
                oldest_idx = i;
            }
        }

        self.removeChain(oldest_idx);
    }

    // -- Query methods --

    /// Number of active chains.
    pub fn chainCount(self: *const UnknownChainSync) usize {
        return self.chains.items.len;
    }

    /// Number of chains in a given state.
    pub fn chainCountByState(self: *const UnknownChainSync, state: State) usize {
        var count: usize = 0;
        for (self.chains.items) |*chain| {
            if (chain.state == state) count += 1;
        }
        return count;
    }

    /// Check if a root is being tracked by any chain.
    pub fn isTracking(self: *const UnknownChainSync, root: [32]u8) bool {
        return self.known_roots.contains(root);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Test stub for fork choice.
const TestForkChoice = struct {
    known_roots: std.AutoArrayHashMap([32]u8, void),

    fn init(alloc: Allocator) TestForkChoice {
        return .{ .known_roots = std.AutoArrayHashMap([32]u8, void).init(alloc) };
    }
    fn deinit(self: *TestForkChoice) void {
        self.known_roots.deinit();
    }
    fn addRoot(self: *TestForkChoice, root: [32]u8) !void {
        try self.known_roots.put(root, {});
    }
    fn hasBlock(ptr: *anyopaque, root: [32]u8) bool {
        const self: *TestForkChoice = @ptrCast(@alignCast(ptr));
        return self.known_roots.contains(root);
    }
    fn query(self: *TestForkChoice) ForkChoiceQuery {
        return .{ .ptr = @ptrCast(self), .hasBlockFn = &hasBlock };
    }
};

/// Test stub for callbacks.
const TestCallbacks = struct {
    fetch_requests: std.ArrayListUnmanaged(FetchReq),
    linked_chains: std.ArrayListUnmanaged(LinkedChainInfo),
    allocator: Allocator,

    const FetchReq = struct { root: [32]u8 };
    const LinkedChainInfo = struct {
        linking_root: [32]u8,
        header_count: usize,
    };

    fn init(alloc: Allocator) TestCallbacks {
        return .{
            .fetch_requests = .empty,
            .linked_chains = .empty,
            .allocator = alloc,
        };
    }
    fn deinit(self: *TestCallbacks) void {
        self.fetch_requests.deinit(self.allocator);
        self.linked_chains.deinit(self.allocator);
    }
    fn fetchBlockByRoot(ptr: *anyopaque, root: [32]u8, _: []const u8) void {
        const self: *TestCallbacks = @ptrCast(@alignCast(ptr));
        self.fetch_requests.append(self.allocator, .{ .root = root }) catch {};
    }
    fn processLinkedChain(ptr: *anyopaque, linking_root: [32]u8, headers: []const MinimalHeader) void {
        const self: *TestCallbacks = @ptrCast(@alignCast(ptr));
        self.linked_chains.append(self.allocator, .{
            .linking_root = linking_root,
            .header_count = headers.len,
        }) catch {};
    }
    fn callbacks(self: *TestCallbacks) Callbacks {
        return .{
            .ptr = @ptrCast(self),
            .fetchBlockByRootFn = &fetchBlockByRoot,
            .processLinkedChainFn = &processLinkedChain,
        };
    }
};

test "UnknownChainSync: onUnknownBlockRoot creates chain" {
    const alloc = std.testing.allocator;
    var sync = UnknownChainSync.init(alloc);
    defer sync.deinit();

    const root = [_]u8{0x01} ** 32;
    try sync.onUnknownBlockRoot(root, "peer-1");

    try std.testing.expectEqual(@as(usize, 1), sync.chainCount());
    try std.testing.expect(sync.isTracking(root));
    try std.testing.expectEqual(@as(usize, 1), sync.chainCountByState(.unknown_head));
}

test "UnknownChainSync: duplicate root doesn't create new chain" {
    const alloc = std.testing.allocator;
    var sync = UnknownChainSync.init(alloc);
    defer sync.deinit();

    const root = [_]u8{0x01} ** 32;
    try sync.onUnknownBlockRoot(root, "peer-1");
    try sync.onUnknownBlockRoot(root, "peer-2");

    try std.testing.expectEqual(@as(usize, 1), sync.chainCount());
    // Both peers should be tracked.
    try std.testing.expectEqual(@as(usize, 2), sync.chains.items[0].peers.count());
}

test "UnknownChainSync: root in fork choice is ignored" {
    const alloc = std.testing.allocator;
    var fc = TestForkChoice.init(alloc);
    defer fc.deinit();

    const known_root = [_]u8{0x01} ** 32;
    try fc.addRoot(known_root);

    var sync = UnknownChainSync.init(alloc);
    defer sync.deinit();
    sync.setForkChoice(fc.query());

    try sync.onUnknownBlockRoot(known_root, "peer-1");
    try std.testing.expectEqual(@as(usize, 0), sync.chainCount());
}

test "UnknownChainSync: advance and link via block input" {
    const alloc = std.testing.allocator;
    var fc = TestForkChoice.init(alloc);
    defer fc.deinit();

    const known_root = [_]u8{0xAA} ** 32; // in fork choice
    try fc.addRoot(known_root);

    var sync = UnknownChainSync.init(alloc);
    defer sync.deinit();
    sync.setForkChoice(fc.query());

    // Unknown root appears.
    const head_root = [_]u8{0x01} ** 32;
    try sync.onUnknownBlockRoot(head_root, "peer-1");

    // Header arrives: head_root → parent_root.
    const parent_root = [_]u8{0x02} ** 32;
    try sync.onUnknownBlockInput(100, head_root, parent_root, "peer-1");
    try std.testing.expectEqual(@as(usize, 1), sync.chainCountByState(.unknown_ancestor));

    // Next header: parent_root → known_root (in fork choice).
    try sync.onUnknownBlockInput(99, parent_root, known_root, "peer-1");

    // Chain should now be linked.
    try std.testing.expectEqual(@as(usize, 1), sync.chainCountByState(.linked));
}

test "UnknownChainSync: onBlockImported links chain" {
    const alloc = std.testing.allocator;
    var fc = TestForkChoice.init(alloc);
    defer fc.deinit();

    var sync = UnknownChainSync.init(alloc);
    defer sync.deinit();
    sync.setForkChoice(fc.query());

    const head_root = [_]u8{0x01} ** 32;
    const parent_root = [_]u8{0x02} ** 32;
    try sync.onUnknownBlockRoot(head_root, "peer-1");
    try sync.onUnknownBlockInput(100, head_root, parent_root, "peer-1");

    // Now parent_root gets imported (and added to fork choice).
    try fc.addRoot(parent_root);
    sync.onBlockImported(parent_root);

    try std.testing.expectEqual(@as(usize, 1), sync.chainCountByState(.linked));
}

test "UnknownChainSync: onFinalized prunes old chains" {
    const alloc = std.testing.allocator;
    var sync = UnknownChainSync.init(alloc);
    defer sync.deinit();

    const root = [_]u8{0x01} ** 32;
    const parent = [_]u8{0x02} ** 32;
    try sync.onUnknownBlockRoot(root, "peer-1");
    try sync.onUnknownBlockInput(50, root, parent, "peer-1");

    // Finalize at slot 100 — chain's oldest header (slot 50) is behind.
    sync.onFinalized(100);
    try std.testing.expectEqual(@as(usize, 0), sync.chainCount());
    try std.testing.expectEqual(@as(u64, 1), sync.chains_pruned);
}

test "UnknownChainSync: tick fetches and processes linked chains" {
    const alloc = std.testing.allocator;
    var fc = TestForkChoice.init(alloc);
    defer fc.deinit();
    var cbs = TestCallbacks.init(alloc);
    defer cbs.deinit();

    const known_root = [_]u8{0xAA} ** 32;
    try fc.addRoot(known_root);

    var sync = UnknownChainSync.init(alloc);
    defer sync.deinit();
    sync.setForkChoice(fc.query());
    sync.setCallbacks(cbs.callbacks());

    // Create a chain and advance it to linked state.
    const head = [_]u8{0x01} ** 32;
    const mid = [_]u8{0x02} ** 32;
    try sync.onUnknownBlockRoot(head, "peer-1");
    try sync.onUnknownBlockInput(102, head, mid, "peer-1");
    try sync.onUnknownBlockInput(101, mid, known_root, "peer-1");

    // Chain should be linked.
    try std.testing.expectEqual(@as(usize, 1), sync.chainCountByState(.linked));

    // Tick should process the linked chain and remove it.
    sync.tick();

    try std.testing.expectEqual(@as(usize, 0), sync.chainCount());
    try std.testing.expectEqual(@as(usize, 1), cbs.linked_chains.items.len);
    try std.testing.expectEqual(@as(usize, 2), cbs.linked_chains.items[0].header_count);
    try std.testing.expectEqual(@as(u64, 1), sync.linked_chains_processed);
}

test "UnknownChainSync: tick requests fetch for unlinked chains" {
    const alloc = std.testing.allocator;
    var cbs = TestCallbacks.init(alloc);
    defer cbs.deinit();

    var sync = UnknownChainSync.init(alloc);
    defer sync.deinit();
    sync.setCallbacks(cbs.callbacks());

    const head = [_]u8{0x01} ** 32;
    try sync.onUnknownBlockRoot(head, "peer-1");

    // Tick should request the head root.
    sync.tick();

    try std.testing.expectEqual(@as(usize, 1), cbs.fetch_requests.items.len);
    try std.testing.expectEqualSlices(u8, &head, &cbs.fetch_requests.items[0].root);
}

test "UnknownChainSync: peer connect/disconnect" {
    const alloc = std.testing.allocator;
    var sync = UnknownChainSync.init(alloc);
    defer sync.deinit();

    const root = [_]u8{0x01} ** 32;
    try sync.onUnknownBlockRoot(root, "peer-1");

    // Connect a peer with matching head root.
    try sync.onPeerConnected("peer-2", root);
    try std.testing.expectEqual(@as(usize, 2), sync.chains.items[0].peers.count());

    // Disconnect peer-1.
    sync.onPeerDisconnected("peer-1");
    try std.testing.expectEqual(@as(usize, 1), sync.chains.items[0].peers.count());
}

test "UnknownChainSync: evicts oldest at capacity" {
    const alloc = std.testing.allocator;
    var sync = UnknownChainSync.init(alloc);
    defer sync.deinit();

    // Fill to capacity.
    for (0..MAX_CHAINS) |i| {
        var root: [32]u8 = [_]u8{0} ** 32;
        root[0] = @intCast(i);
        try sync.onUnknownBlockRoot(root, "peer-1");
    }
    try std.testing.expectEqual(MAX_CHAINS, sync.chainCount());

    // One more should evict oldest.
    const new_root: [32]u8 = [_]u8{0xFF} ** 32;
    try sync.onUnknownBlockRoot(new_root, "peer-1");
    try std.testing.expectEqual(MAX_CHAINS, sync.chainCount());
}
