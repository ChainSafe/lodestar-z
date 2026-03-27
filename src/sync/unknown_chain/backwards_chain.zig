//! BackwardsChain: state machine for building a chain of headers backwards.
//!
//! When we encounter a block root not in our fork choice (e.g., from gossip
//! attestations, peer status, or orphan blocks), we create a BackwardsChain
//! to track it. The chain builds backwards parent-by-parent until it either:
//!
//! - Links to a known block in fork choice → forward sync can take over.
//! - Falls behind the finalization horizon → irrelevant, discard.
//!
//! Design: only minimal headers are stored (slot, root, parent_root) — NOT
//! full blocks — so we can track extended periods of non-finality without OOM.
//!
//! Reference: Lodestar TS PR #8221 — `sync/unknownChain/backwardsChain.ts`

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Minimal block header — just enough to build the chain backwards.
/// Full block data is NOT stored; that's handled by forward sync after linking.
pub const MinimalHeader = struct {
    slot: u64,
    root: [32]u8,
    parent_root: [32]u8,
};

/// PeerSet — tracks which peers have referenced this chain.
/// Peers are stored as owned copies of their ID strings.
pub const PeerSet = struct {
    peers: std.ArrayListUnmanaged(PeerEntry),

    pub const PeerEntry = struct {
        id_buf: [128]u8,
        id_len: u8,

        pub fn id(self: *const PeerEntry) []const u8 {
            return self.id_buf[0..self.id_len];
        }
    };

    pub const empty: PeerSet = .{ .peers = .empty };

    pub fn deinit(self: *PeerSet, allocator: Allocator) void {
        self.peers.deinit(allocator);
    }

    /// Add a peer if not already present. Returns true if added.
    pub fn add(self: *PeerSet, allocator: Allocator, peer_id: []const u8) !bool {
        // Check for duplicate.
        for (self.peers.items) |*entry| {
            if (std.mem.eql(u8, entry.id(), peer_id)) return false;
        }
        var entry: PeerEntry = .{ .id_buf = undefined, .id_len = @intCast(@min(peer_id.len, 128)) };
        @memcpy(entry.id_buf[0..entry.id_len], peer_id[0..entry.id_len]);
        try self.peers.append(allocator, entry);
        return true;
    }

    /// Remove a peer. Returns true if found and removed.
    pub fn remove(self: *PeerSet, peer_id: []const u8) bool {
        for (self.peers.items, 0..) |*entry, i| {
            if (std.mem.eql(u8, entry.id(), peer_id)) {
                _ = self.peers.swapRemove(i);
                return true;
            }
        }
        return false;
    }

    pub fn count(self: *const PeerSet) usize {
        return self.peers.items.len;
    }

    pub fn isEmpty(self: *const PeerSet) bool {
        return self.peers.items.len == 0;
    }
};

/// BackwardsChain state machine.
pub const State = enum {
    /// Only a lone block root is known (from peer status, attestation, etc.).
    /// No headers fetched yet.
    unknown_head,

    /// Chain of headers is known, but the earliest ancestor's parent is
    /// still unknown. Transitions from unknown_head after first advance().
    unknown_ancestor,

    /// Chain is linked to a known block in fork choice (or before finalization).
    /// Headers have been reorganized into forward (oldest→newest) order.
    linked,
};

/// A chain of headers built backwards from an unknown head.
///
/// The chain starts with a lone unknown root (unknown_head), gets headers
/// appended backwards (unknown_ancestor), and eventually links to a known
/// block (linked). Once linked, the headers are reordered forwards so that
/// forward sync can process them oldest-first.
pub const BackwardsChain = struct {
    allocator: Allocator,

    /// Current state of the chain.
    state: State,

    /// The root that started this chain (the "head" we're chasing).
    head_root: [32]u8,

    /// The root of the earliest known ancestor — the next parent we need to fetch.
    /// In unknown_head state, this equals head_root.
    /// In unknown_ancestor state, this is the parent_root of the last header.
    /// In linked state, this is the linking root (in fork choice).
    ancestor_root: [32]u8,

    /// Headers stored in backwards order: newest (head) first, oldest last.
    /// After linking, reversed to forwards order (oldest first).
    headers: std.ArrayListUnmanaged(MinimalHeader),

    /// Peers that have referenced blocks in this chain.
    peers: PeerSet,

    /// Number of advance attempts (fetch requests made).
    attempts: u16,

    /// Monotonic creation sequence number (for eviction ordering).
    creation_seq: u64,

    /// Maximum number of headers before we consider this chain too long.
    const MAX_HEADERS: usize = 1024;

    /// Maximum number of fetch attempts before giving up.
    const MAX_ATTEMPTS: u16 = 50;

    /// Global monotonic counter for creation ordering.
    var next_seq: u64 = 0;

    /// Create a new chain in the unknown_head state from a single root.
    pub fn initFromRoot(allocator: Allocator, root: [32]u8) BackwardsChain {
        const seq = next_seq;
        next_seq +%= 1;
        return .{
            .allocator = allocator,
            .state = .unknown_head,
            .head_root = root,
            .ancestor_root = root,
            .headers = .empty,
            .peers = PeerSet.empty,
            .attempts = 0,
            .creation_seq = seq,
        };
    }

    pub fn deinit(self: *BackwardsChain) void {
        self.headers.deinit(self.allocator);
        self.peers.deinit(self.allocator);
    }

    /// Advance the chain backwards by one header.
    ///
    /// The header's root must match our current ancestor_root (the parent we
    /// were waiting for). After this call:
    /// - unknown_head → unknown_ancestor (first header received)
    /// - unknown_ancestor → unknown_ancestor (chain grows backwards)
    ///
    /// Returns error.RootMismatch if the header doesn't match what we expect.
    /// Returns error.ChainTooLong if we've exceeded MAX_HEADERS.
    pub fn advance(self: *BackwardsChain, header: MinimalHeader) !void {
        if (self.state == .linked) return error.AlreadyLinked;

        // The header's root must be the parent we're looking for.
        if (!std.mem.eql(u8, &header.root, &self.ancestor_root)) {
            return error.RootMismatch;
        }

        if (self.headers.items.len >= MAX_HEADERS) {
            return error.ChainTooLong;
        }

        // Append header (backwards: newest first, this is going further back).
        try self.headers.append(self.allocator, header);

        // Update ancestor to this header's parent.
        self.ancestor_root = header.parent_root;

        // Transition state.
        switch (self.state) {
            .unknown_head => self.state = .unknown_ancestor,
            .unknown_ancestor => {}, // stays unknown_ancestor
            .linked => unreachable,
        }
    }

    /// Mark this chain as linked to fork choice.
    ///
    /// Called when ancestor_root is found in fork choice (or is at/before
    /// finalization). Reverses headers to forward order (oldest first) so
    /// that forward sync can process them sequentially.
    ///
    /// `linking_slot` is the slot of the known block in fork choice that
    /// we've linked to (for logging/metrics).
    pub fn link(self: *BackwardsChain, linking_slot: u64) void {
        _ = linking_slot;
        self.state = .linked;

        // Reverse headers from backwards (head-first) to forwards (oldest-first).
        if (self.headers.items.len > 1) {
            std.mem.reverse(MinimalHeader, self.headers.items);
        }
    }

    /// Check if this chain is still relevant given the current finalized epoch.
    ///
    /// A chain is irrelevant if:
    /// - It has headers and the oldest one is at or before finalized_slot
    ///   (and we haven't linked it yet — it's on a finalized-away fork)
    /// - It has exceeded MAX_ATTEMPTS
    /// - It has no peers and has been around a while (stale)
    pub fn isRelevant(self: *const BackwardsChain, finalized_slot: u64) bool {
        // Too many attempts — give up.
        if (self.attempts >= MAX_ATTEMPTS) return false;

        // If linked, always relevant (waiting to be processed).
        if (self.state == .linked) return true;

        // If we have headers, check if the oldest is before finalization.
        if (self.headers.items.len > 0) {
            const oldest = self.headers.items[self.headers.items.len - 1];
            if (oldest.slot <= finalized_slot and finalized_slot > 0) {
                return false;
            }
        }

        return true;
    }

    /// Does this chain need advancement? (i.e., is there a parent to fetch?)
    pub fn needsAdvance(self: *const BackwardsChain) bool {
        return switch (self.state) {
            .unknown_head, .unknown_ancestor => true,
            .linked => false,
        };
    }

    /// Get the root that needs to be fetched next.
    pub fn nextNeededRoot(self: *const BackwardsChain) ?[32]u8 {
        return switch (self.state) {
            .unknown_head, .unknown_ancestor => self.ancestor_root,
            .linked => null,
        };
    }

    /// Increment the attempt counter.
    pub fn recordAttempt(self: *BackwardsChain) void {
        self.attempts +|= 1;
    }

    /// Get the number of headers in the chain.
    pub fn headerCount(self: *const BackwardsChain) usize {
        return self.headers.items.len;
    }

    /// Get the head slot (slot of the newest header, or 0 if unknown_head).
    pub fn headSlot(self: *const BackwardsChain) ?u64 {
        if (self.headers.items.len == 0) return null;
        return self.headers.items[0].slot;
    }

    /// Get the oldest known slot (slot of the earliest header).
    pub fn oldestSlot(self: *const BackwardsChain) ?u64 {
        if (self.headers.items.len == 0) return null;
        return self.headers.items[self.headers.items.len - 1].slot;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "BackwardsChain: init from root starts in unknown_head" {
    const alloc = std.testing.allocator;
    const root = [_]u8{0x01} ** 32;
    var chain = BackwardsChain.initFromRoot(alloc, root);
    defer chain.deinit();

    try std.testing.expectEqual(State.unknown_head, chain.state);
    try std.testing.expectEqualSlices(u8, &root, &chain.head_root);
    try std.testing.expectEqualSlices(u8, &root, &chain.ancestor_root);
    try std.testing.expectEqual(@as(usize, 0), chain.headerCount());
    try std.testing.expect(chain.needsAdvance());
}

test "BackwardsChain: advance transitions to unknown_ancestor" {
    const alloc = std.testing.allocator;
    const head_root = [_]u8{0x01} ** 32;
    const parent_root = [_]u8{0x02} ** 32;

    var chain = BackwardsChain.initFromRoot(alloc, head_root);
    defer chain.deinit();

    try chain.advance(.{
        .slot = 100,
        .root = head_root,
        .parent_root = parent_root,
    });

    try std.testing.expectEqual(State.unknown_ancestor, chain.state);
    try std.testing.expectEqual(@as(usize, 1), chain.headerCount());
    try std.testing.expectEqualSlices(u8, &parent_root, &chain.ancestor_root);
    try std.testing.expectEqual(@as(?u64, 100), chain.headSlot());
    try std.testing.expect(chain.needsAdvance());
}

test "BackwardsChain: multiple advances build chain backwards" {
    const alloc = std.testing.allocator;
    const root_a = [_]u8{0x0A} ** 32;
    const root_b = [_]u8{0x0B} ** 32;
    const root_c = [_]u8{0x0C} ** 32;
    const root_d = [_]u8{0x0D} ** 32; // unknown grandparent

    var chain = BackwardsChain.initFromRoot(alloc, root_a);
    defer chain.deinit();

    try chain.advance(.{ .slot = 103, .root = root_a, .parent_root = root_b });
    try chain.advance(.{ .slot = 102, .root = root_b, .parent_root = root_c });
    try chain.advance(.{ .slot = 101, .root = root_c, .parent_root = root_d });

    try std.testing.expectEqual(@as(usize, 3), chain.headerCount());
    try std.testing.expectEqual(State.unknown_ancestor, chain.state);
    try std.testing.expectEqualSlices(u8, &root_d, &chain.ancestor_root);
    try std.testing.expectEqual(@as(?u64, 103), chain.headSlot());
    try std.testing.expectEqual(@as(?u64, 101), chain.oldestSlot());
}

test "BackwardsChain: advance with wrong root fails" {
    const alloc = std.testing.allocator;
    const head_root = [_]u8{0x01} ** 32;
    const wrong_root = [_]u8{0xFF} ** 32;

    var chain = BackwardsChain.initFromRoot(alloc, head_root);
    defer chain.deinit();

    const result = chain.advance(.{
        .slot = 100,
        .root = wrong_root,
        .parent_root = [_]u8{0x02} ** 32,
    });
    try std.testing.expectError(error.RootMismatch, result);
}

test "BackwardsChain: link reverses to forward order" {
    const alloc = std.testing.allocator;
    const root_a = [_]u8{0x0A} ** 32; // slot 103 (head)
    const root_b = [_]u8{0x0B} ** 32; // slot 102
    const root_c = [_]u8{0x0C} ** 32; // slot 101 (oldest)
    const known_root = [_]u8{0x0D} ** 32; // in fork choice

    var chain = BackwardsChain.initFromRoot(alloc, root_a);
    defer chain.deinit();

    try chain.advance(.{ .slot = 103, .root = root_a, .parent_root = root_b });
    try chain.advance(.{ .slot = 102, .root = root_b, .parent_root = root_c });
    try chain.advance(.{ .slot = 101, .root = root_c, .parent_root = known_root });

    // Before link: backwards order (103, 102, 101).
    try std.testing.expectEqual(@as(u64, 103), chain.headers.items[0].slot);
    try std.testing.expectEqual(@as(u64, 101), chain.headers.items[2].slot);

    chain.link(100);

    try std.testing.expectEqual(State.linked, chain.state);
    try std.testing.expect(!chain.needsAdvance());

    // After link: forwards order (101, 102, 103).
    try std.testing.expectEqual(@as(u64, 101), chain.headers.items[0].slot);
    try std.testing.expectEqual(@as(u64, 102), chain.headers.items[1].slot);
    try std.testing.expectEqual(@as(u64, 103), chain.headers.items[2].slot);
}

test "BackwardsChain: isRelevant respects finalization" {
    const alloc = std.testing.allocator;
    const root = [_]u8{0x01} ** 32;
    const parent = [_]u8{0x02} ** 32;

    var chain = BackwardsChain.initFromRoot(alloc, root);
    defer chain.deinit();

    try chain.advance(.{ .slot = 50, .root = root, .parent_root = parent });

    // Finalized at slot 100 — chain's oldest header (slot 50) is behind it.
    try std.testing.expect(!chain.isRelevant(100));

    // Finalized at slot 30 — chain is still ahead.
    try std.testing.expect(chain.isRelevant(30));
}

test "BackwardsChain: isRelevant returns false after too many attempts" {
    const alloc = std.testing.allocator;
    const root = [_]u8{0x01} ** 32;

    var chain = BackwardsChain.initFromRoot(alloc, root);
    defer chain.deinit();

    // Exhaust attempts.
    chain.attempts = BackwardsChain.MAX_ATTEMPTS;
    try std.testing.expect(!chain.isRelevant(0));
}

test "BackwardsChain: linked chain is always relevant" {
    const alloc = std.testing.allocator;
    const root = [_]u8{0x01} ** 32;
    const parent = [_]u8{0x02} ** 32;

    var chain = BackwardsChain.initFromRoot(alloc, root);
    defer chain.deinit();

    try chain.advance(.{ .slot = 50, .root = root, .parent_root = parent });
    chain.link(49);

    // Even with finalization past the chain, linked is always relevant.
    try std.testing.expect(chain.isRelevant(100));
}

test "PeerSet: add, remove, dedup" {
    const alloc = std.testing.allocator;
    var peers = PeerSet.empty;
    defer peers.deinit(alloc);

    // Add first peer.
    try std.testing.expect(try peers.add(alloc, "peer-1"));
    try std.testing.expectEqual(@as(usize, 1), peers.count());

    // Duplicate is rejected.
    try std.testing.expect(!try peers.add(alloc, "peer-1"));
    try std.testing.expectEqual(@as(usize, 1), peers.count());

    // Add second peer.
    try std.testing.expect(try peers.add(alloc, "peer-2"));
    try std.testing.expectEqual(@as(usize, 2), peers.count());

    // Remove peer-1.
    try std.testing.expect(peers.remove("peer-1"));
    try std.testing.expectEqual(@as(usize, 1), peers.count());

    // Remove nonexistent.
    try std.testing.expect(!peers.remove("peer-3"));
}
