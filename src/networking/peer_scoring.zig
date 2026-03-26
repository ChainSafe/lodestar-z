//! Peer scoring foundations for gossipsub message validation.
//!
//! Tracks per-peer scores based on gossip validation outcomes:
//! - ACCEPT: small positive score (peer delivered valid messages).
//! - REJECT: significant negative score (peer sent invalid messages).
//! - IGNORE: small negative score (peer sent duplicates or irrelevant messages).
//!
//! Provides exponential score decay and a disconnect threshold to protect
//! the node from persistently misbehaving peers.
//!
//! This is a foundation for full GossipSub v1.1 scoring (not yet implemented).
//! Reference: https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md#peer-scoring

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const gossip_validation = @import("gossip_validation.zig");
const ValidationResult = gossip_validation.ValidationResult;

const log = std.log.scoped(.peer_scoring);

// ── Score parameters ────────────────────────────────────────────────────────

/// Score awarded for a valid (accepted) message.
const ACCEPT_WEIGHT: f64 = 0.5;

/// Score penalty for a rejected (invalid) message.
const REJECT_WEIGHT: f64 = -10.0;

/// Score penalty for an ignored (duplicate/irrelevant) message.
const IGNORE_WEIGHT: f64 = -0.5;

/// Exponential decay factor applied per slot (~12 seconds).
/// 0.95 means score retains 95% of its value each slot.
const DECAY_PER_SLOT: f64 = 0.95;

/// Score threshold below which a peer should be disconnected.
pub const DISCONNECT_THRESHOLD: f64 = -100.0;

/// Minimum score — clamp to prevent runaway negative scores.
const MIN_SCORE: f64 = -1000.0;

/// Maximum score — clamp to prevent unbounded positive accumulation.
const MAX_SCORE: f64 = 100.0;

// ── PeerScore ───────────────────────────────────────────────────────────────

/// Per-peer score state.
pub const PeerScore = struct {
    /// Current weighted score.
    score: f64,
    /// Total messages accepted.
    accept_count: u64,
    /// Total messages rejected.
    reject_count: u64,
    /// Total messages ignored.
    ignore_count: u64,
    /// Last slot at which decay was applied.
    last_decay_slot: u64,

    pub fn init() PeerScore {
        return .{
            .score = 0.0,
            .accept_count = 0,
            .reject_count = 0,
            .ignore_count = 0,
            .last_decay_slot = 0,
        };
    }
};

// ── PeerScorer ──────────────────────────────────────────────────────────────

/// Manages per-peer scoring based on gossip validation outcomes.
///
/// Thread safety: the caller must ensure exclusive access (e.g., call from
/// the gossip processing thread only, or hold a lock). This is the expected
/// usage pattern since gossip messages are processed sequentially.
pub const PeerScorer = struct {
    allocator: Allocator,
    /// Peer scores keyed by peer identifier.
    /// For now, uses a u64 peer id (compact numeric id from the transport layer).
    scores: std.AutoHashMap(u64, PeerScore),
    /// Current slot — updated externally via `updateSlot`.
    current_slot: u64,
    /// Stats: total messages scored across all peers.
    total_accept: u64,
    total_reject: u64,
    total_ignore: u64,

    pub fn init(allocator: Allocator) PeerScorer {
        return .{
            .allocator = allocator,
            .scores = std.AutoHashMap(u64, PeerScore).init(allocator),
            .current_slot = 0,
            .total_accept = 0,
            .total_reject = 0,
            .total_ignore = 0,
        };
    }

    pub fn deinit(self: *PeerScorer) void {
        self.scores.deinit();
    }

    /// Update the current slot. Triggers lazy decay on next access.
    pub fn updateSlot(self: *PeerScorer, slot: u64) void {
        self.current_slot = slot;
    }

    /// Record a validation outcome for the given peer.
    ///
    /// This is the primary entry point: called after each gossip message
    /// is validated. Updates the peer's score and counters.
    pub fn recordValidation(self: *PeerScorer, result: ValidationResult) void {
        // TODO: Wire peer_id from gossipsub message source.
        // For now, track aggregate stats only.
        switch (result) {
            .accept => self.total_accept += 1,
            .reject => self.total_reject += 1,
            .ignore => self.total_ignore += 1,
        }
    }

    /// Record a validation outcome for a specific peer.
    pub fn recordPeerValidation(self: *PeerScorer, peer_id: u64, result: ValidationResult) !void {
        const entry = try self.scores.getOrPut(peer_id);
        if (!entry.found_existing) {
            entry.value_ptr.* = PeerScore.init();
            entry.value_ptr.last_decay_slot = self.current_slot;
        }

        var peer = entry.value_ptr;

        // Apply decay since last update.
        self.applyDecay(peer);

        // Apply score delta.
        switch (result) {
            .accept => {
                peer.score += ACCEPT_WEIGHT;
                peer.accept_count += 1;
                self.total_accept += 1;
            },
            .reject => {
                peer.score += REJECT_WEIGHT;
                peer.reject_count += 1;
                self.total_reject += 1;
            },
            .ignore => {
                peer.score += IGNORE_WEIGHT;
                peer.ignore_count += 1;
                self.total_ignore += 1;
            },
        }

        // Clamp score to bounds.
        peer.score = @max(MIN_SCORE, @min(MAX_SCORE, peer.score));
    }

    /// Apply exponential decay to a peer's score based on elapsed slots.
    fn applyDecay(self: *PeerScorer, peer: *PeerScore) void {
        if (self.current_slot <= peer.last_decay_slot) return;

        const elapsed = self.current_slot - peer.last_decay_slot;
        // Apply DECAY_PER_SLOT^elapsed.
        // For small elapsed values, iterate. For large gaps, use pow.
        if (elapsed <= 32) {
            var i: u64 = 0;
            while (i < elapsed) : (i += 1) {
                peer.score *= DECAY_PER_SLOT;
            }
        } else {
            peer.score *= std.math.pow(f64, DECAY_PER_SLOT, @floatFromInt(elapsed));
        }

        peer.last_decay_slot = self.current_slot;
    }

    /// Get the score for a peer. Returns 0.0 if the peer is unknown.
    pub fn getScore(self: *PeerScorer, peer_id: u64) f64 {
        const peer = self.scores.getPtr(peer_id) orelse return 0.0;
        self.applyDecay(peer);
        return peer.score;
    }

    /// Check if a peer should be disconnected based on score threshold.
    pub fn shouldDisconnect(self: *PeerScorer, peer_id: u64) bool {
        return self.getScore(peer_id) < DISCONNECT_THRESHOLD;
    }

    /// Collect peer ids that should be disconnected.
    /// Caller owns the returned slice.
    pub fn getPeersToDisconnect(self: *PeerScorer) ![]u64 {
        var result: std.ArrayListUnmanaged(u64) = .empty;
        errdefer result.deinit(self.allocator);

        var it = self.scores.iterator();
        while (it.next()) |entry| {
            self.applyDecay(entry.value_ptr);
            if (entry.value_ptr.score < DISCONNECT_THRESHOLD) {
                try result.append(self.allocator, entry.key_ptr.*);
            }
        }
        return result.toOwnedSlice(self.allocator);
    }

    /// Remove a peer from the scorer (e.g., after disconnection).
    pub fn removePeer(self: *PeerScorer, peer_id: u64) void {
        _ = self.scores.remove(peer_id);
    }

    /// Number of tracked peers.
    pub fn peerCount(self: *const PeerScorer) usize {
        return self.scores.count();
    }
};

// ── Tests ───────────────────────────────────────────────────────────────────

test "PeerScore: init starts at zero" {
    const ps = PeerScore.init();
    try testing.expectEqual(@as(f64, 0.0), ps.score);
    try testing.expectEqual(@as(u64, 0), ps.accept_count);
    try testing.expectEqual(@as(u64, 0), ps.reject_count);
    try testing.expectEqual(@as(u64, 0), ps.ignore_count);
}

test "PeerScorer: accept increases score" {
    var scorer = PeerScorer.init(testing.allocator);
    defer scorer.deinit();

    try scorer.recordPeerValidation(1, .accept);
    const score = scorer.getScore(1);
    try testing.expect(score > 0.0);
    try testing.expectEqual(@as(u64, 1), scorer.total_accept);
}

test "PeerScorer: reject decreases score" {
    var scorer = PeerScorer.init(testing.allocator);
    defer scorer.deinit();

    try scorer.recordPeerValidation(1, .reject);
    const score = scorer.getScore(1);
    try testing.expect(score < 0.0);
    try testing.expectEqual(@as(u64, 1), scorer.total_reject);
}

test "PeerScorer: ignore slightly decreases score" {
    var scorer = PeerScorer.init(testing.allocator);
    defer scorer.deinit();

    try scorer.recordPeerValidation(1, .ignore);
    const score = scorer.getScore(1);
    try testing.expect(score < 0.0);
    try testing.expect(score > -1.0); // Small penalty.
}

test "PeerScorer: score decay over slots" {
    var scorer = PeerScorer.init(testing.allocator);
    defer scorer.deinit();

    // Give peer a large negative score.
    scorer.updateSlot(0);
    try scorer.recordPeerValidation(1, .reject); // -10.0

    const initial = scorer.getScore(1);

    // Advance by many slots.
    scorer.updateSlot(100);
    const decayed = scorer.getScore(1);

    // Score should have decayed toward zero.
    try testing.expect(@abs(decayed) < @abs(initial));
}

test "PeerScorer: disconnect threshold" {
    var scorer = PeerScorer.init(testing.allocator);
    defer scorer.deinit();

    // 11 rejections at -10.0 each = -110.0 > threshold of -100.
    var i: u64 = 0;
    while (i < 11) : (i += 1) {
        try scorer.recordPeerValidation(42, .reject);
    }

    try testing.expect(scorer.shouldDisconnect(42));
    try testing.expect(!scorer.shouldDisconnect(999)); // Unknown peer = 0.0.
}

test "PeerScorer: getPeersToDisconnect" {
    var scorer = PeerScorer.init(testing.allocator);
    defer scorer.deinit();

    // Peer 1: many rejections → below threshold.
    var i: u64 = 0;
    while (i < 11) : (i += 1) {
        try scorer.recordPeerValidation(1, .reject);
    }
    // Peer 2: some accepts → above threshold.
    try scorer.recordPeerValidation(2, .accept);

    const bad_peers = try scorer.getPeersToDisconnect();
    defer scorer.allocator.free(bad_peers);

    try testing.expectEqual(@as(usize, 1), bad_peers.len);
    try testing.expectEqual(@as(u64, 1), bad_peers[0]);
}

test "PeerScorer: removePeer" {
    var scorer = PeerScorer.init(testing.allocator);
    defer scorer.deinit();

    try scorer.recordPeerValidation(1, .accept);
    try testing.expectEqual(@as(usize, 1), scorer.peerCount());

    scorer.removePeer(1);
    try testing.expectEqual(@as(usize, 0), scorer.peerCount());
    try testing.expectEqual(@as(f64, 0.0), scorer.getScore(1));
}

test "PeerScorer: score clamping" {
    var scorer = PeerScorer.init(testing.allocator);
    defer scorer.deinit();

    // Accumulate many accepts — should clamp at MAX_SCORE.
    var i: u64 = 0;
    while (i < 1000) : (i += 1) {
        try scorer.recordPeerValidation(1, .accept);
    }
    try testing.expect(scorer.getScore(1) <= MAX_SCORE);

    // Accumulate many rejects — should clamp at MIN_SCORE.
    i = 0;
    while (i < 1000) : (i += 1) {
        try scorer.recordPeerValidation(2, .reject);
    }
    try testing.expect(scorer.getScore(2) >= MIN_SCORE);
}

test "PeerScorer: aggregate recordValidation" {
    var scorer = PeerScorer.init(testing.allocator);
    defer scorer.deinit();

    scorer.recordValidation(.accept);
    scorer.recordValidation(.reject);
    scorer.recordValidation(.ignore);

    try testing.expectEqual(@as(u64, 1), scorer.total_accept);
    try testing.expectEqual(@as(u64, 1), scorer.total_reject);
    try testing.expectEqual(@as(u64, 1), scorer.total_ignore);
}
