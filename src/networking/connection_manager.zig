//! Connection manager: tracks peer connections and enforces limits.
//!
//! Responsibilities:
//! - Track peer connection states (connecting, connected, disconnecting)
//! - Enforce maximum peer limit (from --target-peers)
//! - Prune excess peers (lowest-scored first via PeerScorer)
//! - Protect high-scoring peers from pruning
//! - Handle disconnection events → cleanup
//! - Track direct peers for guaranteed connectivity
//!
//! Reference: Lodestar packages/beacon-node/src/network/peers/peerManager.ts

const std = @import("std");
const Allocator = std.mem.Allocator;
const peer_scoring = @import("peer_scoring.zig");
const PeerScorer = peer_scoring.PeerScorer;

const log = std.log.scoped(.connection_manager);

// ── Constants ───────────────────────────────────────────────────────────────

/// Minimum peers to maintain before stopping pruning.
const MIN_PEERS: u32 = 10;

/// Score threshold above which peers are protected from pruning.
const PROTECTION_THRESHOLD: f64 = 50.0;

/// Maximum concurrent outbound dial attempts.
const MAX_DIAL_ATTEMPTS: u32 = 8;

/// High-water mark: start pruning when connected > target_peers * HIGH_WATER_FACTOR.
const HIGH_WATER_FACTOR: f64 = 1.1;

/// Low-water mark: stop discovering when connected > target_peers * LOW_WATER_FACTOR.
const LOW_WATER_FACTOR: f64 = 0.8;

// ── Connection State ────────────────────────────────────────────────────────

pub const ConnectionState = enum {
    /// Dial initiated, awaiting connection.
    connecting,
    /// Fully connected, handshake complete.
    connected,
    /// Graceful disconnect in progress.
    disconnecting,
    /// Disconnected, ready for cleanup.
    disconnected,
};

pub const ConnectionDirection = enum {
    inbound,
    outbound,
};

/// Metadata tracked per connected peer.
pub const PeerConnection = struct {
    /// Peer identifier (typically from libp2p).
    peer_id: []const u8,
    /// Current connection state.
    state: ConnectionState,
    /// Whether this is an inbound or outbound connection.
    direction: ConnectionDirection,
    /// Whether this is a direct peer (always connect, never prune).
    is_direct: bool,
    /// Timestamp when connection was established (unix ms).
    connected_at: i64,
    /// Last activity timestamp (unix ms).
    last_activity: i64,
};

// ── Connection Manager ──────────────────────────────────────────────────────

pub const ConnectionManagerConfig = struct {
    /// Maximum desired connected peers.
    target_peers: u32 = 50,
    /// Direct peers that should always be connected (multiaddr strings).
    direct_peers: []const []const u8 = &.{},
};

pub const ConnectionManager = struct {
    allocator: Allocator,
    config: ConnectionManagerConfig,

    /// Tracked peers keyed by peer_id (owned copies).
    peers: std.StringHashMap(PeerConnection),

    /// Peer scorer for prune decisions.
    scorer: PeerScorer,

    /// Next numeric peer ID (for scorer integration which uses u64 keys).
    next_peer_num: u64,
    /// Map peer_id string → numeric ID for scorer lookups.
    peer_id_to_num: std.StringHashMap(u64),

    /// Pending dial targets (peer_ids waiting to connect).
    pending_dials: std.StringHashMap(void),

    /// Stats.
    total_connections: u64,
    total_disconnections: u64,
    total_pruned: u64,

    pub fn init(allocator: Allocator, config: ConnectionManagerConfig) ConnectionManager {
        return .{
            .allocator = allocator,
            .config = config,
            .peers = std.StringHashMap(PeerConnection).init(allocator),
            .scorer = PeerScorer.init(allocator),
            .next_peer_num = 1,
            .peer_id_to_num = std.StringHashMap(u64).init(allocator),
            .pending_dials = std.StringHashMap(void).init(allocator),
            .total_connections = 0,
            .total_disconnections = 0,
            .total_pruned = 0,
        };
    }

    pub fn deinit(self: *ConnectionManager) void {
        // Free owned peer_id strings.
        var it = self.peers.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.peers.deinit();

        var id_it = self.peer_id_to_num.iterator();
        while (id_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.peer_id_to_num.deinit();

        var dial_it = self.pending_dials.iterator();
        while (dial_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.pending_dials.deinit();

        self.scorer.deinit();
    }

    // ── Connection Lifecycle ────────────────────────────────────────────

    /// Record that we're attempting to connect to a peer.
    pub fn onDialing(self: *ConnectionManager, peer_id: []const u8) !void {
        if (self.peers.contains(peer_id)) return; // Already tracked.
        if (self.pending_dials.contains(peer_id)) return; // Already dialing.

        const owned = try self.allocator.dupe(u8, peer_id);
        errdefer self.allocator.free(owned);
        try self.pending_dials.put(owned, {});
    }

    /// Record a successful connection.
    pub fn onConnected(
        self: *ConnectionManager,
        peer_id: []const u8,
        direction: ConnectionDirection,
        is_direct: bool,
    ) !void {
        // Remove from pending dials if present.
        if (self.pending_dials.fetchRemove(peer_id)) |kv| {
            self.allocator.free(kv.key);
        }

        // Update or insert.
        const result = try self.peers.getOrPut(peer_id);
        if (!result.found_existing) {
            const owned = try self.allocator.dupe(u8, peer_id);
            result.key_ptr.* = owned;
            result.value_ptr.* = .{
                .peer_id = owned,
                .state = .connected,
                .direction = direction,
                .is_direct = is_direct,
                .connected_at = 0, // TODO: use real timestamp
                .last_activity = 0,
            };

            // Assign numeric ID for scorer.
            const num = self.next_peer_num;
            self.next_peer_num += 1;
            const num_key = try self.allocator.dupe(u8, peer_id);
            try self.peer_id_to_num.put(num_key, num);
        } else {
            result.value_ptr.state = .connected;
        }

        self.total_connections += 1;
        log.info("Peer connected: {s} ({s}) total={d}", .{
            peer_id[0..@min(peer_id.len, 16)],
            @tagName(direction),
            self.connectedCount(),
        });
    }

    /// Record a peer disconnection.
    pub fn onDisconnected(self: *ConnectionManager, peer_id: []const u8) void {
        // Remove from pending dials.
        if (self.pending_dials.fetchRemove(peer_id)) |kv| {
            self.allocator.free(kv.key);
        }

        // Remove from peers.
        if (self.peers.fetchRemove(peer_id)) |kv| {
            self.allocator.free(kv.key);
            self.total_disconnections += 1;
        }

        // Remove from scorer.
        if (self.peer_id_to_num.fetchRemove(peer_id)) |kv| {
            self.scorer.removePeer(kv.value);
            self.allocator.free(kv.key);
        }
    }

    // ── Peer Queries ────────────────────────────────────────────────────

    /// Number of currently connected peers.
    pub fn connectedCount(self: *const ConnectionManager) u32 {
        var count: u32 = 0;
        var it = self.peers.valueIterator();
        while (it.next()) |v| {
            if (v.state == .connected) count += 1;
        }
        return count;
    }

    /// Total tracked peers (all states).
    pub fn totalTracked(self: *const ConnectionManager) usize {
        return self.peers.count();
    }

    /// Number of pending dial attempts.
    pub fn pendingDialCount(self: *const ConnectionManager) usize {
        return self.pending_dials.count();
    }

    /// Whether we need more peers.
    pub fn needsMorePeers(self: *const ConnectionManager) bool {
        const connected = self.connectedCount();
        const low_water: u32 = @intFromFloat(@as(f64, @floatFromInt(self.config.target_peers)) * LOW_WATER_FACTOR);
        return connected < low_water;
    }

    /// Whether we have too many peers and should prune.
    pub fn shouldPrune(self: *const ConnectionManager) bool {
        const connected = self.connectedCount();
        const high_water: u32 = @intFromFloat(@as(f64, @floatFromInt(self.config.target_peers)) * HIGH_WATER_FACTOR);
        return connected > high_water;
    }

    /// Check if a peer is currently connected.
    pub fn isConnected(self: *const ConnectionManager, peer_id: []const u8) bool {
        if (self.peers.get(peer_id)) |conn| {
            return conn.state == .connected;
        }
        return false;
    }

    /// Check if a peer is a direct peer.
    pub fn isDirectPeer(self: *const ConnectionManager, peer_id: []const u8) bool {
        if (self.peers.get(peer_id)) |conn| {
            return conn.is_direct;
        }
        return false;
    }

    // ── Pruning ─────────────────────────────────────────────────────────

    /// Get peer IDs that should be pruned (lowest-scored, non-protected).
    ///
    /// Returns up to `count` peer IDs to disconnect. Caller owns the slice.
    /// Protected peers (direct peers, high-scoring peers) are excluded.
    pub fn getPeersToPrune(self: *ConnectionManager, count: u32) ![][]const u8 {
        if (!self.shouldPrune()) return &.{};

        const connected = self.connectedCount();
        const excess = connected -| self.config.target_peers;
        const prune_count = @min(count, excess);
        if (prune_count == 0) return &.{};

        // Collect all connected, non-protected peers with their scores.
        const PeerWithScore = struct {
            peer_id: []const u8,
            score: f64,
        };

        var candidates: std.ArrayList(PeerWithScore) = .empty;
        defer candidates.deinit(self.allocator);

        var it = self.peers.iterator();
        while (it.next()) |entry| {
            const conn = entry.value_ptr;
            if (conn.state != .connected) continue;
            if (conn.is_direct) continue; // Never prune direct peers.

            const score = if (self.peer_id_to_num.get(entry.key_ptr.*)) |num|
                self.scorer.getScore(num)
            else
                0.0;

            // Protect high-scoring peers.
            if (score >= PROTECTION_THRESHOLD) continue;

            try candidates.append(self.allocator, .{
                .peer_id = entry.key_ptr.*,
                .score = score,
            });
        }

        // Sort by score ascending (lowest first = prune first).
        std.mem.sort(PeerWithScore, candidates.items, {}, struct {
            fn cmp(_: void, a: PeerWithScore, b: PeerWithScore) bool {
                return a.score < b.score;
            }
        }.cmp);

        const result_count = @min(prune_count, @as(u32, @intCast(candidates.items.len)));
        var result = try self.allocator.alloc([]const u8, result_count);
        for (0..result_count) |i| {
            result[i] = try self.allocator.dupe(u8, candidates.items[i].peer_id);
        }

        self.total_pruned += result_count;
        return result;
    }

    /// Free a slice returned by getPeersToPrune.
    pub fn freePruneList(self: *ConnectionManager, list: [][]const u8) void {
        for (list) |id| self.allocator.free(id);
        self.allocator.free(list);
    }

    // ── Scorer Integration ──────────────────────────────────────────────

    /// Get the peer's score.
    pub fn getPeerScore(self: *ConnectionManager, peer_id: []const u8) f64 {
        const num = self.peer_id_to_num.get(peer_id) orelse return 0.0;
        return self.scorer.getScore(num);
    }

    /// Update the scorer's slot clock.
    pub fn updateSlot(self: *ConnectionManager, slot: u64) void {
        self.scorer.updateSlot(slot);
    }

    // ── Stats ───────────────────────────────────────────────────────────

    pub const Stats = struct {
        connected: u32,
        total_tracked: usize,
        pending_dials: usize,
        total_connections: u64,
        total_disconnections: u64,
        total_pruned: u64,
        target_peers: u32,
    };

    pub fn getStats(self: *const ConnectionManager) Stats {
        return .{
            .connected = self.connectedCount(),
            .total_tracked = self.totalTracked(),
            .pending_dials = self.pendingDialCount(),
            .total_connections = self.total_connections,
            .total_disconnections = self.total_disconnections,
            .total_pruned = self.total_pruned,
            .target_peers = self.config.target_peers,
        };
    }
};

// ── Tests ───────────────────────────────────────────────────────────────────

test "ConnectionManager: init and deinit" {
    var cm = ConnectionManager.init(std.testing.allocator, .{});
    defer cm.deinit();
    try std.testing.expectEqual(@as(u32, 0), cm.connectedCount());
}

test "ConnectionManager: connect and disconnect" {
    var cm = ConnectionManager.init(std.testing.allocator, .{});
    defer cm.deinit();

    try cm.onConnected("peer_a", .outbound, false);
    try std.testing.expectEqual(@as(u32, 1), cm.connectedCount());
    try std.testing.expect(cm.isConnected("peer_a"));

    try cm.onConnected("peer_b", .inbound, false);
    try std.testing.expectEqual(@as(u32, 2), cm.connectedCount());

    cm.onDisconnected("peer_a");
    try std.testing.expectEqual(@as(u32, 1), cm.connectedCount());
    try std.testing.expect(!cm.isConnected("peer_a"));
    try std.testing.expect(cm.isConnected("peer_b"));
}

test "ConnectionManager: direct peers" {
    var cm = ConnectionManager.init(std.testing.allocator, .{});
    defer cm.deinit();

    try cm.onConnected("direct_peer", .outbound, true);
    try std.testing.expect(cm.isDirectPeer("direct_peer"));
    try std.testing.expect(!cm.isDirectPeer("unknown"));
}

test "ConnectionManager: needsMorePeers and shouldPrune" {
    var cm = ConnectionManager.init(std.testing.allocator, .{ .target_peers = 10 });
    defer cm.deinit();

    // With 0 peers, we need more.
    try std.testing.expect(cm.needsMorePeers());
    try std.testing.expect(!cm.shouldPrune());

    // Add peers up to target.
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        var buf: [16]u8 = undefined;
        const id = std.fmt.bufPrint(&buf, "peer_{d}", .{i}) catch continue;
        try cm.onConnected(id, .outbound, false);
    }
    try std.testing.expect(!cm.needsMorePeers());

    // Add excess peers.
    try cm.onConnected("excess_1", .inbound, false);
    try cm.onConnected("excess_2", .inbound, false);
    try std.testing.expect(cm.shouldPrune());
}

test "ConnectionManager: getPeersToPrune excludes direct peers" {
    var cm = ConnectionManager.init(std.testing.allocator, .{ .target_peers = 2 });
    defer cm.deinit();

    try cm.onConnected("direct_a", .outbound, true);
    try cm.onConnected("regular_b", .outbound, false);
    try cm.onConnected("regular_c", .outbound, false);
    try cm.onConnected("regular_d", .outbound, false);

    const to_prune = try cm.getPeersToPrune(5);
    defer cm.freePruneList(to_prune);

    // Should not include direct_a.
    for (to_prune) |id| {
        try std.testing.expect(!std.mem.eql(u8, id, "direct_a"));
    }
}

test "ConnectionManager: onDialing tracks pending" {
    var cm = ConnectionManager.init(std.testing.allocator, .{});
    defer cm.deinit();

    try cm.onDialing("peer_x");
    try std.testing.expectEqual(@as(usize, 1), cm.pendingDialCount());

    // Connecting should clear pending.
    try cm.onConnected("peer_x", .outbound, false);
    try std.testing.expectEqual(@as(usize, 0), cm.pendingDialCount());
}

test "ConnectionManager: getStats" {
    var cm = ConnectionManager.init(std.testing.allocator, .{ .target_peers = 50 });
    defer cm.deinit();

    try cm.onConnected("p1", .outbound, false);
    try cm.onConnected("p2", .inbound, false);
    cm.onDisconnected("p1");

    const stats = cm.getStats();
    try std.testing.expectEqual(@as(u32, 1), stats.connected);
    try std.testing.expectEqual(@as(u64, 2), stats.total_connections);
    try std.testing.expectEqual(@as(u64, 1), stats.total_disconnections);
    try std.testing.expectEqual(@as(u32, 50), stats.target_peers);
}
