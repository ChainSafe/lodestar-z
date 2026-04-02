//! Peer database: manages the collection of known peers.
//!
//! Provides the storage layer for peer information with connection state
//! machine transitions, ban management, and query operations.
//!
//! Informed by Lighthouse's `PeerDB` and Lodestar's `PeersData`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const custody = @import("custody.zig");
const peer_info_mod = @import("peer_info.zig");
const PeerInfo = peer_info_mod.PeerInfo;
const ConnectionState = peer_info_mod.ConnectionState;
const ConnectionDirection = peer_info_mod.ConnectionDirection;
const SyncInfo = peer_info_mod.SyncInfo;
const SyncTarget = peer_info_mod.SyncTarget;
const PeerAction = peer_info_mod.PeerAction;
const BanDuration = peer_info_mod.BanDuration;
const ScoreState = peer_info_mod.ScoreState;
const ClientKind = peer_info_mod.ClientKind;
const AttnetsBitfield = peer_info_mod.AttnetsBitfield;
const SyncnetsBitfield = peer_info_mod.SyncnetsBitfield;
const ATTESTATION_SUBNET_COUNT = peer_info_mod.ATTESTATION_SUBNET_COUNT;
const SYNC_COMMITTEE_SUBNET_COUNT = peer_info_mod.SYNC_COMMITTEE_SUBNET_COUNT;
const RelevanceStatus = peer_info_mod.RelevanceStatus;

const log = std.log.scoped(.peer_db);

// ── PeerDB ──────────────────────────────────────────────────────────────────

/// Database of known peers.
///
/// Owns all PeerInfo entries and the peer_id string keys. All mutations go
/// through the PeerDB to maintain invariants (state machine, counters).
pub const PeerDB = struct {
    allocator: Allocator,
    /// Peer info keyed by peer_id (owned slices).
    peers: std.StringHashMap(PeerInfo),
    /// Count of currently connected peers.
    connected_count: u32 = 0,
    /// Count of connected inbound peers.
    inbound_count: u32 = 0,
    /// Count of connected outbound peers.
    outbound_count: u32 = 0,
    /// Count of currently banned peers.
    banned_count: u32 = 0,
    /// Count of peers in dialing state.
    dialing_count: u32 = 0,

    pub fn init(allocator: Allocator) PeerDB {
        return .{
            .allocator = allocator,
            .peers = std.StringHashMap(PeerInfo).init(allocator),
        };
    }

    pub fn deinit(self: *PeerDB) void {
        var it = self.peers.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.peers.deinit();
    }

    /// Total number of known peers (all states).
    pub fn totalCount(self: *const PeerDB) u32 {
        return @intCast(self.peers.count());
    }

    /// Number of connected peers.
    pub fn connectedPeerCount(self: *const PeerDB) u32 {
        return self.connected_count;
    }

    // ── Lookup ──────────────────────────────────────────────────────

    /// Get peer info (read-only). Returns null if peer is unknown.
    pub fn getPeer(self: *const PeerDB, peer_id: []const u8) ?*const PeerInfo {
        return self.peers.getPtr(peer_id);
    }

    /// Get mutable peer info. Returns null if peer is unknown.
    pub fn getPeerMut(self: *PeerDB, peer_id: []const u8) ?*PeerInfo {
        return self.peers.getPtr(peer_id);
    }

    /// Check if a peer is known.
    pub fn contains(self: *const PeerDB, peer_id: []const u8) bool {
        return self.peers.contains(peer_id);
    }

    /// Check if a peer is currently banned.
    pub fn isBanned(self: *const PeerDB, peer_id: []const u8) bool {
        const info = self.peers.getPtr(peer_id) orelse return false;
        return info.connection_state == .banned;
    }

    // ── State transitions ───────────────────────────────────────────

    /// Register a new outbound dial attempt.
    /// Creates the peer entry if it doesn't exist.
    pub fn dialingPeer(self: *PeerDB, peer_id: []const u8, now_ms: u64) !void {
        const result = try self.peers.getOrPut(peer_id);
        if (!result.found_existing) {
            const owned_id = try self.allocator.dupe(u8, peer_id);
            result.key_ptr.* = owned_id;
            result.value_ptr.* = PeerInfo{};
        }
        const info = result.value_ptr;

        // Valid transitions: disconnected → dialing.
        // If already dialing/connected, skip.
        if (info.connection_state == .disconnected) {
            info.connection_state = .dialing;
            info.direction = .outbound;
            info.last_seen_ms = now_ms;
            self.dialing_count += 1;
        }
    }

    /// Transition a peer to connected state.
    /// Creates entry if needed (for inbound connections we haven't seen before).
    pub fn peerConnected(
        self: *PeerDB,
        peer_id: []const u8,
        direction: ConnectionDirection,
        now_ms: u64,
    ) !*PeerInfo {
        const result = try self.peers.getOrPut(peer_id);
        if (!result.found_existing) {
            const owned_id = try self.allocator.dupe(u8, peer_id);
            result.key_ptr.* = owned_id;
            result.value_ptr.* = PeerInfo{};
        }
        const info = result.value_ptr;

        // Decrement old state counter.
        switch (info.connection_state) {
            .dialing => {
                if (self.dialing_count > 0) self.dialing_count -= 1;
            },
            .banned => {
                if (self.banned_count > 0) self.banned_count -= 1;
            },
            .connected => {
                // Already connected — update direction if needed and return.
                return info;
            },
            .disconnected, .disconnecting => {},
        }

        info.connection_state = .connected;
        info.direction = direction;
        info.connected_at_ms = now_ms;
        info.last_seen_ms = now_ms;
        info.last_ping_response_ms = 0;
        info.last_status_exchange_ms = 0;
        info.peer_score.last_updated_ms = now_ms;

        self.connected_count += 1;
        switch (direction) {
            .inbound => self.inbound_count += 1,
            .outbound => self.outbound_count += 1,
        }

        return info;
    }

    /// Transition a peer to disconnecting state (graceful shutdown initiated).
    pub fn peerDisconnecting(self: *PeerDB, peer_id: []const u8) void {
        const info = self.peers.getPtr(peer_id) orelse return;
        if (info.connection_state != .connected) return;

        info.connection_state = .disconnecting;
        self.decrementConnected(info);
    }

    /// Transition a peer to disconnected state.
    pub fn peerDisconnected(self: *PeerDB, peer_id: []const u8, now_ms: u64) void {
        const info = self.peers.getPtr(peer_id) orelse return;
        switch (info.connection_state) {
            .connected => self.decrementConnected(info),
            .disconnecting => {},
            .dialing => {
                if (self.dialing_count > 0) self.dialing_count -= 1;
            },
            .banned, .disconnected => return,
        }
        info.connection_state = .disconnected;
        info.last_seen_ms = now_ms;
    }

    /// Ban a peer. Disconnects if currently connected.
    pub fn banPeer(
        self: *PeerDB,
        peer_id: []const u8,
        duration: BanDuration,
        now_ms: u64,
    ) !void {
        const result = try self.peers.getOrPut(peer_id);
        if (!result.found_existing) {
            const owned_id = try self.allocator.dupe(u8, peer_id);
            result.key_ptr.* = owned_id;
            result.value_ptr.* = PeerInfo{};
        }
        const info = result.value_ptr;

        // Decrement old state counter.
        switch (info.connection_state) {
            .connected => self.decrementConnected(info),
            .dialing => {
                if (self.dialing_count > 0) self.dialing_count -= 1;
            },
            .banned => {
                // Extend the ban.
                info.ban_expiry_ms = now_ms + duration.seconds() * 1000;
                return;
            },
            .disconnected, .disconnecting => {},
        }

        info.connection_state = .banned;
        info.ban_expiry_ms = now_ms + duration.seconds() * 1000;
        info.last_seen_ms = now_ms;
        self.banned_count += 1;
    }

    /// Unban a peer if the ban has expired.
    /// Returns true if the peer was unbanned.
    pub fn unbanIfExpired(self: *PeerDB, peer_id: []const u8, now_ms: u64) bool {
        const info = self.peers.getPtr(peer_id) orelse return false;
        if (info.connection_state != .banned) return false;
        if (now_ms < info.ban_expiry_ms) return false;

        info.connection_state = .disconnected;
        if (self.banned_count > 0) self.banned_count -= 1;
        return true;
    }

    // ── Updates ─────────────────────────────────────────────────────

    /// Update sync info from a Status message.
    pub fn updateSyncInfo(
        self: *PeerDB,
        peer_id: []const u8,
        sync_info: SyncInfo,
    ) void {
        const info = self.peers.getPtr(peer_id) orelse return;
        info.sync_info = sync_info;
    }

    /// Update agent version and parse client kind.
    pub fn updateAgentVersion(
        self: *PeerDB,
        peer_id: []const u8,
        agent_version: []const u8,
    ) !void {
        const info = self.peers.getPtr(peer_id) orelse return;
        // Free old agent_version if present.
        if (info.agent_version) |old| {
            self.allocator.free(old);
        }
        info.agent_version = try self.allocator.dupe(u8, agent_version);
        info.client_kind = ClientKind.fromAgentVersion(agent_version);
    }

    /// Update subnet subscriptions from metadata or ENR.
    pub fn updateSubnets(
        self: *PeerDB,
        peer_id: []const u8,
        attnets: AttnetsBitfield,
        syncnets: SyncnetsBitfield,
    ) void {
        const info = self.peers.getPtr(peer_id) orelse return;
        info.attnets = attnets;
        info.syncnets = syncnets;
    }

    /// Update the verified discovery node ID for a peer.
    pub fn updatePeerDiscoveryNodeId(
        self: *PeerDB,
        peer_id: []const u8,
        node_id: [32]u8,
    ) !void {
        const info = self.peers.getPtr(peer_id) orelse return;
        info.discovery_node_id = node_id;
        try self.recomputeCustodyColumns(info);
    }

    /// Update metadata sequence number and subnet subscriptions.
    pub fn updatePeerMetadata(
        self: *PeerDB,
        peer_id: []const u8,
        metadata_seq: u64,
        attnets: AttnetsBitfield,
        syncnets: SyncnetsBitfield,
        custody_group_count: ?u64,
    ) !void {
        const info = self.peers.getPtr(peer_id) orelse return;
        info.metadata_seq = metadata_seq;
        info.attnets = attnets;
        info.syncnets = syncnets;
        info.custody_group_count = custody_group_count;
        try self.recomputeCustodyColumns(info);
    }

    /// Record that the peer was observed responding successfully.
    pub fn notePeerSeen(self: *PeerDB, peer_id: []const u8, now_ms: u64) void {
        const info = self.peers.getPtr(peer_id) orelse return;
        info.last_seen_ms = now_ms;
    }

    /// Record a successful outbound ping response.
    pub fn markPingResponse(self: *PeerDB, peer_id: []const u8, now_ms: u64) void {
        const info = self.peers.getPtr(peer_id) orelse return;
        info.last_ping_response_ms = now_ms;
        info.last_seen_ms = now_ms;
    }

    /// Record a successful Status exchange.
    pub fn markStatusExchange(self: *PeerDB, peer_id: []const u8, now_ms: u64) void {
        const info = self.peers.getPtr(peer_id) orelse return;
        info.last_status_exchange_ms = now_ms;
        info.last_seen_ms = now_ms;
    }

    /// Update a peer's last received Status message fields.
    pub fn updatePeerStatus(
        self: *PeerDB,
        peer_id: []const u8,
        fork_digest: [4]u8,
        finalized_root: [32]u8,
        finalized_epoch: u64,
        head_slot: u64,
        head_root: [32]u8,
        earliest_available_slot: ?u64,
    ) void {
        const info = self.peers.getPtr(peer_id) orelse return;
        info.sync_info = .{
            .head_slot = head_slot,
            .head_root = head_root,
            .finalized_epoch = finalized_epoch,
            .finalized_root = finalized_root,
            .earliest_available_slot = earliest_available_slot,
        };
        info.last_status_fork_digest = fork_digest;
        info.last_status_finalized_root = finalized_root;
        info.last_status_finalized_epoch = finalized_epoch;
        info.last_status_head_slot = head_slot;
        info.last_status_earliest_available_slot = earliest_available_slot;
    }

    /// Update the relevance status of a peer.
    pub fn setRelevanceStatus(self: *PeerDB, peer_id: []const u8, status: RelevanceStatus) void {
        const info = self.peers.getPtr(peer_id) orelse return;
        info.relevance = status;
    }

    /// Apply a peer action (score penalty).
    /// Returns the resulting ScoreState — caller should act on it.
    pub fn applyPeerAction(
        self: *PeerDB,
        peer_id: []const u8,
        action: PeerAction,
        now_ms: u64,
    ) ?ScoreState {
        const info = self.peers.getPtr(peer_id) orelse return null;
        info.peer_score.applyAction(action, now_ms);
        return info.peer_score.state();
    }

    /// Decay all peer scores. Called periodically.
    pub fn decayAllScores(self: *PeerDB, now_ms: u64) void {
        var it = self.peers.valueIterator();
        while (it.next()) |info| {
            info.peer_score.decayScore(now_ms);
        }
    }

    /// Mark a peer as trusted.
    pub fn setTrusted(self: *PeerDB, peer_id: []const u8) void {
        const info = self.peers.getPtr(peer_id) orelse return;
        info.is_trusted = true;
    }

    // ── Queries ─────────────────────────────────────────────────────

    /// Get all connected peers as a list of (peer_id, PeerInfo) pairs.
    /// Caller owns the returned slice.
    pub fn getConnectedPeers(self: *PeerDB) ![]ConnectedPeer {
        var result: std.ArrayListUnmanaged(ConnectedPeer) = .empty;
        errdefer result.deinit(self.allocator);

        var it = self.peers.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.connection_state == .connected) {
                try result.append(self.allocator, .{
                    .peer_id = entry.key_ptr.*,
                    .info = entry.value_ptr,
                });
            }
        }
        return result.toOwnedSlice(self.allocator);
    }

    /// Get connected peers on a specific attestation subnet.
    /// Caller owns the returned slice.
    pub fn getPeersOnSubnet(self: *PeerDB, subnet_id: u32) ![][]const u8 {
        var result: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer result.deinit(self.allocator);

        var it = self.peers.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.connection_state == .connected and
                entry.value_ptr.onAttestationSubnet(subnet_id))
            {
                try result.append(self.allocator, entry.key_ptr.*);
            }
        }
        return result.toOwnedSlice(self.allocator);
    }

    /// Count connected peers on each attestation subnet.
    /// Returns array indexed by subnet_id.
    pub fn getSubnetCoverage(self: *PeerDB) [ATTESTATION_SUBNET_COUNT]u32 {
        var coverage = [_]u32{0} ** ATTESTATION_SUBNET_COUNT;
        var it = self.peers.valueIterator();
        while (it.next()) |info| {
            if (info.connection_state != .connected) continue;
            var subnet: u32 = 0;
            while (subnet < ATTESTATION_SUBNET_COUNT) : (subnet += 1) {
                if (info.attnets.isSet(subnet)) {
                    coverage[subnet] += 1;
                }
            }
        }
        return coverage;
    }

    /// Count subnets that have at least `min_peers` connected peers.
    pub fn coveredSubnetCount(self: *PeerDB, min_peers: u32) u32 {
        const coverage = self.getSubnetCoverage();
        var count: u32 = 0;
        for (coverage) |c| {
            if (c >= min_peers) count += 1;
        }
        return count;
    }

    /// Get the highest head slot among connected peers.
    pub fn getHighestPeerSlot(self: *PeerDB) u64 {
        var max_slot: u64 = 0;
        var it = self.peers.valueIterator();
        while (it.next()) |info| {
            if (info.connection_state == .connected) {
                const slot = info.headSlot();
                if (slot > max_slot) max_slot = slot;
            }
        }
        return max_slot;
    }

    /// Get the best sync target (connected peer with highest head slot).
    pub fn getBestSyncTarget(self: *PeerDB) ?SyncTarget {
        var best: ?SyncTarget = null;
        var it = self.peers.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.connection_state != .connected) continue;
            const si = entry.value_ptr.sync_info orelse continue;
            if (best == null or si.head_slot > best.?.sync_info.head_slot) {
                best = .{ .peer_id = entry.key_ptr.*, .sync_info = si };
            }
        }
        return best;
    }

    /// Get up to `count` best peers sorted by head slot (descending).
    /// Caller owns the returned slice.
    pub fn getBestPeers(self: *PeerDB, count: u32) ![]ConnectedPeer {
        var connected: std.ArrayListUnmanaged(ConnectedPeer) = .empty;
        defer connected.deinit(self.allocator);

        var it = self.peers.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.connection_state == .connected and
                entry.value_ptr.sync_info != null)
            {
                try connected.append(self.allocator, .{
                    .peer_id = entry.key_ptr.*,
                    .info = entry.value_ptr,
                });
            }
        }

        const items = connected.items;
        // Sort descending by head slot.
        std.mem.sort(ConnectedPeer, items, {}, struct {
            fn cmp(_: void, a: ConnectedPeer, b: ConnectedPeer) bool {
                return a.info.headSlot() > b.info.headSlot();
            }
        }.cmp);

        const result_count = @min(count, @as(u32, @intCast(items.len)));
        const result = try self.allocator.alloc(ConnectedPeer, result_count);
        @memcpy(result, items[0..result_count]);
        return result;
    }

    /// Collect peer IDs of banned peers with expired bans.
    /// Caller owns the returned slice.
    pub fn getExpiredBans(self: *PeerDB, now_ms: u64) ![][]const u8 {
        var result: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer result.deinit(self.allocator);

        var it = self.peers.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.connection_state == .banned and
                now_ms >= entry.value_ptr.ban_expiry_ms)
            {
                try result.append(self.allocator, entry.key_ptr.*);
            }
        }
        return result.toOwnedSlice(self.allocator);
    }

    /// Collect connected peers that should be disconnected based on score.
    /// Caller owns the returned slice and each duplicated peer ID within it.
    pub fn getScoreDisconnectPeers(self: *PeerDB) ![][]const u8 {
        var result: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer {
            for (result.items) |pid| self.allocator.free(pid);
            result.deinit(self.allocator);
        }

        var it = self.peers.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.connection_state == .connected) {
                const state = entry.value_ptr.peer_score.state();
                if (state == .disconnected or state == .banned) {
                    const owned = try self.allocator.dupe(u8, entry.key_ptr.*);
                    try result.append(self.allocator, owned);
                }
            }
        }
        return result.toOwnedSlice(self.allocator);
    }

    /// Remove disconnected peers that have been unseen for longer than `stale_ms`.
    /// Does NOT remove banned or connected peers.
    pub fn pruneStale(self: *PeerDB, stale_ms: u64, now_ms: u64) u32 {
        var to_remove: std.ArrayListUnmanaged([]const u8) = .empty;
        defer to_remove.deinit(self.allocator);

        var it = self.peers.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.connection_state == .disconnected and
                !entry.value_ptr.is_trusted and
                now_ms > entry.value_ptr.last_seen_ms + stale_ms)
            {
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        var removed: u32 = 0;
        for (to_remove.items) |pid| {
            if (self.peers.fetchRemove(pid)) |kv| {
                var info = kv.value;
                info.deinit(self.allocator);
                self.allocator.free(kv.key);
                removed += 1;
            }
        }
        return removed;
    }

    // ── Internal helpers ────────────────────────────────────────────

    fn decrementConnected(self: *PeerDB, info: *const PeerInfo) void {
        if (self.connected_count > 0) self.connected_count -= 1;
        if (info.direction) |dir| {
            switch (dir) {
                .inbound => {
                    if (self.inbound_count > 0) self.inbound_count -= 1;
                },
                .outbound => {
                    if (self.outbound_count > 0) self.outbound_count -= 1;
                },
            }
        }
    }

    fn recomputeCustodyColumns(self: *PeerDB, info: *PeerInfo) !void {
        if (info.custody_columns) |cols| {
            self.allocator.free(cols);
            info.custody_columns = null;
        }

        const node_id = info.discovery_node_id orelse return;
        const custody_group_count = info.custody_group_count orelse return;
        info.custody_columns = try custody.getCustodyColumns(
            self.allocator,
            node_id,
            custody_group_count,
        );
    }
};

/// A connected peer with its ID and info reference.
pub const ConnectedPeer = struct {
    peer_id: []const u8,
    info: *PeerInfo,
};

// ── Tests ───────────────────────────────────────────────────────────────────

test "PeerDB: connect and disconnect lifecycle" {
    const allocator = std.testing.allocator;
    var db = PeerDB.init(allocator);
    defer db.deinit();

    // Connect inbound peer.
    const info = try db.peerConnected("peer_a", .inbound, 1000);
    try std.testing.expectEqual(ConnectionState.connected, info.connection_state);
    try std.testing.expectEqual(@as(u32, 1), db.connected_count);
    try std.testing.expectEqual(@as(u32, 1), db.inbound_count);
    try std.testing.expectEqual(@as(u32, 0), db.outbound_count);

    // Connect outbound peer.
    _ = try db.peerConnected("peer_b", .outbound, 1000);
    try std.testing.expectEqual(@as(u32, 2), db.connected_count);
    try std.testing.expectEqual(@as(u32, 1), db.outbound_count);

    // Disconnect peer_a.
    db.peerDisconnected("peer_a", 2000);
    try std.testing.expectEqual(@as(u32, 1), db.connected_count);
    try std.testing.expectEqual(@as(u32, 0), db.inbound_count);
}

test "PeerDB: dialing → connected transition" {
    const allocator = std.testing.allocator;
    var db = PeerDB.init(allocator);
    defer db.deinit();

    try db.dialingPeer("peer_a", 1000);
    try std.testing.expectEqual(@as(u32, 1), db.dialing_count);
    try std.testing.expectEqual(@as(u32, 0), db.connected_count);

    _ = try db.peerConnected("peer_a", .outbound, 2000);
    try std.testing.expectEqual(@as(u32, 0), db.dialing_count);
    try std.testing.expectEqual(@as(u32, 1), db.connected_count);
}

test "PeerDB: ban and unban" {
    const allocator = std.testing.allocator;
    var db = PeerDB.init(allocator);
    defer db.deinit();

    _ = try db.peerConnected("peer_a", .inbound, 1000);
    try std.testing.expectEqual(@as(u32, 1), db.connected_count);

    try db.banPeer("peer_a", .short, 2000);
    try std.testing.expectEqual(@as(u32, 0), db.connected_count);
    try std.testing.expectEqual(@as(u32, 1), db.banned_count);
    try std.testing.expect(db.isBanned("peer_a"));

    // Before expiry — should not unban.
    try std.testing.expect(!db.unbanIfExpired("peer_a", 10_000));

    // After expiry (30s = 30_000ms).
    try std.testing.expect(db.unbanIfExpired("peer_a", 35_000));
    try std.testing.expectEqual(@as(u32, 0), db.banned_count);
    try std.testing.expect(!db.isBanned("peer_a"));
}

test "PeerDB: apply peer action and score state" {
    const allocator = std.testing.allocator;
    var db = PeerDB.init(allocator);
    defer db.deinit();

    _ = try db.peerConnected("peer_a", .inbound, 1000);

    // Apply high_tolerance actions — many needed before disconnect.
    var i: u32 = 0;
    while (i < 15) : (i += 1) {
        _ = db.applyPeerAction("peer_a", .high_tolerance, 1000);
    }
    const info = db.getPeerMut("peer_a").?;
    try std.testing.expect(info.peer_score.lodestar_score < 0);
    try std.testing.expectEqual(ScoreState.healthy, info.peer_score.state());

    // Apply fatal action.
    const state = db.applyPeerAction("peer_a", .fatal, 1000);
    try std.testing.expectEqual(ScoreState.banned, state.?);
}

test "PeerDB: subnet coverage tracking" {
    const allocator = std.testing.allocator;
    var db = PeerDB.init(allocator);
    defer db.deinit();

    const info_a = try db.peerConnected("peer_a", .inbound, 1000);
    info_a.attnets.set(0);
    info_a.attnets.set(5);

    const info_b = try db.peerConnected("peer_b", .outbound, 1000);
    info_b.attnets.set(5);
    info_b.attnets.set(10);

    const coverage = db.getSubnetCoverage();
    try std.testing.expectEqual(@as(u32, 1), coverage[0]);
    try std.testing.expectEqual(@as(u32, 2), coverage[5]);
    try std.testing.expectEqual(@as(u32, 1), coverage[10]);
    try std.testing.expectEqual(@as(u32, 0), coverage[1]);

    // 3 subnets covered with at least 1 peer.
    try std.testing.expectEqual(@as(u32, 3), db.coveredSubnetCount(1));
    // 1 subnet covered with at least 2 peers.
    try std.testing.expectEqual(@as(u32, 1), db.coveredSubnetCount(2));
}

test "PeerDB: getPeersOnSubnet" {
    const allocator = std.testing.allocator;
    var db = PeerDB.init(allocator);
    defer db.deinit();

    const info_a = try db.peerConnected("peer_a", .inbound, 1000);
    info_a.attnets.set(5);
    _ = try db.peerConnected("peer_b", .outbound, 1000);
    // peer_b not on subnet 5.

    const on_5 = try db.getPeersOnSubnet(5);
    defer allocator.free(on_5);
    try std.testing.expectEqual(@as(usize, 1), on_5.len);
    try std.testing.expectEqualStrings("peer_a", on_5[0]);
}

test "PeerDB: getHighestPeerSlot and getBestSyncTarget" {
    const allocator = std.testing.allocator;
    var db = PeerDB.init(allocator);
    defer db.deinit();

    _ = try db.peerConnected("peer_a", .inbound, 1000);
    db.updateSyncInfo("peer_a", .{
        .head_slot = 100,
        .head_root = [_]u8{0xAA} ** 32,
        .finalized_epoch = 3,
        .finalized_root = [_]u8{0} ** 32,
    });

    _ = try db.peerConnected("peer_b", .outbound, 1000);
    db.updateSyncInfo("peer_b", .{
        .head_slot = 500,
        .head_root = [_]u8{0xBB} ** 32,
        .finalized_epoch = 15,
        .finalized_root = [_]u8{0} ** 32,
    });

    try std.testing.expectEqual(@as(u64, 500), db.getHighestPeerSlot());
    const target = db.getBestSyncTarget().?;
    try std.testing.expectEqual(@as(u64, 500), target.sync_info.head_slot);
    try std.testing.expectEqualStrings("peer_b", target.peer_id);
}

test "PeerDB: getBestPeers returns sorted" {
    const allocator = std.testing.allocator;
    var db = PeerDB.init(allocator);
    defer db.deinit();

    _ = try db.peerConnected("p1", .inbound, 1000);
    db.updateSyncInfo("p1", .{
        .head_slot = 100,
        .head_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .finalized_root = [_]u8{0} ** 32,
    });
    _ = try db.peerConnected("p2", .inbound, 1000);
    db.updateSyncInfo("p2", .{
        .head_slot = 300,
        .head_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .finalized_root = [_]u8{0} ** 32,
    });
    _ = try db.peerConnected("p3", .inbound, 1000);
    db.updateSyncInfo("p3", .{
        .head_slot = 200,
        .head_root = [_]u8{0} ** 32,
        .finalized_epoch = 0,
        .finalized_root = [_]u8{0} ** 32,
    });

    const best = try db.getBestPeers(2);
    defer allocator.free(best);
    try std.testing.expectEqual(@as(usize, 2), best.len);
    try std.testing.expectEqual(@as(u64, 300), best[0].info.headSlot());
    try std.testing.expectEqual(@as(u64, 200), best[1].info.headSlot());
}

test "PeerDB: expired bans collection" {
    const allocator = std.testing.allocator;
    var db = PeerDB.init(allocator);
    defer db.deinit();

    try db.banPeer("peer_a", .short, 1000); // expires at 31_000
    try db.banPeer("peer_b", .medium, 1000); // expires at 601_000

    const expired = try db.getExpiredBans(35_000);
    defer allocator.free(expired);
    try std.testing.expectEqual(@as(usize, 1), expired.len);
    try std.testing.expectEqualStrings("peer_a", expired[0]);
}

test "PeerDB: score-based disconnect collection" {
    const allocator = std.testing.allocator;
    var db = PeerDB.init(allocator);
    defer db.deinit();

    _ = try db.peerConnected("good_peer", .inbound, 1000);
    _ = try db.peerConnected("bad_peer", .inbound, 1000);

    // Make bad_peer's score warrant disconnect.
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        _ = db.applyPeerAction("bad_peer", .low_tolerance, 1000);
    }

    const to_disconnect = try db.getScoreDisconnectPeers();
    defer {
        for (to_disconnect) |peer_id| allocator.free(peer_id);
        allocator.free(to_disconnect);
    }
    try std.testing.expectEqual(@as(usize, 1), to_disconnect.len);
    try std.testing.expectEqualStrings("bad_peer", to_disconnect[0]);
}

test "PeerDB: update agent version" {
    const allocator = std.testing.allocator;
    var db = PeerDB.init(allocator);
    defer db.deinit();

    _ = try db.peerConnected("peer_a", .inbound, 1000);
    try db.updateAgentVersion("peer_a", "Lighthouse/v4.5.0");

    const info = db.getPeer("peer_a").?;
    try std.testing.expectEqual(ClientKind.lighthouse, info.client_kind);
    try std.testing.expectEqualStrings("Lighthouse/v4.5.0", info.agent_version.?);
}

test "PeerDB: prune stale disconnected peers" {
    const allocator = std.testing.allocator;
    var db = PeerDB.init(allocator);
    defer db.deinit();

    _ = try db.peerConnected("peer_a", .inbound, 1000);
    db.peerDisconnected("peer_a", 1000);

    _ = try db.peerConnected("peer_b", .inbound, 5000);
    // peer_b stays connected.

    // Prune peers unseen for 2000ms. peer_a (last_seen=1000) should be pruned at t=4000.
    const removed = db.pruneStale(2000, 4000);
    try std.testing.expectEqual(@as(u32, 1), removed);
    try std.testing.expect(!db.contains("peer_a"));
    try std.testing.expect(db.contains("peer_b"));
}

test "PeerDB: graceful disconnect flow" {
    const allocator = std.testing.allocator;
    var db = PeerDB.init(allocator);
    defer db.deinit();

    _ = try db.peerConnected("peer_a", .outbound, 1000);
    try std.testing.expectEqual(@as(u32, 1), db.connected_count);

    // Initiate graceful disconnect.
    db.peerDisconnecting("peer_a");
    try std.testing.expectEqual(@as(u32, 0), db.connected_count);
    try std.testing.expectEqual(ConnectionState.disconnecting, db.getPeer("peer_a").?.connection_state);

    // Complete disconnect.
    db.peerDisconnected("peer_a", 2000);
    try std.testing.expectEqual(ConnectionState.disconnected, db.getPeer("peer_a").?.connection_state);
}

test "PeerDB: derives custody columns from discovery identity and metadata" {
    const allocator = std.testing.allocator;
    var db = PeerDB.init(allocator);
    defer db.deinit();

    _ = try db.peerConnected("peer_a", .outbound, 1_000);

    const node_id = [_]u8{0x44} ** 32;
    try db.updatePeerDiscoveryNodeId("peer_a", node_id);
    try std.testing.expect(db.getPeer("peer_a").?.custody_columns == null);

    try db.updatePeerMetadata(
        "peer_a",
        1,
        AttnetsBitfield.initEmpty(),
        SyncnetsBitfield.initEmpty(),
        4,
    );

    const expected = try custody.getCustodyColumns(allocator, node_id, 4);
    defer allocator.free(expected);

    const peer = db.getPeer("peer_a").?;
    try std.testing.expect(peer.custody_columns != null);
    try std.testing.expectEqualSlices(u64, expected, peer.custody_columns.?);

    try db.updatePeerMetadata(
        "peer_a",
        2,
        AttnetsBitfield.initEmpty(),
        SyncnetsBitfield.initEmpty(),
        null,
    );
    try std.testing.expect(db.getPeer("peer_a").?.custody_columns == null);
}
