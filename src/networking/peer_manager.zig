//! Peer manager: orchestrates peer lifecycle, scoring, pruning, and discovery.
//!
//! The central coordinator for all peer-related concerns. Wraps PeerDB for
//! storage and provides the high-level API that the beacon node, sync, and
//! gossip subsystems interact with.
//!
//! Responsibilities:
//! - Accept/reject incoming connections (max peers, ban checks)
//! - Manage outbound connection decisions (who to dial, when)
//! - Periodic heartbeat: prune excess peers, unban expired bans, decay scores
//! - Peer selection for sync (best peers, subnet queries)
//! - Peer actions/penalties from gossip validation and RPC errors
//! - Subnet coverage tracking and discovery requests
//!
//! Informed by TS Lodestar's `PeerManager` and Lighthouse's `PeerManager`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const peer_info_mod = @import("peer_info.zig");
const PeerInfo = peer_info_mod.PeerInfo;
const ConnectionState = peer_info_mod.ConnectionState;
const ConnectionDirection = peer_info_mod.ConnectionDirection;
const SyncInfo = peer_info_mod.SyncInfo;
const SyncTarget = peer_info_mod.SyncTarget;
const PeerAction = peer_info_mod.PeerAction;
const ReportSource = peer_info_mod.ReportSource;
const BanDuration = peer_info_mod.BanDuration;
const ScoreState = peer_info_mod.ScoreState;
const GoodbyeReason = peer_info_mod.GoodbyeReason;
const AttnetsBitfield = peer_info_mod.AttnetsBitfield;
const SyncnetsBitfield = peer_info_mod.SyncnetsBitfield;
const ATTESTATION_SUBNET_COUNT = peer_info_mod.ATTESTATION_SUBNET_COUNT;
const SYNC_COMMITTEE_SUBNET_COUNT = peer_info_mod.SYNC_COMMITTEE_SUBNET_COUNT;

const peer_db_mod = @import("peer_db.zig");
const PeerDB = peer_db_mod.PeerDB;
const ConnectedPeer = peer_db_mod.ConnectedPeer;

const log = std.log.scoped(.peer_manager);

const peer_relevance = @import("peer_relevance.zig");
const assertPeerRelevance = peer_relevance.assertPeerRelevance;
const IrrelevantPeerCode = peer_relevance.IrrelevantPeerCode;

const peer_prioritization = @import("peer_prioritization.zig");
const ConnectedPeerView = peer_prioritization.ConnectedPeerView;
const PrioritizationResult = peer_prioritization.PrioritizationResult;
const SubnetQuery = peer_prioritization.SubnetQuery;
const PeerDisconnect = peer_prioritization.PeerDisconnect;
const DisconnectReason = peer_prioritization.DisconnectReason;

const status_cache = @import("status_cache.zig");
const CachedStatus = status_cache.CachedStatus;
const StatusCache = status_cache.StatusCache;

const subnet_service_mod = @import("subnet_service.zig");
const SubnetService = subnet_service_mod.SubnetService;
const SubnetId = subnet_service_mod.SubnetId;

const RelevanceStatus = peer_info_mod.RelevanceStatus;

// ── Constants ───────────────────────────────────────────────────────────────

/// Heartbeat interval in milliseconds (30 seconds).
pub const HEARTBEAT_INTERVAL_MS: u64 = 30_000;

/// Target number of peers desired per attestation subnet.
const TARGET_SUBNET_PEERS: u32 = 6;

/// Minimum number of sync committee peers to avoid pruning.
const MIN_SYNC_COMMITTEE_PEERS: u32 = 2;

/// Score threshold below which peers are candidates for pruning when at max peers.
const LOW_SCORE_PRUNE_THRESHOLD: f64 = -2.0;

/// Overshoot factor when deciding how many peers to discover.
/// Success rate of dials is low (~33%), so we request 3x what we need.
const DISCOVERY_OVERSHOOT_FACTOR: u32 = 3;

/// Minimum ratio of outbound peers to maintain.
const MIN_OUTBOUND_RATIO: f64 = 0.1;

/// Time (ms) after which a disconnected peer entry is considered stale and can be pruned.
const STALE_PEER_MS: u64 = 3600_000; // 1 hour

/// Maximum entries in the peer DB (including disconnected/banned).
const MAX_PEER_DB_SIZE: u32 = 1000;

// ── Configuration ───────────────────────────────────────────────────────────

/// Peer manager configuration.
pub const PeerManagerConfig = struct {
    /// Target number of connected peers.
    target_peers: u32 = 50,
    /// Hard maximum peers (allow some slack over target for subnet needs).
    max_peers: u32 = 55,
};

// ── Heartbeat result ────────────────────────────────────────────────────────

/// Actions requested by the heartbeat for the caller to execute.
/// The peer manager does not hold P2P handles — the caller (BeaconNode)
/// performs the actual network operations.
pub const HeartbeatActions = struct {
    /// Peer IDs to disconnect (score too low or excess peers).
    peers_to_disconnect: [][]const u8 = &.{},
    /// Peer IDs to ban (fatal action results).
    peers_to_ban: [][]const u8 = &.{},
    /// Number of additional peers to discover.
    peers_to_discover: u32 = 0,
    /// Subnets needing more peers (for targeted discovery).
    subnets_needing_peers: []u32 = &.{},

    pub fn deinit(self: *HeartbeatActions, allocator: Allocator) void {
        if (self.peers_to_disconnect.len > 0) allocator.free(self.peers_to_disconnect);
        if (self.peers_to_ban.len > 0) allocator.free(self.peers_to_ban);
        if (self.subnets_needing_peers.len > 0) allocator.free(self.subnets_needing_peers);
    }
};

// ── PeerManager ─────────────────────────────────────────────────────────────

/// The main peer manager.
///
/// Thread safety: single-threaded. The caller must ensure exclusive access
/// (expected pattern: called from the networking event loop only).
pub const PeerManager = struct {
    allocator: Allocator,
    config: PeerManagerConfig,
    db: PeerDB,

    pub fn init(allocator: Allocator, config: PeerManagerConfig) PeerManager {
        return .{
            .allocator = allocator,
            .config = config,
            .db = PeerDB.init(allocator),
        };
    }

    pub fn deinit(self: *PeerManager) void {
        self.db.deinit();
    }

    // ── Connection events ───────────────────────────────────────────

    /// Called when a new peer connects (inbound or outbound).
    ///
    /// Returns the PeerInfo for further updates (status, metadata).
    /// Returns null if the connection is rejected (banned, at max peers).
    pub fn onPeerConnected(
        self: *PeerManager,
        peer_id: []const u8,
        direction: ConnectionDirection,
        now_ms: u64,
    ) !?*PeerInfo {
        // Reject banned peers.
        if (self.db.isBanned(peer_id)) {
            log.debug("Rejecting banned peer {s}", .{peer_id});
            return null;
        }

        // Accept even if at max peers — the heartbeat will prune.
        // This follows Lodestar's pattern: accept first, prune later.
        const info = try self.db.peerConnected(peer_id, direction, now_ms);

        log.debug("Peer connected {s} direction={s} total={d}", .{
            peer_id,
            @tagName(direction),
            self.db.connected_count,
        });

        return info;
    }

    /// Called when a peer disconnects.
    pub fn onPeerDisconnected(self: *PeerManager, peer_id: []const u8, now_ms: u64) void {
        self.db.peerDisconnected(peer_id, now_ms);
        log.debug("Peer disconnected {s} total={d}", .{
            peer_id,
            self.db.connected_count,
        });
    }

    /// Called when we initiate a dial to a peer.
    pub fn onDialing(self: *PeerManager, peer_id: []const u8, now_ms: u64) !void {
        try self.db.dialingPeer(peer_id, now_ms);
    }

    // ── Status / metadata updates ───────────────────────────────────

    /// Update peer sync status from a Status handshake.
    pub fn updatePeerStatus(
        self: *PeerManager,
        peer_id: []const u8,
        head_slot: u64,
        head_root: [32]u8,
        finalized_epoch: u64,
        finalized_root: [32]u8,
    ) void {
        self.db.updateSyncInfo(peer_id, .{
            .head_slot = head_slot,
            .head_root = head_root,
            .finalized_epoch = finalized_epoch,
            .finalized_root = finalized_root,
        });
    }

    /// Update peer agent version from Identify protocol.
    pub fn updateAgentVersion(
        self: *PeerManager,
        peer_id: []const u8,
        agent_version: []const u8,
    ) !void {
        try self.db.updateAgentVersion(peer_id, agent_version);
    }

    /// Update peer subnet subscriptions from Metadata response or ENR.
    pub fn updateSubnets(
        self: *PeerManager,
        peer_id: []const u8,
        attnets: AttnetsBitfield,
        syncnets: SyncnetsBitfield,
    ) void {
        self.db.updateSubnets(peer_id, attnets, syncnets);
    }

    // ── Peer actions ────────────────────────────────────────────────

    /// Report a peer action (penalty or fatal error).
    ///
    /// Returns the resulting score state. The caller should:
    /// - .banned → disconnect + ban the peer
    /// - .disconnected → disconnect the peer
    /// - .healthy → no action needed
    pub fn reportPeer(
        self: *PeerManager,
        peer_id: []const u8,
        action: PeerAction,
        source: ReportSource,
        now_ms: u64,
    ) ?ScoreState {
        log.debug("Peer action {s}: {s} from {s}", .{
            peer_id,
            @tagName(action),
            @tagName(source),
        });

        const state = self.db.applyPeerAction(peer_id, action, now_ms) orelse return null;

        // Auto-ban on fatal.
        if (action == .fatal) {
            self.db.banPeer(peer_id, .long, now_ms) catch {};
        }

        return state;
    }

    /// Ban a peer directly (e.g., irrelevant network detected).
    pub fn banPeer(
        self: *PeerManager,
        peer_id: []const u8,
        duration: BanDuration,
        now_ms: u64,
    ) !void {
        try self.db.banPeer(peer_id, duration, now_ms);
        log.info("Peer banned {s} duration={d}s", .{
            peer_id,
            duration.seconds(),
        });
    }


    // ── Relevance check ─────────────────────────────────────────────

    /// Check a peer's relevance after a Status exchange.
    ///
    /// Returns the irrelevance code if the peer is on a different chain,
    /// or null if the peer is relevant. The caller should disconnect
    /// irrelevant peers with Goodbye(IRRELEVANT_NETWORK).
    pub fn checkPeerRelevance(
        self: *PeerManager,
        peer_id: []const u8,
        remote_fork_digest: [4]u8,
        remote_finalized_root: [32]u8,
        remote_finalized_epoch: u64,
        remote_head_slot: u64,
        local_status: CachedStatus,
        current_slot: u64,
    ) ?IrrelevantPeerCode {
        const irrelevance = assertPeerRelevance(
            remote_fork_digest,
            remote_finalized_root,
            remote_finalized_epoch,
            remote_head_slot,
            local_status,
            current_slot,
        );

        if (irrelevance) |info| {
            self.db.setRelevanceStatus(peer_id, .irrelevant);
            log.info("Peer irrelevant {s}: {s}", .{
                peer_id,
                @tagName(info.code()),
            });
            return info.code();
        } else {
            self.db.setRelevanceStatus(peer_id, .relevant);
            return null;
        }
    }

    /// Update peer status from a Status handshake AND check relevance.
    /// Returns the irrelevance code if the peer should be disconnected.
    pub fn onPeerStatus(
        self: *PeerManager,
        peer_id: []const u8,
        fork_digest: [4]u8,
        finalized_root: [32]u8,
        finalized_epoch: u64,
        head_root: [32]u8,
        head_slot: u64,
        local_status: CachedStatus,
        current_slot: u64,
    ) ?IrrelevantPeerCode {
        // Update the peer's stored status.
        self.db.updatePeerStatus(
            peer_id,
            fork_digest,
            finalized_root,
            finalized_epoch,
            head_slot,
            head_root,
        );

        // Check relevance.
        return self.checkPeerRelevance(
            peer_id,
            fork_digest,
            finalized_root,
            finalized_epoch,
            head_slot,
            local_status,
            current_slot,
        );
    }

    // ── Prioritization ──────────────────────────────────────────────

    /// Run subnet-aware peer prioritization.
    ///
    /// Returns the prioritization result with peers to disconnect,
    /// discovery count, and subnet queries. Caller owns the result.
    pub fn runPrioritization(
        self: *PeerManager,
        active_attnets: []const SubnetId,
        active_syncnets: []const SubnetId,
    ) !PrioritizationResult {
        // Build the peer snapshot for prioritization.
        const all_connected = try self.db.getConnectedPeers();
        defer self.allocator.free(all_connected);

        var views = try self.allocator.alloc(ConnectedPeerView, all_connected.len);
        defer self.allocator.free(views);

        for (all_connected, 0..) |cp, i| {
            views[i] = .{
                .peer_id = cp.peer_id,
                .direction = cp.info.direction,
                .attnets = cp.info.attnets,
                .syncnets = cp.info.syncnets,
                .score = cp.info.score(),
                .is_trusted = cp.info.is_trusted,
            };
        }

        return peer_prioritization.prioritizePeers(
            self.allocator,
            views,
            active_attnets,
            active_syncnets,
            .{
                .target_peers = self.config.target_peers,
                .max_peers = self.config.max_peers,
            },
        );
    }

    // ── Queries (sync integration) ──────────────────────────────────

    /// Number of connected peers.
    pub fn peerCount(self: *const PeerManager) u32 {
        return self.db.connected_count;
    }

    /// Get peer info (read-only).
    pub fn getPeer(self: *const PeerManager, peer_id: []const u8) ?*const PeerInfo {
        return self.db.getPeer(peer_id);
    }

    /// Highest head slot among connected peers.
    pub fn getHighestPeerSlot(self: *PeerManager) u64 {
        return self.db.getHighestPeerSlot();
    }

    /// Best sync target (connected peer with highest head slot).
    pub fn getSyncTarget(self: *PeerManager) ?SyncTarget {
        return self.db.getBestSyncTarget();
    }

    /// Get up to `count` best peers for sync (sorted by head slot descending).
    /// Caller owns the returned slice.
    pub fn getBestPeers(self: *PeerManager, count: u32) ![]ConnectedPeer {
        return self.db.getBestPeers(count);
    }

    /// Get peers on a specific attestation subnet.
    /// Caller owns the returned slice.
    pub fn getPeersOnSubnet(self: *PeerManager, subnet_id: u32) ![][]const u8 {
        return self.db.getPeersOnSubnet(subnet_id);
    }

    /// Get subnet coverage: count of peers per attestation subnet.
    pub fn getSubnetCoverage(self: *PeerManager) [ATTESTATION_SUBNET_COUNT]u32 {
        return self.db.getSubnetCoverage();
    }

    /// Is a specific peer banned?
    pub fn isBanned(self: *const PeerManager, peer_id: []const u8) bool {
        return self.db.isBanned(peer_id);
    }

    // ── Heartbeat ───────────────────────────────────────────────────

    /// Periodic maintenance tick. Should be called every HEARTBEAT_INTERVAL_MS.
    ///
    /// Returns actions for the caller to execute (disconnect, ban, discover).
    /// Caller owns the returned HeartbeatActions and must call deinit().
    pub fn heartbeat(self: *PeerManager, now_ms: u64) !HeartbeatActions {
        var actions = HeartbeatActions{};
        errdefer actions.deinit(self.allocator);

        // 1. Decay all scores.
        self.db.decayAllScores(now_ms);

        // 2. Unban expired bans.
        const expired = try self.db.getExpiredBans(now_ms);
        defer self.allocator.free(expired);
        for (expired) |pid| {
            _ = self.db.unbanIfExpired(pid, now_ms);
            log.debug("Unbanned expired peer {s}", .{pid});
        }

        // 3. Collect peers to disconnect (score below threshold).
        const score_disconnects = try self.db.getScoreDisconnectPeers();
        // Will be freed by caller via HeartbeatActions.deinit().

        // 4. Prune excess peers if above target.
        const prune_disconnects = try self.pruneExcessPeers();

        // Merge disconnect lists.
        actions.peers_to_disconnect = try self.mergeSlices(score_disconnects, prune_disconnects);
        if (score_disconnects.len > 0) self.allocator.free(score_disconnects);
        if (prune_disconnects.len > 0) self.allocator.free(prune_disconnects);

        // 5. Determine discovery needs.
        if (self.db.connected_count < self.config.target_peers) {
            const deficit = self.config.target_peers - self.db.connected_count;
            actions.peers_to_discover = @min(
                deficit * DISCOVERY_OVERSHOOT_FACTOR,
                self.config.max_peers -| self.db.connected_count,
            );
        }

        // 6. Find subnets needing more peers.
        actions.subnets_needing_peers = try self.getSubnetsNeedingPeers();

        // 7. Prune stale disconnected peer entries from DB.
        _ = self.db.pruneStale(STALE_PEER_MS, now_ms);

        // 8. Log summary.
        log.info("Heartbeat: connected={d} inbound={d} outbound={d} banned={d} " ++
            "to_disconnect={d} to_discover={d} subnets_uncovered={d}", .{
            self.db.connected_count,
            self.db.inbound_count,
            self.db.outbound_count,
            self.db.banned_count,
            actions.peers_to_disconnect.len,
            actions.peers_to_discover,
            actions.subnets_needing_peers.len,
        });

        return actions;
    }

    // ── Pruning ─────────────────────────────────────────────────────

    /// Select excess connected peers for disconnection when above target.
    ///
    /// Pruning priority (disconnect first):
    /// 1. Peers with low scores
    /// 2. Peers providing duplicate subnet coverage
    /// 3. Inbound peers over outbound
    /// Never prune: trusted peers, peers providing unique subnet coverage.
    fn pruneExcessPeers(self: *PeerManager) ![][]const u8 {
        const connected = self.db.connected_count;
        if (connected <= self.config.target_peers) return &.{};

        const excess = connected - self.config.target_peers;
        const all_connected = try self.db.getConnectedPeers();
        defer self.allocator.free(all_connected);

        // Score each peer for pruning. Lower score = more likely to be pruned.
        const PruneCandidate = struct {
            peer_id: []const u8,
            prune_score: f64,
        };

        var candidates: std.ArrayListUnmanaged(PruneCandidate) = .empty;
        defer candidates.deinit(self.allocator);

        const coverage = self.db.getSubnetCoverage();

        for (all_connected) |cp| {
            // Never prune trusted peers.
            if (cp.info.is_trusted) continue;

            var prune_score: f64 = 0;

            // Factor 1: peer's actual score (lower = more prunable).
            prune_score += cp.info.score();

            // Factor 2: direction preference (inbound more prunable).
            if (cp.info.direction) |dir| {
                if (dir == .inbound) prune_score -= 5.0;
            }

            // Factor 3: unique subnet coverage (less prunable if unique).
            var has_unique_subnet = false;
            var subnet: u32 = 0;
            while (subnet < ATTESTATION_SUBNET_COUNT) : (subnet += 1) {
                if (cp.info.attnets.isSet(subnet) and coverage[subnet] <= 1) {
                    has_unique_subnet = true;
                    break;
                }
            }
            if (has_unique_subnet) prune_score += 100.0; // Strongly protect unique coverage.

            try candidates.append(self.allocator, .{
                .peer_id = cp.peer_id,
                .prune_score = prune_score,
            });
        }

        // Sort ascending by prune_score — lowest score first (most prunable).
        std.mem.sort(PruneCandidate, candidates.items, {}, struct {
            fn cmp(_: void, a: PruneCandidate, b: PruneCandidate) bool {
                return a.prune_score < b.prune_score;
            }
        }.cmp);

        const prune_count = @min(@as(u32, @intCast(candidates.items.len)), excess);
        var result = try self.allocator.alloc([]const u8, prune_count);

        var i: u32 = 0;
        while (i < prune_count) : (i += 1) {
            result[i] = candidates.items[i].peer_id;
        }

        return result;
    }

    /// Find attestation subnets that need more peers.
    fn getSubnetsNeedingPeers(self: *PeerManager) ![]u32 {
        const coverage = self.db.getSubnetCoverage();
        var needed: std.ArrayListUnmanaged(u32) = .empty;
        errdefer needed.deinit(self.allocator);

        var subnet: u32 = 0;
        while (subnet < ATTESTATION_SUBNET_COUNT) : (subnet += 1) {
            if (coverage[subnet] < TARGET_SUBNET_PEERS) {
                try needed.append(self.allocator, subnet);
            }
        }
        return needed.toOwnedSlice(self.allocator);
    }

    /// Merge two peer ID slices into one. Caller frees the originals.
    fn mergeSlices(self: *PeerManager, a: [][]const u8, b: [][]const u8) ![][]const u8 {
        if (a.len == 0 and b.len == 0) return &.{};
        if (a.len == 0) {
            const result = try self.allocator.alloc([]const u8, b.len);
            @memcpy(result, b);
            return result;
        }
        if (b.len == 0) {
            const result = try self.allocator.alloc([]const u8, a.len);
            @memcpy(result, a);
            return result;
        }
        const result = try self.allocator.alloc([]const u8, a.len + b.len);
        @memcpy(result[0..a.len], a);
        @memcpy(result[a.len..], b);
        return result;
    }
};

// ── Tests ───────────────────────────────────────────────────────────────────

test "PeerManager: basic connect/disconnect lifecycle" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, .{ .target_peers = 5, .max_peers = 10 });
    defer pm.deinit();

    const info = try pm.onPeerConnected("peer_a", .inbound, 1000);
    try std.testing.expect(info != null);
    try std.testing.expectEqual(@as(u32, 1), pm.peerCount());

    pm.onPeerDisconnected("peer_a", 2000);
    try std.testing.expectEqual(@as(u32, 0), pm.peerCount());
}

test "PeerManager: reject banned peer" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, .{});
    defer pm.deinit();

    // Ban a peer first.
    try pm.banPeer("bad_peer", .medium, 1000);
    try std.testing.expect(pm.isBanned("bad_peer"));

    // Try to connect — should be rejected.
    const info = try pm.onPeerConnected("bad_peer", .inbound, 2000);
    try std.testing.expect(info == null);
}

test "PeerManager: report peer fatal → ban" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, .{});
    defer pm.deinit();

    _ = try pm.onPeerConnected("peer_a", .inbound, 1000);
    const state = pm.reportPeer("peer_a", .fatal, .rpc, 1000);
    try std.testing.expectEqual(ScoreState.banned, state.?);
    try std.testing.expect(pm.isBanned("peer_a"));
}

test "PeerManager: update status and get sync target" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, .{});
    defer pm.deinit();

    _ = try pm.onPeerConnected("peer_a", .outbound, 1000);
    pm.updatePeerStatus("peer_a", 500, [_]u8{0xAA} ** 32, 15, [_]u8{0} ** 32);

    try std.testing.expectEqual(@as(u64, 500), pm.getHighestPeerSlot());

    const target = pm.getSyncTarget().?;
    try std.testing.expectEqual(@as(u64, 500), target.sync_info.head_slot);
}

test "PeerManager: heartbeat discovers when below target" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, .{ .target_peers = 10, .max_peers = 15 });
    defer pm.deinit();

    // Add 3 peers (below target of 10).
    _ = try pm.onPeerConnected("p1", .inbound, 1000);
    _ = try pm.onPeerConnected("p2", .outbound, 1000);
    _ = try pm.onPeerConnected("p3", .inbound, 1000);

    var actions = try pm.heartbeat(2000);
    defer actions.deinit(allocator);

    // Should want to discover more peers.
    try std.testing.expect(actions.peers_to_discover > 0);
    // Deficit is 7, overshoot 3x = 21, but capped at max_peers - connected = 12.
    try std.testing.expectEqual(@as(u32, 12), actions.peers_to_discover);
}

test "PeerManager: heartbeat prunes excess peers" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, .{ .target_peers = 2, .max_peers = 3 });
    defer pm.deinit();

    // Add 4 peers (above target of 2).
    _ = try pm.onPeerConnected("p1", .inbound, 1000);
    _ = try pm.onPeerConnected("p2", .inbound, 1000);
    _ = try pm.onPeerConnected("p3", .inbound, 1000);
    _ = try pm.onPeerConnected("p4", .inbound, 1000);

    var actions = try pm.heartbeat(2000);
    defer actions.deinit(allocator);

    // Should want to disconnect 2 excess peers (4 - 2 = 2).
    try std.testing.expectEqual(@as(usize, 2), actions.peers_to_disconnect.len);
}

test "PeerManager: heartbeat unbans expired peers" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, .{});
    defer pm.deinit();

    try pm.banPeer("peer_a", .short, 1000); // 30s ban
    try std.testing.expect(pm.isBanned("peer_a"));

    // Heartbeat after ban expires.
    var actions = try pm.heartbeat(35_000);
    defer actions.deinit(allocator);

    try std.testing.expect(!pm.isBanned("peer_a"));
}

test "PeerManager: trusted peers not pruned" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, .{ .target_peers = 1, .max_peers = 2 });
    defer pm.deinit();

    _ = try pm.onPeerConnected("trusted", .outbound, 1000);
    pm.db.setTrusted("trusted");

    _ = try pm.onPeerConnected("untrusted1", .inbound, 1000);
    _ = try pm.onPeerConnected("untrusted2", .inbound, 1000);

    var actions = try pm.heartbeat(2000);
    defer actions.deinit(allocator);

    // 3 connected, target 1 → want to disconnect 2.
    // But trusted peer should NOT be in the disconnect list.
    for (actions.peers_to_disconnect) |pid| {
        try std.testing.expect(!std.mem.eql(u8, pid, "trusted"));
    }
}

test "PeerManager: subnet coverage query" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, .{});
    defer pm.deinit();

    const info = (try pm.onPeerConnected("peer_a", .inbound, 1000)).?;
    info.attnets.set(5);
    info.attnets.set(10);

    const on_5 = try pm.getPeersOnSubnet(5);
    defer allocator.free(on_5);
    try std.testing.expectEqual(@as(usize, 1), on_5.len);

    const coverage = pm.getSubnetCoverage();
    try std.testing.expectEqual(@as(u32, 1), coverage[5]);
    try std.testing.expectEqual(@as(u32, 1), coverage[10]);
    try std.testing.expectEqual(@as(u32, 0), coverage[0]);
}

test "PeerManager: unique subnet coverage protects peer from pruning" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, .{ .target_peers = 1, .max_peers = 2 });
    defer pm.deinit();

    // peer_a is the only peer on subnet 42.
    const info_a = (try pm.onPeerConnected("peer_a", .outbound, 1000)).?;
    info_a.attnets.set(42);

    // peer_b is on no unique subnets and has worse direction (inbound).
    _ = try pm.onPeerConnected("peer_b", .inbound, 1000);

    var actions = try pm.heartbeat(2000);
    defer actions.deinit(allocator);

    // Should disconnect 1 peer. peer_a should be protected (unique subnet).
    try std.testing.expectEqual(@as(usize, 1), actions.peers_to_disconnect.len);
    try std.testing.expectEqualStrings("peer_b", actions.peers_to_disconnect[0]);
}
