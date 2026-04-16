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
const ForkSeq = @import("config").ForkSeq;
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
const fmtPeerId = @import("peer_id_fmt.zig").fmtPeerId;

const log = std.log.scoped(.peer_manager);

const peer_relevance = @import("peer_relevance.zig");
const assertPeerRelevance = peer_relevance.assertPeerRelevance;
const IrrelevantPeerCode = peer_relevance.IrrelevantPeerCode;
const custody = @import("custody.zig");

const peer_prioritization = @import("peer_prioritization.zig");
const ConnectedPeerView = peer_prioritization.ConnectedPeerView;
const PrioritizationResult = peer_prioritization.PrioritizationResult;
const SubnetQuery = peer_prioritization.SubnetQuery;
const PeerDisconnect = peer_prioritization.PeerDisconnect;
const DisconnectReason = peer_prioritization.DisconnectReason;

const status_cache = @import("status_cache.zig");
const CachedStatus = status_cache.CachedStatus;
const StatusCache = status_cache.StatusCache;
const peer_scoring = @import("peer_scoring.zig");

const subnet_service_mod = @import("subnet_service.zig");
const SubnetService = subnet_service_mod.SubnetService;
const SubnetId = subnet_service_mod.SubnetId;

const RelevanceStatus = peer_info_mod.RelevanceStatus;

// ── Constants ───────────────────────────────────────────────────────────────

/// Heartbeat interval in milliseconds (30 seconds).
pub const HEARTBEAT_INTERVAL_MS: u64 = 30_000;
/// Periodic ping interval for inbound peers.
pub const INBOUND_PING_INTERVAL_MS: u64 = 15_000;
/// Periodic ping interval for outbound peers.
pub const OUTBOUND_PING_INTERVAL_MS: u64 = 20_000;
/// Periodic Status refresh interval for connected peers.
pub const STATUS_REFRESH_INTERVAL_MS: u64 = 5 * 60_000;
/// Inbound peers are given a short window to Status us first, matching
/// Lodestar's inbound grace behavior before we proactively request Status.
pub const STATUS_INBOUND_GRACE_PERIOD_MS: u64 = 15_000;
/// Retry cadence for peers whose initial Status exchange has not completed.
/// Lodestar retries unresolved peers on its 10s maintenance loop rather than
/// backing off for a full minute.
pub const STATUS_FAILED_RETRY_BACKOFF_MS: u64 = 10_000;

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
    /// Target number of peers for each relevant PeerDAS custody group.
    target_group_peers: u32 = peer_prioritization.TARGET_GROUP_PEERS,
    /// Local PeerDAS custody columns used for retention and discovery demand.
    local_custody_columns: []const u64 = &.{},
};

/// Match Lodestar's CLI semantics: when a user raises target peers, reserve a
/// small amount of headroom above the target for in-flight/outbound churn.
pub fn maxPeersForTarget(target_peers: u32) u32 {
    const scaled = (target_peers * 11) / 10;
    return @max(target_peers, scaled);
}

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
        for (self.peers_to_disconnect) |pid| allocator.free(pid);
        if (self.peers_to_disconnect.len > 0) allocator.free(self.peers_to_disconnect);
        if (self.peers_to_ban.len > 0) allocator.free(self.peers_to_ban);
        if (self.subnets_needing_peers.len > 0) allocator.free(self.subnets_needing_peers);
    }
};

/// Configuration for bounded peer-maintenance selection.
pub const MaintenanceConfig = struct {
    max_ping_requests: u32 = 4,
    max_status_requests: u32 = 2,
    ping_interval_inbound_ms: u64 = INBOUND_PING_INTERVAL_MS,
    ping_interval_outbound_ms: u64 = OUTBOUND_PING_INTERVAL_MS,
    status_refresh_interval_ms: u64 = STATUS_REFRESH_INTERVAL_MS,
};

/// Due maintenance work for the runtime to execute.
pub const MaintenanceActions = struct {
    peers_to_ping: [][]const u8 = &.{},
    peers_to_restatus: [][]const u8 = &.{},

    pub fn deinit(self: *MaintenanceActions, allocator: Allocator) void {
        for (self.peers_to_ping) |peer_id| allocator.free(peer_id);
        if (self.peers_to_ping.len > 0) allocator.free(self.peers_to_ping);
        for (self.peers_to_restatus) |peer_id| allocator.free(peer_id);
        if (self.peers_to_restatus.len > 0) allocator.free(self.peers_to_restatus);
    }
};

/// Generic housekeeping work that should run regardless of subnet demand.
pub const HousekeepingActions = struct {
    peers_to_disconnect: [][]const u8 = &.{},

    pub fn deinit(self: *HousekeepingActions, allocator: Allocator) void {
        for (self.peers_to_disconnect) |peer_id| allocator.free(peer_id);
        if (self.peers_to_disconnect.len > 0) allocator.free(self.peers_to_disconnect);
    }
};

pub const metric_connection_states = [_]ConnectionState{
    .disconnected,
    .dialing,
    .connected,
    .disconnecting,
    .banned,
};
pub const metric_score_states = [_]ScoreState{ .healthy, .disconnected, .banned };
pub const metric_relevance_states = [_]RelevanceStatus{ .unknown, .relevant, .irrelevant };
pub const metric_report_sources = [_]ReportSource{ .gossipsub, .rpc, .processor, .sync, .peer_manager };
pub const metric_peer_actions = [_]PeerAction{ .fatal, .low_tolerance, .mid_tolerance, .high_tolerance };

pub const GoodbyeMetricReason = enum {
    client_shutdown,
    irrelevant_network,
    fault_error,
    unable_to_verify,
    too_many_peers,
    score_too_low,
    banned,
    other,
};

pub const metric_goodbye_reasons = [_]GoodbyeMetricReason{
    .client_shutdown,
    .irrelevant_network,
    .fault_error,
    .unable_to_verify,
    .too_many_peers,
    .score_too_low,
    .banned,
    .other,
};

pub const MetricsSnapshot = struct {
    known_peers: u64 = 0,
    connected_peers: u64 = 0,
    inbound_connected_peers: u64 = 0,
    outbound_connected_peers: u64 = 0,
    connection_state_counts: [metric_connection_states.len]u64 = [_]u64{0} ** metric_connection_states.len,
    score_state_counts: [metric_score_states.len]u64 = [_]u64{0} ** metric_score_states.len,
    relevance_counts: [metric_relevance_states.len]u64 = [_]u64{0} ** metric_relevance_states.len,
    peer_report_counts: [metric_report_sources.len][metric_peer_actions.len]u64 = [_][metric_peer_actions.len]u64{[_]u64{0} ** metric_peer_actions.len} ** metric_report_sources.len,
    goodbye_received_counts: [metric_goodbye_reasons.len]u64 = [_]u64{0} ** metric_goodbye_reasons.len,

    pub fn connectionStateCount(self: *const MetricsSnapshot, state: ConnectionState) u64 {
        return self.connection_state_counts[
            switch (state) {
                .disconnected => 0,
                .dialing => 1,
                .connected => 2,
                .disconnecting => 3,
                .banned => 4,
            }
        ];
    }

    pub fn scoreStateCount(self: *const MetricsSnapshot, state: ScoreState) u64 {
        return self.score_state_counts[
            switch (state) {
                .healthy => 0,
                .disconnected => 1,
                .banned => 2,
            }
        ];
    }

    pub fn relevanceCount(self: *const MetricsSnapshot, status: RelevanceStatus) u64 {
        return self.relevance_counts[
            switch (status) {
                .unknown => 0,
                .relevant => 1,
                .irrelevant => 2,
            }
        ];
    }

    pub fn peerReportCount(self: *const MetricsSnapshot, source: ReportSource, action: PeerAction) u64 {
        return self.peer_report_counts[
            switch (source) {
                .gossipsub => 0,
                .rpc => 1,
                .processor => 2,
                .sync => 3,
                .peer_manager => 4,
            }
        ][
            switch (action) {
                .fatal => 0,
                .low_tolerance => 1,
                .mid_tolerance => 2,
                .high_tolerance => 3,
            }
        ];
    }

    pub fn goodbyeReceivedCount(self: *const MetricsSnapshot, reason: GoodbyeMetricReason) u64 {
        return self.goodbye_received_counts[
            switch (reason) {
                .client_shutdown => 0,
                .irrelevant_network => 1,
                .fault_error => 2,
                .unable_to_verify => 3,
                .too_many_peers => 4,
                .score_too_low => 5,
                .banned => 6,
                .other => 7,
            }
        ];
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
    connected_count_atomic: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    peer_report_counts: [metric_report_sources.len][metric_peer_actions.len]u64 = [_][metric_peer_actions.len]u64{[_]u64{0} ** metric_peer_actions.len} ** metric_report_sources.len,
    goodbye_received_counts: [metric_goodbye_reasons.len]u64 = [_]u64{0} ** metric_goodbye_reasons.len,

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

    fn syncConnectedCount(self: *PeerManager) void {
        self.connected_count_atomic.store(self.db.connected_count, .release);
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
        self.syncConnectedCount();

        log.debug("Peer connected {f} direction={s} total={d}", .{
            fmtPeerId(peer_id),
            @tagName(direction),
            self.db.connected_count,
        });

        return info;
    }

    /// Called when a peer disconnects.
    pub fn onPeerDisconnected(self: *PeerManager, peer_id: []const u8, now_ms: u64) void {
        const apply_inbound_cooldown = if (self.db.getPeer(peer_id)) |info|
            info.connection_state == .connected and info.direction == .inbound
        else
            false;

        self.db.peerDisconnected(peer_id, now_ms);
        self.syncConnectedCount();
        if (apply_inbound_cooldown) {
            self.db.applyReconnectionCoolDown(peer_id, peer_scoring.inboundDisconnectCoolDownMs(), now_ms);
        }
        log.debug("Peer disconnected {f} total={d}", .{
            fmtPeerId(peer_id),
            self.db.connected_count,
        });
    }

    /// Called when we begin a graceful disconnect but the transport has not
    /// fully torn down yet.
    pub fn onPeerDisconnecting(self: *PeerManager, peer_id: []const u8) void {
        self.db.peerDisconnecting(peer_id);
        self.syncConnectedCount();
    }

    /// Called when a peer initiates a Goodbye disconnect.
    pub fn onPeerGoodbye(
        self: *PeerManager,
        peer_id: []const u8,
        reason: GoodbyeReason,
        now_ms: u64,
    ) void {
        self.db.peerDisconnecting(peer_id);
        self.goodbye_received_counts[goodbyeMetricReasonIndex(goodbyeReasonForMetrics(reason))] += 1;
        if (peer_scoring.reconnectionCoolDownMs(reason)) |cool_down_ms| {
            self.db.applyReconnectionCoolDown(peer_id, cool_down_ms, now_ms);
        }
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

    /// Update the verified discovery node ID for a peer.
    pub fn updatePeerDiscoveryNodeId(
        self: *PeerManager,
        peer_id: []const u8,
        node_id: [32]u8,
    ) !void {
        try self.db.updatePeerDiscoveryNodeId(peer_id, node_id);
    }

    /// Update peer metadata sequence and subnet subscriptions from Metadata.
    pub fn updatePeerMetadata(
        self: *PeerManager,
        peer_id: []const u8,
        metadata_seq: u64,
        attnets: AttnetsBitfield,
        syncnets: SyncnetsBitfield,
        custody_group_count: ?u64,
    ) !void {
        try self.db.updatePeerMetadata(peer_id, metadata_seq, attnets, syncnets, custody_group_count);
    }

    /// Update a peer's last-seen timestamp after any successful req/resp exchange.
    pub fn notePeerSeen(self: *PeerManager, peer_id: []const u8, now_ms: u64) void {
        self.db.notePeerSeen(peer_id, now_ms);
    }

    /// Record a successful outbound ping response.
    pub fn markPingResponse(self: *PeerManager, peer_id: []const u8, now_ms: u64) void {
        self.db.markPingResponse(peer_id, now_ms);
    }

    /// Record an outbound Status attempt.
    pub fn markStatusAttempt(self: *PeerManager, peer_id: []const u8, now_ms: u64) void {
        self.db.markStatusAttempt(peer_id, now_ms);
    }

    /// Record a successful Status exchange.
    pub fn markStatusExchange(self: *PeerManager, peer_id: []const u8, now_ms: u64) void {
        self.db.markStatusExchange(peer_id, now_ms);
    }

    /// Mirror the live gossipsub router score into peer state.
    pub fn updateGossipsubScore(
        self: *PeerManager,
        peer_id: []const u8,
        score: f64,
        ignore_negative: bool,
        now_ms: u64,
    ) ?ScoreState {
        return self.db.updateGossipsubScore(peer_id, score, ignore_negative, now_ms);
    }

    pub fn negativeGossipsubIgnoreCount(self: *const PeerManager) u32 {
        return peer_scoring.negativeGossipsubIgnoreCount(self.config.target_peers);
    }

    pub fn metricsSnapshot(self: *const PeerManager) MetricsSnapshot {
        var snapshot: MetricsSnapshot = .{
            .known_peers = @intCast(self.db.totalCount()),
            .connected_peers = @intCast(self.db.connected_count),
            .inbound_connected_peers = @intCast(self.db.inbound_count),
            .outbound_connected_peers = @intCast(self.db.outbound_count),
            .peer_report_counts = self.peer_report_counts,
            .goodbye_received_counts = self.goodbye_received_counts,
        };

        var it = self.db.peers.valueIterator();
        while (it.next()) |info| {
            snapshot.connection_state_counts[connectionStateIndex(info.connection_state)] += 1;
            snapshot.score_state_counts[scoreStateIndex(info.scoreState())] += 1;
            snapshot.relevance_counts[relevanceStatusIndex(info.relevance)] += 1;
        }

        return snapshot;
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
        self.peer_report_counts[reportSourceIndex(source)][peerActionIndex(action)] += 1;

        // Auto-ban on fatal.
        if (action == .fatal) {
            self.db.banPeer(peer_id, .long, now_ms) catch {};
            self.syncConnectedCount();
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
        self.syncConnectedCount();
        log.info("peer banned {f} duration={d}s", .{
            fmtPeerId(peer_id),
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
        remote_earliest_available_slot: ?u64,
        local_status: CachedStatus,
        local_fork_seq: ForkSeq,
        current_slot: u64,
    ) ?IrrelevantPeerCode {
        const irrelevance = assertPeerRelevance(
            remote_fork_digest,
            remote_finalized_root,
            remote_finalized_epoch,
            remote_head_slot,
            remote_earliest_available_slot,
            local_status,
            local_fork_seq,
            current_slot,
        );

        if (irrelevance) |info| {
            self.db.setRelevanceStatus(peer_id, .irrelevant);
            log.debug("Peer irrelevant {s}: {s}", .{
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
        earliest_available_slot: ?u64,
        local_status: CachedStatus,
        local_fork_seq: ForkSeq,
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
            earliest_available_slot,
        );

        // Check relevance.
        return self.checkPeerRelevance(
            peer_id,
            fork_digest,
            finalized_root,
            finalized_epoch,
            head_slot,
            earliest_available_slot,
            local_status,
            local_fork_seq,
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
                .custody_columns = cp.info.custody_columns,
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
                .target_group_peers = self.config.target_group_peers,
                .local_custody_columns = self.config.local_custody_columns,
            },
        );
    }

    // ── Queries (sync integration) ──────────────────────────────────

    /// Number of connected peers.
    pub fn peerCount(self: *const PeerManager) u32 {
        return self.connected_count_atomic.load(.acquire);
    }

    /// Number of outbound dials currently in flight.
    pub fn dialingPeerCount(self: *const PeerManager) u32 {
        return self.db.dialing_count;
    }

    /// Get peer info (read-only).
    pub fn getPeer(self: *const PeerManager, peer_id: []const u8) ?*const PeerInfo {
        return self.db.getPeer(peer_id);
    }

    /// Get transport-live peer IDs (connected or disconnecting). Caller owns the returned slice and entries.
    pub fn getConnectedPeerIds(self: *PeerManager) ![][]const u8 {
        var live_count: usize = 0;
        var count_iter = self.db.peers.valueIterator();
        while (count_iter.next()) |peer| {
            if (peer.connection_state == .connected or peer.connection_state == .disconnecting) {
                live_count += 1;
            }
        }

        var copied: usize = 0;
        var peer_ids = try self.allocator.alloc([]const u8, live_count);
        errdefer {
            for (peer_ids[0..copied]) |peer_id| self.allocator.free(peer_id);
            self.allocator.free(peer_ids);
        }

        var iter = self.db.peers.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.connection_state != .connected and entry.value_ptr.connection_state != .disconnecting) continue;
            peer_ids[copied] = try self.allocator.dupe(u8, entry.key_ptr.*);
            copied += 1;
        }

        return peer_ids;
    }

    /// Select the best connected peer to request missing data columns from.
    ///
    /// Prefers peers with known custody overlap, falling back to peers with
    /// unknown custody only when no better option is available.
    /// Caller owns the returned peer ID.
    pub fn selectDataColumnPeer(
        self: *PeerManager,
        missing_columns: []const u64,
        start_slot: u64,
        end_slot: u64,
        preferred_peer_id: ?[]const u8,
        excluded_peer_ids: []const []const u8,
    ) !?[]const u8 {
        _ = start_slot;
        _ = end_slot;
        const connected = try self.db.getConnectedPeers();
        defer self.allocator.free(connected);

        const Candidate = struct {
            peer_id: []const u8,
            coverage: usize,
            head_slot: u64,
            score: f64,
            preferred: bool,
        };

        var best_known: ?Candidate = null;
        var best_unknown: ?Candidate = null;
        var connected_count: usize = 0;
        var unknown_count: usize = 0;
        var zero_overlap_count: usize = 0;

        for (connected) |cp| {
            connected_count += 1;
            if (containsPeerId(excluded_peer_ids, cp.peer_id)) continue;
            if (cp.info.relevance == .irrelevant) continue;

            const is_preferred = if (preferred_peer_id) |preferred|
                std.mem.eql(u8, cp.peer_id, preferred)
            else
                false;

            if (cp.info.custody_columns) |custody_columns| {
                const coverage = custodyCoverageCount(custody_columns, missing_columns);
                if (coverage == 0) {
                    zero_overlap_count += 1;
                    continue;
                }

                const candidate: Candidate = .{
                    .peer_id = cp.peer_id,
                    .coverage = coverage,
                    .head_slot = cp.info.headSlot(),
                    .score = cp.info.score(),
                    .preferred = is_preferred,
                };
                if (best_known == null or betterDataColumnCandidate(candidate, best_known.?)) {
                    best_known = candidate;
                }
            } else {
                unknown_count += 1;
                const candidate: Candidate = .{
                    .peer_id = cp.peer_id,
                    .coverage = 0,
                    .head_slot = cp.info.headSlot(),
                    .score = cp.info.score(),
                    .preferred = is_preferred,
                };
                if (best_unknown == null or betterDataColumnCandidate(candidate, best_unknown.?)) {
                    best_unknown = candidate;
                }
            }
        }

        if (best_known) |candidate| {
            return try self.allocator.dupe(u8, candidate.peer_id);
        }
        if (best_unknown) |candidate| {
            return try self.allocator.dupe(u8, candidate.peer_id);
        }
        log.debug(
            "No data column peer selected: connected={d} unknown={d} zero_overlap={d} missing_columns={d} preferred={f}",
            .{
                connected_count,
                unknown_count,
                zero_overlap_count,
                missing_columns.len,
                fmtPeerId(preferred_peer_id),
            },
        );
        return null;
    }

    /// Select a bounded set of connected peers that are due for maintenance.
    ///
    /// Status refreshes take precedence over pings since they also re-run the
    /// relevance check. Selected peer IDs are duplicated for the caller.
    pub fn maintenance(self: *PeerManager, now_ms: u64, config: MaintenanceConfig) !MaintenanceActions {
        var actions = MaintenanceActions{};
        errdefer actions.deinit(self.allocator);

        const connected = try self.db.getConnectedPeers();
        defer self.allocator.free(connected);

        var status_peers = std.ArrayListUnmanaged([]const u8).empty;
        defer status_peers.deinit(self.allocator);

        var ping_peers = std.ArrayListUnmanaged([]const u8).empty;
        defer ping_peers.deinit(self.allocator);

        for (connected) |peer| {
            if (status_peers.items.len >= @as(usize, @intCast(config.max_status_requests))) break;
            if (!peerNeedsStatusRefresh(peer.info, now_ms, config.status_refresh_interval_ms)) continue;
            try status_peers.append(self.allocator, try self.allocator.dupe(u8, peer.peer_id));
        }

        for (connected) |peer| {
            if (ping_peers.items.len >= @as(usize, @intCast(config.max_ping_requests))) break;
            if (containsPeerId(status_peers.items, peer.peer_id)) continue;
            if (!peerNeedsPing(peer.info, now_ms, config)) continue;
            try ping_peers.append(self.allocator, try self.allocator.dupe(u8, peer.peer_id));
        }

        actions.peers_to_restatus = try status_peers.toOwnedSlice(self.allocator);
        actions.peers_to_ping = try ping_peers.toOwnedSlice(self.allocator);
        return actions;
    }

    /// Highest head slot among connected peers.
    pub fn getHighestPeerSlot(self: *PeerManager) u64 {
        return self.db.getHighestPeerSlot();
    }

    /// Best sync target (connected peer with highest head slot).
    pub fn getSyncTarget(self: *PeerManager) ?SyncTarget {
        return self.db.getBestSyncTarget();
    }

    /// Get all connected peers for sync liveness checks.
    /// Caller owns the returned slice.
    pub fn getConnectedPeers(self: *PeerManager) ![]ConnectedPeer {
        return self.db.getConnectedPeers();
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

        const housekeeping_actions = try self.housekeeping(now_ms);
        defer {
            if (housekeeping_actions.peers_to_disconnect.len > 0) self.allocator.free(housekeeping_actions.peers_to_disconnect);
        }

        // 4. Prune excess peers if above target.
        const prune_disconnects = try self.pruneExcessPeers();

        // Merge disconnect lists.
        actions.peers_to_disconnect = try self.mergeSlices(housekeeping_actions.peers_to_disconnect, prune_disconnects);
        if (prune_disconnects.len > 0) self.allocator.free(prune_disconnects);

        // 5. Determine discovery needs.
        if (self.db.connected_count < self.config.target_peers) {
            const deficit = self.config.target_peers - self.db.connected_count;
            actions.peers_to_discover = @min(
                deficit * DISCOVERY_OVERSHOOT_FACTOR,
                self.config.max_peers -| self.db.connected_count,
            );
        }

        const custody_deficit = try self.maxCustodyCoverageDeficit();
        if (custody_deficit > 0) {
            const custody_discovery = @min(
                custody_deficit * DISCOVERY_OVERSHOOT_FACTOR,
                self.config.max_peers -| self.db.connected_count,
            );
            actions.peers_to_discover = @max(actions.peers_to_discover, custody_discovery);
        }

        // 6. Find subnets needing more peers.
        actions.subnets_needing_peers = try self.getSubnetsNeedingPeers();

        // 7. Prune stale disconnected peer entries from DB.
        _ = self.db.pruneStale(STALE_PEER_MS, now_ms);

        // 8. Log summary.
        log.debug("Heartbeat: connected={d} inbound={d} outbound={d} banned={d} " ++
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

    /// Run score decay, expired-ban cleanup, and low-score disconnection
    /// selection without subnet-agnostic pruning.
    pub fn housekeeping(self: *PeerManager, now_ms: u64) !HousekeepingActions {
        var actions = HousekeepingActions{};
        errdefer actions.deinit(self.allocator);

        self.db.decayAllScores(now_ms);

        const expired = try self.db.getExpiredBans(now_ms);
        defer self.allocator.free(expired);
        for (expired) |pid| {
            _ = self.db.unbanIfExpired(pid, now_ms);
            log.debug("Unbanned expired peer {s}", .{pid});
        }

        actions.peers_to_disconnect = try self.db.getScoreDisconnectPeers();
        _ = self.db.pruneStale(STALE_PEER_MS, now_ms);
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

            if (self.peerProvidesCriticalCustodyCoverage(cp.info, all_connected)) {
                prune_score += 100.0;
            }

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
            result[i] = self.allocator.dupe(u8, candidates.items[i].peer_id) catch {
                // Rollback already-duped entries on OOM.
                for (result[0..i]) |prev| self.allocator.free(prev);
                self.allocator.free(result);
                return &.{};
            };
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

    fn peerNeedsStatusRefresh(peer: *const PeerInfo, now_ms: u64, interval_ms: u64) bool {
        if (peer.last_status_exchange_ms == 0) {
            if (peer.last_status_attempt_ms == 0) {
                const first_status_at_ms = switch (peer.direction orelse .inbound) {
                    .outbound => peer.connected_at_ms,
                    .inbound => peer.connected_at_ms + STATUS_INBOUND_GRACE_PERIOD_MS,
                };
                return now_ms >= first_status_at_ms;
            }
            return now_ms >= peer.last_status_attempt_ms + STATUS_FAILED_RETRY_BACKOFF_MS;
        }
        if (peer.last_status_fork_digest == null or peer.relevance == .unknown) return true;
        return now_ms >= peer.last_status_exchange_ms + interval_ms;
    }

    fn peerNeedsPing(peer: *const PeerInfo, now_ms: u64, config: MaintenanceConfig) bool {
        const interval_ms = switch (peer.direction orelse .inbound) {
            .inbound => config.ping_interval_inbound_ms,
            .outbound => config.ping_interval_outbound_ms,
        };
        const last_ping_ms = if (peer.last_ping_response_ms != 0)
            peer.last_ping_response_ms
        else
            peer.connected_at_ms;
        return now_ms >= last_ping_ms + interval_ms;
    }

    fn containsPeerId(peer_ids: []const []const u8, needle: []const u8) bool {
        for (peer_ids) |peer_id| {
            if (std.mem.eql(u8, peer_id, needle)) return true;
        }
        return false;
    }

    fn peerCanServeRange(peer: *const PeerInfo, start_slot: u64, end_slot: u64) bool {
        if (peer.relevance == .irrelevant) return false;
        const sync_info = peer.sync_info orelse return false;
        if (sync_info.head_slot < end_slot) return false;
        if (sync_info.earliest_available_slot) |earliest| {
            if (start_slot < earliest) return false;
        }
        return true;
    }

    fn custodyCoverageCount(custody_columns: []const u64, missing_columns: []const u64) usize {
        var count: usize = 0;
        for (missing_columns) |column_index| {
            if (custody.isCustodied(column_index, custody_columns)) count += 1;
        }
        return count;
    }

    fn betterDataColumnCandidate(candidate: anytype, current: @TypeOf(candidate)) bool {
        if (candidate.coverage != current.coverage) return candidate.coverage > current.coverage;
        if (candidate.preferred != current.preferred) return candidate.preferred;
        if (candidate.score != current.score) return candidate.score > current.score;
        if (candidate.head_slot != current.head_slot) return candidate.head_slot > current.head_slot;
        return std.mem.lessThan(u8, candidate.peer_id, current.peer_id);
    }

    fn connectionStateIndex(state: ConnectionState) usize {
        return switch (state) {
            .disconnected => 0,
            .dialing => 1,
            .connected => 2,
            .disconnecting => 3,
            .banned => 4,
        };
    }

    fn scoreStateIndex(state: ScoreState) usize {
        return switch (state) {
            .healthy => 0,
            .disconnected => 1,
            .banned => 2,
        };
    }

    fn relevanceStatusIndex(status: RelevanceStatus) usize {
        return switch (status) {
            .unknown => 0,
            .relevant => 1,
            .irrelevant => 2,
        };
    }

    fn reportSourceIndex(source: ReportSource) usize {
        return switch (source) {
            .gossipsub => 0,
            .rpc => 1,
            .processor => 2,
            .sync => 3,
            .peer_manager => 4,
        };
    }

    fn peerActionIndex(action: PeerAction) usize {
        return switch (action) {
            .fatal => 0,
            .low_tolerance => 1,
            .mid_tolerance => 2,
            .high_tolerance => 3,
        };
    }

    fn goodbyeReasonForMetrics(reason: GoodbyeReason) GoodbyeMetricReason {
        return switch (reason) {
            .client_shutdown => .client_shutdown,
            .irrelevant_network => .irrelevant_network,
            .fault_error => .fault_error,
            .unable_to_verify => .unable_to_verify,
            .too_many_peers => .too_many_peers,
            .score_too_low => .score_too_low,
            .banned => .banned,
            else => .other,
        };
    }

    fn goodbyeMetricReasonIndex(reason: GoodbyeMetricReason) usize {
        return switch (reason) {
            .client_shutdown => 0,
            .irrelevant_network => 1,
            .fault_error => 2,
            .unable_to_verify => 3,
            .too_many_peers => 4,
            .score_too_low => 5,
            .banned => 6,
            .other => 7,
        };
    }

    fn maxCustodyCoverageDeficit(self: *PeerManager) !u32 {
        if (self.config.local_custody_columns.len == 0) return 0;

        const connected = try self.db.getConnectedPeers();
        defer self.allocator.free(connected);

        var max_deficit: u32 = 0;
        for (self.config.local_custody_columns) |column_index| {
            var count: u32 = 0;
            for (connected) |cp| {
                const peer_columns = cp.info.custody_columns orelse continue;
                if (custody.isCustodied(column_index, peer_columns)) {
                    count += 1;
                }
            }
            if (count < self.config.target_group_peers) {
                max_deficit = @max(max_deficit, self.config.target_group_peers - count);
            }
        }
        return max_deficit;
    }

    fn peerProvidesCriticalCustodyCoverage(
        self: *PeerManager,
        peer: *const PeerInfo,
        connected: []const ConnectedPeer,
    ) bool {
        const peer_columns = peer.custody_columns orelse return false;
        if (self.config.local_custody_columns.len == 0) return false;

        for (self.config.local_custody_columns) |column_index| {
            if (!custody.isCustodied(column_index, peer_columns)) continue;

            var count: u32 = 0;
            for (connected) |cp| {
                const other_columns = cp.info.custody_columns orelse continue;
                if (custody.isCustodied(column_index, other_columns)) {
                    count += 1;
                }
            }

            if (count < self.config.target_group_peers) return true;
        }

        return false;
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

test "PeerManager: inbound disconnect applies reconnection cool-down" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, .{ .target_peers = 5, .max_peers = 10 });
    defer pm.deinit();

    _ = try pm.onPeerConnected("peer_a", .inbound, 1000);
    pm.onPeerDisconnected("peer_a", 2000);

    const peer = pm.getPeer("peer_a").?;
    try std.testing.expect(peer.peer_score.isCoolingDown(2000));
}

test "PeerManager: outbound disconnect does not apply reconnection cool-down" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, .{ .target_peers = 5, .max_peers = 10 });
    defer pm.deinit();

    _ = try pm.onPeerConnected("peer_a", .outbound, 1000);
    pm.onPeerDisconnected("peer_a", 2000);

    const peer = pm.getPeer("peer_a").?;
    try std.testing.expect(!peer.peer_score.isCoolingDown(2000));
}

test "PeerManager: goodbye cool-down prevents immediate outbound redial" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, .{ .target_peers = 5, .max_peers = 10 });
    defer pm.deinit();

    _ = try pm.onPeerConnected("peer_a", .outbound, 1000);
    pm.onPeerGoodbye("peer_a", .too_many_peers, 1200);
    pm.onPeerDisconnected("peer_a", 1300);

    try std.testing.expectError(error.PeerCoolingDown, pm.onDialing("peer_a", 1400));
    try pm.onDialing("peer_a", 1200 + 5 * 60 * 1000 + 1);
    const peer = pm.getPeer("peer_a").?;
    try std.testing.expectEqual(ConnectionState.dialing, peer.connection_state);
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

test "PeerManager: metrics snapshot exposes peer states and events" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, .{});
    defer pm.deinit();

    _ = try pm.onPeerConnected("peer_a", .inbound, 1000);
    _ = try pm.onPeerConnected("peer_b", .outbound, 1000);
    _ = pm.reportPeer("peer_a", .low_tolerance, .rpc, 1100);
    pm.onPeerGoodbye("peer_b", .too_many_peers, 1200);

    const snapshot = pm.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 2), snapshot.known_peers);
    try std.testing.expectEqual(@as(u64, 1), snapshot.connected_peers);
    try std.testing.expectEqual(@as(u64, 1), snapshot.inbound_connected_peers);
    try std.testing.expectEqual(@as(u64, 0), snapshot.outbound_connected_peers);
    try std.testing.expectEqual(@as(u64, 1), snapshot.connectionStateCount(.connected));
    try std.testing.expectEqual(@as(u64, 1), snapshot.connectionStateCount(.disconnecting));
    try std.testing.expectEqual(@as(u64, 2), snapshot.scoreStateCount(.healthy));
    try std.testing.expectEqual(@as(u64, 2), snapshot.relevanceCount(.unknown));
    try std.testing.expectEqual(@as(u64, 1), snapshot.peerReportCount(.rpc, .low_tolerance));
    try std.testing.expectEqual(@as(u64, 1), snapshot.goodbyeReceivedCount(.too_many_peers));
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

test "PeerManager: maintenance schedules pings by connection direction" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, .{});
    defer pm.deinit();

    _ = try pm.onPeerConnected("inbound_peer", .inbound, 1_000);
    _ = try pm.onPeerConnected("outbound_peer", .outbound, 1_000);
    pm.db.updatePeerStatus("inbound_peer", [_]u8{0x11} ** 4, [_]u8{0x22} ** 32, 1, 2, [_]u8{0x33} ** 32, null);
    pm.db.updatePeerStatus("outbound_peer", [_]u8{0x44} ** 4, [_]u8{0x55} ** 32, 1, 2, [_]u8{0x66} ** 32, null);
    pm.db.setRelevanceStatus("inbound_peer", .relevant);
    pm.db.setRelevanceStatus("outbound_peer", .relevant);
    pm.markStatusExchange("inbound_peer", 1_000);
    pm.markStatusExchange("outbound_peer", 1_000);

    var actions = try pm.maintenance(16_000, .{ .max_ping_requests = 4, .max_status_requests = 2 });
    defer actions.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), actions.peers_to_ping.len);
    try std.testing.expectEqualStrings("inbound_peer", actions.peers_to_ping[0]);

    pm.markPingResponse("inbound_peer", 16_000);

    var later_actions = try pm.maintenance(21_000, .{ .max_ping_requests = 4, .max_status_requests = 2 });
    defer later_actions.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), later_actions.peers_to_ping.len);
    try std.testing.expectEqualStrings("outbound_peer", later_actions.peers_to_ping[0]);
}

test "PeerManager: maintenance prioritizes status refresh over ping" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, .{});
    defer pm.deinit();

    _ = try pm.onPeerConnected("peer_a", .outbound, 1_000);
    pm.db.updatePeerStatus("peer_a", [_]u8{0x77} ** 4, [_]u8{0x88} ** 32, 1, 2, [_]u8{0x99} ** 32, null);
    pm.db.setRelevanceStatus("peer_a", .relevant);
    pm.markStatusExchange("peer_a", 1_000);
    pm.markPingResponse("peer_a", 1_000);

    var actions = try pm.maintenance(301_000, .{ .max_ping_requests = 1, .max_status_requests = 1 });
    defer actions.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), actions.peers_to_restatus.len);
    try std.testing.expectEqualStrings("peer_a", actions.peers_to_restatus[0]);
    try std.testing.expectEqual(@as(usize, 0), actions.peers_to_ping.len);
}

test "PeerManager: maintenance restatuses outbound peers without prior status immediately" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, .{});
    defer pm.deinit();

    _ = try pm.onPeerConnected("peer_a", .outbound, 1_000);

    var actions = try pm.maintenance(2_000, .{ .max_ping_requests = 1, .max_status_requests = 1 });
    defer actions.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), actions.peers_to_restatus.len);
    try std.testing.expectEqualStrings("peer_a", actions.peers_to_restatus[0]);
}

test "PeerManager: maintenance gives inbound peers a status grace period" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, .{});
    defer pm.deinit();

    _ = try pm.onPeerConnected("peer_a", .inbound, 1_000);

    var early_actions = try pm.maintenance(1_000 + STATUS_INBOUND_GRACE_PERIOD_MS - 1, .{ .max_ping_requests = 1, .max_status_requests = 1 });
    defer early_actions.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), early_actions.peers_to_restatus.len);

    var ready_actions = try pm.maintenance(1_000 + STATUS_INBOUND_GRACE_PERIOD_MS, .{ .max_ping_requests = 1, .max_status_requests = 1 });
    defer ready_actions.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), ready_actions.peers_to_restatus.len);
    try std.testing.expectEqualStrings("peer_a", ready_actions.peers_to_restatus[0]);
}

test "PeerManager: maintenance retries failed initial status exchanges quickly" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, .{});
    defer pm.deinit();

    _ = try pm.onPeerConnected("peer_a", .outbound, 1_000);
    pm.markStatusAttempt("peer_a", 1_500);

    var actions = try pm.maintenance(2_000, .{ .max_ping_requests = 1, .max_status_requests = 1 });
    defer actions.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), actions.peers_to_restatus.len);

    var retry_actions = try pm.maintenance(1_500 + STATUS_FAILED_RETRY_BACKOFF_MS, .{ .max_ping_requests = 1, .max_status_requests = 1 });
    defer retry_actions.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), retry_actions.peers_to_restatus.len);
    try std.testing.expectEqualStrings("peer_a", retry_actions.peers_to_restatus[0]);
}

test "PeerManager: maintenance restatuses newly reconnected peers immediately" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, .{});
    defer pm.deinit();

    _ = try pm.onPeerConnected("peer_a", .outbound, 1_000);
    pm.db.updatePeerStatus("peer_a", [_]u8{0x11} ** 4, [_]u8{0x22} ** 32, 1, 2, [_]u8{0x33} ** 32, null);
    pm.db.setRelevanceStatus("peer_a", .relevant);
    pm.markStatusExchange("peer_a", 1_000);

    pm.onPeerDisconnected("peer_a", 2_000);
    _ = try pm.onPeerConnected("peer_a", .outbound, 3_000);

    var actions = try pm.maintenance(3_001, .{ .max_ping_requests = 1, .max_status_requests = 1 });
    defer actions.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), actions.peers_to_restatus.len);
    try std.testing.expectEqualStrings("peer_a", actions.peers_to_restatus[0]);
}

test "PeerManager: selectDataColumnPeer prefers custody overlap" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, .{});
    defer pm.deinit();

    _ = try pm.onPeerConnected("preferred_peer", .outbound, 1_000);
    pm.db.updatePeerStatus("preferred_peer", [_]u8{0x11} ** 4, [_]u8{0x22} ** 32, 1, 128, [_]u8{0x33} ** 32, 0);
    pm.db.setRelevanceStatus("preferred_peer", .relevant);

    _ = try pm.onPeerConnected("custody_peer", .outbound, 1_000);
    pm.db.updatePeerStatus("custody_peer", [_]u8{0x44} ** 4, [_]u8{0x55} ** 32, 1, 128, [_]u8{0x66} ** 32, 0);
    pm.db.setRelevanceStatus("custody_peer", .relevant);

    const custody_node_id = [_]u8{0x77} ** 32;
    try pm.updatePeerDiscoveryNodeId("custody_peer", custody_node_id);
    try pm.updatePeerMetadata(
        "custody_peer",
        1,
        AttnetsBitfield.initEmpty(),
        SyncnetsBitfield.initEmpty(),
        4,
    );

    const custody_columns = pm.getPeer("custody_peer").?.custody_columns.?;
    const missing = [_]u64{custody_columns[0]};

    const selected = (try pm.selectDataColumnPeer(&missing, 64, 64, "preferred_peer", &.{})).?;
    defer allocator.free(selected);

    try std.testing.expectEqualStrings("custody_peer", selected);
}

test "PeerManager: selectDataColumnPeer ignores stale status range for by-root fetches" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, .{});
    defer pm.deinit();

    _ = try pm.onPeerConnected("preferred_peer", .outbound, 1_000);
    pm.db.updatePeerStatus("preferred_peer", [_]u8{0x11} ** 4, [_]u8{0x22} ** 32, 1, 128, [_]u8{0x33} ** 32, 0);
    pm.db.setRelevanceStatus("preferred_peer", .relevant);

    _ = try pm.onPeerConnected("custody_peer", .outbound, 1_000);
    pm.db.updatePeerStatus("custody_peer", [_]u8{0x44} ** 4, [_]u8{0x55} ** 32, 1, 128, [_]u8{0x66} ** 32, 96);
    pm.db.setRelevanceStatus("custody_peer", .relevant);

    const custody_node_id = [_]u8{0x88} ** 32;
    try pm.updatePeerDiscoveryNodeId("custody_peer", custody_node_id);
    try pm.updatePeerMetadata(
        "custody_peer",
        1,
        AttnetsBitfield.initEmpty(),
        SyncnetsBitfield.initEmpty(),
        4,
    );

    const custody_columns = pm.getPeer("custody_peer").?.custody_columns.?;
    const missing = [_]u64{custody_columns[0]};

    const selected = (try pm.selectDataColumnPeer(&missing, 64, 64, "preferred_peer", &.{})).?;
    defer allocator.free(selected);

    try std.testing.expectEqualStrings("custody_peer", selected);
}
