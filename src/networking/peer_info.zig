//! Peer information types for the peer manager.
//!
//! Defines the comprehensive state tracked per peer, including connection
//! state machine, sync status, scoring integration, subnet subscriptions,
//! and ban management.
//!
//! Design informed by Lighthouse's `PeerInfo` and Lodestar's `PeerData`.

const std = @import("std");
const constants = @import("constants");

// ── Constants ───────────────────────────────────────────────────────────────

pub const ATTESTATION_SUBNET_COUNT: u32 = constants.ATTESTATION_SUBNET_COUNT;
pub const SYNC_COMMITTEE_SUBNET_COUNT: u32 = constants.SYNC_COMMITTEE_SUBNET_COUNT;

// ── Connection state machine ────────────────────────────────────────────────

/// Connection state machine.
///
/// Transitions:
///   disconnected → dialing  (we initiate outbound connection)
///   disconnected → connected (inbound connection accepted)
///   dialing      → connected (dial succeeded)
///   dialing      → disconnected (dial failed)
///   connected    → disconnecting (graceful shutdown initiated)
///   disconnecting → disconnected (transport confirmed closed)
///   *            → banned (fatal action or score below threshold)
///   banned       → disconnected (ban expired)
pub const ConnectionState = enum {
    disconnected,
    dialing,
    connected,
    disconnecting,
    banned,

    pub fn isConnected(self: ConnectionState) bool {
        return self == .connected;
    }

    pub fn isDisconnected(self: ConnectionState) bool {
        return self == .disconnected;
    }

    pub fn isBanned(self: ConnectionState) bool {
        return self == .banned;
    }
};

/// Direction of the connection.
pub const ConnectionDirection = enum {
    inbound,
    outbound,
};

// ── Peer actions / penalties ────────────────────────────────────────────────

/// Peer action types, following Lighthouse/Lodestar conventions.
///
/// Score deltas:
///   fatal             → set to MIN_SCORE (-100), immediate ban
///   low_tolerance     → -10.0  (~5 occurrences → ban)
///   mid_tolerance     → -5.0   (~10 occurrences → ban)
///   high_tolerance    → -1.0   (~50 occurrences → ban)
pub const PeerAction = enum {
    /// Immediate disconnect + ban. Wrong network, protocol violation.
    fatal,
    /// Not malicious but intolerable. ~5 → ban. Invalid block, attestation to wrong target.
    low_tolerance,
    /// Moderate penalty. ~10 → ban. Timeout, slow response.
    mid_tolerance,
    /// Minor penalty. ~50 → ban. Useless response, duplicate.
    high_tolerance,

    /// Score delta for this action.
    pub fn scoreDelta(self: PeerAction) f64 {
        return switch (self) {
            .fatal => -100.0, // Straight to MIN_SCORE
            .low_tolerance => -10.0,
            .mid_tolerance => -5.0,
            .high_tolerance => -1.0,
        };
    }
};

/// Source reporting a peer action. Used for logging/metrics.
pub const ReportSource = enum {
    gossipsub,
    rpc,
    processor,
    sync,
    peer_manager,
};

// ── Ban durations ───────────────────────────────────────────────────────────

/// Ban durations in seconds.
pub const BanDuration = enum(u64) {
    /// Short ban: 30 seconds. Transient issues.
    short = 30,
    /// Medium ban: 10 minutes. Repeated bad behavior.
    medium = 600,
    /// Long ban: 1 hour. Serious violations.
    long = 3600,
    /// Permanent ban: 24 hours (effective permanent for session).
    permanent = 86400,

    pub fn seconds(self: BanDuration) u64 {
        return @intFromEnum(self);
    }
};

// ── Score state ─────────────────────────────────────────────────────────────

/// The expected state of the peer given its score.
pub const ScoreState = enum {
    /// Score is healthy. Permit connections and messages.
    healthy,
    /// Score warrants disconnection. Allow reconnection if the peer is persistent.
    disconnected,
    /// Score warrants ban. Disallow new connections until score decays.
    banned,
};

// ── Score constants ─────────────────────────────────────────────────────────

/// Default score for new peers.
pub const DEFAULT_SCORE: f64 = 0.0;
/// Minimum score before forced disconnect.
pub const MIN_SCORE_BEFORE_DISCONNECT: f64 = -20.0;
/// Minimum score before ban.
pub const MIN_SCORE_BEFORE_BAN: f64 = -50.0;
/// Maximum score a peer can obtain.
pub const MAX_SCORE: f64 = 100.0;
/// Minimum score a peer can obtain.
pub const MIN_SCORE: f64 = -100.0;
/// Score halflife in milliseconds (10 minutes).
pub const SCORE_HALFLIFE_MS: f64 = 600_000.0;
/// Pre-computed decay constant: -ln(2) / halflife_ms.
pub const HALFLIFE_DECAY_MS: f64 = -0.6931471805599453 / SCORE_HALFLIFE_MS;
/// Duration in ms that a banned peer's score is frozen before decay begins.
pub const BANNED_BEFORE_DECAY_MS: u64 = 30 * 60 * 1000; // 30 minutes

// ── Subnet bitfields ────────────────────────────────────────────────────────

/// Attestation subnet bitfield — 64 bits for 64 subnets.
pub const AttnetsBitfield = std.StaticBitSet(ATTESTATION_SUBNET_COUNT);

/// Sync committee subnet bitfield — 4 bits for 4 subnets.
pub const SyncnetsBitfield = std.StaticBitSet(SYNC_COMMITTEE_SUBNET_COUNT);

// ── Client identification ───────────────────────────────────────────────────

/// Known client implementations, identified from the agent version string.
pub const ClientKind = enum {
    lighthouse,
    lodestar,
    nimbus,
    prysm,
    teku,
    grandine,
    lodestar_z,
    unknown,

    /// Parse client kind from an agent version string (e.g. "Lighthouse/v4.5.0-...").
    pub fn fromAgentVersion(agent: []const u8) ClientKind {
        if (agent.len == 0) return .unknown;
        if (std.mem.startsWith(u8, agent, "Lighthouse")) return .lighthouse;
        if (std.mem.startsWith(u8, agent, "lodestar-z")) return .lodestar_z;
        if (std.mem.startsWith(u8, agent, "lodestar")) return .lodestar;
        if (std.mem.startsWith(u8, agent, "Nimbus")) return .nimbus;
        if (std.mem.startsWith(u8, agent, "Prysm")) return .prysm;
        if (std.mem.startsWith(u8, agent, "teku")) return .teku;
        if (std.mem.startsWith(u8, agent, "Grandine")) return .grandine;
        return .unknown;
    }
};

// ── GoodbyeReason ───────────────────────────────────────────────────────────

/// Known Goodbye reason codes from the eth2 spec.
pub const GoodbyeReason = enum(u64) {
    /// Client shut down.
    client_shutdown = 1,
    /// Irrelevant network (wrong fork).
    irrelevant_network = 2,
    /// Generic fault/error.
    fault_error = 3,
    /// Unable to verify network (added in later specs).
    unable_to_verify = 128,
    /// Too many peers.
    too_many_peers = 129,
    /// Score too low.
    score_too_low = 250,
    /// Peer banned.
    banned = 251,
    _,
};

// ── SyncInfo ────────────────────────────────────────────────────────────────

/// Sync-relevant data from the Status handshake.
/// Sync target — peer ID + sync info pair used by getBestSyncTarget / getSyncTarget.
pub const SyncTarget = struct {
    peer_id: []const u8,
    sync_info: SyncInfo,
};
pub const SyncInfo = struct {
    head_slot: u64,
    head_root: [32]u8,
    finalized_epoch: u64,
    finalized_root: [32]u8,
};

// ── PeerScore ───────────────────────────────────────────────────────────────

/// Per-peer score with time-based decay.
///
/// Follows the Lighthouse/Lodestar model: a lodestar_score that decays
/// exponentially, combined with a gossipsub score from the router.
pub const PeerScore = struct {
    /// Application-level score (our own assessment).
    lodestar_score: f64 = DEFAULT_SCORE,
    /// Score from the gossipsub router.
    gossipsub_score: f64 = DEFAULT_SCORE,
    /// Whether to ignore negative gossipsub scores.
    ignore_negative_gossipsub: bool = false,
    /// Combined score.
    score: f64 = DEFAULT_SCORE,
    /// Timestamp (ms) of last score update. If in the future, score is frozen (ban cooldown).
    last_updated_ms: u64 = 0,

    /// Recompute the combined score from components.
    pub fn recomputeScore(self: *PeerScore) void {
        self.score = self.lodestar_score;
        // If lodestar score is catastrophically low, ignore gossipsub entirely.
        if (self.lodestar_score <= MIN_SCORE_BEFORE_BAN) return;
        if (self.gossipsub_score >= 0.0) {
            // Weight positive gossipsub scores conservatively.
            self.score += self.gossipsub_score * gossipsubNegativeScoreWeight();
        } else if (!self.ignore_negative_gossipsub) {
            self.score += self.gossipsub_score * gossipsubNegativeScoreWeight();
        }
    }

    /// Apply a peer action's score delta.
    pub fn applyAction(self: *PeerScore, action: PeerAction, now_ms: u64) void {
        switch (action) {
            .fatal => self.setLodestarScore(MIN_SCORE, now_ms),
            else => self.addDelta(action.scoreDelta(), now_ms),
        }
    }

    /// Add a score delta, clamping to bounds.
    pub fn addDelta(self: *PeerScore, delta: f64, now_ms: u64) void {
        var new_score = self.lodestar_score + delta;
        new_score = @max(MIN_SCORE, @min(MAX_SCORE, new_score));
        self.setLodestarScore(new_score, now_ms);
    }

    /// Set the lodestar score, triggering state update.
    fn setLodestarScore(self: *PeerScore, new_score: f64, now_ms: u64) void {
        const was_not_banned = self.score > MIN_SCORE_BEFORE_BAN;
        self.lodestar_score = new_score;
        self.recomputeScore();
        // If transitioning to banned, freeze score for BANNED_BEFORE_DECAY duration.
        if (was_not_banned and self.score <= MIN_SCORE_BEFORE_BAN) {
            self.last_updated_ms = now_ms + BANNED_BEFORE_DECAY_MS;
        }
    }

    /// Apply time-based exponential decay to the lodestar score.
    pub fn decayScore(self: *PeerScore, now_ms: u64) void {
        if (now_ms <= self.last_updated_ms) return; // Still in cooldown.
        const elapsed_ms: f64 = @floatFromInt(now_ms - self.last_updated_ms);
        self.last_updated_ms = now_ms;
        // e^(HALFLIFE_DECAY_MS * elapsed_ms)
        const decay_factor = @exp(HALFLIFE_DECAY_MS * elapsed_ms);
        self.lodestar_score *= decay_factor;
        // Drop tiny values to zero.
        if (@abs(self.lodestar_score) < 0.01) self.lodestar_score = 0.0;
        self.recomputeScore();
    }

    /// Update gossipsub score from the router.
    pub fn updateGossipsubScore(self: *PeerScore, new_gs_score: f64, ignore: bool, now_ms: u64) void {
        // Only update if not in ban cooldown.
        if (self.last_updated_ms <= now_ms) {
            self.gossipsub_score = new_gs_score;
            self.ignore_negative_gossipsub = ignore;
            self.recomputeScore();
        }
    }

    /// Apply a reconnection cool-down period.
    ///
    /// Sets last_updated_ms into the future so that score decay is frozen
    /// for the given duration. This prevents quick reconnection after
    /// a Goodbye with certain reason codes.
    ///
    /// Reference: Lodestar TS score.ts RealScore.applyReconnectionCoolDown()
    pub fn applyReconnectionCoolDown(self: *PeerScore, cool_down_ms: u64, now_ms: u64) void {
        self.last_updated_ms = now_ms + cool_down_ms;
    }

    /// Whether the score is currently in a cool-down period (frozen).
    pub fn isCoolingDown(self: *const PeerScore, now_ms: u64) bool {
        return now_ms < self.last_updated_ms;
    }

    /// Determine the expected state from the current score.
    pub fn state(self: *const PeerScore) ScoreState {
        if (self.score <= MIN_SCORE_BEFORE_BAN) return .banned;
        if (self.score <= MIN_SCORE_BEFORE_DISCONNECT) return .disconnected;
        return .healthy;
    }
};

/// Gossipsub negative score weight. Ensures gossipsub scores alone
/// never push a peer below disconnect threshold.
fn gossipsubNegativeScoreWeight() f64 {
    // This follows Lighthouse/Lodestar: weight = (MIN_SCORE_BEFORE_DISCONNECT + 1) / greylist_threshold
    // Greylist threshold is typically around -16000. We use a conservative approximation.
    // For now, a simple weight that prevents gossipsub from causing disconnects alone.
    return 0.0012;
}

// ── Relevance status ────────────────────────────────────────────────────────

/// Whether a peer has been determined to be on our chain.
pub const RelevanceStatus = enum {
    /// Not yet checked (no Status exchange yet).
    unknown,
    /// Peer passed relevance check — on our chain.
    relevant,
    /// Peer failed relevance check — different chain.
    irrelevant,
};

// ── PeerInfo ────────────────────────────────────────────────────────────────

/// Comprehensive per-peer state.
///
/// Tracks everything the node knows about a peer: connection state, sync
/// status, score, subnet participation, identification, and ban expiry.
pub const PeerInfo = struct {
    /// Connection state machine.
    connection_state: ConnectionState = .disconnected,
    /// Direction of the connection (null if never connected).
    direction: ?ConnectionDirection = null,
    /// Sync status from Status handshake (null if no Status received yet).
    sync_info: ?SyncInfo = null,
    /// Peer score.
    peer_score: PeerScore = .{},
    /// Client identification from Identify protocol.
    client_kind: ClientKind = .unknown,
    /// Raw agent version string (owned, null-terminated for logging).
    agent_version: ?[]const u8 = null,
    /// Attestation subnet subscriptions from ENR or Metadata.
    attnets: AttnetsBitfield = AttnetsBitfield.initEmpty(),
    /// Sync committee subnet subscriptions.
    syncnets: SyncnetsBitfield = SyncnetsBitfield.initEmpty(),
    /// Metadata sequence number from Metadata req/resp.
    metadata_seq: u64 = 0,
    /// Timestamp (ms) when the peer connected.
    connected_at_ms: u64 = 0,
    /// Timestamp (ms) of last message received from this peer.
    last_seen_ms: u64 = 0,
    /// Ban expiry timestamp (ms). Only meaningful when connection_state == .banned.
    ban_expiry_ms: u64 = 0,
    /// Whether this is a trusted/direct peer that should always be reconnected.
    is_trusted: bool = false,
    /// Relevance status from last Status exchange.
    relevance: RelevanceStatus = .unknown,
    /// Last received Status message fields (for periodic re-checks).
    last_status_fork_digest: ?[4]u8 = null,
    last_status_finalized_root: ?[32]u8 = null,
    last_status_finalized_epoch: ?u64 = null,
    last_status_head_slot: ?u64 = null,

    /// Get the combined score.
    pub fn score(self: *const PeerInfo) f64 {
        return self.peer_score.score;
    }

    /// Get the score state (healthy/disconnected/banned).
    pub fn scoreState(self: *const PeerInfo) ScoreState {
        return self.peer_score.state();
    }

    /// Whether this peer is currently connected.
    pub fn isConnected(self: *const PeerInfo) bool {
        return self.connection_state.isConnected();
    }

    /// Whether this peer is banned.
    pub fn isBanned(self: *const PeerInfo) bool {
        return self.connection_state.isBanned();
    }

    /// Head slot from the last Status message, or 0 if unknown.
    pub fn headSlot(self: *const PeerInfo) u64 {
        return if (self.sync_info) |si| si.head_slot else 0;
    }

    /// Finalized epoch from the last Status message, or 0 if unknown.
    pub fn finalizedEpoch(self: *const PeerInfo) u64 {
        return if (self.sync_info) |si| si.finalized_epoch else 0;
    }

    /// Check if the peer is on a specific attestation subnet.
    pub fn onAttestationSubnet(self: *const PeerInfo, subnet_id: u32) bool {
        if (subnet_id >= ATTESTATION_SUBNET_COUNT) return false;
        return self.attnets.isSet(subnet_id);
    }

    /// Check if the peer is on a specific sync committee subnet.
    pub fn onSyncCommitteeSubnet(self: *const PeerInfo, subnet_id: u32) bool {
        if (subnet_id >= SYNC_COMMITTEE_SUBNET_COUNT) return false;
        return self.syncnets.isSet(subnet_id);
    }

    /// Number of attestation subnets this peer covers.
    pub fn attestationSubnetCount(self: *const PeerInfo) u32 {
        return @intCast(self.attnets.count());
    }

    /// Free owned memory (agent_version).
    pub fn deinit(self: *PeerInfo, allocator: std.mem.Allocator) void {
        if (self.agent_version) |av| {
            allocator.free(av);
            self.agent_version = null;
        }
    }
};

// ── Tests ───────────────────────────────────────────────────────────────────

test "ClientKind: parse known agent strings" {
    try std.testing.expectEqual(ClientKind.lighthouse, ClientKind.fromAgentVersion("Lighthouse/v4.5.0-abc123"));
    try std.testing.expectEqual(ClientKind.lodestar, ClientKind.fromAgentVersion("lodestar/v1.20.0/linux-x64"));
    try std.testing.expectEqual(ClientKind.prysm, ClientKind.fromAgentVersion("Prysm/v5.0.0/Go"));
    try std.testing.expectEqual(ClientKind.teku, ClientKind.fromAgentVersion("teku/v24.3.0"));
    try std.testing.expectEqual(ClientKind.nimbus, ClientKind.fromAgentVersion("Nimbus/v24.3.0"));
    try std.testing.expectEqual(ClientKind.grandine, ClientKind.fromAgentVersion("Grandine/v0.4.0"));
    try std.testing.expectEqual(ClientKind.lodestar_z, ClientKind.fromAgentVersion("lodestar-z/0.0.1"));
    try std.testing.expectEqual(ClientKind.unknown, ClientKind.fromAgentVersion(""));
    try std.testing.expectEqual(ClientKind.unknown, ClientKind.fromAgentVersion("SomeRandomClient/1.0"));
}

test "PeerAction: score deltas" {
    try std.testing.expectEqual(@as(f64, -100.0), PeerAction.fatal.scoreDelta());
    try std.testing.expectEqual(@as(f64, -10.0), PeerAction.low_tolerance.scoreDelta());
    try std.testing.expectEqual(@as(f64, -5.0), PeerAction.mid_tolerance.scoreDelta());
    try std.testing.expectEqual(@as(f64, -1.0), PeerAction.high_tolerance.scoreDelta());
}

test "PeerScore: apply action and decay" {
    var ps = PeerScore{};
    ps.last_updated_ms = 0;

    // Apply a mid_tolerance action.
    ps.applyAction(.mid_tolerance, 1000);
    try std.testing.expect(ps.score < 0.0);
    try std.testing.expectEqual(@as(f64, -5.0), ps.lodestar_score);

    // Score should decay toward zero over time.
    const before = ps.lodestar_score;
    ps.decayScore(601_000); // 10 minutes = 1 halflife
    try std.testing.expect(@abs(ps.lodestar_score) < @abs(before));
    // After one halflife, score should be approximately halved.
    try std.testing.expect(@abs(ps.lodestar_score - before / 2.0) < 0.1);
}

test "PeerScore: fatal action triggers ban state" {
    var ps = PeerScore{};
    ps.last_updated_ms = 1000;

    ps.applyAction(.fatal, 1000);
    try std.testing.expectEqual(ScoreState.banned, ps.state());
    try std.testing.expectEqual(@as(f64, -100.0), ps.lodestar_score);
}

test "PeerScore: score clamping" {
    var ps = PeerScore{};

    // Many positive actions should clamp at MAX_SCORE.
    var i: u32 = 0;
    while (i < 200) : (i += 1) {
        ps.addDelta(1.0, 0);
    }
    try std.testing.expect(ps.lodestar_score <= MAX_SCORE);

    // Reset and apply many negatives.
    ps.lodestar_score = 0;
    i = 0;
    while (i < 200) : (i += 1) {
        ps.addDelta(-1.0, 0);
    }
    try std.testing.expect(ps.lodestar_score >= MIN_SCORE);
}

test "PeerInfo: subnet tracking" {
    var info = PeerInfo{};
    try std.testing.expect(!info.onAttestationSubnet(5));

    info.attnets.set(5);
    info.attnets.set(10);
    try std.testing.expect(info.onAttestationSubnet(5));
    try std.testing.expect(info.onAttestationSubnet(10));
    try std.testing.expect(!info.onAttestationSubnet(11));
    try std.testing.expectEqual(@as(u32, 2), info.attestationSubnetCount());
}

test "PeerInfo: sync info access" {
    var info = PeerInfo{};
    try std.testing.expectEqual(@as(u64, 0), info.headSlot());
    try std.testing.expectEqual(@as(u64, 0), info.finalizedEpoch());

    info.sync_info = .{
        .head_slot = 500,
        .head_root = [_]u8{0xAA} ** 32,
        .finalized_epoch = 15,
        .finalized_root = [_]u8{0xBB} ** 32,
    };
    try std.testing.expectEqual(@as(u64, 500), info.headSlot());
    try std.testing.expectEqual(@as(u64, 15), info.finalizedEpoch());
}

test "ConnectionState: state queries" {
    try std.testing.expect(ConnectionState.connected.isConnected());
    try std.testing.expect(!ConnectionState.disconnected.isConnected());
    try std.testing.expect(ConnectionState.disconnected.isDisconnected());
    try std.testing.expect(ConnectionState.banned.isBanned());
    try std.testing.expect(!ConnectionState.connected.isBanned());
}

test "PeerScore: ban cooldown freezes decay" {
    var ps = PeerScore{};
    ps.last_updated_ms = 0;

    // Fatal action at t=1000ms — should freeze until t + BANNED_BEFORE_DECAY_MS.
    ps.applyAction(.fatal, 1000);
    const frozen_until = ps.last_updated_ms;
    try std.testing.expect(frozen_until > 1000);

    // Decay at a time before cooldown expires — score should not change.
    const score_before = ps.lodestar_score;
    ps.decayScore(frozen_until - 1);
    try std.testing.expectEqual(score_before, ps.lodestar_score);

    // Decay after cooldown — score should decay.
    ps.decayScore(frozen_until + 600_000);
    try std.testing.expect(@abs(ps.lodestar_score) < @abs(score_before));
}

test "PeerScore: reconnection cool-down" {
    var ps = PeerScore{};
    ps.last_updated_ms = 1000;

    // Apply 5 minute cool-down.
    ps.applyReconnectionCoolDown(5 * 60 * 1000, 1000);
    try std.testing.expect(ps.isCoolingDown(1000));
    try std.testing.expect(ps.isCoolingDown(100_000));

    // After cool-down expires.
    try std.testing.expect(!ps.isCoolingDown(1000 + 5 * 60 * 1000 + 1));

    // Score should not decay during cool-down.
    ps.lodestar_score = -10.0;
    ps.decayScore(100_000); // Still in cool-down
    try std.testing.expectEqual(@as(f64, -10.0), ps.lodestar_score);

    // After cool-down, decay should work.
    ps.decayScore(1000 + 5 * 60 * 1000 + 600_000); // After cool-down + 10 min
    try std.testing.expect(@abs(ps.lodestar_score) < 10.0);
}
