//! Multi-component peer scoring for gossipsub and req/resp.
//!
//! Tracks per-peer scores across multiple dimensions:
//! - Gossip validation outcomes (accept/reject/ignore per topic type)
//! - Req/resp response quality (useful/timeout/error/invalid)
//! - Application-level penalties via PeerAction
//!
//! Integrates with the PeerScore in peer_info.zig (which handles the combined
//! lodestar_score + gossipsub_score and state transitions) by producing score
//! deltas that feed into PeerInfo.peer_score.applyAction().
//!
//! This module serves as the bridge between protocol events (gossip validation,
//! req/resp outcomes) and the peer scoring/management system.
//!
//! Design: see PEER_SCORING_DESIGN.md

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const gossip_validation = @import("gossip_validation.zig");
const ValidationResult = gossip_validation.ValidationResult;
const peer_info_mod = @import("peer_info.zig");
const PeerAction = peer_info_mod.PeerAction;
const ReportSource = peer_info_mod.ReportSource;
const GoodbyeReason = peer_info_mod.GoodbyeReason;

const log = std.log.scoped(.peer_scoring);

// ── Gossip reject reasons ───────────────────────────────────────────────────

/// Reason a gossip message was rejected, used to determine score penalty.
///
/// Different rejection reasons warrant different severity levels.
/// Reference: Lodestar TS gossipHandlers.ts
pub const GossipRejectReason = enum {
    /// Invalid cryptographic signature (BLS verification failed).
    invalid_signature,
    /// Message targets wrong subnet (attestation on wrong subnet).
    wrong_subnet,
    /// Invalid slot — too old or too far in the future.
    invalid_slot,
    /// Invalid block that fails state transition (consensus violation).
    invalid_block,
    /// Invalid attestation (wrong target, bad committee index, etc.).
    invalid_attestation,
    /// Proposer slashing or other slashable offense detected.
    slashable_offense,
    /// Malformed SSZ encoding.
    invalid_ssz,
    /// Generic validation failure not covered above.
    validation_failed,

    /// Map reject reason to PeerAction severity.
    ///
    /// Follows Lodestar TS conventions:
    /// - Consensus violations (invalid blocks, slashable) → fatal
    /// - Crypto failures (bad signatures) → low_tolerance
    /// - Routing errors (wrong subnet) → mid_tolerance
    /// - Timing/minor issues → high_tolerance
    pub fn toPeerAction(self: GossipRejectReason) PeerAction {
        return switch (self) {
            .invalid_block, .slashable_offense => .fatal,
            .invalid_signature, .invalid_ssz => .low_tolerance,
            .wrong_subnet, .invalid_attestation, .validation_failed => .mid_tolerance,
            .invalid_slot => .high_tolerance,
        };
    }
};

// ── Req/resp outcome reasons ────────────────────────────────────────────────

/// Outcome of an outgoing req/resp request, used for scoring the responding peer.
///
/// Reference: Lodestar TS reqresp/score.ts
pub const ReqRespOutcome = enum {
    /// Peer returned a valid, useful response.
    success,
    /// Peer returned an empty response when data was expected.
    empty_response,
    /// Response timed out.
    response_timeout,
    /// Response could not be decoded (invalid SSZ).
    invalid_response,
    /// Peer returned a server error.
    server_error,
    /// Peer returned an unknown error status code.
    unknown_error,
    /// Request too large (SSZ over max size).
    request_too_large,
    /// Dial failed or timed out.
    dial_error,
    /// Peer was rate limited (they told us to slow down).
    rate_limited,
    /// Protocol not supported by peer.
    unsupported_protocol,

    /// Map outcome to optional PeerAction.
    ///
    /// Returns null when no score change is warranted (success, rate_limited from us).
    /// Follows Lodestar TS reqresp/score.ts conventions.
    pub fn toPeerAction(self: ReqRespOutcome) ?PeerAction {
        return switch (self) {
            .success => null, // Positive scoring handled separately
            .invalid_response, .request_too_large => .low_tolerance,
            .server_error, .response_timeout => .mid_tolerance,
            .unknown_error, .empty_response => .high_tolerance,
            .dial_error => .low_tolerance,
            .unsupported_protocol => .low_tolerance,
            .rate_limited => null, // Don't penalize for rate limiting — could be our fault
        };
    }
};

/// Protocol context for req/resp scoring — some outcomes vary by protocol.
pub const ReqRespProtocol = enum {
    status,
    goodbye,
    ping,
    metadata,
    beacon_blocks_by_range,
    beacon_blocks_by_root,
    blob_sidecars_by_range,
    blob_sidecars_by_root,
    data_column_sidecars_by_range,
    data_column_sidecars_by_root,

    /// Whether a timeout on this protocol warrants a stronger penalty.
    /// Ping/Status/Metadata timeouts are worse (these are lightweight protocols).
    pub fn timeoutSeverity(self: ReqRespProtocol) PeerAction {
        return switch (self) {
            .ping, .status, .metadata => .low_tolerance,
            .beacon_blocks_by_range, .beacon_blocks_by_root => .mid_tolerance,
            .blob_sidecars_by_range, .blob_sidecars_by_root => .mid_tolerance,
            .data_column_sidecars_by_range, .data_column_sidecars_by_root => .mid_tolerance,
            .goodbye => .high_tolerance,
        };
    }

    /// Whether unsupported protocol on this type warrants a fatal penalty.
    /// Not supporting Ping is fatal (required base protocol).
    pub fn unsupportedSeverity(self: ReqRespProtocol) PeerAction {
        return switch (self) {
            .ping => .fatal,
            .status, .metadata => .low_tolerance,
            else => .high_tolerance, // Optional protocols
        };
    }
};

// ── Reconnection cool-down ──────────────────────────────────────────────────

/// Calculate reconnection cool-down duration from a Goodbye reason code.
///
/// Returns cool-down duration in milliseconds, or null if no cool-down
/// should be applied (let scoring handle it).
///
/// Reference: Lodestar TS score.ts RealScore.applyReconnectionCoolDown()
pub fn reconnectionCoolDownMs(reason: GoodbyeReason) ?u64 {
    return switch (reason) {
        // Let scoring system handle decay by itself
        .banned, .score_too_low => null,
        // Transient: peer has too many connections, try again soon
        .too_many_peers => 5 * 60 * 1000, // 5 minutes
        // Peer shutting down or generic error
        .client_shutdown, .fault_error => 60 * 60 * 1000, // 60 minutes
        // Wrong network — very long cool-down
        .irrelevant_network, .unable_to_verify => 240 * 60 * 1000, // 4 hours
        // Unknown reason codes — moderate cool-down
        _ => 30 * 60 * 1000, // 30 minutes
    };
}

// ── Per-peer scoring stats ──────────────────────────────────────────────────

/// Detailed scoring statistics tracked per peer.
///
/// Used for diagnostics, metrics, and informed pruning decisions.
/// Complements the PeerScore in peer_info.zig which handles the actual
/// score value and state transitions.
pub const PeerScoringStats = struct {
    // Gossip stats
    gossip_accept_count: u64 = 0,
    gossip_reject_count: u64 = 0,
    gossip_ignore_count: u64 = 0,

    // Req/resp stats
    reqresp_success_count: u64 = 0,
    reqresp_error_count: u64 = 0,
    reqresp_timeout_count: u64 = 0,

    // Rate limiting stats
    rate_limit_hit_count: u64 = 0,

    /// Total interactions (for peer quality assessment).
    pub fn totalInteractions(self: *const PeerScoringStats) u64 {
        return self.gossip_accept_count + self.gossip_reject_count +
            self.gossip_ignore_count + self.reqresp_success_count +
            self.reqresp_error_count + self.reqresp_timeout_count;
    }

    /// Ratio of successful interactions (0.0 to 1.0).
    /// Returns 1.0 if no interactions yet (benefit of the doubt).
    pub fn successRatio(self: *const PeerScoringStats) f64 {
        const total = self.totalInteractions();
        if (total == 0) return 1.0;
        const good: f64 = @floatFromInt(self.gossip_accept_count + self.reqresp_success_count);
        return good / @as(f64, @floatFromInt(total));
    }
};

// ── PeerScoreService ────────────────────────────────────────────────────────

/// Service that bridges protocol events to the peer scoring system.
///
/// This is the primary entry point for all scoring-related events.
/// It maintains per-peer statistics and translates protocol outcomes
/// into PeerAction calls on the PeerDB/PeerManager.
///
/// Usage pattern:
/// ```
/// var service = PeerScoreService.init(allocator);
/// defer service.deinit();
///
/// // On gossip validation result:
/// const action = service.onGossipValidation(peer_id, .reject, .invalid_signature);
/// // action == PeerAction.low_tolerance → caller applies via peer_manager.reportPeer()
///
/// // On req/resp result:
/// const action2 = service.onReqRespResult(peer_id, .response_timeout, .ping);
/// // action2 == PeerAction.low_tolerance
/// ```
pub const PeerScoreService = struct {
    allocator: Allocator,
    /// Per-peer scoring statistics.
    stats: std.StringHashMap(PeerScoringStats),
    /// Aggregate stats across all peers.
    total_gossip_accept: u64 = 0,
    total_gossip_reject: u64 = 0,
    total_gossip_ignore: u64 = 0,
    total_reqresp_success: u64 = 0,
    total_reqresp_error: u64 = 0,

    pub fn init(allocator: Allocator) PeerScoreService {
        return .{
            .allocator = allocator,
            .stats = std.StringHashMap(PeerScoringStats).init(allocator),
        };
    }

    pub fn deinit(self: *PeerScoreService) void {
        // Free owned keys.
        var it = self.stats.keyIterator();
        while (it.next()) |key| {
            self.allocator.free(key.*);
        }
        self.stats.deinit();
    }

    /// Get or create stats entry for a peer. Allocates a copy of peer_id if new.
    fn getOrCreateStats(self: *PeerScoreService, peer_id: []const u8) !*PeerScoringStats {
        const result = try self.stats.getOrPut(peer_id);
        if (!result.found_existing) {
            const owned_id = try self.allocator.dupe(u8, peer_id);
            result.key_ptr.* = owned_id;
            result.value_ptr.* = .{};
        }
        return result.value_ptr;
    }

    /// Record a gossip validation outcome and return the PeerAction to apply (if any).
    ///
    /// - `accept` → null (positive scoring via small boost, tracked in stats)
    /// - `reject` with reason → PeerAction based on severity
    /// - `ignore` → null (no penalty for duplicates)
    ///
    /// The caller is responsible for applying the returned PeerAction via
    /// `peer_manager.reportPeer()`.
    pub fn onGossipValidation(
        self: *PeerScoreService,
        peer_id: []const u8,
        result: ValidationResult,
        reject_reason: ?GossipRejectReason,
    ) !?PeerAction {
        const stats = try self.getOrCreateStats(peer_id);

        switch (result) {
            .accept => {
                stats.gossip_accept_count += 1;
                self.total_gossip_accept += 1;
                return null; // No negative action; positive scoring handled elsewhere
            },
            .reject => {
                stats.gossip_reject_count += 1;
                self.total_gossip_reject += 1;
                const reason = reject_reason orelse .validation_failed;
                const action = reason.toPeerAction();
                log.debug("Gossip reject from {s}: reason={s} action={s}", .{
                    peer_id,
                    @tagName(reason),
                    @tagName(action),
                });
                return action;
            },
            .ignore => {
                stats.gossip_ignore_count += 1;
                self.total_gossip_ignore += 1;
                return null;
            },
        }
    }

    /// Record a req/resp outcome and return the PeerAction to apply (if any).
    ///
    /// Some outcomes are protocol-dependent (e.g., timeouts are more severe
    /// for lightweight protocols like Ping/Status).
    pub fn onReqRespResult(
        self: *PeerScoreService,
        peer_id: []const u8,
        outcome: ReqRespOutcome,
        proto: ReqRespProtocol,
    ) !?PeerAction {
        const stats = try self.getOrCreateStats(peer_id);

        switch (outcome) {
            .success => {
                stats.reqresp_success_count += 1;
                self.total_reqresp_success += 1;
                return null;
            },
            .response_timeout => {
                stats.reqresp_timeout_count += 1;
                self.total_reqresp_error += 1;
                // Timeout severity depends on protocol
                return proto.timeoutSeverity();
            },
            .unsupported_protocol => {
                stats.reqresp_error_count += 1;
                self.total_reqresp_error += 1;
                // Not supporting Ping is fatal
                return proto.unsupportedSeverity();
            },
            else => {
                stats.reqresp_error_count += 1;
                self.total_reqresp_error += 1;
                return outcome.toPeerAction();
            },
        }
    }

    /// Record a rate limit hit for a peer.
    pub fn onRateLimitHit(self: *PeerScoreService, peer_id: []const u8) !void {
        const stats = try self.getOrCreateStats(peer_id);
        stats.rate_limit_hit_count += 1;
    }

    /// Get scoring stats for a peer. Returns null if peer is unknown.
    pub fn getStats(self: *const PeerScoreService, peer_id: []const u8) ?*const PeerScoringStats {
        return self.stats.getPtr(peer_id);
    }

    /// Remove stats for a disconnected peer (to free memory).
    pub fn removePeer(self: *PeerScoreService, peer_id: []const u8) void {
        if (self.stats.fetchRemove(peer_id)) |kv| {
            self.allocator.free(kv.key);
        }
    }

    /// Number of tracked peers.
    pub fn peerCount(self: *const PeerScoreService) usize {
        return self.stats.count();
    }

    /// Prune peers with zero interactions that haven't been seen recently.
    /// Returns number of pruned entries.
    pub fn pruneInactive(self: *PeerScoreService) u32 {
        var to_remove = std.ArrayList([]const u8).init(self.allocator);
        defer to_remove.deinit();

        var it = self.stats.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.totalInteractions() == 0) {
                to_remove.append(entry.key_ptr.*) catch continue;
            }
        }

        var removed: u32 = 0;
        for (to_remove.items) |key| {
            if (self.stats.fetchRemove(key)) |kv| {
                self.allocator.free(kv.key);
                removed += 1;
            }
        }
        return removed;
    }
};

// ── Tests ───────────────────────────────────────────────────────────────────

test "GossipRejectReason: fatal actions for consensus violations" {
    try testing.expectEqual(PeerAction.fatal, GossipRejectReason.invalid_block.toPeerAction());
    try testing.expectEqual(PeerAction.fatal, GossipRejectReason.slashable_offense.toPeerAction());
}

test "GossipRejectReason: low tolerance for crypto failures" {
    try testing.expectEqual(PeerAction.low_tolerance, GossipRejectReason.invalid_signature.toPeerAction());
    try testing.expectEqual(PeerAction.low_tolerance, GossipRejectReason.invalid_ssz.toPeerAction());
}

test "GossipRejectReason: mid tolerance for routing errors" {
    try testing.expectEqual(PeerAction.mid_tolerance, GossipRejectReason.wrong_subnet.toPeerAction());
    try testing.expectEqual(PeerAction.mid_tolerance, GossipRejectReason.invalid_attestation.toPeerAction());
}

test "GossipRejectReason: high tolerance for timing issues" {
    try testing.expectEqual(PeerAction.high_tolerance, GossipRejectReason.invalid_slot.toPeerAction());
}

test "ReqRespOutcome: no penalty for success and rate limiting" {
    try testing.expectEqual(@as(?PeerAction, null), ReqRespOutcome.success.toPeerAction());
    try testing.expectEqual(@as(?PeerAction, null), ReqRespOutcome.rate_limited.toPeerAction());
}

test "ReqRespOutcome: low tolerance for invalid responses" {
    try testing.expectEqual(PeerAction.low_tolerance, ReqRespOutcome.invalid_response.toPeerAction().?);
    try testing.expectEqual(PeerAction.low_tolerance, ReqRespOutcome.request_too_large.toPeerAction().?);
}

test "ReqRespOutcome: mid tolerance for server errors" {
    try testing.expectEqual(PeerAction.mid_tolerance, ReqRespOutcome.server_error.toPeerAction().?);
    try testing.expectEqual(PeerAction.mid_tolerance, ReqRespOutcome.response_timeout.toPeerAction().?);
}

test "ReqRespProtocol: timeout severity varies by protocol" {
    try testing.expectEqual(PeerAction.low_tolerance, ReqRespProtocol.ping.timeoutSeverity());
    try testing.expectEqual(PeerAction.low_tolerance, ReqRespProtocol.status.timeoutSeverity());
    try testing.expectEqual(PeerAction.mid_tolerance, ReqRespProtocol.beacon_blocks_by_range.timeoutSeverity());
}

test "ReqRespProtocol: unsupported ping is fatal" {
    try testing.expectEqual(PeerAction.fatal, ReqRespProtocol.ping.unsupportedSeverity());
    try testing.expectEqual(PeerAction.low_tolerance, ReqRespProtocol.status.unsupportedSeverity());
}

test "reconnectionCoolDownMs: varies by reason" {
    try testing.expectEqual(@as(?u64, null), reconnectionCoolDownMs(.banned));
    try testing.expectEqual(@as(?u64, null), reconnectionCoolDownMs(.score_too_low));
    try testing.expectEqual(@as(?u64, 5 * 60 * 1000), reconnectionCoolDownMs(.too_many_peers));
    try testing.expectEqual(@as(?u64, 60 * 60 * 1000), reconnectionCoolDownMs(.client_shutdown));
    try testing.expectEqual(@as(?u64, 240 * 60 * 1000), reconnectionCoolDownMs(.irrelevant_network));
}

test "PeerScoringStats: success ratio" {
    var stats = PeerScoringStats{};

    // No interactions → 1.0 (benefit of the doubt).
    try testing.expectEqual(@as(f64, 1.0), stats.successRatio());

    // All successes → 1.0.
    stats.gossip_accept_count = 10;
    stats.reqresp_success_count = 5;
    try testing.expectEqual(@as(f64, 1.0), stats.successRatio());

    // Mixed → ratio.
    stats.gossip_reject_count = 5;
    // 15 good / 20 total = 0.75
    try testing.expectEqual(@as(f64, 0.75), stats.successRatio());
}

test "PeerScoreService: gossip accept returns null" {
    var service = PeerScoreService.init(testing.allocator);
    defer service.deinit();

    const action = try service.onGossipValidation("peer1", .accept, null);
    try testing.expectEqual(@as(?PeerAction, null), action);
    try testing.expectEqual(@as(u64, 1), service.total_gossip_accept);

    const stats = service.getStats("peer1").?;
    try testing.expectEqual(@as(u64, 1), stats.gossip_accept_count);
}

test "PeerScoreService: gossip reject returns action" {
    var service = PeerScoreService.init(testing.allocator);
    defer service.deinit();

    const action = try service.onGossipValidation("peer1", .reject, .invalid_block);
    try testing.expectEqual(PeerAction.fatal, action.?);
    try testing.expectEqual(@as(u64, 1), service.total_gossip_reject);
}

test "PeerScoreService: gossip ignore returns null" {
    var service = PeerScoreService.init(testing.allocator);
    defer service.deinit();

    const action = try service.onGossipValidation("peer1", .ignore, null);
    try testing.expectEqual(@as(?PeerAction, null), action);
    try testing.expectEqual(@as(u64, 1), service.total_gossip_ignore);
}

test "PeerScoreService: reqresp success returns null" {
    var service = PeerScoreService.init(testing.allocator);
    defer service.deinit();

    const action = try service.onReqRespResult("peer1", .success, .status);
    try testing.expectEqual(@as(?PeerAction, null), action);
    try testing.expectEqual(@as(u64, 1), service.total_reqresp_success);
}

test "PeerScoreService: reqresp timeout uses protocol severity" {
    var service = PeerScoreService.init(testing.allocator);
    defer service.deinit();

    // Ping timeout → low_tolerance
    const action1 = try service.onReqRespResult("peer1", .response_timeout, .ping);
    try testing.expectEqual(PeerAction.low_tolerance, action1.?);

    // Range timeout → mid_tolerance
    const action2 = try service.onReqRespResult("peer1", .response_timeout, .beacon_blocks_by_range);
    try testing.expectEqual(PeerAction.mid_tolerance, action2.?);
}

test "PeerScoreService: reqresp unsupported ping is fatal" {
    var service = PeerScoreService.init(testing.allocator);
    defer service.deinit();

    const action = try service.onReqRespResult("peer1", .unsupported_protocol, .ping);
    try testing.expectEqual(PeerAction.fatal, action.?);
}

test "PeerScoreService: rate limit tracking" {
    var service = PeerScoreService.init(testing.allocator);
    defer service.deinit();

    try service.onRateLimitHit("peer1");
    try service.onRateLimitHit("peer1");
    try service.onRateLimitHit("peer1");

    const stats = service.getStats("peer1").?;
    try testing.expectEqual(@as(u64, 3), stats.rate_limit_hit_count);
}

test "PeerScoreService: remove peer frees memory" {
    var service = PeerScoreService.init(testing.allocator);
    defer service.deinit();

    _ = try service.onGossipValidation("peer1", .accept, null);
    try testing.expectEqual(@as(usize, 1), service.peerCount());

    service.removePeer("peer1");
    try testing.expectEqual(@as(usize, 0), service.peerCount());
    try testing.expectEqual(@as(?*const PeerScoringStats, null), service.getStats("peer1"));
}

test "PeerScoreService: multiple peers tracked independently" {
    var service = PeerScoreService.init(testing.allocator);
    defer service.deinit();

    _ = try service.onGossipValidation("peer1", .accept, null);
    _ = try service.onGossipValidation("peer1", .accept, null);
    _ = try service.onGossipValidation("peer2", .reject, .invalid_slot);

    try testing.expectEqual(@as(usize, 2), service.peerCount());

    const stats1 = service.getStats("peer1").?;
    try testing.expectEqual(@as(u64, 2), stats1.gossip_accept_count);
    try testing.expectEqual(@as(u64, 0), stats1.gossip_reject_count);

    const stats2 = service.getStats("peer2").?;
    try testing.expectEqual(@as(u64, 0), stats2.gossip_accept_count);
    try testing.expectEqual(@as(u64, 1), stats2.gossip_reject_count);
}

test "PeerScoreService: integrated scoring flow" {
    // Simulate a complete scoring flow:
    // 1. Peer sends valid gossip → accept
    // 2. Peer sends invalid block → fatal reject
    // 3. Req/resp timeout on status → low_tolerance
    var service = PeerScoreService.init(testing.allocator);
    defer service.deinit();

    const peer = "peer_badactor";

    // Step 1: Valid gossip
    const a1 = try service.onGossipValidation(peer, .accept, null);
    try testing.expectEqual(@as(?PeerAction, null), a1);

    // Step 2: Invalid block
    const a2 = try service.onGossipValidation(peer, .reject, .invalid_block);
    try testing.expectEqual(PeerAction.fatal, a2.?);

    // Step 3: Status timeout
    const a3 = try service.onReqRespResult(peer, .response_timeout, .status);
    try testing.expectEqual(PeerAction.low_tolerance, a3.?);

    // Verify stats
    const stats = service.getStats(peer).?;
    try testing.expectEqual(@as(u64, 1), stats.gossip_accept_count);
    try testing.expectEqual(@as(u64, 1), stats.gossip_reject_count);
    try testing.expectEqual(@as(u64, 0), stats.reqresp_success_count);
    try testing.expectEqual(@as(u64, 1), stats.reqresp_timeout_count);
}

// ── Legacy PeerScorer (DEPRECATED) ────────────────────────────────────────
//
// ## Migration path
//
// PeerScorer (this section) is the **legacy** scoring system:
//   - Numeric u64 peer IDs (incompatible with libp2p string peer IDs)
//   - Simple accept/reject/ignore weights only
//   - Used by: ConnectionManager (deprecated), EthGossipAdapter (via optional field)
//
// PeerScoreService (top of this file) is the **current** scoring system:
//   - String peer IDs matching PeerDB and PeerManager
//   - Rich reject reasons (FuturSlot, ParentUnknown, etc.)
//   - Req/resp outcome tracking with per-protocol severity
//   - Decay with configurable half-life
//   - Used by: PeerManager, PeerDB
//
// EthGossipAdapter holds an optional `*PeerScorer` field (`peer_scorer`).
// Once gossip scoring is wired through PeerManager, this field should be
// removed and EthGossipAdapter should call PeerScoreService via a callback.
//
// ConnectionManager also uses PeerScorer. When ConnectionManager is removed,
// PeerScorer can be removed too.

/// Legacy per-peer scorer using numeric peer IDs.
///
/// @deprecated Use PeerScoreService (top of this file) for new code.
/// This type will be removed once ConnectionManager and the EthGossipAdapter
/// legacy scorer path are deleted.
pub const PeerScorer = struct {
    allocator: Allocator,
    scores: std.AutoHashMap(u64, LegacyPeerScore),
    current_slot: u64,
    total_accept: u64,
    total_reject: u64,
    total_ignore: u64,

    pub fn init(allocator: Allocator) PeerScorer {
        return .{
            .allocator = allocator,
            .scores = std.AutoHashMap(u64, LegacyPeerScore).init(allocator),
            .current_slot = 0,
            .total_accept = 0,
            .total_reject = 0,
            .total_ignore = 0,
        };
    }

    pub fn deinit(self: *PeerScorer) void {
        self.scores.deinit();
    }

    pub fn updateSlot(self: *PeerScorer, slot: u64) void {
        self.current_slot = slot;
    }

    pub fn recordValidation(self: *PeerScorer, result: ValidationResult) void {
        switch (result) {
            .accept => self.total_accept += 1,
            .reject => self.total_reject += 1,
            .ignore => self.total_ignore += 1,
        }
    }

    pub fn recordPeerValidation(self: *PeerScorer, peer_id: u64, result: ValidationResult) !void {
        const entry = try self.scores.getOrPut(peer_id);
        if (!entry.found_existing) {
            entry.value_ptr.* = LegacyPeerScore.init();
            entry.value_ptr.last_decay_slot = self.current_slot;
        }

        var peer = entry.value_ptr;
        self.applyDecay(peer);

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

        peer.score = @max(MIN_LEGACY_SCORE, @min(MAX_LEGACY_SCORE, peer.score));
    }

    fn applyDecay(self: *PeerScorer, peer: *LegacyPeerScore) void {
        if (self.current_slot <= peer.last_decay_slot) return;
        const elapsed = self.current_slot - peer.last_decay_slot;
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

    pub fn getScore(self: *PeerScorer, peer_id: u64) f64 {
        const peer = self.scores.getPtr(peer_id) orelse return 0.0;
        self.applyDecay(peer);
        return peer.score;
    }

    pub fn shouldDisconnect(self: *PeerScorer, peer_id: u64) bool {
        return self.getScore(peer_id) < LEGACY_DISCONNECT_THRESHOLD;
    }

    pub fn getPeersToDisconnect(self: *PeerScorer) ![]u64 {
        var result: std.ArrayListUnmanaged(u64) = .empty;
        errdefer result.deinit(self.allocator);

        var it = self.scores.iterator();
        while (it.next()) |entry| {
            self.applyDecay(entry.value_ptr);
            if (entry.value_ptr.score < LEGACY_DISCONNECT_THRESHOLD) {
                try result.append(self.allocator, entry.key_ptr.*);
            }
        }
        return result.toOwnedSlice(self.allocator);
    }

    pub fn removePeer(self: *PeerScorer, peer_id: u64) void {
        _ = self.scores.remove(peer_id);
    }

    pub fn peerCount(self: *const PeerScorer) usize {
        return self.scores.count();
    }
};

const LegacyPeerScore = struct {
    score: f64,
    accept_count: u64,
    reject_count: u64,
    ignore_count: u64,
    last_decay_slot: u64,

    pub fn init() LegacyPeerScore {
        return .{
            .score = 0.0,
            .accept_count = 0,
            .reject_count = 0,
            .ignore_count = 0,
            .last_decay_slot = 0,
        };
    }
};

const ACCEPT_WEIGHT: f64 = 0.5;
const REJECT_WEIGHT: f64 = -10.0;
const IGNORE_WEIGHT: f64 = -0.5;
const DECAY_PER_SLOT: f64 = 0.95;
pub const LEGACY_DISCONNECT_THRESHOLD: f64 = -100.0;
const MIN_LEGACY_SCORE: f64 = -1000.0;
const MAX_LEGACY_SCORE: f64 = 100.0;
