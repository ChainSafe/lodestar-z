const std = @import("std");
const Allocator = std.mem.Allocator;
const constants = @import("constants.zig");
const types = @import("types.zig");

const PeerScoreData = types.PeerScoreData;
const PeerAction = types.PeerAction;
const GoodbyeReasonCode = types.GoodbyeReasonCode;
const ScoreState = types.ScoreState;
const GossipScoreUpdate = types.GossipScoreUpdate;
const Config = types.Config;

/// Convert a numeric score to a ScoreState.
/// Port of scoreToState from score/utils.ts.
pub fn scoreToState(score: f64) ScoreState {
    if (score <= constants.MIN_SCORE_BEFORE_BAN) return .banned;
    if (score <= constants.MIN_SCORE_BEFORE_DISCONNECT) return .disconnected;
    return .healthy;
}

/// Scoring engine that tracks per-peer scores with exponential decay,
/// gossipsub score blending, reconnection cooldowns, and ban transitions.
/// Port of RealScore (score.ts) + PeerRpcScoreStore (store.ts) + utils.ts.
pub const PeerScorer = struct {
    allocator: Allocator,
    scores: std.StringHashMap(PeerScoreData),
    config: Config,
    /// Injectable clock for deterministic testing. Returns current time in ms.
    clock_fn: *const fn () i64,

    pub fn init(
        allocator: Allocator,
        config: Config,
        clock_fn: *const fn () i64,
    ) PeerScorer {
        return .{
            .allocator = allocator,
            .scores = std.StringHashMap(PeerScoreData).init(allocator),
            .config = config,
            .clock_fn = clock_fn,
        };
    }

    pub fn deinit(self: *PeerScorer) void {
        var it = self.scores.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.scores.deinit();
    }

    // ── Score Mutations ──────────────────────────────────────────────

    /// Port of PeerRpcScoreStore.applyAction (store.ts lines 2428-2435).
    pub fn reportPeer(
        self: *PeerScorer,
        peer_id: []const u8,
        action: PeerAction,
    ) void {
        if (self.config.disable_peer_scoring) return;

        const data = self.getOrCreateScore(peer_id);
        const prev_state = scoreToState(data.score);

        data.lodestar_score += action.scoreDelta();
        data.lodestar_score = clampScore(data.lodestar_score);
        recomputeScore(data, self.config);

        const new_state = scoreToState(data.score);
        if (prev_state != .banned and new_state == .banned) {
            data.last_update_ms = self.clock_fn() + constants.COOL_DOWN_BEFORE_DECAY_MS;
        }
    }

    /// Port of updateGossipsubScores from score/utils.ts (lines 2487-2510).
    pub fn updateGossipScores(
        self: *PeerScorer,
        updates: []const GossipScoreUpdate,
    ) void {
        if (self.config.disable_peer_scoring) return;
        if (updates.len == 0) return;

        // Sort by gossip score descending. We need a mutable copy of the
        // slice indices so we can sort without mutating the caller's data.
        const indices = self.allocator.alloc(usize, updates.len) catch return;
        defer self.allocator.free(indices);
        for (indices, 0..) |*idx, i| idx.* = i;

        const Ctx = struct {
            items: []const GossipScoreUpdate,
            fn lessThan(ctx: @This(), a: usize, b: usize) bool {
                return ctx.items[a].new_score > ctx.items[b].new_score;
            }
        };
        std.mem.sort(usize, indices, Ctx{ .items = updates }, Ctx.lessThan);

        var to_ignore = computeIgnoreCount(self.config);
        for (indices) |idx| {
            const u = updates[idx];
            const ignore = self.shouldIgnoreNegative(u.new_score, &to_ignore);
            self.updateSingleGossipScore(u.peer_id, u.new_score, ignore);
        }
    }

    /// Port of RealScore.applyReconnectionCoolDown (score.ts lines 2218-2239).
    pub fn applyReconnectionCoolDown(
        self: *PeerScorer,
        peer_id: []const u8,
        reason: GoodbyeReasonCode,
    ) i64 {
        if (self.config.disable_peer_scoring) return constants.NO_COOL_DOWN_APPLIED;

        const cooldown_min: i64 = switch (reason) {
            .banned, .score_too_low => return constants.NO_COOL_DOWN_APPLIED,
            .inbound_disconnect, .too_many_peers => 5,
            .@"error", .client_shutdown => 60,
            .irrelevant_network => 240,
            _ => return constants.NO_COOL_DOWN_APPLIED,
        };

        const data = self.getOrCreateScore(peer_id);
        data.last_update_ms = self.clock_fn() + cooldown_min * 60 * 1000;
        return cooldown_min;
    }

    /// Port of PeerRpcScoreStore.update (store.ts lines 2447-2458).
    /// Decays scores and prunes stale entries.
    pub fn decayScores(self: *PeerScorer) void {
        if (self.config.disable_peer_scoring) return;

        self.pruneToMax();

        const now_ms = self.clock_fn();
        var it = self.scores.iterator();
        // Collect keys to remove (cannot remove during iteration).
        var to_remove = std.ArrayList([]const u8).init(self.allocator);
        defer to_remove.deinit();

        while (it.next()) |entry| {
            const data = entry.value_ptr;
            const elapsed = now_ms - data.last_update_ms;
            if (elapsed > 0) {
                data.last_update_ms = now_ms;
                const decay = @exp(constants.HALFLIFE_DECAY_MS *
                    @as(f64, @floatFromInt(elapsed)));
                data.lodestar_score *= decay;
                recomputeScore(data, self.config);
            }
            if (@abs(data.lodestar_score) < constants.SCORE_THRESHOLD) {
                to_remove.append(entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            _ = self.scores.remove(key);
            self.allocator.free(key);
        }
    }

    // ── Queries ──────────────────────────────────────────────────────

    pub fn getScore(self: *const PeerScorer, peer_id: []const u8) f64 {
        if (self.config.disable_peer_scoring) return constants.MAX_SCORE;
        const data = self.scores.get(peer_id) orelse return constants.DEFAULT_SCORE;
        return data.score;
    }

    pub fn getGossipScore(self: *const PeerScorer, peer_id: []const u8) f64 {
        if (self.config.disable_peer_scoring) return constants.DEFAULT_SCORE;
        const data = self.scores.get(peer_id) orelse return constants.DEFAULT_SCORE;
        return data.gossip_score;
    }

    pub fn getScoreState(self: *const PeerScorer, peer_id: []const u8) ScoreState {
        if (self.config.disable_peer_scoring) return .healthy;
        return scoreToState(self.getScore(peer_id));
    }

    pub fn isCoolingDown(self: *const PeerScorer, peer_id: []const u8) bool {
        if (self.config.disable_peer_scoring) return false;
        const data = self.scores.get(peer_id) orelse return false;
        return self.clock_fn() < data.last_update_ms;
    }

    // ── Internal Helpers ─────────────────────────────────────────────

    /// Get or create a score entry, duping the key on first insert.
    fn getOrCreateScore(self: *PeerScorer, peer_id: []const u8) *PeerScoreData {
        const result = self.scores.getOrPut(peer_id) catch
            @panic("PeerScorer: allocation failure in getOrCreateScore");
        if (result.found_existing) return result.value_ptr;

        const owned_key = self.allocator.dupe(u8, peer_id) catch
            @panic("PeerScorer: allocation failure duping key");
        result.key_ptr.* = owned_key;
        result.value_ptr.* = PeerScoreData{ .last_update_ms = self.clock_fn() };
        return result.value_ptr;
    }

    /// Recompute the final score from lodestar + gossip components.
    /// Port of RealScore.recomputeScore (score.ts lines 2310-2322).
    fn recomputeScore(data: *PeerScoreData, config: Config) void {
        data.score = data.lodestar_score;
        if (data.score <= constants.MIN_LODESTAR_SCORE_BEFORE_BAN) return;

        if (data.gossip_score >= 0) {
            data.score += data.gossip_score * config.gossipsub_positive_score_weight;
        } else if (!data.ignore_negative_gossip_score) {
            data.score += data.gossip_score * config.gossipsub_negative_score_weight;
        }
    }

    fn clampScore(score: f64) f64 {
        return @max(constants.MIN_SCORE, @min(constants.MAX_SCORE, score));
    }

    fn computeIgnoreCount(config: Config) usize {
        return @intFromFloat(@floor(
            constants.ALLOWED_NEGATIVE_GOSSIPSUB_FACTOR *
                @as(f64, @floatFromInt(config.target_peers)),
        ));
    }

    fn shouldIgnoreNegative(
        self: *const PeerScorer,
        gossip_score: f64,
        to_ignore: *usize,
    ) bool {
        if (gossip_score < 0 and
            gossip_score > self.config.negative_gossip_score_ignore_threshold and
            to_ignore.* > 0)
        {
            to_ignore.* -= 1;
            return true;
        }
        return false;
    }

    /// Port of RealScore.updateGossipsubScore (score.ts lines 2265-2272).
    fn updateSingleGossipScore(
        self: *PeerScorer,
        peer_id: []const u8,
        new_score: f64,
        ignore: bool,
    ) void {
        const data = self.getOrCreateScore(peer_id);
        // Only update gossip if not cooling down.
        if (data.last_update_ms <= self.clock_fn()) {
            data.gossip_score = new_score;
            data.ignore_negative_gossip_score = ignore;
            recomputeScore(data, self.config);
        }
    }

    /// Prune map to MAX_SCORE_ENTRIES by removing entries with lowest
    /// absolute score first.
    fn pruneToMax(self: *PeerScorer) void {
        if (self.scores.count() <= constants.MAX_SCORE_ENTRIES) return;

        const to_prune = self.scores.count() - constants.MAX_SCORE_ENTRIES;
        const keys = self.allocator.alloc([]const u8, self.scores.count()) catch return;
        defer self.allocator.free(keys);

        var i: usize = 0;
        var it = self.scores.iterator();
        while (it.next()) |entry| : (i += 1) {
            keys[i] = entry.key_ptr.*;
        }

        const Ctx = struct {
            map: *const std.StringHashMap(PeerScoreData),
            fn lessThan(ctx: @This(), a: []const u8, b: []const u8) bool {
                const sa = ctx.map.get(a) orelse return true;
                const sb = ctx.map.get(b) orelse return false;
                return @abs(sa.lodestar_score) < @abs(sb.lodestar_score);
            }
        };
        std.mem.sort([]const u8, keys, Ctx{ .map = &self.scores }, Ctx.lessThan);

        for (keys[0..to_prune]) |key| {
            _ = self.scores.remove(key);
            self.allocator.free(key);
        }
    }
};

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

var test_clock_value: i64 = 0;

fn testClock() i64 {
    return test_clock_value;
}

fn testConfig() Config {
    return .{
        .target_peers = 50,
        .gossipsub_negative_score_weight = 1.0,
        .gossipsub_positive_score_weight = 1.0,
        .negative_gossip_score_ignore_threshold = -100.0,
        .initial_fork_name = .deneb,
    };
}

test "reportPeer fatal results in ban" {
    test_clock_value = 0;
    var scorer = PeerScorer.init(std.testing.allocator, testConfig(), &testClock);
    defer scorer.deinit();

    scorer.reportPeer("peer1", .fatal);
    try std.testing.expectEqual(ScoreState.banned, scorer.getScoreState("peer1"));
}

test "reportPeer score clamping" {
    test_clock_value = 0;
    var scorer = PeerScorer.init(std.testing.allocator, testConfig(), &testClock);
    defer scorer.deinit();

    // Apply many low_tolerance actions — score should never go below MIN_SCORE.
    for (0..50) |_| {
        scorer.reportPeer("peer1", .low_tolerance);
    }
    try std.testing.expect(scorer.getScore("peer1") >= constants.MIN_SCORE);
}

test "decayScores exponential decay" {
    test_clock_value = 0;
    var scorer = PeerScorer.init(std.testing.allocator, testConfig(), &testClock);
    defer scorer.deinit();

    // Set score to -50 via reportPeer actions.
    scorer.reportPeer("peer1", .fatal);
    // Fatal sets score to -200 clamped to -100, but also triggers ban cooldown.
    // Instead, use multiple mid_tolerance to get to -50.
    scorer.deinit();
    scorer = PeerScorer.init(std.testing.allocator, testConfig(), &testClock);

    // 10 * mid_tolerance (-5 each) = -50
    for (0..10) |_| {
        scorer.reportPeer("peer1", .mid_tolerance);
    }
    const initial_score = scorer.scores.get("peer1").?.lodestar_score;
    try std.testing.expectApproxEqAbs(@as(f64, -50.0), initial_score, 0.01);

    // Advance clock by one halflife (10 minutes = 600_000 ms).
    test_clock_value = @intFromFloat(constants.SCORE_HALFLIFE_MS);
    scorer.decayScores();

    const decayed = scorer.scores.get("peer1").?.lodestar_score;
    // After one halflife, score should be approximately halved.
    try std.testing.expectApproxEqAbs(@as(f64, -25.0), decayed, 0.5);
}

test "decayScores does not decay during cooldown" {
    test_clock_value = 0;
    var scorer = PeerScorer.init(std.testing.allocator, testConfig(), &testClock);
    defer scorer.deinit();

    scorer.reportPeer("peer1", .fatal);
    const score_after_ban = scorer.scores.get("peer1").?.lodestar_score;

    // Advance clock by less than COOL_DOWN_BEFORE_DECAY_MS.
    test_clock_value = @divTrunc(constants.COOL_DOWN_BEFORE_DECAY_MS, 2);
    scorer.decayScores();

    const score_during_cooldown = scorer.scores.get("peer1").?.lodestar_score;
    try std.testing.expectEqual(score_after_ban, score_during_cooldown);
}

test "isCoolingDown during ban period" {
    test_clock_value = 0;
    var scorer = PeerScorer.init(std.testing.allocator, testConfig(), &testClock);
    defer scorer.deinit();

    scorer.reportPeer("peer1", .fatal);
    try std.testing.expect(scorer.isCoolingDown("peer1"));

    // Advance past cooldown.
    test_clock_value = constants.COOL_DOWN_BEFORE_DECAY_MS + 1;
    try std.testing.expect(!scorer.isCoolingDown("peer1"));
}

test "applyReconnectionCoolDown reasons" {
    test_clock_value = 0;
    var scorer = PeerScorer.init(std.testing.allocator, testConfig(), &testClock);
    defer scorer.deinit();

    // banned / score_too_low → NO_COOL_DOWN_APPLIED
    try std.testing.expectEqual(
        constants.NO_COOL_DOWN_APPLIED,
        scorer.applyReconnectionCoolDown("p1", .banned),
    );
    try std.testing.expectEqual(
        constants.NO_COOL_DOWN_APPLIED,
        scorer.applyReconnectionCoolDown("p2", .score_too_low),
    );

    // inbound_disconnect → 5 min
    try std.testing.expectEqual(
        @as(i64, 5),
        scorer.applyReconnectionCoolDown("p3", .inbound_disconnect),
    );
    try std.testing.expectEqual(
        @as(i64, 5),
        scorer.applyReconnectionCoolDown("p4", .too_many_peers),
    );

    // error / client_shutdown → 60 min
    try std.testing.expectEqual(
        @as(i64, 60),
        scorer.applyReconnectionCoolDown("p5", .@"error"),
    );
    try std.testing.expectEqual(
        @as(i64, 60),
        scorer.applyReconnectionCoolDown("p6", .client_shutdown),
    );

    // irrelevant_network → 240 min
    try std.testing.expectEqual(
        @as(i64, 240),
        scorer.applyReconnectionCoolDown("p7", .irrelevant_network),
    );
}

test "gossipsub positive score blending" {
    test_clock_value = 0;
    var cfg = testConfig();
    cfg.gossipsub_positive_score_weight = 0.5;
    var scorer = PeerScorer.init(std.testing.allocator, cfg, &testClock);
    defer scorer.deinit();

    // Give peer a small negative lodestar score so it stays above
    // MIN_LODESTAR_SCORE_BEFORE_BAN but gossip still matters.
    scorer.reportPeer("peer1", .high_tolerance); // -1

    const updates = [_]GossipScoreUpdate{
        .{ .peer_id = "peer1", .new_score = 10.0 },
    };
    scorer.updateGossipScores(&updates);

    // score = lodestar(-1) + gossip(10) * weight(0.5) = -1 + 5 = 4
    try std.testing.expectApproxEqAbs(@as(f64, 4.0), scorer.getScore("peer1"), 0.01);
}

test "gossipsub negative score ignored for top peers" {
    test_clock_value = 0;
    var cfg = testConfig();
    cfg.target_peers = 10;
    // ALLOWED_NEGATIVE_GOSSIPSUB_FACTOR = 0.1, so floor(0.1 * 10) = 1 peer ignored
    cfg.negative_gossip_score_ignore_threshold = -50.0;
    cfg.gossipsub_negative_score_weight = 1.0;
    var scorer = PeerScorer.init(std.testing.allocator, cfg, &testClock);
    defer scorer.deinit();

    // Two peers with negative gossip. The one with the higher (less negative)
    // score should be ignored (sorted desc, so -5 comes before -30).
    const updates = [_]GossipScoreUpdate{
        .{ .peer_id = "peerA", .new_score = -5.0 },
        .{ .peer_id = "peerB", .new_score = -30.0 },
    };
    scorer.updateGossipScores(&updates);

    // peerA: score=-5 but ignored → score = 0 (lodestar=0, gossip ignored)
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), scorer.getScore("peerA"), 0.01);
    // peerB: score=-30, not ignored → score = 0 + (-30)*1.0 = -30
    try std.testing.expectApproxEqAbs(@as(f64, -30.0), scorer.getScore("peerB"), 0.01);
}

test "MIN_LODESTAR_SCORE_BEFORE_BAN ignores gossip" {
    test_clock_value = 0;
    var cfg = testConfig();
    cfg.gossipsub_positive_score_weight = 1.0;
    var scorer = PeerScorer.init(std.testing.allocator, cfg, &testClock);
    defer scorer.deinit();

    // Drive lodestar score below -60. Fatal gives -(100 - (-100)) = -200,
    // clamped to -100 which is below -60.
    scorer.reportPeer("peer1", .fatal);

    // Now advance past cooldown and apply positive gossip.
    test_clock_value = constants.COOL_DOWN_BEFORE_DECAY_MS + 1;
    const updates = [_]GossipScoreUpdate{
        .{ .peer_id = "peer1", .new_score = 50.0 },
    };
    scorer.updateGossipScores(&updates);

    // Score should still be -100 (gossip ignored because lodestar <= -60).
    try std.testing.expectApproxEqAbs(@as(f64, -100.0), scorer.getScore("peer1"), 0.01);
}

test "disable_peer_scoring returns MAX_SCORE" {
    test_clock_value = 0;
    var cfg = testConfig();
    cfg.disable_peer_scoring = true;
    var scorer = PeerScorer.init(std.testing.allocator, cfg, &testClock);
    defer scorer.deinit();

    scorer.reportPeer("peer1", .fatal);
    try std.testing.expectEqual(constants.MAX_SCORE, scorer.getScore("peer1"));
    try std.testing.expectEqual(ScoreState.healthy, scorer.getScoreState("peer1"));
    try std.testing.expect(!scorer.isCoolingDown("peer1"));
    // No entry should have been created.
    try std.testing.expectEqual(@as(u32, 0), scorer.scores.count());
}

test "decayScores prunes below threshold" {
    test_clock_value = 0;
    var scorer = PeerScorer.init(std.testing.allocator, testConfig(), &testClock);
    defer scorer.deinit();

    // Apply a small negative score (high_tolerance = -1).
    scorer.reportPeer("peer1", .high_tolerance);
    try std.testing.expect(scorer.scores.contains("peer1"));

    // Advance clock enough for the score to decay below SCORE_THRESHOLD (1.0).
    // -1 * exp(decay * t) → need |result| < 1, so about 1 halflife is plenty.
    test_clock_value = @intFromFloat(constants.SCORE_HALFLIFE_MS);
    scorer.decayScores();

    try std.testing.expect(!scorer.scores.contains("peer1"));
}

test "scoreToState transitions" {
    // Boundary: exactly -50 → banned
    try std.testing.expectEqual(ScoreState.banned, scoreToState(-50.0));
    // Below -50 → banned
    try std.testing.expectEqual(ScoreState.banned, scoreToState(-51.0));
    // Between -50 and -20 → disconnected
    try std.testing.expectEqual(ScoreState.disconnected, scoreToState(-20.0));
    try std.testing.expectEqual(ScoreState.disconnected, scoreToState(-49.9));
    // Above -20 → healthy
    try std.testing.expectEqual(ScoreState.healthy, scoreToState(-19.9));
    try std.testing.expectEqual(ScoreState.healthy, scoreToState(0.0));
    try std.testing.expectEqual(ScoreState.healthy, scoreToState(100.0));
}
