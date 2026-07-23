const std = @import("std");
const Allocator = std.mem.Allocator;
const m = @import("metrics");
const types = @import("types.zig");

/// Defaults to noop metrics, making this safe to use whether or not `init` is
/// called. Recording into a noop metric — and timing while `timing_io` is null —
/// is a no-op, so the peer manager can be exercised (e.g. in unit tests) without
/// any metrics setup.
pub var peer_manager = m.initializeNoop(Metrics);

/// Clock used for duration metrics. Set by `init`; while null, timers are no-ops.
var timing_io: ?std.Io = null;

// ── Label value enums (rendered via @tagName; values mirror the TS metrics) ──

/// Mirrors TS `ScoreState` ("Healthy" | "Disconnected" | "Banned").
pub const ScoreState = enum { Healthy, Disconnected, Banned };

/// Mirrors the TS peers-pruned reasons: the top-of-heartbeat bad-score
/// disconnects (`banned`, `score_too_low`) plus `ExcessPeerDisconnectReason`.
pub const PruneReason = enum {
    banned,
    score_too_low,
    low_score,
    no_long_lived_subnet,
    too_grouped_subnet,
    find_better_peers,
};

/// Mirrors TS `assertPeerRelevance` outcomes (`IrrelevantPeerCode` + "relevant").
pub const RelevanceResult = enum {
    relevant,
    IRRELEVANT_PEER_INCOMPATIBLE_FORKS,
    IRRELEVANT_PEER_DIFFERENT_CLOCKS,
    IRRELEVANT_PEER_DIFFERENT_FINALIZED,
    NO_EARLIEST_AVAILABLE_SLOT,
};

/// Mirrors TS `SubnetType`.
pub const SubnetType = enum { attnets, syncnets };

const ScoreTransitionLabel = struct { from: ScoreState, to: ScoreState };
const PruneReasonLabel = struct { reason: PruneReason };
const RelevanceResultLabel = struct { result: RelevanceResult };
const SubnetTypeLabel = struct { type: SubnetType };

const Metrics = struct {
    prioritize_peers_seconds: Duration,
    score_update_seconds: Duration,
    peers_evaluated_count: PeersEvaluated,
    peers_pruned_total: PrunedVec,
    peers_per_active_subnet: SubnetHistogram,
    outbound_peers_ratio: RatioGauge,
    score_state_transitions_total: TransitionVec,
    score_map_size: SizeGauge,
    connected_peers_map_size: SizeGauge,
    relevance_check_total: RelevanceVec,

    const Duration = m.Histogram(f64, &.{ 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1 });
    const PeersEvaluated = m.Histogram(u32, &.{ 0, 25, 50, 75, 100, 150, 200 });
    const PrunedVec = m.CounterVec(u64, PruneReasonLabel);
    const SubnetHistogram = m.HistogramVec(u32, SubnetTypeLabel, &.{ 0, 2, 4, 6, 8, 12 });
    const RatioGauge = m.Gauge(f64);
    const TransitionVec = m.CounterVec(u64, ScoreTransitionLabel);
    const SizeGauge = m.Gauge(u64);
    const RelevanceVec = m.CounterVec(u64, RelevanceResultLabel);

    /// Deinitializes all `CounterVec`/`HistogramVec` metrics.
    pub fn deinit(self: *Metrics) void {
        self.peers_pruned_total.deinit();
        self.peers_per_active_subnet.deinit();
        self.score_state_transitions_total.deinit();
        self.relevance_check_total.deinit();
    }
};

/// Initializes all peer manager metrics. Requires an allocator (for the labelled
/// metrics) and an `io` (for duration timing). Call once on startup.
pub fn init(allocator: Allocator, io: std.Io, comptime opts: m.RegistryOpts) !void {
    var peers_pruned_total = try Metrics.PrunedVec.init(
        allocator,
        io,
        "lodestar_peer_manager_peers_pruned_total",
        .{ .help = "Total peers the peer manager intends to disconnect, labeled by reason (incl. bad-score and prioritization reasons)" },
        opts,
    );
    errdefer peers_pruned_total.deinit();
    var peers_per_active_subnet = try Metrics.SubnetHistogram.init(
        allocator,
        io,
        "lodestar_peer_manager_peers_per_active_subnet",
        .{ .help = "Histogram of connected peer count per active subnet, labeled by subnet type" },
        opts,
    );
    errdefer peers_per_active_subnet.deinit();
    var score_state_transitions_total = try Metrics.TransitionVec.init(
        allocator,
        io,
        "lodestar_peer_score_state_transitions_total",
        .{ .help = "Total peer score state transitions, labeled by from and to state (Healthy/Disconnected/Banned)" },
        opts,
    );
    errdefer score_state_transitions_total.deinit();
    var relevance_check_total = try Metrics.RelevanceVec.init(
        allocator,
        io,
        "lodestar_peer_relevance_check_total",
        .{ .help = "Total peer relevance checks on Status, labeled by result (relevant or irrelevant reason code)" },
        opts,
    );
    errdefer relevance_check_total.deinit();

    peer_manager = .{
        .prioritize_peers_seconds = Metrics.Duration.init(
            "lodestar_peer_manager_prioritize_peers_seconds",
            .{ .help = "prioritizePeers function duration in seconds, the core peer selection/pruning algorithm" },
            opts,
        ),
        .score_update_seconds = Metrics.Duration.init(
            "lodestar_peer_score_update_seconds",
            .{ .help = "Peer score store update (decay + prune over all peers) duration in seconds" },
            opts,
        ),
        .peers_evaluated_count = Metrics.PeersEvaluated.init(
            "lodestar_peer_manager_peers_evaluated_count",
            .{ .help = "Number of connected healthy peers evaluated by prioritizePeers per heartbeat, denominator for prioritize_peers_seconds" },
            opts,
        ),
        .peers_pruned_total = peers_pruned_total,
        .peers_per_active_subnet = peers_per_active_subnet,
        .outbound_peers_ratio = Metrics.RatioGauge.init(
            "lodestar_peer_manager_outbound_peers_ratio",
            .{ .help = "Ratio of outbound peers to total connected healthy peers, verifies the outbound peers invariant" },
            opts,
        ),
        .score_state_transitions_total = score_state_transitions_total,
        .score_map_size = Metrics.SizeGauge.init(
            "lodestar_peer_manager_score_map_size",
            .{ .help = "Current number of entries in the peer score store" },
            opts,
        ),
        .connected_peers_map_size = Metrics.SizeGauge.init(
            "lodestar_peer_manager_connected_peers_map_size",
            .{ .help = "Current number of entries in the peer manager connectedPeers map" },
            opts,
        ),
        .relevance_check_total = relevance_check_total,
    };

    timing_io = io;
}

/// Writes all peer manager metrics to `writer`.
pub fn write(writer: *std.Io.Writer) !void {
    try m.write(&peer_manager, writer);
}

/// Releases labelled-metric resources and reverts to noop.
pub fn deinit() void {
    peer_manager.deinit();
    peer_manager = m.initializeNoop(Metrics);
    timing_io = null;
}

// ── Timing ───────────────────────────────────────────────────────────

/// A monotonic start point. `elapsedSeconds` is null when metrics timing is
/// disabled (no `io`), so callers no-op cleanly.
pub const Timer = struct {
    start_ns: ?i128 = null,

    pub fn elapsedSeconds(self: Timer) ?f64 {
        const start = self.start_ns orelse return null;
        const now = nowNs() orelse return null;
        return @as(f64, @floatFromInt(now - start)) / std.time.ns_per_s;
    }
};

fn nowNs() ?i128 {
    const io = timing_io orelse return null;
    return std.Io.Timestamp.now(io, .awake).toNanoseconds();
}

pub fn startTimer() Timer {
    return .{ .start_ns = nowNs() };
}

// ── Recording helpers (safe no-ops while noop / disabled) ────────────

pub fn observePrioritizeDuration(timer: Timer) void {
    const seconds = timer.elapsedSeconds() orelse return;
    peer_manager.prioritize_peers_seconds.observe(seconds);
}

pub fn observeScoreUpdateDuration(timer: Timer) void {
    const seconds = timer.elapsedSeconds() orelse return;
    peer_manager.score_update_seconds.observe(seconds);
}

pub fn observePeersEvaluated(count: u32) void {
    peer_manager.peers_evaluated_count.observe(count);
}

pub fn observePeersPerSubnet(subnet_type: SubnetType, count: u32) void {
    peer_manager.peers_per_active_subnet.observe(.{ .type = subnet_type }, count) catch {};
}

pub fn recordPeerPruned(reason: PruneReason) void {
    peer_manager.peers_pruned_total.incr(.{ .reason = reason }) catch {};
}

pub fn recordScoreStateTransition(from: ScoreState, to: ScoreState) void {
    peer_manager.score_state_transitions_total.incr(.{ .from = from, .to = to }) catch {};
}

pub fn recordRelevanceCheck(result: RelevanceResult) void {
    peer_manager.relevance_check_total.incr(.{ .result = result }) catch {};
}

pub fn setOutboundPeersRatio(ratio: f64) void {
    peer_manager.outbound_peers_ratio.set(ratio);
}

pub fn setScoreMapSize(size: u64) void {
    peer_manager.score_map_size.set(size);
}

pub fn setConnectedPeersMapSize(size: u64) void {
    peer_manager.connected_peers_map_size.set(size);
}

// ── Mapping from internal enums to label enums ───────────────────────

pub fn scoreStateLabel(state: types.ScoreState) ScoreState {
    return switch (state) {
        .healthy => .Healthy,
        .disconnected => .Disconnected,
        .banned => .Banned,
    };
}

pub fn relevanceResultLabel(result: types.IrrelevantPeerResult) RelevanceResult {
    return switch (result) {
        .incompatible_forks => .IRRELEVANT_PEER_INCOMPATIBLE_FORKS,
        .different_clocks => .IRRELEVANT_PEER_DIFFERENT_CLOCKS,
        .different_finalized => .IRRELEVANT_PEER_DIFFERENT_FINALIZED,
        .no_earliest_available_slot => .NO_EARLIEST_AVAILABLE_SLOT,
    };
}

pub fn pruneReasonFromExcess(reason: types.ExcessPeerDisconnectReason) PruneReason {
    return switch (reason) {
        .low_score => .low_score,
        .no_long_lived_subnet => .no_long_lived_subnet,
        .too_grouped_subnet => .too_grouped_subnet,
        .find_better_peers => .find_better_peers,
    };
}
