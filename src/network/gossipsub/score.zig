const std = @import("std");
const constants = @import("constants.zig");

const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// Per-topic scoring weights and decays. Ethereum derives these from expected
/// message rates; the registry slice supplies the real values, and these
/// defaults keep the mechanism testable.
pub const TopicParams = struct {
    weight: f64 = 1.0,
    time_in_mesh_weight: f64 = 0.03,
    time_in_mesh_cap: f64 = 300.0,
    time_in_mesh_quantum_ms: u64 = 1_000,
    first_delivery_weight: f64 = 1.0,
    first_delivery_cap: f64 = 100.0,
    first_delivery_decay: f64 = 0.9,
    mesh_delivery_weight: f64 = -1.0,
    mesh_delivery_threshold: f64 = 5.0,
    mesh_delivery_cap: f64 = 50.0,
    mesh_delivery_decay: f64 = 0.9,
    mesh_delivery_activation_ms: u64 = 30_000,
    mesh_failure_weight: f64 = -1.0,
    mesh_failure_decay: f64 = 0.9,
    invalid_weight: f64 = -100.0,
    invalid_decay: f64 = 0.9,
};

/// Global weights, thresholds, and decay cadence.
pub const Params = struct {
    app_weight: f64 = 1.0,
    behaviour_weight: f64 = -10.0,
    behaviour_threshold: f64 = 6.0,
    behaviour_decay: f64 = 0.9,
    topic_cap: f64 = 3200.0,
    decay_interval_ms: u64 = 12_000,
    decay_to_zero: f64 = 0.01,
    gossip_threshold: f64 = -4000.0,
    publish_threshold: f64 = -8000.0,
    graylist_threshold: f64 = -16000.0,
    accept_px_threshold: f64 = 100.0,
    opportunistic_graft_threshold: f64 = 5.0,
    topic: TopicParams = .{},
};

/// The Ethereum-tuned baseline: the thresholds follow Lighthouse's shipped
/// values, and the default per-topic params are a sane starting point a host
/// refines from the expected per-topic message rates (as Lighthouse derives
/// them in gossipsub_scoring_parameters.rs).
pub fn ethereum() Params {
    return .{};
}

const TopicCounters = struct {
    in_mesh: bool = false,
    graft_ms: u64 = 0,
    first_deliveries: f64 = 0,
    mesh_deliveries: f64 = 0,
    mesh_failures: f64 = 0,
    invalid: f64 = 0,
};

pub const PeerScore = struct {
    params: Params,
    topics: []TopicCounters,
    app_score: []f64,
    behaviour: []f64,
    last_decay_ms: u64 = 0,

    pub fn init(allocator: Allocator, params: Params) Allocator.Error!PeerScore {
        const cells = constants.peers_cap * constants.topics_cap;
        const topics = try allocator.alloc(TopicCounters, cells);
        errdefer allocator.free(topics);
        @memset(topics, .{});
        const app_score = try allocator.alloc(f64, constants.peers_cap);
        errdefer allocator.free(app_score);
        @memset(app_score, 0);
        const behaviour = try allocator.alloc(f64, constants.peers_cap);
        errdefer allocator.free(behaviour);
        @memset(behaviour, 0);
        return .{
            .params = params,
            .topics = topics,
            .app_score = app_score,
            .behaviour = behaviour,
        };
    }

    pub fn deinit(self: *PeerScore, allocator: Allocator) void {
        allocator.free(self.behaviour);
        allocator.free(self.app_score);
        allocator.free(self.topics);
        self.* = undefined;
    }

    fn tc(self: *PeerScore, peer: u16, topic: u16) *TopicCounters {
        const index = @as(usize, peer) * constants.topics_cap + topic;
        assert(index < self.topics.len);
        return &self.topics[index];
    }

    /// Clears every counter for a peer whose slot is being reused.
    pub fn resetPeer(self: *PeerScore, peer: u16) void {
        const base = @as(usize, peer) * constants.topics_cap;
        @memset(self.topics[base..][0..constants.topics_cap], .{});
        self.app_score[peer] = 0;
        self.behaviour[peer] = 0;
    }

    pub fn graft(self: *PeerScore, peer: u16, topic: u16, now_ms: u64) void {
        const counters = self.tc(peer, topic);
        counters.in_mesh = true;
        counters.graft_ms = now_ms;
    }

    pub fn prune(self: *PeerScore, peer: u16, topic: u16, now_ms: u64) void {
        const counters = self.tc(peer, topic);
        if (!counters.in_mesh) return;
        const params = self.params.topic;
        const elapsed = now_ms -| counters.graft_ms;
        if (elapsed >= params.mesh_delivery_activation_ms and
            counters.mesh_deliveries < params.mesh_delivery_threshold)
        {
            const deficit = params.mesh_delivery_threshold - counters.mesh_deliveries;
            counters.mesh_failures += deficit * deficit;
        }
        counters.in_mesh = false;
    }

    /// A first-seen valid message from `peer` on `topic`: rewards first delivery
    /// and counts toward the mesh delivery rate.
    pub fn deliver(self: *PeerScore, peer: u16, topic: u16) void {
        const counters = self.tc(peer, topic);
        counters.first_deliveries += 1;
        if (counters.in_mesh) counters.mesh_deliveries += 1;
    }

    /// A duplicate from a mesh peer still counts toward its mesh delivery rate.
    pub fn duplicate(self: *PeerScore, peer: u16, topic: u16) void {
        const counters = self.tc(peer, topic);
        if (counters.in_mesh) counters.mesh_deliveries += 1;
    }

    pub fn invalid(self: *PeerScore, peer: u16, topic: u16) void {
        self.tc(peer, topic).invalid += 1;
    }

    pub fn penalize(self: *PeerScore, peer: u16, amount: f64) void {
        self.behaviour[peer] += amount;
    }

    pub fn setAppScore(self: *PeerScore, peer: u16, value: f64) void {
        self.app_score[peer] = value;
    }

    pub fn score(self: *PeerScore, peer: u16, now_ms: u64) f64 {
        var total: f64 = 0;
        const params = &self.params.topic;
        var topic: usize = 0;
        while (topic < constants.topics_cap) : (topic += 1) {
            const counters = &self.topics[@as(usize, peer) * constants.topics_cap + topic];
            if (!counters.in_mesh and counters.first_deliveries == 0 and
                counters.mesh_failures == 0 and counters.invalid == 0) continue;
            var topic_score: f64 = 0;
            const elapsed: u64 = if (counters.in_mesh) now_ms -| counters.graft_ms else 0;
            if (counters.in_mesh) {
                const p1 = @min(
                    @as(f64, @floatFromInt(elapsed / params.time_in_mesh_quantum_ms)),
                    params.time_in_mesh_cap,
                );
                topic_score += params.time_in_mesh_weight * p1;
            }
            topic_score += params.first_delivery_weight *
                @min(counters.first_deliveries, params.first_delivery_cap);
            if (counters.in_mesh and elapsed >= params.mesh_delivery_activation_ms and
                counters.mesh_deliveries < params.mesh_delivery_threshold)
            {
                const deficit = params.mesh_delivery_threshold - counters.mesh_deliveries;
                topic_score += params.mesh_delivery_weight * deficit * deficit;
            }
            topic_score += params.mesh_failure_weight * counters.mesh_failures;
            topic_score += params.invalid_weight * counters.invalid * counters.invalid;
            total += params.weight * topic_score;
        }
        if (self.params.topic_cap > 0 and total > self.params.topic_cap) {
            total = self.params.topic_cap;
        }
        total += self.params.app_weight * self.app_score[peer];
        if (self.behaviour[peer] > self.params.behaviour_threshold) {
            const excess = self.behaviour[peer] - self.params.behaviour_threshold;
            total += self.params.behaviour_weight * excess * excess;
        }
        return total;
    }

    pub fn refresh(self: *PeerScore, now_ms: u64) void {
        if (self.last_decay_ms == 0) {
            self.last_decay_ms = now_ms;
            return;
        }
        var steps: u32 = 0;
        while (now_ms -| self.last_decay_ms >= self.params.decay_interval_ms and
            steps < max_decay_steps) : (steps += 1)
        {
            self.last_decay_ms += self.params.decay_interval_ms;
            self.applyDecay();
        }
        if (now_ms -| self.last_decay_ms >= self.params.decay_interval_ms) {
            self.last_decay_ms = now_ms;
        }
    }

    fn applyDecay(self: *PeerScore) void {
        const zero = self.params.decay_to_zero;
        const tp = self.params.topic;
        for (self.topics) |*c| {
            c.first_deliveries = decayed(c.first_deliveries, tp.first_delivery_decay, zero);
            c.mesh_deliveries = decayed(c.mesh_deliveries, tp.mesh_delivery_decay, zero);
            c.mesh_failures = decayed(c.mesh_failures, tp.mesh_failure_decay, zero);
            c.invalid = decayed(c.invalid, tp.invalid_decay, zero);
        }
        for (self.behaviour) |*value| {
            value.* = decayed(value.*, self.params.behaviour_decay, zero);
        }
    }
};

const max_decay_steps: u32 = 64;

fn decayed(value: f64, decay: f64, zero: f64) f64 {
    const next = value * decay;
    return if (next < zero) 0 else next;
}

test "score rewards deliveries and punishes invalid messages" {
    var score = try PeerScore.init(std.testing.allocator, .{});
    defer score.deinit(std.testing.allocator);

    score.graft(1, 0, 0);
    score.deliver(1, 0);
    score.deliver(1, 0);
    try std.testing.expect(score.score(1, 1_000) > 0);

    score.invalid(2, 0);
    try std.testing.expect(score.score(2, 1_000) < 0);
}

test "score crosses the graylist threshold on repeated invalid messages" {
    var score = try PeerScore.init(std.testing.allocator, .{});
    defer score.deinit(std.testing.allocator);
    var n: usize = 0;
    while (n < 20) : (n += 1) score.invalid(1, 0);
    try std.testing.expect(score.score(1, 0) < score.params.graylist_threshold);
}

test "score decays counters toward zero over intervals" {
    var score = try PeerScore.init(std.testing.allocator, .{});
    defer score.deinit(std.testing.allocator);
    score.deliver(1, 0);
    const before = score.score(1, 0);
    score.refresh(0); // primes last_decay
    var now: u64 = 0;
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        now += score.params.decay_interval_ms;
        score.refresh(now);
    }
    const after = score.score(1, now);
    try std.testing.expect(after < before);
    try std.testing.expect(@abs(after) < @abs(before));
}

test "score resets when a peer slot is reused" {
    var score = try PeerScore.init(std.testing.allocator, .{});
    defer score.deinit(std.testing.allocator);
    score.invalid(1, 0);
    try std.testing.expect(score.score(1, 0) < 0);
    score.resetPeer(1);
    try std.testing.expectEqual(@as(f64, 0), score.score(1, 0));
}
