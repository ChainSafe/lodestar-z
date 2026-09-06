const std = @import("std");
const constants = @import("constants.zig");

const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// Generic defaults. Hosts copy independently tuned parameters for each topic.
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
    mesh_delivery_window_ms: u64 = 10,
    mesh_failure_weight: f64 = -1.0,
    mesh_failure_decay: f64 = 0.9,
    invalid_weight: f64 = -100.0,
    invalid_decay: f64 = 0.9,
};

/// Global weights, thresholds, and decay cadence.
pub const Params = struct {
    app_weight: f64 = 1.0,
    ip_colocation_weight: f64 = 0,
    ip_colocation_threshold: u16 = 3,
    behaviour_weight: f64 = -10.0,
    behaviour_threshold: f64 = 6.0,
    behaviour_decay: f64 = 0.9,
    topic_cap: f64 = 3200.0,
    decay_interval_ms: u64 = 12_000,
    decay_to_zero: f64 = 0.01,
    gossip_threshold: f64 = -4000.0,
    publish_threshold: f64 = -8000.0,
    graylist_threshold: f64 = -16000.0,
    opportunistic_graft_threshold: f64 = 5.0,
    topic: TopicParams = .{},
};

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
    topic_params: [constants.topics_cap]TopicParams,
    connected: [peer_capacity]bool = [_]bool{true} ** peer_capacity,
    last_decay_ms: [peer_capacity]?u64 = [_]?u64{null} ** peer_capacity,
    dirty: [peer_capacity]bool = [_]bool{true} ** peer_capacity,
    cached_at: [peer_capacity]?u64 = [_]?u64{null} ** peer_capacity,
    cached: [peer_capacity]f64 = [_]f64{0} ** peer_capacity,
    cached_ip: [peer_capacity]u16 = [_]u16{0} ** peer_capacity,
    ip_count: [peer_capacity]u16 = [_]u16{0} ** peer_capacity,

    pub fn init(allocator: Allocator, params: Params) (Allocator.Error || error{InvalidLimits})!PeerScore {
        return initCapacity(allocator, params, peer_capacity);
    }

    pub fn initCapacity(allocator: Allocator, params: Params, count: u16) (Allocator.Error || error{InvalidLimits})!PeerScore {
        if (count == 0 or count > peer_capacity) return error.InvalidLimits;
        try validateParams(params);
        const cells = @as(usize, count) * constants.topics_cap;
        const topics = try allocator.alloc(TopicCounters, cells);
        errdefer allocator.free(topics);
        @memset(topics, .{});
        const app_score = try allocator.alloc(f64, count);
        errdefer allocator.free(app_score);
        @memset(app_score, 0);
        const behaviour = try allocator.alloc(f64, count);
        errdefer allocator.free(behaviour);
        @memset(behaviour, 0);
        return .{
            .params = params,
            .topic_params = [_]TopicParams{params.topic} ** constants.topics_cap,
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
        self.dirty[peer] = true;
        return &self.topics[index];
    }

    /// Clears every counter for a peer whose slot is being reused.
    pub fn resetPeer(self: *PeerScore, peer: u16) void {
        self.dirty[peer] = true;
        const base = @as(usize, peer) * constants.topics_cap;
        @memset(self.topics[base..][0..constants.topics_cap], .{});
        self.app_score[peer] = 0;
        self.behaviour[peer] = 0;
    }

    pub fn graft(self: *PeerScore, peer: u16, topic: u16, now_ms: u64) void {
        const counters = self.tc(peer, topic);
        if (counters.in_mesh) return;
        counters.in_mesh = true;
        counters.graft_ms = now_ms;
    }

    pub fn prune(self: *PeerScore, peer: u16, topic: u16, now_ms: u64) void {
        const counters = self.tc(peer, topic);
        if (!counters.in_mesh) return;
        const params = self.topic_params[topic];
        const elapsed = now_ms -| counters.graft_ms;
        if (elapsed >= params.mesh_delivery_activation_ms and
            counters.mesh_deliveries < params.mesh_delivery_threshold)
        {
            const deficit = params.mesh_delivery_threshold - counters.mesh_deliveries;
            counters.mesh_failures = @min(counter_max, counters.mesh_failures + deficit * deficit);
        }
        counters.in_mesh = false;
    }

    /// A first-seen valid message from `peer` on `topic`: rewards first delivery
    /// and counts toward the mesh delivery rate.
    pub fn deliver(self: *PeerScore, peer: u16, topic: u16) void {
        self.deliverEligible(peer, topic, self.tc(peer, topic).in_mesh);
    }

    pub fn deliverEligible(self: *PeerScore, peer: u16, topic: u16, mesh_eligible: bool) void {
        const counters = self.tc(peer, topic);
        const params = self.topic_params[topic];
        counters.first_deliveries = @min(counters.first_deliveries + 1, params.first_delivery_cap);
        if (mesh_eligible) self.creditMesh(peer, topic);
    }

    pub fn creditMesh(self: *PeerScore, peer: u16, topic: u16) void {
        const counters = self.tc(peer, topic);
        counters.mesh_deliveries = @min(counters.mesh_deliveries + 1, self.topic_params[topic].mesh_delivery_cap);
    }

    /// A duplicate from a mesh peer still counts toward its mesh delivery rate.
    pub fn duplicate(self: *PeerScore, peer: u16, topic: u16) void {
        const counters = self.tc(peer, topic);
        const cap = self.topic_params[topic].mesh_delivery_cap;
        if (counters.in_mesh) counters.mesh_deliveries = @min(counters.mesh_deliveries + 1, cap);
    }

    pub fn invalid(self: *PeerScore, peer: u16, topic: u16) void {
        const c = self.tc(peer, topic);
        c.invalid = @min(counter_max, c.invalid + 1);
    }

    pub fn penalize(self: *PeerScore, peer: u16, amount: f64) void {
        assert(safeMagnitude(amount) and amount >= 0);
        self.dirty[peer] = true;
        self.behaviour[peer] = @min(counter_max, self.behaviour[peer] + amount);
    }

    pub fn setAppScore(self: *PeerScore, peer: u16, value: f64) bool {
        if (!safeMagnitude(value)) return false;
        self.dirty[peer] = true;
        self.app_score[peer] = value;
        return true;
    }

    pub fn score(self: *PeerScore, peer: u16, now_ms: u64) f64 {
        if (!self.dirty[peer] and self.cached_at[peer] == now_ms and self.cached_ip[peer] == self.ip_count[peer]) return self.cached[peer];
        var total: f64 = 0;
        var topic: usize = 0;
        while (topic < constants.topics_cap) : (topic += 1) {
            const params = &self.topic_params[topic];
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
        const excess_ip: f64 = @floatFromInt(self.ip_count[peer] -| self.params.ip_colocation_threshold);
        total += self.params.ip_colocation_weight * excess_ip * excess_ip;
        assert(std.math.isFinite(total));
        self.dirty[peer] = false;
        self.cached_at[peer] = now_ms;
        self.cached_ip[peer] = self.ip_count[peer];
        self.cached[peer] = total;
        return total;
    }

    pub fn resetTopic(self: *PeerScore, topic: u16) void {
        for (0..self.app_score.len) |peer| {
            const counters = self.tc(@intCast(peer), topic);
            assert(!counters.in_mesh);
            counters.* = .{};
        }
    }

    pub fn retainsTopic(self: *PeerScore, topic: u16) bool {
        for (0..self.app_score.len) |peer| {
            const counters = self.tc(@intCast(peer), topic);
            if (counters.in_mesh or counters.first_deliveries != 0 or counters.mesh_deliveries != 0 or
                counters.mesh_failures != 0 or counters.invalid != 0) return true;
        }
        return false;
    }

    pub fn configureTopic(self: *PeerScore, topic: u16, params: TopicParams) error{InvalidLimits}!void {
        assert(topic < constants.topics_cap);
        try validateTopic(params);
        self.topic_params[topic] = params;
        @memset(&self.dirty, true);
    }

    pub fn setConnected(self: *PeerScore, peer: u16, connected: bool, now_ms: u64) void {
        assert(peer < self.app_score.len);
        self.refreshPeer(peer, now_ms);
        self.dirty[peer] = true;
        self.connected[peer] = connected;
        self.last_decay_ms[peer] = now_ms;
    }

    pub fn refresh(self: *PeerScore, now_ms: u64) void {
        for (0..self.app_score.len) |peer| self.refreshPeer(@intCast(peer), now_ms);
    }

    fn refreshPeer(self: *PeerScore, peer: u16, now_ms: u64) void {
        if (!self.connected[peer]) return;
        const last = self.last_decay_ms[peer] orelse {
            self.last_decay_ms[peer] = now_ms;
            return;
        };
        const steps = (now_ms -| last) / self.params.decay_interval_ms;
        if (steps == 0) return;
        self.last_decay_ms[peer] = last + steps * self.params.decay_interval_ms;
        self.decayPeer(peer, steps);
    }

    fn decayPeer(self: *PeerScore, peer: u16, steps: u64) void {
        const zero = self.params.decay_to_zero;
        for (0..constants.topics_cap) |topic| {
            const c = self.tc(peer, @intCast(topic));
            const tp = self.topic_params[topic];
            c.first_deliveries = decayed(c.first_deliveries, tp.first_delivery_decay, steps, zero);
            c.mesh_deliveries = decayed(c.mesh_deliveries, tp.mesh_delivery_decay, steps, zero);
            c.mesh_failures = decayed(c.mesh_failures, tp.mesh_failure_decay, steps, zero);
            c.invalid = decayed(c.invalid, tp.invalid_decay, steps, zero);
        }
        self.behaviour[peer] = decayed(self.behaviour[peer], self.params.behaviour_decay, steps, zero);
    }
};

pub const peer_capacity = 512;
// Each squared counter is at most 1e12, each weighted topic at most 1e24.
// Summing 512 topic terms and global terms remains far below f64 overflow.
pub const counter_max: f64 = 1_000_000;

fn safeMagnitude(value: f64) bool {
    return std.math.isFinite(value) and @abs(value) <= counter_max;
}

pub fn validateTopic(p: TopicParams) error{InvalidLimits}!void {
    inline for (std.meta.fields(TopicParams)) |field| {
        const value = @field(p, field.name);
        if (field.type == f64 and !safeMagnitude(value)) return error.InvalidLimits;
    }
    if (p.weight < 0 or p.time_in_mesh_weight < 0 or p.time_in_mesh_cap < 0 or
        p.time_in_mesh_quantum_ms == 0 or p.first_delivery_weight < 0 or p.first_delivery_cap < 0 or
        p.mesh_delivery_weight > 0 or p.mesh_delivery_threshold < 0 or
        p.mesh_delivery_cap < p.mesh_delivery_threshold or p.mesh_failure_weight > 0 or p.invalid_weight > 0)
        return error.InvalidLimits;
    for ([_]f64{ p.first_delivery_decay, p.mesh_delivery_decay, p.mesh_failure_decay, p.invalid_decay }) |decay| {
        if (decay < 0 or decay >= 1) return error.InvalidLimits;
    }
}

pub fn validateParams(p: Params) error{InvalidLimits}!void {
    try validateTopic(p.topic);
    inline for (std.meta.fields(Params)) |field| {
        if (field.type == f64 and !safeMagnitude(@field(p, field.name))) return error.InvalidLimits;
    }
    if (p.decay_interval_ms == 0 or p.decay_to_zero <= 0 or p.behaviour_threshold < 0 or
        p.behaviour_weight > 0 or p.behaviour_decay < 0 or p.behaviour_decay >= 1 or
        p.ip_colocation_weight > 0 or p.topic_cap < 0 or p.gossip_threshold > 0 or
        p.publish_threshold > p.gossip_threshold or p.graylist_threshold > p.publish_threshold)
        return error.InvalidLimits;
}

fn decayed(value: f64, decay: f64, intervals: u64, zero: f64) f64 {
    var factor: f64 = 1;
    var base = decay;
    var exponent = intervals;
    for (0..64) |_| {
        if (exponent == 0) break;
        if (exponent & 1 != 0) factor *= base;
        base *= base;
        exponent >>= 1;
    }
    assert(exponent == 0);
    const next = value * factor;
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

test "gossip policy duplicate graft preserves activation" {
    var score = try PeerScore.init(std.testing.allocator, .{});
    defer score.deinit(std.testing.allocator);
    score.graft(0, 0, 1);
    const activated = score.score(0, 30_001);
    score.graft(0, 0, 30_001);
    try std.testing.expectEqual(activated, score.score(0, 30_001));
}

test "gossip policy active decay accounts for the complete bounded time gap" {
    var score = try PeerScore.init(std.testing.allocator, .{ .topic = .{ .first_delivery_decay = 0.99 } });
    defer score.deinit(std.testing.allocator);
    score.deliver(0, 0);
    score.refresh(1);
    score.refresh(1 + 100 * score.params.decay_interval_ms);
    try std.testing.expectApproxEqAbs(@as(f64, 0.3660323412732292), score.score(0, 1), 0.0000000001);
}

test "gossip policy score rejects unsafe finite configuration" {
    try std.testing.expectError(error.InvalidLimits, PeerScore.init(std.testing.allocator, .{ .topic = .{ .invalid_weight = -std.math.floatMax(f64) } }));
    try std.testing.expectError(error.InvalidLimits, PeerScore.init(std.testing.allocator, .{ .decay_interval_ms = 0 }));
    try std.testing.expectError(error.InvalidLimits, PeerScore.init(std.testing.allocator, .{ .topic = .{ .weight = std.math.nan(f64) } }));
}

test "gossip policy independent topic decay and frozen offline counters" {
    var score = try PeerScore.init(std.testing.allocator, .{ .decay_interval_ms = 10 });
    defer score.deinit(std.testing.allocator);
    try score.configureTopic(0, .{ .first_delivery_weight = 2, .first_delivery_decay = 0.5 });
    try score.configureTopic(1, .{ .first_delivery_weight = 4, .first_delivery_decay = 0.25 });
    score.deliver(0, 0);
    score.deliver(0, 1);
    score.refresh(0);
    score.refresh(10);
    try std.testing.expectEqual(@as(f64, 2), score.score(0, 10));
    score.setConnected(0, false, 10);
    score.refresh(1000);
    try std.testing.expectEqual(@as(f64, 2), score.score(0, 1000));
    score.setConnected(0, true, 1000);
    score.refresh(1010);
    try std.testing.expectEqual(@as(f64, 0.75), score.score(0, 1010));
}

test "gossip policy score matches independent libp2p 17.1.1 two topic oracle" {
    var score = try PeerScore.init(std.testing.allocator, .{
        .topic_cap = 50,
        .app_weight = 2,
        .ip_colocation_weight = -5,
        .ip_colocation_threshold = 3,
        .behaviour_weight = -3,
        .behaviour_threshold = 2,
        .behaviour_decay = 0.5,
    });
    defer score.deinit(std.testing.allocator);
    const first: TopicParams = .{ .weight = 2, .time_in_mesh_weight = 0.25, .time_in_mesh_cap = 30, .first_delivery_weight = 3, .first_delivery_cap = 10, .first_delivery_decay = 0.5, .mesh_delivery_weight = -2, .mesh_delivery_threshold = 5, .mesh_delivery_cap = 10, .mesh_delivery_decay = 0.5, .mesh_delivery_activation_ms = 1000, .mesh_failure_weight = -4, .mesh_failure_decay = 0.5, .invalid_weight = -10, .invalid_decay = 0.5 };
    var second = first;
    second.weight = 0.5;
    second.first_delivery_weight = 2;
    second.first_delivery_decay = 0.25;
    second.mesh_failure_weight = -1;
    second.invalid_weight = -8;
    try score.configureTopic(0, first);
    try score.configureTopic(1, second);
    score.tc(0, 0).* = .{ .in_mesh = true, .graft_ms = 1, .first_deliveries = 4, .mesh_deliveries = 2, .mesh_failures = 1.5, .invalid = 2 };
    score.tc(0, 1).* = .{ .first_deliveries = 3, .mesh_failures = 2, .invalid = 1 };
    try std.testing.expect(score.setAppScore(0, 7));
    score.penalize(0, 5);
    score.ip_count[0] = 5;
    try std.testing.expectEqual(@as(f64, -124), score.score(0, 40_001));
    score.ip_count[0] = 0;
    try std.testing.expectEqual(@as(f64, -104), score.score(0, 40_001));
    score.ip_count[0] = 5;
    score.behaviour[0] = 2;
    try std.testing.expectEqual(@as(f64, -97), score.score(0, 40_002));
    score.tc(0, 0).* = .{ .first_deliveries = 20 };
    score.tc(0, 1).* = .{ .first_deliveries = 3 };
    score.ip_count[0] = 0;
    score.behaviour[0] = 0;
    try std.testing.expectEqual(@as(f64, 64), score.score(0, 40_001));
}

test "gossip policy host scores and saturated penalties stay finite" {
    var score = try PeerScore.init(std.testing.allocator, .{});
    defer score.deinit(std.testing.allocator);
    try std.testing.expect(score.setAppScore(0, 5));
    try std.testing.expect(!score.setAppScore(0, std.math.nan(f64)));
    try std.testing.expect(!score.setAppScore(0, std.math.floatMax(f64)));
    try std.testing.expectEqual(@as(f64, 5), score.score(0, 1));
    score.tc(0, 0).invalid = counter_max;
    score.invalid(0, 0);
    try std.testing.expectEqual(counter_max, score.tc(0, 0).invalid);
    score.penalize(0, counter_max);
    score.penalize(0, counter_max);
    try std.testing.expectEqual(counter_max, score.behaviour[0]);
    try std.testing.expect(std.math.isFinite(score.score(0, 1)));
}
