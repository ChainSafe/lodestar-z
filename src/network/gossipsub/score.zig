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

pub const TopicCounters = struct {
    in_mesh: bool = false,
    graft_ms: u64 = 0,
    first_deliveries: f64 = 0,
    mesh_deliveries: f64 = 0,
    mesh_failures: f64 = 0,
    invalid: f64 = 0,
};

pub const TopicWeights = struct {
    p1: f64 = 0,
    p2: f64 = 0,
    p3: f64 = 0,
    p3b: f64 = 0,
    p4: f64 = 0,

    pub fn total(self: *const TopicWeights) f64 {
        return self.p1 + self.p2 + self.p3 + self.p3b + self.p4;
    }
};

pub const GlobalWeights = struct { p5: f64 = 0, p6: f64 = 0, p7: f64 = 0 };
pub const Penalties = struct { graft_backoff: u64 = 0, broken_promise: u64 = 0, message_deficit: u64 = 0, invalid_message: u64 = 0 };
pub const Breakdown = struct {
    topics: [constants.topics_cap]TopicWeights = @splat(.{}),
    global: GlobalWeights = .{},
};

pub const CacheDelta = struct {
    pub const bounds = [_]f64{ 10, 100, 1000 };
    buckets: [bounds.len + 1]u64 = @splat(0),
    count: u64 = 0,
    sum: f64 = 0,

    fn observe(self: *CacheDelta, value: f64) void {
        assert(std.math.isFinite(value) and value >= 0);
        if (self.count == std.math.maxInt(u64)) return;
        var index: usize = bounds.len;
        for (bounds, 0..) |bound, i| if (value <= bound) {
            index = i;
            break;
        };
        self.buckets[index] += 1;
        self.count += 1;
        self.sum += value;
        assert(std.math.isFinite(self.sum));
    }
};

pub const PeerScore = struct {
    revision: u64 = 0,
    calculations: u64 = 0,
    calls: u64 = 0,
    cache_delta: CacheDelta = .{},
    penalties: Penalties = .{},
    topic_visits: u64 = 0,
    params: Params,
    topics: []TopicCounters,
    rows: []PeerState,
    topic_params: [constants.topics_cap]TopicParams,

    pub const PeerState = struct {
        app_score: f64 = 0,
        behaviour: f64 = 0,
        connected: bool = false,
        last_decay_ms: ?u64 = null,
        dirty: bool = true,
        cached_until: ?u64 = null,
        cached_at: ?u64 = null,
        cached: f64 = 0,
        cached_ip: u16 = 0,
    };

    pub fn backingBytes(count: usize) usize {
        return count * (@sizeOf(PeerState) + constants.topics_cap * @sizeOf(TopicCounters));
    }

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
        const rows = try allocator.alloc(PeerState, count);
        errdefer allocator.free(rows);
        @memset(rows, .{});
        return .{
            .params = params,
            .topic_params = [_]TopicParams{params.topic} ** constants.topics_cap,
            .topics = topics,
            .rows = rows,
        };
    }

    pub fn deinit(self: *PeerScore, allocator: Allocator) void {
        allocator.free(self.rows);
        allocator.free(self.topics);
        self.* = undefined;
    }

    fn tc(self: *PeerScore, peer: u16, topic: u16) *TopicCounters {
        const index = @as(usize, peer) * constants.topics_cap + topic;
        assert(index < self.topics.len);
        self.revision +|= 1;
        self.rows[peer].dirty = true;
        return &self.topics[index];
    }

    /// Clears every counter for a peer whose slot is being reused.
    pub fn resetPeer(self: *PeerScore, peer: u16) void {
        self.revision +|= 1;
        self.rows[peer] = .{};
        const base = @as(usize, peer) * constants.topics_cap;
        @memset(self.topics[base..][0..constants.topics_cap], .{});
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
        if (elapsed > params.mesh_delivery_activation_ms and
            counters.mesh_deliveries < params.mesh_delivery_threshold)
        {
            const deficit = params.mesh_delivery_threshold - counters.mesh_deliveries;
            counters.mesh_failures = @min(counter_max, counters.mesh_failures + deficit * deficit);
            self.penalties.message_deficit +|= 1;
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
        self.penalties.invalid_message +|= 1;
    }

    pub fn penalize(self: *PeerScore, peer: u16, amount: f64) void {
        assert(safeMagnitude(amount) and amount >= 0);
        self.revision +|= 1;
        self.rows[peer].dirty = true;
        self.rows[peer].behaviour = @min(counter_max, self.rows[peer].behaviour + amount);
    }

    pub fn setAppScore(self: *PeerScore, peer: u16, value: f64) bool {
        if (!safeMagnitude(value)) return false;
        if (self.rows[peer].app_score == value) return true;
        self.revision +|= 1;
        self.rows[peer].dirty = true;
        self.rows[peer].app_score = value;
        return true;
    }

    pub fn score(self: *PeerScore, peer: u16, now_ms: u64, ip_count: u16) f64 {
        assert(peer < self.rows.len);
        const row = &self.rows[peer];
        self.calls +|= 1;
        if (!row.dirty and row.cached_at != null and now_ms >= row.cached_at.? and
            (row.cached_until == null or now_ms < row.cached_until.?) and
            row.cached_ip == ip_count) return row.cached;
        self.calculations +|= 1;
        self.topic_visits +|= constants.topics_cap;
        const result = self.evaluate(peer, now_ms, ip_count, null);
        if (row.cached_at != null) self.cache_delta.observe(@abs(result.total - row.cached));
        row.dirty = false;
        row.cached_at = now_ms;
        row.cached_until = result.next_change;
        row.cached_ip = ip_count;
        row.cached = result.total;
        return result.total;
    }

    /// Evaluates current counters without changing decay, cache validity or policy metrics.
    pub fn snapshot(self: *const PeerScore, peer: u16, now_ms: u64, ip_count: u16) f64 {
        return self.evaluate(peer, now_ms, ip_count, null).total;
    }

    pub fn snapshotWeights(self: *const PeerScore, peer: u16, now_ms: u64, ip_count: u16, out: *Breakdown) f64 {
        out.* = .{};
        return self.evaluate(peer, now_ms, ip_count, out).total;
    }

    fn evaluate(self: *const PeerScore, peer: u16, now_ms: u64, ip_count: u16, out: ?*Breakdown) struct { total: f64, next_change: ?u64 } {
        assert(peer < self.rows.len);
        const row = &self.rows[peer];
        var next_change: ?u64 = null;
        var total: f64 = 0;
        var topic: usize = 0;
        while (topic < constants.topics_cap) : (topic += 1) {
            const params = &self.topic_params[topic];
            const counters = &self.topics[@as(usize, peer) * constants.topics_cap + topic];
            if (!counters.in_mesh and counters.first_deliveries == 0 and
                counters.mesh_failures == 0 and counters.invalid == 0) continue;
            var weights: TopicWeights = .{};
            const elapsed: u64 = if (counters.in_mesh) now_ms -| counters.graft_ms else 0;
            if (counters.in_mesh) {
                const p1 = @min(
                    @as(f64, @floatFromInt(elapsed / params.time_in_mesh_quantum_ms)),
                    params.time_in_mesh_cap,
                );
                weights.p1 = params.time_in_mesh_weight * p1;
                if (params.weight != 0 and params.time_in_mesh_weight != 0 and p1 < params.time_in_mesh_cap) {
                    const remaining = params.time_in_mesh_quantum_ms - elapsed % params.time_in_mesh_quantum_ms;
                    const start = @max(now_ms, counters.graft_ms);
                    if (remaining <= std.math.maxInt(u64) - start) {
                        const next = start + remaining;
                        next_change = @min(next_change orelse next, next);
                    }
                }
                if (params.weight != 0 and params.mesh_delivery_weight != 0 and
                    counters.mesh_deliveries < params.mesh_delivery_threshold and elapsed <= params.mesh_delivery_activation_ms and
                    params.mesh_delivery_activation_ms < std.math.maxInt(u64) - counters.graft_ms)
                {
                    const next = counters.graft_ms + params.mesh_delivery_activation_ms + 1;
                    next_change = @min(next_change orelse next, next);
                }
            }
            weights.p2 = params.first_delivery_weight *
                @min(counters.first_deliveries, params.first_delivery_cap);
            if (counters.in_mesh and elapsed > params.mesh_delivery_activation_ms and
                counters.mesh_deliveries < params.mesh_delivery_threshold)
            {
                const deficit = params.mesh_delivery_threshold - counters.mesh_deliveries;
                weights.p3 = params.mesh_delivery_weight * deficit * deficit;
            }
            weights.p3b = params.mesh_failure_weight * counters.mesh_failures;
            weights.p4 = params.invalid_weight * counters.invalid * counters.invalid;
            total += params.weight * weights.total();
            if (out) |details| details.topics[topic] = weights;
        }
        if (self.params.topic_cap > 0 and total > self.params.topic_cap) {
            total = self.params.topic_cap;
        }
        var global: GlobalWeights = .{ .p5 = self.params.app_weight * row.app_score };
        total += global.p5;
        if (row.behaviour > self.params.behaviour_threshold) {
            const excess = row.behaviour - self.params.behaviour_threshold;
            global.p7 = self.params.behaviour_weight * excess * excess;
            total += global.p7;
        }
        const excess_ip: f64 = @floatFromInt(ip_count -| self.params.ip_colocation_threshold);
        global.p6 = self.params.ip_colocation_weight * excess_ip * excess_ip;
        total += global.p6;
        if (out) |details| details.global = global;
        assert(std.math.isFinite(total));
        return .{ .total = total, .next_change = next_change };
    }

    /// Valid after a cached score read. Background refresh invalidates on counter decay;
    /// reads never advance decay or change the heartbeat's fixed score snapshot.
    pub fn nextChange(self: *const PeerScore, peer: u16) ?u64 {
        assert(peer < self.rows.len and !self.rows[peer].dirty);
        return self.rows[peer].cached_until;
    }

    pub fn resetTopic(self: *PeerScore, topic: u16) void {
        for (0..self.rows.len) |peer| {
            const counters = self.tc(@intCast(peer), topic);
            assert(!counters.in_mesh);
            counters.* = .{};
        }
    }

    pub fn retainsTopic(self: *const PeerScore, topic: u16) bool {
        assert(topic < constants.topics_cap);
        for (0..self.rows.len) |peer| {
            const counters = &self.topics[peer * constants.topics_cap + topic];
            if (counters.in_mesh or counters.first_deliveries != 0 or counters.mesh_deliveries != 0 or
                counters.mesh_failures != 0 or counters.invalid != 0) return true;
        }
        return false;
    }

    pub fn configureTopic(self: *PeerScore, topic: u16, params: TopicParams) error{InvalidLimits}!void {
        assert(topic < constants.topics_cap);
        try validateTopic(params);
        self.applyValidatedTopic(topic, params);
    }

    /// Params must pass validateTopic before entering a prepared owner transaction.
    pub fn applyValidatedTopic(self: *PeerScore, topic: u16, params: TopicParams) void {
        assert(topic < constants.topics_cap);
        if (std.meta.eql(self.topic_params[topic], params)) return;
        self.revision +|= 1;
        self.topic_params[topic] = params;
        for (self.rows) |*row| row.dirty = true;
    }

    pub fn setConnected(self: *PeerScore, peer: u16, connected: bool, now_ms: u64) void {
        assert(peer < self.rows.len);
        const row = &self.rows[peer];
        self.refreshPeer(peer, now_ms);
        self.revision +|= 1;
        row.dirty = true;
        row.connected = connected;
        row.last_decay_ms = now_ms;
    }

    pub fn refresh(self: *PeerScore, now_ms: u64) void {
        for (0..self.rows.len) |peer| self.refreshPeer(@intCast(peer), now_ms);
    }

    fn refreshPeer(self: *PeerScore, peer: u16, now_ms: u64) void {
        const row = &self.rows[peer];
        if (!row.connected) return;
        const last = row.last_decay_ms orelse {
            row.last_decay_ms = now_ms;
            return;
        };
        const steps = (now_ms -| last) / self.params.decay_interval_ms;
        if (steps == 0) return;
        row.last_decay_ms = last + steps * self.params.decay_interval_ms;
        self.decayPeer(peer, steps);
    }

    fn decayPeer(self: *PeerScore, peer: u16, steps: u64) void {
        const zero = self.params.decay_to_zero;
        for (0..constants.topics_cap) |topic| {
            const c = &self.topics[@as(usize, peer) * constants.topics_cap + topic];
            if (c.first_deliveries == 0 and c.mesh_deliveries == 0 and c.mesh_failures == 0 and c.invalid == 0) continue;
            self.revision +|= 1;
            self.rows[peer].dirty = true;
            const tp = self.topic_params[topic];
            c.first_deliveries = decayed(c.first_deliveries, tp.first_delivery_decay, steps, zero);
            c.mesh_deliveries = decayed(c.mesh_deliveries, tp.mesh_delivery_decay, steps, zero);
            c.mesh_failures = decayed(c.mesh_failures, tp.mesh_failure_decay, steps, zero);
            c.invalid = decayed(c.invalid, tp.invalid_decay, steps, zero);
        }
        if (self.rows[peer].behaviour != 0) {
            self.revision +|= 1;
            self.rows[peer].dirty = true;
            self.rows[peer].behaviour = decayed(self.rows[peer].behaviour, self.params.behaviour_decay, steps, zero);
        }
    }
};

pub const peer_capacity = constants.retained_peers_cap;
pub const counter_max: f64 = 1_000_000;
// Two weights and a squared counter bound each topic term by 1e36.
// Summing all 512 topics and global terms stays below 1e40.
pub const weight_max: f64 = 1_000_000_000_000;

fn safeMagnitude(value: f64) bool {
    return std.math.isFinite(value) and @abs(value) <= counter_max;
}

fn safeParameter(comptime name: []const u8, value: f64) bool {
    const weight = comptime std.mem.eql(u8, name, "weight") or std.mem.endsWith(u8, name, "_weight");
    return std.math.isFinite(value) and @abs(value) <= (if (weight) weight_max else counter_max);
}

pub fn validateTopic(p: TopicParams) error{InvalidLimits}!void {
    inline for (std.meta.fields(TopicParams)) |field| {
        const value = @field(p, field.name);
        if (field.type == f64 and !safeParameter(field.name, value)) return error.InvalidLimits;
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
        if (field.type == f64 and !safeParameter(field.name, @field(p, field.name))) return error.InvalidLimits;
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

fn testScores(a: Allocator, params: Params, count: u16) !PeerScore {
    const scores = try PeerScore.initCapacity(a, params, count);
    for (scores.rows) |*row| row.connected = true;
    return scores;
}

test "score accepts small validator set weights with bounded counters" {
    var score = try testScores(std.testing.allocator, .{}, peer_capacity);
    defer score.deinit(std.testing.allocator);
    try score.configureTopic(0, .{ .mesh_failure_weight = -30_494_071.26802956 });
    score.graft(0, 0, 0);
    score.prune(0, 0, 30_001);
    try std.testing.expectApproxEqAbs(@as(f64, -762_351_781.700739), score.score(0, 30_001, 0), 0.001);
    try std.testing.expectError(error.InvalidLimits, score.configureTopic(0, .{ .first_delivery_cap = counter_max + 1 }));
}

test "score weight limit keeps worst case arithmetic finite" {
    var score = try testScores(std.testing.allocator, .{}, 1);
    defer score.deinit(std.testing.allocator);
    for (0..constants.topics_cap) |topic| {
        try score.configureTopic(@intCast(topic), .{ .weight = weight_max, .invalid_weight = -weight_max });
        score.tc(0, @intCast(topic)).invalid = counter_max;
    }
    const worst = score.score(0, 0, 0);
    try std.testing.expect(std.math.isFinite(worst) and worst < 0 and worst > -1e40);
    try std.testing.expectError(error.InvalidLimits, score.configureTopic(0, .{ .weight = weight_max + 1 }));
    try std.testing.expectError(error.InvalidLimits, validateParams(.{ .app_weight = weight_max + 1 }));
    try std.testing.expectError(error.InvalidLimits, validateParams(.{ .behaviour_threshold = counter_max + 1 }));
}

test "score rewards deliveries and punishes invalid messages" {
    var score = try testScores(std.testing.allocator, .{}, peer_capacity);
    defer score.deinit(std.testing.allocator);

    score.graft(1, 0, 0);
    score.deliver(1, 0);
    score.deliver(1, 0);
    try std.testing.expect(score.score(1, 1_000, 0) > 0);

    score.invalid(2, 0);
    try std.testing.expect(score.score(2, 1_000, 0) < 0);
}

test "score crosses the graylist threshold on repeated invalid messages" {
    var score = try testScores(std.testing.allocator, .{}, peer_capacity);
    defer score.deinit(std.testing.allocator);
    var n: usize = 0;
    while (n < 20) : (n += 1) score.invalid(1, 0);
    try std.testing.expect(score.score(1, 0, 0) < score.params.graylist_threshold);
}

test "score decays counters toward zero over intervals" {
    var score = try testScores(std.testing.allocator, .{}, peer_capacity);
    defer score.deinit(std.testing.allocator);
    score.deliver(1, 0);
    const before = score.score(1, 0, 0);
    score.refresh(0); // primes last_decay
    var now: u64 = 0;
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        now += score.params.decay_interval_ms;
        score.refresh(now);
    }
    const after = score.score(1, now, 0);
    try std.testing.expect(after < before);
    try std.testing.expect(@abs(after) < @abs(before));
}

test "score resets when a peer slot is reused" {
    var score = try testScores(std.testing.allocator, .{}, peer_capacity);
    defer score.deinit(std.testing.allocator);
    score.invalid(1, 0);
    try std.testing.expect(score.score(1, 0, 0) < 0);
    score.resetPeer(1);
    try std.testing.expectEqual(@as(f64, 0), score.score(1, 0, 0));
}

test "gossip policy duplicate graft preserves activation" {
    var score = try testScores(std.testing.allocator, .{}, peer_capacity);
    defer score.deinit(std.testing.allocator);
    score.graft(0, 0, 1);
    const activated = score.score(0, 30_001, 0);
    score.graft(0, 0, 30_001);
    try std.testing.expectEqual(activated, score.score(0, 30_001, 0));
}

test "gossip policy active decay accounts for the complete bounded time gap" {
    var score = try testScores(std.testing.allocator, .{ .topic = .{ .first_delivery_decay = 0.99 } }, peer_capacity);
    defer score.deinit(std.testing.allocator);
    score.deliver(0, 0);
    score.refresh(1);
    score.refresh(1 + 100 * score.params.decay_interval_ms);
    try std.testing.expectApproxEqAbs(@as(f64, 0.3660323412732292), score.score(0, 1, 0), 0.0000000001);
}

test "gossip policy score rejects unsafe finite configuration" {
    try std.testing.expectError(error.InvalidLimits, testScores(std.testing.allocator, .{ .topic = .{ .invalid_weight = -std.math.floatMax(f64) } }, peer_capacity));
    try std.testing.expectError(error.InvalidLimits, testScores(std.testing.allocator, .{ .decay_interval_ms = 0 }, peer_capacity));
    try std.testing.expectError(error.InvalidLimits, testScores(std.testing.allocator, .{ .topic = .{ .weight = std.math.nan(f64) } }, peer_capacity));
}

test "gossip policy independent topic decay and frozen offline counters" {
    var score = try testScores(std.testing.allocator, .{ .decay_interval_ms = 10 }, peer_capacity);
    defer score.deinit(std.testing.allocator);
    try score.configureTopic(0, .{ .first_delivery_weight = 2, .first_delivery_decay = 0.5 });
    try score.configureTopic(1, .{ .first_delivery_weight = 4, .first_delivery_decay = 0.25 });
    score.deliver(0, 0);
    score.deliver(0, 1);
    score.refresh(0);
    score.refresh(10);
    try std.testing.expectEqual(@as(f64, 2), score.score(0, 10, 0));
    score.setConnected(0, false, 10);
    score.refresh(1000);
    try std.testing.expectEqual(@as(f64, 2), score.score(0, 1000, 0));
    score.setConnected(0, true, 1000);
    score.refresh(1010);
    try std.testing.expectEqual(@as(f64, 0.75), score.score(0, 1010, 0));
}

test "gossip policy score matches independent libp2p 17.1.1 two topic oracle" {
    var ip_count: u16 = 0;
    var score = try testScores(std.testing.allocator, .{
        .topic_cap = 50,
        .app_weight = 2,
        .ip_colocation_weight = -5,
        .ip_colocation_threshold = 3,
        .behaviour_weight = -3,
        .behaviour_threshold = 2,
        .behaviour_decay = 0.5,
    }, peer_capacity);
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
    ip_count = 5;
    try std.testing.expectEqual(@as(f64, -124), score.score(0, 40_001, ip_count));
    ip_count = 0;
    try std.testing.expectEqual(@as(f64, -104), score.score(0, 40_001, ip_count));
    ip_count = 5;
    score.rows[0].behaviour = 2;
    try std.testing.expectEqual(@as(f64, -97), score.score(0, 40_002, ip_count));
    score.tc(0, 0).* = .{ .first_deliveries = 20 };
    score.tc(0, 1).* = .{ .first_deliveries = 3 };
    ip_count = 0;
    score.rows[0].behaviour = 0;
    try std.testing.expectEqual(@as(f64, 64), score.score(0, 40_001, ip_count));
}

test "gossip policy host scores and saturated penalties stay finite" {
    var score = try testScores(std.testing.allocator, .{}, peer_capacity);
    defer score.deinit(std.testing.allocator);
    try std.testing.expect(score.setAppScore(0, 5));
    try std.testing.expect(!score.setAppScore(0, std.math.nan(f64)));
    try std.testing.expect(!score.setAppScore(0, std.math.floatMax(f64)));
    try std.testing.expectEqual(@as(f64, 5), score.score(0, 1, 0));
    score.tc(0, 0).invalid = counter_max;
    score.invalid(0, 0);
    try std.testing.expectEqual(counter_max, score.tc(0, 0).invalid);
    score.penalize(0, counter_max);
    score.penalize(0, counter_max);
    try std.testing.expectEqual(counter_max, score.rows[0].behaviour);
    try std.testing.expect(std.math.isFinite(score.score(0, 1, 0)));
}

test "score cache preserves exact boundaries without repeated calculations" {
    var score = try testScores(std.testing.allocator, .{ .decay_interval_ms = 10, .topic = .{ .time_in_mesh_weight = 2, .time_in_mesh_cap = 2.5, .time_in_mesh_quantum_ms = 10, .mesh_delivery_activation_ms = 25, .mesh_delivery_threshold = 2, .mesh_delivery_weight = -3 } }, 2);
    defer score.deinit(std.testing.allocator);
    score.graft(0, 0, 5);
    try std.testing.expectEqual(@as(f64, 0), score.score(0, 5, 0));
    try std.testing.expectEqual(@as(f64, 0), score.score(0, 14, 0));
    try std.testing.expectEqual(@as(u64, 1), score.calculations);
    try std.testing.expectEqual(@as(f64, 2), score.score(0, 15, 0));
    try std.testing.expectEqual(@as(f64, 2), score.score(0, 16, 0));
    try std.testing.expectEqual(@as(f64, 4), score.score(0, 29, 0));
    try std.testing.expectEqual(@as(f64, 4), score.score(0, 30, 0));
    try std.testing.expectEqual(@as(f64, -8), score.score(0, 31, 0));
    try std.testing.expectEqual(@as(f64, -7), score.score(0, 35, 0));
    const calculations = score.calculations;
    try std.testing.expectEqual(@as(f64, -7), score.score(0, 1000, 0));
    try std.testing.expectEqual(calculations, score.calculations);
    // A caller using an earlier clock must still get the exact earlier P1/P3.
    try std.testing.expectEqual(@as(f64, 2), score.score(0, 15, 0));
}

test "score read only topic inspection preserves cache validity" {
    var score = try testScores(std.testing.allocator, .{}, 2);
    defer score.deinit(std.testing.allocator);
    _ = score.score(0, 0, 0);
    try std.testing.expect(!score.retainsTopic(0));
    try std.testing.expect(!score.rows[0].dirty);
    _ = score.score(0, 0, 0);
    try std.testing.expectEqual(@as(u64, 1), score.calculations);
}

test "score cache mutation IP topic and heartbeat decay boundaries remain exact" {
    var ip_count: u16 = 0;
    var score = try testScores(std.testing.allocator, .{ .ip_colocation_weight = -5, .decay_interval_ms = 10, .topic = .{ .first_delivery_decay = 0.5 } }, 2);
    defer score.deinit(std.testing.allocator);
    score.deliver(0, 0);
    score.refresh(0);
    try std.testing.expectEqual(@as(f64, 1), score.score(0, 0, ip_count));
    try std.testing.expectEqual(@as(?u64, null), score.nextChange(0));
    score.refresh(9);
    try std.testing.expectEqual(@as(f64, 1), score.score(0, 9, ip_count));
    try std.testing.expectEqual(@as(u64, 1), score.calculations);
    // Wall time alone does not move the background decay schedule.
    try std.testing.expectEqual(@as(f64, 1), score.score(0, 10, ip_count));
    try std.testing.expectEqual(@as(u64, 1), score.calculations);
    score.refresh(10);
    try std.testing.expectEqual(@as(f64, 0.5), score.score(0, 10, ip_count));
    try std.testing.expectEqual(@as(u64, 2), score.calculations);
    score.refresh(11);
    try std.testing.expectEqual(@as(f64, 0.5), score.score(0, 11, ip_count));
    try std.testing.expectEqual(@as(u64, 2), score.calculations);
    ip_count = 5;
    try std.testing.expectEqual(@as(f64, -19.5), score.score(0, 11, ip_count));
    try std.testing.expect(score.setAppScore(0, 7));
    try std.testing.expectEqual(@as(f64, -12.5), score.score(0, 11, ip_count));
    score.deliver(0, 0);
    try std.testing.expectEqual(@as(f64, -11.5), score.score(0, 11, ip_count));
    try score.configureTopic(0, .{ .first_delivery_weight = 2, .first_delivery_decay = 0.5 });
    try std.testing.expectEqual(@as(f64, -10), score.score(0, 11, ip_count));
    score.setConnected(0, false, 11);
    score.refresh(1000);
    try std.testing.expectEqual(@as(f64, -10), score.score(0, 1000, ip_count));
    const frozen = score.calculations;
    score.refresh(2000);
    try std.testing.expectEqual(@as(f64, -10), score.score(0, 2000, ip_count));
    try std.testing.expectEqual(frozen, score.calculations);
}

test "score cache reports earliest active topic quantum activation and cap" {
    var score = try testScores(std.testing.allocator, .{}, 1);
    defer score.deinit(std.testing.allocator);
    try score.configureTopic(0, .{ .time_in_mesh_quantum_ms = 10, .time_in_mesh_cap = 1.5, .mesh_delivery_activation_ms = 17 });
    try score.configureTopic(1, .{ .time_in_mesh_weight = 0, .mesh_delivery_activation_ms = 13 });
    score.graft(0, 0, 5);
    score.graft(0, 1, 5);
    _ = score.score(0, 14, 0);
    try std.testing.expectEqual(@as(?u64, 15), score.nextChange(0));
    _ = score.score(0, 15, 0);
    try std.testing.expectEqual(@as(?u64, 19), score.nextChange(0));
    _ = score.score(0, 19, 0);
    try std.testing.expectEqual(@as(?u64, 23), score.nextChange(0));
    _ = score.score(0, 23, 0);
    try std.testing.expectEqual(@as(?u64, 25), score.nextChange(0));
    _ = score.score(0, 25, 0);
    try std.testing.expectEqual(@as(?u64, null), score.nextChange(0));
    score.revision = std.math.maxInt(u64);
    score.invalid(0, 0);
    try std.testing.expectEqual(std.math.maxInt(u64), score.revision);
    try std.testing.expect(score.rows[0].dirty);
}

test "score empty background decay does not fabricate mutations" {
    var score = try testScores(std.testing.allocator, .{}, 1);
    defer score.deinit(std.testing.allocator);
    score.refresh(0);
    _ = score.score(0, 0, 0);
    const revision = score.revision;
    score.refresh(score.params.decay_interval_ms);
    try std.testing.expectEqual(revision, score.revision);
    try std.testing.expect(!score.rows[0].dirty);
}

test "score activation is strictly after the window for P3" {
    var score = try testScores(std.testing.allocator, .{ .topic = .{ .time_in_mesh_weight = 0, .mesh_delivery_activation_ms = 10, .mesh_delivery_threshold = 2, .mesh_delivery_weight = -3, .mesh_failure_weight = -1 } }, 3);
    defer score.deinit(std.testing.allocator);
    score.graft(0, 0, 5);
    try std.testing.expectEqual(@as(f64, 0), score.score(0, 14, 0));
    try std.testing.expectEqual(@as(?u64, 16), score.nextChange(0));
    try std.testing.expectEqual(@as(f64, 0), score.score(0, 15, 0));
    try std.testing.expectEqual(@as(u64, 1), score.calculations);
    try std.testing.expectEqual(@as(f64, -12), score.score(0, 16, 0));
    try std.testing.expectEqual(@as(u64, 2), score.calculations);
    try std.testing.expectEqual(@as(?u64, null), score.nextChange(0));
}

test "score activation is strictly after the window for P3b pruning" {
    var score = try testScores(std.testing.allocator, .{ .topic = .{ .time_in_mesh_weight = 0, .mesh_delivery_activation_ms = 10, .mesh_delivery_threshold = 2, .mesh_delivery_weight = -3, .mesh_failure_weight = -1 } }, 3);
    defer score.deinit(std.testing.allocator);
    for ([_]u64{ 14, 15, 16 }, 0..) |now, i| {
        const peer: u16 = @intCast(i);
        score.graft(peer, 0, 5);
        score.prune(peer, 0, now);
        try std.testing.expectEqual(@as(f64, if (now > 15) -4 else 0), score.score(peer, now, 0));
    }
}

test "score activation zero window still waits for the first elapsed tick" {
    var score = try testScores(std.testing.allocator, .{ .topic = .{ .time_in_mesh_weight = 0, .mesh_delivery_activation_ms = 0 } }, 1);
    defer score.deinit(std.testing.allocator);
    score.graft(0, 0, 5);
    try std.testing.expectEqual(@as(f64, 0), score.score(0, 5, 0));
    try std.testing.expectEqual(@as(?u64, 6), score.nextChange(0));
    try std.testing.expectEqual(@as(f64, -25), score.score(0, 6, 0));
}

test "score activation and quantum deadlines never invent an overflowing instant" {
    var score = try testScores(std.testing.allocator, .{ .topic = .{ .time_in_mesh_weight = 0, .mesh_delivery_activation_ms = 10 } }, 1);
    defer score.deinit(std.testing.allocator);
    const maximum = std.math.maxInt(u64);
    score.graft(0, 0, maximum - 10);
    try std.testing.expectEqual(@as(f64, 0), score.score(0, maximum - 1, 0));
    try std.testing.expectEqual(@as(?u64, null), score.nextChange(0));
    try std.testing.expectEqual(@as(f64, 0), score.score(0, maximum, 0));
    score.prune(0, 0, maximum);
    try std.testing.expectEqual(@as(f64, 0), score.score(0, maximum, 0));

    score.resetPeer(0);
    score.graft(0, 0, maximum - 11);
    try std.testing.expectEqual(@as(f64, 0), score.score(0, maximum - 1, 0));
    try std.testing.expectEqual(@as(?u64, maximum), score.nextChange(0));
    try std.testing.expectEqual(@as(f64, -25), score.score(0, maximum, 0));
    try std.testing.expectEqual(@as(?u64, null), score.nextChange(0));
    score.prune(0, 0, maximum);
    try std.testing.expectEqual(@as(f64, -25), score.score(0, maximum, 0));

    score.resetPeer(0);
    try score.configureTopic(0, .{ .time_in_mesh_quantum_ms = 10, .mesh_delivery_weight = 0 });
    score.graft(0, 0, maximum - 9);
    try std.testing.expectEqual(@as(f64, 0), score.score(0, maximum - 1, 0));
    try std.testing.expectEqual(@as(?u64, null), score.nextChange(0));
    try std.testing.expectEqual(@as(f64, 0), score.score(0, maximum, 0));
}

test "score retirement invalidates primed totals with identical parameters" {
    var score = try testScores(std.testing.allocator, .{}, 2);
    defer score.deinit(std.testing.allocator);
    score.refresh(0);
    score.deliver(0, 0);
    score.invalid(1, 0);
    for ([_]f64{ 1, -100 }, 0..) |expected, peer| {
        try std.testing.expectEqual(expected, score.score(@intCast(peer), 1, 0));
        try std.testing.expect(!score.rows[peer].dirty);
        try std.testing.expectEqual(@as(?u64, null), score.nextChange(@intCast(peer)));
    }
    const params = score.topic_params[0];
    const revision = score.revision;
    score.resetTopic(0);
    try std.testing.expect(score.revision > revision);
    const retired_revision = score.revision;
    try score.configureTopic(0, params);
    try std.testing.expectEqual(retired_revision, score.revision);
    for (0..2) |peer| {
        try std.testing.expect(score.rows[peer].dirty);
        try std.testing.expectEqual(@as(f64, 0), score.score(@intCast(peer), 1, 0));
    }
    const calculations = score.calculations;
    score.refresh(score.params.decay_interval_ms);
    for (0..2) |peer| try std.testing.expectEqual(@as(f64, 0), score.score(@intCast(peer), score.params.decay_interval_ms, 0));
    try std.testing.expectEqual(retired_revision, score.revision);
    try std.testing.expectEqual(calculations, score.calculations);
}

test "metrics score snapshots preserve cache state and match policy evaluation" {
    var scores = try testScores(std.testing.allocator, .{}, 1);
    defer scores.deinit(std.testing.allocator);
    scores.graft(0, 0, 0);
    _ = scores.score(0, 1000, 0);
    scores.deliver(0, 0);
    const cached = scores.rows[0].cached;
    const calculations = scores.calculations;
    const visits = scores.topic_visits;
    const revision = scores.revision;
    const next = scores.rows[0].cached_until;
    const value = scores.snapshot(0, 50000, 0);
    try std.testing.expectEqual(cached, scores.rows[0].cached);
    try std.testing.expectEqual(calculations, scores.calculations);
    try std.testing.expectEqual(visits, scores.topic_visits);
    try std.testing.expectEqual(revision, scores.revision);
    try std.testing.expectEqual(next, scores.rows[0].cached_until);
    try std.testing.expect(scores.rows[0].dirty);
    try std.testing.expectEqual(value, scores.score(0, 50000, 0));
}

test "metrics score weights use policy thresholds and snapshots do not count as cache calls" {
    var ip_count: u16 = 0;
    var scores = try testScores(std.testing.allocator, .{
        .app_weight = 2,
        .ip_colocation_weight = -3,
        .ip_colocation_threshold = 1,
        .behaviour_weight = -2,
        .behaviour_threshold = 1,
        .topic_cap = 10,
        .topic = .{ .weight = 2, .time_in_mesh_weight = 1, .time_in_mesh_cap = 2, .first_delivery_weight = 3, .mesh_delivery_weight = -5, .mesh_delivery_threshold = 3, .mesh_delivery_activation_ms = 1000, .mesh_failure_weight = -7, .invalid_weight = -11 },
    }, 1);
    defer scores.deinit(std.testing.allocator);
    scores.graft(0, 0, 0);
    scores.deliver(0, 0);
    scores.invalid(0, 0);
    scores.tc(0, 0).mesh_failures = 1;
    scores.penalize(0, 3);
    try std.testing.expect(scores.setAppScore(0, 3));
    ip_count = 3;
    var details: Breakdown = undefined;
    const value = scores.snapshotWeights(0, 2000, ip_count, &details);
    try std.testing.expectEqualDeep(TopicWeights{ .p1 = 2, .p2 = 3, .p3 = -20, .p3b = -7, .p4 = -11 }, details.topics[0]);
    try std.testing.expectEqualDeep(GlobalWeights{ .p5 = 6, .p6 = -12, .p7 = -8 }, details.global);
    try std.testing.expectEqual(@as(f64, -80), value);
    try std.testing.expectEqual(@as(u64, 0), scores.calls);
    try std.testing.expectEqual(value, scores.score(0, 2000, ip_count));
    try std.testing.expectEqual(value, scores.score(0, 2000, ip_count));
    try std.testing.expectEqual(@as(u64, 2), scores.calls);
    try std.testing.expectEqual(@as(u64, 1), scores.calculations);
    try std.testing.expectEqual(@as(u64, 0), scores.cache_delta.count);
    try std.testing.expect(scores.setAppScore(0, 13));
    try std.testing.expectEqual(value + 20, scores.score(0, 2000, ip_count));
    try std.testing.expectEqual(@as(f64, 20), scores.cache_delta.sum);
    try std.testing.expectEqualSlices(u64, &.{ 0, 1, 0, 0 }, &scores.cache_delta.buckets);
    scores.resetPeer(0);
    _ = scores.score(0, 2000, ip_count);
    try std.testing.expectEqual(@as(u64, 1), scores.cache_delta.count);
    _ = scores.snapshotWeights(0, 2000, ip_count, &details);
    try std.testing.expectEqualDeep(TopicWeights{}, details.topics[0]);
    scores.topic_params[0].first_delivery_weight = 100;
    scores.deliver(0, 0);
    const capped = scores.snapshotWeights(0, 2000, ip_count, &details);
    try std.testing.expectEqual(@as(f64, 100), details.topics[0].p2);
    try std.testing.expectEqual(@as(f64, 10) + details.global.p6, capped);
    scores.graft(0, 0, 0);
    scores.prune(0, 0, 5000);
    scores.prune(0, 0, 5000);
    try std.testing.expectEqual(@as(u64, 1), scores.penalties.message_deficit);
    try std.testing.expectEqual(@as(u64, 1), scores.penalties.invalid_message);
}
