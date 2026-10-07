const prom = @import("../metrics/registry.zig");
const std = @import("std");
const policy = @import("topic_policy.zig");
const topic = @import("topic.zig");
const PeerBook = @import("peer_book.zig").PeerBook;
const Overlay = @import("overlay.zig").Overlay;
const Sessions = @import("sessions.zig").Sessions;
const PeerSet = @import("sessions.zig").PeerSet;
const histogram = @import("../metrics/histogram.zig");

pub const ValidationTime = histogram.Duration(&.{ 10, 30, 100, 300, 1000, 3000, 10000 });

/// Data frame recipients by delivery origin: selected, then queued, pressured or unavailable;
/// queued frames later complete when QUIC accepts their last byte, which is not delivery, or are
/// cancelled by cache eviction or a stream reset.
pub const Delivery = struct {
    const delivery = @import("delivery.zig");
    pub const Outcome = enum { selected, queued, pressured, unavailable, completed, cancelled };

    recipients: [delivery.origin_count][@typeInfo(Outcome).@"enum".fields.len]u64 = @splat(@splat(0)),

    pub fn recipient(self: *Delivery, origin: delivery.Origin, outcome: Outcome) void {
        if (outcome != .completed and outcome != .cancelled) self.recipients[@intFromEnum(origin)][@intFromEnum(Outcome.selected)] +|= 1;
        self.recipients[@intFromEnum(origin)][@intFromEnum(outcome)] +|= 1;
    }

    pub fn cancelled(self: *Delivery, queued: *const [delivery.origin_count]usize) void {
        for (&self.recipients, queued) |*outcomes, count| outcomes[@intFromEnum(Outcome.cancelled)] +|= count;
    }

    pub fn write(self: *const Delivery, w: *prom.Encoder) prom.Error!void {
        const recipients = try w.family(.{ .name = "lodestar_native_gossip_data_recipients_total", .kind = .counter, .help = "Data frame recipients by delivery origin: selected, then queued, pressured or unavailable; queued frames later complete when QUIC accepts their last byte, which is not delivery, or are cancelled by cache eviction or a stream reset", .labels = &.{ "origin", "outcome" } });
        inline for (@typeInfo(delivery.Origin).@"enum".fields) |origin| {
            inline for (@typeInfo(Outcome).@"enum".fields) |outcome| try recipients.sample(.{ origin.name, outcome.name }, self.recipients[origin.value][outcome.value]);
        }
    }
};

/// Messages received, received again and published, applied verdicts, and accepted messages
/// handed to forwarding, for one topic kind.
pub const Counters = struct {
    received: u64 = 0,
    duplicate: u64 = 0,
    published: u64 = 0,
    accepted: u64 = 0,
    rejected: u64 = 0,
    ignored: u64 = 0,
    forwarded: u64 = 0,
};

pub const Topics = struct {
    counts: [policy.kind_count + 1]Counters = @splat(.{}),

    pub fn get(self: *Topics, wire: []const u8) *Counters {
        const parsed = topic.parse(wire) orelse return &self.counts[policy.kind_count];
        const known = topic.Name.parse(parsed.name) orelse return &self.counts[policy.kind_count];
        return &self.counts[@intFromEnum(known.kind)];
    }
};

/// Connected gossip peers, and the distinct peers in any mesh, by the score gates they clear, with
/// each population's score range. Gates are cumulative: a peer at or above one clears every lower
/// one.
pub const ScorePopulations = struct {
    const Scope = enum { connected, mesh };
    const Threshold = enum { all, nonnegative, gossip, publish, graylist };
    const Population = struct {
        peers: [std.meta.fields(Threshold).len]u32 = @splat(0),
        min: f64 = 0,
        max: f64 = 0,
        sum: f64 = 0,

        fn observe(self: *Population, value: f64, gates: *const [std.meta.fields(Threshold).len]f64) void {
            std.debug.assert(std.math.isFinite(value));
            const first = self.peers[@intFromEnum(Threshold.all)] == 0;
            for (&self.peers, gates) |*count, gate| count.* += @intFromBool(value >= gate);
            self.min = if (first) value else @min(self.min, value);
            self.max = if (first) value else @max(self.max, value);
            self.sum += value;
        }
    };

    populations: [std.meta.fields(Scope).len]Population = @splat(.{}),

    /// Evaluates each connected peer's score once, without changing decay, cache validity or
    /// policy metrics. Each active session holds a distinct logical peer.
    pub fn collect(peers: *const PeerBook, overlay: *const Overlay, sessions: *const Sessions, now_ms: u64) ScorePopulations {
        var meshed = PeerSet.empty;
        for (overlay.rows) |*row| if (row.active) meshed.setUnion(row.mesh);
        const params = &peers.scores.params;
        const gates = [_]f64{ -std.math.inf(f64), 0, params.gossip_threshold, params.publish_threshold, params.graylist_threshold };
        var result: ScorePopulations = .{};
        for (sessions.rows, 0..) |*session, index| {
            if (!session.active) continue;
            const value = peers.snapshot(session.logical, now_ms);
            result.populations[@intFromEnum(Scope.connected)].observe(value, &gates);
            if (meshed.isSet(index)) result.populations[@intFromEnum(Scope.mesh)].observe(value, &gates);
        }
        return result;
    }

    pub fn write(self: *const ScorePopulations, w: *prom.Encoder) prom.Error!void {
        const counts = try w.family(.{
            .name = "lodestar_native_gossip_score_peers",
            .kind = .gauge,
            .help = "Connected gossip peers, and distinct peers in any mesh, whose score meets each configured gate; gates are cumulative, and all counts the whole population",
            .labels = &.{ "scope", "threshold" },
        });
        inline for (std.meta.fields(Scope)) |scope| {
            inline for (std.meta.fields(Threshold)) |threshold| try counts.sample(.{ scope.name, threshold.name }, self.populations[scope.value].peers[threshold.value]);
        }
        const scores = try w.family(.{
            .name = "lodestar_native_gossip_score",
            .kind = .gauge,
            .help = "Minimum, mean and maximum gossip score of connected peers and of distinct mesh peers; an empty population has no samples",
            .labels = &.{ "scope", "stat" },
        });
        inline for (std.meta.fields(Scope)) |scope| {
            const population = &self.populations[scope.value];
            const count = population.peers[@intFromEnum(Threshold.all)];
            if (count > 0) {
                try scores.sample(.{ scope.name, "min" }, population.min);
                try scores.sample(.{ scope.name, "mean" }, population.sum / @as(f64, @floatFromInt(count)));
                try scores.sample(.{ scope.name, "max" }, population.max);
            }
        }
    }
};

/// An IWANT ID absent from history, or present and then over its retransmission limit,
/// queued or refused for queue pressure.
pub const IwantOutcome = enum { miss, limited, queued, refused };
pub const iwant_outcome_count = @typeInfo(IwantOutcome).@"enum".fields.len;

test {
    _ = @import("metrics_test.zig");
}
