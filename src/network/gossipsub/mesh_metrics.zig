const std = @import("std");
const topic = @import("topic.zig");
const policy = @import("topic_policy.zig");
const prom = @import("../metrics/registry.zig");

pub const Addition = enum { underfull, outbound, opportunistic, remote_graft };
pub const Removal = enum { disconnected, stream_unavailable, bad_score, prune, remote_unsubscribe, local_unsubscribe, excess, direct, backoff };
/// A received GRAFT joined the mesh, found the peer already in it, or was refused: we do not
/// know or subscribe to the topic, the peer is direct, backed off or scored below zero, the mesh
/// is full, or we have no stream to answer on.
pub const GraftOutcome = enum { accepted, member, unknown_topic, local_unsubscribe, direct, backoff, bad_score, excess, no_stream };

pub const Metrics = struct {
    additions: [policy.kind_count + 1][std.meta.fields(Addition).len]u64 = @splat(@splat(0)),
    removals: [policy.kind_count + 1][std.meta.fields(Removal).len]u64 = @splat(@splat(0)),
    graft_received: [std.meta.fields(GraftOutcome).len]u64 = @splat(0),
    prune_sent: [std.meta.fields(Removal).len]u64 = @splat(0),
    /// Mesh members integrated over time by topic kind, sampled at each heartbeat.
    peer_ms: [policy.kind_count]u64 = @splat(0),
    sampled_ms: ?u64 = null,

    pub fn graftReceived(self: *Metrics, outcome: GraftOutcome) void {
        self.graft_received[@intFromEnum(outcome)] +|= 1;
    }

    pub fn pruneSent(self: *Metrics, reason: Removal) void {
        self.prune_sent[@intFromEnum(reason)] +|= 1;
    }

    /// Credits each topic kind with its current mesh members for the time since the last sample.
    pub fn sampleMesh(self: *Metrics, rows: []const @import("overlay.zig").Row, now_ms: u64) void {
        const last = self.sampled_ms orelse now_ms;
        self.sampled_ms = @max(last, now_ms);
        if (now_ms <= last) return;
        for (rows) |*row| {
            if (!row.active) continue;
            const topic_kind = row.kind orelse continue;
            self.peer_ms[@intFromEnum(topic_kind)] +|= (now_ms - last) * row.mesh.count();
        }
    }

    pub fn added(self: *Metrics, name: []const u8, reason: Addition) void {
        self.additions[kind(name)][@intFromEnum(reason)] +|= 1;
    }

    pub fn removed(self: *Metrics, name: []const u8, reason: Removal) void {
        self.removals[kind(name)][@intFromEnum(reason)] +|= 1;
    }

    pub fn write(self: *const Metrics, w: *prom.Encoder) prom.Error!void {
        inline for (.{
            .{ Addition, "gossipsub_mesh_peer_inclusion_events_total", "additions", "Actual peer/topic mesh additions" },
            .{ Removal, "gossipsub_peer_churn_events_total", "removals", "Actual peer/topic mesh removals, including local subscription changes" },
        }) |group| {
            const events = try w.family(.{ .name = group[1], .kind = .counter, .help = group[3], .labels = &.{ "topic", "reason" } });
            for (@field(self, group[2]), 0..) |counts, index| {
                const label = if (index == policy.kind_count) "unknown" else @tagName(@as(policy.Kind, @enumFromInt(index)));
                inline for (std.meta.fields(group[0])) |reason| try events.sample(.{ label, reason.name }, counts[reason.value]);
            }
        }
        try w.enums(.{ .name = "lodestar_native_gossip_graft_received_total", .kind = .counter, .help = "Received GRAFTs by outcome", .labels = &.{"outcome"} }, GraftOutcome, &self.graft_received);
        try w.enums(.{ .name = "lodestar_native_gossip_prune_sent_total", .kind = .counter, .help = "PRUNEs queued to peers by reason, including refusals of peers outside the mesh", .labels = &.{"reason"} }, Removal, &self.prune_sent);
        const time = try w.family(.{ .name = "lodestar_native_gossip_mesh_peer_seconds_total", .kind = .counter, .help = "Mesh members integrated over time by topic kind, sampled at each heartbeat", .labels = &.{"kind"}, .unit = .seconds });
        for (self.peer_ms, 0..) |ms, index| try time.sample(.{@tagName(@as(policy.Kind, @enumFromInt(index)))}, @as(f64, @floatFromInt(ms)) / 1000);
    }
};

fn kind(name: []const u8) usize {
    const parsed = topic.parse(name) orelse return policy.kind_count;
    const known = topic.Name.parse(parsed.name) orelse return policy.kind_count;
    return @intFromEnum(known.kind);
}
