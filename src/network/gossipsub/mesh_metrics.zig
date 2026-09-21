const std = @import("std");
const topic = @import("topic.zig");
const policy = @import("topic_policy.zig");
const prom = @import("../metrics/registry.zig");

pub const Addition = enum { underfull, outbound, opportunistic, remote_graft };
pub const Removal = enum { disconnected, stream_unavailable, bad_score, prune, remote_unsubscribe, local_unsubscribe, excess, direct, backoff };

pub const Metrics = struct {
    additions: [policy.kind_count + 1][std.meta.fields(Addition).len]u64 = @splat(@splat(0)),
    removals: [policy.kind_count + 1][std.meta.fields(Removal).len]u64 = @splat(@splat(0)),

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
    }
};

fn kind(name: []const u8) usize {
    const parsed = topic.parse(name) orelse return policy.kind_count;
    const known = topic.Name.parse(parsed.name) orelse return policy.kind_count;
    return @intFromEnum(known.kind);
}
