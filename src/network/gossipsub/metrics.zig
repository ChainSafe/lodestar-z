const prom = @import("../metrics/registry.zig");
const std = @import("std");
const policy = @import("topic_policy.zig");
const topic = @import("topic.zig");

pub const ValidationTime = @import("../metrics/histogram.zig").Duration(&.{ 10, 30, 100, 300, 1000, 3000, 10000 });

/// Data frame recipients by delivery origin: selected, then queued, pressured or unavailable;
/// queued frames later complete when QUIC accepts their last byte, which is not delivery, or are
/// cancelled by a stream reset.
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
        const recipients = try w.family(.{ .name = "lodestar_native_gossip_data_recipients_total", .kind = .counter, .help = "Data frame recipients by delivery origin: selected, then queued, pressured or unavailable; queued frames later complete when QUIC accepts their last byte, which is not delivery, or are cancelled by a stream reset", .labels = &.{ "origin", "outcome" } });
        inline for (@typeInfo(delivery.Origin).@"enum".fields) |origin| {
            inline for (@typeInfo(Outcome).@"enum".fields) |outcome| try recipients.sample(.{ origin.name, outcome.name }, self.recipients[origin.value][outcome.value]);
        }
    }
};

/// Applied verdicts, and accepted messages handed to forwarding, for one topic kind.
pub const Counters = struct {
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

/// An IWANT ID absent from history, or present and then suppressed by IDONTWANT, over its
/// retransmission limit, queued or refused for queue pressure.
pub const IwantOutcome = enum { miss, suppressed, limited, queued, refused };
pub const iwant_outcome_count = @typeInfo(IwantOutcome).@"enum".fields.len;

test {
    _ = @import("metrics_test.zig");
}
