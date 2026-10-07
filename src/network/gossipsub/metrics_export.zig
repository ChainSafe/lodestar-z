const std = @import("std");
const prom = @import("../metrics/registry.zig");
const gossip = @import("root.zig");
const Gossipsub = @import("Gossipsub.zig");
const outbox = @import("outbox.zig");
const StorageRefusal = @import("messages.zig").StorageRefusal;
const IwantOutcome = @import("metrics.zig").IwantOutcome;

pub fn writeCounters(g: *const Gossipsub, w: *prom.Encoder) prom.Error!void {
    try w.enums(.{
        .name = "lodestar_native_gossipsub_storage_refusals_total",
        .kind = .counter,
        .help = "Gossip storage admission attempts refused by bounded resource reason",
        .labels = &.{"reason"},
    }, StorageRefusal, &g.messages.storage_refusals);
    try w.enums(.{
        .name = "lodestar_native_gossip_retention_refusals_total",
        .kind = .counter,
        .help = "Accepted or published messages neither cached nor forwarded because their kind's retention allowance stayed full",
        .labels = &.{"kind"},
    }, gossip.topic.Kind, &g.messages.retention_refusals);
    try w.enums(.{
        .name = "lodestar_native_gossip_iwant_ids_total",
        .kind = .counter,
        .help = "Examined valid IWANT IDs by outcome: absent from history, or present and then over the retransmission limit, queued, or refused for queue pressure",
        .labels = &.{"outcome"},
    }, IwantOutcome, &g.iwant_outcomes);
    try w.scalar(.{
        .name = "gossipsub_iwant_promise_broken",
        .kind = .counter,
        .help = "Randomly sampled IWANT batch promises that expired without their sampled message",
    }, g.counters.broken_promises);
    try w.scalar(.{
        .name = "lodestar_native_gossip_iwant_promises_started_total",
        .kind = .counter,
        .help = "Randomly sampled IWANT batch promises armed when the request's send completed with its sample outstanding; local cancellation can remove one before it expires",
    }, g.recovery.armed);
    try w.enums(.{
        .name = "lodestar_native_gossip_behaviour_penalties_total",
        .kind = .counter,
        .help = "Behaviour penalty units applied to peers by protocol violation",
        .labels = &.{"reason"},
    }, gossip.score.Penalty, &g.peers.scores.penalties);
    try g.overlay.mesh_changes.write(w);
    try g.delivery_metrics.write(w);
    const validation_time = try w.histograms(.{
        .name = "gossipsub_async_validation_delay_from_first_seen",
        .kind = .histogram,
        .help = "Seconds from native gossip admission until an applied validation verdict",
        .labels = &.{},
        .unit = .seconds,
    }, @TypeOf(g.validation_time));
    try validation_time.histogram(.{}, &g.validation_time);
}

pub fn writeScores(g: *const Gossipsub, running: bool, now_ms: u64, w: *prom.Encoder) prom.Error!void {
    const ScorePopulations = @import("metrics.zig").ScorePopulations;
    const populations: ScorePopulations = if (running) .collect(&g.peers, g.overlay, g.sessions, now_ms) else .{};
    try populations.write(w);
}

pub fn writeMessages(g: *const Gossipsub, w: *prom.Encoder) prom.Error!void {
    inline for (.{
        .{ "lodestar_native_gossip_messages_received_total", "received", "Decoded gossip messages consumed from peers by topic kind, including ignored, invalid, duplicate and storage-refused messages" },
        .{ "lodestar_native_gossip_messages_duplicate_total", "duplicate", "Received gossip messages already seen or awaiting validation by topic kind" },
        .{ "lodestar_native_gossip_messages_published_total", "published", "Local publications admitted to gossip history by topic kind, including those without recipients" },
        .{ "gossipsub_accepted_messages_total", "accepted", "Applied accept verdicts by topic kind" },
        .{ "gossipsub_rejected_messages_total", "rejected", "Applied reject verdicts by topic kind" },
        .{ "gossipsub_ignored_messages_total", "ignored", "Applied ignore verdicts by topic kind" },
        .{ "gossipsub_msg_forward_count_total", "forwarded", "Accepted messages handed to forwarding by topic kind" },
    }) |metric| {
        const messages = try w.family(.{ .name = metric[0], .kind = .counter, .help = metric[2], .labels = &.{"topic"} });
        inline for (@typeInfo(gossip.topic_policy.Kind).@"enum".fields) |field| {
            try messages.sample(.{field.name}, @field(g.topic_metrics.counts[field.value], metric[1]));
        }
        try messages.sample(.{"unknown"}, @field(g.topic_metrics.counts[gossip.topic_policy.kind_count], metric[1]));
    }
}

pub fn writeQueueDrops(g: *const Gossipsub, w: *prom.Encoder) prom.Error!void {
    var drops = g.retired_queue_drops;
    for (g.sessions.rows) |*row| for (&drops, row.io.tx.drops) |*total, value| {
        total.* +|= value;
    };
    try w.enums(.{
        .name = "lodestar_native_gossip_queue_drops_total",
        .kind = .counter,
        .help = "Gossip queue admissions refused by resource limit, including mesh control",
        .labels = &.{"reason"},
    }, outbox.DropReason, &drops);
}
