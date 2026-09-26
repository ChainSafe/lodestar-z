//! Measurements of the seam between the JS thread and the network owner. The bindings runtime
//! records them; the owner copies a snapshot under the runtime mutex before each render.
const std = @import("std");
const histogram = @import("histogram.zig");
const prom = @import("registry.zig");
const processor = @import("../gossip_processor/root.zig");
const stages = processor.stages_mod;
const gossip_limits = @import("../gossip_limits.zig");
const Kind = gossip_limits.Kind;

/// Native calls timed on the JS thread, with the runtime mutex waits they incur.
pub const Entry = enum { exchange, publish_gossip, get_metrics, request_start, request_pull, request_retire, incoming_ready, incoming_respond, incoming_terminal, incoming_release };
/// Owner sections that hold the runtime mutex, named after the owner steps that take it.
pub const Phase = enum { turn, reports, commands, publications, requests, gossip_flags, request_flags, incoming_flags, capture, gossip_ingress, peer_lane, metrics };
pub const AdmissionKind = enum { block, column, aggregate, attestation, other };
/// Items the JS thread's native calls deliver to the host: settled table cells, peer events,
/// serving starts, and gossip messages and dependency checks claimed.
pub const Delivery = enum { completion, peer_event, serving_start, gossip_message, dependency_check };
const entry_count = @typeInfo(Entry).@"enum".fields.len;
const phase_count = @typeInfo(Phase).@"enum".fields.len;
const admission_kind_count = @typeInfo(AdmissionKind).@"enum".fields.len;
const delivery_count = @typeInfo(Delivery).@"enum".fields.len;

pub fn admissionKind(kind: Kind) AdmissionKind {
    return switch (kind) {
        .beacon_block => .block,
        .data_column_sidecar => .column,
        .beacon_aggregate_and_proof => .aggregate,
        .beacon_attestation => .attestation,
        else => .other,
    };
}

pub const Duration = histogram.Histogram(u64, &.{ 100_000, 250_000, 500_000, 1_000_000, 2_500_000, 5_000_000, 10_000_000, 25_000_000, 50_000_000, 100_000_000, 250_000_000, 500_000_000, 1_000_000_000 }, .{ .unit = .nanoseconds });
pub const Chain = histogram.Histogram(u64, &.{ 0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 999 }, .{});
pub const PublicationLatency = histogram.Duration(&.{ 0, 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 5000 });

/// Monotonic nanoseconds on any thread.
pub fn now() u64 {
    return @import("timing.zig").now(std.Io.Threaded.global_single_threaded.io());
}

/// A Duration written without the runtime mutex. Each word is an independent relaxed counter,
/// so a concurrent read can miss the observation in flight; the count is the bucket total.
pub const SharedDuration = struct {
    buckets: [Duration.bounds.len + 1]std.atomic.Value(u64) = @splat(std.atomic.Value(u64).init(0)),
    sum: std.atomic.Value(u64) = .init(0),

    pub fn observe(self: *SharedDuration, ns: u64) void {
        var index: usize = Duration.bounds.len;
        for (Duration.bounds, 0..) |bound, i| {
            if (ns <= bound) {
                index = i;
                break;
            }
        }
        _ = self.buckets[index].fetchAdd(1, .monotonic);
        _ = self.sum.fetchAdd(ns, .monotonic);
    }

    pub fn load(self: *const SharedDuration) Duration {
        var result: Duration = .{};
        for (&result.buckets, &self.buckets) |*bucket, *value| {
            bucket.* = value.load(.monotonic);
            result.count +|= bucket.*;
        }
        result.sum = self.sum.load(.monotonic);
        return result;
    }
};

/// Runtime-owned measurements. The JS thread writes `calls` and `notify` without the runtime
/// mutex and the other JS-thread fields under it; only the owner writes `owner_waits`, `holds` and
/// `admission_lag`.
pub const Recorder = struct {
    calls: [entry_count]SharedDuration = @splat(.{}),
    notify: SharedDuration = .{},
    waits: [entry_count]Duration = @splat(.{}),
    js_pings: [entry_count]u64 = @splat(0),
    notifies: u64 = 0,
    chain: Chain = .{},
    chained: u64 = 0,
    delivered: [delivery_count]u64 = @splat(0),
    owner_waits: [phase_count]Duration = @splat(.{}),
    holds: [phase_count]Duration = @splat(.{}),
    admission_lag: [admission_kind_count]Duration = @splat(.{}),

    /// The JS thread holds the runtime mutex.
    pub fn deliver(self: *Recorder, kind: Delivery, count: usize) void {
        self.delivered[@intFromEnum(kind)] +|= count;
    }

    pub fn notified(self: *Recorder) void {
        self.notifies +|= 1;
        self.chained +|= 1;
    }

    /// A drain boundary: records the notification callbacks since the previous one.
    pub fn boundary(self: *Recorder) void {
        self.chain.observe(self.chained);
        self.chained = 0;
    }

    /// The owner holds the runtime mutex.
    pub fn snapshot(self: *const Recorder, into: *Snapshot) void {
        for (&into.calls, &self.calls) |*value, *source| value.* = source.load();
        into.notify = self.notify.load();
        into.waits = self.waits;
        into.js_pings = self.js_pings;
        into.notifies = self.notifies;
        into.chain = self.chain;
        into.delivered = self.delivered;
        into.owner_waits = self.owner_waits;
        into.holds = self.holds;
        into.admission_lag = self.admission_lag;
    }
};

pub const Snapshot = struct {
    calls: [entry_count]Duration = @splat(.{}),
    notify: Duration = .{},
    waits: [entry_count]Duration = @splat(.{}),
    js_pings: [entry_count]u64 = @splat(0),
    notifies: u64 = 0,
    chain: Chain = .{},
    delivered: [delivery_count]u64 = @splat(0),
    owner_waits: [phase_count]Duration = @splat(.{}),
    holds: [phase_count]Duration = @splat(.{}),
    admission_lag: [admission_kind_count]Duration = @splat(.{}),
    publication_queue: PublicationLatency = .{},
    items: [gossip_limits.kind_count][processor.occupancy_count]u64 = @splat(@splat(0)),
    refusals: [gossip_limits.kind_count][processor.refusal_count]u64 = @splat(@splat(0)),
    /// Stage timing with the open credit waits and credits in use accounted up to the capture.
    stages: stages.Stages = .{},
    execution: gossip_limits.Limits = @splat(.{ .items = 0, .bytes = 0 }),

    /// The caller holds the runtime mutex that guards `table`.
    pub fn captureProcessor(self: *Snapshot, table: *const processor.GossipProcessor, now_ns: u64) void {
        for (&self.items, 0..) |*items, k| items.* = table.occupancy(@enumFromInt(k));
        self.refusals = table.refusals;
        self.stages = table.stages;
        self.stages.tick(now_ns);
        for (0..gossip_limits.kind_count) |k| {
            const kind: Kind = @enumFromInt(k);
            self.stages.credit(kind, false);
            self.stages.integrate(kind, table.executing_items[k], table.executing_bytes[k]);
        }
        self.execution = table.execution.?;
    }
};

pub const empty: Snapshot = .{};

/// Renders the bridge and processor series. Processor gauges read zero once the owner stops.
pub fn write(snapshot: *const Snapshot, running: bool, w: *prom.Encoder) prom.Error!void {
    const items = try w.family(.{ .name = "lodestar_native_gossip_processor_items", .kind = .gauge, .help = "Gossip processor items per kind queued for the host, waiting for a dependency, awaiting a host dependency check, or executing on the host", .labels = &.{ "kind", "state" } });
    for (snapshot.items, 0..) |states, k| for (states, 0..) |count, s| {
        try items.sample(.{ @tagName(@as(Kind, @enumFromInt(k))), @tagName(@as(processor.Occupancy, @enumFromInt(s))) }, if (running) count else 0);
    };
    const refusals = try w.family(.{ .name = "lodestar_native_gossip_processor_refusals_total", .kind = .counter, .help = "Gossip messages the processor refused per kind: kind or shared store capacity, the source's share, slot or fork eligibility, or dependency waiting room", .labels = &.{ "kind", "reason" } });
    for (snapshot.refusals, 0..) |reasons, k| for (reasons, 0..) |count, reason| {
        try refusals.sample(.{ @tagName(@as(Kind, @enumFromInt(k))), @tagName(@as(processor.Refusal, @enumFromInt(reason))) }, count);
    };
    const stage = try w.histograms(.{ .name = "lodestar_native_gossip_processor_stage_seconds", .kind = .histogram, .help = "Processor stages of each gossip message per kind: receipt (gossipsub admission) to dependency-ready; ready to claim, split into time the kind's execution credits refused its next ready item (ready_credit_blocked) and the rest (ready_other_wait), neither alone proving a cause; claim to the verdict's application, which frees its credit; for verdicts the host times, its validation settling to the call of the exchange carrying the verdict and to the application; and application to the owner report that hands an accepted message to gossip delivery. Host and native means add up at the claim and the verdict's exchange call to within the host's microseconds from its timestamp to the call. Add means only over comparable populations, never quantiles", .labels = &.{ "kind", "interval" }, .unit = .seconds }, stages.Duration);
    for (&snapshot.stages.intervals, 0..) |*intervals, k| for (intervals, 0..) |*value, i| {
        try stage.histogram(.{ @tagName(@as(Kind, @enumFromInt(k))), @tagName(@as(stages.Interval, @enumFromInt(i))) }, value);
    };
    const stops = try w.family(.{ .name = "lodestar_native_gossip_processor_claim_stops_total", .kind = .counter, .help = "Exchange claims that left a kind's next ready item, by why: the kind's execution items or bytes, the claim's item, work or byte bound, the ordinary gate, or other", .labels = &.{ "kind", "reason" } });
    for (snapshot.stages.stops, 0..) |reasons, k| for (reasons, 0..) |count, reason| {
        try stops.sample(.{ @tagName(@as(Kind, @enumFromInt(k))), @tagName(@as(stages.Stop, @enumFromInt(reason))) }, count);
    };
    const blocked = try w.family(.{ .name = "lodestar_native_gossip_processor_credit_blocked_seconds_total", .kind = .counter, .help = "Time each kind's execution credits refused its next ready item", .labels = &.{"kind"}, .unit = .seconds });
    for (snapshot.stages.blocked_ns, 0..) |ns, k| try blocked.sample(.{@tagName(@as(Kind, @enumFromInt(k)))}, seconds(ns));
    const in_use = try w.family(.{ .name = "lodestar_native_gossip_processor_execution_credit_seconds_total", .kind = .counter, .help = "Execution credits in use per kind integrated over time, in item-seconds and byte-seconds; the rate is the mean in use", .labels = &.{ "kind", "credit" } });
    for (snapshot.stages.item_ns, snapshot.stages.byte_ns, 0..) |item_ns, byte_ns, k| {
        try in_use.sample(.{ @tagName(@as(Kind, @enumFromInt(k))), "items" }, seconds(item_ns));
        try in_use.sample(.{ @tagName(@as(Kind, @enumFromInt(k))), "bytes" }, seconds(byte_ns));
    }
    const limit = try w.family(.{ .name = "lodestar_native_gossip_processor_execution_credit_limit", .kind = .gauge, .help = "Execution credits per kind, in items and bytes", .labels = &.{ "kind", "credit" } });
    for (snapshot.execution, 0..) |value, k| {
        try limit.sample(.{ @tagName(@as(Kind, @enumFromInt(k))), "items" }, value.items);
        try limit.sample(.{ @tagName(@as(Kind, @enumFromInt(k))), "bytes" }, value.bytes);
    }
    const lag = try w.histograms(.{ .name = "lodestar_native_gossip_admission_lag_seconds", .kind = .histogram, .help = "Processor admission time, runtime mutex acquisition included, after the owner turn's tick", .labels = &.{"kind"}, .unit = .seconds }, Duration);
    for (&snapshot.admission_lag, 0..) |*value, k| try lag.histogram(.{@tagName(@as(AdmissionKind, @enumFromInt(k)))}, value);
    const calls = try w.histograms(.{ .name = "lodestar_native_bridge_call_seconds", .kind = .histogram, .help = "Wall duration of native calls on the JS thread", .labels = &.{"entry"}, .unit = .seconds }, Duration);
    for (&snapshot.calls, 0..) |*value, e| try calls.histogram(.{@tagName(@as(Entry, @enumFromInt(e)))}, value);
    const waits = try w.histograms(.{ .name = "lodestar_native_bridge_lock_wait_seconds", .kind = .histogram, .help = "JS thread waits to acquire the runtime mutex, one sample per acquisition", .labels = &.{"entry"}, .unit = .seconds }, Duration);
    for (&snapshot.waits, 0..) |*value, e| try waits.histogram(.{@tagName(@as(Entry, @enumFromInt(e)))}, value);
    const owner_waits = try w.histograms(.{ .name = "lodestar_native_bridge_owner_lock_wait_seconds", .kind = .histogram, .help = "Owner waits to acquire the runtime mutex, one sample per acquisition", .labels = &.{"phase"}, .unit = .seconds }, Duration);
    for (&snapshot.owner_waits, 0..) |*value, p| try owner_waits.histogram(.{@tagName(@as(Phase, @enumFromInt(p)))}, value);
    const holds = try w.histograms(.{ .name = "lodestar_native_bridge_lock_hold_seconds", .kind = .histogram, .help = "Owner holds of the runtime mutex, one sample per acquisition", .labels = &.{"phase"}, .unit = .seconds }, Duration);
    for (&snapshot.holds, 0..) |*value, p| try holds.histogram(.{@tagName(@as(Phase, @enumFromInt(p)))}, value);
    try w.scalar(.{ .name = "lodestar_native_bridge_notify_total", .kind = .counter, .help = "Owner notification callbacks run on the JS thread" }, snapshot.notifies);
    const notify = try w.histograms(.{ .name = "lodestar_native_bridge_notify_seconds", .kind = .histogram, .help = "Duration of owner notification callbacks on the JS thread", .unit = .seconds }, Duration);
    try notify.histogram(.{}, &snapshot.notify);
    const chain = try w.histograms(.{ .name = "lodestar_native_bridge_notify_chain", .kind = .histogram, .help = "Owner notification callbacks between two host drain boundaries" }, Chain);
    try chain.histogram(.{}, &snapshot.chain);
    const pings = try w.family(.{ .name = "lodestar_native_bridge_js_pings_total", .kind = .counter, .help = "Owner notifications queued from the JS thread", .labels = &.{"entry"} });
    for (snapshot.js_pings, 0..) |count, e| try pings.sample(.{@tagName(@as(Entry, @enumFromInt(e)))}, count);
    const delivered = try w.family(.{ .name = "lodestar_native_bridge_delivered_items_total", .kind = .counter, .help = "Items native calls on the JS thread delivered to the host: settled table cells, peer events, serving starts, and claimed gossip messages and dependency checks", .labels = &.{"kind"} });
    for (snapshot.delivered, 0..) |count, k| try delivered.sample(.{@tagName(@as(Delivery, @enumFromInt(k)))}, count);
    const queue = try w.histograms(.{ .name = "lodestar_native_publication_queue_seconds", .kind = .histogram, .help = "Gossip publication wait from host submission to owner execution", .unit = .seconds }, PublicationLatency);
    try queue.histogram(.{}, &snapshot.publication_queue);
}

fn seconds(ns: anytype) f64 {
    return @as(f64, @floatFromInt(ns)) / std.time.ns_per_s;
}

test "bridge snapshot renders recorded calls, waits, holds, deliveries, notifications and processor state" {
    const limits: gossip_limits.Limits = @splat(.{ .items = 4, .bytes = 4096 });
    var table = try processor.GossipProcessor.init(std.testing.allocator, .{ .capacity = gossip_limits.items(&limits), .bytes = gossip_limits.bytes(&limits), .limits = limits });
    defer table.deinit();
    const column = @intFromEnum(Kind.data_column_sidecar);
    table.stages.tick(1_000_000_000);
    table.stages.integrate(.data_column_sidecar, 0, 0);
    table.executing_items[column] = 2;
    table.executing_bytes[column] = 4096;
    defer table.executing_items[column] = 0;
    defer table.executing_bytes[column] = 0;
    table.stages.credit(.data_column_sidecar, true);
    table.stages.observe(.data_column_sidecar, .ready_credit_blocked, 7_000_000);
    table.stages.stop(.data_column_sidecar, .item_credit);
    var recorder: Recorder = .{};
    recorder.calls[@intFromEnum(Entry.exchange)].observe(3_000);
    recorder.calls[@intFromEnum(Entry.exchange)].observe(2_000_000);
    recorder.holds[@intFromEnum(Phase.gossip_flags)].observe(750_000);
    recorder.owner_waits[@intFromEnum(Phase.capture)].observe(0);
    recorder.owner_waits[@intFromEnum(Phase.capture)].observe(300_000);
    recorder.deliver(.gossip_message, 64);
    recorder.deliver(.gossip_message, 3);
    recorder.deliver(.completion, 1);
    recorder.notified();
    recorder.notified();
    recorder.boundary();
    recorder.boundary();
    var snapshot: Snapshot = .{};
    recorder.snapshot(&snapshot);
    // The capture accounts the open credit wait and the credits in use up to its time, leaving the table's own.
    snapshot.captureProcessor(&table, 1_500_000_000);
    try std.testing.expect(table.stages.blocked_since[column] != null);
    try std.testing.expectEqual(@as(u128, 0), table.stages.item_ns[column]);
    snapshot.items[@intFromEnum(Kind.beacon_attestation)][@intFromEnum(processor.Occupancy.waiting)] = 5;
    snapshot.refusals[@intFromEnum(Kind.data_column_sidecar)][@intFromEnum(processor.Refusal.source_full)] = 2;
    var buffer: [512 * 1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    var encoder: prom.Encoder = .{ .writer = &writer };
    try write(&snapshot, true, &encoder);
    const output = writer.buffered();
    for ([_][]const u8{
        "lodestar_native_bridge_call_seconds_bucket{entry=\"exchange\",le=\"0.0001\"} 1\n",
        "lodestar_native_bridge_call_seconds_bucket{entry=\"exchange\",le=\"0.0025\"} 2\n",
        "lodestar_native_bridge_call_seconds_count{entry=\"exchange\"} 2\n",
        "lodestar_native_bridge_lock_hold_seconds_bucket{phase=\"gossip_flags\",le=\"0.001\"} 1\n",
        "lodestar_native_bridge_owner_lock_wait_seconds_bucket{phase=\"capture\",le=\"0.0001\"} 1\n",
        "lodestar_native_bridge_owner_lock_wait_seconds_bucket{phase=\"capture\",le=\"0.0005\"} 2\n",
        "lodestar_native_bridge_owner_lock_wait_seconds_count{phase=\"turn\"} 0\n",
        "lodestar_native_bridge_delivered_items_total{kind=\"gossip_message\"} 67\n",
        "lodestar_native_bridge_delivered_items_total{kind=\"completion\"} 1\n",
        "lodestar_native_bridge_delivered_items_total{kind=\"peer_event\"} 0\n",
        "lodestar_native_bridge_notify_total 2\n",
        "lodestar_native_bridge_notify_chain_bucket{le=\"0\"} 1\n",
        "lodestar_native_bridge_notify_chain_bucket{le=\"2\"} 2\n",
        "lodestar_native_gossip_processor_items{kind=\"beacon_attestation\",state=\"waiting\"} 5\n",
        "lodestar_native_gossip_processor_refusals_total{kind=\"data_column_sidecar\",reason=\"source_full\"} 2\n",
        "lodestar_native_gossip_processor_stage_seconds_bucket{kind=\"data_column_sidecar\",interval=\"ready_credit_blocked\",le=\"0.005\"} 0\n",
        "lodestar_native_gossip_processor_stage_seconds_bucket{kind=\"data_column_sidecar\",interval=\"ready_credit_blocked\",le=\"0.01\"} 1\n",
        "lodestar_native_gossip_processor_stage_seconds_count{kind=\"data_column_sidecar\",interval=\"claimed_to_applied\"} 0\n",
        "lodestar_native_gossip_processor_claim_stops_total{kind=\"data_column_sidecar\",reason=\"item_credit\"} 1\n",
        "lodestar_native_gossip_processor_credit_blocked_seconds_total{kind=\"data_column_sidecar\"} 0.5\n",
        "lodestar_native_gossip_processor_execution_credit_seconds_total{kind=\"data_column_sidecar\",credit=\"items\"} 1\n",
        "lodestar_native_gossip_processor_execution_credit_seconds_total{kind=\"data_column_sidecar\",credit=\"bytes\"} 2048\n",
        "lodestar_native_gossip_processor_execution_credit_limit{kind=\"data_column_sidecar\",credit=\"items\"} 2\n",
        "lodestar_native_gossip_processor_execution_credit_limit{kind=\"data_column_sidecar\",credit=\"bytes\"} 4096\n",
    }) |expected| try std.testing.expect(std.mem.indexOf(u8, output, expected) != null);
    writer = std.Io.Writer.fixed(&buffer);
    encoder = .{ .writer = &writer };
    try write(&snapshot, false, &encoder);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "state=\"waiting\"} 5\n") == null);
}
