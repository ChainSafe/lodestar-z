//! Measurements of the seam between the JS thread and the network owner. The bindings runtime
//! records them; the owner copies a snapshot under the runtime mutex before each render.
const std = @import("std");
const histogram = @import("histogram.zig");
const prom = @import("registry.zig");
const processor = @import("../gossip_processor/root.zig");
const gossip_limits = @import("../gossip_limits.zig");
const Kind = gossip_limits.Kind;

/// Native calls timed on the JS thread, with the runtime mutex waits they incur.
pub const Entry = enum { exchange, classify_gossip, report_gossip, publish_gossip, get_metrics, request_start, request_pull, request_retire, incoming_ready, incoming_respond, incoming_terminal, incoming_release };
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

    /// The caller holds the runtime mutex that guards `table`.
    pub fn captureProcessor(self: *Snapshot, table: *const processor.GossipProcessor) void {
        for (&self.items, 0..) |*items, k| items.* = table.occupancy(@enumFromInt(k));
        self.refusals = table.refusals;
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

test "bridge snapshot renders recorded calls, waits, holds, deliveries, notifications and processor state" {
    var recorder: Recorder = .{};
    recorder.calls[@intFromEnum(Entry.report_gossip)].observe(3_000);
    recorder.calls[@intFromEnum(Entry.report_gossip)].observe(2_000_000);
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
    snapshot.items[@intFromEnum(Kind.beacon_attestation)][@intFromEnum(processor.Occupancy.waiting)] = 5;
    snapshot.refusals[@intFromEnum(Kind.data_column_sidecar)][@intFromEnum(processor.Refusal.source_full)] = 2;
    var buffer: [256 * 1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    var encoder: prom.Encoder = .{ .writer = &writer };
    try write(&snapshot, true, &encoder);
    const output = writer.buffered();
    for ([_][]const u8{
        "lodestar_native_bridge_call_seconds_bucket{entry=\"report_gossip\",le=\"0.0001\"} 1\n",
        "lodestar_native_bridge_call_seconds_bucket{entry=\"report_gossip\",le=\"0.0025\"} 2\n",
        "lodestar_native_bridge_call_seconds_count{entry=\"report_gossip\"} 2\n",
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
    }) |expected| try std.testing.expect(std.mem.indexOf(u8, output, expected) != null);
    writer = std.Io.Writer.fixed(&buffer);
    encoder = .{ .writer = &writer };
    try write(&snapshot, false, &encoder);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "state=\"waiting\"} 5\n") == null);
}
