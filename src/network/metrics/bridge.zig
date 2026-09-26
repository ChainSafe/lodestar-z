//! Measurements of the seam between the JS thread and the network owner. The bindings runtime
//! records them; the owner copies a snapshot under the runtime mutex before each render.
const std = @import("std");
const histogram = @import("histogram.zig");
const prom = @import("registry.zig");
const processor = @import("../gossip_processor/root.zig");
const gossip_limits = @import("../gossip_limits.zig");
const Kind = gossip_limits.Kind;

/// Native calls timed on the JS thread.
pub const Entry = enum { exchange, publish_gossip, get_metrics, request_start, request_pull, request_retire, incoming_ready, incoming_respond, incoming_terminal, incoming_release };
/// Items the JS thread's native calls deliver to the host: settled table cells, peer events,
/// serving starts, and gossip messages and dependency checks claimed.
pub const Delivery = enum { completion, peer_event, serving_start, gossip_message, dependency_check };
const entry_count = @typeInfo(Entry).@"enum".fields.len;
const delivery_count = @typeInfo(Delivery).@"enum".fields.len;

pub const Duration = histogram.Histogram(u64, &.{ 100_000, 250_000, 500_000, 1_000_000, 2_500_000, 5_000_000, 10_000_000, 25_000_000, 50_000_000, 100_000_000, 250_000_000, 500_000_000, 1_000_000_000 }, .{ .unit = .nanoseconds });

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

/// Runtime-owned measurements. The JS thread writes `calls` without the runtime mutex and
/// `delivered` under it.
pub const Recorder = struct {
    calls: [entry_count]SharedDuration = @splat(.{}),
    delivered: [delivery_count]u64 = @splat(0),

    /// The JS thread holds the runtime mutex.
    pub fn deliver(self: *Recorder, kind: Delivery, count: usize) void {
        self.delivered[@intFromEnum(kind)] +|= count;
    }

    /// The owner holds the runtime mutex.
    pub fn snapshot(self: *const Recorder, into: *Snapshot) void {
        for (&into.calls, &self.calls) |*value, *source| value.* = source.load();
        into.delivered = self.delivered;
    }
};

pub const Snapshot = struct {
    calls: [entry_count]Duration = @splat(.{}),
    delivered: [delivery_count]u64 = @splat(0),
    items: [gossip_limits.kind_count][processor.occupancy_count]u64 = @splat(@splat(0)),
    refusals: [gossip_limits.kind_count][processor.refusal_count]u64 = @splat(@splat(0)),
    execution: gossip_limits.Limits = @splat(.{ .items = 0, .bytes = 0 }),

    /// The caller holds the runtime mutex that guards `table`.
    pub fn captureProcessor(self: *Snapshot, table: *const processor.GossipProcessor) void {
        for (&self.items, 0..) |*items, k| items.* = table.occupancy(@enumFromInt(k));
        self.refusals = table.refusals;
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
    const limit = try w.family(.{ .name = "lodestar_native_gossip_processor_execution_credit_limit", .kind = .gauge, .help = "Execution credits per kind, in items and bytes", .labels = &.{ "kind", "credit" } });
    for (snapshot.execution, 0..) |value, k| {
        try limit.sample(.{ @tagName(@as(Kind, @enumFromInt(k))), "items" }, value.items);
        try limit.sample(.{ @tagName(@as(Kind, @enumFromInt(k))), "bytes" }, value.bytes);
    }
    const calls = try w.histograms(.{ .name = "lodestar_native_bridge_call_seconds", .kind = .histogram, .help = "Wall duration of native calls on the JS thread", .labels = &.{"entry"}, .unit = .seconds }, Duration);
    for (&snapshot.calls, 0..) |*value, e| try calls.histogram(.{@tagName(@as(Entry, @enumFromInt(e)))}, value);
    const delivered = try w.family(.{ .name = "lodestar_native_bridge_delivered_items_total", .kind = .counter, .help = "Items native calls on the JS thread delivered to the host: settled table cells, peer events, serving starts, and claimed gossip messages and dependency checks", .labels = &.{"kind"} });
    for (snapshot.delivered, 0..) |count, k| try delivered.sample(.{@tagName(@as(Delivery, @enumFromInt(k)))}, count);
}

test "bridge snapshot renders recorded calls, deliveries and processor state" {
    const limits: gossip_limits.Limits = @splat(.{ .items = 4, .bytes = 4096 });
    var table = try processor.GossipProcessor.init(std.testing.allocator, .{ .capacity = gossip_limits.items(&limits), .bytes = gossip_limits.bytes(&limits), .limits = limits });
    defer table.deinit();
    var recorder: Recorder = .{};
    recorder.calls[@intFromEnum(Entry.exchange)].observe(3_000);
    recorder.calls[@intFromEnum(Entry.exchange)].observe(2_000_000);
    recorder.deliver(.gossip_message, 64);
    recorder.deliver(.gossip_message, 3);
    recorder.deliver(.completion, 1);
    var snapshot: Snapshot = .{};
    recorder.snapshot(&snapshot);
    snapshot.captureProcessor(&table);
    snapshot.items[@intFromEnum(Kind.beacon_attestation)][@intFromEnum(processor.Occupancy.waiting)] = 5;
    snapshot.refusals[@intFromEnum(Kind.data_column_sidecar)][@intFromEnum(processor.Refusal.source_full)] = 2;
    var buffer: [256 * 1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    var encoder: prom.Encoder = .{ .writer = &writer };
    try write(&snapshot, true, &encoder);
    const output = writer.buffered();
    for ([_][]const u8{
        "lodestar_native_bridge_call_seconds_bucket{entry=\"exchange\",le=\"0.0001\"} 1\n",
        "lodestar_native_bridge_call_seconds_bucket{entry=\"exchange\",le=\"0.0025\"} 2\n",
        "lodestar_native_bridge_call_seconds_count{entry=\"exchange\"} 2\n",
        "lodestar_native_bridge_delivered_items_total{kind=\"gossip_message\"} 67\n",
        "lodestar_native_bridge_delivered_items_total{kind=\"completion\"} 1\n",
        "lodestar_native_bridge_delivered_items_total{kind=\"peer_event\"} 0\n",
        "lodestar_native_gossip_processor_items{kind=\"beacon_attestation\",state=\"waiting\"} 5\n",
        "lodestar_native_gossip_processor_refusals_total{kind=\"data_column_sidecar\",reason=\"source_full\"} 2\n",
        "lodestar_native_gossip_processor_execution_credit_limit{kind=\"data_column_sidecar\",credit=\"items\"} 2\n",
        "lodestar_native_gossip_processor_execution_credit_limit{kind=\"data_column_sidecar\",credit=\"bytes\"} 4096\n",
    }) |expected| try std.testing.expect(std.mem.indexOf(u8, output, expected) != null);
    writer = std.Io.Writer.fixed(&buffer);
    encoder = .{ .writer = &writer };
    try write(&snapshot, false, &encoder);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "state=\"waiting\"} 5\n") == null);
}
