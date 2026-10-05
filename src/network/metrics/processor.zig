//! Host gossip processing metrics sampled under the runtime mutex.
const std = @import("std");
const prom = @import("registry.zig");
const processor = @import("../gossip_processor/root.zig");
const gossip_limits = @import("../gossip_limits.zig");
const Kind = gossip_limits.Kind;

pub const Snapshot = struct {
    items: [gossip_limits.kind_count][processor.GossipProcessor.occupancy_count]u64 = @splat(@splat(0)),
    refusals: [gossip_limits.kind_count][processor.GossipProcessor.refusal_count]u64 = @splat(@splat(0)),
    execution: gossip_limits.Limits = @splat(.{ .items = 0, .bytes = 0 }),

    /// The caller holds the runtime mutex that guards `table`.
    pub fn captureProcessor(self: *Snapshot, table: *const processor.GossipProcessor) void {
        for (&self.items, 0..) |*items, k| items.* = table.occupancy(@enumFromInt(k));
        self.refusals = table.refusals;
        self.execution = table.execution;
    }
};

pub const empty: Snapshot = .{};

/// Renders processor series. Processor gauges read zero once the owner stops.
pub fn write(snapshot: *const Snapshot, running: bool, w: *prom.Encoder) prom.Error!void {
    const items = try w.family(.{ .name = "lodestar_native_gossip_processor_items", .kind = .gauge, .help = "Gossip processor items per kind queued for the host, waiting for a dependency, awaiting a host dependency check, or executing on the host", .labels = &.{ "kind", "state" } });
    for (snapshot.items, 0..) |states, k| for (states, 0..) |count, s| {
        try items.sample(.{ @tagName(@as(Kind, @enumFromInt(k))), @tagName(@as(processor.GossipProcessor.Occupancy, @enumFromInt(s))) }, if (running) count else 0);
    };
    const refusals = try w.family(.{ .name = "lodestar_native_gossip_processor_refusals_total", .kind = .counter, .help = "Gossip messages the processor refused per kind: kind or shared store capacity, the source's share, slot or fork eligibility, or dependency waiting room", .labels = &.{ "kind", "reason" } });
    for (snapshot.refusals, 0..) |reasons, k| for (reasons, 0..) |count, reason| {
        try refusals.sample(.{ @tagName(@as(Kind, @enumFromInt(k))), @tagName(@as(processor.GossipProcessor.Refusal, @enumFromInt(reason))) }, count);
    };
    const limit = try w.family(.{ .name = "lodestar_native_gossip_processor_execution_credit_limit", .kind = .gauge, .help = "Execution credits per kind, in items and bytes", .labels = &.{ "kind", "credit" } });
    for (snapshot.execution, 0..) |value, k| {
        try limit.sample(.{ @tagName(@as(Kind, @enumFromInt(k))), "items" }, value.items);
        try limit.sample(.{ @tagName(@as(Kind, @enumFromInt(k))), "bytes" }, value.bytes);
    }
}

test "processor snapshot renders occupancy, refusals and execution limits" {
    const limits: gossip_limits.Limits = @splat(.{ .items = 4, .bytes = 4096 });
    var table = try processor.GossipProcessor.init(std.testing.allocator, .{ .limits = limits });
    defer table.deinit();
    var snapshot: Snapshot = .{};
    snapshot.captureProcessor(&table);
    snapshot.items[@intFromEnum(Kind.beacon_attestation)][@intFromEnum(processor.GossipProcessor.Occupancy.waiting)] = 5;
    snapshot.refusals[@intFromEnum(Kind.data_column_sidecar)][@intFromEnum(processor.GossipProcessor.Refusal.source_full)] = 2;
    var buffer: [256 * 1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    var encoder: prom.Encoder = .{ .writer = &writer };
    try write(&snapshot, true, &encoder);
    const output = writer.buffered();
    for ([_][]const u8{
        "lodestar_native_gossip_processor_items{kind=\"beacon_attestation\",state=\"waiting\"} 5\n",
        "lodestar_native_gossip_processor_refusals_total{kind=\"data_column_sidecar\",reason=\"source_full\"} 2\n",
        "lodestar_native_gossip_processor_execution_credit_limit{kind=\"data_column_sidecar\",credit=\"items\"} 2\n",
        "lodestar_native_gossip_processor_execution_credit_limit{kind=\"data_column_sidecar\",credit=\"bytes\"} 4096\n",
    }) |expected| try std.testing.expect(std.mem.find(u8, output, expected) != null);
    writer = std.Io.Writer.fixed(&buffer);
    encoder = .{ .writer = &writer };
    try write(&snapshot, false, &encoder);
    try std.testing.expect(std.mem.find(u8, writer.buffered(), "state=\"waiting\"} 5\n") == null);
}
