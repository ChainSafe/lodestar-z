const std = @import("std");
const t = std.testing;
const gossip = @import("gossipsub.zig");
const processor = @import("../gossip_processor/root.zig");
const messages = @import("messages.zig");
const support = @import("test_support.zig");
const protobuf = @import("protobuf.zig");
const snappy = @import("snappy");
const block = "/eth2/01020304/beacon_block/ssz_snappy";
const attestation = "/eth2/01020304/beacon_attestation_0/ssz_snappy";
const options: gossip.Options = .{
    .topic_policy = &.{@import("topic_fixture.zig").bytes(.{ 1, 2, 3, 4 })},
    .random_seed = 1,
    .connected_capacity = 4,
    .retained_capacity = 8,
    .retained_outbound_reserve = 1,
    .observe_subscriptions = false,
    .body_buffer_bytes = 64,
};

const Consumer = struct {
    table: *processor.GossipProcessor,
    fill_during_delivery: bool = false,

    fn sink(self: *Consumer) gossip.MessageSink {
        return .{ .context = self, .has_capacity = hasCapacity, .deliver = deliver };
    }

    fn hasCapacity(context: *anyopaque, kind: processor.limits_mod.Kind, len: usize) bool {
        const self: *Consumer = @ptrCast(@alignCast(context));
        return self.table.hasCapacity(kind, len);
    }

    fn deliver(context: *anyopaque, message: *const messages.MessageEvent) bool {
        const self: *Consumer = @ptrCast(@alignCast(context));
        const table = self.table;
        const publication = if (self.fill_during_delivery) table.budget.limit - table.budget.used else 0;
        table.budget.reserve(publication) catch unreachable;
        defer table.budget.release(publication);
        const kind = @import("topic.zig").parseCanonical(message.topic).?.name.kind;
        const token = table.reserveKind(kind, message.bytes.len) catch |err| switch (err) {
            error.NetworkBridgeFull, error.NetworkGossipFull => return false,
            else => unreachable,
        };
        const cell = table.get(token).?;
        cell.handle = message.handle;
        cell.source = message.source;
        cell.identity = message.identity;
        cell.connection = message.peer;
        cell.id = message.id;
        cell.deadline = message.deadline;
        cell.admitted_ms = message.admitted_ms;
        cell.topic_len = @intCast(message.topic.len);
        @memcpy(cell.topic[0..cell.topic_len], message.topic);
        table.install(token, message.bytes);
        return true;
    }
};

fn receive(g: *gossip.Gossipsub, source: u16, topic: []const u8, payload: []const u8) !void {
    var compressed: [8192]u8 = undefined;
    const len = try snappy.raw.compress(payload, &compressed);
    var turn = @import("session_io.zig").beginPump(g, .{ .mono_ms = 1, .unix_s = 0 }, &.{});
    var credit = @import("turn.zig").Credits.peer(&g.options);
    try t.expectEqual(.done, g.receiveItem(g.sessions.ref(source), .{ .message = .{ .topic = topic, .data = compressed[0..len] } }, &turn, &credit));
    try t.expectEqual(@as(usize, 0), turn.count);
    try t.expectEqual(@as(usize, 0), turn.used);
}

test "gossip direct processor admission drains paged RPCs while the host queue stays full" {
    var pair: @import("test_pair.zig").Pair = .{};
    try pair.initOpts(options, options);
    defer pair.deinit();
    const g = pair.shared.server.gossipsub;
    try support.subscribe(g, block);
    pair.server_event_capacity = 0;
    var budget: @import("../byte_budget.zig").Budget = .{ .limit = 65536 };
    var table = try processor.GossipProcessor.initPlanned(t.allocator, 2, 16384, &budget, null);
    defer table.deinit();
    defer table.close();
    var consumer: Consumer = .{ .table = &table };
    const sink = consumer.sink();
    g.message_sink = &sink;
    defer g.message_sink = null;
    for (0..16) |_| try pair.pumpOnce();

    var payloads: [3][6000]u8 = undefined;
    var random = std.Random.DefaultPrng.init(82);
    var compressed: [8192]u8 = undefined;
    var body: [32768]u8 = undefined;
    var writer = protobuf.Writer.init(&body);
    for (&payloads) |*payload| {
        random.random().bytes(payload);
        const len = try snappy.raw.compress(payload, &compressed);
        protobuf.writeMessage(&writer, compressed[0..len], block);
    }
    var framed: [32776]u8 = undefined;
    const wire = @import("frame.zig").writeFrame(&framed, writer.written());
    const source = g.sessions.findPeer(pair.shared.handles.server).?;
    const row = &g.sessions.rows[source];
    const score = g.peers.score(row.logical, pair.shared.pair.now.mono_ms);
    var sent: usize = 0;
    for (0..128) |_| {
        if (sent < wire.len) sent += pair.shared.pair.client.write(pair.clientStream(), wire[sent..], false) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => return err,
        };
        try pair.pumpOnce();
        if (sent == wire.len and g.counters.message_capacity_refusals > 0 and row.io.rpc == null) break;
    }
    try t.expectEqual(wire.len, sent);
    try t.expectEqual(@as(usize, 2), table.diag.occupied);
    try t.expectEqual(@as(u64, 2), g.messages.decoded_messages);
    try t.expectEqual(@as(u64, 1), g.messages.storage_refusals[@intFromEnum(messages.StorageRefusal.processor_capacity)]);
    try t.expectEqual(@as(usize, 2), g.resourceSnapshot().pending_validations);
    try t.expectEqual(g.sessions.receive_pool.next.len, g.sessions.receive_pool.free_pages);
    try t.expect(row.io.rpc == null and row.in_stream != null);
    try t.expectEqual(@as(u64, 0), g.counters.local_pressure_resets);
    try t.expectEqual(score, g.peers.score(row.logical, pair.shared.pair.now.mono_ms));
    @memset(g.msg_scratch, 0xa5);
    @memset(g.sessions.decode_scratch, 0xa5);
    @memset(row.io.body, 0xa5);
    var actual: [6000]u8 = undefined;
    for (table.cells, 0..) |*cell, i| {
        table.copyPayload(cell, &actual);
        try t.expectEqualSlices(u8, &payloads[i], &actual);
    }
}

test "gossip full processor preserves duplicate attribution without runtime allocations" {
    var ledger: @import("../reservations.zig").Reservations = .{ .backing = t.allocator };
    var g = try support.init(ledger.allocator(), options);
    defer g.deinit();
    var budget: @import("../byte_budget.zig").Budget = .{ .limit = 65536 };
    var table = try processor.GossipProcessor.initPlanned(ledger.allocator(), 1, 4096, &budget, null);
    defer table.deinit();
    defer table.close();
    var consumer: Consumer = .{ .table = &table };
    const sink = consumer.sink();
    g.message_sink = &sink;
    try support.subscribe(&g, block);
    for (0..2) |i| _ = support.addPeer(&g, .{ .index = @intCast(i), .generation = 1 }, .v1_2).?;
    const allocations = ledger.allocation_calls;
    ledger.byte_limit = ledger.bytes;
    try receive(&g, 0, block, "pending");
    const handle = table.cells[0].handle;
    try receive(&g, 1, block, "pending");
    try receive(&g, 1, block, "unexamined");
    var turn = @import("session_io.zig").beginPump(&g, .{ .mono_ms = 1, .unix_s = 0 }, &.{});
    var credit = @import("turn.zig").Credits.peer(&g.options);
    try t.expectEqual(.done, g.receiveItem(g.sessions.ref(1), .{ .message = .{ .topic = block, .data = &.{7} } }, &turn, &credit));
    try t.expectEqual(@as(u64, 1), g.messages.fast_hits);
    try t.expectEqual(@as(u64, 1), g.messages.decoded_messages);
    try t.expectEqual(@as(u64, 0), g.peers.scores.penalties.invalid_message);
    try t.expectEqual(gossip.ReportOutcome{ .applied = .reject }, g.report(handle, .reject, .{ .mono_ms = 2, .unix_s = 0 }));
    try t.expectEqual(@as(u64, 2), g.peers.scores.penalties.invalid_message);
    try t.expectEqual(@as(u64, 2), g.counters.message_capacity_refusals);
    try t.expectEqual(allocations, ledger.allocation_calls);
}

test "gossip saturated attestation intake preserves block priority and storage" {
    var g = try support.init(t.allocator, options);
    defer g.deinit();
    var budget: @import("../byte_budget.zig").Budget = .{};
    const limits: processor.limits_mod.Limits = @splat(.{ .items = 2, .bytes = 8192 });
    var table = try processor.GossipProcessor.initPlanned(t.allocator, processor.limits_mod.items(&limits), processor.limits_mod.bytes(&limits), &budget, limits);
    defer table.deinit();
    defer table.close();
    var consumer: Consumer = .{ .table = &table };
    const sink = consumer.sink();
    g.message_sink = &sink;
    _ = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    try support.subscribe(&g, block);
    try support.subscribe(&g, attestation);
    for ([_][]const u8{ "first", "second", "refused" }) |payload| try receive(&g, 0, attestation, payload);
    try receive(&g, 0, block, "urgent");
    try t.expectEqual(@as(usize, 3), table.diag.occupied);
    try t.expectEqual(@as(u64, 3), g.messages.decoded_messages);
    const batch = table.claimDemand(2, .{ .ordinary = false });
    try t.expectEqual(@as(usize, 1), batch.len);
    try t.expectEqual(.beacon_block, table.get(batch.tokens[0]).?.kind);
    table.finish(&batch, false);
}

test "gossip capacity lost after preflight rolls back admission and allows redelivery" {
    var g = try support.init(t.allocator, options);
    defer g.deinit();
    var budget: @import("../byte_budget.zig").Budget = .{ .limit = 100 };
    var table = try processor.GossipProcessor.initPlanned(t.allocator, 1, 4096, &budget, null);
    defer table.deinit();
    defer table.close();
    var consumer: Consumer = .{ .table = &table, .fill_during_delivery = true };
    const sink = consumer.sink();
    g.message_sink = &sink;
    _ = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    try support.subscribe(&g, block);
    try receive(&g, 0, block, "racing publication");
    try t.expectEqual(@as(usize, 0), table.diag.occupied);
    try t.expectEqual(@as(usize, 0), budget.used);
    try t.expectEqual(@as(usize, 0), g.resourceSnapshot().pending_validations);
    try t.expectEqual(@as(u64, 0), table.diag.reportsAppliedIgnore);
    try t.expectEqual(@as(u64, 1), g.messages.storage_refusals[@intFromEnum(messages.StorageRefusal.processor_capacity)]);
    consumer.fill_during_delivery = false;
    try receive(&g, 0, block, "racing publication");
    try t.expectEqual(@as(usize, 1), table.diag.occupied);
    try t.expectEqual(@as(usize, 1), g.resourceSnapshot().pending_validations);
    try t.expectEqual(@as(u64, 0), g.peers.scores.penalties.invalid_message);
}

test "gossip invalid verdict stops remaining publications in the same RPC" {
    var opts = options;
    opts.score_params.gossip_threshold = -20;
    opts.score_params.publish_threshold = -40;
    opts.score_params.graylist_threshold = -50;
    var g = try support.init(t.allocator, opts);
    defer g.deinit();
    const source = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    try support.subscribe(&g, block);
    var body: [1024]u8 = undefined;
    var writer = protobuf.Writer.init(&body);
    for (0..3) |_| protobuf.writeMessage(&writer, &.{5}, block);
    const io = &g.sessions.rows[source.index].io;
    io.startRpc(writer.written());
    var turn = @import("session_io.zig").beginPump(&g, .{ .mono_ms = 1, .unix_s = 0 }, &.{});
    var credit = @import("turn.zig").Credits.peer(&g.options);
    try t.expectEqual(.done, try @import("session_io.zig").processRpc(&g, source.index, &turn, &credit));
    try t.expectEqual(@as(u64, 1), g.peers.scores.penalties.invalid_message);
    try t.expectEqual(@as(u64, 1), g.rpc_metrics.graylist_dropped);
    _ = g.sessions.finishFrame(io);
}
