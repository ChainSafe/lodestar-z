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
    .body_buffer_bytes = 64,
};

const Consumer = struct {
    table: *processor.GossipProcessor,
    owner: *gossip.Gossipsub,
    slot: u64 = 1,

    fn sink(self: *Consumer) gossip.MessageSink {
        return .{ .context = self, .has_capacity = hasCapacity, .admit = admit };
    }

    fn hasCapacity(context: *anyopaque, kind: processor.limits_mod.Kind, len: usize) bool {
        const self: *Consumer = @ptrCast(@alignCast(context));
        return self.table.hasCapacity(kind, len) or self.table.freshnessVictim(kind) != null;
    }

    fn admit(context: *anyopaque, candidate: *gossip.Admission) bool {
        const self: *Consumer = @ptrCast(@alignCast(context));
        return self.table.admit(self.owner, candidate, candidate.event.admitted_ms, 1, self.slot);
    }
};

fn receive(g: *gossip.Gossipsub, source: u16, topic: []const u8, payload: []const u8) !void {
    var compressed: [8192]u8 = undefined;
    const len = try snappy.raw.compress(payload, &compressed);
    var turn = @import("session_io.zig").beginPump(g, .{ .mono_ms = 1, .unix_s = 0 });
    var credit = @import("turn.zig").Credits.peer(&g.options);
    try t.expectEqual(.done, g.receiveItem(g.sessions.ref(source), .{ .message = .{ .topic = topic, .data = compressed[0..len] } }, &turn, &credit));
}

test "gossip direct processor admission drains paged RPCs while the host queue stays full" {
    var pair: @import("test_pair.zig").Pair = .{};
    try pair.initOpts(options, options);
    defer pair.deinit();
    const g = pair.shared.server.gossipsub;
    try support.subscribe(g, block);
    const limits: processor.limits_mod.Limits = @splat(.{ .items = 4, .bytes = 16384 });
    var table = try processor.GossipProcessor.init(t.allocator, .{ .capacity = processor.limits_mod.items(&limits), .bytes = processor.limits_mod.bytes(&limits), .limits = limits, .forks = &.{.{ .digest = .{ 1, 2, 3, 4 }, .fork = .fulu }} });
    defer table.deinit();
    defer table.close();
    var consumer: Consumer = .{ .table = &table, .owner = g };
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
        std.mem.writeInt(u64, payload[100..108], 1, .little);
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
    for (table.cells[0..2], 0..) |*cell, i| {
        table.copyPayload(cell, &actual);
        try t.expectEqualSlices(u8, &payloads[i], &actual);
    }
}

test "gossip full processor preserves duplicate attribution without runtime allocations" {
    var ledger: @import("../reservations.zig").Reservations = .{ .backing = t.allocator };
    var g = try support.init(ledger.allocator(), options);
    defer g.deinit();
    const limits: processor.limits_mod.Limits = @splat(.{ .items = 2, .bytes = 4096 });
    var table = try processor.GossipProcessor.init(ledger.allocator(), .{ .capacity = processor.limits_mod.items(&limits), .bytes = processor.limits_mod.bytes(&limits), .limits = limits, .forks = &.{.{ .digest = .{ 1, 2, 3, 4 }, .fork = .fulu }} });
    defer table.deinit();
    defer table.close();
    var consumer: Consumer = .{ .table = &table, .owner = &g };
    const sink = consumer.sink();
    g.message_sink = &sink;
    try support.subscribe(&g, block);
    for (0..2) |i| _ = support.addPeer(&g, .{ .index = @intCast(i), .generation = 1 }, .v1_2).?;
    const allocations = ledger.allocation_calls;
    ledger.byte_limit = ledger.bytes;
    try receive(&g, 1, block, "filler");
    try receive(&g, 0, block, "pending");
    const handle = table.cells[1].handle;
    try receive(&g, 1, block, "pending");
    try receive(&g, 1, block, "unexamined");
    var turn = @import("session_io.zig").beginPump(&g, .{ .mono_ms = 1, .unix_s = 0 });
    var credit = @import("turn.zig").Credits.peer(&g.options);
    try t.expectEqual(.done, g.receiveItem(g.sessions.ref(1), .{ .message = .{ .topic = block, .data = &.{7} } }, &turn, &credit));
    try t.expectEqual(@as(u64, 1), g.messages.fast_hits);
    try t.expectEqual(@as(u64, 2), g.messages.decoded_messages);
    try t.expectEqual(@as(u64, 0), g.peers.scores.penalties.invalid_message);
    try t.expectEqual(gossip.ReportOutcome{ .applied = .reject }, g.report(handle, .reject, .{ .mono_ms = 2, .unix_s = 0 }));
    try t.expectEqual(@as(u64, 2), g.peers.scores.penalties.invalid_message);
    try t.expectEqual(@as(u64, 2), g.counters.message_capacity_refusals);
    try t.expectEqual(allocations, ledger.allocation_calls);
}

test "gossip saturated attestation intake preserves block priority and storage" {
    var g = try support.init(t.allocator, options);
    defer g.deinit();
    const limits: processor.limits_mod.Limits = @splat(.{ .items = 2, .bytes = 8192 });
    var table = try processor.GossipProcessor.init(t.allocator, .{ .capacity = processor.limits_mod.items(&limits), .bytes = processor.limits_mod.bytes(&limits), .limits = limits, .forks = &.{.{ .digest = .{ 1, 2, 3, 4 }, .fork = .fulu }} });
    defer table.deinit();
    defer table.close();
    var consumer: Consumer = .{ .table = &table, .owner = &g };
    const sink = consumer.sink();
    g.message_sink = &sink;
    _ = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    try support.subscribe(&g, block);
    try support.subscribe(&g, attestation);
    _ = support.addPeer(&g, .{ .index = 1, .generation = 1 }, .v1_2).?;
    try receive(&g, 0, attestation, "first");
    try receive(&g, 1, attestation, "second");
    try receive(&g, 0, attestation, "refused");
    try receive(&g, 0, block, "urgent");
    try t.expectEqual(@as(usize, 3), table.diag.occupied);
    try t.expectEqual(@as(u64, 4), g.messages.decoded_messages);
    const batch = table.claimDemand(2, .{ .ordinary = false });
    try t.expectEqual(@as(usize, 1), batch.len);
    try t.expectEqual(.beacon_block, table.get(batch.tokens[0]).?.kind);
    table.finish(&batch, false);
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
    var inbox: support.Inbox = .{};
    defer inbox.deinit();
    inbox.attach(&g);
    var body: [1024]u8 = undefined;
    var writer = protobuf.Writer.init(&body);
    for (0..3) |_| protobuf.writeMessage(&writer, &.{5}, block);
    const io = &g.sessions.rows[source.index].io;
    io.startRpc(writer.written());
    var turn = @import("session_io.zig").beginPump(&g, .{ .mono_ms = 1, .unix_s = 0 });
    var credit = @import("turn.zig").Credits.peer(&g.options);
    try t.expectEqual(.done, try @import("session_io.zig").processRpc(&g, source.index, &turn, &credit));
    try t.expectEqual(@as(u64, 1), g.peers.scores.penalties.invalid_message);
    try t.expectEqual(@as(u64, 1), g.rpc_metrics.graylist_dropped);
    _ = g.sessions.finishFrame(io);
}

fn vote(bytes: []u8, tag: u8, slot: u64) void {
    @memset(bytes, tag);
    if (bytes.len >= 24) std.mem.writeInt(u64, bytes[16..24], slot, .little);
}

test "gossip admission rejects ineligible candidates without replacing work and commits valid replacements atomically" {
    var opts = options;
    const limits: processor.limits_mod.Limits = @splat(.{ .items = 4, .bytes = 16384 });
    var boundary = @import("topic_fixture.zig").bytes(.{ 1, 2, 3, 4 });
    for (&boundary.rules) |*rule| rule.ssz_max = 6000;
    opts.topic_policy = &.{boundary};
    opts.processor_limits = limits;
    opts.validation_capacity = processor.limits_mod.items(&limits);
    var g = try support.init(t.allocator, opts);
    defer g.deinit();
    var table = try processor.GossipProcessor.init(t.allocator, processor.Plan.resolve(&opts, &.{.{ .digest = .{ 1, 2, 3, 4 }, .fork = .fulu }}));
    defer table.deinit();
    defer table.close();
    var consumer: Consumer = .{ .table = &table, .owner = &g };
    const sink = consumer.sink();
    g.message_sink = &sink;
    try support.subscribe(&g, attestation);
    for (0..3) |i| _ = support.addPeer(&g, .{ .index = @intCast(i), .generation = 1 }, .v1_2).?;
    var bytes: [240]u8 = undefined;
    for (0..4) |i| {
        vote(&bytes, @intCast(i), 1);
        try receive(&g, @intCast(i / 2), attestation, &bytes);
    }
    const victim = table.freshnessVictim(.beacon_attestation).?;
    const handle = table.get(victim).?.handle;
    const free_pages = g.messages.store.free_pages;
    vote(&bytes, 9, 1000);
    try receive(&g, 2, attestation, &bytes);
    try t.expectEqual(@as(u64, 1), table.diag.slotRefusals);
    try t.expect(table.get(victim) != null);
    try t.expectEqual(@as(usize, 4), g.resourceSnapshot().pending_validations);
    try t.expectEqual(free_pages, g.messages.store.free_pages);
    vote(&bytes, 10, 1);
    try receive(&g, 2, attestation, &bytes);
    try t.expect(table.get(victim) == null);
    try t.expectEqual(@as(u64, 1), table.diag.reportsAppliedIgnore);
    try t.expectEqual(@as(usize, 4), table.diag.occupied);
    try t.expectEqual(@as(usize, 4), g.resourceSnapshot().pending_validations);
    try t.expectEqual(gossip.ReportOutcome.already_resolved, g.report(handle, .reject, .{ .mono_ms = 2, .unix_s = 0 }));
    try t.expectEqual(@as(u64, 0), g.peers.scores.penalties.invalid_message);
}

test "gossip admission leaves queued work intact when a host copy pins the required pages" {
    var opts = options;
    const limits: processor.limits_mod.Limits = @splat(.{ .items = 4, .bytes = 8192 });
    var boundary = @import("topic_fixture.zig").bytes(.{ 1, 2, 3, 4 });
    for (&boundary.rules) |*rule| rule.ssz_max = 6000;
    opts.topic_policy = &.{boundary};
    opts.processor_limits = limits;
    opts.validation_capacity = processor.limits_mod.items(&limits);
    var g = try support.init(t.allocator, opts);
    defer g.deinit();
    var table = try processor.GossipProcessor.init(t.allocator, processor.Plan.resolve(&opts, &.{.{ .digest = .{ 1, 2, 3, 4 }, .fork = .fulu }}));
    defer table.deinit();
    defer table.close();
    var consumer: Consumer = .{ .table = &table, .owner = &g };
    const sink = consumer.sink();
    g.message_sink = &sink;
    try support.subscribe(&g, attestation);
    for (0..3) |i| _ = support.addPeer(&g, .{ .index = @intCast(i), .generation = 1 }, .v1_2).?;
    var large: [6000]u8 = undefined;
    vote(&large, 1, 1);
    try receive(&g, 0, attestation, &large);
    const checks = table.claimChecks(1);
    try t.expectEqual(@as(usize, 1), checks.len);
    try t.expect(table.classify(checks.tokens[0], true));
    const copying = table.claim(60);
    try t.expectEqual(@as(usize, 1), copying.len);
    defer table.finish(&copying, false);
    var small: [240]u8 = undefined;
    for (0..2) |i| {
        vote(&small, @intCast(i + 2), 1);
        try receive(&g, 1, attestation, &small);
    }
    const victim = table.freshnessVictim(.beacon_attestation).?;
    var candidate: [1000]u8 = undefined;
    vote(&candidate, 4, 1);
    try receive(&g, 2, attestation, &candidate);
    try t.expectEqual(@as(u64, 0), table.diag.reportsAppliedIgnore);
    try t.expectEqual(@as(usize, 3), table.diag.occupied);
    try t.expectEqual(@as(usize, 3), g.resourceSnapshot().pending_validations);
    try t.expect(table.get(victim) != null);
    try t.expectEqual(processor.State.copying, table.get(copying.tokens[0]).?.state);
}
