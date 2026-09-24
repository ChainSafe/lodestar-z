const std = @import("std");
const gossip = @import("gossipsub.zig");
const Gossipsub = gossip.Gossipsub;
const Event = gossip.Event;
const constants = @import("constants.zig");
const local_intent = @import("local_intent.zig");
const protobuf = @import("protobuf.zig");
const topic_mod = @import("topic.zig");
const peers_mod = @import("peer_book.zig");
const score_mod = @import("score.zig");
const engine_mod = @import("../quic/engine.zig");
const Handle = engine_mod.Handle;
const Now = @import("../types.zig").Now;
const snappy = @import("snappy");
const support = @import("test_support.zig");
const testMessage = support.message;

test "gossip accepts a full namespace subscription transition in one RPC" {
    const policy = @import("topic_policy.zig");
    var boundary: policy.Boundary = .{ .digest = .{ 1, 2, 3, 4 } };
    var topic_count: usize = 0;
    for (std.enums.values(topic_mod.Kind)) |kind| {
        boundary.rules[@intFromEnum(kind)] = .{ .count = kind.countMax(), .ssz_min = 1, .ssz_max = 1024 };
        topic_count += kind.countMax();
    }
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .topic_policy = &.{boundary} });
    defer g.deinit();
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    var bytes: [64 * 1024]u8 = undefined;
    var writer = protobuf.Writer.init(&bytes);
    for ([_]bool{ true, false }) |subscribed| {
        for (std.enums.values(topic_mod.Kind)) |kind| {
            for (0..kind.countMax()) |subnet| {
                var suffix_buffer: [topic_mod.name_max_len]u8 = undefined;
                const suffix = if (kind.countMax() == 1) @tagName(kind) else try std.fmt.bufPrint(&suffix_buffer, "{s}_{d}", .{ @tagName(kind), subnet });
                var topic: [topic_mod.topic_max_len]u8 = undefined;
                const name = topic_mod.build(boundary.digest, suffix, &topic);
                if (subscribed) try support.subscribe(&g, name);
                protobuf.writeSubscription(&writer, subscribed, name);
            }
        }
    }
    const io = &g.sessions.rows[peer.index].io;
    io.startRpc(writer.written());
    var received: usize = 0;
    for (0..128) |_| {
        var events: [16]Event = undefined;
        var count: usize = 0;
        var items: usize = 16;
        const done = try support.processRpc(&g, peer.index, .{ .mono_ms = 1, .unix_s = 1 }, &events, &count, &items);
        for (events[0..count]) |event| {
            try std.testing.expect(event == .subscription_change);
            try std.testing.expectEqual(received < topic_count, event.subscription_change.subscribed);
            received += 1;
        }
        if (done) break;
    }
    try std.testing.expectEqual(2 * topic_count, received);
    try std.testing.expectEqual(@as(usize, 0), g.resourceSnapshot().remote_subscriptions);
    _ = g.sessions.finishFrame(io);
}

test "gossipsub IHAVE security ignores unknown and unsubscribed topics through RPC decoding" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const subscribed = "/eth2/01020304/beacon_block/ssz_snappy";
    const retired = "/eth2/01020304/beacon_aggregate_and_proof/ssz_snappy";
    try support.subscribe(&g, subscribed);
    try support.subscribe(&g, retired);
    try support.unsubscribe(&g, retired);
    for ([_][]const u8{ "/eth2/01020304/unknown/ssz_snappy", retired, subscribed }) |name| {
        var bytes: [256]u8 = undefined;
        var writer = protobuf.Writer.init(&bytes);
        protobuf.beginIhaveRpc(&writer, name, 1, constants.message_id_length);
        protobuf.writeIhaveId(&writer, &([_]u8{7} ** 20));
        const io = &g.sessions.rows[peer.index].io;
        io.startRpc(writer.written());
        var items: usize = 128;
        var count: usize = 0;
        try std.testing.expect(try @import("test_support.zig").processRpc(&g, peer.index, .{ .mono_ms = 1, .unix_s = 1 }, &.{}, &count, &items));
        try std.testing.expectEqual(@as(usize, @intFromBool(std.mem.eql(u8, name, subscribed))), g.recovery.len);
        try std.testing.expect(!g.sessions.finishFrame(io));
    }
}

test "gossip policy reconnect retains authenticated penalty" {
    var g = try support.init(std.testing.allocator, .{
        .random_seed = 1,
    });
    defer g.deinit();
    const metadata: peers_mod.Metadata = .{
        .identity = .{ .bytes = [_]u8{1} ** @import("../wire/peer_id.zig").length },
        .address = .unspecified,
        .direction = .inbound,
    };
    const now: Now = .{ .mono_ms = 1, .unix_s = 0 };
    const first = g.addPeer(.{ .index = 0, .generation = 1 }, &metadata, now).admitted;
    const original = g.sessions.rows[first.index].logical;
    g.peers.scores.penalize(original.index, 20);
    const topic_name = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, topic_name);
    const topic = g.overlay.findTopic(topic_name).?;
    const topic_generation = g.overlay.rows[topic].generation;
    g.peers.addBackoff(original, topic, topic_generation, 1, 60_000);
    g.connectionClosed(.{ .index = 0, .generation = 1 });
    const second = g.addPeer(.{ .index = 0, .generation = 2 }, &metadata, now).admitted;
    try std.testing.expectEqual(original, g.sessions.rows[second.index].logical);
    try std.testing.expect(g.peers.backedOff(original, topic, topic_generation, 60_000));
    try std.testing.expect(!g.peers.backedOff(original, topic, topic_generation, 60_001));
    try std.testing.expect(g.peers.score(g.sessions.rows[second.index].logical, 1) < 0);
}

test "gossip policy GRAFT rejects negative peers and excludes direct peers" {
    var g = try support.init(std.testing.allocator, .{
        .random_seed = 1,
    });
    defer g.deinit();
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const peer = @import("test_support.zig").addPeer(&g, conn, .v1_2).?;
    const topic_str = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, topic_str);
    const topic = g.overlay.findTopic(topic_str).?;
    support.penalize(&g, conn, 7);
    support.control(&g, peer.index, .{ .graft = topic_str }, .{ .mono_ms = 1, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 0), g.overlay.mesh(topic).count());
    g.peers.scores.rows[g.sessions.rows[peer.index].logical.index].behaviour = 0;
    support.penalize(&g, conn, 0);
    g.markDirect(conn);
    _ = g.overlay.peerSubscription(&g.overlayContext(g.last_now_ms), peer.index, g.overlay.topicString(topic), true);
    var context = g.overlayContext(100_000);
    context.snapshot = &g.cycle.scores;
    g.overlay.maintain(&context, topic);
    try std.testing.expectEqual(@as(usize, 0), g.overlay.mesh(topic).count());
}

test "gossip policy combined transport calls respect one shared peer allowance" {
    var setup: @import("test_pair.zig").Pair = .{};
    try setup.init();
    defer setup.deinit();
    for (0..20) |_| try setup.pumpOnce();
    const peer = setup.shared.client.gossipsub.sessions.findPeer(setup.shared.handles.client).?;
    setup.shared.client.gossipsub.options.calls_per_peer = 1;
    var events: [1]Event = undefined;
    for ([_]usize{ 8, 1 }) |global| {
        setup.shared.client.gossipsub.options.calls_per_pump = global;
        var read_turns: usize = 0;
        var write_turns: usize = 0;
        for (0..8) |_| {
            try std.testing.expect(setup.shared.client.gossipsub.sessions.rows[peer].io.tx.inject(&.{0}, setup.shared.pair.now.mono_ms));
            setup.shared.client.gossipsub.sessions.connectionActivity(setup.shared.handles.client);
            const turn = @import("test_support.zig").pumpTurn(setup.shared.client.gossipsub, &setup.shared.pair.client, setup.shared.pair.now, &events);
            const calls = global - turn.budget.calls;
            try std.testing.expect(calls <= 1);
            if (calls > 0) {
                if (turn.budget.output < setup.shared.client.gossipsub.options.output_per_pump) write_turns += 1 else read_turns += 1;
            }
        }
        try std.testing.expect(read_turns > 0 and write_turns > 0);
        for (0..32) |_| {
            if (@import("session_io.zig").nextIoWakeup(setup.shared.client.gossipsub, setup.shared.pair.now, events.len).? > setup.shared.pair.now.mono_ms) break;
            const turn = @import("test_support.zig").pumpTurn(setup.shared.client.gossipsub, &setup.shared.pair.client, setup.shared.pair.now, &events);
            try std.testing.expect(global - turn.budget.calls <= 1);
        }
        try std.testing.expect(!setup.shared.client.gossipsub.sessions.rows[peer].io.tx.pending());
        try std.testing.expect(@import("session_io.zig").nextIoWakeup(setup.shared.client.gossipsub, setup.shared.pair.now, events.len).? > setup.shared.pair.now.mono_ms);
    }
}

test "gossip policy sent promise survives reconnect without token rearming" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const metadata: peers_mod.Metadata = .{ .identity = .{ .bytes = [_]u8{1} ** @import("../wire/peer_id.zig").length }, .address = .unspecified, .direction = .inbound };
    const now: Now = .{ .mono_ms = 1, .unix_s = 0 };
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const first = g.addPeer(conn, &metadata, now).admitted;
    const ref = g.sessions.rows[first.index].logical;
    g.recovery.add(&g.peers, [_]u8{1} ** 20, g.sessions.rows[first.index].logical, g.sessions.rows[first.index].conn, 9, 30_000);
    g.recovery.controlSent(g.sessions.rows[first.index].conn, 9, g.options.iwant_followup_ms, 10);
    g.connectionClosed(conn);
    try std.testing.expectEqual(@as(usize, 1), g.recovery.len);
    const next = g.addPeer(.{ .index = 0, .generation = 2 }, &metadata, now).admitted;
    g.recovery.controlSent(g.sessions.rows[next.index].conn, 9, g.options.iwant_followup_ms, 2000);
    try std.testing.expectEqual(@as(?u64, 3010), g.recovery.batches[0].expiry);
    @import("session_io.zig").finishPump(&g, .{ .mono_ms = 3010, .unix_s = 0 });
    try std.testing.expectEqual(@as(u64, 1), g.counters.broken_promises);
    try std.testing.expectEqual(@as(u32, 0), g.peers.rows[ref.index].pins);
}

test "gossip policy duplicate connections preserve one logical owner and direct deliveries" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    var metadata: peers_mod.Metadata = .{ .identity = .{ .bytes = [_]u8{1} ** @import("../wire/peer_id.zig").length }, .address = .unspecified, .direction = .outbound };
    const now: Now = .{ .mono_ms = 1, .unix_s = 0 };
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const first = g.addPeer(conn, &metadata, now).admitted;
    const second: Handle = .{ .index = 1, .generation = 1 };
    try std.testing.expectEqual(Gossipsub.PeerAdmission.duplicate, g.addPeer(second, &metadata, now));
    g.connectionClosed(second);
    try std.testing.expectEqual(@as(?u16, first.index), g.sessions.findPeer(conn));
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, topic);
    _ = g.overlay.peerSubscription(&g.overlayContext(g.last_now_ms), first.index, topic, true);
    g.markDirect(conn);
    support.penalize(&g, conn, 110);
    g.sessions.rows[first.index].outbound = .{ .live = .{ .stream = .{ .conn = conn, .id = 2, .slot = 0 }, .version = .v1_2 } };
    const result = try g.publish(topic, "direct data", now);
    try std.testing.expectEqual(@as(u16, 1), result.queued);
    try std.testing.expectEqual(@as(usize, 0), g.overlay.mesh(g.overlay.findTopic(topic).?).count());
    g.connectionClosed(conn);
    metadata.direct = true;
    const next = g.addPeer(second, &metadata, now).admitted;
    try std.testing.expect(g.peers.rows[g.sessions.rows[next.index].logical.index].direct);
    g.connectionClosed(second);
    metadata.direct = false;
    const indirect = g.addPeer(.{ .index = 1, .generation = 2 }, &metadata, now).admitted;
    try std.testing.expect(!g.peers.rows[g.sessions.rows[indirect.index].logical.index].direct);
}

test "gossip policy topic reuse waits for attribution and preserves copied event window" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const peer = @import("test_support.zig").addPeer(&g, conn, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, name);
    const topic = g.overlay.findTopic(name).?;
    const generation = g.overlay.rows[topic].generation;
    var inbox: support.Inbox = .{};
    defer inbox.deinit();
    inbox.attach(&g);
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(?usize, 1), try testMessage(&g, peer.index, "retained", 1, &events));
    const event = inbox.last();
    const copied = g.resourceSnapshot();
    try support.subscribe(&g, name);
    try std.testing.expectEqualStrings("retained", event.bytes);
    try std.testing.expectEqualStrings(name, event.topic);
    try std.testing.expectEqual(@as(usize, 1), copied.pending_validations);
    try std.testing.expectEqualDeep(copied, g.resourceSnapshot());
    try support.unsubscribe(&g, name);
    g.connectionClosed(conn);
    g.overlay.reclaimTopic(&g.overlayContext(g.last_now_ms), &g.messages.topicPins(), topic);
    try std.testing.expect(g.overlay.rows[topic].active);
    _ = g.report(event.handle, .ignore, .{ .mono_ms = 2, .unix_s = 0 });
    g.messages.validation.expire(&g.messages.store, &g.peers, 30_002);
    g.last_now_ms = 30_002;
    g.overlay.reclaimTopic(&g.overlayContext(g.last_now_ms), &g.messages.topicPins(), topic);
    try std.testing.expect(!g.overlay.rows[topic].active);
    const next_name = "/eth2/01020304/voluntary_exit/ssz_snappy";
    try support.subscribe(&g, next_name);
    try std.testing.expectEqual(@as(?u16, topic), g.overlay.findTopic(next_name));
    try std.testing.expect(g.overlay.rows[topic].generation > generation);
    try std.testing.expectEqualStrings(name, event.topic);
    try std.testing.expectEqualStrings("retained", event.bytes);
}

test "gossip policy topic retirement bounds arbitrarily slow active score decay" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .retained_score_ms = 10, .score_params = .{ .decay_interval_ms = 1, .topic = .{ .first_delivery_decay = 0.999999999999 } } });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, name);
    const topic = g.overlay.findTopic(name).?;
    g.peers.scores.deliverEligible(g.sessions.rows[peer.index].logical.index, topic, false);
    try support.unsubscribe(&g, name);
    g.overlay.flushSubscriptions(&g.sessions.rows[peer.index].io.tx, g.last_now_ms);
    g.last_now_ms = 11;
    g.peers.scores.refresh(11);
    g.overlay.reclaimTopic(&g.overlayContext(g.last_now_ms), &g.messages.topicPins(), topic);
    try std.testing.expect(!g.overlay.rows[topic].active);
    try std.testing.expectEqual(@as(f64, 0), g.peers.score(g.sessions.rows[peer.index].logical, 11));
}

test "gossip policy unsent subscriptions cannot pin retired topics indefinitely" {
    var pair: @import("../test_support.zig").Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .pressure_timeout_ms = 10 });
    defer g.deinit();
    const conn: Handle = .{ .index = 0, .generation = 1 };
    _ = @import("test_support.zig").addPeer(&g, conn, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, name);
    try support.unsubscribe(&g, name);
    var events: [0]Event = .{};
    _ = @import("test_support.zig").pump(&g, &pair.server, .{ .mono_ms = 11, .unix_s = 0 }, &events);
    try std.testing.expect(g.sessions.findPeer(conn) == null);
    try std.testing.expectEqual(@as(u64, 1), g.counters.subscription_timeouts);
    try std.testing.expectEqual(@as(u64, 1), g.counters.local_pressure_resets);
    const topic = g.overlay.findTopic(name).?;
    g.overlay.reclaimTopic(&g.overlayContext(g.last_now_ms), &g.messages.topicPins(), topic);
    try std.testing.expect(!g.overlay.rows[topic].active);
}

test "gossip policy subscription retry preserves its first pressure deadline" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    try support.subscribe(&g, "/eth2/01020304/beacon_block/ssz_snappy");
    g.last_now_ms = 1;
    g.sendSubscriptions(peer.index);
    try std.testing.expectEqual(@as(?u64, 0), g.sessions.rows[peer.index].io.tx.subscription_since);
}

test "gossip policy review I4 heartbeat fanout and advertisements share one snapshot" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 17, .topics_per_pump = 1 });
    defer g.deinit();
    const first_name = "/eth2/01020304/beacon_block/ssz_snappy";
    const second_name = "/eth2/01020304/beacon_aggregate_and_proof/ssz_snappy";
    _ = g.overlay.internTopic(&g.overlayContext(g.last_now_ms), &g.messages.topicPins(), first_name).?;
    const second = g.overlay.internTopic(&g.overlayContext(g.last_now_ms), &g.messages.topicPins(), second_name).?;
    for (0..9) |i| {
        const peer = @import("test_support.zig").addPeer(&g, .{ .index = @intCast(i), .generation = 1 }, .v1_2).?;
        _ = g.overlay.peerSubscription(&g.overlayContext(g.last_now_ms), peer.index, first_name, true);
        _ = g.overlay.peerSubscription(&g.overlayContext(g.last_now_ms), peer.index, second_name, true);
        g.sessions.rows[peer.index].outbound = .{ .live = .{ .stream = .{ .conn = g.sessions.rows[peer.index].conn, .id = 2, .slot = 0 }, .version = .v1_2 } };
    }
    const start: Now = .{ .mono_ms = 1, .unix_s = 0 };
    _ = try g.publish(first_name, "first", start);
    _ = try g.publish(second_name, "second", start);
    support.heartbeat(&g, start);
    @import("session_io.zig").finishPump(&g, start);
    try std.testing.expectEqual(@as(usize, 1), g.cycle.cursor);
    try std.testing.expectEqual(@as(u64, 0), g.maintenance.cycles.count);
    try std.testing.expectEqual(@as(u64, 1), g.maintenance.setup.count);
    try std.testing.expectEqual(@as(u64, 1), g.maintenance.topics.count);
    const cycle_started = g.maintenance.started_ns.?;
    const retained = g.overlay.fanoutMembers(second).findFirstSet().?;
    var advertised: u16 = 0;
    for (0..9) |i| if (!g.overlay.fanoutMembers(second).isSet(i)) {
        advertised = @intCast(i);
    };
    g.peers.scores.penalize(g.sessions.rows[@intCast(retained)].logical.index, 50);
    g.peers.scores.penalize(g.sessions.rows[advertised].logical.index, 50);
    for (g.sessions.rows) |*peer| peer.io.tx.cancelStream(&g.messages.store);
    g.last_now_ms = 2;
    g.opportunistic_at = 2;
    support.heartbeat(&g, .{ .mono_ms = 2, .unix_s = 0 });
    try std.testing.expect(!g.cycle.opportunistic);
    try std.testing.expectEqual(cycle_started, g.maintenance.started_ns.?);
    try std.testing.expectEqual(@as(u64, 1), g.counters.heartbeats_skipped);
    @import("session_io.zig").finishPump(&g, .{ .mono_ms = 2, .unix_s = 0 });
    try std.testing.expect(g.overlay.fanoutMembers(second).isSet(retained));
    try std.testing.expectEqual(@as(usize, 8), g.overlay.fanoutMembers(second).count());
    try std.testing.expectEqual(@as(usize, 1), g.sessions.rows[advertised].io.tx.control.count);
    try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[retained].io.tx.control.count);
    @import("session_io.zig").finishPump(&g, .{ .mono_ms = 3, .unix_s = 0 });
    try std.testing.expect(!g.cycle.isActive());
    try std.testing.expect(g.maintenance.started_ns == null);
    try std.testing.expectEqual(@as(u64, 1), g.maintenance.cycles.count);
    try std.testing.expectEqual(@as(u64, 2), g.maintenance.setup.count);
    try std.testing.expectEqual(@as(u64, 3), g.maintenance.topics.count);
    try std.testing.expect(g.maintenance.completed_unix_s > 0);
    for (g.sessions.rows) |*peer| peer.io.tx.cancelStream(&g.messages.store);
    g.last_now_ms = 701;
    support.heartbeat(&g, .{ .mono_ms = 701, .unix_s = 0 });
    @import("session_io.zig").finishPump(&g, .{ .mono_ms = 701, .unix_s = 0 });
    @import("session_io.zig").finishPump(&g, .{ .mono_ms = 702, .unix_s = 0 });
    try std.testing.expect(!g.overlay.fanoutMembers(second).isSet(retained));
    try std.testing.expectEqual(@as(usize, 7), g.overlay.fanoutMembers(second).count());
    try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[advertised].io.tx.control.count);
    try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[retained].io.tx.control.count);
    const live = g.overlay.fanoutMembers(second).findFirstSet().?;
    g.peers.scores.penalize(g.sessions.rows[@intCast(live)].logical.index, 50);
    _ = try g.publish(second_name, "live publish", .{ .mono_ms = 703, .unix_s = 0 });
    try std.testing.expect(!g.overlay.fanoutMembers(second).isSet(live));
}

test "gossip topic rejection preserves expired scores and retained obligations" {
    var opts: gossip.Options = .{
        .topic_policy = &@import("topic_fixture.zig").churn,
        .random_seed = 1,
        .connected_capacity = 2,
        .retained_capacity = 4,
        .retained_outbound_reserve = 1,
    };
    opts.topic_params = @splat(.{});
    opts.topic_params.?[0].params.weight = 2;
    var g = try support.init(std.testing.allocator, opts);
    defer g.deinit();
    var name: [topic_mod.topic_max_len]u8 = undefined;
    for (0..constants.topics_cap) |index| {
        const text = try @import("topic_fixture.zig").churnTopic(index, &name);
        try support.subscribe(&g, text);
    }
    const first = g.overlay.topicString(0);
    try support.unsubscribe(&g, first);
    g.peers.scores.invalid(0, 0);
    g.last_now_ms = g.overlay.rows[0].retire_after_ms.?;
    g.peers.backoffs[0] = .{ .topic_generation = g.overlay.rows[0].generation, .until = g.last_now_ms + 100 };
    const revision = g.peers.scores.revision;
    const generation = g.overlay.rows[0].generation;
    const score = g.peers.scores.topics[0];
    const old_scores = try std.testing.allocator.dupe(@TypeOf(score), g.peers.scores.topics);
    defer std.testing.allocator.free(old_scores);
    const old_topics = try std.testing.allocator.dupe(@TypeOf(g.overlay.rows[0]), &g.overlay.rows);
    defer std.testing.allocator.free(old_topics);
    const old_backoffs = try std.testing.allocator.dupe(@TypeOf(g.peers.backoffs[0]), g.peers.backoffs);
    defer std.testing.allocator.free(old_backoffs);
    const old_params = g.peers.scores.topic_params;
    const old_rows = try std.testing.allocator.dupe(score_mod.PeerScore.PeerState, g.peers.scores.rows);
    defer std.testing.allocator.free(old_rows);
    try std.testing.expectEqual(@as(?u16, null), support.intern(&g, "/eth2/090a0b0c/beacon_block/ssz_snappy"));
    try std.testing.expectEqualDeep(old_scores, g.peers.scores.topics);
    try std.testing.expectEqualDeep(old_backoffs, g.peers.backoffs);
    try std.testing.expectEqualDeep(old_params, g.peers.scores.topic_params);
    try std.testing.expectEqualDeep(old_rows, g.peers.scores.rows);
    for (old_topics, &g.overlay.rows) |*before, *after| {
        try std.testing.expectEqual(before.active, after.active);
        try std.testing.expectEqual(before.generation, after.generation);
        try std.testing.expectEqual(before.subscribed, after.subscribed);
        try std.testing.expectEqual(before.retire_after_ms, after.retire_after_ms);
        try std.testing.expectEqualDeep(before.subscribers, after.subscribers);
        try std.testing.expectEqualDeep(before.mesh, after.mesh);
        try std.testing.expectEqualDeep(before.fanout, after.fanout);
        try std.testing.expectEqualStrings(before.string[0..before.string_len], after.string[0..after.string_len]);
    }
    try std.testing.expectEqual(revision, g.peers.scores.revision);
    try std.testing.expectEqual(generation, g.overlay.rows[0].generation);
    try std.testing.expect(g.overlay.rows[0].active);
    try std.testing.expectEqual(@as(?u16, null), support.intern(&g, "invalid"));
    try std.testing.expectEqualDeep(score, g.peers.scores.topics[0]);
    try std.testing.expectEqual(revision, g.peers.scores.revision);
    g.last_now_ms += 100;
    g.overlay.rows[0].generation = std.math.maxInt(u64);
    try std.testing.expectEqual(@as(?u16, null), support.intern(&g, "/eth2/090a0b0c/beacon_block/ssz_snappy"));
    try std.testing.expectEqualDeep(score, g.peers.scores.topics[0]);
    g.overlay.rows[0].generation = generation;
    _ = support.intern(&g, "/eth2/090a0b0c/beacon_block/ssz_snappy").?;
    try std.testing.expectEqual(generation + 1, g.overlay.rows[0].generation);
    try std.testing.expect(!g.peers.scores.retainsTopic(0));
    try std.testing.expectEqual(@as(f64, 2), g.peers.scores.topic_params[0].weight);
}

test "gossip topic retirement clears expired scores while backoff remains" {
    var g = try support.init(std.testing.allocator, .{
        .random_seed = 1,
        .connected_capacity = 2,
        .retained_capacity = 4,
        .retained_outbound_reserve = 1,
    });
    defer g.deinit();
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, name);
    g.peers.scores.invalid(0, 0);
    try support.unsubscribe(&g, name);
    g.last_now_ms = g.overlay.rows[0].retire_after_ms.?;
    const generation = g.overlay.rows[0].generation;
    g.peers.backoffs[0] = .{ .topic_generation = generation, .until = g.last_now_ms + 100 };
    g.overlay.reclaimTopic(&g.overlayContext(g.last_now_ms), &g.messages.topicPins(), 0);
    try std.testing.expect(!g.peers.scores.retainsTopic(0));
    try std.testing.expect(g.overlay.rows[0].active);
    try std.testing.expectEqual(generation, g.overlay.rows[0].generation);
    try std.testing.expectEqual(g.last_now_ms + 100, g.peers.backoffs[0].until);
}

test "fanout interning snapshots aliased text under full capacity" {
    var ledger: @import("../reservations.zig").Reservations = .{ .backing = std.testing.allocator };
    var g = try Gossipsub.init(ledger.allocator(), .{ .random_seed = 1, .connected_capacity = 2, .retained_capacity = 4, .retained_outbound_reserve = 1 });
    defer g.deinit();
    const calls = ledger.allocation_calls;
    const original = "/eth2/00000000/a/ssz_snappy/b/ssz_snappy";
    const shorter = "/eth2/00000000/a/ssz_snappy";
    _ = support.intern(&g, original).?;
    var name: [topic_mod.topic_max_len]u8 = undefined;
    for (1..constants.topics_cap) |index| {
        const text = try std.fmt.bufPrint(&name, "/eth2/{x:0>8}/custom/ssz_snappy", .{index});
        _ = support.intern(&g, text).?;
    }
    const input = g.overlay.topicString(0)[0..shorter.len];
    const generation = g.overlay.rows[0].generation;
    _ = support.intern(&g, input).?;
    try std.testing.expectEqualStrings(shorter, g.overlay.topicString(0));
    try std.testing.expectEqual(generation + 1, g.overlay.rows[0].generation);
    try std.testing.expectEqual(@as(f64, 1), g.peers.scores.topic_params[0].weight);
    try std.testing.expectEqual(calls, ledger.allocation_calls);
}

test "publication subscribed fanout expires through owner maintenance" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const p = @import("test_support.zig").addPeer(&g, conn, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, name);
    const t = g.overlay.findTopic(name).?;
    _ = g.overlay.peerSubscription(&g.overlayContext(g.last_now_ms), p.index, name, true);
    g.sessions.rows[p.index].outbound = .{ .live = .{ .stream = .{ .conn = conn, .id = 2, .slot = 0 }, .version = .v1_2 } };
    _ = try g.publish(name, "fanout expiry", .{ .mono_ms = 0, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 1), g.overlay.fanoutMembers(t).count());
    support.heartbeat(&g, .{ .mono_ms = 59_999, .unix_s = 0 });
    @import("session_io.zig").finishPump(&g, .{ .mono_ms = 59_999, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 1), g.overlay.fanoutMembers(t).count());
    support.heartbeat(&g, .{ .mono_ms = 60_000, .unix_s = 0 });
    @import("session_io.zig").finishPump(&g, .{ .mono_ms = 60_000, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 0), g.overlay.fanoutMembers(t).count());
    _ = g.overlay.peerSubscription(&g.overlayContext(g.last_now_ms), p.index, name, false);
    g.sessions.rows[p.index].io.tx.cancelStream(&g.messages.store);
    const next_conn: Handle = .{ .index = 1, .generation = 1 };
    const next = @import("test_support.zig").addPeer(&g, next_conn, .v1_2).?;
    _ = g.overlay.peerSubscription(&g.overlayContext(g.last_now_ms), next.index, name, true);
    g.sessions.rows[next.index].outbound = .{ .live = .{ .stream = .{ .conn = next_conn, .id = 2, .slot = 0 }, .version = .v1_2 } };
    const result = try g.publish(name, "fresh fanout", .{ .mono_ms = 60_001, .unix_s = 0 });
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .selected = 1, .queued = 1 }, result);
    try std.testing.expectEqual(@as(usize, 1), g.overlay.fanoutMembers(t).count());
    try std.testing.expect(g.overlay.fanoutMembers(t).isSet(next.index));
    try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[p.index].io.tx.data.count);
    const queued = g.sessions.rows[next.index].io.tx.data.first().?.message;
    try std.testing.expectEqual(topic_mod.validMessageId(name, "fresh fanout", .{}), g.messages.store.get(queued).?.id);
}

test "local intent reclaimed history answers actual IWANT with original wire topic and bytes" {
    var g = try support.init(std.testing.allocator, .{
        .random_seed = 1,
        .connected_capacity = 2,
        .retained_capacity = 4,
        .retained_outbound_reserve = 1,
        .topic_policy = &.{@import("topic_fixture.zig").full(.{ 1, 2, 3, 4 })},
    });
    defer g.deinit();
    const workspace = try std.testing.allocator.create(local_intent.Workspace);
    defer std.testing.allocator.destroy(workspace);
    workspace.* = .{};
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    const replacement = "/eth2/01020304/voluntary_exit/ssz_snappy";
    for (g.overlay.rows[1..]) |*row| row.generation = std.math.maxInt(u64);
    const now: Now = .{ .mono_ms = 1, .unix_s = 0 };
    _ = try g.publish(name, "original payload", now);
    const id = topic_mod.validMessageId(name, "original payload", .{});
    const message = g.messages.history.message(g.messages.history.get(&g.messages.store, id).?);
    try std.testing.expect(try g.prepareSubscriptions(@import("topic_fixture.zig").subscriptions(&.{replacement}), workspace, now, 0));
    g.commitSubscriptions(workspace);
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    var request: [64]u8 = undefined;
    var writer = protobuf.Writer.init(&request);
    protobuf.beginIwantRpc(&writer, 1, id.len);
    protobuf.writeIwantId(&writer, &id);
    var reader = protobuf.RpcReader.init(writer.written());
    support.control(&g, peer.index, .{ .iwant = (try reader.next()).?.iwant }, .{ .mono_ms = g.last_now_ms, .unix_s = 0 });
    const io = &g.sessions.rows[peer.index].io;
    try std.testing.expectEqual(@as(usize, 1), io.tx.data.count);
    try std.testing.expectEqual(message, io.tx.data.first().?.message);
    try std.testing.expectEqual(@as(u8, 1), g.messages.history.countsRow(g.messages.history.get(&g.messages.store, id).?)[g.sessions.rows[peer.index].logical.index]);
    var wire: [512]u8 = undefined;
    var used: usize = 0;
    for (0..8) |_| {
        const segment = io.tx.segment(&g.messages.store);
        if (segment.len == 0) break;
        try std.testing.expect(used + segment.len <= wire.len);
        @memcpy(wire[used..][0..segment.len], segment);
        used += segment.len;
        _ = io.tx.advance(&g.messages.store, segment.len);
    }
    try std.testing.expectEqual(@as(usize, 0), io.tx.data.count);
    try std.testing.expect(std.mem.indexOf(u8, wire[0..used], name) != null);
    var decompressed: [64]u8 = undefined;
    const size = try snappy.raw.uncompress(g.messages.store.segment(message, g.messages.store.cursor(message)), &decompressed);
    try std.testing.expectEqualStrings("original payload", decompressed[0..size]);
    try std.testing.expectEqualStrings(replacement, g.overlay.topicString(0));
}

test "gossip advertisements sample the whole burst independently for each recipient" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 17 });
    defer g.deinit();
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    const t = g.overlay.internTopic(&g.overlayContext(g.last_now_ms), &g.messages.topicPins(), name).?;
    for (0..2) |i| {
        const peer = @import("test_support.zig").addPeer(&g, .{ .index = @intCast(i), .generation = 1 }, .v1_2).?;
        _ = g.overlay.peerSubscription(&g.overlayContext(g.last_now_ms), peer.index, name, true);
        g.sessions.rows[peer.index].outbound = .{ .live = .{ .stream = .{ .conn = g.sessions.rows[peer.index].conn, .id = 2, .slot = 0 }, .version = .v1_2 } };
    }
    for (0..512) |i| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, i, .little);
        _ = try g.publish(name, &bytes, .{ .mono_ms = 1, .unix_s = 0 });
    }
    for (g.sessions.rows) |*peer| peer.io.tx.cancelStream(&g.messages.store);
    g.overlay.rows[t].fanout = .initEmpty();
    const context = g.overlayContext(1);
    g.cycle.begin(context.sessions, context.peers, context.now, false);
    @import("session_io.zig").finishPump(&g, .{ .mono_ms = context.now, .unix_s = 0 });
    const first = g.sessions.rows[0].io.tx.segment(&g.messages.store);
    const second = g.sessions.rows[1].io.tx.segment(&g.messages.store);
    try std.testing.expect(first.len > 0 and second.len > 0);
    try std.testing.expect(!std.mem.eql(u8, first, second));
    var beyond_prefix: usize = 0;
    for (g.messages.gossip_ids[0..constants.gossip_ids_max]) |id| {
        const entry = g.messages.history.get(&g.messages.store, id).?;
        if (g.messages.history.message(entry).index >= constants.gossip_ids_max) beyond_prefix += 1;
    }
    try std.testing.expect(beyond_prefix > constants.gossip_ids_max / 2);
}
