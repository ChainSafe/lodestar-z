const std = @import("std");
const Gossipsub = @import("gossipsub.zig").Gossipsub;
const topic_mod = @import("topic.zig");
const support = @import("test_support.zig");
const topic = "/eth2/01020304/beacon_block/ssz_snappy";

test "publication refusal retry duplicate and exact expiry preserve admission" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .seen_ttl_ms = 100, .mcache_capacity = 2, .seen_capacity = 2 });
    defer g.deinit();
    const id = topic_mod.validMessageId(topic, "local", .{});
    try std.testing.expectError(error.NoPeersSubscribedToTopic, g.publishWithOptions(topic, "local", .{ .allow_zero_peers = false }, .{ .mono_ms = 10, .unix_s = 0 }));
    try std.testing.expect(!g.messages.seen.contains(id, 10));
    try std.testing.expectEqual(@as(usize, 0), g.messages.history.count);
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const t = g.overlay.findTopic(topic).?;
    _ = g.overlay.peerSubscription(&g.overlayContext(g.last_now_ms), peer.index, topic, true);
    g.markDirect(g.sessions.rows[peer.index].conn);
    const admitted = try g.publishWithOptions(topic, "local", .{ .allow_zero_peers = false }, .{ .mono_ms = 11, .unix_s = 0 });
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .selected = 1, .queued = 1 }, admitted);
    const retained = g.messages.history.message(g.messages.history.get(&g.messages.store, id).?);
    const tx_before = g.messages.store.get(retained).?.tx;
    const seen_at = g.messages.seen.added_ms[g.messages.seen.tail];
    const fanout_at = g.overlay.rows[t].fanout_last_ms;
    try std.testing.expectError(error.Duplicate, g.publish(topic, "local", .{ .mono_ms = 20, .unix_s = 0 }));
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .duplicate = true }, try g.publishWithOptions(topic, "local", .{ .ignore_duplicate = true }, .{ .mono_ms = 110, .unix_s = 0 }));
    try std.testing.expectEqual(retained, g.messages.history.message(g.messages.history.get(&g.messages.store, id).?));
    try std.testing.expectEqual(tx_before, g.messages.store.get(retained).?.tx);
    try std.testing.expectEqual(seen_at, g.messages.seen.added_ms[g.messages.seen.tail]);
    try std.testing.expectEqual(fanout_at, g.overlay.rows[t].fanout_last_ms);
    try std.testing.expectEqual(@as(u64, 1), g.counters.messages_published);
    _ = try g.publish(topic, "local", .{ .mono_ms = 111, .unix_s = 0 });
    try std.testing.expectEqual(@as(u64, 2), g.counters.messages_published);
}

test "publication recipient policy tops up without graft and accounts unique shared descriptors" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .score_params = .{ .publish_threshold = -9000 }, .connected_capacity = 16, .retained_capacity = 32, .retained_outbound_reserve = 1 });
    defer g.deinit();
    try support.subscribe(&g, topic);
    const t = g.overlay.findTopic(topic).?;
    for (0..12) |index| {
        const conn: @import("../quic/engine.zig").Handle = .{ .index = @intCast(index), .generation = 1 };
        const peer = support.addPeer(&g, conn, .v1_2).?;
        _ = g.overlay.peerSubscription(&g.overlayContext(g.last_now_ms), peer.index, topic, true);
        g.sessions.rows[peer.index].outbound = .{ .live = .{ .stream = .{ .conn = conn, .id = 2, .slot = 0 }, .version = .v1_2 } };
    }
    g.markDirect(g.sessions.rows[0].conn);
    support.penalize(&g, g.sessions.rows[0].conn, 40);
    support.penalize(&g, g.sessions.rows[10].conn, 40);
    support.penalize(&g, g.sessions.rows[9].conn, 36);
    try std.testing.expectEqual(g.options.score_params.publish_threshold, g.scoreSnapshot(g.sessions.rows[9].conn, .{ .mono_ms = 0, .unix_s = 0 }).?);
    g.options.pressure_timeout_ms = 1;
    g.sessions.setOutbound(11, .{ .closing = g.sessions.rows[11].outStream().? });
    g.overlay.rows[t].mesh.set(1);
    g.overlay.rows[t].mesh.set(10);
    g.overlay.rows[t].mesh.set(11);
    g.sessions.rows[1].outbound = .none;
    g.sessions.rows[9].outbound = .none;
    const outcome = try g.publish(topic, "short mesh", .{ .mono_ms = 1, .unix_s = 0 });
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .selected = 8, .queued = 8 }, outcome);
    try std.testing.expectEqual(@as(usize, 3), g.overlay.mesh(t).count());
    const id = topic_mod.validMessageId(topic, "short mesh", .{});
    const h = g.messages.history.message(g.messages.history.get(&g.messages.store, id).?);
    try std.testing.expectEqual(@as(usize, 1), g.messages.store.used_entries);
    try std.testing.expectEqual(@as(u32, 8), g.messages.store.get(h).?.tx);
    for (g.sessions.rows[0..12], 0..) |*peer, index| {
        const io = &peer.io;
        try std.testing.expectEqual(@as(usize, 0), io.tx.critical.used);
        if (index == 0 or (index >= 2 and index <= 8)) {
            try std.testing.expectEqual(@as(usize, 1), io.tx.data.count);
            try std.testing.expectEqual(h, io.tx.data.next(&g.messages.store).?.message);
        } else try std.testing.expectEqual(@as(usize, 0), io.tx.data.count);
        io.tx.cancelStream(&g.messages.store);
    }
    g.sessions.rows[2].outbound = .none;
    const full = &g.sessions.rows[3].io.tx;
    for (0..@import("outbox.zig").data_capacity) |_| {
        const origin: @import("delivery.zig").Origin = if (full.data.full()) .publication else .forward;
        try std.testing.expectEqual(.queued, full.queueData(&g.messages.store, h, origin, .{ .bytes = g.options.tx_peer_bytes }, 2));
    }
    const flood = try g.publishWithOptions(topic, "flood", .{ .flood = true }, .{ .mono_ms = 2, .unix_s = 0 });
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .selected = 7, .queued = 6, .pressured = 1 }, flood);
}

test "publication failed history admission retains payloads and recovery attribution" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .mcache_capacity = 1, .validation_capacity = 1 });
    defer g.deinit();
    const conn: @import("../quic/engine.zig").Handle = .{ .index = 0, .generation = 1 };
    const peer = support.addPeer(&g, conn, .v1_2).?;
    var retained: [2]@import("message_store.zig").Handle = undefined;
    for ([_][]const u8{ "retained zero", "retained one" }, &retained) |payload, *h| {
        _ = try g.publish(topic, payload, .{ .mono_ms = 1, .unix_s = 0 });
        h.* = g.messages.history.message(g.messages.history.get(&g.messages.store, topic_mod.validMessageId(topic, payload, .{})).?);
        try std.testing.expectEqual(.queued, g.sessions.rows[peer.index].io.tx.queueData(&g.messages.store, h.*, .forward, .{ .bytes = g.options.tx_peer_bytes }, 1));
    }
    const id = topic_mod.validMessageId(topic, "retry", .{});
    const logical = g.sessions.rows[peer.index].logical;
    const second_conn: @import("../quic/engine.zig").Handle = .{ .index = 1, .generation = 1 };
    const second_peer = support.addPeer(&g, second_conn, .v1_2).?;
    const second_logical = g.sessions.rows[second_peer.index].logical;
    g.recovery.add(&g.peers, id, logical, conn, 1, 30_000);
    g.recovery.add(&g.peers, id, second_logical, second_conn, 2, 30_000);
    g.recovery.controlSent(conn, 1, 12_000, 1);
    try std.testing.expectError(error.ResourceExhausted, g.publish(topic, "retry", .{ .mono_ms = 2, .unix_s = 0 }));
    try std.testing.expect(!g.messages.seen.contains(id, 2));
    try std.testing.expectEqual(@as(usize, 2), g.recovery.len);
    try std.testing.expectEqual(@as(?u64, 12_001), g.recovery.nextExpiry());
    try std.testing.expectEqual(@as(u32, 1), g.peers.rows[logical.index].pins);
    try std.testing.expectEqual(@as(u32, 1), g.peers.rows[second_logical.index].pins);
    for (retained, [_][]const u8{ "retained zero", "retained one" }) |h, expected| {
        try std.testing.expectEqual(@as(u32, 1), g.messages.store.get(h).?.tx);
        var decoded: [32]u8 = undefined;
        const size = try @import("snappy").raw.uncompress(g.messages.store.segment(h, g.messages.store.cursor(h)), &decoded);
        try std.testing.expectEqualStrings(expected, decoded[0..size]);
    }
    g.sessions.rows[peer.index].io.tx.cancelStream(&g.messages.store);
    _ = try g.publish(topic, "retry", .{ .mono_ms = 3, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 0), g.recovery.len);
    try std.testing.expectEqual(@as(u32, 0), g.peers.rows[logical.index].pins);
    try std.testing.expectEqual(@as(u32, 0), g.peers.rows[second_logical.index].pins);
    try std.testing.expectError(error.UnknownTopic, g.publish("invalid", "bytes", .{ .mono_ms = 4, .unix_s = 0 }));
    const oversized = try std.testing.allocator.alloc(u8, @import("constants.zig").MAX_PAYLOAD_SIZE + 1);
    defer std.testing.allocator.free(oversized);
    try std.testing.expectError(error.PayloadTooLarge, g.publish(topic, oversized, .{ .mono_ms = 4, .unix_s = 0 }));
    try std.testing.expectEqual(@as(u64, 3), g.counters.messages_published);
}

test "publication empty subscribed mesh reuses bounded fanout and full mesh excludes extra peers" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .connected_capacity = 16, .retained_capacity = 32, .retained_outbound_reserve = 1 });
    defer g.deinit();
    try support.subscribe(&g, topic);
    const t = g.overlay.findTopic(topic).?;
    for (0..10) |index| {
        const conn: @import("../quic/engine.zig").Handle = .{ .index = @intCast(index), .generation = 1 };
        const p = support.addPeer(&g, conn, .v1_2).?;
        _ = g.overlay.peerSubscription(&g.overlayContext(g.last_now_ms), p.index, topic, true);
        g.sessions.rows[p.index].outbound = .{ .live = .{ .stream = .{ .conn = conn, .id = 2, .slot = 0 }, .version = .v1_2 } };
    }
    const first = try g.publish(topic, "empty mesh", .{ .mono_ms = 1, .unix_s = 0 });
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .selected = 8, .queued = 8 }, first);
    const fanout = g.overlay.fanoutMembers(t).*;
    try std.testing.expectEqual(@as(usize, 8), fanout.count());
    try std.testing.expectEqual(@as(usize, 0), g.overlay.mesh(t).count());
    _ = try g.publish(topic, "reuse fanout", .{ .mono_ms = 2, .unix_s = 0 });
    try std.testing.expectEqual(fanout, g.overlay.fanoutMembers(t).*);
    for (0..8) |index| g.overlay.rows[t].mesh.set(index);
    for (g.sessions.rows) |*peer| peer.io.tx.cancelStream(&g.messages.store);
    const full = try g.publish(topic, "full mesh", .{ .mono_ms = 3, .unix_s = 0 });
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .selected = 8, .queued = 8 }, full);
    for (g.sessions.rows[0..10], 0..) |*peer, index| try std.testing.expectEqual(@as(usize, if (index < 8) 1 else 0), peer.io.tx.data.count);
}

test "publication local IDONTWANT cannot suppress exact bytes over QUIC" {
    var pair: @import("test_pair.zig").Pair = .{};
    try pair.init();
    defer pair.deinit();
    try support.subscribe(pair.shared.client.gossipsub, topic);
    try support.subscribe(pair.shared.server.gossipsub, topic);
    for (0..20) |_| try pair.pumpOnce();
    const destination = pair.shared.client.gossipsub.sessions.find(pair.shared.handles.client).?;
    const id = topic_mod.validMessageId(topic, "originated wire bytes", .{});
    pair.shared.client.gossipsub.sessions.suppress(destination, id, pair.shared.pair.now.mono_ms, 60_000);
    const outcome = try pair.shared.client.gossipsub.publishWithOptions(topic, "originated wire bytes", .{ .allow_zero_peers = false }, pair.shared.pair.now);
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .selected = 1, .queued = 1 }, outcome);
    var received: usize = 0;
    for (0..30) |_| {
        try pair.pumpOnce();
        for (pair.serverMessages()) |message| {
            try std.testing.expectEqual(id, message.id);
            try std.testing.expectEqualStrings(topic, message.topic);
            try std.testing.expectEqualStrings("originated wire bytes", message.bytes);
            received += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), received);
}

test "publication distinguishes topic capacity from unknown wire names" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .topic_policy = &@import("topic_fixture.zig").churn });
    defer g.deinit();
    for (0..@import("constants.zig").topics_cap) |i| {
        var bytes: [128]u8 = undefined;
        const name = try @import("topic_fixture.zig").churnTopic(i, &bytes);
        try support.subscribe(&g, name);
    }
    try std.testing.expectError(error.ResourceExhausted, g.publish(topic, "body", .{ .mono_ms = 1, .unix_s = 0 }));
    try std.testing.expectError(error.UnknownTopic, g.publish("invalid", "body", .{ .mono_ms = 1, .unix_s = 0 }));
}

test "delivery metrics attribute refused frames by origin, limit, client and slot phase" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    // Monotonic 2 ms is 6 s into a 12 s slot: phase 5,000 basis points.
    const slots = @import("../slot_clock.zig");
    var clock: slots.SlotClock = .{ .genesis_unix_ms = 1_742_213_400_000, .slot_duration_ms = 12_000 };
    clock.observe(.{ .mono_ms = 2, .unix_s = 0, .unix_ms = clock.genesis_unix_ms + 7 * 12_000 + 6_000 });
    g.slot_clock = &clock;
    const conn: @import("../quic/engine.zig").Handle = .{ .index = 0, .generation = 1 };
    const peer = support.addPeer(&g, conn, .v1_2).?;
    _ = g.overlay.peerSubscription(&g.overlayContext(g.last_now_ms), peer.index, topic, true);
    g.markDirect(conn);
    g.identified(conn, .Nimbus);
    try std.testing.expectEqual(@import("../peers/client.zig").Client.Nimbus, g.sessions.rows[peer.index].client);
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .selected = 1, .queued = 1 }, try g.publish(topic, "filler", .{ .mono_ms = 1, .unix_s = 0 }));
    const id = topic_mod.validMessageId(topic, "filler", .{});
    const filler = g.messages.history.message(g.messages.history.get(&g.messages.store, id).?);
    const io = &g.sessions.rows[peer.index].io;
    // Forwards fill the ordinary allowance and publications the local reserve.
    for (1..@import("outbox.zig").data_capacity) |_| {
        const origin: @import("delivery.zig").Origin = if (io.tx.data.full()) .publication else .forward;
        try std.testing.expectEqual(.queued, io.tx.queueData(&g.messages.store, filler, origin, .{ .bytes = g.options.tx_peer_bytes }, 1));
    }
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .selected = 1, .pressured = 1 }, try g.publish(topic, "refused", .{ .mono_ms = 2, .unix_s = 0 }));
    var body: [32]u8 = undefined;
    var writer = @import("protobuf.zig").Writer.init(&body);
    writer.bytesField(1, &id);
    support.control(&g, peer.index, .{ .iwant = .{ .body = writer.written() } }, .{ .mono_ms = 3, .unix_s = 0 });
    const metrics = &g.delivery_metrics;
    const nimbus = @intFromEnum(@import("../peers/client.zig").Client.Nimbus);
    for (metrics.drops, 0..) |origins, client| for (origins, 0..) |reasons, origin| for (reasons, 0..) |count, reason| {
        const expected = client == nimbus and reason == 0 and (origin == @intFromEnum(@import("delivery.zig").Origin.publication) or origin == @intFromEnum(@import("delivery.zig").Origin.iwant));
        try std.testing.expectEqual(@as(u64, @intFromBool(expected)), count);
    };
    for (metrics.drops_by_phase, slots.bucket_labels) |count, label| try std.testing.expectEqual(@as(u64, if (std.mem.eql(u8, label, "5000")) 2 else 0), count);
    try std.testing.expectEqual(@as(u64, 2), g.counters.send_dropped);
    // The first queued frame was the publication; its write completes 39 ms after admission.
    for (0..16) |_| {
        const segment = io.tx.segment(&g.messages.store);
        g.advanceWrite(g.sessions.ref(peer.index), segment.len, 40);
        if (metrics.write_time[@intFromEnum(@import("delivery.zig").Origin.publication)].count == 1) break;
    }
    const written = &metrics.write_time[@intFromEnum(@import("delivery.zig").Origin.publication)];
    try std.testing.expectEqual(@as(u64, 1), written.count);
    try std.testing.expectEqual(@as(u128, 39), written.sum);
    try std.testing.expectEqual(@as(u64, 0), metrics.write_time[@intFromEnum(@import("delivery.zig").Origin.forward)].count);
    io.tx.cancelStream(&g.messages.store);
}

test "publication priority belongs to each attempt: an IWANT for our publication is ordinary" {
    const Origin = @import("delivery.zig").Origin;
    const Outcome = @import("metrics.zig").Delivery.Outcome;
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const conn: @import("../quic/engine.zig").Handle = .{ .index = 0, .generation = 1 };
    const peer = support.addPeer(&g, conn, .v1_2).?;
    _ = g.overlay.peerSubscription(&g.overlayContext(g.last_now_ms), peer.index, topic, true);
    g.markDirect(conn);
    const io = &g.sessions.rows[peer.index].io;
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .selected = 1, .queued = 1 }, try g.publish(topic, "mine", .{ .mono_ms = 1, .unix_s = 0 }));
    const id = topic_mod.validMessageId(topic, "mine", .{});
    var body: [32]u8 = undefined;
    var writer = @import("protobuf.zig").Writer.init(&body);
    writer.bytesField(1, &id);
    support.control(&g, peer.index, .{ .iwant = .{ .body = writer.written() } }, .{ .mono_ms = 2, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 1), io.tx.data.classCount(.local));
    try std.testing.expectEqual(@as(usize, 1), io.tx.data.classCount(.ordinary));
    try std.testing.expectEqual(@as(usize, 1), io.tx.data.origins[@intFromEnum(Origin.iwant)]);
    // Both frames complete, the local one first; a later publication is cancelled by a reset.
    for (0..16) |_| {
        const segment = io.tx.segment(&g.messages.store);
        if (segment.len == 0) break;
        g.advanceWrite(g.sessions.ref(peer.index), segment.len, 3);
    }
    _ = try g.publish(topic, "cancelled", .{ .mono_ms = 4, .unix_s = 0 });
    g.cancelWrites(g.sessions.ref(peer.index));
    const recipients = &g.delivery_metrics.recipients;
    const publication = recipients[@intFromEnum(Origin.publication)];
    const iwant = recipients[@intFromEnum(Origin.iwant)];
    for ([_]Outcome{ .selected, .queued, .completed, .cancelled, .pressured, .unavailable }, [_]u64{ 2, 2, 1, 1, 0, 0 }, [_]u64{ 1, 1, 1, 0, 0, 0 }) |outcome, local, ordinary| {
        try std.testing.expectEqual(local, publication[@intFromEnum(outcome)]);
        try std.testing.expectEqual(ordinary, iwant[@intFromEnum(outcome)]);
    }
    try std.testing.expectEqual(@as(u64, 2), g.delivery_metrics.write_time[@intFromEnum(Origin.publication)].count + g.delivery_metrics.write_time[@intFromEnum(Origin.iwant)].count);
}
