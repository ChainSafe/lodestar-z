const std = @import("std");
const Gossipsub = @import("gossipsub.zig").Gossipsub;
const topic_mod = @import("topic.zig");
const support = @import("test_support.zig");
const topic = "/eth2/01020304/beacon_block/ssz_snappy";

test "publication refusal retry duplicate and exact expiry preserve admission" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1, .seen_ttl_ms = 100, .mcache_capacity = 2, .seen_capacity = 2 });
    defer g.deinit();
    const id = topic_mod.validMessageId(topic, "local", .{});
    try std.testing.expectError(error.NoPeersSubscribedToTopic, g.publishWithOptions(topic, "local", .{ .allow_zero_peers = false }, .{ .mono_ms = 10, .unix_s = 0 }));
    try std.testing.expect(!g.messages.seen.contains(id, 10));
    try std.testing.expectEqual(@as(usize, 0), g.messages.history.count);
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const t = g.state.registry.findTopic(topic).?;
    g.state.registry.setSubscription(t, peer.index, true);
    g.markDirect(g.state.peers[peer.index].conn);
    const admitted = try g.publishWithOptions(topic, "local", .{ .allow_zero_peers = false }, .{ .mono_ms = 11, .unix_s = 0 });
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .selected = 1, .unavailable = 1 }, admitted);
    const retained = g.messages.history.get(&g.messages.store, id).?.message;
    const tx_before = g.messages.store.get(retained).?.tx;
    const seen_at = g.messages.seen.added_ms[g.messages.seen.tail];
    const fanout_at = g.state.registry.rows[t].fanout_last_ms;
    try std.testing.expectError(error.Duplicate, g.publish(topic, "local", .{ .mono_ms = 20, .unix_s = 0 }));
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .duplicate = true }, try g.publishWithOptions(topic, "local", .{ .ignore_duplicate = true }, .{ .mono_ms = 110, .unix_s = 0 }));
    try std.testing.expectEqual(retained, g.messages.history.get(&g.messages.store, id).?.message);
    try std.testing.expectEqual(tx_before, g.messages.store.get(retained).?.tx);
    try std.testing.expectEqual(seen_at, g.messages.seen.added_ms[g.messages.seen.tail]);
    try std.testing.expectEqual(fanout_at, g.state.registry.rows[t].fanout_last_ms);
    try std.testing.expectEqual(@as(u64, 1), g.counters.messages_published);
    _ = try g.publish(topic, "local", .{ .mono_ms = 111, .unix_s = 0 });
    try std.testing.expectEqual(@as(u64, 2), g.counters.messages_published);
}

test "publication recipient policy tops up without graft and accounts unique shared descriptors" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1, .connected_capacity = 16, .retained_capacity = 32, .retained_outbound_reserve = 1 });
    defer g.deinit();
    try std.testing.expect(g.subscribe(topic));
    const t = g.state.registry.findTopic(topic).?;
    for (0..12) |index| {
        const conn: @import("../quic/engine.zig").Handle = .{ .index = @intCast(index), .generation = 1 };
        const peer = support.addPeer(&g, conn, .v1_2).?;
        g.state.registry.setSubscription(t, peer.index, true);
        g.state.peers[peer.index].outbound = .{ .live = .{ .conn = conn, .id = 2, .slot = 0 } };
    }
    g.markDirect(g.state.peers[0].conn);
    try std.testing.expect(g.setPeerScore(g.state.peers[0].conn, -10_000));
    try std.testing.expect(g.setPeerScore(g.state.peers[10].conn, g.options.score_params.publish_threshold - 1));
    try std.testing.expect(g.setPeerScore(g.state.peers[9].conn, g.options.score_params.publish_threshold));
    g.mesh_policy.retire.set(11);
    g.state.registry.mesh(t).set(1);
    g.state.registry.mesh(t).set(10);
    g.state.registry.mesh(t).set(11);
    g.state.peers[1].outbound = .{ .waiting = 0 };
    g.state.peers[9].outbound = .{ .waiting = 0 };
    const outcome = try g.publish(topic, "short mesh", .{ .mono_ms = 1, .unix_s = 0 });
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .selected = 9, .queued = 8, .unavailable = 1 }, outcome);
    try std.testing.expectEqual(@as(usize, 3), g.state.registry.mesh(t).count());
    const id = topic_mod.validMessageId(topic, "short mesh", .{});
    const h = g.messages.history.get(&g.messages.store, id).?.message;
    try std.testing.expectEqual(@as(usize, 1), g.messages.store.used_entries);
    try std.testing.expectEqual(@as(u32, 8), g.messages.store.get(h).?.tx);
    for (g.state.peers[0..12], 0..) |*peer, index| {
        const io = &peer.io;
        try std.testing.expectEqual(@as(usize, 0), io.critical.used);
        if (index == 0 or (index >= 2 and index <= 8)) {
            try std.testing.expectEqual(@as(usize, 1), io.data_count);
            try std.testing.expectEqual(h, io.data[io.data_head].message);
        } else try std.testing.expectEqual(@as(usize, 0), io.data_count);
        io.resetTx(&g.messages.store);
    }
    g.state.peers[2].outbound = .{ .waiting = 0 };
    for (0..g.state.peers[3].io.data.len) |_| try std.testing.expectEqual(.queued, g.state.peers[3].io.queueData(&g.messages.store, h, g.options.tx_peer_bytes, 2));
    const flood = try g.publishWithOptions(topic, "flood", .{ .flood = true }, .{ .mono_ms = 2, .unix_s = 0 });
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .selected = 10, .queued = 6, .pressured = 1, .unavailable = 3 }, flood);
}

test "publication failed history admission retains payloads and recovery attribution" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1, .mcache_capacity = 1, .validation_capacity = 1 });
    defer g.deinit();
    const conn: @import("../quic/engine.zig").Handle = .{ .index = 0, .generation = 1 };
    const peer = support.addPeer(&g, conn, .v1_2).?;
    var retained: [2]@import("message_store.zig").Handle = undefined;
    for ([_][]const u8{ "retained zero", "retained one" }, &retained) |payload, *h| {
        _ = try g.publish(topic, payload, .{ .mono_ms = 1, .unix_s = 0 });
        h.* = g.messages.history.get(&g.messages.store, topic_mod.validMessageId(topic, payload, .{})).?.message;
        try std.testing.expectEqual(.queued, g.state.peers[peer.index].io.queueData(&g.messages.store, h.*, g.options.tx_peer_bytes, 1));
    }
    const id = topic_mod.validMessageId(topic, "retry", .{});
    const logical = g.state.peers[peer.index].logical;
    const second_conn: @import("../quic/engine.zig").Handle = .{ .index = 1, .generation = 1 };
    const second_peer = support.addPeer(&g, second_conn, .v1_2).?;
    const second_logical = g.state.peers[second_peer.index].logical;
    g.recovery.add(&g.peers, id, logical, conn, 1);
    g.recovery.add(&g.peers, id, second_logical, second_conn, 2);
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
    g.state.peers[peer.index].io.resetTx(&g.messages.store);
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
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1, .connected_capacity = 16, .retained_capacity = 32, .retained_outbound_reserve = 1 });
    defer g.deinit();
    try std.testing.expect(g.subscribe(topic));
    const t = g.state.registry.findTopic(topic).?;
    for (0..10) |index| {
        const conn: @import("../quic/engine.zig").Handle = .{ .index = @intCast(index), .generation = 1 };
        const p = support.addPeer(&g, conn, .v1_2).?;
        g.state.registry.setSubscription(t, p.index, true);
        g.state.peers[p.index].outbound = .{ .live = .{ .conn = conn, .id = 2, .slot = 0 } };
    }
    const first = try g.publish(topic, "empty mesh", .{ .mono_ms = 1, .unix_s = 0 });
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .selected = 8, .queued = 8 }, first);
    const fanout = g.state.registry.fanout(t).*;
    try std.testing.expectEqual(@as(usize, 8), fanout.count());
    try std.testing.expectEqual(@as(usize, 0), g.state.registry.mesh(t).count());
    _ = try g.publish(topic, "reuse fanout", .{ .mono_ms = 2, .unix_s = 0 });
    try std.testing.expectEqual(fanout, g.state.registry.fanout(t).*);
    for (0..8) |index| g.state.registry.mesh(t).set(index);
    for (g.state.peers) |*peer| peer.io.resetTx(&g.messages.store);
    const full = try g.publish(topic, "full mesh", .{ .mono_ms = 3, .unix_s = 0 });
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .selected = 8, .queued = 8 }, full);
    for (g.state.peers[0..10], 0..) |*peer, index| try std.testing.expectEqual(@as(usize, if (index < 8) 1 else 0), peer.io.data_count);
}

test "publication local IDONTWANT cannot suppress exact bytes over QUIC" {
    var pair: @import("gossipsub_test.zig").GossipPair = .{};
    try pair.init();
    defer pair.deinit();
    try std.testing.expect(pair.client.subscribe(topic));
    try std.testing.expect(pair.server.subscribe(topic));
    for (0..20) |_| try pair.pumpOnce();
    const destination = pair.client.state.findPeer(pair.handles.client).?;
    const id = topic_mod.validMessageId(topic, "originated wire bytes", .{});
    pair.client.state.suppress(destination, id, pair.pair.now.mono_ms, 60_000);
    const outcome = try pair.client.publishWithOptions(topic, "originated wire bytes", .{ .allow_zero_peers = false }, pair.pair.now);
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .selected = 1, .queued = 1 }, outcome);
    var received: usize = 0;
    for (0..30) |_| {
        try pair.pumpOnce();
        for (pair.serverEvents()) |event| if (event == .message) {
            try std.testing.expectEqual(id, event.message.id);
            try std.testing.expectEqualStrings(topic, event.message.topic);
            try std.testing.expectEqualStrings("originated wire bytes", event.message.bytes);
            received += 1;
        };
    }
    try std.testing.expectEqual(@as(usize, 1), received);
}

test "publication distinguishes topic capacity from unknown wire names" {
    var g = try Gossipsub.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    for (0..@import("constants.zig").topics_cap) |i| {
        var bytes: [128]u8 = undefined;
        const name = try std.fmt.bufPrint(&bytes, "/eth2/01020304/topic_{d}/ssz_snappy", .{i});
        try std.testing.expect(g.subscribe(name));
    }
    try std.testing.expectError(error.ResourceExhausted, g.publish(topic, "body", .{ .mono_ms = 1, .unix_s = 0 }));
    try std.testing.expectError(error.UnknownTopic, g.publish("invalid", "body", .{ .mono_ms = 1, .unix_s = 0 }));
}
