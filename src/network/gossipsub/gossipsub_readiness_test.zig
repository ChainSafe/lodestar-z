const std = @import("std");
const gossip_test = @import("test_support.zig");
const engine_mod = @import("../quic/engine.zig");
const Pair = @import("test_pair.zig").Pair;

const topic = "/eth2/6a95a1a9/beacon_block/ssz_snappy";
const heartbeat = @import("constants.zig").heartbeat_interval_ms;

fn connectMesh(setup: *Pair) !void {
    try gossip_test.subscribe(setup.shared.client.gossipsub, topic);
    try gossip_test.subscribe(setup.shared.server.gossipsub, topic);
    for (0..20) |_| try setup.pumpOnce();
    setup.shared.pair.advance(heartbeat + 1);
    for (0..20) |_| try setup.pumpOnce();
}

/// Delivers the client's pending engine events to its service and reports whether any of them
/// was a readiness event routed to the client's gossip session.
fn processClient(setup: *Pair) bool {
    var storage: [64]engine_mod.Event = undefined;
    const events = setup.shared.pair.events(&setup.shared.pair.client, &storage);
    var routed = false;
    for (events) |event| if (event == .stream_ready) {
        const bound = setup.shared.pair.client.route(event.stream_ready.stream) orelse continue;
        routed = routed or bound.owner == .gossip_inbound or bound.owner == .gossip_outbound;
    };
    _ = setup.shared.client.process(&setup.shared.pair.client, events, setup.shared.pair.now, .{});
    return routed;
}

test "gossip idle mesh of 200 sessions costs no session visits" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();
    try connectMesh(&setup);
    const g = setup.shared.client.gossipsub;
    const index = g.overlay.findTopic(topic).?;
    // 199 more sessions on connections this engine does not hold. Their subscriptions count as
    // announced, they subscribe to the topic and eight of them graft us.
    for (0..199) |i| {
        const peer = gossip_test.addPeer(g, .{ .index = @intCast(300 + i), .generation = 1 }, .v1_2).?;
        const tx = &g.sessions.rows[peer.index].io.tx;
        tx.subscription_dirty = .initEmpty();
        tx.subscription_since = null;
        g.settle(peer.index);
        const context = g.overlayContext(setup.shared.pair.now.mono_ms);
        _ = g.overlay.peerSubscription(&context, peer.index, topic, true);
        if (i < 8) g.overlay.onGraft(&context, index, peer.index);
    }
    // One turn takes the sessions marked at admission, which have nothing to do.
    for (0..8) |_| try setup.pumpOnce();
    try std.testing.expectEqual(@as(usize, 200), g.resourceSnapshot().admitted_peers);
    const mesh = g.overlay.mesh(index).count();
    try std.testing.expect(mesh >= 9);
    const visits = g.sessions.visits;
    const writes = g.io_metrics.write_calls;
    const heartbeats = g.maintenance.cycles.count;
    for (0..120) |_| {
        setup.shared.pair.advance(30);
        try setup.pumpOnce();
        try std.testing.expectEqual(@as(usize, 0), g.sessions.ready.len);
        try std.testing.expect(g.nextWakeup(setup.shared.pair.now).? > setup.shared.pair.now.mono_ms);
    }
    try std.testing.expect(g.maintenance.cycles.count - heartbeats >= 4);
    try std.testing.expectEqual(visits, g.sessions.visits);
    try std.testing.expectEqual(writes, g.io_metrics.write_calls);
    try std.testing.expectEqual(mesh, g.overlay.mesh(index).count());
}

test "gossip retries a flow-blocked session only when send capacity grows" {
    var setup: Pair = .{};
    try setup.initWindow(.{ .random_seed = 1, .large_frame_timeout_ms = 400 }, .{ .random_seed = 1 }, 4096);
    defer setup.deinit();
    try connectMesh(&setup);
    const g = setup.shared.client.gossipsub;
    const index = g.sessions.find(setup.shared.handles.client).?;
    const io = &g.sessions.rows[index].io;
    var payload: [48 * 1024]u8 = undefined;
    var random = std.Random.DefaultPrng.init(7);
    random.random().bytes(&payload);
    try std.testing.expectEqual(@as(u16, 1), (try g.publish(topic, &payload, setup.shared.pair.now)).queued);

    // The publish is written in the turn that follows it, until the server's credit runs out.
    const writes = g.io_metrics.write_calls;
    _ = processClient(&setup);
    try std.testing.expect(g.io_metrics.write_calls > writes);
    try std.testing.expect(!io.tx.ready and io.tx.pending());
    try std.testing.expect(!g.sessions.rows[index].ready_link.linked);

    // The server does not read. Each round the client sends one byte on a stream of its own and
    // the server acknowledges it: ACKs without credit wake no session and retry no write.
    const probe = try setup.shared.pair.client.openStream(setup.shared.handles.client);
    const visits = g.sessions.visits;
    const blocked = g.io_metrics.write_would_block;
    const attempts = g.io_metrics.write_calls;
    const received = setup.shared.pair.client.counters.accepted;
    for (0..100) |_| {
        try std.testing.expectEqual(@as(usize, 1), try setup.shared.pair.client.write(probe, "x", false));
        try setup.shared.pair.pump();
        try std.testing.expect(!processClient(&setup));
        try std.testing.expect(gossip_test.sessionWakeup(g, setup.shared.pair.now) > setup.shared.pair.now.mono_ms);
    }
    try std.testing.expect(setup.shared.pair.client.counters.accepted - received >= 100);
    try std.testing.expectEqual(visits, g.sessions.visits);
    try std.testing.expectEqual(blocked, g.io_metrics.write_would_block);
    try std.testing.expectEqual(attempts, g.io_metrics.write_calls);

    // The server reads, and its credit arrives as writable events. A turn visits the session
    // exactly when an event reached it, and each visit writes into the new credit.
    var rounds: usize = 0;
    var woken: usize = 0;
    while (io.tx.data.count > 0 and rounds < 256) : (rounds += 1) {
        _ = setup.shared.processServer(.{});
        try setup.shared.pair.pump();
        const before = g.sessions.visits;
        const calls = g.io_metrics.write_calls;
        const routed = processClient(&setup);
        try std.testing.expectEqual(@as(u64, @intFromBool(routed)), g.sessions.visits - before);
        if (routed) {
            woken += 1;
            try std.testing.expect(g.io_metrics.write_calls > calls);
        } else try std.testing.expectEqual(calls, g.io_metrics.write_calls);
        try setup.shared.pair.pump();
    }
    try std.testing.expectEqual(@as(usize, 0), io.tx.data.count);
    try std.testing.expect(woken > 1);
    try std.testing.expectEqual(@as(u64, 0), g.counters.tx_stalled);

    // A blocked stream that never gains credit is reset at its progress deadline, popped from
    // the heap on the first turn at or after it.
    try std.testing.expectEqual(@as(u16, 1), (try g.publish(topic, payload[0 .. 32 * 1024], setup.shared.pair.now)).queued);
    _ = processClient(&setup);
    try std.testing.expect(!io.tx.ready and io.tx.pending());
    const deadline = io.deadlines(&g.options).next().?;
    try std.testing.expectEqual(deadline, g.sessions.deadlines.get(index).?);
    try std.testing.expectEqual(io.tx.progress_ms.? + g.options.large_frame_timeout_ms, deadline);
    setup.shared.pair.advance(deadline - 1 - setup.shared.pair.now.mono_ms);
    try std.testing.expect(g.nextWakeup(setup.shared.pair.now).? > setup.shared.pair.now.mono_ms);
    _ = processClient(&setup);
    try std.testing.expectEqual(@as(u64, 0), g.counters.send_progress_timeouts);
    setup.shared.pair.advance(1);
    try std.testing.expectEqual(@as(?u64, setup.shared.pair.now.mono_ms), g.nextWakeup(setup.shared.pair.now));
    _ = processClient(&setup);
    try std.testing.expectEqual(@as(u64, 1), g.counters.send_progress_timeouts);
    try std.testing.expect(g.sessions.rows[index].outStream() == null);
    try std.testing.expect(!io.tx.pending());
}

test "gossip busy session cannot starve the others" {
    const per_turn = 4;
    var setup: Pair = .{};
    try setup.initOpts(.{ .random_seed = 1, .connected_capacity = 3 * per_turn, .peers_per_pump = per_turn, .calls_per_peer = 1 }, .{ .random_seed = 2 });
    defer setup.deinit();
    for (0..20) |_| try setup.pumpOnce();
    const g = setup.shared.client.gossipsub;
    const busy = g.sessions.find(setup.shared.handles.client).?;
    const stream = setup.clientStream();
    for (1..3 * per_turn) |i| {
        _ = gossip_test.addPeer(g, .{ .index = @intCast(300 + i), .generation = 1 }, .v1_2).?;
    }
    try std.testing.expectEqual(@as(usize, 3 * per_turn), g.resourceSnapshot().admitted_peers);
    _ = gossip_test.pumpTurn(g, &setup.shared.pair.client, setup.shared.pair.now);
    _ = gossip_test.pumpTurn(g, &setup.shared.pair.client, setup.shared.pair.now);
    _ = gossip_test.pumpTurn(g, &setup.shared.pair.client, setup.shared.pair.now);
    try std.testing.expectEqual(@as(usize, 0), g.sessions.ready.len);
    // One writable QUIC stream isolates the rotation from remote flow control. The busy session
    // queues 64 frames and writes one per turn; every other session queues one.
    for (g.sessions.rows, 0..) |*row, position| {
        g.sessions.setOutbound(@intCast(position), .{ .live = .{ .stream = stream, .version = .v1_2 } });
        const frames: usize = if (position == busy) 64 else 1;
        for (0..frames) |_| try std.testing.expect(row.io.tx.inject(&.{0}, setup.shared.pair.now.mono_ms));
        g.settle(@intCast(position));
    }
    try std.testing.expectEqual(@as(usize, 3 * per_turn), g.sessions.ready.len);
    for (0..3) |_| {
        const visits = g.sessions.visits;
        _ = gossip_test.pumpTurn(g, &setup.shared.pair.client, setup.shared.pair.now);
        try std.testing.expectEqual(@as(u64, per_turn), g.sessions.visits - visits);
        // The busy session still has work and waits behind every session queued before it.
        try std.testing.expect(g.sessions.rows[busy].ready_link.linked);
    }
    for (g.sessions.rows, 0..) |*row, position| {
        if (position != busy) try std.testing.expect(!row.io.tx.pending());
    }
    try std.testing.expectEqual(@as(usize, 1), g.sessions.ready.len);
    try std.testing.expectEqual(@as(usize, 64 - 1), g.sessions.rows[busy].io.tx.control.count);
}

test "gossip publish reaches a mesh peer in the turn after it and leaves no ready session" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();
    try connectMesh(&setup);
    const g = setup.shared.client.gossipsub;
    const index = g.sessions.find(setup.shared.handles.client).?;
    try std.testing.expectEqual(@as(usize, 0), g.sessions.ready.len);
    try std.testing.expectEqual(@as(u16, 1), (try g.publish(topic, "same turn", setup.shared.pair.now)).queued);
    try std.testing.expect(g.sessions.rows[index].ready_link.linked);
    try std.testing.expectEqual(@as(?u64, setup.shared.pair.now.mono_ms), g.nextWakeup(setup.shared.pair.now));
    _ = setup.shared.processClient(.{});
    try std.testing.expect(!g.sessions.rows[index].io.tx.pending());
    try std.testing.expectEqual(@as(usize, 0), g.sessions.ready.len);
    try std.testing.expect(gossip_test.sessionWakeup(g, setup.shared.pair.now) > setup.shared.pair.now.mono_ms);
    try std.testing.expect(setup.shared.pair.client.backlog() or setup.shared.pair.client.dirtyCount() > 0);
    try setup.shared.pair.pump();
    _ = setup.shared.processServer(.{});
    try std.testing.expectEqual(@as(usize, 1), setup.serverMessages().len);
    try std.testing.expectEqualStrings("same turn", setup.serverMessages()[0].bytes);
}
