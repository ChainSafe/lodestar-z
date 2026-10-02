const gossip_test = @import("test_support.zig");
const std = @import("std");
const service_mod = @import("../service.zig");
const topic_mod = @import("topic.zig");
const Engine = @import("../quic/Engine.zig");
const support = @import("../quic/test_support.zig");

const Service = service_mod.Service;
const digest = topic_mod.ForkDigest{ 0x6a, 0x95, 0xa1, 0xa9 };
const heartbeat = @import("constants.zig").heartbeat_interval_ms;

const Pair = @import("test_pair.zig").Pair;

test "gossipsub service composes the mesh and delivers a message" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();

    var buf: [topic_mod.topic_max_len]u8 = undefined;
    const beacon_block = topic_mod.build(digest, "beacon_block", &buf);
    try gossip_test.subscribe(setup.shared.client.gossipsub, beacon_block);
    try gossip_test.subscribe(setup.shared.server.gossipsub, beacon_block);

    var rounds: usize = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();
    setup.shared.pair.advance(heartbeat + 100);
    rounds = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();

    const payload = "a block delivered through the gossipsub service";
    _ = try setup.shared.client.gossipsub.publish(beacon_block, payload, setup.shared.pair.now);

    var received = false;
    rounds = 0;
    while (rounds < 20 and !received) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverMessages()) |m| {
            try std.testing.expectEqualStrings(payload, m.bytes);
            _ = setup.shared.server.gossipsub.report(m.handle, .accept, setup.shared.pair.now);
            received = true;
        }
    }
    try std.testing.expect(received);
    try std.testing.expectEqual(@as(u64, 1), setup.shared.server.gossipsub.topic_metrics.get(beacon_block).accepted);
}

test "gossipsub service does not retry a closed outbound stream" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();
    for (0..16) |_| try setup.pumpOnce();
    const index = setup.shared.client.gossipsub.sessions.find(setup.shared.handles.client).?;
    const first = setup.shared.client.gossipsub.sessions.outStream(index).?;
    setup.shared.pair.client.closeStream(first, 0);
    _ = setup.shared.client.process(&setup.shared.pair.client, &.{.{ .stream_closed = .{ .stream = first, .reset_code = 0 } }}, setup.shared.pair.now, .{});
    for (0..4) |_| try setup.pumpOnce();
    try std.testing.expect(setup.shared.client.gossipsub.sessions.outStream(index) == null);
    const started = setup.shared.client.gossipsub.counters.negotiation_started;
    for (0..10) |_| {
        setup.shared.pair.advance(30_000);
        for (0..16) |_| try setup.pumpOnce();
        try std.testing.expect(!setup.shared.client.gossipsub.deliveryAvailable(setup.shared.handles.client));
    }
    try std.testing.expectEqual(started, setup.shared.client.gossipsub.counters.negotiation_started);
}

test "gossipsub direct send timeout retries once after a bounded delay" {
    const driver = @import("session_io.zig");
    const Recovery = enum { resume_stream, negotiation_timeout, remove_direct };
    for ([_]Recovery{ .resume_stream, .negotiation_timeout, .remove_direct }) |recovery| {
        var setup: Pair = .{};
        try setup.initOpts(.{ .random_seed = 1, .tx_timeout_ms = 5 }, .{ .random_seed = 1 });
        defer setup.deinit();
        const topic = "/eth2/6a95a1a9/beacon_block/ssz_snappy";
        const g = setup.shared.client.gossipsub;
        try gossip_test.subscribe(g, topic);
        try gossip_test.subscribe(setup.shared.server.gossipsub, topic);
        for (0..32) |_| try setup.pumpOnce();
        g.markDirect(setup.shared.handles.client);
        for (0..4) |_| try setup.pumpOnce();
        const index = g.sessions.find(setup.shared.handles.client).?;
        const previous = g.sessions.rows[index].outStream().?;
        const started = g.counters.negotiation_started;
        try std.testing.expectEqual(@as(u16, 1), (try g.publish(topic, "stalled", setup.shared.pair.now)).queued);
        setup.shared.pair.advance(g.options.tx_timeout_ms);
        for (0..4) |_| try setup.pumpOnce();
        try std.testing.expectEqual(setup.shared.pair.now.mono_ms + driver.direct_retry_delay_ms, g.sessions.rows[index].outbound.retry_at);
        try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[index].io.tx.data.count);
        try std.testing.expectEqual(.pending, setup.shared.client.gossipsub.deliveryStatus(setup.shared.handles.client));
        setup.shared.pair.advance(driver.direct_retry_delay_ms - 1);
        for (0..4) |_| try setup.pumpOnce();
        try std.testing.expectEqual(started, g.counters.negotiation_started);
        if (recovery == .remove_direct) g.unmarkDirect(&setup.shared.pair.server_ctx.local_peer_id);
        setup.shared.pair.advance(1);
        _ = setup.shared.client.process(&setup.shared.pair.client, &.{}, setup.shared.pair.now, .{});
        if (recovery == .resume_stream) {
            for (0..32) |_| try setup.pumpOnce();
            try std.testing.expectEqual(started + 1, g.counters.negotiation_started);
            try std.testing.expect(g.sessions.rows[index].outStream().?.id != previous.id);
            try std.testing.expectEqual(@as(u16, 1), (try g.publish(topic, "resumed", setup.shared.pair.now)).queued);
            var received = false;
            for (0..32) |_| {
                try setup.pumpOnce();
                for (setup.serverMessages()) |message| {
                    try std.testing.expectEqualStrings("resumed", message.bytes);
                    _ = setup.shared.server.gossipsub.report(message.handle, .accept, setup.shared.pair.now);
                    received = true;
                }
                if (received) break;
            }
            try std.testing.expect(received);
        } else {
            if (recovery == .negotiation_timeout) {
                try std.testing.expectEqual(started + 1, g.counters.negotiation_started);
                setup.shared.pair.advance(@import("../negotiate.zig").negotiate_timeout_ms + 1);
                _ = setup.shared.client.process(&setup.shared.pair.client, &.{}, setup.shared.pair.now, .{});
            }
            try std.testing.expect(g.sessions.rows[index].outbound == .none);
            const final_started = g.counters.negotiation_started;
            setup.shared.pair.advance(driver.direct_retry_delay_ms * 2);
            _ = setup.shared.client.process(&setup.shared.pair.client, &.{}, setup.shared.pair.now, .{});
            try std.testing.expectEqual(final_started, g.counters.negotiation_started);
        }
    }
}

fn propose(pair: *support.Pair, conn: Engine.Handle, version: []const u8, payload: []const u8) !Engine.StreamHandle {
    const stream = try pair.client.openStream(conn);
    const dialer = try @import("../wire/multistream.zig").Dialer.init(version);
    var bytes: [512]u8 = undefined;
    const hello = try dialer.initialWrite(&bytes);
    @memcpy(bytes[hello.len..][0..payload.len], payload);
    const len = hello.len + payload.len;
    try std.testing.expectEqual(len, try pair.client.write(stream, bytes[0..len], false));
    return stream;
}

test "gossipsub replacement resets a partial frame and keeps directional versions" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();
    var topic_buf: [topic_mod.topic_max_len]u8 = undefined;
    const topic = topic_mod.build(digest, "beacon_block", &topic_buf);
    try gossip_test.subscribe(setup.shared.server.gossipsub, topic);
    for (0..16) |_| try setup.pumpOnce();
    const index = setup.shared.server.gossipsub.sessions.find(setup.shared.handles.server).?;
    const first = try propose(&setup.shared.pair, setup.shared.handles.client, "/meshsub/1.1.0", &.{ 0x80, 0x01, 0x08 });
    for (0..8) |_| try setup.pumpOnce();
    try std.testing.expectEqual(@as(?usize, 128), setup.shared.server.gossipsub.sessions.rows[index].io.reader.declaredLen());
    try std.testing.expectEqual(@import("sessions.zig").Version.v1_2, setup.shared.server.gossipsub.sessions.rows[index].outbound.live.version);
    var bytes: [160]u8 = undefined;
    const protobuf = @import("protobuf.zig");
    var writer = protobuf.Writer.init(&bytes);
    writer.varint(protobuf.subscriptionSize(topic));
    protobuf.writeSubscription(&writer, true, topic);
    _ = try propose(&setup.shared.pair, setup.shared.handles.client, "/meshsub/1.2.0", writer.written());
    for (0..16) |_| try setup.pumpOnce();
    try std.testing.expectEqual(@as(?usize, null), setup.shared.server.gossipsub.sessions.rows[index].io.reader.declaredLen());
    try std.testing.expectError(error.StreamStopped, setup.shared.pair.client.write(first, "x", false));
}

test "gossipsub service negotiates with a v1.1-only peer" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();
    setup.shared.server.deinit();
    setup.shared.server = try @import("../service_test_support.zig").initService(std.testing.allocator, .{ .reqresp = .{ .forks = &.{}, .peers = 4, .outbound_max = 1, .inbound_max = 1, .inbound_per_peer_max = 1, .admission = try @import("../reqresp/ReqResp.zig").Options.Admission.defaults(&@import("../reqresp/policy_fixture.zig").config(), 4, 4, 1) }, .gossipsub = .{ .random_seed = 1 }, .router = .{ .meshsub_versions = &.{.v1_1} } }, &setup.shared.pair.server);
    setup.shared.server_inbox.attach(setup.shared.server.gossipsub);
    _ = setup.shared.server.gossipsub.peerConnected(&setup.shared.pair.server, setup.shared.handles.server, false, setup.shared.pair.now);
    for (0..24) |_| try setup.pumpOnce();
    const client_index = setup.shared.client.gossipsub.sessions.find(setup.shared.handles.client).?;
    const server_index = setup.shared.server.gossipsub.sessions.find(setup.shared.handles.server).?;
    try std.testing.expect(setup.shared.client.gossipsub.sessions.outStream(client_index) != null);
    try std.testing.expect(setup.shared.server.gossipsub.sessions.outStream(server_index) != null);
    try std.testing.expectEqual(@import("sessions.zig").Version.v1_1, setup.shared.client.gossipsub.sessions.rows[client_index].outbound.live.version);
    try std.testing.expectEqual(@import("sessions.zig").Version.v1_1, setup.shared.server.gossipsub.sessions.rows[server_index].outbound.live.version);
}

test "gossipsub service subscribes only after negotiation and retirement cancels the router" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();
    setup.shared.client.gossipsub.options.pressure_timeout_ms = 5;
    const topic = "/eth2/6a95a1a9/beacon_block/ssz_snappy";
    try gossip_test.subscribe(setup.shared.client.gossipsub, topic);
    _ = setup.shared.client.gossipsub.pump(&setup.shared.client.router, &setup.shared.pair.client, setup.shared.pair.now);
    const index = setup.shared.client.gossipsub.sessions.find(setup.shared.handles.client).?;
    const session = &setup.shared.client.gossipsub.sessions.rows[index];
    try std.testing.expect(session.outbound == .negotiating);
    try std.testing.expectEqual(@as(usize, 0), session.io.tx.subscription_dirty.count());
    setup.shared.pair.advance(6);
    _ = setup.shared.client.gossipsub.pump(&setup.shared.client.router, &setup.shared.pair.client, setup.shared.pair.now);
    try std.testing.expect(setup.shared.client.gossipsub.admitted(setup.shared.handles.client));
    @import("session_io.zig").retirePeer(setup.shared.client.gossipsub, &setup.shared.client.router, &setup.shared.pair.client, index);
    try std.testing.expectEqual(@as(?u64, null), setup.shared.client.router.nextWakeup(setup.shared.pair.now, 16));
    try std.testing.expect(setup.shared.pair.client.peerId(setup.shared.handles.client) != null);
}

test "gossipsub service ignores stale outcomes after connection and peer slot reuse" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();
    for (0..16) |_| try setup.pumpOnce();
    const old_conn = setup.shared.handles.client;
    const old_index = setup.shared.client.gossipsub.sessions.find(old_conn).?;
    const old_generation = setup.shared.client.gossipsub.sessions.peerGeneration(old_index);
    const old_stream = setup.shared.client.gossipsub.sessions.outStream(old_index).?;
    try std.testing.expect(setup.shared.pair.client.close(old_conn, 0));
    for (0..16) |_| try setup.pumpOnce();
    setup.shared.pair.advance(30_000);
    for (0..4) |_| try setup.pumpOnce();
    const handles = try support.connectPair(&setup.shared.pair);
    setup.shared.handles = .{ .client = handles.client, .server = handles.server };
    _ = setup.shared.client.gossipsub.peerConnected(&setup.shared.pair.client, handles.client, false, setup.shared.pair.now);
    _ = setup.shared.server.gossipsub.peerConnected(&setup.shared.pair.server, handles.server, false, setup.shared.pair.now);
    for (0..16) |_| try setup.pumpOnce();
    const index = setup.shared.client.gossipsub.sessions.find(handles.client).?;
    try std.testing.expectEqual(old_index, index);
    try std.testing.expect(setup.shared.client.gossipsub.sessions.peerGeneration(index) != old_generation);
    try std.testing.expectEqual(old_conn.index, handles.client.index);
    try std.testing.expect(old_conn.generation != handles.client.generation);
    const live = setup.shared.client.gossipsub.sessions.outStream(index).?;
    setup.shared.client.gossipsub.negotiationResult(&setup.shared.pair.client, .{
        .stream = old_stream,
        .direction = .outbound,
        .owner = .meshsub,
        .result = .{ .ready = .{ .protocol = .{ .meshsub = .v1_1 }, .leftover = "", .fin = false } },
    }, setup.shared.pair.now);
    _ = setup.shared.client.process(&setup.shared.pair.client, &.{.{ .stream_closed = .{ .stream = old_stream, .reset_code = 0 } }}, setup.shared.pair.now, .{});
    try std.testing.expectEqual(live, setup.shared.client.gossipsub.sessions.outStream(index).?);
    try std.testing.expectEqual(@import("sessions.zig").Version.v1_2, setup.shared.client.gossipsub.sessions.rows[index].outbound.live.version);
    const peer = setup.shared.client.gossipsub.peers.rows[setup.shared.client.gossipsub.sessions.rows[index].logical.index];
    try std.testing.expectEqual(setup.shared.pair.client.peerId(handles.client).?, peer.identity);
    try std.testing.expectEqual(setup.shared.pair.client.direction(handles.client).?, peer.direction);
    try std.testing.expectEqual(@import("peer_book.zig").normalize(setup.shared.pair.client.peerAddress(handles.client).?), peer.address);
}

test "gossipsub service detects an idle stop and reopens only on a new inbound stream" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();
    var topic_buffer: [topic_mod.topic_max_len]u8 = undefined;
    const topic = topic_mod.build(digest, "beacon_block", &topic_buffer);
    try gossip_test.subscribe(setup.shared.server.gossipsub, topic);
    for (0..16) |_| try setup.pumpOnce();
    const client_index = setup.shared.client.gossipsub.sessions.find(setup.shared.handles.client).?;
    const server_index = setup.shared.server.gossipsub.sessions.find(setup.shared.handles.server).?;
    const first = setup.shared.client.gossipsub.sessions.outStream(client_index).?;
    const remote = setup.shared.server.gossipsub.sessions.rows[server_index].in_stream.?;
    try std.testing.expectEqual(first.id, remote.id);
    const io = &setup.shared.client.gossipsub.sessions.rows[client_index].io;
    try std.testing.expect(!io.tx.pending());
    setup.shared.pair.server.closeStream(remote, 0);
    for (0..4) |_| try setup.pumpOnce();
    try std.testing.expect(setup.shared.client.gossipsub.sessions.outStream(client_index) == null);
    const started = setup.shared.client.gossipsub.counters.negotiation_started;
    setup.shared.pair.advance(30_000);
    for (0..16) |_| try setup.pumpOnce();
    try std.testing.expectEqual(started, setup.shared.client.gossipsub.counters.negotiation_started);
    try std.testing.expect(setup.shared.client.gossipsub.sessions.outStream(client_index) == null);
    const stream = try setup.shared.pair.server.openStream(setup.shared.handles.server);
    const dialer = try @import("../wire/multistream.zig").Dialer.init("/meshsub/1.2.0");
    var hello_buffer: [512]u8 = undefined;
    const hello = try dialer.initialWrite(&hello_buffer);
    try std.testing.expectEqual(hello.len, try setup.shared.pair.server.write(stream, hello, false));
    for (0..16) |_| try setup.pumpOnce();
    const replacement = setup.shared.client.gossipsub.sessions.outStream(client_index).?;
    try std.testing.expect(!std.meta.eql(first, replacement));
    try gossip_test.subscribe(setup.shared.client.gossipsub, topic);
    for (0..16) |_| try setup.pumpOnce();
}

test "gossipsub service preserves a remotely half-closed outbound stream without idle work hints" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();
    var topic_buffer: [topic_mod.topic_max_len]u8 = undefined;
    const topic = topic_mod.build(digest, "beacon_block", &topic_buffer);
    try gossip_test.subscribe(setup.shared.server.gossipsub, topic);
    for (0..16) |_| try setup.pumpOnce();
    const client_index = setup.shared.client.gossipsub.sessions.find(setup.shared.handles.client).?;
    const server_index = setup.shared.server.gossipsub.sessions.find(setup.shared.handles.server).?;
    const stream = setup.shared.client.gossipsub.sessions.outStream(client_index).?;
    const remote = setup.shared.server.gossipsub.sessions.rows[server_index].in_stream.?;
    try std.testing.expectEqual(@as(usize, 0), try setup.shared.pair.server.write(remote, "", true));
    for (0..16) |_| try setup.pumpOnce();
    setup.shared.pair.advance(1_000);
    for (0..16) |_| try setup.pumpOnce();
    try std.testing.expectEqual(stream, setup.shared.client.gossipsub.sessions.outStream(client_index).?);
    try setup.shared.pair.flush(&setup.shared.pair.client);
    for (0..8) |_| {
        _ = setup.shared.client.process(&setup.shared.pair.client, &.{}, setup.shared.pair.now, .{});
        try std.testing.expect(!setup.shared.pair.client.backlog());
    }
    try gossip_test.subscribe(setup.shared.client.gossipsub, topic);
    for (0..16) |_| try setup.pumpOnce();
    try std.testing.expectEqual(stream, setup.shared.client.gossipsub.sessions.outStream(client_index).?);
}

fn compositionAllocationPrefix(allocator: std.mem.Allocator) !void {
    const resolved = try @import("../configuration.zig").resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .admission_policy = @import("../reqresp/policy_fixture.zig").config() });
    var service = try Service.init(allocator, .{ .reqresp = resolved.core.service.reqresp, .gossipsub = resolved.core.service.gossipsub, .router = .{ .negotiations_max = 2 } }, &try @import("../service_test_support.zig").fixtureLocal(.{}));
    defer service.deinit();
    try std.testing.expectEqual(@as(usize, 12), service.gossipsub.sessions.rows.len);
    try std.testing.expectEqual(@as(usize, 2), service.router.negotiator.entries.len);
}

test "network composition with gossip cleans every initialization prefix" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, compositionAllocationPrefix, .{});
}

test "gossipsub rejected negotiation stays terminal without new inbound evidence" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();
    setup.shared.client.router.deinit();
    setup.shared.client.router = try @import("../router.zig").Router.init(std.testing.allocator, .{ .meshsub_versions = &.{.v1_2} });
    setup.shared.server.router.deinit();
    setup.shared.server.router = try @import("../router.zig").Router.init(std.testing.allocator, .{ .meshsub_versions = &.{.v1_1} });
    for (0..32) |_| try setup.pumpOnce();
    try std.testing.expectEqual(@as(u64, 1), setup.shared.client.gossipsub.counters.negotiation_started);
    const index = setup.shared.client.gossipsub.sessions.find(setup.shared.handles.client).?;
    try std.testing.expect(setup.shared.client.gossipsub.sessions.rows[index].outbound == .none);
    for (0..20) |_| {
        setup.shared.pair.advance(1_000);
        for (0..4) |_| try setup.pumpOnce();
    }
    try std.testing.expectEqual(@as(u64, 1), setup.shared.client.gossipsub.counters.negotiation_started);
    try std.testing.expect(setup.shared.pair.client.peerId(setup.shared.handles.client) != null);
}

test "gossipsub negotiation timeout releases resources without creating a retry deadline" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();
    setup.shared.client.gossipsub.markDirect(setup.shared.handles.client);
    try gossip_test.subscribe(setup.shared.client.gossipsub, "/eth2/6a95a1a9/beacon_block/ssz_snappy");
    _ = setup.shared.client.process(&setup.shared.pair.client, &.{}, setup.shared.pair.now, .{});
    setup.shared.pair.advance(@import("../negotiate.zig").negotiate_timeout_ms + 1);
    _ = setup.shared.client.process(&setup.shared.pair.client, &.{}, setup.shared.pair.now, .{});
    _ = setup.shared.client.process(&setup.shared.pair.client, &.{}, setup.shared.pair.now, .{});
    try std.testing.expect(setup.shared.client.router.nextWakeup(setup.shared.pair.now, 16) == null);
    const index = setup.shared.client.gossipsub.sessions.find(setup.shared.handles.client).?;
    try std.testing.expect(setup.shared.client.gossipsub.sessions.rows[index].outbound == .none);
    try std.testing.expect(setup.shared.client.gossipsub.sessions.rows[index].io.deadlines(&setup.shared.client.gossipsub.options).next() == null);
    for (0..10) |_| {
        setup.shared.pair.advance(30_000);
        _ = setup.shared.client.process(&setup.shared.pair.client, &.{}, setup.shared.pair.now, .{});
    }
    try std.testing.expectEqual(@as(u64, 1), setup.shared.client.gossipsub.counters.negotiation_started);
}

test "gossipsub PRUNE exhaustion closes gossip streams and leaves the transport usable" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();
    const topic = "/eth2/6a95a1a9/beacon_block/ssz_snappy";
    try gossip_test.subscribe(setup.shared.client.gossipsub, topic);
    try gossip_test.subscribe(setup.shared.server.gossipsub, topic);
    for (0..32) |_| try setup.pumpOnce();
    const g = setup.shared.client.gossipsub;
    const index = g.sessions.find(setup.shared.handles.client).?;
    const topic_index = g.overlay.findTopic(topic).?;
    const generation = g.sessions.peerGeneration(index);
    const tx = &g.sessions.rows[index].io.tx;
    const full = try std.testing.allocator.alloc(u8, g.options.critical_bytes);
    defer std.testing.allocator.free(full);
    @memset(full, 0);
    try std.testing.expect(tx.injectFrame(full, true, setup.shared.pair.now.mono_ms) != null);
    g.overlay.prune(&g.overlayContext(setup.shared.pair.now.mono_ms), topic_index, index, 60_000, .excess);
    try std.testing.expect(g.sessions.rows[index].outbound == .closing);
    try std.testing.expect(!setup.shared.client.gossipsub.deliveryAvailable(setup.shared.handles.client));
    _ = setup.shared.client.gossipsub.pump(&setup.shared.client.router, &setup.shared.pair.client, setup.shared.pair.now);
    try std.testing.expect(!setup.shared.client.gossipsub.admitted(setup.shared.handles.client));
    try std.testing.expect(!g.sessions.matches(.{ .index = index, .generation = generation }));
    try std.testing.expect(!tx.pending());
    try std.testing.expectEqual(@as(usize, 0), tx.subscription_dirty.count());
    try std.testing.expect(!g.overlay.mesh(topic_index).isSet(index));
    try std.testing.expect(setup.shared.pair.client.peerId(setup.shared.handles.client) != null);
    _ = try setup.shared.pair.client.openStream(setup.shared.handles.client);
}
