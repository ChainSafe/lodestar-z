const std = @import("std");
const gossipsub = @import("gossipsub.zig");
const service_mod = @import("../service.zig");
const topic_mod = @import("topic.zig");
const engine_mod = @import("../quic/engine.zig");
const support = @import("../test_support.zig");

const Event = gossipsub.Event;
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
    try std.testing.expect(setup.client.gossipsub.inner.subscribe(beacon_block));
    try std.testing.expect(setup.server.gossipsub.inner.subscribe(beacon_block));

    var rounds: usize = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();
    setup.pair.advance(heartbeat + 100);
    rounds = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();

    const payload = "a block delivered through the gossipsub service";
    _ = try setup.client.gossipsub.inner.publish(beacon_block, payload, setup.pair.now);

    var received = false;
    rounds = 0;
    while (rounds < 20 and !received) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .message => |m| {
                try std.testing.expectEqualStrings(payload, m.bytes);
                _ = setup.server.gossipsub.inner.report(m.handle, .accept, setup.pair.now);
                received = true;
            },
            else => {},
        };
    }
    try std.testing.expect(received);
    try std.testing.expectEqual(@as(u64, 1), setup.server.gossipsub.inner.counters.messages_received);
}

test "gossipsub service preserves coalesced negotiation subscription and FIN" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    var server = try Service.init(std.testing.allocator, .{
        .reqresp = .{ .forks = &.{}, .peers = 4, .outbound_max = 1, .inbound_max = 1, .inbound_per_peer_max = 1 },
        .gossipsub = .{ .random_seed = 1 },
    });
    defer server.deinit();
    const handles = try support.connectPair(&pair);
    _ = server.gossipsub.peerConnected(&pair.server, handles.server, pair.now);
    var topic_buffer: [topic_mod.topic_max_len]u8 = undefined;
    const topic = topic_mod.build(digest, "beacon_block", &topic_buffer);
    try std.testing.expect(server.gossipsub.inner.subscribe(topic));
    const stream = try pair.client.openStream(handles.client);
    const multistream = @import("../wire/multistream.zig");
    const protobuf = @import("protobuf.zig");
    const dialer = try multistream.Dialer.init("/meshsub/1.2.0");
    var bytes: [512]u8 = undefined;
    const hello = try dialer.initialWrite(&bytes);
    var writer = protobuf.Writer.init(bytes[hello.len..]);
    writer.varint(protobuf.subscriptionSize(topic));
    protobuf.writeSubscription(&writer, true, topic);
    const len = hello.len + writer.len;
    try std.testing.expectEqual(len, try pair.client.write(stream, bytes[0..len], true));
    var received = false;
    for (0..16) |_| {
        try pair.pump();
        var storage: [16]engine_mod.Event = undefined;
        var out: [16]Event = undefined;
        const count = server.process(&pair.server, pair.events(&pair.server, &storage), &.{}, pair.now, .{ .gossipsub = &out }).gossipsub;
        for (out[0..count]) |event| switch (event) {
            .subscription_change => |change| {
                try std.testing.expectEqualStrings(topic, change.topic);
                try std.testing.expect(change.subscribed);
                received = true;
            },
            else => {},
        };
    }
    try std.testing.expect(received);
}

test "gossipsub service does not retry a closed outbound stream" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();
    for (0..16) |_| try setup.pumpOnce();
    const index = setup.client.gossipsub.inner.sessions.findPeer(setup.handles.client).?;
    const first = setup.client.gossipsub.inner.sessions.outStream(index).?;
    setup.pair.client.closeStream(first, 0);
    var out: [16]Event = undefined;
    _ = setup.client.process(&setup.pair.client, &.{.{ .stream_closed = .{ .stream = first, .reset_code = 0 } }}, &.{}, setup.pair.now, .{ .gossipsub = &out });
    for (0..4) |_| try setup.pumpOnce();
    try std.testing.expect(setup.client.gossipsub.inner.sessions.outStream(index) == null);
    const started = setup.client.gossipsub.inner.counters.negotiation_started;
    for (0..10) |_| {
        setup.pair.advance(30_000);
        for (0..16) |_| try setup.pumpOnce();
        try std.testing.expect(!setup.client.gossipsub.deliveryAvailable(setup.handles.client));
    }
    try std.testing.expectEqual(started, setup.client.gossipsub.inner.counters.negotiation_started);
}

test "gossipsub direct send timeout retries once after a bounded delay" {
    const driver = @import("session_driver.zig");
    const Recovery = enum { resume_stream, negotiation_timeout, remove_direct };
    for ([_]Recovery{ .resume_stream, .negotiation_timeout, .remove_direct }) |recovery| {
        var setup: Pair = .{};
        try setup.initOpts(.{ .random_seed = 1, .tx_timeout_ms = 5 }, .{ .random_seed = 1 });
        defer setup.deinit();
        const topic = "/eth2/6a95a1a9/beacon_block/ssz_snappy";
        const g = setup.client.gossipsub.inner;
        try std.testing.expect(g.subscribe(topic));
        try std.testing.expect(setup.server.gossipsub.inner.subscribe(topic));
        for (0..32) |_| try setup.pumpOnce();
        g.markDirect(setup.handles.client);
        for (0..4) |_| try setup.pumpOnce();
        const index = g.sessions.findPeer(setup.handles.client).?;
        const previous = g.sessions.rows[index].outStream().?;
        const started = g.counters.negotiation_started;
        try std.testing.expectEqual(@as(u16, 1), (try g.publish(topic, "stalled", setup.pair.now)).queued);
        setup.pair.advance(g.options.tx_timeout_ms);
        for (0..4) |_| try setup.pumpOnce();
        try std.testing.expectEqual(@as(u64, 1), g.counters.send_queue_timeouts);
        try std.testing.expectEqual(setup.pair.now.mono_ms + driver.direct_retry_delay_ms, g.sessions.rows[index].outbound.retry_at);
        try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[index].io.tx.data.count);
        try std.testing.expectEqual(.pending, setup.client.gossipsub.deliveryStatus(setup.handles.client));
        setup.pair.advance(driver.direct_retry_delay_ms - 1);
        for (0..4) |_| try setup.pumpOnce();
        try std.testing.expectEqual(started, g.counters.negotiation_started);
        if (recovery == .remove_direct) g.unmarkDirect(&setup.pair.server_ctx.local_peer_id);
        setup.pair.advance(1);
        _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, .{ .gossipsub = &setup.client_events });
        if (recovery == .resume_stream) {
            for (0..32) |_| try setup.pumpOnce();
            try std.testing.expectEqual(started + 1, g.counters.negotiation_started);
            try std.testing.expect(g.sessions.rows[index].outStream().?.id != previous.id);
            try std.testing.expectEqual(@as(u16, 1), (try g.publish(topic, "resumed", setup.pair.now)).queued);
            var received = false;
            for (0..32) |_| {
                try setup.pumpOnce();
                for (setup.serverEvents()) |event| if (event == .message) {
                    try std.testing.expectEqualStrings("resumed", event.message.bytes);
                    _ = setup.server.gossipsub.inner.report(event.message.handle, .accept, setup.pair.now);
                    received = true;
                };
                if (received) break;
            }
            try std.testing.expect(received);
        } else {
            if (recovery == .negotiation_timeout) {
                try std.testing.expectEqual(started + 1, g.counters.negotiation_started);
                setup.pair.advance(@import("../negotiate.zig").negotiate_timeout_ms + 1);
                _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, .{ .gossipsub = &setup.client_events });
                try std.testing.expectEqual(@as(u64, 1), g.counters.negotiation_failed);
            }
            try std.testing.expect(g.sessions.rows[index].outbound == .none);
            const final_started = g.counters.negotiation_started;
            setup.pair.advance(driver.direct_retry_delay_ms * 2);
            _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, .{ .gossipsub = &setup.client_events });
            try std.testing.expectEqual(final_started, g.counters.negotiation_started);
        }
    }
}

fn propose(pair: *support.Pair, conn: engine_mod.Handle, version: []const u8, payload: []const u8) !engine_mod.StreamHandle {
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
    try std.testing.expect(setup.server.gossipsub.inner.subscribe(topic));
    for (0..16) |_| try setup.pumpOnce();
    const index = setup.server.gossipsub.inner.sessions.findPeer(setup.handles.server).?;
    const first = try propose(&setup.pair, setup.handles.client, "/meshsub/1.1.0", &.{ 0x80, 0x01, 0x08 });
    for (0..8) |_| try setup.pumpOnce();
    try std.testing.expectEqual(@as(?usize, 128), setup.server.gossipsub.inner.sessions.rows[index].io.reader.declaredLen());
    try std.testing.expectEqual(@import("sessions.zig").Version.v1_2, setup.server.gossipsub.inner.sessions.rows[index].outbound.live.version);
    var bytes: [160]u8 = undefined;
    const protobuf = @import("protobuf.zig");
    var writer = protobuf.Writer.init(&bytes);
    writer.varint(protobuf.subscriptionSize(topic));
    protobuf.writeSubscription(&writer, true, topic);
    _ = try propose(&setup.pair, setup.handles.client, "/meshsub/1.2.0", writer.written());
    var received = false;
    for (0..16) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| {
            if (event == .subscription_change) received = true;
        }
    }
    try std.testing.expect(received);
    try std.testing.expectEqual(@as(?usize, null), setup.server.gossipsub.inner.sessions.rows[index].io.reader.declaredLen());
    try std.testing.expectError(error.StreamStopped, setup.pair.client.write(first, "x", false));
}

test "gossipsub service negotiates with a v1.1-only peer" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();
    setup.server.deinit();
    setup.server = try Service.init(std.testing.allocator, .{ .reqresp = .{ .forks = &.{}, .peers = 4, .outbound_max = 1, .inbound_max = 1, .inbound_per_peer_max = 1 }, .gossipsub = .{ .random_seed = 1 }, .router = .{ .meshsub_versions = &.{.v1_1} } });
    _ = setup.server.gossipsub.peerConnected(&setup.pair.server, setup.handles.server, setup.pair.now);
    for (0..24) |_| try setup.pumpOnce();
    const client_index = setup.client.gossipsub.inner.sessions.findPeer(setup.handles.client).?;
    const server_index = setup.server.gossipsub.inner.sessions.findPeer(setup.handles.server).?;
    try std.testing.expect(setup.client.gossipsub.inner.sessions.outStream(client_index) != null);
    try std.testing.expect(setup.server.gossipsub.inner.sessions.outStream(server_index) != null);
    try std.testing.expectEqual(@import("sessions.zig").Version.v1_1, setup.client.gossipsub.inner.sessions.rows[client_index].outbound.live.version);
    try std.testing.expectEqual(@import("sessions.zig").Version.v1_1, setup.server.gossipsub.inner.sessions.rows[server_index].outbound.live.version);
}

test "gossipsub service subscribes only after negotiation and retirement cancels the router" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();
    setup.client.gossipsub.inner.options.pressure_timeout_ms = 5;
    const topic = "/eth2/6a95a1a9/beacon_block/ssz_snappy";
    try std.testing.expect(setup.client.gossipsub.inner.subscribe(topic));
    _ = setup.client.gossipsub.pump(&setup.client.router, &setup.pair.client, setup.pair.now, &setup.client_events);
    const index = setup.client.gossipsub.inner.sessions.findPeer(setup.handles.client).?;
    const session = &setup.client.gossipsub.inner.sessions.rows[index];
    try std.testing.expect(session.outbound == .negotiating);
    try std.testing.expectEqual(@as(usize, 0), session.io.tx.subscription_dirty.count());
    setup.pair.advance(6);
    _ = setup.client.gossipsub.pump(&setup.client.router, &setup.pair.client, setup.pair.now, &setup.client_events);
    try std.testing.expect(setup.client.gossipsub.admitted(setup.handles.client));
    try std.testing.expectEqual(@as(u64, 0), setup.client.gossipsub.inner.counters.subscription_timeouts);
    setup.client.gossipsub.retirePeer(&setup.client.router, &setup.pair.client, index);
    try std.testing.expectEqual(@as(?u64, null), setup.client.router.nextWakeup(setup.pair.now, 16));
    try std.testing.expect(setup.pair.client.peerId(setup.handles.client) != null);
}

test "gossipsub service ignores stale outcomes after connection and peer slot reuse" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();
    for (0..16) |_| try setup.pumpOnce();
    const old_conn = setup.handles.client;
    const old_index = setup.client.gossipsub.inner.sessions.findPeer(old_conn).?;
    const old_generation = setup.client.gossipsub.inner.sessions.peerGeneration(old_index);
    const old_stream = setup.client.gossipsub.inner.sessions.outStream(old_index).?;
    try std.testing.expect(setup.pair.client.close(old_conn, 0));
    for (0..16) |_| try setup.pumpOnce();
    setup.pair.advance(30_000);
    for (0..4) |_| try setup.pumpOnce();
    const handles = try support.connectPair(&setup.pair);
    setup.handles = .{ .client = handles.client, .server = handles.server };
    _ = setup.client.gossipsub.peerConnected(&setup.pair.client, handles.client, setup.pair.now);
    _ = setup.server.gossipsub.peerConnected(&setup.pair.server, handles.server, setup.pair.now);
    for (0..16) |_| try setup.pumpOnce();
    const index = setup.client.gossipsub.inner.sessions.findPeer(handles.client).?;
    try std.testing.expectEqual(old_index, index);
    try std.testing.expect(setup.client.gossipsub.inner.sessions.peerGeneration(index) != old_generation);
    try std.testing.expectEqual(old_conn.index, handles.client.index);
    try std.testing.expect(old_conn.generation != handles.client.generation);
    const live = setup.client.gossipsub.inner.sessions.outStream(index).?;
    setup.client.gossipsub.negotiationResult(&setup.pair.client, .{
        .stream = old_stream,
        .direction = .outbound,
        .owner = .meshsub,
        .result = .{ .ready = .{ .protocol = .{ .meshsub = .v1_1 }, .leftover = "", .fin = false } },
    }, setup.pair.now);
    var out: [16]Event = undefined;
    _ = setup.client.process(&setup.pair.client, &.{.{ .stream_closed = .{ .stream = old_stream, .reset_code = 0 } }}, &.{}, setup.pair.now, .{ .gossipsub = &out });
    try std.testing.expectEqual(live, setup.client.gossipsub.inner.sessions.outStream(index).?);
    try std.testing.expectEqual(@import("sessions.zig").Version.v1_2, setup.client.gossipsub.inner.sessions.rows[index].outbound.live.version);
    const peer = setup.client.gossipsub.inner.peers.rows[setup.client.gossipsub.inner.sessions.rows[index].logical.index];
    try std.testing.expectEqual(setup.pair.client.peerId(handles.client).?, peer.identity);
    try std.testing.expectEqual(setup.pair.client.direction(handles.client).?, peer.direction);
    try std.testing.expectEqual(@import("peer_book.zig").normalize(setup.pair.client.peerAddress(handles.client).?), peer.address);
}

test "gossipsub service detects an idle stop and reopens only on a new inbound stream" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();
    var topic_buffer: [topic_mod.topic_max_len]u8 = undefined;
    const topic = topic_mod.build(digest, "beacon_block", &topic_buffer);
    try std.testing.expect(setup.server.gossipsub.inner.subscribe(topic));
    for (0..16) |_| try setup.pumpOnce();
    const client_index = setup.client.gossipsub.inner.sessions.findPeer(setup.handles.client).?;
    const server_index = setup.server.gossipsub.inner.sessions.findPeer(setup.handles.server).?;
    const first = setup.client.gossipsub.inner.sessions.outStream(client_index).?;
    const remote = setup.server.gossipsub.inner.sessions.rows[server_index].in_stream.?;
    try std.testing.expectEqual(first.id, remote.id);
    const io = &setup.client.gossipsub.inner.sessions.rows[client_index].io;
    try std.testing.expect(!io.tx.pending());
    setup.pair.server.closeStream(remote, 0);
    for (0..4) |_| try setup.pumpOnce();
    try std.testing.expect(setup.client.gossipsub.inner.sessions.outStream(client_index) == null);
    const started = setup.client.gossipsub.inner.counters.negotiation_started;
    setup.pair.advance(30_000);
    for (0..16) |_| try setup.pumpOnce();
    try std.testing.expectEqual(started, setup.client.gossipsub.inner.counters.negotiation_started);
    try std.testing.expect(setup.client.gossipsub.inner.sessions.outStream(client_index) == null);
    const stream = try setup.pair.server.openStream(setup.handles.server);
    const dialer = try @import("../wire/multistream.zig").Dialer.init("/meshsub/1.2.0");
    var hello_buffer: [512]u8 = undefined;
    const hello = try dialer.initialWrite(&hello_buffer);
    try std.testing.expectEqual(hello.len, try setup.pair.server.write(stream, hello, false));
    for (0..16) |_| try setup.pumpOnce();
    const replacement = setup.client.gossipsub.inner.sessions.outStream(client_index).?;
    try std.testing.expect(!std.meta.eql(first, replacement));
    try std.testing.expect(setup.client.gossipsub.inner.subscribe(topic));
    var received = false;
    for (0..16) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| {
            if (event == .subscription_change) {
                try std.testing.expectEqualStrings(topic, event.subscription_change.topic);
                received = true;
            }
        }
    }
    try std.testing.expect(received);
}

test "gossipsub service preserves a remotely half-closed outbound stream without idle work hints" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();
    var topic_buffer: [topic_mod.topic_max_len]u8 = undefined;
    const topic = topic_mod.build(digest, "beacon_block", &topic_buffer);
    try std.testing.expect(setup.server.gossipsub.inner.subscribe(topic));
    for (0..16) |_| try setup.pumpOnce();
    const client_index = setup.client.gossipsub.inner.sessions.findPeer(setup.handles.client).?;
    const server_index = setup.server.gossipsub.inner.sessions.findPeer(setup.handles.server).?;
    const stream = setup.client.gossipsub.inner.sessions.outStream(client_index).?;
    const remote = setup.server.gossipsub.inner.sessions.rows[server_index].in_stream.?;
    try std.testing.expectEqual(@as(usize, 0), try setup.pair.server.write(remote, "", true));
    for (0..16) |_| try setup.pumpOnce();
    setup.pair.advance(1_000);
    for (0..16) |_| try setup.pumpOnce();
    try std.testing.expectEqual(stream, setup.client.gossipsub.inner.sessions.outStream(client_index).?);
    _ = setup.pair.client.takeHostWork();
    var out: [16]Event = undefined;
    for (0..8) |_| {
        _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, .{ .gossipsub = &out });
        try std.testing.expect(!setup.pair.client.takeHostWork());
    }
    try std.testing.expect(setup.client.gossipsub.inner.subscribe(topic));
    var received = false;
    for (0..16) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| {
            if (event == .subscription_change) received = true;
        }
    }
    try std.testing.expect(received);
    try std.testing.expectEqual(stream, setup.client.gossipsub.inner.sessions.outStream(client_index).?);
}

fn compositionAllocationPrefix(allocator: std.mem.Allocator) !void {
    const resolved = try @import("../configuration.zig").resolve(.{ .profile = .small, .seed = 1, .forks = &.{} });
    var service = try Service.init(allocator, .{ .reqresp = resolved.core.service.reqresp, .gossipsub = resolved.core.service.gossipsub, .router = .{ .negotiations_max = 2 } });
    defer service.deinit();
    try std.testing.expectEqual(@as(usize, 12), service.gossipsub.inner.sessions.rows.len);
    try std.testing.expectEqual(@as(usize, 2), service.router.negotiator.entries.len);
}

test "network composition with gossip cleans every initialization prefix" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, compositionAllocationPrefix, .{});
}

test "gossipsub rejected negotiation stays terminal without new inbound evidence" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();
    setup.client.router.deinit();
    setup.client.router = try @import("../router.zig").Router.init(std.testing.allocator, .{ .reqresp = false, .meshsub_versions = &.{.v1_2} });
    setup.server.router.deinit();
    setup.server.router = try @import("../router.zig").Router.init(std.testing.allocator, .{ .reqresp = false, .meshsub_versions = &.{.v1_1} });
    for (0..32) |_| try setup.pumpOnce();
    try std.testing.expectEqual(@as(u64, 1), setup.client.gossipsub.inner.counters.negotiation_started);
    try std.testing.expect(setup.client.gossipsub.inner.counters.negotiation_rejected > 0);
    const index = setup.client.gossipsub.inner.sessions.findPeer(setup.handles.client).?;
    try std.testing.expect(setup.client.gossipsub.inner.sessions.rows[index].outbound == .none);
    for (0..20) |_| {
        setup.pair.advance(1_000);
        for (0..4) |_| try setup.pumpOnce();
    }
    try std.testing.expectEqual(@as(u64, 1), setup.client.gossipsub.inner.counters.negotiation_started);
    try std.testing.expectEqual(@as(u64, 0), setup.client.gossipsub.inner.counters.subscription_timeouts);
    try std.testing.expect(setup.pair.client.peerId(setup.handles.client) != null);
}

test "gossipsub negotiation timeout releases resources without creating a retry deadline" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();
    setup.client.gossipsub.inner.markDirect(setup.handles.client);
    try std.testing.expect(setup.client.gossipsub.inner.subscribe("/eth2/6a95a1a9/beacon_block/ssz_snappy"));
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, .{ .gossipsub = &setup.client_events });
    setup.pair.advance(@import("../negotiate.zig").negotiate_timeout_ms + 1);
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, .{ .gossipsub = &setup.client_events });
    try std.testing.expectEqual(@as(u64, 1), setup.client.gossipsub.inner.counters.negotiation_failed);
    _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, .{ .gossipsub = &setup.client_events });
    try std.testing.expect(setup.client.router.nextWakeup(setup.pair.now, 16) == null);
    const index = setup.client.gossipsub.inner.sessions.findPeer(setup.handles.client).?;
    try std.testing.expect(setup.client.gossipsub.inner.sessions.rows[index].outbound == .none);
    try std.testing.expect(setup.client.gossipsub.inner.sessions.rows[index].io.deadlines(&setup.client.gossipsub.inner.options).next() == null);
    for (0..10) |_| {
        setup.pair.advance(30_000);
        _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, .{ .gossipsub = &setup.client_events });
    }
    try std.testing.expectEqual(@as(u64, 1), setup.client.gossipsub.inner.counters.negotiation_started);
}

test "gossipsub PRUNE exhaustion closes gossip streams and leaves the transport usable" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();
    const topic = "/eth2/6a95a1a9/beacon_block/ssz_snappy";
    try std.testing.expect(setup.client.gossipsub.inner.subscribe(topic));
    try std.testing.expect(setup.server.gossipsub.inner.subscribe(topic));
    for (0..32) |_| try setup.pumpOnce();
    const g = setup.client.gossipsub.inner;
    const index = g.sessions.findPeer(setup.handles.client).?;
    const topic_index = g.overlay.findTopic(topic).?;
    const generation = g.sessions.peerGeneration(index);
    const tx = &g.sessions.rows[index].io.tx;
    const full = try std.testing.allocator.alloc(u8, g.options.critical_bytes);
    defer std.testing.allocator.free(full);
    @memset(full, 0);
    try std.testing.expect(tx.injectFrame(full, true, null, setup.pair.now.mono_ms) != null);
    g.overlay.prune(&g.overlayContext(setup.pair.now.mono_ms), topic_index, index, 60_000);
    try std.testing.expect(g.sessions.rows[index].outbound == .closing);
    try std.testing.expect(!setup.client.gossipsub.deliveryAvailable(setup.handles.client));
    _ = setup.client.gossipsub.pump(&setup.client.router, &setup.pair.client, setup.pair.now, &setup.client_events);
    try std.testing.expect(!setup.client.gossipsub.admitted(setup.handles.client));
    try std.testing.expect(!g.sessions.matches(.{ .index = index, .generation = generation }));
    try std.testing.expect(!tx.pending());
    try std.testing.expectEqual(@as(usize, 0), tx.subscription_dirty.count());
    try std.testing.expect(!g.overlay.mesh(topic_index).isSet(index));
    try std.testing.expect(setup.pair.client.peerId(setup.handles.client) != null);
    _ = try setup.pair.client.openStream(setup.handles.client);
}
