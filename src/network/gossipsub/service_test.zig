const std = @import("std");
const gossipsub = @import("gossipsub.zig");
const service_mod = @import("service.zig");
const topic_mod = @import("topic.zig");
const engine_mod = @import("../quic/engine.zig");
const support = @import("../test_support.zig");

const Event = gossipsub.Event;
const Service = service_mod.Service;
const digest = topic_mod.ForkDigest{ 0x6a, 0x95, 0xa1, 0xa9 };
const heartbeat = @import("constants.zig").heartbeat_interval_ms;

const ServicePair = struct {
    pair: support.Pair = .{},
    client: Service = undefined,
    server: Service = undefined,
    handles: struct { client: engine_mod.Handle, server: engine_mod.Handle } = undefined,
    client_events: [16]Event = undefined,
    client_count: usize = 0,
    server_events: [16]Event = undefined,
    server_count: usize = 0,

    fn init(self: *ServicePair) !void {
        try self.pair.init(.{}, .{});
        errdefer self.pair.deinit();
        self.client = try Service.init(std.testing.allocator, .{
            .gossipsub = .{ .random_seed = 1 },
        });
        errdefer self.client.deinit();
        self.server = try Service.init(std.testing.allocator, .{
            .gossipsub = .{ .random_seed = 1 },
        });
        errdefer self.server.deinit();
        const handles = try support.connectPair(&self.pair);
        self.handles = .{ .client = handles.client, .server = handles.server };
        // connectPair consumed the connected events, so open the meshsub streams now
        _ = self.client.handler.peerConnected(&self.pair.client, handles.client, self.pair.now);
        _ = self.server.handler.peerConnected(&self.pair.server, handles.server, self.pair.now);
    }

    fn deinit(self: *ServicePair) void {
        self.server.deinit();
        self.client.deinit();
        self.pair.deinit();
    }

    fn pumpOnce(self: *ServicePair) !void {
        try self.pair.pump();
        const now = self.pair.now;
        var storage: [16]engine_mod.Event = undefined;
        var activity: [128]engine_mod.Handle = undefined;
        const server_active = self.pair.server.driverView().takeActivity(&activity);
        const server_ev = self.pair.events(&self.pair.server, &storage);
        self.server_count = self.server.process(
            &self.pair.server,
            server_ev,
            activity[0..server_active],
            now,
            &self.server_events,
        );
        var storage2: [16]engine_mod.Event = undefined;
        const client_active = self.pair.client.driverView().takeActivity(&activity);
        const client_ev = self.pair.events(&self.pair.client, &storage2);
        self.client_count = self.client.process(
            &self.pair.client,
            client_ev,
            activity[0..client_active],
            now,
            &self.client_events,
        );
        try self.pair.pump();
    }

    fn serverEvents(self: *const ServicePair) []const Event {
        return self.server_events[0..self.server_count];
    }
};

test "gossipsub service composes the mesh and delivers a message" {
    var setup: ServicePair = .{};
    try setup.init();
    defer setup.deinit();

    var buf: [topic_mod.topic_max_len]u8 = undefined;
    const beacon_block = topic_mod.build(digest, "beacon_block", &buf);
    try std.testing.expect(setup.client.handler.subscribe(beacon_block));
    try std.testing.expect(setup.server.handler.subscribe(beacon_block));

    var rounds: usize = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();
    setup.pair.advance(heartbeat + 100);
    rounds = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();

    const payload = "a block delivered through the gossipsub service";
    _ = try setup.client.handler.publish(beacon_block, payload, setup.pair.now);

    var received = false;
    rounds = 0;
    while (rounds < 20 and !received) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .message => |m| {
                try std.testing.expectEqualStrings(payload, m.bytes);
                _ = setup.server.handler.report(m.handle, .accept, setup.pair.now);
                received = true;
            },
            else => {},
        };
    }
    try std.testing.expect(received);
    try std.testing.expectEqual(@as(u64, 1), setup.server.handler.counters().messages_received);
}

test "gossipsub service preserves coalesced negotiation subscription and FIN" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    var server = try Service.init(std.testing.allocator, .{
        .gossipsub = .{ .random_seed = 1 },
    });
    defer server.deinit();
    const handles = try support.connectPair(&pair);
    _ = server.handler.peerConnected(&pair.server, handles.server, pair.now);
    var topic_buffer: [topic_mod.topic_max_len]u8 = undefined;
    const topic = topic_mod.build(digest, "beacon_block", &topic_buffer);
    try std.testing.expect(server.handler.subscribe(topic));
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
        const count = server.process(&pair.server, pair.events(&pair.server, &storage), &.{}, pair.now, &out);
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

test "gossipsub service retries a closed outbound stream after bounded backoff" {
    var setup: ServicePair = .{};
    try setup.init();
    defer setup.deinit();
    for (0..16) |_| try setup.pumpOnce();
    const index = setup.client.handler.inner.sessions.findPeer(setup.handles.client).?;
    const first = setup.client.handler.inner.sessions.outStream(index).?;
    setup.pair.client.closeStream(first, 0);
    var out: [16]Event = undefined;
    _ = setup.client.process(&setup.pair.client, &.{.{ .stream_closed = .{ .stream = first, .reset_code = 0 } }}, &.{}, setup.pair.now, &out);
    for (0..4) |_| try setup.pumpOnce();
    try std.testing.expect(setup.client.handler.inner.sessions.outStream(index) == null);
    setup.pair.advance(1_000);
    for (0..16) |_| try setup.pumpOnce();
    const replacement = setup.client.handler.inner.sessions.outStream(index) orelse return error.TestUnexpectedResult;
    try std.testing.expect(!std.meta.eql(first, replacement));
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
    var setup: ServicePair = .{};
    try setup.init();
    defer setup.deinit();
    var topic_buf: [topic_mod.topic_max_len]u8 = undefined;
    const topic = topic_mod.build(digest, "beacon_block", &topic_buf);
    try std.testing.expect(setup.server.handler.subscribe(topic));
    for (0..16) |_| try setup.pumpOnce();
    const index = setup.server.handler.inner.sessions.findPeer(setup.handles.server).?;
    const first = try propose(&setup.pair, setup.handles.client, "/meshsub/1.1.0", &.{ 0x80, 0x01, 0x08 });
    for (0..8) |_| try setup.pumpOnce();
    try std.testing.expectEqual(@as(?usize, 128), setup.server.handler.inner.sessions.rows[index].io.reader.declaredLen());
    try std.testing.expectEqual(@import("sessions.zig").Version.v1_2, setup.server.handler.inner.sessions.peerVersion(index));
    try std.testing.expectEqual(@import("sessions.zig").Version.v1_1, setup.server.handler.inner.sessions.rows[index].inbound_version);
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
    try std.testing.expectEqual(@as(?usize, null), setup.server.handler.inner.sessions.rows[index].io.reader.declaredLen());
    try std.testing.expectError(error.StreamStopped, setup.pair.client.write(first, "x", false));
}

test "gossipsub service negotiates with a v1.1-only peer" {
    var setup: ServicePair = .{};
    try setup.init();
    defer setup.deinit();
    setup.server.deinit();
    setup.server = try Service.init(std.testing.allocator, .{ .gossipsub = .{ .random_seed = 1 }, .versions = &.{.v1_1} });
    _ = setup.server.handler.peerConnected(&setup.pair.server, setup.handles.server, setup.pair.now);
    for (0..24) |_| try setup.pumpOnce();
    const client_index = setup.client.handler.inner.sessions.findPeer(setup.handles.client).?;
    const server_index = setup.server.handler.inner.sessions.findPeer(setup.handles.server).?;
    try std.testing.expect(setup.client.handler.inner.sessions.outStream(client_index) != null);
    try std.testing.expect(setup.server.handler.inner.sessions.outStream(server_index) != null);
    try std.testing.expectEqual(@import("sessions.zig").Version.v1_1, setup.client.handler.inner.sessions.peerVersion(client_index));
    try std.testing.expectEqual(@import("sessions.zig").Version.v1_1, setup.server.handler.inner.sessions.peerVersion(server_index));
}

test "gossipsub service cancels negotiation when subscriptions retire a peer" {
    var setup: ServicePair = .{};
    try setup.init();
    defer setup.deinit();
    setup.client.handler.inner.options.pressure_timeout_ms = 5;
    var topic_buffer: [topic_mod.topic_max_len]u8 = undefined;
    const topic = topic_mod.build(digest, "beacon_block", &topic_buffer);
    try std.testing.expect(setup.client.handler.subscribe(topic));
    _ = setup.client.handler.pump(&setup.client.router, &setup.pair.client, setup.pair.now, &setup.client_events);
    try std.testing.expect(setup.client.router.nextWakeup(setup.pair.now, 16) != null);

    setup.pair.advance(6);
    _ = setup.client.handler.pump(&setup.client.router, &setup.pair.client, setup.pair.now, &setup.client_events);
    try std.testing.expect(!setup.client.handler.admitted(setup.handles.client));
    try std.testing.expectEqual(@as(u64, 1), setup.client.handler.counters().subscription_timeouts);
    try std.testing.expectEqual(@as(?u64, null), setup.client.router.nextWakeup(setup.pair.now, 16));
    try std.testing.expect(setup.pair.client.peerId(setup.handles.client) != null);

    setup.client.handler.inner.options.pressure_timeout_ms = 30_000;
    try std.testing.expectEqual(.admitted, setup.client.handler.peerConnected(&setup.pair.client, setup.handles.client, setup.pair.now));
    for (0..16) |_| try setup.pumpOnce();
    try std.testing.expect(setup.client.handler.deliveryAvailable(setup.handles.client));
}

test "gossipsub service ignores stale outcomes after connection and peer slot reuse" {
    var setup: ServicePair = .{};
    try setup.init();
    defer setup.deinit();
    for (0..16) |_| try setup.pumpOnce();
    const old_conn = setup.handles.client;
    const old_index = setup.client.handler.inner.sessions.findPeer(old_conn).?;
    const old_generation = setup.client.handler.inner.sessions.peerGeneration(old_index);
    const old_stream = setup.client.handler.inner.sessions.outStream(old_index).?;
    try std.testing.expect(setup.pair.client.close(old_conn, 0));
    for (0..16) |_| try setup.pumpOnce();
    setup.pair.advance(30_000);
    for (0..4) |_| try setup.pumpOnce();
    const handles = try support.connectPair(&setup.pair);
    setup.handles = .{ .client = handles.client, .server = handles.server };
    _ = setup.client.handler.peerConnected(&setup.pair.client, handles.client, setup.pair.now);
    _ = setup.server.handler.peerConnected(&setup.pair.server, handles.server, setup.pair.now);
    for (0..16) |_| try setup.pumpOnce();
    const index = setup.client.handler.inner.sessions.findPeer(handles.client).?;
    try std.testing.expectEqual(old_index, index);
    try std.testing.expect(setup.client.handler.inner.sessions.peerGeneration(index) != old_generation);
    try std.testing.expectEqual(old_conn.index, handles.client.index);
    try std.testing.expect(old_conn.generation != handles.client.generation);
    const live = setup.client.handler.inner.sessions.outStream(index).?;
    setup.client.handler.negotiationResult(&setup.pair.client, .{
        .stream = old_stream,
        .direction = .outbound,
        .owner = .meshsub,
        .result = .{ .ready = .{ .protocol = .{ .meshsub = .v1_1 }, .leftover = "", .fin = false } },
    }, setup.pair.now);
    var out: [16]Event = undefined;
    _ = setup.client.process(&setup.pair.client, &.{.{ .stream_closed = .{ .stream = old_stream, .reset_code = 0 } }}, &.{}, setup.pair.now, &out);
    try std.testing.expectEqual(live, setup.client.handler.inner.sessions.outStream(index).?);
    try std.testing.expectEqual(@import("sessions.zig").Version.v1_2, setup.client.handler.inner.sessions.peerVersion(index));
    const peer = setup.client.handler.inner.peers.rows[setup.client.handler.inner.sessions.rows[index].logical.index];
    try std.testing.expectEqual(setup.pair.client.peerId(handles.client).?, peer.identity);
    try std.testing.expectEqual(setup.pair.client.direction(handles.client).?, peer.direction);
    try std.testing.expectEqual(@import("peer_book.zig").normalize(setup.pair.client.peerAddress(handles.client).?), peer.address);
}

test "gossipsub service detects an idle remote stop and retries without fabricated events" {
    var setup: ServicePair = .{};
    try setup.init();
    defer setup.deinit();
    var topic_buffer: [topic_mod.topic_max_len]u8 = undefined;
    const topic = topic_mod.build(digest, "beacon_block", &topic_buffer);
    try std.testing.expect(setup.server.handler.subscribe(topic));
    for (0..16) |_| try setup.pumpOnce();
    const client_index = setup.client.handler.inner.sessions.findPeer(setup.handles.client).?;
    const server_index = setup.server.handler.inner.sessions.findPeer(setup.handles.server).?;
    const first = setup.client.handler.inner.sessions.outStream(client_index).?;
    const remote = setup.server.handler.inner.sessions.rows[server_index].in_stream.?;
    try std.testing.expectEqual(first.id, remote.id);
    const io = &setup.client.handler.inner.sessions.rows[client_index].io;
    try std.testing.expect(!io.tx.pending());
    setup.pair.server.closeStream(remote, 0);
    for (0..4) |_| try setup.pumpOnce();
    try std.testing.expect(setup.client.handler.inner.sessions.outStream(client_index) == null);
    setup.pair.advance(999);
    for (0..4) |_| try setup.pumpOnce();
    try std.testing.expect(setup.client.handler.inner.sessions.outStream(client_index) == null);
    setup.pair.advance(1);
    for (0..16) |_| try setup.pumpOnce();
    const replacement = setup.client.handler.inner.sessions.outStream(client_index).?;
    try std.testing.expect(!std.meta.eql(first, replacement));
    try std.testing.expect(setup.client.handler.subscribe(topic));
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
    var setup: ServicePair = .{};
    try setup.init();
    defer setup.deinit();
    var topic_buffer: [topic_mod.topic_max_len]u8 = undefined;
    const topic = topic_mod.build(digest, "beacon_block", &topic_buffer);
    try std.testing.expect(setup.server.handler.subscribe(topic));
    for (0..16) |_| try setup.pumpOnce();
    const client_index = setup.client.handler.inner.sessions.findPeer(setup.handles.client).?;
    const server_index = setup.server.handler.inner.sessions.findPeer(setup.handles.server).?;
    const stream = setup.client.handler.inner.sessions.outStream(client_index).?;
    const remote = setup.server.handler.inner.sessions.rows[server_index].in_stream.?;
    try std.testing.expectEqual(@as(usize, 0), try setup.pair.server.write(remote, "", true));
    for (0..16) |_| try setup.pumpOnce();
    setup.pair.advance(1_000);
    for (0..16) |_| try setup.pumpOnce();
    try std.testing.expectEqual(stream, setup.client.handler.inner.sessions.outStream(client_index).?);
    _ = setup.pair.client.driverView().takeHostWork();
    var out: [16]Event = undefined;
    for (0..8) |_| {
        _ = setup.client.process(&setup.pair.client, &.{}, &.{}, setup.pair.now, &out);
        try std.testing.expect(!setup.pair.client.driverView().takeHostWork());
    }
    try std.testing.expect(setup.client.handler.subscribe(topic));
    var received = false;
    for (0..16) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| {
            if (event == .subscription_change) received = true;
        }
    }
    try std.testing.expect(received);
    try std.testing.expectEqual(stream, setup.client.handler.inner.sessions.outStream(client_index).?);
}

fn standaloneAllocationPrefix(allocator: std.mem.Allocator) !void {
    const resolved = try @import("../configuration.zig").resolve(.{ .profile = .small, .seed = 1, .forks = &.{} });
    var service = try Service.init(allocator, .{ .gossipsub = resolved.core.service.gossipsub, .negotiations_max = 2 });
    defer service.deinit();
    try std.testing.expectEqual(@as(usize, 12), service.handler.inner.sessions.rows.len);
    try std.testing.expectEqual(@as(usize, 2), service.router.negotiator.entries.len);
}

test "gossipsub standalone composition cleans every initialization prefix" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, standaloneAllocationPrefix, .{});
}
