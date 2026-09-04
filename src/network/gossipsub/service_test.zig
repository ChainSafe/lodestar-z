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
        self.client = try Service.init(std.testing.allocator, .{});
        errdefer self.client.deinit();
        self.server = try Service.init(std.testing.allocator, .{});
        errdefer self.server.deinit();
        const handles = try support.connectPair(&self.pair);
        self.handles = .{ .client = handles.client, .server = handles.server };
        // connectPair consumed the connected events, so open the meshsub streams now
        self.client.peerConnected(&self.pair.client, handles.client, self.pair.now);
        self.server.peerConnected(&self.pair.server, handles.server, self.pair.now);
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
        const server_ev = self.pair.events(&self.pair.server, &storage);
        self.server_count = self.server.process(
            &self.pair.server,
            server_ev,
            now,
            &self.server_events,
        );
        var storage2: [16]engine_mod.Event = undefined;
        const client_ev = self.pair.events(&self.pair.client, &storage2);
        self.client_count = self.client.process(
            &self.pair.client,
            client_ev,
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
    try std.testing.expect(setup.client.subscribe(beacon_block));
    try std.testing.expect(setup.server.subscribe(beacon_block));

    var rounds: usize = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();
    setup.pair.advance(heartbeat + 100);
    rounds = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();

    const payload = "a block delivered through the gossipsub service";
    try setup.client.publish(beacon_block, payload, setup.pair.now);

    var received = false;
    rounds = 0;
    while (rounds < 20 and !received) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .message => |m| {
                try std.testing.expectEqualStrings(payload, m.bytes);
                setup.server.report(m.handle, .accept);
                received = true;
            },
            else => {},
        };
    }
    try std.testing.expect(received);
    try std.testing.expectEqual(@as(u64, 1), setup.server.counters().messages_received);
}

test "gossipsub service preserves coalesced negotiation subscription and FIN" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    var server = try Service.init(std.testing.allocator, .{});
    defer server.deinit();
    const handles = try support.connectPair(&pair);
    server.peerConnected(&pair.server, handles.server, pair.now);
    var topic_buffer: [topic_mod.topic_max_len]u8 = undefined;
    const topic = topic_mod.build(digest, "beacon_block", &topic_buffer);
    try std.testing.expect(server.subscribe(topic));
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
        const count = server.process(&pair.server, pair.events(&pair.server, &storage), pair.now, &out);
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
    const index = setup.client.inner.state.findPeer(setup.handles.client).?;
    const first = setup.client.inner.state.outStream(index).?;
    setup.pair.client.closeStream(first, 0);
    var out: [16]Event = undefined;
    _ = setup.client.process(&setup.pair.client, &.{.{ .stream_closed = .{ .stream = first, .reset_code = 0 } }}, setup.pair.now, &out);
    for (0..4) |_| try setup.pumpOnce();
    try std.testing.expect(setup.client.inner.state.outStream(index) == null);
    setup.pair.advance(1_000);
    for (0..16) |_| try setup.pumpOnce();
    const replacement = setup.client.inner.state.outStream(index) orelse return error.TestUnexpectedResult;
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
    try std.testing.expect(setup.server.subscribe(topic));
    for (0..16) |_| try setup.pumpOnce();
    const index = setup.server.inner.state.findPeer(setup.handles.server).?;
    const first = try propose(&setup.pair, setup.handles.client, "/meshsub/1.1.0", &.{ 0x80, 0x01, 0x08 });
    for (0..8) |_| try setup.pumpOnce();
    try std.testing.expectEqual(@as(?usize, 128), setup.server.inner.io[index].reader.declaredLen());
    try std.testing.expectEqual(@import("state.zig").Version.v1_2, setup.server.inner.state.peerVersion(index));
    try std.testing.expectEqual(@import("state.zig").Version.v1_1, setup.server.inner.state.peers[index].inbound_version);
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
    try std.testing.expectEqual(@as(?usize, null), setup.server.inner.io[index].reader.declaredLen());
    try std.testing.expectError(error.StreamStopped, setup.pair.client.write(first, "x", false));
}

test "gossipsub service negotiates with a v1.1-only peer" {
    var setup: ServicePair = .{};
    try setup.init();
    defer setup.deinit();
    setup.server.deinit();
    setup.server = try Service.init(std.testing.allocator, .{ .versions = &.{.v1_1} });
    setup.server.peerConnected(&setup.pair.server, setup.handles.server, setup.pair.now);
    for (0..24) |_| try setup.pumpOnce();
    const client_index = setup.client.inner.state.findPeer(setup.handles.client).?;
    const server_index = setup.server.inner.state.findPeer(setup.handles.server).?;
    try std.testing.expect(setup.client.inner.state.outStream(client_index) != null);
    try std.testing.expect(setup.server.inner.state.outStream(server_index) != null);
    try std.testing.expectEqual(@import("state.zig").Version.v1_1, setup.client.inner.state.peerVersion(client_index));
    try std.testing.expectEqual(@import("state.zig").Version.v1_1, setup.server.inner.state.peerVersion(server_index));
}

test "gossipsub service ignores stale outcomes after connection and peer slot reuse" {
    var setup: ServicePair = .{};
    try setup.init();
    defer setup.deinit();
    for (0..16) |_| try setup.pumpOnce();
    const old_conn = setup.handles.client;
    const old_index = setup.client.inner.state.findPeer(old_conn).?;
    const old_generation = setup.client.inner.state.peerGeneration(old_index);
    const old_stream = setup.client.inner.state.outStream(old_index).?;
    try std.testing.expect(setup.pair.client.close(old_conn, 0));
    for (0..16) |_| try setup.pumpOnce();
    setup.pair.advance(30_000);
    for (0..4) |_| try setup.pumpOnce();
    const handles = try support.connectPair(&setup.pair);
    setup.handles = .{ .client = handles.client, .server = handles.server };
    setup.client.peerConnected(&setup.pair.client, handles.client, setup.pair.now);
    setup.server.peerConnected(&setup.pair.server, handles.server, setup.pair.now);
    for (0..16) |_| try setup.pumpOnce();
    const index = setup.client.inner.state.findPeer(handles.client).?;
    try std.testing.expectEqual(old_index, index);
    try std.testing.expect(setup.client.inner.state.peerGeneration(index) != old_generation);
    try std.testing.expectEqual(old_conn.index, handles.client.index);
    try std.testing.expect(old_conn.generation != handles.client.generation);
    const live = setup.client.inner.state.outStream(index).?;
    setup.client.negotiationResult(&setup.pair.client, .{
        .stream = old_stream,
        .direction = .outbound,
        .owner = .meshsub,
        .result = .{ .ready = .{ .protocol = .{ .meshsub = .v1_1 }, .leftover = "", .fin = false } },
    }, setup.pair.now);
    var out: [16]Event = undefined;
    _ = setup.client.process(&setup.pair.client, &.{.{ .stream_closed = .{ .stream = old_stream, .reset_code = 0 } }}, setup.pair.now, &out);
    try std.testing.expectEqual(live, setup.client.inner.state.outStream(index).?);
    try std.testing.expectEqual(@import("state.zig").Version.v1_2, setup.client.inner.state.peerVersion(index));
    const peer = setup.client.inner.state.peers[index];
    try std.testing.expectEqual(setup.pair.client.peerId(handles.client).?, peer.peer_id.?);
    try std.testing.expectEqual(setup.pair.client.direction(handles.client).?, peer.direction.?);
    try std.testing.expectEqual(setup.pair.client.peerAddress(handles.client).?, peer.address.?);
}
