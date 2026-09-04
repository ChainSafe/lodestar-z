const std = @import("std");
const gossipsub = @import("gossipsub.zig");
const topic_mod = @import("topic.zig");
const engine_mod = @import("../quic/engine.zig");
const negotiate = @import("../negotiate.zig");
const support = @import("../test_support.zig");

const Event = gossipsub.Event;
const Gossipsub = gossipsub.Gossipsub;

const meshsub_1_2 = "/meshsub/1.2.0";
pub const meshsub_ids = [_][]const u8{ "/meshsub/1.2.0", "/meshsub/1.1.0", "/meshsub/1.0.0" };

const digest = topic_mod.ForkDigest{ 0x6a, 0x95, 0xa1, 0xa9 };

pub const GossipPair = struct {
    pair: support.Pair = .{},
    client_neg: negotiate.Negotiator = undefined,
    server_neg: negotiate.Negotiator = undefined,
    client: Gossipsub = undefined,
    server: Gossipsub = undefined,
    handles: struct { client: engine_mod.Handle, server: engine_mod.Handle } = undefined,
    client_send: engine_mod.StreamHandle = undefined,
    server_send: engine_mod.StreamHandle = undefined,
    client_events: [16]Event = undefined,
    client_count: usize = 0,
    server_events: [16]Event = undefined,
    server_count: usize = 0,

    pub fn init(self: *GossipPair) !void {
        try self.initOpts(.{}, .{});
    }

    pub fn initOpts(
        self: *GossipPair,
        client_opts: gossipsub.Options,
        server_opts: gossipsub.Options,
    ) !void {
        try self.pair.init(.{}, .{});
        errdefer self.pair.deinit();
        self.client_neg = try negotiate.Negotiator.init(std.testing.allocator, 8);
        errdefer self.client_neg.deinit();
        self.server_neg = try negotiate.Negotiator.init(std.testing.allocator, 8);
        errdefer self.server_neg.deinit();
        self.client = try Gossipsub.init(std.testing.allocator, client_opts);
        errdefer self.client.deinit();
        self.server = try Gossipsub.init(std.testing.allocator, server_opts);
        errdefer self.server.deinit();
        const handles = try support.connectPair(&self.pair);
        self.handles = .{ .client = handles.client, .server = handles.server };
        _ = self.client.addPeer(handles.client, .v1_2).?;
        _ = self.server.addPeer(handles.server, .v1_2).?;
        self.client_send = try self.client_neg.beginOutbound(
            &self.pair.client,
            handles.client,
            meshsub_1_2,
            self.pair.now,
        );
        self.server_send = try self.server_neg.beginOutbound(
            &self.pair.server,
            handles.server,
            meshsub_1_2,
            self.pair.now,
        );
    }

    pub fn deinit(self: *GossipPair) void {
        self.server.deinit();
        self.client.deinit();
        self.server_neg.deinit();
        self.client_neg.deinit();
        self.pair.deinit();
    }

    pub fn pumpOnce(self: *GossipPair) !void {
        try self.pair.pump();
        const now = self.pair.now;
        try self.drive(&self.client, &self.client_neg, &self.pair.client, self.client_send);
        try self.drive(&self.server, &self.server_neg, &self.pair.server, self.server_send);
        self.client_count = self.client.pump(&self.pair.client, now, &self.client_events);
        self.server_count = self.server.pump(&self.pair.server, now, &self.server_events);
        try self.pair.pump();
    }

    fn drive(
        self: *GossipPair,
        gs: *Gossipsub,
        neg: *negotiate.Negotiator,
        engine: *engine_mod.Engine,
        send: engine_mod.StreamHandle,
    ) !void {
        const now = self.pair.now;
        var storage: [8]engine_mod.Event = undefined;
        for (self.pair.events(engine, &storage)) |event| switch (event) {
            .stream_opened => |stream| try neg.acceptInbound(stream, &meshsub_ids, now),
            .closed => |closed| gs.connectionClosed(closed.conn),
            else => {},
        };
        var outcomes: [8]negotiate.Outcome = undefined;
        const ready = neg.pump(engine, now, &outcomes);
        for (outcomes[0..ready]) |outcome| switch (outcome.result) {
            .ready => {
                const index = gs.state.findPeer(outcome.stream.conn) orelse continue;
                if (std.meta.eql(outcome.stream, send)) {
                    gs.setStreams(index, outcome.stream, null);
                } else {
                    gs.setStreams(index, null, outcome.stream);
                }
            },
            else => {},
        };
    }

    pub fn clientEvents(self: *const GossipPair) []const Event {
        return self.client_events[0..self.client_count];
    }

    pub fn serverEvents(self: *const GossipPair) []const Event {
        return self.server_events[0..self.server_count];
    }
};

fn buildTopic(name: []const u8, out: []u8) []const u8 {
    return topic_mod.build(digest, name, out);
}

test "gossipsub peers exchange subscriptions over the mesh streams" {
    var setup: GossipPair = .{};
    try setup.init();
    defer setup.deinit();

    var buf: [topic_mod.topic_max_len]u8 = undefined;
    const beacon_block = buildTopic("beacon_block", &buf);
    try std.testing.expect(setup.client.subscribe(beacon_block));
    try std.testing.expect(setup.server.subscribe(beacon_block));

    var client_saw = false;
    var server_saw = false;
    var rounds: usize = 0;
    while (rounds < 20 and !(client_saw and server_saw)) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.clientEvents()) |event| switch (event) {
            .subscription_change => |change| {
                try std.testing.expectEqualStrings(beacon_block, change.topic);
                try std.testing.expect(change.subscribed);
                client_saw = true;
            },
            else => {},
        };
        for (setup.serverEvents()) |event| switch (event) {
            .subscription_change => |change| {
                try std.testing.expectEqualStrings(beacon_block, change.topic);
                server_saw = true;
            },
            else => {},
        };
    }
    try std.testing.expect(client_saw);
    try std.testing.expect(server_saw);

    // each side now records the other as a subscriber of the topic
    const server_topic = setup.server.state.findTopic(beacon_block).?;
    try std.testing.expect(setup.server.state.subscribers(server_topic).count() == 1);
}

test "gossipsub forms a mesh through the heartbeat" {
    var setup: GossipPair = .{};
    try setup.init();
    defer setup.deinit();

    var buf: [topic_mod.topic_max_len]u8 = undefined;
    const beacon_block = buildTopic("beacon_block", &buf);
    try std.testing.expect(setup.client.subscribe(beacon_block));
    try std.testing.expect(setup.server.subscribe(beacon_block));

    var rounds: usize = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();
    setup.pair.advance(constants_heartbeat + 100);
    rounds = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();

    const client_topic = setup.client.state.findTopic(beacon_block).?;
    const server_topic = setup.server.state.findTopic(beacon_block).?;
    try std.testing.expectEqual(@as(usize, 1), setup.client.state.mesh(client_topic).count());
    try std.testing.expectEqual(@as(usize, 1), setup.server.state.mesh(server_topic).count());
}

test "gossipsub delivers a published message to a mesh peer" {
    var setup: GossipPair = .{};
    try setup.init();
    defer setup.deinit();

    var buf: [topic_mod.topic_max_len]u8 = undefined;
    const beacon_block = buildTopic("beacon_block", &buf);
    try std.testing.expect(setup.client.subscribe(beacon_block));
    try std.testing.expect(setup.server.subscribe(beacon_block));

    var rounds: usize = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();
    setup.pair.advance(constants_heartbeat + 100);
    rounds = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();

    const payload = "a signed beacon block payload for the mesh";
    try setup.client.publish(beacon_block, payload, setup.pair.now);

    var received = false;
    rounds = 0;
    while (rounds < 20 and !received) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .message => |m| {
                try std.testing.expectEqualStrings(beacon_block, m.topic);
                try std.testing.expectEqualStrings(payload, m.bytes);
                setup.server.report(m.handle, .accept);
                received = true;
            },
            else => {},
        };
    }
    try std.testing.expect(received);
    try std.testing.expectEqual(@as(u64, 1), setup.server.counters.messages_received);
    try std.testing.expectEqual(@as(u64, 1), setup.client.counters.messages_published);
}

test "gossipsub prunes a peer whose messages are rejected" {
    var setup: GossipPair = .{};
    try setup.init();
    defer setup.deinit();

    var buf: [topic_mod.topic_max_len]u8 = undefined;
    const beacon_block = buildTopic("beacon_block", &buf);
    try std.testing.expect(setup.client.subscribe(beacon_block));
    try std.testing.expect(setup.server.subscribe(beacon_block));

    var rounds: usize = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();
    setup.pair.advance(constants_heartbeat + 100);
    rounds = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();

    // the client publishes, the server rejects it as invalid
    try setup.client.publish(beacon_block, "an invalid block", setup.pair.now);
    rounds = 0;
    var rejected = false;
    while (rounds < 20 and !rejected) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .message => |m| {
                setup.server.report(m.handle, .reject);
                rejected = true;
            },
            else => {},
        };
    }
    try std.testing.expect(rejected);

    // the server's score for the client is now negative and the heartbeat prunes it
    const client_index = setup.server.state.findPeer(setup.handles.server).?;
    try std.testing.expect(setup.server.scores.score(client_index, setup.pair.now.mono_ms) < 0);
    setup.pair.advance(constants_heartbeat + 100);
    rounds = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();
    const server_topic = setup.server.state.findTopic(beacon_block).?;
    try std.testing.expectEqual(@as(usize, 0), setup.server.state.mesh(server_topic).count());
}

test "gossipsub credits first delivery only after the host accepts" {
    var setup: GossipPair = .{};
    try setup.init();
    defer setup.deinit();

    var buf: [topic_mod.topic_max_len]u8 = undefined;
    const beacon_block = buildTopic("beacon_block", &buf);
    try std.testing.expect(setup.client.subscribe(beacon_block));
    try std.testing.expect(setup.server.subscribe(beacon_block));

    var rounds: usize = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();
    setup.pair.advance(constants_heartbeat + 100);
    rounds = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();

    try setup.client.publish(beacon_block, "a beacon block payload", setup.pair.now);
    var handle: ?gossipsub.MessageId = null;
    rounds = 0;
    while (rounds < 20 and handle == null) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .message => |m| handle = m.handle,
            else => {},
        };
    }
    try std.testing.expect(handle != null);

    // receiving the message must not credit the sender; only the host's accept does
    const client_index = setup.server.state.findPeer(setup.handles.server).?;
    const before = setup.server.scores.score(client_index, setup.pair.now.mono_ms);
    setup.server.report(handle.?, .accept);
    const after = setup.server.scores.score(client_index, setup.pair.now.mono_ms);
    try std.testing.expect(after > before);
}

test "gossipsub receives a message larger than the per-peer body buffer" {
    var setup: GossipPair = .{};
    // the server holds a tiny per-peer body buffer, so the message must be read
    // through a claimed large-pool buffer instead
    try setup.initOpts(.{}, .{ .body_buffer_bytes = 1024, .large_message_bytes = 64 * 1024 });
    defer setup.deinit();

    var buf: [topic_mod.topic_max_len]u8 = undefined;
    const beacon_block = buildTopic("beacon_block", &buf);
    try std.testing.expect(setup.client.subscribe(beacon_block));
    try std.testing.expect(setup.server.subscribe(beacon_block));

    var rounds: usize = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();
    setup.pair.advance(constants_heartbeat + 100);
    rounds = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();

    // a poorly-compressible 8 KB payload: its compressed frame exceeds 1 KB
    var payload: [8192]u8 = undefined;
    for (&payload, 0..) |*byte, i| byte.* = @intCast((i * 131 + 7) & 0xff);
    try setup.client.publish(beacon_block, &payload, setup.pair.now);

    var received = false;
    rounds = 0;
    while (rounds < 20 and !received) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .message => |m| {
                try std.testing.expectEqualSlices(u8, &payload, m.bytes);
                setup.server.report(m.handle, .accept);
                received = true;
            },
            else => {},
        };
    }
    try std.testing.expect(received);
    try std.testing.expectEqual(@as(u64, 0), setup.server.counters.oversized_dropped);
}

const constants_heartbeat = @import("constants.zig").heartbeat_interval_ms;

fn expectControlFloodBounded(control_tag: u8) !void {
    var setup: GossipPair = .{};
    try setup.init();
    defer setup.deinit();
    for (0..20) |_| try setup.pumpOnce();
    const peer = setup.server.state.findPeer(setup.handles.server).?;
    const before = setup.server.counters.rpcs_received;
    var rpc: [8195]u8 = undefined;
    var writer = @import("protobuf.zig").Writer.init(&rpc);
    writer.bytes(&.{ 0x1a, 0x80, 0x40 });
    for (0..4096) |_| writer.bytes(&.{ control_tag, 0 });
    var framed: [8197]u8 = undefined;
    const wire = @import("frame.zig").writeFrame(&framed, writer.written());
    for (0..17) |_| {
        try std.testing.expectEqual(
            wire.len,
            try setup.pair.client.write(setup.client_send, wire, false),
        );
        for (0..4) |_| try setup.pumpOnce();
    }
    try std.testing.expectEqual(before + 17, setup.server.counters.rpcs_received);
    const count = if (control_tag == 0x0a)
        setup.server.io[peer].ihave_recv
    else
        setup.server.io[peer].idontwant_recv;
    try std.testing.expectEqual(@as(u16, 10), count);
}

test "gossipsub bounds more than 65535 IHAVE controls per heartbeat" {
    try expectControlFloodBounded(0x0a);
}

test "gossipsub bounds more than 65535 IDONTWANT controls per heartbeat" {
    try expectControlFloodBounded(0x2a);
}

fn idFromHex(hex: []const u8) gossipsub.MessageId {
    var id: gossipsub.MessageId = undefined;
    _ = std.fmt.hexToBytes(&id, hex) catch unreachable;
    return id;
}

test "gossipsub uses configured message IDs on publish and wire receive" {
    const vectors = [_]struct {
        policy: topic_mod.MessageIdPolicy,
        valid: []const u8,
        invalid: []const u8,
        invalid_body: []const u8,
    }{
        .{
            .policy = .{},
            .valid = "a9fe6ab574e2aac2f18a37d95a6250a6e0f5b583",
            .invalid = "a28c11a9057a41e968c2c3eead4b4c9fdd39c0d0",
            .invalid_body = "c2f970d6f12a642a5df7488e0cef9d76062b0b12",
        },
        .{
            .policy = .{ .phase0_digest = .{ 1, 2, 3, 4 } },
            .valid = "79d62a59d0e47597aeb73cb85ba034c3f67f90e8",
            .invalid = "a0960f8d63bfe4fce6c26ae9e33f8f2d2729239a",
            .invalid_body = "785b35d50e5df9eee4bb06e5b102b1088d149500",
        },
    };
    for (vectors) |vector| {
        var setup: GossipPair = .{};
        try setup.initOpts(
            .{ .message_id_policy = vector.policy },
            .{ .message_id_policy = vector.policy },
        );
        defer setup.deinit();
        const topic = "/eth2/01020304/beacon_block/ssz_snappy";
        try std.testing.expect(setup.client.subscribe(topic));
        try std.testing.expect(setup.server.subscribe(topic));
        for (0..20) |_| try setup.pumpOnce();
        setup.pair.advance(constants_heartbeat + 100);
        for (0..10) |_| try setup.pumpOnce();
        try setup.client.publish(topic, "hello", setup.pair.now);
        const valid = idFromHex(vector.valid);
        try std.testing.expect(setup.client.seen.contains(valid));
        var received = false;
        for (0..20) |_| {
            try setup.pumpOnce();
            for (setup.serverEvents()) |event| switch (event) {
                .message => |message| {
                    try std.testing.expectEqual(valid, message.handle);
                    received = true;
                },
                else => {},
            };
            if (received) break;
        }
        try std.testing.expect(received);
        const protobuf = @import("protobuf.zig");
        const malformed = [_][]const u8{ &.{0xff}, &.{ 5, 0 } };
        const invalid_ids = [_][]const u8{ vector.invalid, vector.invalid_body };
        for (malformed, invalid_ids) |data, expected| {
            var rpc: [128]u8 = undefined;
            var writer = protobuf.Writer.init(&rpc);
            protobuf.writeMessage(&writer, data, topic);
            var framed: [130]u8 = undefined;
            const wire = @import("frame.zig").writeFrame(&framed, writer.written());
            try std.testing.expectEqual(
                wire.len,
                try setup.pair.client.write(setup.client_send, wire, false),
            );
            for (0..4) |_| try setup.pumpOnce();
            try std.testing.expect(setup.server.seen.contains(idFromHex(expected)));
        }
    }
}
