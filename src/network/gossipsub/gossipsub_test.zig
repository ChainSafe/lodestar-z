const std = @import("std");
const gossipsub = @import("gossipsub.zig");
const topic_mod = @import("topic.zig");
const engine_mod = @import("../quic/engine.zig");
const routing = @import("../router.zig");
const support = @import("../test_support.zig");

const Event = gossipsub.Event;
const Gossipsub = gossipsub.Gossipsub;

const digest = topic_mod.ForkDigest{ 0x6a, 0x95, 0xa1, 0xa9 };

pub const GossipPair = struct {
    pair: support.Pair = .{},
    client_neg: routing.Router = undefined,
    server_neg: routing.Router = undefined,
    client: Gossipsub = undefined,
    server: Gossipsub = undefined,
    handles: struct { client: engine_mod.Handle, server: engine_mod.Handle } = undefined,
    client_send: engine_mod.StreamHandle = undefined,
    server_send: engine_mod.StreamHandle = undefined,
    client_events: [16]Event = undefined,
    client_count: usize = 0,
    server_events: [16]Event = undefined,
    server_count: usize = 0,
    client_event_capacity: usize = 16,
    server_event_capacity: usize = 16,

    pub fn init(self: *GossipPair) !void {
        try self.initOpts(.{
            .random_seed = 1,
        }, .{
            .random_seed = 1,
        });
    }

    pub fn initOpts(
        self: *GossipPair,
        client_opts: gossipsub.Options,
        server_opts: gossipsub.Options,
    ) !void {
        try self.pair.init(.{}, .{});
        errdefer self.pair.deinit();
        self.client_neg = try routing.Router.init(std.testing.allocator, .{ .negotiations_max = 8, .reqresp = false });
        errdefer self.client_neg.deinit();
        self.server_neg = try routing.Router.init(std.testing.allocator, .{ .negotiations_max = 8, .reqresp = false });
        errdefer self.server_neg.deinit();
        self.client = try Gossipsub.init(std.testing.allocator, client_opts);
        errdefer self.client.deinit();
        self.server = try Gossipsub.init(std.testing.allocator, server_opts);
        errdefer self.server.deinit();
        const handles = try support.connectPair(&self.pair);
        self.handles = .{ .client = handles.client, .server = handles.server };
        _ = @import("test_support.zig").addPeer(&self.client, handles.client, .v1_2).?;
        _ = @import("test_support.zig").addPeer(&self.server, handles.server, .v1_2).?;
        self.client_send = try self.client_neg.beginOutbound(
            &self.pair.client,
            handles.client,
            .{ .meshsub = .v1_2 },
            self.pair.now,
        );
        self.server_send = try self.server_neg.beginOutbound(
            &self.pair.server,
            handles.server,
            .{ .meshsub = .v1_2 },
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
        try self.drive(&self.client, &self.client_neg, &self.pair.client);
        try self.drive(&self.server, &self.server_neg, &self.pair.server);
        self.client_count = 0;
        self.server_count = 0;
        if (@import("test_support.zig").driver(&self.client).nextIoWakeup(now, self.client_event_capacity).? <= now.mono_ms)
            self.client_count = @import("test_support.zig").pump(&self.client, &self.pair.client, now, self.client_events[0..self.client_event_capacity]);
        if (@import("test_support.zig").driver(&self.server).nextIoWakeup(now, self.server_event_capacity).? <= now.mono_ms)
            self.server_count = @import("test_support.zig").pump(&self.server, &self.pair.server, now, self.server_events[0..self.server_event_capacity]);
        try self.pair.pump();
    }

    fn drive(
        self: *GossipPair,
        gs: *Gossipsub,
        neg: *routing.Router,
        engine: *engine_mod.Engine,
    ) !void {
        const now = self.pair.now;
        var storage: [8]engine_mod.Event = undefined;
        var activity: [128]engine_mod.Handle = undefined;
        const active = engine.driverView().takeActivity(&activity);
        for (activity[0..active]) |conn| gs.sessions.connectionActivity(conn);
        const events = self.pair.events(engine, &storage);
        neg.transportEvents(engine, events, now);
        for (events) |event| switch (event) {
            .closed => |closed| gs.connectionClosed(closed.conn),
            else => {},
        };
        var outcomes: [8]routing.Outcome = undefined;
        const ready = neg.pump(engine, now, &outcomes);
        for (outcomes[0..ready]) |outcome| switch (outcome.result) {
            .ready => |selection| {
                const index = gs.sessions.findPeer(outcome.stream.conn) orelse continue;
                if (outcome.direction == .outbound) {
                    @import("test_support.zig").driver(gs).replaceOutbound(engine, index, outcome.stream, selection.protocol.meshsub);
                } else {
                    @import("test_support.zig").driver(gs).replaceInbound(engine, index, outcome.stream, selection.protocol.meshsub);
                    try std.testing.expect(gs.sessions.receiveHandoff(index, selection.leftover, selection.fin));
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
    const server_topic = setup.server.overlay.findTopic(beacon_block).?;
    try std.testing.expect(setup.server.overlay.subscribers(server_topic).count() == 1);
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

    const client_topic = setup.client.overlay.findTopic(beacon_block).?;
    const server_topic = setup.server.overlay.findTopic(beacon_block).?;
    try std.testing.expectEqual(@as(usize, 1), setup.client.overlay.mesh(client_topic).count());
    try std.testing.expectEqual(@as(usize, 1), setup.server.overlay.mesh(server_topic).count());
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
    _ = try setup.client.publish(beacon_block, payload, setup.pair.now);

    var received = false;
    rounds = 0;
    while (rounds < 20 and !received) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .message => |m| {
                try std.testing.expectEqualStrings(beacon_block, m.topic);
                try std.testing.expectEqualStrings(payload, m.bytes);
                _ = setup.server.report(m.handle, .accept, setup.pair.now);
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
    _ = try setup.client.publish(beacon_block, "an invalid block", setup.pair.now);
    rounds = 0;
    var rejected = false;
    while (rounds < 20 and !rejected) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .message => |m| {
                _ = setup.server.report(m.handle, .reject, setup.pair.now);
                rejected = true;
            },
            else => {},
        };
    }
    try std.testing.expect(rejected);

    // the server's score for the client is now negative and the heartbeat prunes it
    const client_index = setup.server.sessions.findPeer(setup.handles.server).?;
    try std.testing.expect(setup.server.peers.score(.{ .index = client_index, .generation = setup.server.peers.rows[client_index].generation }, setup.pair.now.mono_ms) < 0);
    setup.pair.advance(constants_heartbeat + 100);
    rounds = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();
    const server_topic = setup.server.overlay.findTopic(beacon_block).?;
    try std.testing.expectEqual(@as(usize, 0), setup.server.overlay.mesh(server_topic).count());
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

    _ = try setup.client.publish(beacon_block, "a beacon block payload", setup.pair.now);
    var handle: ?gossipsub.ValidationHandle = null;
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
    const client_index = setup.server.sessions.findPeer(setup.handles.server).?;
    const before = setup.server.peers.score(.{ .index = client_index, .generation = setup.server.peers.rows[client_index].generation }, setup.pair.now.mono_ms);
    _ = setup.server.report(handle.?, .accept, setup.pair.now);
    const after = setup.server.peers.score(.{ .index = client_index, .generation = setup.server.peers.rows[client_index].generation }, setup.pair.now.mono_ms);
    try std.testing.expect(after > before);
}

test "gossipsub receives a message larger than the per-peer body buffer" {
    var setup: GossipPair = .{};
    // the server holds a tiny per-peer body buffer, so the message must be read
    // through a claimed large-pool buffer instead
    try setup.initOpts(.{
        .random_seed = 1,
    }, .{ .random_seed = 1, .body_buffer_bytes = 1024 });
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
    _ = try setup.client.publish(beacon_block, &payload, setup.pair.now);

    var received = false;
    rounds = 0;
    while (rounds < 20 and !received) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .message => |m| {
                try std.testing.expectEqualSlices(u8, &payload, m.bytes);
                _ = setup.server.report(m.handle, .accept, setup.pair.now);
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
    try setup.initOpts(.{
        .random_seed = 1,
    }, .{ .random_seed = 1, .items_per_peer = 4096, .items_per_pump = 8192 });
    defer setup.deinit();
    for (0..20) |_| try setup.pumpOnce();
    const peer = setup.server.sessions.findPeer(setup.handles.server).?;
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
        setup.server.sessions.rows[peer].io.ihave_recv
    else
        setup.server.sessions.rows[peer].io.idontwant_recv;
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
            .{ .random_seed = 1, .message_id_policy = vector.policy },
            .{ .random_seed = 1, .message_id_policy = vector.policy },
        );
        defer setup.deinit();
        const topic = "/eth2/01020304/beacon_block/ssz_snappy";
        try std.testing.expect(setup.client.subscribe(topic));
        try std.testing.expect(setup.server.subscribe(topic));
        for (0..20) |_| try setup.pumpOnce();
        setup.pair.advance(constants_heartbeat + 100);
        for (0..10) |_| try setup.pumpOnce();
        _ = try setup.client.publish(topic, "hello", setup.pair.now);
        const valid = idFromHex(vector.valid);
        try std.testing.expect(setup.client.messages.seen.contains(valid, setup.pair.now.mono_ms));
        var received = false;
        for (0..20) |_| {
            try setup.pumpOnce();
            for (setup.serverEvents()) |event| switch (event) {
                .message => |message| {
                    try std.testing.expectEqual(valid, message.id);
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
            try std.testing.expect(setup.server.messages.seen.contains(idFromHex(expected), setup.pair.now.mono_ms));
        }
    }
}

test "gossipsub queues incompressible 64 KiB publish" {
    var g = try Gossipsub.init(std.testing.allocator, .{
        .random_seed = 1,
    });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(topic));
    g.overlay.rows[g.overlay.findTopic(topic).?].mesh.set(peer.index);
    var payload: [65536]u8 = undefined;
    var rng = std.Random.DefaultPrng.init(42);
    rng.random().bytes(&payload);
    _ = try g.publish(topic, &payload, .{ .mono_ms = 1, .unix_s = 1 });
    try std.testing.expectEqual(@as(u64, 0), g.counters.send_dropped);
}

const test_topic = "/eth2/01020304/beacon_block/ssz_snappy";

fn connectMesh(setup: *GossipPair) !void {
    try std.testing.expect(setup.client.subscribe(test_topic));
    try std.testing.expect(setup.server.subscribe(test_topic));
    for (0..20) |_| try setup.pumpOnce();
    setup.pair.advance(constants_heartbeat + 1);
    for (0..20) |_| try setup.pumpOnce();
}

fn publishAdmissionA(setup: *GossipPair) !struct { count: usize, handle: ?gossipsub.ValidationHandle } {
    setup.pair.advance(1);
    const queued = try setup.client.publish(test_topic, "A", setup.pair.now);
    try std.testing.expectEqual(@as(u16, 1), queued.queued);
    var count: usize = 0;
    var handle: ?gossipsub.ValidationHandle = null;
    for (0..20) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| if (event == .message) {
            try std.testing.expectEqualStrings("A", event.message.bytes);
            count += 1;
            handle = event.message.handle;
        };
    }
    return .{ .count = count, .handle = handle };
}

test "gossipsub readmission reuses tombstones across repeated Seen eviction" {
    var setup: GossipPair = .{};
    try setup.initOpts(.{
        .random_seed = 1,
        .seen_ttl_ms = 1,
    }, .{ .random_seed = 1, .seen_capacity = 1, .validation_capacity = 4, .mcache_capacity = 1 });
    defer setup.deinit();
    try connectMesh(&setup);
    const first = try publishAdmissionA(&setup);
    try std.testing.expectEqual(@as(usize, 1), first.count);
    const old = first.handle.?;
    try std.testing.expectEqual(gossipsub.ReportOutcome{ .applied = .ignore }, setup.server.report(old, .ignore, setup.pair.now));
    try std.testing.expectEqual(@as(usize, 0), setup.server.messages.store.used_entries);
    _ = try setup.server.publish(test_topic, "B", setup.pair.now);
    const second = try publishAdmissionA(&setup);
    try std.testing.expectEqual(@as(usize, 1), second.count);
    const current = second.handle.?;
    const retained = setup.server.messages.validation.entries[current.index].state.pending.message;
    const id = topic_mod.validMessageId(test_topic, "A", .{});
    for (0..8) |i| {
        const payload = [_]u8{@as(u8, @intCast(i)) + 'C'};
        _ = try setup.server.publish(test_topic, &payload, setup.pair.now);
        try std.testing.expect(!setup.server.messages.seen.contains(id, setup.pair.now.mono_ms));
        const duplicates_before = setup.server.counters.duplicates;
        const duplicate = try publishAdmissionA(&setup);
        try std.testing.expectEqual(@as(usize, 0), duplicate.count);
        try std.testing.expectEqual(duplicates_before + 1, setup.server.counters.duplicates);
        var pending: usize = 0;
        for (setup.server.messages.validation.recent) |entry| {
            if (entry.state == .pending and std.mem.eql(u8, &entry.id, &id)) pending += 1;
        }
        try std.testing.expectEqual(@as(usize, 1), pending);
        try std.testing.expectEqual(@as(usize, 2), setup.server.messages.store.used_entries);
        try std.testing.expect(setup.server.messages.store.get(retained).?.validation);
    }
    try std.testing.expectEqual(old.index, current.index);
    try std.testing.expectEqual(old.generation + 1, current.generation);
    try std.testing.expectEqual(gossipsub.ReportOutcome.stale_handle, setup.server.report(old, .accept, setup.pair.now));
    try std.testing.expectEqual(gossipsub.ReportOutcome{ .applied = .ignore }, setup.server.report(current, .ignore, setup.pair.now));
    try std.testing.expectEqual(gossipsub.ReportOutcome.already_resolved, setup.server.report(current, .accept, setup.pair.now));
    try std.testing.expect(setup.server.messages.store.get(retained) == null);
    try std.testing.expectEqual(@as(usize, 1), setup.server.messages.store.used_entries);
    for (0..@import("constants.zig").mcache_len) |_| @import("test_support.zig").ageHistory(&setup.server);
    try std.testing.expectEqual(@as(usize, 0), setup.server.messages.store.used_entries);
    try std.testing.expectEqual(setup.server.messages.store.next.len, setup.server.messages.store.free_pages);
}

test "gossipsub legal maximum and above two MiB publish use actual resumable IO" {
    const sizes = [_]usize{ 65536, 2 * 1024 * 1024 + 1, @import("constants.zig").MAX_PAYLOAD_SIZE };
    for (sizes) |size| {
        var setup: GossipPair = .{};
        try setup.init();
        defer setup.deinit();
        try connectMesh(&setup);
        const payload = try std.testing.allocator.alloc(u8, size);
        defer std.testing.allocator.free(payload);
        var rng = std.Random.DefaultPrng.init(42);
        rng.random().bytes(payload);
        const outcome = try setup.client.publish(test_topic, payload, setup.pair.now);
        try std.testing.expectEqual(@as(u16, 1), outcome.queued);
        try std.testing.expectEqual(@as(u16, 0), outcome.pressured);
        var received = false;
        for (0..2000) |_| {
            try setup.pumpOnce();
            for (setup.serverEvents()) |event| if (event == .message) {
                try std.testing.expectEqualSlices(u8, payload, event.message.bytes);
                try std.testing.expectEqual(gossipsub.ReportOutcome{ .applied = .accept }, setup.server.report(event.message.handle, .accept, setup.pair.now));
                received = true;
            };
            if (received) break;
        }
        try std.testing.expect(received);
        try std.testing.expectEqual(@as(u64, 0), setup.client.counters.send_dropped);
        try std.testing.expectEqual(@as(u64, 0), setup.server.counters.oversized_dropped);
        try std.testing.expectEqual(setup.server.sessions.receive_pool.slots.len, setup.server.sessions.receive_pool.available());
    }
}

test "gossipsub legal maximum IWANT response uses actual IO without mesh publish" {
    var setup: GossipPair = .{};
    try setup.init();
    defer setup.deinit();
    try std.testing.expect(setup.server.subscribe(test_topic));
    try std.testing.expect(setup.client.subscribe(test_topic));
    for (0..20) |_| try setup.pumpOnce();
    const payload = try std.testing.allocator.alloc(u8, @import("constants.zig").MAX_PAYLOAD_SIZE);
    defer std.testing.allocator.free(payload);
    var rng = std.Random.DefaultPrng.init(73);
    rng.random().bytes(payload);
    const destination = setup.client.sessions.findPeer(setup.handles.client).?;
    const topic_index = setup.client.overlay.findTopic(test_topic).?;
    setup.client.overlay.setSubscription(&setup.client.overlayContext(setup.client.last_now_ms), topic_index, destination, false);
    const result = try setup.client.publish(test_topic, payload, setup.pair.now);
    try std.testing.expectEqual(@as(u16, 0), result.queued);
    setup.client.overlay.setSubscription(&setup.client.overlayContext(setup.client.last_now_ms), topic_index, destination, true);
    const id = topic_mod.validMessageId(test_topic, payload, .{});
    const pb = @import("protobuf.zig");
    var buf: [64]u8 = undefined;
    var w = pb.Writer.init(&buf);
    w.varint(pb.iwantRpcSize(1, 20));
    pb.beginIwantRpc(&w, 1, 20);
    pb.writeIwantId(&w, &id);
    try std.testing.expectEqual(w.len, try setup.pair.server.write(setup.server_send, w.written(), false));
    var received = false;
    for (0..2000) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| if (event == .message) {
            try std.testing.expectEqualSlices(u8, payload, event.message.bytes);
            received = true;
        };
        if (received) break;
    }
    try std.testing.expect(received);
    const cached = setup.client.messages.history.get(&setup.client.messages.store, id).?;
    try std.testing.expectEqual(@as(u8, 1), setup.client.messages.history.countsRow(cached)[0]);
}

test "gossipsub holds multiple messages and unread RPCs under zero event pressure" {
    var setup: GossipPair = .{};
    try setup.init();
    defer setup.deinit();
    try connectMesh(&setup);
    setup.server_event_capacity = 0;
    const pb = @import("protobuf.zig");
    const snappy = @import("snappy");
    var compressed: [128]u8 = undefined;
    const n = try snappy.raw.compress("first", &compressed);
    var body: [512]u8 = undefined;
    var w = pb.Writer.init(&body);
    pb.writeMessage(&w, compressed[0..n], test_topic);
    const n2 = try snappy.raw.compress("second", &compressed);
    pb.writeMessage(&w, compressed[0..n2], test_topic);
    var framed: [1024]u8 = undefined;
    const frame = @import("frame.zig").writeFrame(&framed, w.written());
    const n3 = try snappy.raw.compress("third", &compressed);
    w = pb.Writer.init(&body);
    pb.writeMessage(&w, compressed[0..n3], test_topic);
    const frame2 = @import("frame.zig").writeFrame(framed[frame.len..], w.written());
    try std.testing.expectEqual(frame.len + frame2.len, try setup.pair.client.write(setup.client_send, framed[0 .. frame.len + frame2.len], false));
    for (0..8) |_| try setup.pumpOnce();
    try std.testing.expectEqual(@as(u64, 0), setup.server.counters.messages_received);
    try std.testing.expect(@import("test_support.zig").driver(&setup.server).nextIoWakeup(setup.pair.now, 0).? > setup.pair.now.mono_ms);
    try std.testing.expectEqual(@as(?u64, setup.pair.now.mono_ms), @import("test_support.zig").driver(&setup.server).nextIoWakeup(setup.pair.now, 1));
    setup.server_event_capacity = 1;
    const expected = [_][]const u8{ "first", "second", "third" };
    var received: usize = 0;
    for (0..20) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| if (event == .message) {
            try std.testing.expect(received < expected.len);
            try std.testing.expectEqualStrings(expected[received], event.message.bytes);
            received += 1;
        };
        if (received == expected.len) break;
    }
    try std.testing.expectEqual(expected.len, received);
    for (0..8) |_| try setup.pumpOnce();
    try std.testing.expect(@import("test_support.zig").driver(&setup.server).nextIoWakeup(setup.pair.now, 1).? > setup.pair.now.mono_ms);
}

test "gossipsub subscription cursors synchronize all topics through small critical queues" {
    const topic_capacity = @import("constants.zig").topics_cap;
    var setup: GossipPair = .{};
    try setup.initOpts(.{ .random_seed = 1, .critical_bytes = 256, .control_bytes = 64 }, .{ .random_seed = 1, .critical_bytes = 256, .control_bytes = 64 });
    defer setup.deinit();
    var buf: [topic_mod.topic_max_len]u8 = undefined;
    for (0..topic_capacity) |i| {
        const topic = try std.fmt.bufPrint(&buf, "/eth2/01020304/topic_{d}/ssz_snappy", .{i});
        try std.testing.expect(setup.client.subscribe(topic));
        try std.testing.expect(setup.server.subscribe(topic));
    }
    var received: usize = 0;
    for (0..128) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| if (event == .subscription_change) {
            const expected = try std.fmt.bufPrint(&buf, "/eth2/01020304/topic_{d}/ssz_snappy", .{received});
            try std.testing.expectEqualStrings(expected, event.subscription_change.topic);
            received += 1;
        };
        if (received == topic_capacity) break;
    }
    try std.testing.expectEqual(@as(usize, topic_capacity), received);
    const peer = setup.client.sessions.findPeer(setup.handles.client).?;
    @import("test_support.zig").driver(&setup.client).resetOutbound(&setup.pair.client, peer);
    setup.client_send = try setup.client_neg.beginOutbound(&setup.pair.client, setup.handles.client, .{ .meshsub = .v1_2 }, setup.pair.now);
    received = 0;
    var seen = std.StaticBitSet(topic_capacity).initEmpty();
    for (0..128) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| if (event == .subscription_change) {
            const parsed = topic_mod.parse(event.subscription_change.topic).?;
            const number = try std.fmt.parseInt(usize, parsed.name[6..], 10);
            try std.testing.expect(number < topic_capacity and !seen.isSet(number));
            seen.set(number);
            received += 1;
        };
        if (received == topic_capacity) break;
    }
    try std.testing.expectEqual(@as(usize, topic_capacity), received);
    for (0..8) |_| try setup.pumpOnce();
    try std.testing.expect(@import("test_support.zig").driver(&setup.client).nextIoWakeup(setup.pair.now, 16).? > setup.pair.now.mono_ms);
}

test "gossipsub activity behind partial peer cursor remains ready and generation checked" {
    var setup: GossipPair = .{};
    try setup.initOpts(.{
        .random_seed = 1,
    }, .{ .random_seed = 1, .peers_per_pump = 1 });
    defer setup.deinit();
    try connectMesh(&setup);
    const real_peer = setup.server.sessions.findPeer(setup.handles.server).?;
    const extra = @import("test_support.zig").addPeer(&setup.server, .{ .index = 77, .generation = 9 }, .v1_2).?;
    setup.server.sessions.cursor = extra.index;
    const pb = @import("protobuf.zig");
    var compressed: [64]u8 = undefined;
    const n = try @import("snappy").raw.compress("arrived behind cursor", &compressed);
    var body: [256]u8 = undefined;
    var w = pb.Writer.init(&body);
    pb.writeMessage(&w, compressed[0..n], test_topic);
    var frame: [258]u8 = undefined;
    const wire = @import("frame.zig").writeFrame(&frame, w.written());
    try std.testing.expectEqual(wire.len, try setup.pair.client.write(setup.client_send, wire, false));
    try setup.pair.pump();
    var activity: [128]engine_mod.Handle = undefined;
    const active = setup.pair.server.driverView().takeActivity(&activity);
    try std.testing.expect(active > 0);
    for (activity[0..active]) |conn| setup.server.sessions.connectionActivity(conn);
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 0), @import("test_support.zig").pump(&setup.server, &setup.pair.server, setup.pair.now, &events));
    try std.testing.expectEqual(@as(?u64, setup.pair.now.mono_ms), @import("test_support.zig").driver(&setup.server).nextIoWakeup(setup.pair.now, 1));
    try std.testing.expectEqual(@as(usize, 1), @import("test_support.zig").pump(&setup.server, &setup.pair.server, setup.pair.now, &events));
    try std.testing.expectEqualStrings("arrived behind cursor", events[0].message.bytes);
    for (0..8) |_| {
        if (@import("test_support.zig").driver(&setup.server).nextIoWakeup(setup.pair.now, 1).? > setup.pair.now.mono_ms) break;
        _ = @import("test_support.zig").pump(&setup.server, &setup.pair.server, setup.pair.now, &events);
    }
    try std.testing.expect(!setup.server.sessions.rows[real_peer].io.rx_ready);
    setup.server.sessions.connectionActivity(.{ .index = setup.handles.server.index, .generation = setup.handles.server.generation + 1 });
    try std.testing.expect(!setup.server.sessions.rows[real_peer].io.rx_ready);
    try std.testing.expect(@import("test_support.zig").driver(&setup.server).nextIoWakeup(setup.pair.now, 1).? > setup.pair.now.mono_ms);
}

test "gossipsub frame and TX absolute residence survive steady byte progress" {
    var setup: GossipPair = .{};
    try setup.initOpts(.{ .random_seed = 1, .output_per_peer = 1, .tx_timeout_ms = 500 }, .{ .random_seed = 1, .body_buffer_bytes = 64, .large_frame_timeout_ms = 150, .pressure_timeout_ms = 500 });
    defer setup.deinit();
    for (0..16) |_| try setup.pumpOnce();
    const server_peer = setup.server.sessions.findPeer(setup.handles.server).?;
    const client_peer = setup.client.sessions.findPeer(setup.handles.client).?;
    var prefix: [8]u8 = undefined;
    var w = @import("protobuf.zig").Writer.init(&prefix);
    w.varint(65536);
    w.bytes("x");
    try std.testing.expectEqual(w.len, try setup.pair.client.write(setup.client_send, w.written(), false));
    for (0..4) |_| try setup.pumpOnce();
    try std.testing.expect(setup.server.sessions.rows[server_peer].io.large_slot != null);
    try std.testing.expect(setup.client.subscribe(test_topic));
    setup.client.overlay.rows[setup.client.overlay.findTopic(test_topic).?].mesh.set(client_peer);
    _ = try setup.client.publish(test_topic, "held transmit payload", setup.pair.now);
    for (0..4) |_| try setup.pumpOnce();
    const began = setup.pair.now.mono_ms;
    for (0..4) |_| {
        setup.pair.advance(100);
        try std.testing.expectEqual(@as(usize, 1), try setup.pair.client.write(setup.client_send, "x", false));
        try setup.pumpOnce();
        try std.testing.expect(setup.server.sessions.rows[server_peer].io.large_slot != null);
        try std.testing.expect(setup.server.sessions.rows[server_peer].io.progress_ms > began);
    }
    setup.pair.advance(100);
    try setup.pumpOnce();
    try std.testing.expectEqual(@as(u64, 1), setup.server.counters.large_stalled);
    try std.testing.expect(setup.server.sessions.rows[server_peer].io.large_slot == null);
    try std.testing.expectEqual(@as(u64, 1), setup.client.counters.tx_stalled);
    try std.testing.expectEqual(@as(usize, 0), setup.client.sessions.rows[client_peer].io.tx.data.count);
    for (setup.client.messages.store.entries) |e| if (e.active) try std.testing.expectEqual(@as(u32, 0), e.tx);
}

test "gossipsub pinned payload pressure resumes held large frame after host report" {
    const constants = @import("constants.zig");
    var setup: GossipPair = .{};
    try setup.initOpts(.{
        .random_seed = 1,
    }, .{ .random_seed = 1, .mcache_arena_bytes = constants.maxCompressedLen(constants.MAX_PAYLOAD_SIZE) + 4096, .large_pool_count = 1 });
    defer setup.deinit();
    try connectMesh(&setup);
    const payload = try std.testing.allocator.alloc(u8, constants.MAX_PAYLOAD_SIZE);
    defer std.testing.allocator.free(payload);
    var rng = std.Random.DefaultPrng.init(97);
    rng.random().bytes(payload);
    _ = try setup.client.publish(test_topic, payload, setup.pair.now);
    var handle: ?gossipsub.ValidationHandle = null;
    for (0..2000) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| if (event == .message) {
            handle = event.message.handle;
        };
        if (handle != null) break;
    }
    try std.testing.expect(handle != null);
    _ = try setup.client.publish(test_topic, payload[0 .. 3 * 1024 * 1024], setup.pair.now);
    const peer = setup.server.sessions.findPeer(setup.handles.server).?;
    for (0..2000) |_| {
        try setup.pumpOnce();
        if (setup.server.sessions.rows[peer].io.blocked == .storage) break;
    }
    try std.testing.expectEqual(.storage, setup.server.sessions.rows[peer].io.blocked);
    try std.testing.expect(setup.server.sessions.rows[peer].io.large_slot != null);
    try std.testing.expect(@import("test_support.zig").driver(&setup.server).nextIoWakeup(setup.pair.now, 16).? > setup.pair.now.mono_ms);
    try std.testing.expectEqual(@as(u64, 1), setup.server.counters.messages_received);
    _ = setup.server.report(handle.?, .ignore, setup.pair.now);
    try std.testing.expectEqual(@as(?u64, setup.pair.now.mono_ms), @import("test_support.zig").driver(&setup.server).nextIoWakeup(setup.pair.now, 16));
    var received = false;
    for (0..20) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| if (event == .message) {
            try std.testing.expectEqualSlices(u8, payload[0 .. 3 * 1024 * 1024], event.message.bytes);
            received = true;
        };
        if (received) break;
    }
    try std.testing.expect(received);
    try std.testing.expect(setup.server.sessions.rows[peer].io.large_slot == null);
    try std.testing.expectEqual(@as(u64, 0), setup.server.counters.local_pressure_resets);
}

test "gossipsub native write credit behind cursor resumes and blocked writes quiesce" {
    var setup: GossipPair = .{};
    try setup.initOpts(.{ .random_seed = 1, .peers_per_pump = 1 }, .{
        .random_seed = 1,
    });
    defer setup.deinit();
    try connectMesh(&setup);
    const index = setup.client.sessions.findPeer(setup.handles.client).?;
    const payload = try std.testing.allocator.alloc(u8, @import("constants.zig").MAX_PAYLOAD_SIZE);
    defer std.testing.allocator.free(payload);
    var rng = std.Random.DefaultPrng.init(112);
    rng.random().bytes(payload);
    _ = try setup.client.publish(test_topic, payload, setup.pair.now);
    var activity: [128]engine_mod.Handle = undefined;
    var events: [16]Event = undefined;
    for (0..512) |_| {
        const active = setup.pair.client.driverView().takeActivity(&activity);
        for (activity[0..active]) |conn| setup.client.sessions.connectionActivity(conn);
        if (@import("test_support.zig").driver(&setup.client).nextIoWakeup(setup.pair.now, 16).? > setup.pair.now.mono_ms) break;
        _ = @import("test_support.zig").pump(&setup.client, &setup.pair.client, setup.pair.now, &events);
        try setup.pair.pump();
    }
    const io = &setup.client.sessions.rows[index].io;
    try std.testing.expect(io.tx.data.count > 0);
    try std.testing.expect(!io.tx.ready);
    try std.testing.expect(@import("test_support.zig").driver(&setup.client).nextIoWakeup(setup.pair.now, 16).? > setup.pair.now.mono_ms);
    const before = io.tx.data.first().?.page.remaining;
    const extra = @import("test_support.zig").addPeer(&setup.client, .{ .index = 77, .generation = 1 }, .v1_2).?;
    setup.client.sessions.cursor = extra.index;
    setup.server.sessions.connectionActivity(setup.handles.server);
    for (0..32) |_| {
        _ = @import("test_support.zig").pump(&setup.server, &setup.pair.server, setup.pair.now, &events);
        try setup.pair.pump();
    }
    const active = setup.pair.client.driverView().takeActivity(&activity);
    try std.testing.expect(active > 0);
    for (activity[0..active]) |conn| setup.client.sessions.connectionActivity(conn);
    _ = @import("test_support.zig").pump(&setup.client, &setup.pair.client, setup.pair.now, &events);
    try std.testing.expectEqual(@as(?u64, setup.pair.now.mono_ms), @import("test_support.zig").driver(&setup.client).nextIoWakeup(setup.pair.now, 16));
    _ = @import("test_support.zig").pump(&setup.client, &setup.pair.client, setup.pair.now, &events);
    try std.testing.expect(io.tx.data.first().?.page.remaining < before);
    setup.client.connectionClosed(setup.handles.client);
    try std.testing.expectEqual(@as(usize, 0), io.tx.data.count);
    for (setup.client.messages.store.entries) |entry| if (entry.active) try std.testing.expectEqual(@as(u32, 0), entry.tx);
}

test "gossipsub healthy continuous frame turnover does not expire a nonempty queue" {
    var setup: GossipPair = .{};
    try setup.initOpts(.{ .random_seed = 1, .calls_per_peer = 3, .tx_timeout_ms = 500 }, .{
        .random_seed = 1,
    });
    defer setup.deinit();
    try connectMesh(&setup);
    const index = setup.client.sessions.findPeer(setup.handles.client).?;
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, 0, .little);
    _ = try setup.client.publish(test_topic, &bytes, setup.pair.now);
    std.mem.writeInt(u64, &bytes, 1, .little);
    _ = try setup.client.publish(test_topic, &bytes, setup.pair.now);
    const began = setup.pair.now.mono_ms;
    for (2..34) |i| {
        try setup.pumpOnce();
        try std.testing.expect(setup.client.sessions.rows[index].io.tx.pending());
        try std.testing.expect(setup.client.sessions.rows[index].io.tx.data.count > 0);
        setup.pair.advance(25);
        std.mem.writeInt(u64, &bytes, i, .little);
        const result = try setup.client.publish(test_topic, &bytes, setup.pair.now);
        try std.testing.expectEqual(@as(u16, 1), result.queued);
    }
    try std.testing.expect(setup.pair.now.mono_ms - began > 500);
    try std.testing.expectEqual(@as(u64, 0), setup.client.counters.tx_stalled);
    try std.testing.expect(setup.client.sessions.outStream(index) != null);
}

test "gossipsub temporary frame pool pressure preserves prefix unread bytes and resumes" {
    var setup: GossipPair = .{};
    try setup.initOpts(.{
        .random_seed = 1,
    }, .{ .random_seed = 1, .large_pool_count = 1, .body_buffer_bytes = 1024 });
    defer setup.deinit();
    try connectMesh(&setup);
    const owner_conn: engine_mod.Handle = .{ .index = 77, .generation = 1 };
    const owner = @import("test_support.zig").addPeer(&setup.server, owner_conn, .v1_2).?;
    setup.server.sessions.rows[owner.index].io.large_slot = setup.server.sessions.receive_pool.claim().?;
    var payload: [65536]u8 = undefined;
    var rng = std.Random.DefaultPrng.init(113);
    rng.random().bytes(&payload);
    _ = try setup.client.publish(test_topic, &payload, setup.pair.now);
    const peer = setup.server.sessions.findPeer(setup.handles.server).?;
    for (0..64) |_| {
        try setup.pumpOnce();
        if (setup.server.sessions.rows[peer].io.blocked == .storage) break;
    }
    try std.testing.expectEqual(.storage, setup.server.sessions.rows[peer].io.blocked);
    try std.testing.expect(setup.server.sessions.rows[peer].io.reader.declaredLen() != null);
    try std.testing.expectEqual(@as(u64, 0), setup.server.counters.messages_received);
    try std.testing.expect(@import("test_support.zig").driver(&setup.server).nextIoWakeup(setup.pair.now, 16).? > setup.pair.now.mono_ms);
    setup.server.connectionClosed(owner_conn);
    try std.testing.expectEqual(@as(?u64, setup.pair.now.mono_ms), @import("test_support.zig").driver(&setup.server).nextIoWakeup(setup.pair.now, 16));
    var received = false;
    for (0..64) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| if (event == .message) {
            try std.testing.expectEqualSlices(u8, &payload, event.message.bytes);
            received = true;
        };
        if (received) break;
    }
    try std.testing.expect(received);
    try std.testing.expectEqual(@as(usize, 1), setup.server.sessions.receive_pool.available());
}
