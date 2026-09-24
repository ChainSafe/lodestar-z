const gossip_test = @import("test_support.zig");
const std = @import("std");
const gossipsub = @import("gossipsub.zig");
const topic_mod = @import("topic.zig");
const engine_mod = @import("../quic/engine.zig");

const Gossipsub = gossipsub.Gossipsub;

const digest = topic_mod.ForkDigest{ 0x6a, 0x95, 0xa1, 0xa9 };

const Pair = @import("test_pair.zig").Pair;

fn buildTopic(name: []const u8, out: []u8) []const u8 {
    return topic_mod.build(digest, name, out);
}

test "gossipsub peers exchange subscriptions over the mesh streams" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();

    var buf: [topic_mod.topic_max_len]u8 = undefined;
    const beacon_block = buildTopic("beacon_block", &buf);
    try gossip_test.subscribe(setup.shared.client.gossipsub, beacon_block);
    try gossip_test.subscribe(setup.shared.server.gossipsub, beacon_block);

    var rounds: usize = 0;
    while (rounds < 20) : (rounds += 1) {
        try setup.pumpOnce();
    }

    // each side now records the other as a subscriber of the topic
    const server_topic = setup.shared.server.gossipsub.overlay.findTopic(beacon_block).?;
    try std.testing.expect(setup.shared.server.gossipsub.overlay.subscribers(server_topic).count() == 1);
}

test "gossipsub forms a mesh through the heartbeat" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();

    var buf: [topic_mod.topic_max_len]u8 = undefined;
    const beacon_block = buildTopic("beacon_block", &buf);
    try gossip_test.subscribe(setup.shared.client.gossipsub, beacon_block);
    try gossip_test.subscribe(setup.shared.server.gossipsub, beacon_block);

    var rounds: usize = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();
    setup.shared.pair.advance(constants_heartbeat + 100);
    rounds = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();

    const client_topic = setup.shared.client.gossipsub.overlay.findTopic(beacon_block).?;
    const server_topic = setup.shared.server.gossipsub.overlay.findTopic(beacon_block).?;
    try std.testing.expectEqual(@as(usize, 1), setup.shared.client.gossipsub.overlay.mesh(client_topic).count());
    try std.testing.expectEqual(@as(usize, 1), setup.shared.server.gossipsub.overlay.mesh(server_topic).count());
}

test "gossipsub delivers a published message to a mesh peer" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();

    var buf: [topic_mod.topic_max_len]u8 = undefined;
    const beacon_block = buildTopic("beacon_block", &buf);
    try gossip_test.subscribe(setup.shared.client.gossipsub, beacon_block);
    try gossip_test.subscribe(setup.shared.server.gossipsub, beacon_block);

    var rounds: usize = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();
    setup.shared.pair.advance(constants_heartbeat + 100);
    rounds = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();

    const payload = "a signed beacon block payload for the mesh";
    _ = try setup.shared.client.gossipsub.publish(beacon_block, payload, setup.shared.pair.now);

    var received = false;
    rounds = 0;
    while (rounds < 20 and !received) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverMessages()) |m| {
            try std.testing.expectEqualStrings(beacon_block, m.topic);
            try std.testing.expectEqualStrings(payload, m.bytes);
            _ = setup.shared.server.gossipsub.report(m.handle, .accept, setup.shared.pair.now);
            received = true;
        }
    }
    try std.testing.expect(received);
    try std.testing.expectEqual(@as(u64, 1), setup.shared.server.gossipsub.counters.messages_received);
    try std.testing.expectEqual(@as(u64, 1), setup.shared.client.gossipsub.counters.messages_published);
}

test "gossipsub prunes a peer whose messages are rejected" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();

    var buf: [topic_mod.topic_max_len]u8 = undefined;
    const beacon_block = buildTopic("beacon_block", &buf);
    try gossip_test.subscribe(setup.shared.client.gossipsub, beacon_block);
    try gossip_test.subscribe(setup.shared.server.gossipsub, beacon_block);

    var rounds: usize = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();
    setup.shared.pair.advance(constants_heartbeat + 100);
    rounds = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();

    // the client publishes, the server rejects it as invalid
    _ = try setup.shared.client.gossipsub.publish(beacon_block, "an invalid block", setup.shared.pair.now);
    rounds = 0;
    var rejected = false;
    while (rounds < 20 and !rejected) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverMessages()) |m| {
            _ = setup.shared.server.gossipsub.report(m.handle, .reject, setup.shared.pair.now);
            rejected = true;
        }
    }
    try std.testing.expect(rejected);

    // the server's score for the client is now negative and the heartbeat prunes it
    const client_index = setup.shared.server.gossipsub.sessions.findPeer(setup.shared.handles.server).?;
    try std.testing.expect(setup.shared.server.gossipsub.peers.score(.{ .index = client_index, .generation = setup.shared.server.gossipsub.peers.rows[client_index].generation }, setup.shared.pair.now.mono_ms) < 0);
    setup.shared.pair.advance(constants_heartbeat + 100);
    rounds = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();
    const server_topic = setup.shared.server.gossipsub.overlay.findTopic(beacon_block).?;
    try std.testing.expectEqual(@as(usize, 0), setup.shared.server.gossipsub.overlay.mesh(server_topic).count());
}

test "gossipsub credits first delivery only after the host accepts" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();

    var buf: [topic_mod.topic_max_len]u8 = undefined;
    const beacon_block = buildTopic("beacon_block", &buf);
    try gossip_test.subscribe(setup.shared.client.gossipsub, beacon_block);
    try gossip_test.subscribe(setup.shared.server.gossipsub, beacon_block);

    var rounds: usize = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();
    setup.shared.pair.advance(constants_heartbeat + 100);
    rounds = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();

    _ = try setup.shared.client.gossipsub.publish(beacon_block, "a beacon block payload", setup.shared.pair.now);
    var handle: ?gossipsub.ValidationHandle = null;
    rounds = 0;
    while (rounds < 20 and handle == null) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverMessages()) |m| handle = m.handle;
    }
    try std.testing.expect(handle != null);

    // receiving the message must not credit the sender; only the host's accept does
    const client_index = setup.shared.server.gossipsub.sessions.findPeer(setup.shared.handles.server).?;
    const before = setup.shared.server.gossipsub.peers.score(.{ .index = client_index, .generation = setup.shared.server.gossipsub.peers.rows[client_index].generation }, setup.shared.pair.now.mono_ms);
    _ = setup.shared.server.gossipsub.report(handle.?, .accept, setup.shared.pair.now);
    const after = setup.shared.server.gossipsub.peers.score(.{ .index = client_index, .generation = setup.shared.server.gossipsub.peers.rows[client_index].generation }, setup.shared.pair.now.mono_ms);
    try std.testing.expect(after > before);
}

test "gossipsub receives a message larger than the per-peer body buffer" {
    var setup: Pair = .{};
    // the server holds a tiny per-peer body buffer, so the message must be read
    // through a claimed large-pool buffer instead
    try setup.initOpts(.{
        .random_seed = 1,
    }, .{ .random_seed = 1, .body_buffer_bytes = 1024 });
    defer setup.deinit();

    var buf: [topic_mod.topic_max_len]u8 = undefined;
    const beacon_block = buildTopic("beacon_block", &buf);
    try gossip_test.subscribe(setup.shared.client.gossipsub, beacon_block);
    try gossip_test.subscribe(setup.shared.server.gossipsub, beacon_block);

    var rounds: usize = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();
    setup.shared.pair.advance(constants_heartbeat + 100);
    rounds = 0;
    while (rounds < 10) : (rounds += 1) try setup.pumpOnce();

    // a poorly-compressible 8 KB payload: its compressed frame exceeds 1 KB
    var payload: [8192]u8 = undefined;
    for (&payload, 0..) |*byte, i| byte.* = @intCast((i * 131 + 7) & 0xff);
    _ = try setup.shared.client.gossipsub.publish(beacon_block, &payload, setup.shared.pair.now);

    var received = false;
    rounds = 0;
    while (rounds < 20 and !received) : (rounds += 1) {
        try setup.pumpOnce();
        for (setup.serverMessages()) |m| {
            try std.testing.expectEqualSlices(u8, &payload, m.bytes);
            _ = setup.shared.server.gossipsub.report(m.handle, .accept, setup.shared.pair.now);
            received = true;
        }
    }
    try std.testing.expect(received);
}

const constants_heartbeat = @import("constants.zig").heartbeat_interval_ms;

fn expectControlFloodBounded(control_tag: u8) !void {
    var setup: Pair = .{};
    try setup.initOpts(.{
        .random_seed = 1,
    }, .{ .random_seed = 1, .items_per_peer = 4096, .items_per_pump = 8192 });
    defer setup.deinit();
    for (0..20) |_| try setup.pumpOnce();
    const peer = setup.shared.server.gossipsub.sessions.findPeer(setup.shared.handles.server).?;
    const before = setup.shared.server.gossipsub.counters.rpcs_received;
    const item: std.meta.Tag(@import("protobuf.zig").Item) = if (control_tag == 0x0a) .ihave else .idontwant;
    const items_before = setup.shared.server.gossipsub.rpc_metrics.items[@intFromEnum(item)];
    const now = setup.shared.pair.now.mono_ms;
    const controls_per_rpc = 4096;
    const io = &setup.shared.server.gossipsub.sessions.rows[peer].io;
    var rpc: [5 * controls_per_rpc + 8]u8 = undefined;
    var writer = @import("protobuf.zig").Writer.init(&rpc);
    writer.tag(3, 2);
    writer.varint(controls_per_rpc * @as(usize, if (control_tag == 0x0a) 5 else 2));
    for (0..controls_per_rpc) |_| {
        writer.bytes(&.{ control_tag, if (control_tag == 0x0a) 3 else 0 });
        if (control_tag == 0x0a) writer.bytesField(1, "t");
    }
    var framed: [rpc.len + 8]u8 = undefined;
    const wire = @import("frame.zig").writeFrame(&framed, writer.written());
    for (0..17) |rpc_index| {
        var sent: usize = 0;
        for (0..controls_per_rpc + 4) |_| {
            if (sent < wire.len) sent += setup.shared.pair.client.write(setup.clientStream(), wire[sent..], false) catch |err| switch (err) {
                error.WouldBlock => 0,
                else => return err,
            };
            try setup.pumpOnce();
            if (setup.shared.server.gossipsub.counters.rpcs_received == before + rpc_index + 1 and io.rpc == null) break;
        }
        try std.testing.expectEqual(wire.len, sent);
        try std.testing.expectEqual(before + rpc_index + 1, setup.shared.server.gossipsub.counters.rpcs_received);
        try std.testing.expect(io.rpc == null);
        try std.testing.expectEqual(items_before + (rpc_index + 1) * controls_per_rpc, setup.shared.server.gossipsub.rpc_metrics.items[@intFromEnum(item)]);
        try std.testing.expectEqual(now, setup.shared.pair.now.mono_ms);
    }
    try std.testing.expectEqual(before + 17, setup.shared.server.gossipsub.counters.rpcs_received);
    const count = if (control_tag == 0x0a)
        setup.shared.server.gossipsub.sessions.rows[peer].io.ihave_recv
    else
        setup.shared.server.gossipsub.sessions.rows[peer].io.idontwant_recv;
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
        var setup: Pair = .{};
        try setup.initOpts(
            .{ .random_seed = 1, .message_id_policy = vector.policy },
            .{ .random_seed = 1, .message_id_policy = vector.policy },
        );
        defer setup.deinit();
        const topic = "/eth2/01020304/beacon_block/ssz_snappy";
        try gossip_test.subscribe(setup.shared.client.gossipsub, topic);
        try gossip_test.subscribe(setup.shared.server.gossipsub, topic);
        for (0..20) |_| try setup.pumpOnce();
        setup.shared.pair.advance(constants_heartbeat + 100);
        for (0..10) |_| try setup.pumpOnce();
        _ = try setup.shared.client.gossipsub.publish(topic, "hello", setup.shared.pair.now);
        const valid = idFromHex(vector.valid);
        try std.testing.expect(setup.shared.client.gossipsub.messages.seen.contains(valid, setup.shared.pair.now.mono_ms));
        var received = false;
        for (0..20) |_| {
            try setup.pumpOnce();
            for (setup.serverMessages()) |message| {
                try std.testing.expectEqual(valid, message.id);
                received = true;
            }
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
                try setup.shared.pair.client.write(setup.clientStream(), wire, false),
            );
            for (0..4) |_| try setup.pumpOnce();
            try std.testing.expect(setup.shared.server.gossipsub.messages.seen.contains(idFromHex(expected), setup.shared.pair.now.mono_ms));
        }
    }
}

test "gossipsub queues incompressible 64 KiB publish" {
    var g = try gossip_test.init(std.testing.allocator, .{
        .random_seed = 1,
    });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try gossip_test.subscribe(&g, topic);
    g.overlay.rows[g.overlay.findTopic(topic).?].mesh.set(peer.index);
    var payload: [65536]u8 = undefined;
    var rng = std.Random.DefaultPrng.init(42);
    rng.random().bytes(&payload);
    _ = try g.publish(topic, &payload, .{ .mono_ms = 1, .unix_s = 1 });
    try std.testing.expectEqual(@as(u64, 0), g.counters.send_dropped);
}

const test_topic = "/eth2/01020304/beacon_block/ssz_snappy";

fn connectMesh(setup: *Pair) !void {
    try gossip_test.subscribe(setup.shared.client.gossipsub, test_topic);
    try gossip_test.subscribe(setup.shared.server.gossipsub, test_topic);
    for (0..20) |_| try setup.pumpOnce();
    setup.shared.pair.advance(constants_heartbeat + 1);
    for (0..20) |_| try setup.pumpOnce();
}

fn publishAdmissionA(setup: *Pair) !struct { count: usize, handle: ?gossipsub.ValidationHandle } {
    setup.shared.pair.advance(1);
    const queued = try setup.shared.client.gossipsub.publish(test_topic, "A", setup.shared.pair.now);
    try std.testing.expectEqual(@as(u16, 1), queued.queued);
    var count: usize = 0;
    var handle: ?gossipsub.ValidationHandle = null;
    for (0..20) |_| {
        try setup.pumpOnce();
        for (setup.serverMessages()) |message| {
            try std.testing.expectEqualStrings("A", message.bytes);
            count += 1;
            handle = message.handle;
        }
    }
    return .{ .count = count, .handle = handle };
}

test "gossipsub readmission reuses tombstones across repeated Seen eviction" {
    var setup: Pair = .{};
    try setup.initOpts(.{
        .random_seed = 1,
        .seen_ttl_ms = 1,
    }, .{ .random_seed = 1, .seen_capacity = 1, .validation_capacity = 4, .mcache_capacity = 1 });
    defer setup.deinit();
    try connectMesh(&setup);
    const first = try publishAdmissionA(&setup);
    try std.testing.expectEqual(@as(usize, 1), first.count);
    const old = first.handle.?;
    try std.testing.expectEqual(gossipsub.ReportOutcome{ .applied = .ignore }, setup.shared.server.gossipsub.report(old, .ignore, setup.shared.pair.now));
    try std.testing.expectEqual(@as(usize, 0), setup.shared.server.gossipsub.messages.store.used_entries);
    _ = try setup.shared.server.gossipsub.publish(test_topic, "B", setup.shared.pair.now);
    const second = try publishAdmissionA(&setup);
    try std.testing.expectEqual(@as(usize, 1), second.count);
    const current = second.handle.?;
    const retained = setup.shared.server.gossipsub.messages.validation.entries[current.index].state.pending.message;
    const id = topic_mod.validMessageId(test_topic, "A", .{});
    for (0..8) |i| {
        const payload = [_]u8{@as(u8, @intCast(i)) + 'C'};
        _ = try setup.shared.server.gossipsub.publish(test_topic, &payload, setup.shared.pair.now);
        try std.testing.expect(!setup.shared.server.gossipsub.messages.seen.contains(id, setup.shared.pair.now.mono_ms));
        const duplicates_before = setup.shared.server.gossipsub.counters.duplicates;
        const duplicate = try publishAdmissionA(&setup);
        try std.testing.expectEqual(@as(usize, 0), duplicate.count);
        try std.testing.expectEqual(duplicates_before + 1, setup.shared.server.gossipsub.counters.duplicates);
        var pending: usize = 0;
        for (setup.shared.server.gossipsub.messages.validation.recent) |entry| {
            if (entry.state == .pending and std.mem.eql(u8, &entry.id, &id)) pending += 1;
        }
        try std.testing.expectEqual(@as(usize, 1), pending);
        try std.testing.expectEqual(@as(usize, 2), setup.shared.server.gossipsub.messages.store.used_entries);
        try std.testing.expect(setup.shared.server.gossipsub.messages.store.get(retained).?.validation);
    }
    try std.testing.expectEqual(old.index, current.index);
    try std.testing.expectEqual(old.generation + 1, current.generation);
    try std.testing.expectEqual(gossipsub.ReportOutcome.stale_handle, setup.shared.server.gossipsub.report(old, .accept, setup.shared.pair.now));
    try std.testing.expectEqual(gossipsub.ReportOutcome{ .applied = .ignore }, setup.shared.server.gossipsub.report(current, .ignore, setup.shared.pair.now));
    try std.testing.expectEqual(gossipsub.ReportOutcome.already_resolved, setup.shared.server.gossipsub.report(current, .accept, setup.shared.pair.now));
    try std.testing.expect(setup.shared.server.gossipsub.messages.store.get(retained) == null);
    try std.testing.expectEqual(@as(usize, 1), setup.shared.server.gossipsub.messages.store.used_entries);
    for (0..@import("constants.zig").mcache_len) |_| @import("test_support.zig").ageHistory(setup.shared.server.gossipsub);
    try std.testing.expectEqual(@as(usize, 0), setup.shared.server.gossipsub.messages.store.used_entries);
    try std.testing.expectEqual(setup.shared.server.gossipsub.messages.store.next.len, setup.shared.server.gossipsub.messages.store.free_pages);
}

test "gossipsub legal maximum and above two MiB publish use actual resumable IO" {
    const sizes = [_]usize{ 65536, 2 * 1024 * 1024 + 1, @import("constants.zig").MAX_PAYLOAD_SIZE };
    for (sizes) |size| {
        var setup: Pair = .{};
        try setup.init();
        defer setup.deinit();
        try connectMesh(&setup);
        const payload = try std.testing.allocator.alloc(u8, size);
        defer std.testing.allocator.free(payload);
        var rng = std.Random.DefaultPrng.init(42);
        rng.random().bytes(payload);
        const outcome = try setup.shared.client.gossipsub.publish(test_topic, payload, setup.shared.pair.now);
        try std.testing.expectEqual(@as(u16, 1), outcome.queued);
        try std.testing.expectEqual(@as(u16, 0), outcome.pressured);
        var received = false;
        for (0..2000) |_| {
            try setup.pumpOnce();
            for (setup.serverMessages()) |message| {
                try std.testing.expectEqualSlices(u8, payload, message.bytes);
                try std.testing.expectEqual(gossipsub.ReportOutcome{ .applied = .accept }, setup.shared.server.gossipsub.report(message.handle, .accept, setup.shared.pair.now));
                received = true;
            }
            if (received) break;
        }
        try std.testing.expect(received);
        try std.testing.expectEqual(@as(u64, 0), setup.shared.client.gossipsub.counters.send_dropped);
        try std.testing.expectEqual(setup.shared.server.gossipsub.sessions.receive_pool.next.len, setup.shared.server.gossipsub.sessions.receive_pool.free_pages);
    }
}

test "gossipsub legal maximum IWANT response uses actual IO without mesh publish" {
    var setup: Pair = .{};
    try setup.init();
    defer setup.deinit();
    try gossip_test.subscribe(setup.shared.server.gossipsub, test_topic);
    try gossip_test.subscribe(setup.shared.client.gossipsub, test_topic);
    for (0..20) |_| try setup.pumpOnce();
    const payload = try std.testing.allocator.alloc(u8, @import("constants.zig").MAX_PAYLOAD_SIZE);
    defer std.testing.allocator.free(payload);
    var rng = std.Random.DefaultPrng.init(73);
    rng.random().bytes(payload);
    const destination = setup.shared.client.gossipsub.sessions.findPeer(setup.shared.handles.client).?;
    _ = setup.shared.client.gossipsub.overlay.peerSubscription(&setup.shared.client.gossipsub.overlayContext(setup.shared.client.gossipsub.last_now_ms), destination, test_topic, false);
    const result = try setup.shared.client.gossipsub.publish(test_topic, payload, setup.shared.pair.now);
    try std.testing.expectEqual(@as(u16, 0), result.queued);
    _ = setup.shared.client.gossipsub.overlay.peerSubscription(&setup.shared.client.gossipsub.overlayContext(setup.shared.client.gossipsub.last_now_ms), destination, test_topic, true);
    const id = topic_mod.validMessageId(test_topic, payload, .{});
    const pb = @import("protobuf.zig");
    var buf: [64]u8 = undefined;
    var w = pb.Writer.init(&buf);
    w.varint(pb.iwantRpcSize(1, 20));
    pb.beginIwantRpc(&w, 1, 20);
    pb.writeIwantId(&w, &id);
    try std.testing.expectEqual(w.len, try setup.shared.pair.server.write(setup.serverStream(), w.written(), false));
    var received = false;
    for (0..2000) |_| {
        try setup.pumpOnce();
        for (setup.serverMessages()) |message| {
            try std.testing.expectEqualSlices(u8, payload, message.bytes);
            received = true;
        }
        if (received) break;
    }
    try std.testing.expect(received);
    const cached = setup.shared.client.gossipsub.messages.history.get(&setup.shared.client.gossipsub.messages.store, id).?;
    try std.testing.expectEqual(@as(u8, 1), setup.shared.client.gossipsub.messages.history.countsRow(cached)[0]);
}

test "gossipsub subscription cursors synchronize all topics through small critical queues" {
    const topic_capacity = @import("constants.zig").topics_cap;
    const topics = &@import("topic_fixture.zig").churn;
    var setup: Pair = .{};
    try setup.initOpts(.{ .random_seed = 1, .topic_policy = topics, .critical_bytes = 256, .control_bytes = 64 }, .{ .random_seed = 1, .topic_policy = topics, .critical_bytes = 256, .control_bytes = 64 });
    defer setup.deinit();
    var buf: [topic_mod.topic_max_len]u8 = undefined;
    for (0..topic_capacity) |i| {
        const topic = try @import("topic_fixture.zig").churnTopic(i, &buf);
        try gossip_test.subscribe(setup.shared.client.gossipsub, topic);
        try gossip_test.subscribe(setup.shared.server.gossipsub, topic);
    }
    for (0..128) |_| try setup.pumpOnce();
    const peer = setup.shared.client.gossipsub.sessions.findPeer(setup.shared.handles.client).?;
    @import("session_io.zig").resetOutbound(setup.shared.client.gossipsub, &setup.shared.pair.client, peer);
    setup.shared.client.gossipsub.sessions.setOutbound(peer, .pending);
    for (0..128) |_| try setup.pumpOnce();
    for (0..8) |_| try setup.pumpOnce();
    try std.testing.expect(@import("session_io.zig").nextIoWakeup(setup.shared.client.gossipsub, setup.shared.pair.now).? > setup.shared.pair.now.mono_ms);
}

test "gossipsub activity behind partial peer cursor remains ready and generation checked" {
    var setup: Pair = .{};
    try setup.initOpts(.{
        .random_seed = 1,
    }, .{ .random_seed = 1, .peers_per_pump = 1 });
    defer setup.deinit();
    try connectMesh(&setup);
    const real_peer = setup.shared.server.gossipsub.sessions.findPeer(setup.shared.handles.server).?;
    const extra = @import("test_support.zig").addPeer(setup.shared.server.gossipsub, .{ .index = 77, .generation = 9 }, .v1_2).?;
    setup.shared.server.gossipsub.sessions.cursor = extra.index;
    const pb = @import("protobuf.zig");
    var compressed: [64]u8 = undefined;
    const n = try @import("snappy").raw.compress("arrived behind cursor", &compressed);
    var body: [256]u8 = undefined;
    var w = pb.Writer.init(&body);
    pb.writeMessage(&w, compressed[0..n], test_topic);
    var frame: [258]u8 = undefined;
    const wire = @import("frame.zig").writeFrame(&frame, w.written());
    try std.testing.expectEqual(wire.len, try setup.shared.pair.client.write(setup.clientStream(), wire, false));
    try setup.shared.pair.pump();
    var activity: [128]engine_mod.Handle = undefined;
    const active = setup.shared.pair.activity(&setup.shared.pair.server, &activity);
    try std.testing.expect(active > 0);
    for (activity[0..active]) |conn| setup.shared.server.gossipsub.sessions.connectionActivity(conn);
    try std.testing.expectEqual(@as(usize, 0), @import("test_support.zig").pump(setup.shared.server.gossipsub, &setup.shared.pair.server, setup.shared.pair.now));
    try std.testing.expectEqual(@as(?u64, setup.shared.pair.now.mono_ms), @import("session_io.zig").nextIoWakeup(setup.shared.server.gossipsub, setup.shared.pair.now));
    try std.testing.expectEqual(@as(usize, 1), @import("test_support.zig").pump(setup.shared.server.gossipsub, &setup.shared.pair.server, setup.shared.pair.now));
    try std.testing.expectEqualStrings("arrived behind cursor", setup.serverMessages()[0].bytes);
    for (0..8) |_| {
        if (@import("session_io.zig").nextIoWakeup(setup.shared.server.gossipsub, setup.shared.pair.now).? > setup.shared.pair.now.mono_ms) break;
        _ = @import("test_support.zig").pump(setup.shared.server.gossipsub, &setup.shared.pair.server, setup.shared.pair.now);
    }
    try std.testing.expect(!setup.shared.server.gossipsub.sessions.rows[real_peer].io.rx_ready);
    setup.shared.server.gossipsub.sessions.connectionActivity(.{ .index = setup.shared.handles.server.index, .generation = setup.shared.handles.server.generation + 1 });
    try std.testing.expect(!setup.shared.server.gossipsub.sessions.rows[real_peer].io.rx_ready);
    try std.testing.expect(@import("session_io.zig").nextIoWakeup(setup.shared.server.gossipsub, setup.shared.pair.now).? > setup.shared.pair.now.mono_ms);
}

test "gossipsub large frame deadline releases receive pages despite byte progress" {
    var setup: Pair = .{};
    try setup.initOpts(.{ .random_seed = 1, .output_per_peer = 1, .tx_timeout_ms = 500 }, .{ .random_seed = 1, .body_buffer_bytes = 64, .large_frame_timeout_ms = 150, .pressure_timeout_ms = 500 });
    defer setup.deinit();
    for (0..16) |_| try setup.pumpOnce();
    const server_peer = setup.shared.server.gossipsub.sessions.findPeer(setup.shared.handles.server).?;
    const client_peer = setup.shared.client.gossipsub.sessions.findPeer(setup.shared.handles.client).?;
    var prefix: [128]u8 = undefined;
    var w = @import("protobuf.zig").Writer.init(&prefix);
    w.varint(65536);
    w.bytes(&([_]u8{'x'} ** 65));
    try std.testing.expectEqual(w.len, try setup.shared.pair.client.write(setup.clientStream(), w.written(), false));
    for (0..4) |_| try setup.pumpOnce();
    try std.testing.expect(setup.shared.server.gossipsub.sessions.rows[server_peer].io.reader.declaredLen() != null);
    try std.testing.expectEqual(@as(u32, 1), setup.shared.server.gossipsub.sessions.rows[server_peer].io.overflow.pages);
    try gossip_test.subscribe(setup.shared.client.gossipsub, test_topic);
    setup.shared.client.gossipsub.overlay.rows[setup.shared.client.gossipsub.overlay.findTopic(test_topic).?].mesh.set(client_peer);
    _ = try setup.shared.client.gossipsub.publish(test_topic, "held transmit payload", setup.shared.pair.now);
    for (0..4) |_| try setup.pumpOnce();
    const began = setup.shared.pair.now.mono_ms;
    for (0..1) |_| {
        setup.shared.pair.advance(100);
        try std.testing.expectEqual(@as(usize, 1), try setup.shared.pair.client.write(setup.clientStream(), "x", false));
        try setup.pumpOnce();
        try std.testing.expect(setup.shared.server.gossipsub.sessions.rows[server_peer].io.reader.declaredLen() != null);
        try std.testing.expect(setup.shared.server.gossipsub.sessions.rows[server_peer].io.progress_ms > began);
    }
    setup.shared.pair.advance(100);
    try setup.pumpOnce();
    try std.testing.expectEqual(@as(u64, 1), setup.shared.server.gossipsub.counters.large_stalled);
    try std.testing.expect(setup.shared.server.gossipsub.sessions.rows[server_peer].io.overflow.pages == 0);
    const logical = setup.shared.server.gossipsub.sessions.rows[server_peer].logical;
    try std.testing.expect(setup.shared.server.gossipsub.peers.rows[logical.index].large_frame_denied_until > setup.shared.pair.now.mono_ms);
    setup.shared.pair.advance(300);
    try setup.pumpOnce();
    try std.testing.expectEqual(@as(usize, 0), setup.shared.client.gossipsub.sessions.rows[client_peer].io.tx.data.count);
    for (setup.shared.client.gossipsub.messages.store.entries) |e| if (e.active) try std.testing.expectEqual(@as(u32, 0), e.tx);
}

test "gossipsub completed frame expiry releases pages without blaming the peer" {
    var setup: Pair = .{};
    try setup.initOpts(.{ .random_seed = 1 }, .{
        .random_seed = 1,
        .body_buffer_bytes = 64,
        .items_per_peer = 1,
        .large_frame_timeout_ms = 50,
        .pressure_timeout_ms = 100,
    });
    defer setup.deinit();
    try connectMesh(&setup);
    const g = setup.shared.server.gossipsub;
    const index = g.sessions.findPeer(setup.shared.handles.server).?;
    const peer = &g.sessions.rows[index];
    const before = g.peers.score(peer.logical, setup.shared.pair.now.mono_ms);
    var body: [256]u8 = undefined;
    var writer = @import("protobuf.zig").Writer.init(&body);
    @import("protobuf.zig").writeSubscription(&writer, true, test_topic);
    @import("protobuf.zig").writeSubscription(&writer, false, test_topic);
    var frame: [260]u8 = undefined;
    const wire = @import("frame.zig").writeFrame(&frame, writer.written());
    try std.testing.expectEqual(wire.len, try setup.shared.pair.client.write(setup.clientStream(), wire, false));
    for (0..16) |_| {
        try setup.pumpOnce();
        if (peer.io.rpc != null) break;
    }
    try std.testing.expect(peer.io.rpc != null);
    try std.testing.expectEqual(@as(u32, 1), peer.io.overflow.pages);
    const began = peer.io.frame_since.?;
    try std.testing.expectEqual(@as(?u64, began + 100), peer.io.deadlines(&g.options).values[@intFromEnum(@import("peer_io.zig").TimeoutReason.receive_frame)]);
    g.recovery.add(&g.peers, @splat(1), peer.logical, peer.conn, 1, began + 1000);
    setup.shared.pair.advance(100);
    try setup.pumpOnce();
    try std.testing.expectEqual(@as(u64, 0), g.counters.local_pressure_resets);
    try std.testing.expectEqual(@as(u64, 1), g.counters.local_pressure_discards);
    try std.testing.expectEqual(@as(u64, 1), g.counters.promises_cancelled_pressure);
    try std.testing.expectEqual(@as(u64, 0), g.counters.large_stalled);
    try std.testing.expectEqual(@as(u64, 0), g.counters.broken_promises);
    try std.testing.expectEqual(before, g.peers.score(peer.logical, setup.shared.pair.now.mono_ms));
    try std.testing.expectEqual(@as(u64, 0), g.peers.rows[peer.logical.index].large_frame_denied_until);
    try std.testing.expectEqual(g.sessions.receive_pool.next.len, g.sessions.receive_pool.free_pages);
    try std.testing.expect(peer.in_stream != null and peer.outStream() != null);
}

test "gossipsub pinned payload pressure drops the publication and releases receive pages" {
    const constants = @import("constants.zig");
    var setup: Pair = .{};
    try setup.initOpts(.{ .random_seed = 1 }, .{ .random_seed = 1, .mcache_arena_bytes = constants.maxCompressedLen(constants.MAX_PAYLOAD_SIZE) + 4096 });
    defer setup.deinit();
    try connectMesh(&setup);
    const payload = try std.testing.allocator.alloc(u8, constants.MAX_PAYLOAD_SIZE);
    defer std.testing.allocator.free(payload);
    var rng = std.Random.DefaultPrng.init(97);
    rng.random().bytes(payload);
    _ = try setup.shared.client.gossipsub.publish(test_topic, payload, setup.shared.pair.now);
    var handle: ?gossipsub.ValidationHandle = null;
    for (0..2000) |_| {
        try setup.pumpOnce();
        for (setup.serverMessages()) |message| {
            handle = message.handle;
        }
        if (handle != null) break;
    }
    try std.testing.expect(handle != null);
    const refused_id = @import("topic.zig").validMessageId(test_topic, payload[0 .. 3 * 1024 * 1024], .{});
    _ = try setup.shared.client.gossipsub.publish(test_topic, payload[0 .. 3 * 1024 * 1024], setup.shared.pair.now);
    const g = setup.shared.server.gossipsub;
    const peer = g.sessions.findPeer(setup.shared.handles.server).?;
    for (0..2000) |_| {
        try setup.pumpOnce();
        if (g.counters.message_capacity_refusals != 0) break;
    }
    try std.testing.expectEqual(@as(u64, 1), g.counters.message_capacity_refusals);
    try std.testing.expectEqual(@as(u64, 1), g.counters.messages_received);
    try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[peer].io.overflow.pages);
    try std.testing.expect(g.sessions.rows[peer].io.rpc == null);
    try std.testing.expect(!g.messages.wasSeen(refused_id, setup.shared.pair.now.mono_ms));
    try std.testing.expectEqual(@as(u64, 0), g.counters.local_pressure_resets);
    _ = g.report(handle.?, .ignore, setup.shared.pair.now);
    payload[0] ^= 1;
    _ = try setup.shared.client.gossipsub.publish(test_topic, payload[0 .. 3 * 1024 * 1024], setup.shared.pair.now);
    var received = false;
    for (0..2000) |_| {
        try setup.pumpOnce();
        for (setup.serverMessages()) |message| {
            try std.testing.expectEqualSlices(u8, payload[0 .. 3 * 1024 * 1024], message.bytes);
            received = true;
        }
        if (received) break;
    }
    try std.testing.expect(received);
}

test "gossipsub native write credit behind cursor resumes and blocked writes quiesce" {
    var setup: Pair = .{};
    try setup.initOpts(.{ .random_seed = 1, .peers_per_pump = 1 }, .{
        .random_seed = 1,
    });
    defer setup.deinit();
    try connectMesh(&setup);
    const index = setup.shared.client.gossipsub.sessions.findPeer(setup.shared.handles.client).?;
    const payload = try std.testing.allocator.alloc(u8, @import("constants.zig").MAX_PAYLOAD_SIZE);
    defer std.testing.allocator.free(payload);
    var rng = std.Random.DefaultPrng.init(112);
    rng.random().bytes(payload);
    _ = try setup.shared.client.gossipsub.publish(test_topic, payload, setup.shared.pair.now);
    var activity: [128]engine_mod.Handle = undefined;
    for (0..512) |_| {
        const active = setup.shared.pair.activity(&setup.shared.pair.client, &activity);
        for (activity[0..active]) |conn| setup.shared.client.gossipsub.sessions.connectionActivity(conn);
        if (@import("session_io.zig").nextIoWakeup(setup.shared.client.gossipsub, setup.shared.pair.now).? > setup.shared.pair.now.mono_ms) break;
        _ = @import("test_support.zig").pump(setup.shared.client.gossipsub, &setup.shared.pair.client, setup.shared.pair.now);
        try setup.shared.pair.pump();
    }
    const io = &setup.shared.client.gossipsub.sessions.rows[index].io;
    try std.testing.expect(io.tx.data.count > 0);
    try std.testing.expect(!io.tx.ready);
    try std.testing.expect(io.write_would_block + io.write_zero > 0);
    try std.testing.expect(setup.shared.client.gossipsub.io_metrics.write_would_block + setup.shared.client.gossipsub.io_metrics.write_zero > 0);
    try std.testing.expect(@import("session_io.zig").nextIoWakeup(setup.shared.client.gossipsub, setup.shared.pair.now).? > setup.shared.pair.now.mono_ms);
    const before = io.tx.data.first().?.page.remaining;
    const extra = @import("test_support.zig").addPeer(setup.shared.client.gossipsub, .{ .index = 77, .generation = 1 }, .v1_2).?;
    setup.shared.client.gossipsub.sessions.cursor = extra.index;
    setup.shared.server.gossipsub.sessions.connectionActivity(setup.shared.handles.server);
    for (0..32) |_| {
        _ = @import("test_support.zig").pump(setup.shared.server.gossipsub, &setup.shared.pair.server, setup.shared.pair.now);
        try setup.shared.pair.pump();
    }
    const active = setup.shared.pair.activity(&setup.shared.pair.client, &activity);
    try std.testing.expect(active > 0);
    for (activity[0..active]) |conn| setup.shared.client.gossipsub.sessions.connectionActivity(conn);
    _ = @import("test_support.zig").pump(setup.shared.client.gossipsub, &setup.shared.pair.client, setup.shared.pair.now);
    try std.testing.expectEqual(@as(?u64, setup.shared.pair.now.mono_ms), @import("session_io.zig").nextIoWakeup(setup.shared.client.gossipsub, setup.shared.pair.now));
    _ = @import("test_support.zig").pump(setup.shared.client.gossipsub, &setup.shared.pair.client, setup.shared.pair.now);
    try std.testing.expect(io.tx.data.first().?.page.remaining < before);
    setup.shared.client.gossipsub.connectionClosed(setup.shared.handles.client);
    try std.testing.expectEqual(@as(usize, 0), io.tx.data.count);
    for (setup.shared.client.gossipsub.messages.store.entries) |entry| if (entry.active) try std.testing.expectEqual(@as(u32, 0), entry.tx);
}

test "gossipsub healthy continuous frame turnover does not expire a nonempty queue" {
    var setup: Pair = .{};
    try setup.initOpts(.{ .random_seed = 1, .calls_per_peer = 3, .tx_timeout_ms = 500 }, .{
        .random_seed = 1,
    });
    defer setup.deinit();
    try connectMesh(&setup);
    const index = setup.shared.client.gossipsub.sessions.findPeer(setup.shared.handles.client).?;
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, 0, .little);
    _ = try setup.shared.client.gossipsub.publish(test_topic, &bytes, setup.shared.pair.now);
    std.mem.writeInt(u64, &bytes, 1, .little);
    _ = try setup.shared.client.gossipsub.publish(test_topic, &bytes, setup.shared.pair.now);
    const began = setup.shared.pair.now.mono_ms;
    for (2..34) |i| {
        try setup.pumpOnce();
        try std.testing.expect(setup.shared.client.gossipsub.sessions.rows[index].io.tx.pending());
        try std.testing.expect(setup.shared.client.gossipsub.sessions.rows[index].io.tx.data.count > 0);
        setup.shared.pair.advance(25);
        std.mem.writeInt(u64, &bytes, i, .little);
        const result = try setup.shared.client.gossipsub.publish(test_topic, &bytes, setup.shared.pair.now);
        try std.testing.expectEqual(@as(u16, 1), result.queued);
    }
    try std.testing.expect(setup.shared.pair.now.mono_ms - began > 500);
    try std.testing.expectEqual(@as(u64, 0), setup.shared.client.gossipsub.counters.tx_stalled);
    try std.testing.expect(setup.shared.client.gossipsub.sessions.outStream(index) != null);
}

test "gossipsub receive page exhaustion discards only the requesting frame without blame" {
    var setup: Pair = .{};
    try setup.initOpts(.{ .random_seed = 1 }, .{ .random_seed = 1, .body_buffer_bytes = 1024 });
    defer setup.deinit();
    try connectMesh(&setup);
    const g = setup.shared.server.gossipsub;
    var held: [3]@import("receive_pool.zig").Chain = @splat(.{});
    defer for (&held) |*chain| g.sessions.receive_pool.release(chain);
    for (0..g.sessions.receive_pool.next.len) |i| {
        const chain = &held[i % held.len];
        _ = g.sessions.receive_pool.writable(chain).?;
        chain.len += @import("receive_pool.zig").page_bytes;
    }
    const peer = g.sessions.findPeer(setup.shared.handles.server).?;
    const logical = g.sessions.rows[peer].logical;
    const before = g.peers.score(logical, setup.shared.pair.now.mono_ms);
    var payload: [65536]u8 = undefined;
    var rng = std.Random.DefaultPrng.init(113);
    rng.random().bytes(&payload);
    _ = try setup.shared.client.gossipsub.publish(test_topic, &payload, setup.shared.pair.now);
    for (0..64) |_| {
        try setup.pumpOnce();
        if (g.counters.receive_capacity_refusals != 0 and g.sessions.rows[peer].io.reader.declaredLen() == null) break;
    }
    try std.testing.expectEqual(@as(u64, 1), g.counters.receive_capacity_refusals);
    try std.testing.expectEqual(@as(u64, 0), g.counters.local_pressure_resets);
    try std.testing.expectEqual(@as(u64, 1), g.counters.local_pressure_discards);
    try std.testing.expectEqual(@as(u64, 0), g.counters.malformed_rpcs);
    try std.testing.expectEqual(before, g.peers.score(logical, setup.shared.pair.now.mono_ms));
    try std.testing.expectEqual(@as(u64, 0), g.peers.rows[logical.index].large_frame_denied_until);
    try std.testing.expect(g.sessions.rows[peer].in_stream != null);
    try std.testing.expect(g.sessions.rows[peer].outStream() != null);
    try std.testing.expect(g.sessions.rows[peer].io.reader.declaredLen() == null);
    try std.testing.expectEqual(@as(usize, 0), g.sessions.receive_pool.free_pages);
    const inbound = g.sessions.rows[peer].in_stream.?;
    _ = try setup.shared.client.gossipsub.publish(test_topic, "after discarded frame", setup.shared.pair.now);
    var received = false;
    for (0..32) |_| {
        try setup.pumpOnce();
        for (setup.serverMessages()) |message| {
            try std.testing.expectEqualStrings("after discarded frame", message.bytes);
            received = true;
        }
        if (received) break;
    }
    try std.testing.expect(received);
    try std.testing.expectEqual(inbound, g.sessions.rows[peer].in_stream.?);
}

test "gossipsub graylist refuses bulk reception and releases an idle partial frame" {
    for ([_]bool{ false, true }) |partial| {
        var setup: Pair = .{};
        try setup.initOpts(.{ .random_seed = 1 }, .{ .random_seed = 1, .body_buffer_bytes = 64 });
        defer setup.deinit();
        for (0..16) |_| try setup.pumpOnce();
        const g = setup.shared.server.gossipsub;
        const index = g.sessions.findPeer(setup.shared.handles.server).?;
        const row = &g.sessions.rows[index];
        var wire: [1024]u8 = undefined;
        var writer = @import("protobuf.zig").Writer.init(&wire);
        writer.varint(@import("constants.zig").GOSSIP_MAX_SIZE);
        writer.bytes(&([_]u8{0} ** 128));
        if (!partial) @import("test_support.zig").penalize(g, row.conn, 50);
        const before = g.rpc_metrics.received_bytes;
        try std.testing.expectEqual(writer.len, try setup.shared.pair.client.write(setup.clientStream(), writer.written(), false));
        for (0..8) |_| try setup.pumpOnce();
        if (partial) {
            try std.testing.expect(row.io.overflow.pages > 0);
            try std.testing.expect(!row.io.rx_ready);
            @import("test_support.zig").penalize(g, row.conn, 50);
            try setup.pumpOnce();
        } else try std.testing.expectEqual(before, g.rpc_metrics.received_bytes);
        try std.testing.expect(row.in_stream == null and row.io.rpc == null);
        try std.testing.expectEqual(g.sessions.receive_pool.next.len, g.sessions.receive_pool.free_pages);
        try std.testing.expectEqual(@as(u64, 1), g.rpc_metrics.graylist_dropped);
        try std.testing.expectEqual(@as(u64, 0), g.counters.malformed_rpcs);
        try std.testing.expectEqual(@as(f64, 50), g.peers.scores.rows[row.logical.index].behaviour);
    }
}

test "gossipsub malformed framing and RPCs penalize authenticated sources across stream resets" {
    var setup: Pair = .{};
    try setup.initOpts(.{ .random_seed = 1 }, .{ .random_seed = 1, .score_params = .{ .behaviour_threshold = 0 } });
    defer setup.deinit();
    for (0..16) |_| try setup.pumpOnce();
    const g = setup.shared.server.gossipsub;
    const index = g.sessions.findPeer(setup.shared.handles.server).?;
    const row = &g.sessions.rows[index];
    const source = row.logical;
    const malformed = [_][]const u8{
        &.{ 2, 0x08, 0 },
        &.{ 0x80, 0x00 },
    };
    for (malformed, 0..) |wire, i| {
        try std.testing.expectEqual(wire.len, try setup.shared.pair.client.write(setup.clientStream(), wire, false));
        for (0..32) |_| {
            try setup.pumpOnce();
            if (g.counters.malformed_rpcs == i + 1) break;
        }
        try std.testing.expectEqual(i + 1, g.counters.malformed_rpcs);
        try std.testing.expect(row.in_stream == null);
        try std.testing.expectEqual(source, row.logical);
        try std.testing.expectEqual(@as(f64, @floatFromInt(i + 1)), g.peers.scores.rows[source.index].behaviour);
        try std.testing.expect(g.peers.score(source, setup.shared.pair.now.mono_ms) < 0);
        try std.testing.expectEqual(@as(u64, 0), g.peers.scores.penalties.invalid_message);
        try std.testing.expectEqual(g.sessions.receive_pool.next.len, g.sessions.receive_pool.free_pages);
        for (0..16) |_| try setup.pumpOnce();
        if (i + 1 < malformed.len) {
            const client = setup.shared.client.gossipsub;
            const client_index = client.sessions.findPeer(setup.shared.handles.client).?;
            try std.testing.expectEqual(.none, client.sessions.rows[client_index].outbound);
            client.sessions.setOutbound(client_index, .pending);
            for (0..16) |_| try setup.pumpOnce();
            try std.testing.expect(client.sessions.rows[client_index].outStream() != null);
        }
    }
}

test "gossipsub discarding a locally refused frame preserves its deadline without blaming the peer" {
    var setup: Pair = .{};
    try setup.initOpts(.{ .random_seed = 1 }, .{ .random_seed = 1, .body_buffer_bytes = 1024, .large_frame_timeout_ms = 200 });
    defer setup.deinit();
    try connectMesh(&setup);
    const g = setup.shared.server.gossipsub;
    var held: [3]@import("receive_pool.zig").Chain = @splat(.{});
    defer for (&held) |*chain| g.sessions.receive_pool.release(chain);
    for (0..g.sessions.receive_pool.next.len) |i| {
        const chain = &held[i % held.len];
        _ = g.sessions.receive_pool.writable(chain).?;
        chain.len += @import("receive_pool.zig").page_bytes;
    }
    const index = g.sessions.findPeer(setup.shared.handles.server).?;
    const peer = &g.sessions.rows[index];
    const before = g.peers.score(peer.logical, setup.shared.pair.now.mono_ms);
    var wire: [65540]u8 = undefined;
    const body: [65536]u8 = @splat(0);
    _ = @import("frame.zig").writeFrame(&wire, &body);
    try std.testing.expectEqual(@as(usize, 2048), try setup.shared.pair.client.write(setup.clientStream(), wire[0..2048], false));
    for (0..16) |_| {
        try setup.pumpOnce();
        if (peer.io.discarding) break;
    }
    try std.testing.expect(peer.io.discarding);
    const began = peer.io.frame_since.?;
    setup.shared.pair.now.mono_ms = began + 199;
    try setup.pumpOnce();
    try std.testing.expect(peer.in_stream != null);
    setup.shared.pair.advance(1);
    try setup.pumpOnce();
    try std.testing.expect(peer.in_stream == null);
    try std.testing.expectEqual(@as(u64, 1), g.counters.local_pressure_discards);
    try std.testing.expectEqual(@as(u64, 1), g.counters.local_pressure_resets);
    try std.testing.expectEqual(@as(u64, 0), g.counters.large_stalled);
    try std.testing.expectEqual(before, g.peers.score(peer.logical, setup.shared.pair.now.mono_ms));
    try std.testing.expectEqual(@as(u64, 0), g.peers.rows[peer.logical.index].large_frame_denied_until);
}
