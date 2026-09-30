const std = @import("std");
const gossip = @import("gossipsub.zig");
const Gossipsub = gossip.Gossipsub;
const MessageId = gossip.MessageId;
const ReportOutcome = gossip.ReportOutcome;
const constants = @import("constants.zig");
const protobuf = @import("protobuf.zig");
const topic_mod = @import("topic.zig");
const peers_mod = @import("peer_book.zig");
const engine_mod = @import("../quic/engine.zig");
const Handle = engine_mod.Handle;
const StreamHandle = engine_mod.StreamHandle;
const Now = @import("../types.zig").Now;
const Credits = @import("turn.zig").Credits;
const Progress = @import("turn.zig").Progress;
const snappy = @import("snappy");
const support = @import("test_support.zig");
const receiveForTest = support.receiveMessage;
const testMessage = support.message;

test "gossip graylist drops an RPC before decoding or admitting messages" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const session = support.addPeer(&g, conn, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, name);
    support.penalize(&g, conn, 50);
    // An accepting host: a message that got past the graylist would be delivered.
    var inbox: support.Inbox = .{};
    defer inbox.deinit();
    inbox.attach(&g);
    var encoded: [256]u8 = undefined;
    var compressed: [64]u8 = undefined;
    const len = try snappy.raw.compress("payload", &compressed);
    var writer = protobuf.Writer.init(&encoded);
    protobuf.writeMessage(&writer, compressed[0..len], name);
    g.sessions.rows[session.index].io.startRpc(writer.written());
    var count: usize = 0;
    var items = g.options.items_per_peer;
    try std.testing.expect(try support.processRpc(&g, session.index, .{ .mono_ms = 1, .unix_s = 0 }, &count, &items));
    // The graylist ends the RPC before it takes an item credit or decodes a field.
    try std.testing.expectEqual(g.options.items_per_peer, items);
    try std.testing.expectEqual(@as(usize, 0), inbox.count);
    try std.testing.expectEqual(@as(usize, 0), g.messages.seen.count);
}

test "gossip IWANT admits 5000 IDs and rejects larger envelopes before service" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const session = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    for ([_]usize{ constants.max_iwant_ids_per_rpc, constants.max_iwant_ids_per_rpc + 1 }) |count| {
        const encoded = try std.testing.allocator.alloc(u8, protobuf.iwantRpcSize(count, constants.message_id_length));
        defer std.testing.allocator.free(encoded);
        var writer = protobuf.Writer.init(encoded);
        protobuf.beginIwantRpc(&writer, count, constants.message_id_length);
        const id: MessageId = @splat(0xab);
        for (0..count) |_| protobuf.writeIwantId(&writer, &id);
        const io = &g.sessions.rows[session.index].io;
        io.startRpc(writer.written());
        var emitted: usize = 0;
        var items = g.options.items_per_peer;
        const result = support.processRpc(&g, session.index, .{ .mono_ms = 1, .unix_s = 0 }, &emitted, &items);
        if (count == constants.max_iwant_ids_per_rpc) {
            try std.testing.expect(try result);
        } else {
            try std.testing.expectError(error.OccurrenceLimit, result);
        }
        try std.testing.expectEqual(@as(u64, constants.max_iwant_ids_per_rpc), g.iwant_outcomes[@intFromEnum(@import("metrics.zig").IwantOutcome.miss)]);
        try std.testing.expectEqual(@as(usize, 0), emitted);
        _ = g.sessions.finishFrame(io);
    }
}

test "gossip turn separates credit exhaustion from host pressure and preserves event borrows" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .work_per_pump = 1, .decompress_per_peer_bytes = 1 });
    defer g.deinit();
    const session = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, name);
    var encoded: [256]u8 = undefined;
    var compressed: [64]u8 = undefined;
    var writer = protobuf.Writer.init(&encoded);
    for ([_][]const u8{ "first", "second" }) |payload| {
        const len = try snappy.raw.compress(payload, &compressed);
        protobuf.writeMessage(&writer, compressed[0..len], name);
    }
    const io = &g.sessions.rows[session.index].io;
    io.startRpc(writer.written());
    const driver = @import("session_io.zig");
    var turn = @import("session_io.zig").beginPump(&g, .{ .mono_ms = 1, .unix_s = 0 });
    var peer = Credits.peer(&g.options);
    try std.testing.expectEqual(Progress.credits, try driver.processRpc(&g, session.index, &turn, &peer));
    try std.testing.expect(io.rpc.?.item != null);
}

test "gossipsub pending validation survives history churn and report publish event reuse" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .mcache_capacity = 1, .validation_capacity = 2, .seen_capacity = 1 });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, topic);
    var inbox: support.Inbox = .{};
    defer inbox.deinit();
    inbox.attach(&g);
    try std.testing.expectEqual(@as(?usize, 1), try testMessage(&g, peer.index, "pending", 1));
    const event = inbox.last();
    for (0..20) |i| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, i, .little);
        _ = try g.publish(topic, &bytes, .{ .mono_ms = 2, .unix_s = 1 });
        @import("test_support.zig").ageHistory(&g);
    }
    try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, peer.index, "pending", 3));
    try std.testing.expectEqual(ReportOutcome{ .applied = .ignore }, g.report(event.handle, .ignore, .{ .mono_ms = 4, .unix_s = 1 }));
    _ = try g.publish("/eth2/01020304/voluntary_exit/ssz_snappy", "reuse", .{ .mono_ms = 5, .unix_s = 1 });
    try std.testing.expectEqualStrings("pending", event.bytes);
    try std.testing.expectEqualStrings(topic, event.topic);
    try std.testing.expectEqual(ReportOutcome.already_resolved, g.report(event.handle, .accept, .{ .mono_ms = 6, .unix_s = 1 }));
    try std.testing.expectEqual(@as(?usize, 1), try testMessage(&g, peer.index, "expires", 7));
    const expires = inbox.last().handle;
    try std.testing.expectEqual(ReportOutcome.expired, g.report(expires, .accept, .{ .mono_ms = 30_007, .unix_s = 1 }));
    try std.testing.expectEqual(ReportOutcome.stale_handle, g.report(expires, .accept, .{ .mono_ms = 60_007, .unix_s = 1 }));
}

test "gossipsub duplicate invalid bytes do not evict useful history" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .mcache_capacity = 1 });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, topic);
    _ = try g.publish(topic, "useful", .{ .mono_ms = 1, .unix_s = 1 });
    const useful = topic_mod.validMessageId(topic, "useful", .{});
    const retained = g.messages.history.message(g.messages.history.get(&g.messages.store, useful).?);
    for (0..20) |_| {
        try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, peer.index, "useful", 2));
        _ = receiveForTest(&g, peer.index, .{ .topic = topic, .data = &.{ 5, 0 } }, .{ .mono_ms = 2, .unix_s = 1 });
        try std.testing.expectEqual(retained, g.messages.history.message(g.messages.history.get(&g.messages.store, useful).?));
    }
}

test "gossipsub IWANT promises commit on queue and start at completed control transmission" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .control_bytes = 64 });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, topic);
    var body: [32]u8 = undefined;
    var w = protobuf.Writer.init(&body);
    const id = [_]u8{7} ** 20;
    w.bytesField(2, &id);
    try std.testing.expect(g.sessions.rows[peer.index].io.tx.inject(&([_]u8{0} ** 64), 1));
    support.control(&g, peer.index, .{ .ihave = .{ .topic = topic, .body = w.written() } }, .{ .mono_ms = 1, .unix_s = 1 });
    try std.testing.expectEqual(@as(usize, 0), g.recovery.len);
    g.sessions.rows[peer.index].io.tx.cancelStream(&g.messages.store);
    support.control(&g, peer.index, .{ .ihave = .{ .topic = topic, .body = w.written() } }, .{ .mono_ms = 2, .unix_s = 1 });
    try std.testing.expectEqual(@as(usize, 1), g.recovery.len);
    @import("session_io.zig").finishPump(&g, .{ .mono_ms = 1_000, .unix_s = 0 });
    try std.testing.expectEqual(@as(u64, 0), g.counters.broken_promises);
    const io = &g.sessions.rows[peer.index].io;
    const first = io.tx.segment(&g.messages.store);
    _ = io.tx.advance(&g.messages.store, 1);
    try std.testing.expectEqual(@as(u64, 3_002), g.recovery.batches[0].expiry);
    const token = io.tx.advance(&g.messages.store, first.len - 1).?.control.token;
    g.recovery.controlSent(g.sessions.rows[peer.index].conn, token, g.options.iwant_followup_ms, 1_000);
    try std.testing.expectEqual(@as(u64, 4_000), g.recovery.batches[0].expiry);
}

test "gossipsub IHAVE pending and duplicate prefixes do not hide new tail IDs" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, name);
    var bytes: [8192]u8 = undefined;
    var writer = protobuf.Writer.init(&bytes);
    for (0..constants.gossip_ids_max) |i| {
        const id: MessageId = @splat(@intCast(i));
        writer.bytesField(2, &id);
    }
    support.control(&g, peer.index, .{ .ihave = .{ .topic = name, .body = writer.written() } }, .{ .mono_ms = 1, .unix_s = 1 });
    try std.testing.expectEqual(constants.gossip_ids_max, g.recovery.len);
    const first_tail: MessageId = @splat(128);
    for (0..constants.gossip_ids_max) |_| writer.bytesField(2, &first_tail);
    const second_tail: MessageId = @splat(129);
    writer.bytesField(2, &second_tail);
    support.control(&g, peer.index, .{ .ihave = .{ .topic = name, .body = writer.written() } }, .{ .mono_ms = 2, .unix_s = 1 });
    try std.testing.expectEqual(constants.gossip_ids_max + 2, g.recovery.len);
    try std.testing.expectEqual(@as(u16, constants.gossip_ids_max + 2), g.sessions.rows[peer.index].io.iwant_ids_sent);
    support.control(&g, peer.index, .{ .ihave = .{ .topic = name, .body = writer.written() } }, .{ .mono_ms = 3, .unix_s = 1 });
    try std.testing.expectEqual(constants.gossip_ids_max + 2, g.recovery.len);
}

test "gossipsub IHAVE samples eligible IDs across the advertisement independently per peer" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .connected_capacity = 2, .retained_capacity = 4, .retained_outbound_reserve = 1 });
    defer g.deinit();
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, name);
    var bytes: [16384]u8 = undefined;
    var writer = protobuf.Writer.init(&bytes);
    for (0..512) |i| {
        var id: MessageId = @splat(0);
        std.mem.writeInt(u16, id[0..2], @intCast(i), .big);
        writer.bytesField(2, &id);
        if (i < 16) _ = g.messages.seen.add(id, 0);
    }
    for (0..2) |i| {
        const peer = support.addPeer(&g, .{ .index = @intCast(i), .generation = 1 }, .v1_2).?;
        support.control(&g, peer.index, .{ .ihave = .{ .topic = name, .body = writer.written() } }, .{ .mono_ms = 1, .unix_s = 0 });
    }
    try std.testing.expectEqual(@as(usize, 2), g.recovery.batch_len);
    var selected: [2]std.StaticBitSet(512) = @splat(.initEmpty());
    for (g.recovery.batches[0..2], 0..) |batch, peer| {
        try std.testing.expectEqual(@as(u16, constants.gossip_ids_max), batch.count);
        var slot = batch.head;
        var high = false;
        for (0..batch.count) |_| {
            const request = &g.recovery.requests[slot];
            const id = std.mem.readInt(u16, request.id[0..2], .big);
            try std.testing.expect(id >= 16 and id < 512 and !selected[peer].isSet(id));
            selected[peer].set(id);
            high = high or id >= 256;
            slot = request.next;
        }
        try std.testing.expect(high);
    }
    try std.testing.expect(!selected[0].eql(selected[1]));
    try std.testing.expectEqual(@as(usize, 2 * constants.gossip_ids_max), g.recovery.len);
}

test "gossipsub IHAVE security bounds one identity and deduplicates queued requests" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .iwant_followup_ms = 12000 });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, name);
    var bytes: [4096]u8 = undefined;
    var writer = protobuf.Writer.init(&bytes);
    const duplicate = [_]u8{7} ** 20;
    for (0..128) |_| writer.bytesField(2, &duplicate);
    const io = &g.sessions.rows[peer.index].io;
    for (0..2) |_| support.control(&g, peer.index, .{ .ihave = .{ .topic = name, .body = writer.written() } }, .{ .mono_ms = 1, .unix_s = 1 });
    try std.testing.expectEqual(@as(usize, 1), g.recovery.len);
    for (0..7) |heartbeat| {
        io.resetHeartbeat();
        for (0..constants.max_ihave_per_heartbeat) |batch| {
            writer.len = 0;
            for (0..constants.gossip_ids_max) |item| {
                var id: MessageId = @splat(0);
                std.mem.writeInt(u32, id[0..4], @intCast((heartbeat * constants.max_ihave_per_heartbeat + batch) * constants.gossip_ids_max + item), .little);
                writer.bytesField(2, &id);
            }
            support.control(&g, peer.index, .{ .ihave = .{ .topic = name, .body = writer.written() } }, .{ .mono_ms = heartbeat * 1000, .unix_s = 1 });
            for (0..4) |_| {
                const segment = io.tx.segment(&g.messages.store);
                if (segment.len == 0) break;
                if (io.tx.advance(&g.messages.store, segment.len)) |completion| g.writeCompleted(g.sessions.ref(peer.index), completion, heartbeat * 1000);
            }
        }
    }
    try std.testing.expectEqual(@as(usize, constants.gossip_ids_max * constants.max_ihave_per_heartbeat), g.recovery.len);
    const other = @import("test_support.zig").addPeer(&g, .{ .index = 1, .generation = 1 }, .v1_2).?;
    const occupied = g.recovery.len;
    support.control(&g, other.index, .{ .ihave = .{ .topic = name, .body = writer.written() } }, .{ .mono_ms = 7000, .unix_s = 1 });
    try std.testing.expectEqual(occupied + constants.gossip_ids_max, g.recovery.len);
    try std.testing.expectEqual(occupied, g.recovery.cancel(&g.peers, g.sessions.rows[peer.index].conn, true).removed);
    io.resetHeartbeat();
    support.control(&g, peer.index, .{ .ihave = .{ .topic = name, .body = writer.written() } }, .{ .mono_ms = 7000, .unix_s = 1 });
    try std.testing.expectEqual(@as(usize, 2 * constants.gossip_ids_max), g.recovery.len);
}

test "gossipsub legal maximum host acceptance forwards retained pages through actual IO" {
    var setup: @import("test_pair.zig").Pair = .{};
    const small = try @import("../configuration.zig").resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .admission_policy = @import("../reqresp/policy_fixture.zig").config() });
    try setup.initOpts(small.core.service.gossipsub, small.core.service.gossipsub);
    defer setup.deinit();
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(setup.shared.client.gossipsub, topic);
    try support.subscribe(setup.shared.server.gossipsub, topic);
    for (0..20) |_| try setup.pumpOnce();
    const destination = setup.shared.server.gossipsub.sessions.find(setup.shared.handles.server).?;
    // The small profile finds sessions among 16 connection slots.
    const source = @import("test_support.zig").addPeer(setup.shared.server.gossipsub, .{ .index = 7, .generation = 1 }, .v1_2).?;
    setup.shared.server.gossipsub.overlay.rows[setup.shared.server.gossipsub.overlay.findTopic(topic).?].mesh.set(destination);
    const payload = try std.testing.allocator.alloc(u8, constants.MAX_PAYLOAD_SIZE);
    defer std.testing.allocator.free(payload);
    var rng = std.Random.DefaultPrng.init(91);
    rng.random().bytes(payload);
    _ = @import("test_support.zig").pump(setup.shared.server.gossipsub, &setup.shared.pair.server, setup.shared.pair.now);
    // The sink path decodes into msg_scratch, so the wire bytes live elsewhere.
    const compressed = try std.testing.allocator.alloc(u8, constants.maxCompressedLen(constants.MAX_PAYLOAD_SIZE));
    defer std.testing.allocator.free(compressed);
    const len = try snappy.raw.compress(payload, compressed);
    try std.testing.expectEqual(@as(?usize, 1), receiveForTest(setup.shared.server.gossipsub, source.index, .{ .topic = topic, .data = compressed[0..len] }, setup.shared.pair.now));
    const handle = setup.shared.server_inbox.last().handle;
    const message = setup.shared.server.gossipsub.messages.validation.entries[handle.index].state.pending.message;
    try std.testing.expectEqual(ReportOutcome{ .applied = .accept }, setup.shared.server.gossipsub.report(handle, .accept, setup.shared.pair.now));
    try std.testing.expectEqual(@as(u32, 1), setup.shared.server.gossipsub.messages.store.get(message).?.tx);
    for (0..constants.mcache_len) |_| @import("test_support.zig").ageHistory(setup.shared.server.gossipsub);
    try std.testing.expect(!setup.shared.server.gossipsub.messages.store.get(message).?.history);
    var received = false;
    for (0..2000) |_| {
        try setup.pumpOnce();
        for (setup.clientMessages()) |delivered| {
            try std.testing.expectEqualSlices(u8, payload, delivered.bytes);
            received = true;
        }
        if (received) break;
    }
    try std.testing.expect(received);
    try std.testing.expect(setup.shared.server.gossipsub.messages.store.get(message) == null);
}

test "gossipsub rotates the legal atomic allowance past a duplicate flood" {
    var pair: @import("../test_support.zig").Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .decompress_per_peer_bytes = 1 });
    defer g.deinit();
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, topic);
    var inbox: support.Inbox = .{};
    defer inbox.deinit();
    inbox.attach(&g);
    var first_rpc: [128]u8 = undefined;
    var second_rpc: [128]u8 = undefined;
    var compressed: [64]u8 = undefined;
    var w1 = protobuf.Writer.init(&first_rpc);
    var w2 = protobuf.Writer.init(&second_rpc);
    const n1 = try snappy.raw.compress("one", &compressed);
    protobuf.writeMessage(&w1, compressed[0..n1], topic);
    const n2 = try snappy.raw.compress("two", &compressed);
    protobuf.writeMessage(&w2, compressed[0..n2], topic);
    const first = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const second = @import("test_support.zig").addPeer(&g, .{ .index = 1, .generation = 1 }, .v1_2).?;
    const stream1: StreamHandle = .{ .conn = .{ .index = 0, .generation = 1 }, .slot = 0, .id = 0 };
    const stream2: StreamHandle = .{ .conn = .{ .index = 1, .generation = 1 }, .slot = 0, .id = 0 };
    g.sessions.rows[first.index].in_stream = stream1;
    g.sessions.rows[first.index].io.rx_ready = true;
    g.sessions.rows[second.index].in_stream = stream2;
    g.sessions.rows[second.index].io.rx_ready = true;
    g.sessions.rows[first.index].io.startRpc(w1.written());
    g.sessions.rows[second.index].io.startRpc(w2.written());
    g.settle(first.index);
    g.settle(second.index);
    try std.testing.expectEqual(@as(usize, 1), @import("test_support.zig").pump(&g, &pair.server, pair.now));
    try std.testing.expectEqualStrings("one", inbox.last().bytes);
    g.sessions.rows[first.index].in_stream = stream1;
    g.sessions.rows[first.index].io.rx_ready = true;
    g.sessions.rows[first.index].io.startRpc(w1.written());
    g.settle(first.index);
    try std.testing.expectEqual(@as(?u64, pair.now.mono_ms), g.nextWakeup(pair.now));
    try std.testing.expectEqual(@as(usize, 1), @import("test_support.zig").pump(&g, &pair.server, pair.now));
    try std.testing.expectEqualStrings("two", inbox.last().bytes);
}

test "gossipsub validation attribution cannot penalize reused source or duplicate slots" {
    var g = try support.init(std.testing.allocator, .{
        .random_seed = 1,
    });
    defer g.deinit();
    const source_conn: Handle = .{ .index = 0, .generation = 1 };
    const duplicate_conn: Handle = .{ .index = 1, .generation = 1 };
    const source = @import("test_support.zig").addPeer(&g, source_conn, .v1_2).?;
    const duplicate = @import("test_support.zig").addPeer(&g, duplicate_conn, .v1_2).?;
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, topic);
    var inbox: support.Inbox = .{};
    defer inbox.deinit();
    inbox.attach(&g);
    try std.testing.expectEqual(@as(?usize, 1), try testMessage(&g, source.index, "invalid", 1));
    const handle = inbox.last().handle;
    try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, duplicate.index, "invalid", 2));
    g.connectionClosed(source_conn);
    g.connectionClosed(duplicate_conn);
    const replacement1 = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 2 }, .v1_2).?;
    const replacement2 = @import("test_support.zig").addPeer(&g, .{ .index = 1, .generation = 2 }, .v1_2).?;
    try std.testing.expectEqual(ReportOutcome{ .applied = .reject }, g.report(handle, .reject, .{ .mono_ms = 3, .unix_s = 1 }));
    try std.testing.expectEqual(@as(f64, 0), g.peers.score(g.sessions.rows[replacement1.index].logical, 3));
    try std.testing.expectEqual(@as(f64, 0), g.peers.score(g.sessions.rows[replacement2.index].logical, 3));
}

test "gossip independent RPC enumerates every receive split through admission" {
    // RPC 17.1.1, it-length-prefixed 11.0.1 and Snappy 7.3.3 encoded this two-message fixture.
    const wire = @embedFile("testdata/independent-two.rpc");
    const name = "/eth2/01000000/beacon_block/ssz_snappy";
    try std.testing.expect(wire[0] & 0x80 != 0);
    var g = try support.init(std.testing.allocator, .{
        .random_seed = 1,
        .mcache_capacity = 2,
        .validation_capacity = 4,
        .seen_capacity = 2,
        .seen_ttl_ms = 1,
        .validation_tombstone_ms = 1,
        .body_buffer_bytes = 1,
        .topic_policy = &.{@import("topic_fixture.zig").bytes(.{ 1, 0, 0, 0 })},
    });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    try support.subscribe(&g, name);
    var inbox: support.Inbox = .{};
    defer inbox.deinit();
    inbox.attach(&g);
    var expected: [2][64]u8 = undefined;
    for (0..64) |i| {
        expected[0][i] = @intCast(i);
        expected[1][i] = @intCast(255 - i);
    }
    for (0..wire.len + 1) |split| {
        const now: Now = .{ .mono_ms = 1 + split * 10, .unix_s = 1 };
        g.last_now_ms = now.mono_ms;
        g.messages.validation.expire(&g.messages.store, &g.peers, now.mono_ms);
        const io = &g.sessions.rows[peer.index].io;
        try std.testing.expect(!g.sessions.resetRx(peer.index));
        var count: usize = 0;
        var consumed: usize = 0;
        var items: usize = 128;
        for ([_][]const u8{ wire[0..split], wire[split..] }) |fragment| {
            try std.testing.expect(g.sessions.receiveHandoff(peer.index, fragment, false));
            for (0..wire.len + 1) |_| {
                if (io.unread_start == io.unread_end) break;
                const result = try io.feedUnread(&g.sessions.receive_pool, io.unread_end - io.unread_start, now.mono_ms);
                try std.testing.expect(result.consumed > 0);
                consumed += result.consumed;
                if (result.complete) {
                    try std.testing.expect(try @import("test_support.zig").processRpc(&g, peer.index, now, &count, &items));
                    try std.testing.expect(try @import("test_support.zig").processRpc(&g, peer.index, now, &count, &items));
                    try std.testing.expect(g.sessions.finishFrame(io));
                }
            }
        }
        try std.testing.expectEqual(wire.len, consumed);
        try std.testing.expectEqual(@as(usize, 2), count);
        for (inbox.messages(), 0..) |message, i| {
            try std.testing.expectEqualSlices(u8, &expected[i], message.bytes);
            try std.testing.expect(g.report(message.handle, .ignore, now) == .applied);
        }
        inbox.clear();
        try std.testing.expect(io.rpc == null and io.reader.declaredLen() == null);
        try std.testing.expectEqual(io.unread_end, io.unread_start);
        const snapshot = g.resourceSnapshot();
        try std.testing.expectEqual(@as(usize, 0), snapshot.pending_validations);
        try std.testing.expectEqual(@as(usize, 0), snapshot.store_entries);
        try std.testing.expectEqual(@as(usize, 0), snapshot.store_pages);
    }
}

test "gossipsub history queue refusal and authenticated reconnect preserve retransmission counts" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .mcache_capacity = 2 });
    defer g.deinit();
    const metadata: peers_mod.Metadata = .{
        .identity = .{ .bytes = [_]u8{1} ** @import("../wire/peer_id.zig").length },
        .address = .unspecified,
        .direction = .inbound,
    };
    const now: Now = .{ .mono_ms = 1, .unix_s = 0 };
    const first = g.addPeer(.{ .index = 0, .generation = 1 }, &metadata, now).admitted;
    g.sessions.setOutbound(first.index, .{ .live = .{ .stream = .{ .conn = g.sessions.rows[first.index].conn, .id = 2, .slot = 0 }, .version = .v1_2 } });
    const logical_peer = g.sessions.rows[first.index].logical;
    const id: MessageId = @splat(9);
    const message = g.messages.store.put(id, "t", "payload").?;
    g.messages.history.put(&g.messages.store, message, g.cycle.epoch);
    g.messages.store.seal(message);
    var bytes: [64]u8 = undefined;
    var writer = protobuf.Writer.init(&bytes);
    protobuf.beginIwantRpc(&writer, 1, id.len);
    protobuf.writeIwantId(&writer, &id);
    var reader = protobuf.RpcReader.init(writer.written());
    const iwant = (try reader.next()).?.iwant;
    // Forwards fill the ordinary allowance and publications the local reserve.
    const tx = &g.sessions.rows[first.index].io.tx;
    for (0..@import("outbox.zig").data_capacity) |_| {
        const origin: @import("delivery.zig").Origin = if (tx.data.full()) .publication else .forward;
        try std.testing.expectEqual(@import("outbox.zig").QueueResult.queued, tx.queueData(&g.messages.store, message, origin, .{ .bytes = g.options.tx_peer_bytes }, 1));
    }
    support.control(&g, first.index, .{ .iwant = iwant }, .{ .mono_ms = g.last_now_ms, .unix_s = 0 });
    try std.testing.expectEqual(@as(u8, 0), g.messages.history.countsRow(g.messages.history.get(&g.messages.store, id).?)[logical_peer.index]);
    try std.testing.expectEqual(@as(u64, 1), g.iwant_outcomes[@intFromEnum(@import("metrics.zig").IwantOutcome.refused)]);
    g.sessions.rows[first.index].io.tx.cancelStream(&g.messages.store);
    for (0..4) |_| support.control(&g, first.index, .{ .iwant = iwant }, .{ .mono_ms = g.last_now_ms, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 3), g.sessions.rows[first.index].io.tx.data.count);
    g.connectionClosed(.{ .index = 0, .generation = 1 });
    const second = g.addPeer(.{ .index = 0, .generation = 2 }, &metadata, now).admitted;
    g.sessions.setOutbound(second.index, .{ .live = .{ .stream = .{ .conn = g.sessions.rows[second.index].conn, .id = 2, .slot = 0 }, .version = .v1_2 } });
    try std.testing.expectEqual(logical_peer, g.sessions.rows[second.index].logical);
    support.control(&g, second.index, .{ .iwant = iwant }, .{ .mono_ms = g.last_now_ms, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[second.index].io.tx.data.count);
    g.connectionClosed(.{ .index = 0, .generation = 2 });
    const expired: Now = .{ .mono_ms = g.peers.retention_ms + 2, .unix_s = 0 };
    const third = g.addPeer(.{ .index = 0, .generation = 3 }, &metadata, expired).admitted;
    g.sessions.setOutbound(third.index, .{ .live = .{ .stream = .{ .conn = g.sessions.rows[third.index].conn, .id = 2, .slot = 0 }, .version = .v1_2 } });
    try std.testing.expectEqual(logical_peer.index, g.sessions.rows[third.index].logical.index);
    try std.testing.expect(g.sessions.rows[third.index].logical.generation > logical_peer.generation);
    for (0..4) |_| support.control(&g, third.index, .{ .iwant = iwant }, .{ .mono_ms = g.last_now_ms, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 3), g.sessions.rows[third.index].io.tx.data.count);
}

test "recovery owner clear releases sent and unsent attribution pins" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const peer = @import("test_support.zig").addPeer(&g, conn, .v1_2).?;
    const ref = g.sessions.rows[peer.index].logical;
    g.recovery.add(&g.peers, [_]u8{1} ** 20, g.sessions.rows[peer.index].logical, g.sessions.rows[peer.index].conn, 1, 30_000);
    g.recovery.add(&g.peers, [_]u8{2} ** 20, g.sessions.rows[peer.index].logical, g.sessions.rows[peer.index].conn, 2, 30_000);
    g.recovery.controlSent(g.sessions.rows[peer.index].conn, 1, g.options.iwant_followup_ms, 10);
    try std.testing.expectEqual(@as(u32, 2), g.peers.rows[ref.index].pins);
    g.recovery.clear(&g.peers);
    try std.testing.expectEqual(@as(u32, 0), g.peers.rows[ref.index].pins);
    g.recovery.controlSent(g.sessions.rows[peer.index].conn, 2, g.options.iwant_followup_ms, 20);
    @import("session_io.zig").finishPump(&g, .{ .mono_ms = 4000, .unix_s = 0 });
    try std.testing.expectEqual(@as(u64, 0), g.counters.broken_promises);
}

test "gossipsub configured IWANT receipt starts twelve second deadline once" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .iwant_followup_ms = 12_000 });
    defer g.deinit();
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const p = @import("test_support.zig").addPeer(&g, conn, .v1_2).?;
    const io = &g.sessions.rows[p.index].io;
    const token = io.tx.injectFrame("control", false, 1).?;
    g.recovery.add(&g.peers, [_]u8{1} ** 20, g.sessions.rows[p.index].logical, conn, token, 30_000);
    g.recovery.controlSent(.{ .index = 0, .generation = 2 }, token, 12_000, 5);
    g.recovery.controlSent(g.sessions.rows[p.index].conn, token + 1, g.options.iwant_followup_ms, 5);
    try std.testing.expectEqual(@as(?u64, 30_000), g.recovery.nextExpiry());
    _ = io.tx.segment(&g.messages.store);
    try std.testing.expect(io.tx.advance(&g.messages.store, 1) == null);
    try std.testing.expectEqual(@as(?u64, 30_000), g.recovery.nextExpiry());
    g.writeCompleted(g.sessions.ref(p.index), io.tx.advance(&g.messages.store, 6).?, 100);
    g.recovery.controlSent(g.sessions.rows[p.index].conn, token, g.options.iwant_followup_ms, 200);
    try std.testing.expectEqual(@as(?u64, 12_100), g.recovery.nextExpiry());
    @import("session_io.zig").finishPump(&g, .{ .mono_ms = 12_099, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 1), g.recovery.len);
    @import("session_io.zig").finishPump(&g, .{ .mono_ms = 12_100, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 0), g.recovery.len);
    try std.testing.expectEqual(@as(u64, 1), g.counters.broken_promises);
    try std.testing.expectEqual(@as(u32, 0), g.peers.rows[g.sessions.rows[p.index].logical.index].pins);
}

test "gossipsub configured IDONTWANT uses admitted compressed wire bytes" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .idontwant_min_data_size = 128 });
    defer g.deinit();
    const source = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const destination = @import("test_support.zig").addPeer(&g, .{ .index = 1, .generation = 1 }, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, name);
    var inbox: support.Inbox = .{};
    defer inbox.deinit();
    inbox.attach(&g);
    g.overlay.rows[g.overlay.findTopic(name).?].mesh.set(destination.index);
    var payload: [126]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast(index);
    var compressed: [constants.maxCompressedLen(256)]u8 = undefined;
    for ([_]usize{ 124, 125, 126 }, [_]usize{ 127, 128, 129 }) |size, wire_size| {
        g.sessions.rows[destination.index].io.tx.cancelStream(&g.messages.store);
        const len = try snappy.raw.compress(payload[0..size], &compressed);
        try std.testing.expectEqual(wire_size, len);
        try std.testing.expectEqual(@as(?usize, 1), receiveForTest(&g, source.index, .{ .topic = name, .data = compressed[0..len] }, .{ .mono_ms = 1, .unix_s = 0 }));
        try std.testing.expectEqual(wire_size >= 128, g.sessions.rows[destination.index].io.tx.control.used > 0);
        g.sessions.rows[destination.index].io.tx.cancelStream(&g.messages.store);
        try std.testing.expectEqual(@as(?usize, 0), receiveForTest(&g, source.index, .{ .topic = name, .data = compressed[0..len] }, .{ .mono_ms = 1, .unix_s = 0 }));
        try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[destination.index].io.tx.control.used);
    }
    const len = try snappy.raw.compress(&([_]u8{0} ** 256), &compressed);
    try std.testing.expect(len < 128);
    try std.testing.expectEqual(@as(?usize, 1), receiveForTest(&g, source.index, .{ .topic = name, .data = compressed[0..len] }, .{ .mono_ms = 1, .unix_s = 0 }));
    try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[destination.index].io.tx.control.used);
    _ = receiveForTest(&g, source.index, .{ .topic = name, .data = &.{ 5, 0 } }, .{ .mono_ms = 1, .unix_s = 0 });
    try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[destination.index].io.tx.control.used);
    const fresh_len = try snappy.raw.compress("nonadmitted", &compressed);
    g.options.idontwant_min_data_size = 0;
    inbox.full = true;
    try std.testing.expectEqual(@as(?usize, 0), receiveForTest(&g, source.index, .{ .topic = name, .data = compressed[0..fresh_len] }, .{ .mono_ms = 1, .unix_s = 0 }));
    try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[destination.index].io.tx.control.used);
    inbox.full = false;
    try std.testing.expectEqual(@as(?usize, 1), receiveForTest(&g, source.index, .{ .topic = name, .data = compressed[0..fresh_len] }, .{ .mono_ms = 1, .unix_s = 0 }));
    try std.testing.expect(g.sessions.rows[destination.index].io.tx.control.used > 0);
}

test "gossipsub remote forwarding honors IDONTWANT and preserves borrowed event through local publication" {
    var pair: @import("test_pair.zig").Pair = .{};
    try pair.init();
    defer pair.deinit();
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(pair.shared.client.gossipsub, name);
    try support.subscribe(pair.shared.server.gossipsub, name);
    for (0..20) |_| try pair.pumpOnce();
    const destination = pair.shared.server.gossipsub.sessions.find(pair.shared.handles.server).?;
    const source = @import("test_support.zig").addPeer(pair.shared.server.gossipsub, .{ .index = 77, .generation = 1 }, .v1_2).?;
    pair.shared.server.gossipsub.overlay.rows[pair.shared.server.gossipsub.overlay.findTopic(name).?].mesh.set(destination);
    const suppressed_id = topic_mod.validMessageId(name, "remote suppressed", .{});
    pair.shared.server.gossipsub.sessions.suppress(destination, suppressed_id, pair.shared.pair.now.mono_ms, 60_000);
    try std.testing.expectEqual(@as(?usize, 1), try testMessage(pair.shared.server.gossipsub, source.index, "remote suppressed", pair.shared.pair.now.mono_ms));
    const borrowed = pair.shared.server_inbox.last();
    try std.testing.expectEqual(ReportOutcome{ .applied = .accept }, pair.shared.server.gossipsub.report(borrowed.handle, .accept, pair.shared.pair.now));
    try std.testing.expectEqual(@as(usize, 0), pair.shared.server.gossipsub.sessions.rows[destination].io.tx.data.count);
    const local = try pair.shared.server.gossipsub.publish(name, "local while borrowed", pair.shared.pair.now);
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .selected = 1, .queued = 1 }, local);
    try std.testing.expectError(error.Duplicate, pair.shared.server.gossipsub.publish(name, "local while borrowed", pair.shared.pair.now));
    try std.testing.expectEqual(Gossipsub.PublishOutcome{ .duplicate = true }, try pair.shared.server.gossipsub.publishWithOptions(name, "local while borrowed", .{ .ignore_duplicate = true }, pair.shared.pair.now));
    try std.testing.expectEqualStrings(name, borrowed.topic);
    try std.testing.expectEqualStrings("remote suppressed", borrowed.bytes);
    var received: usize = 0;
    for (0..30) |_| {
        try pair.pumpOnce();
        for (pair.clientMessages()) |message| {
            try std.testing.expectEqualStrings("local while borrowed", message.bytes);
            received += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), received);
    try std.testing.expectEqual(@as(u64, 0), pair.shared.server.gossipsub.topic_metrics.get(name).forwarded);
    try std.testing.expectEqual(@as(?usize, 1), try testMessage(pair.shared.server.gossipsub, source.index, "remote forwarded", pair.shared.pair.now.mono_ms));
    try std.testing.expectEqual(ReportOutcome{ .applied = .accept }, pair.shared.server.gossipsub.report(pair.shared.server_inbox.last().handle, .accept, pair.shared.pair.now));
    try std.testing.expectEqual(@as(usize, 1), pair.shared.server.gossipsub.sessions.rows[destination].io.tx.data.count);
    received = 0;
    for (0..30) |_| {
        try pair.pumpOnce();
        for (pair.clientMessages()) |message| {
            try std.testing.expectEqualStrings("remote forwarded", message.bytes);
            received += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), received);
    try std.testing.expectEqual(@as(u64, 1), pair.shared.server.gossipsub.topic_metrics.get(name).forwarded);
}

test "gossip forwarding excludes recorded duplicate senders but reaches other mesh peers" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, name);
    var peers: [3]u16 = undefined;
    for (&peers, 0..) |*peer, index| {
        peer.* = support.addPeer(&g, .{ .index = @intCast(index), .generation = 1 }, .v1_2).?.index;
        g.overlay.rows[g.overlay.findTopic(name).?].mesh.set(peer.*);
    }
    var inbox: support.Inbox = .{};
    defer inbox.deinit();
    inbox.attach(&g);
    try std.testing.expectEqual(@as(?usize, 1), try testMessage(&g, peers[0], "shared payload", 1));
    const handle = inbox.last().handle;
    try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, peers[1], "shared payload", 2));
    try std.testing.expectEqual(ReportOutcome{ .applied = .accept }, g.report(handle, .accept, .{ .mono_ms = 3, .unix_s = 0 }));
    try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[peers[0]].io.tx.data.count);
    try std.testing.expectEqual(@as(usize, 0), g.sessions.rows[peers[1]].io.tx.data.count);
    try std.testing.expectEqual(@as(usize, 1), g.sessions.rows[peers[2]].io.tx.data.count);
}

test "gossip duplicate fast path ignores host capacity and malformed bodies receive penalties" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .validation_capacity = 1 });
    defer g.deinit();
    const peer = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, name);
    var inbox: support.Inbox = .{};
    defer inbox.deinit();
    inbox.attach(&g);
    try std.testing.expectEqual(@as(?usize, 1), try testMessage(&g, peer.index, "pending", 1));
    const handle = inbox.last().handle;
    inbox.full = true;
    try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, peer.index, "pending", 2));
    inbox.full = false;
    try std.testing.expectEqual(@as(u64, 0), g.messages.storage_refusals[@intFromEnum(@import("messages.zig").StorageRefusal.processor_capacity)]);
    _ = g.report(handle, .ignore, .{ .mono_ms = 3, .unix_s = 1 });
    try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, peer.index, "pending", 4));
    for (0..20) |_| {
        _ = receiveForTest(&g, peer.index, .{ .topic = name, .data = &.{5} }, .{ .mono_ms = 5, .unix_s = 1 });
    }
    try std.testing.expectEqual(@as(f64, 20), support.invalidDeliveries(&g));
}

test "gossip recent attribution survives validation slot reuse and duplicate pressure" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .validation_capacity = 1 });
    defer g.deinit();
    const source = @import("test_support.zig").addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const duplicate = @import("test_support.zig").addPeer(&g, .{ .index = 1, .generation = 1 }, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, name);
    var inbox: support.Inbox = .{};
    defer inbox.deinit();
    inbox.attach(&g);
    try std.testing.expectEqual(@as(?usize, 1), try testMessage(&g, source.index, "rejected", 1));
    const old = inbox.last().handle;
    _ = g.report(old, .reject, .{ .mono_ms = 2, .unix_s = 0 });
    try std.testing.expectEqual(@as(?usize, 1), try testMessage(&g, source.index, "pending", 3));
    const current = inbox.last();
    try std.testing.expectEqual(old.index, current.handle.index);
    try std.testing.expect(old.generation != current.handle.generation);
    try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, duplicate.index, "rejected", 4));
    try std.testing.expectEqual(@as(f64, 2), support.invalidDeliveries(&g));
    try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, duplicate.index, "rejected", 5));
    try std.testing.expectEqual(@as(f64, 2), support.invalidDeliveries(&g));
    try std.testing.expectEqual(ReportOutcome.stale_handle, g.report(old, .accept, .{ .mono_ms = 6, .unix_s = 0 }));
    @memset(g.messages.fast, .{});
    try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, source.index, "pending", 7));
    try std.testing.expectEqualStrings("pending", current.bytes);
    try std.testing.expectEqualStrings(name, current.topic);
    try std.testing.expectEqual(ReportOutcome{ .applied = .ignore }, g.report(current.handle, .ignore, .{ .mono_ms = 8, .unix_s = 0 }));
    g.messages.expire(&g.peers, 30_008);
    try std.testing.expectEqual(@as(u32, 0), g.peers.rows[g.sessions.rows[source.index].logical.index].pins);
    try std.testing.expectEqual(@as(u32, 0), g.peers.rows[g.sessions.rows[duplicate.index].logical.index].pins);
}

test "gossipsub IHAVE work preflight defers without consuming the advertisement" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const session = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, name);
    var bytes: [4096]u8 = undefined;
    var writer = protobuf.Writer.init(&bytes);
    protobuf.beginIhaveRpc(&writer, name, 128, constants.message_id_length);
    const id: MessageId = @splat(7);
    for (0..128) |_| protobuf.writeIhaveId(&writer, &id);
    const io = &g.sessions.rows[session.index].io;
    io.startRpc(writer.written());
    const driver = @import("session_io.zig");
    var turn = @import("turn.zig").Turn.init(&g.options, .{ .mono_ms = 1, .unix_s = 0 }, &.{});
    var peer = Credits.peer(&g.options);
    turn.budget.work = 0;
    for (0..2) |_| {
        try std.testing.expectEqual(Progress.credits, try driver.processRpc(&g, session.index, &turn, &peer));
        try std.testing.expectEqual(@as(u16, 0), io.ihave_recv);
        try std.testing.expect(io.rpc.?.item != null);
        try std.testing.expectEqual(@as(usize, 0), g.recovery.len);
        try std.testing.expect(!turn.large_used);
    }
    const cost = g.ihaveWork(io.rpc.?.item.?.bytes.len);
    try std.testing.expect(cost > writer.len);
    turn.budget.work = cost;
    peer.work = cost - 1;
    try std.testing.expectEqual(Progress.credits, try driver.processRpc(&g, session.index, &turn, &peer));
    try std.testing.expectEqual(cost, turn.budget.work);
    try std.testing.expectEqual(@as(u16, 0), io.ihave_recv);
    peer.work = cost;
    try std.testing.expectEqual(Progress.done, try driver.processRpc(&g, session.index, &turn, &peer));
    try std.testing.expectEqual(@as(usize, 0), turn.budget.work);
    try std.testing.expectEqual(@as(usize, 0), peer.work);
    try std.testing.expectEqual(@as(u16, 1), io.ihave_recv);
    try std.testing.expect(io.rpc.?.item == null);
    try std.testing.expectEqual(@as(usize, 1), g.recovery.len);
    try std.testing.expect(!g.sessions.finishFrame(io));
    io.startRpc(writer.written());
    turn = @import("turn.zig").Turn.init(&g.options, turn.now, &.{});
    peer = Credits.peer(&g.options);
    try std.testing.expectEqual(Progress.done, try driver.processRpc(&g, session.index, &turn, &peer));
    try std.testing.expectEqual(@as(usize, 1), g.recovery.len);
}

test "gossipsub IHAVE maximum advertisement shares oversized allowance with data and makes progress" {
    const small = try @import("../configuration.zig").resolve(.{ .profile = .small, .seed = 1, .forks = &.{}, .admission_policy = @import("../reqresp/policy_fixture.zig").config() });
    var options = small.core.service.gossipsub;
    options.work_per_pump = 1;
    options.decompress_per_peer_bytes = 1;
    var g = try support.init(std.testing.allocator, options);
    defer g.deinit();
    const session = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, name);
    const bytes = try std.testing.allocator.alloc(u8, 128 * 1024);
    defer std.testing.allocator.free(bytes);
    var writer = protobuf.Writer.init(bytes);
    const wire_pb = @import("../wire/protobuf.zig");
    const long = wire_pb.bytesFieldSize(1, name.len) + constants.max_ihave_ids_per_heartbeat * wire_pb.bytesFieldSize(2, constants.message_id_length);
    const short = wire_pb.bytesFieldSize(1, name.len) + wire_pb.bytesFieldSize(2, constants.message_id_length);
    writer.tag(3, protobuf.wire_len);
    writer.varint(wire_pb.bytesFieldSize(1, long) + wire_pb.bytesFieldSize(1, short));
    writer.tag(1, protobuf.wire_len);
    writer.varint(long);
    writer.bytesField(1, name);
    const id: MessageId = @splat(7);
    for (0..constants.max_ihave_ids_per_heartbeat) |_| protobuf.writeIhaveId(&writer, &id);
    writer.tag(1, protobuf.wire_len);
    writer.varint(short);
    writer.bytesField(1, name);
    protobuf.writeIhaveId(&writer, &id);
    var compressed: [64]u8 = undefined;
    const len = try snappy.raw.compress("payload", &compressed);
    protobuf.writeMessage(&writer, compressed[0..len], name);
    const io = &g.sessions.rows[session.index].io;
    io.startRpc(writer.written());
    const driver = @import("session_io.zig");
    var inbox: support.Inbox = .{};
    defer inbox.deinit();
    inbox.attach(&g);
    var scratch: [64]u8 = undefined;
    var turn = @import("turn.zig").Turn.init(&g.options, .{ .mono_ms = 1, .unix_s = 0 }, &scratch);
    turn.sink = g.message_sink;
    var peer = Credits.peer(&g.options);
    try std.testing.expectEqual(Progress.credits, try driver.processRpc(&g, session.index, &turn, &peer));
    try std.testing.expect(turn.large_used);
    try std.testing.expectEqual(@as(usize, 1), g.recovery.len);
    try std.testing.expectEqual(@as(u16, 1), io.ihave_recv);
    turn = @import("turn.zig").Turn.init(&g.options, .{ .mono_ms = 2, .unix_s = 0 }, &scratch);
    turn.sink = g.message_sink;
    peer = Credits.peer(&g.options);
    try std.testing.expectEqual(Progress.credits, try driver.processRpc(&g, session.index, &turn, &peer));
    try std.testing.expect(turn.large_used);
    try std.testing.expectEqual(@as(u16, 2), io.ihave_recv);
    turn = @import("turn.zig").Turn.init(&g.options, .{ .mono_ms = 3, .unix_s = 0 }, &scratch);
    turn.sink = g.message_sink;
    peer = Credits.peer(&g.options);
    try std.testing.expectEqual(Progress.done, try driver.processRpc(&g, session.index, &turn, &peer));
    try std.testing.expectEqual(@as(usize, 1), inbox.count);
    try std.testing.expectEqualStrings("payload", inbox.last().bytes);
    try std.testing.expect(turn.large_used);
    try std.testing.expectEqual(@as(u16, 2), io.ihave_recv);
    try std.testing.expectEqual(@as(usize, 1), g.recovery.len);
}

test "gossip pending validation quota preserves room for another peer and refunds completed work" {
    var boundary: @import("topic_policy.zig").Boundary = .{ .digest = .{ 1, 2, 3, 4 } };
    boundary.rules[@intFromEnum(topic_mod.Kind.beacon_block)] = .{ .count = 1, .ssz_max = 1024 };
    for ([_]bool{ false, true }) |planned| {
        var g = try support.init(std.testing.allocator, .{ .random_seed = 1, .topic_policy = &.{boundary}, .validation_capacity = if (planned) 4 * @import("../gossip_limits.zig").kind_count else 4, .processor_limits = if (planned) @as(@import("../gossip_limits.zig").Limits, @splat(.{ .items = 4, .bytes = 4096 })) else null });
        defer g.deinit();
        const first = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
        const second = support.addPeer(&g, .{ .index = 1, .generation = 1 }, .v1_2).?;
        try support.subscribe(&g, "/eth2/01020304/beacon_block/ssz_snappy");
        var inbox: support.Inbox = .{};
        defer inbox.deinit();
        inbox.attach(&g);
        try std.testing.expectEqual(@as(?usize, 1), try testMessage(&g, first.index, "first", 1));
        const held = inbox.last().handle;
        try std.testing.expectEqual(@as(?usize, 1), try testMessage(&g, first.index, "second", 2));
        try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, first.index, "third", 3));
        try std.testing.expectEqual(@as(u64, 1), g.messages.storage_refusals[@intFromEnum(@import("messages.zig").StorageRefusal.peer_validations)]);
        try std.testing.expectEqual(@as(f64, 0), g.peers.score(g.sessions.rows[first.index].logical, 3));
        try std.testing.expectEqual(@as(?usize, 1), try testMessage(&g, second.index, "other peer", 4));
        try std.testing.expectEqual(ReportOutcome{ .applied = .ignore }, g.report(held, .ignore, .{ .mono_ms = 5, .unix_s = 0 }));
        try std.testing.expectEqual(@as(?usize, 1), try testMessage(&g, first.index, "third", 6));
    }
}

test "gossip unsent IWANT expiry refunds recovery slots without blaming the peer" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const peer = support.addPeer(&g, conn, .v1_2).?;
    const logical = g.sessions.rows[peer.index].logical;
    const capacity = g.recovery.available();
    g.recovery.add(&g.peers, @splat(1), logical, conn, 1, 100);
    try std.testing.expectEqual(@as(u32, 1), g.peers.rows[logical.index].pins);
    g.recovery.controlSent(conn, 1, 3000, 100);
    @import("session_io.zig").finishPump(&g, .{ .mono_ms = 100, .unix_s = 0 });
    try std.testing.expectEqual(capacity, g.recovery.available());
    try std.testing.expectEqual(@as(u32, 0), g.peers.rows[logical.index].pins);
    try std.testing.expectEqual(@as(u64, 0), g.counters.broken_promises);
    try std.testing.expectEqual(@as(?u64, null), g.recovery.nextExpiry());
}

test "gossip paged RPC cursors survive shared workspace reuse without runtime allocation" {
    var ledger: @import("../reservations.zig").Reservations = .{ .backing = std.testing.allocator };
    var g = try support.init(ledger.allocator(), .{
        .random_seed = 1,
        .connected_capacity = 4,
        .retained_capacity = 8,
        .retained_outbound_reserve = 1,
        .body_buffer_bytes = 2,
    });
    defer g.deinit();
    const calls = ledger.allocation_calls;
    ledger.byte_limit = ledger.bytes;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, name);
    for (0..4) |i| {
        const peer = support.addPeer(&g, .{ .index = @intCast(i), .generation = 1 }, .v1_2).?;
        try std.testing.expectEqual(i, peer.index);
    }
    var prefix: [8]u8 = undefined;
    var pw = protobuf.Writer.init(&prefix);
    pw.varint(@import("constants.zig").GOSSIP_MAX_SIZE);
    for (0..2) |i| try feedPagedTestFrame(&g, @intCast(i), pw.written());
    try std.testing.expectEqual(g.sessions.receive_pool.next.len, g.sessions.receive_pool.free_pages);
    for (0..2) |i| try feedPagedTestFrame(&g, @intCast(i), "slow");
    try std.testing.expectEqual(g.sessions.receive_pool.next.len - 2, g.sessions.receive_pool.free_pages);

    var payloads: [4][6000]u8 = undefined;
    var rng = std.Random.DefaultPrng.init(947);
    for (&payloads) |*payload| rng.random().bytes(payload);
    var compressed: [8192]u8 = undefined;
    var body: [16384]u8 = undefined;
    var wire: [16388]u8 = undefined;
    for (0..2) |i| {
        var writer = protobuf.Writer.init(&body);
        for (0..2) |j| {
            const len = try @import("snappy").raw.compress(&payloads[i * 2 + j], &compressed);
            protobuf.writeMessage(&writer, compressed[0..len], name);
        }
        try feedPagedTestFrame(&g, @intCast(i + 2), @import("frame.zig").writeFrame(&wire, writer.written()));
        try std.testing.expect(g.sessions.rows[i + 2].io.rpc != null);
    }
    var inbox: support.Inbox = .{};
    defer inbox.deinit();
    inbox.attach(&g);
    const now: Now = .{ .mono_ms = 2, .unix_s = 1 };
    for (0..2) |round| {
        for (0..2) |i| {
            var count: usize = 0;
            // One item credit pauses each RPC after its first message; two finish it.
            var items: usize = 1 + round;
            const done = try support.processRpc(&g, @intCast(i + 2), now, &count, &items);
            try std.testing.expectEqual(round == 1, done);
            try std.testing.expectEqual(@as(usize, 1), count);
            try std.testing.expectEqualSlices(u8, &payloads[i * 2 + round], inbox.last().bytes);
            @memset(g.sessions.decode_scratch, 0xa5);
            try std.testing.expectEqualSlices(u8, &payloads[i * 2 + round], inbox.last().bytes);
            _ = g.report(inbox.last().handle, .ignore, now);
            if (done) _ = g.sessions.finishFrame(&g.sessions.rows[i + 2].io);
        }
    }
    for (0..2) |i| try std.testing.expect(g.sessions.resetRx(@intCast(i)));
    try std.testing.expectEqual(g.sessions.receive_pool.next.len, g.sessions.receive_pool.free_pages);
    try std.testing.expectEqual(calls, ledger.allocation_calls);
}

fn feedPagedTestFrame(g: *Gossipsub, index: u16, wire: []const u8) !void {
    const io = &g.sessions.rows[index].io;
    var offset: usize = 0;
    for (0..wire.len + 1) |_| {
        if (offset == wire.len) return;
        const take = @min(io.unread.len, wire.len - offset);
        @memcpy(io.unread[0..take], wire[offset..][0..take]);
        io.unread_start = 0;
        io.unread_end = take;
        for (0..take + 1) |_| {
            if (io.unread_start == io.unread_end) break;
            const result = try io.feedUnread(&g.sessions.receive_pool, io.unread_end - io.unread_start, 1);
            try std.testing.expect(result.consumed > 0);
        }
        offset += take;
    }
    unreachable;
}

test "gossip counts each consumed message once by topic kind and never on a work retry" {
    var g = try support.init(std.testing.allocator, .{ .random_seed = 1 });
    defer g.deinit();
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try support.subscribe(&g, name);
    var inbox: support.Inbox = .{};
    defer inbox.deinit();
    inbox.attach(&g);
    var compressed: [64]u8 = undefined;
    const message: protobuf.Message = .{ .topic = name, .data = compressed[0..try snappy.raw.compress("payload", &compressed)] };
    const now: Now = .{ .mono_ms = 1, .unix_s = 0 };
    var turn = @import("turn.zig").Turn.init(&g.options, now, g.msg_scratch);
    turn.sink = g.message_sink;
    turn.large_used = true;
    turn.budget.work = 0;
    var credits = Credits.peer(&g.options);
    try std.testing.expectEqual(Progress.credits, g.receiveItem(g.sessions.ref(peer.index), .{ .message = message }, &turn, &credits));
    const counts = g.topic_metrics.get(name);
    try std.testing.expectEqual(@as(u64, 0), counts.received);
    try std.testing.expectEqual(@as(?usize, 1), receiveForTest(&g, peer.index, message, now));
    try std.testing.expectEqual(@as(?usize, 0), receiveForTest(&g, peer.index, message, now));
    try std.testing.expectEqual(@as(?usize, 0), receiveForTest(&g, peer.index, .{ .topic = name, .data = &.{5} }, now));
    try std.testing.expectEqual(@as(f64, 1), support.invalidDeliveries(&g));
    inbox.full = true;
    try std.testing.expectEqual(@as(?usize, 0), try testMessage(&g, peer.index, "refused", 1));
    try std.testing.expectEqual(@as(u64, 1), g.messages.storage_refusals[@intFromEnum(@import("messages.zig").StorageRefusal.processor_capacity)]);
    try std.testing.expectEqual(@as(u64, 4), counts.received);
    try std.testing.expectEqual(@as(u64, 1), counts.duplicate);
    const unsubscribed = "/eth2/01020304/voluntary_exit/ssz_snappy";
    const unknown = "/eth2/01020304/beacon_blocks/ssz_snappy";
    for ([_][]const u8{ unsubscribed, unknown, unknown }) |topic| {
        try std.testing.expectEqual(@as(?usize, 0), receiveForTest(&g, peer.index, .{ .topic = topic, .data = message.data }, now));
    }
    try std.testing.expectEqual(@as(u64, 1), g.topic_metrics.get(unsubscribed).received);
    try std.testing.expectEqual(@as(u64, 2), g.topic_metrics.counts[@import("topic_policy.zig").kind_count].received);
    try std.testing.expectEqual(@as(u64, 4), counts.received);
    for (g.topic_metrics.counts) |kind| try std.testing.expectEqual(@as(u64, 0), kind.published);
}
