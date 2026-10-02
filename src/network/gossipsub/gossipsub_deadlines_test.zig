const support = @import("test_support.zig");
const std = @import("std");
const Pair = @import("test_pair.zig").Pair;
const Penalty = @import("score.zig").Penalty;
const test_topic = "/eth2/01020304/beacon_block/ssz_snappy";

test "gossipsub large frame deadline releases receive pages despite byte progress" {
    var setup: Pair = .{};
    try setup.initOpts(.{ .random_seed = 1, .output_per_peer = 1, .tx_timeout_ms = 500 }, .{ .random_seed = 1, .body_buffer_bytes = 64, .large_frame_timeout_ms = 150, .pressure_timeout_ms = 500 });
    defer setup.deinit();
    for (0..16) |_| try setup.pumpOnce();
    const server_peer = setup.shared.server.gossipsub.sessions.find(setup.shared.handles.server).?;
    const client_peer = setup.shared.client.gossipsub.sessions.find(setup.shared.handles.client).?;
    var prefix: [128]u8 = undefined;
    var w = @import("protobuf.zig").Writer.init(&prefix);
    w.varint(65536);
    w.bytes(&([_]u8{'x'} ** 65));
    try std.testing.expectEqual(w.len, try setup.shared.pair.client.write(setup.clientStream(), w.written(), false));
    for (0..4) |_| try setup.pumpOnce();
    try std.testing.expect(setup.shared.server.gossipsub.sessions.rows[server_peer].io.reader.declaredLen() != null);
    try std.testing.expectEqual(@as(u32, 1), setup.shared.server.gossipsub.sessions.rows[server_peer].io.overflow.pages);
    try support.subscribe(setup.shared.client.gossipsub, test_topic);
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
    try std.testing.expect(setup.shared.server.gossipsub.sessions.rows[server_peer].io.overflow.pages == 0);
    const logical = setup.shared.server.gossipsub.sessions.rows[server_peer].logical;
    try std.testing.expect(setup.shared.server.gossipsub.peers.rows[logical.index].large_frame_denied_until > setup.shared.pair.now.mono_ms);
    try std.testing.expectEqual(@as(u64, 1), setup.shared.server.gossipsub.peers.scores.penalties[@intFromEnum(Penalty.large_frame_timeout)]);
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
    try setup.connectMesh();
    const g = setup.shared.server.gossipsub;
    const index = g.sessions.find(setup.shared.handles.server).?;
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
    try std.testing.expect(peer.io.rpc == null);
    try std.testing.expectEqual(@as(usize, 0), g.recovery.len);
    try std.testing.expectEqual(@as(u64, 0), g.counters.broken_promises);
    try std.testing.expectEqual(before, g.peers.score(peer.logical, setup.shared.pair.now.mono_ms));
    try std.testing.expectEqual(@as(u64, 0), g.peers.rows[peer.logical.index].large_frame_denied_until);
    try std.testing.expectEqual(g.sessions.receive_pool.next.len, g.sessions.receive_pool.free_pages);
    try std.testing.expect(peer.in_stream != null and peer.outStream() != null);
}

test "gossipsub healthy continuous frame turnover does not expire a nonempty queue" {
    var setup: Pair = .{};
    try setup.initOpts(.{ .random_seed = 1, .calls_per_peer = 1, .tx_timeout_ms = 500 }, .{
        .random_seed = 1,
    });
    defer setup.deinit();
    try setup.connectMesh();
    const index = setup.shared.client.gossipsub.sessions.find(setup.shared.handles.client).?;
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
    try std.testing.expect(setup.shared.client.gossipsub.sessions.outStream(index) != null);
}

test "gossipsub discarding a locally refused frame preserves its deadline without blaming the peer" {
    var setup: Pair = .{};
    try setup.initOpts(.{ .random_seed = 1 }, .{ .random_seed = 1, .body_buffer_bytes = 1024, .large_frame_timeout_ms = 200 });
    defer setup.deinit();
    try setup.connectMesh();
    const g = setup.shared.server.gossipsub;
    var held: [3]@import("receive_pool.zig").Chain = @splat(.{});
    defer for (&held) |*chain| g.sessions.receive_pool.release(chain);
    for (0..g.sessions.receive_pool.next.len) |i| {
        const chain = &held[i % held.len];
        _ = g.sessions.receive_pool.writable(chain).?;
        chain.len += @import("receive_pool.zig").page_bytes;
    }
    const index = g.sessions.find(setup.shared.handles.server).?;
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
    try std.testing.expectEqual(@as(u64, 1), g.counters.local_pressure_resets);
    try std.testing.expectEqual(before, g.peers.score(peer.logical, setup.shared.pair.now.mono_ms));
    try std.testing.expectEqual(@as(u64, 0), g.peers.rows[peer.logical.index].large_frame_denied_until);
    for (g.peers.scores.penalties) |count| try std.testing.expectEqual(@as(u64, 0), count);
}
