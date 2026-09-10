const std = @import("std");
const gossip = @import("gossipsub.zig");
const support = @import("test_support.zig");
const delivery = @import("delivery.zig");
const name = "/eth2/01020304/beacon_block/ssz_snappy";
const options: gossip.Options = .{ .random_seed = 1, .connected_capacity = 3, .retained_capacity = 4, .retained_outbound_reserve = 1, .validation_capacity = 1, .mcache_capacity = 2, .seen_capacity = 4 };

test "gossip validation finishes without allocation while shared deliveries are full" {
    var allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var g = try gossip.Gossipsub.init(allocator.allocator(), options);
    defer g.deinit();
    try std.testing.expect(g.subscribe(name));
    const topic = g.overlay.findTopic(name).?;
    const message = g.messages.publish(@splat(1), name, "retained", 0, 0).?;
    for (0..3) |i| {
        const conn: @import("../quic/engine.zig").Handle = .{ .index = @intCast(i), .generation = 1 };
        const session = support.addPeer(&g, conn, .v1_2).?;
        g.sessions.rows[session.index].outbound = .{ .live = .{ .conn = conn, .id = 2, .slot = 0 } };
        g.overlay.rows[topic].mesh.set(i);
        const count: usize = if (i == 0) delivery.per_peer_limit else delivery.per_peer_reserve;
        for (0..count) |_| try std.testing.expectEqual(.queued, g.sessions.rows[i].io.tx.queueData(&g.messages.store, message, g.options.tx_peer_bytes, 0));
    }
    const occupied = g.resourceSnapshot();
    try std.testing.expectEqual(occupied.delivery_descriptors_capacity, occupied.queued_descriptors);
    allocator.fail_index = allocator.alloc_index;
    var compressed: [64]u8 = undefined;
    const len = try @import("snappy").raw.compress("valid message", &compressed);
    const now: @import("../types.zig").Now = .{ .mono_ms = 1, .unix_s = 0 };
    var events: [1]gossip.Event = undefined;
    var turn = g.beginPump(now, &events);
    var credits = @import("turn.zig").Credits.peer(&g.options);
    try std.testing.expectEqual(.done, g.receiveItem(g.sessions.ref(0), .{ .message = .{ .topic = name, .data = compressed[0..len] } }, &turn, &credits));
    try std.testing.expectEqual(@as(usize, 1), turn.count);
    try std.testing.expectEqualDeep(gossip.ReportOutcome{ .applied = .accept }, g.report(events[0].message.handle, .accept, now));
    try std.testing.expect(g.messages.hasPayload(events[0].message.id));
    try std.testing.expectEqual(@as(usize, 0), g.resourceSnapshot().pending_validations);
    try std.testing.expectEqual(@as(u64, 2), g.counters.send_dropped);
    const old = g.sessions.ref(1);
    g.connectionClosed(g.sessions.rows[1].conn);
    const replacement = support.addPeer(&g, .{ .index = 1, .generation = 2 }, .v1_2).?;
    try std.testing.expect(replacement.generation != old.generation);
    g.cancelWrites(old);
    try std.testing.expectEqual(@as(usize, delivery.per_peer_reserve), g.sessions.deliveries.available);
    try std.testing.expectEqual(allocator.fail_index, allocator.alloc_index);
}

test "gossip recovery refusal restores promise slots and identity pins before returning" {
    var g = try gossip.Gossipsub.init(std.testing.allocator, options);
    defer g.deinit();
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const row = &g.sessions.rows[peer.index];
    const bytes = g.msg_scratch[0..row.io.tx.control.bytes.len];
    @memset(bytes, 1);
    try std.testing.expect(row.io.tx.inject(bytes, 0));
    const available = g.recovery.available();
    var ids: [2]gossip.MessageId = .{ @splat(1), @splat(2) };
    try std.testing.expectError(error.OutboxFull, g.recovery.requestBatch(&g.peers, &row.io.tx, &ids, row.logical, row.conn, g.overlay.rng.random(), 1));
    try std.testing.expectEqual(available, g.recovery.available());
    try std.testing.expectEqual(@as(usize, 0), g.recovery.batch_len);
    try std.testing.expectEqual(@as(u32, 0), g.peers.rows[row.logical.index].pins);
    try std.testing.expect(row.io.tx.submit(&.{ .graft = name }, 1) != null);
    row.io.tx.reset(&g.messages.store);
    try std.testing.expectEqual(@as(usize, 2), try g.recovery.requestBatch(&g.peers, &row.io.tx, &ids, row.logical, row.conn, g.overlay.rng.random(), 2));
    try std.testing.expectEqual(@as(u32, 1), g.peers.rows[row.logical.index].pins);
    g.cancelWrites(peer);
    try std.testing.expectEqual(available, g.recovery.available());
    try std.testing.expectEqual(@as(u32, 0), g.peers.rows[row.logical.index].pins);
}

test "gossip optional subscription observations do not consume validation event capacity" {
    var config = options;
    config.observe_subscriptions = false;
    var g = try gossip.Gossipsub.init(std.testing.allocator, config);
    defer g.deinit();
    try std.testing.expect(g.subscribe(name));
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    var turn = g.beginPump(.{ .mono_ms = 1, .unix_s = 0 }, &.{});
    var credits = @import("turn.zig").Credits.peer(&g.options);
    try std.testing.expectEqual(.done, g.receiveItem(peer, .{ .subscription = .{ .topic = name, .subscribe = true } }, &turn, &credits));
    try std.testing.expectEqual(@as(usize, 0), turn.used);
    try std.testing.expect(g.overlay.subscribers(g.overlay.findTopic(name).?).isSet(peer.index));
    g.options.observe_subscriptions = true;
    try std.testing.expectEqual(.events, g.receiveItem(peer, .{ .subscription = .{ .topic = name, .subscribe = false } }, &turn, &credits));
    try std.testing.expect(g.overlay.subscribers(g.overlay.findTopic(name).?).isSet(peer.index));
}
