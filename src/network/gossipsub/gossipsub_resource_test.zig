const std = @import("std");
const gossip = @import("gossipsub.zig");
const support = @import("test_support.zig");
const delivery = @import("delivery.zig");
const name = "/eth2/01020304/beacon_block/ssz_snappy";
const options: gossip.Options = .{ .random_seed = 1, .connected_capacity = 3, .retained_capacity = 4, .retained_outbound_reserve = 1, .validation_capacity = 1, .mcache_capacity = 2, .seen_capacity = 4 };

test "gossip validation finishes without allocation while shared deliveries are full" {
    var allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var g = try support.init(allocator.allocator(), options);
    defer g.deinit();
    try support.subscribe(&g, name);
    const topic = g.overlay.findTopic(name).?;
    const message = g.messages.publish(@splat(1), name, "retained", 0, 0).?;
    for (0..3) |i| {
        const conn: @import("../quic/Engine.zig").Handle = .{ .index = @intCast(i), .generation = 1 };
        const session = support.addPeer(&g, conn, .v1_2).?;
        g.sessions.rows[session.index].outbound = .{ .live = .{ .stream = .{ .conn = conn, .id = 2, .slot = 0 }, .version = .v1_2 } };
        g.overlay.rows[topic].mesh.set(i);
        const count: usize = if (i == 0) delivery.per_peer_limit else delivery.per_peer_reserve;
        const tx = &g.sessions.rows[i].io.tx;
        for (0..count) |_| {
            const origin: delivery.Origin = if (tx.data.full()) .publication else .forward;
            try std.testing.expectEqual(.queued, tx.queueData(&g.messages.store, message, origin, .{ .bytes = g.options.tx_peer_bytes }, 0));
        }
    }
    const occupied = g.resourceSnapshot();
    try std.testing.expectEqual(occupied.delivery_descriptors_capacity, occupied.queued_descriptors);
    allocator.fail_index = allocator.alloc_index;
    var compressed: [64]u8 = undefined;
    const len = try @import("snappy").raw.compress("valid message", &compressed);
    const now: @import("../types.zig").Now = .{ .mono_ms = 1, .unix_s = 0 };
    var inbox: support.Inbox = .{};
    defer inbox.deinit();
    inbox.attach(&g);
    var turn = @import("session_io.zig").beginPump(&g, now);
    var credits = @import("turn.zig").Credits.peer(&g.options);
    try std.testing.expectEqual(.done, g.receiveItem(g.sessions.ref(0), .{ .message = .{ .topic = name, .data = compressed[0..len] } }, &turn, &credits));
    try std.testing.expectEqual(@as(usize, 1), inbox.count);
    try std.testing.expectEqualDeep(gossip.ReportOutcome{ .applied = .accept }, g.report(inbox.last().handle, .accept, now));
    try std.testing.expect(g.messages.hasPayload(inbox.last().id));
    try std.testing.expectEqual(@as(usize, 0), g.resourceSnapshot().pending_validations);
    try std.testing.expectEqual(@as(u64, 2), g.delivery_metrics.recipients[@intFromEnum(delivery.Origin.forward)][@intFromEnum(@import("metrics.zig").Delivery.Outcome.pressured)]);
    const old = g.sessions.ref(1);
    g.connectionClosed(g.sessions.rows[1].conn);
    const replacement = support.addPeer(&g, .{ .index = 1, .generation = 2 }, .v1_2).?;
    try std.testing.expect(replacement.generation != old.generation);
    g.cancelWrites(old);
    try std.testing.expectEqual(@as(usize, delivery.per_peer_reserve), g.sessions.deliveries.available);
    try std.testing.expectEqual(allocator.fail_index, allocator.alloc_index);
}

test "gossip recovery refusal restores promise slots and identity pins before returning" {
    var g = try support.init(std.testing.allocator, options);
    defer g.deinit();
    const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
    const row = &g.sessions.rows[peer.index];
    const bytes = g.msg_scratch[0..row.io.tx.control.bytes.len];
    @memset(bytes, 1);
    try std.testing.expect(row.io.tx.inject(bytes, 0));
    const available = g.recovery.available();
    var ids: [2]gossip.MessageId = .{ @splat(1), @splat(2) };
    _ = try g.recovery.filterPending(row.logical, &ids);
    try std.testing.expectError(error.OutboxFull, g.recovery.requestBatch(&g.peers, &row.io.tx, &g.sessions.control_scratch, &ids, row.logical, row.conn, g.overlay.rng.random(), g.options.iwant_followup_ms, 1));
    try std.testing.expectEqual(available, g.recovery.available());
    try std.testing.expectEqual(@as(usize, 0), g.recovery.batch_len);
    try std.testing.expect(std.mem.allEqual(u16, g.recovery.buckets, std.math.maxInt(u16)));
    try std.testing.expectEqual(@as(u32, 0), g.peers.rows[row.logical.index].pins);
    try std.testing.expect(row.io.tx.submit(&.{ .graft = name }, &g.sessions.control_scratch, 1) != null);
    row.io.tx.cancelStream(&g.messages.store);
    _ = try g.recovery.filterPending(row.logical, &ids);
    try g.recovery.requestBatch(&g.peers, &row.io.tx, &g.sessions.control_scratch, &ids, row.logical, row.conn, g.overlay.rng.random(), g.options.iwant_followup_ms, 2);
    try std.testing.expectEqual(@as(usize, 2), g.recovery.len);
    try std.testing.expectEqual(g.recovery.buckets.len - 2, std.mem.count(u16, g.recovery.buckets, &.{std.math.maxInt(u16)}));
    try std.testing.expectEqual(@as(u32, 1), g.peers.rows[row.logical.index].pins);
    g.cancelWrites(peer);
    try std.testing.expectEqual(available, g.recovery.available());
    try std.testing.expect(std.mem.allEqual(u16, g.recovery.buckets, std.math.maxInt(u16)));
    try std.testing.expectEqual(@as(u32, 0), g.peers.rows[row.logical.index].pins);
}
