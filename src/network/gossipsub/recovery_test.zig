const Handle = @import("../quic/engine.zig").Handle;
const MessageId = @import("topic.zig").MessageId;
const Peers = @import("peer_book.zig").PeerBook;
const Recovery = @import("recovery.zig").Recovery;
const constants = @import("constants.zig");
const std = @import("std");

test "recovery receipts bind connection generation and token and release only cancelled pins" {
    const allocator = std.testing.allocator;
    var peers = try Peers.init(allocator, &.{ .retained_score_ms = 10_000, .retained_capacity = 2, .retained_outbound_reserve = 1 });
    defer peers.deinit(allocator);
    var recovery = try Recovery.init(allocator);
    defer recovery.deinit(allocator, &peers);
    const connection: Handle = .{ .index = 0, .generation = 1 };
    const next_connection: Handle = .{ .index = 0, .generation = 2 };
    const metadata: @import("peer_book.zig").Metadata = .{
        .identity = .{ .bytes = [_]u8{1} ** @import("../wire/peer_id.zig").length },
        .address = .unspecified,
        .direction = .inbound,
    };
    const peer = peers.admit(connection, &metadata, 0).admitted.peer;
    recovery.add(&peers, [_]u8{1} ** 20, peer, connection, 7, 30_000);
    recovery.add(&peers, [_]u8{2} ** 20, peer, connection, 8, 30_000);
    recovery.controlSent(next_connection, 7, 3000, 10);
    recovery.controlSent(connection, 6, 3000, 10);
    try std.testing.expectEqual(@as(?u64, 30_000), recovery.nextExpiry());
    try std.testing.expectEqual(@as(u64, 0), recovery.metrics.sent);
    recovery.controlSent(connection, 7, 3000, 20);
    try std.testing.expectEqual(@as(?u64, 3020), recovery.nextExpiry());
    try std.testing.expectEqual(@as(u64, 0), recovery.cancel(&peers, next_connection, true));
    try std.testing.expectEqual(@as(u64, 1), recovery.cancel(&peers, connection, false));
    try std.testing.expectEqual(@as(u32, 1), peers.rows[peer.index].pins);
    recovery.controlSent(connection, 7, 3000, 200);
    recovery.controlSent(connection, 8, 3000, 200);
    try std.testing.expectEqual(@as(?u64, 3020), recovery.nextExpiry());
    try std.testing.expectEqual(@as(u64, 1), recovery.metrics.sent);
    try std.testing.expectEqual(@as(u64, 1), recovery.cancel(&peers, connection, true));
    try std.testing.expectEqual(@as(u32, 0), peers.rows[peer.index].pins);
    try std.testing.expectEqual(@as(usize, constants.promises_cap), recovery.available());
    recovery.controlSent(connection, 7, 3000, 300);
    try std.testing.expect(recovery.nextExpiry() == null);
}

test "recovery capacity resolves every matching attribution and deinit releases remaining pins" {
    const allocator = std.testing.allocator;
    var peers = try Peers.init(allocator, &.{ .retained_score_ms = 10_000, .retained_capacity = 2, .retained_outbound_reserve = 1 });
    defer peers.deinit(allocator);
    const connection: Handle = .{ .index = 0, .generation = 1 };
    const metadata: @import("peer_book.zig").Metadata = .{
        .identity = .{ .bytes = [_]u8{1} ** @import("../wire/peer_id.zig").length },
        .address = .unspecified,
        .direction = .inbound,
    };
    const peer = peers.admit(connection, &metadata, 0).admitted.peer;
    {
        var recovery = try Recovery.init(allocator);
        defer recovery.deinit(allocator, &peers);
        for (0..constants.promises_cap) |_| recovery.add(&peers, [_]u8{1} ** 20, peer, connection, 7, 30_000);
        try std.testing.expectEqual(@as(usize, 0), recovery.available());
        recovery.resolve(&peers, [_]u8{1} ** 20, .{ .now_ms = 100 });
        try std.testing.expectEqual(@as(u32, 0), peers.rows[peer.index].pins);
        try std.testing.expectEqual(@as(u64, 0), recovery.metrics.resolved);
        recovery.add(&peers, [_]u8{2} ** 20, peer, connection, 8, 30_000);
    }
    try std.testing.expectEqual(@as(u32, 0), peers.rows[peer.index].pins);
}

test "recovery metrics distinguish incoming delivery from queued and locally resolved requests" {
    const allocator = std.testing.allocator;
    var peers = try Peers.init(allocator, &.{ .retained_score_ms = 10_000, .retained_capacity = 2, .retained_outbound_reserve = 1 });
    defer peers.deinit(allocator);
    var recovery = try Recovery.init(allocator);
    defer recovery.deinit(allocator, &peers);
    const connection: Handle = .{ .index = 0, .generation = 1 };
    const metadata: @import("peer_book.zig").Metadata = .{
        .identity = .{ .bytes = [_]u8{1} ** @import("../wire/peer_id.zig").length },
        .address = .unspecified,
        .direction = .inbound,
    };
    const peer = peers.admit(connection, &metadata, 0).admitted.peer;
    const id = [_]u8{1} ** 20;
    recovery.add(&peers, id, peer, connection, 1, 30_000);
    recovery.add(&peers, id, peer, connection, 2, 30_000);
    recovery.controlSent(connection, 1, 3000, 100);
    recovery.controlSent(connection, 1, 3000, 200);
    recovery.resolve(&peers, id, .{ .now_ms = 600 });
    recovery.resolve(&peers, id, .{ .now_ms = 700 });
    try std.testing.expectEqual(@as(u64, 1), recovery.metrics.sent);
    try std.testing.expectEqual(@as(u64, 1), recovery.metrics.resolved);
    try std.testing.expectEqual(@as(u64, 0), recovery.metrics.resolved_duplicate);
    try std.testing.expectEqual(@as(u128, 500), recovery.metrics.delivery.sum);
    recovery.add(&peers, id, peer, connection, 3, 30_000);
    recovery.controlSent(connection, 3, 3000, 1000);
    recovery.resolve(&peers, id, .{ .now_ms = 1100, .duplicate = true });
    recovery.add(&peers, id, peer, connection, 4, 30_000);
    recovery.controlSent(connection, 4, 3000, 1200);
    recovery.resolve(&peers, id, null);
    try std.testing.expectEqual(@as(u64, 3), recovery.metrics.sent);
    try std.testing.expectEqual(@as(u64, 2), recovery.metrics.resolved);
    try std.testing.expectEqual(@as(u64, 1), recovery.metrics.resolved_duplicate);
    try std.testing.expectEqual(@as(u64, 2), recovery.metrics.delivery.count);
    try std.testing.expectEqual(@as(u128, 600), recovery.metrics.delivery.sum);
    try std.testing.expectEqual(@as(u32, 0), peers.rows[peer.index].pins);
}

test "recovery batches pin identity once and score one randomly selected promise" {
    const a = std.testing.allocator;
    var peers = try Peers.init(a, &.{ .retained_score_ms = 10000, .retained_capacity = 2, .retained_outbound_reserve = 1 });
    defer peers.deinit(a);
    var recovery = try Recovery.init(a);
    defer recovery.deinit(a, &peers);
    const connection: Handle = .{ .index = 0, .generation = 1 };
    const metadata: @import("peer_book.zig").Metadata = .{ .identity = .{ .bytes = @splat(1) }, .address = .unspecified, .direction = .inbound };
    const peer = peers.admit(connection, &metadata, 0).admitted.peer;
    var ids: [constants.gossip_ids_max]MessageId = undefined;
    for (&ids, 0..) |*id, i| id.* = @splat(@intCast(i));
    recovery.addBatch(&peers, &ids, peer, connection, 1, 64, 30_000);
    try std.testing.expectEqual(@as(u32, 1), peers.rows[peer.index].pins);
    try std.testing.expectEqual(@as(u64, 0), recovery.expire(&peers, 20000));
    recovery.controlSent(connection, 1, 3000, 20000);
    try std.testing.expectEqual(@as(u64, 1), recovery.expire(&peers, 23000));
    try std.testing.expectEqual(@as(u64, 1), peers.scores.penalties.broken_promise);
    try std.testing.expectEqual(@as(u64, 128), recovery.metrics.expired_ids);
    try std.testing.expectEqual(@as(u32, 0), peers.rows[peer.index].pins);
    recovery.addBatch(&peers, &ids, peer, connection, 2, 64, 30_000);
    recovery.controlSent(connection, 2, 3000, 24000);
    recovery.resolve(&peers, ids[64], .{ .now_ms = 25000 });
    try std.testing.expectEqual(@as(usize, 127), recovery.len);
    try std.testing.expectEqual(@as(u32, 1), peers.rows[peer.index].pins);
    try std.testing.expectEqual(@as(u64, 0), recovery.expire(&peers, 27000));
    try std.testing.expectEqual(@as(u64, 1), peers.scores.penalties.broken_promise);
    try std.testing.expectEqual(@as(u64, 255), recovery.metrics.expired_ids);
    try std.testing.expectEqual(@as(u64, 2), recovery.metrics.batches_sent);
    try std.testing.expectEqual(@as(usize, constants.promises_cap), recovery.available());
    try std.testing.expectEqual(@as(u32, 0), peers.rows[peer.index].pins);
}
