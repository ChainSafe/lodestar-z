const Handle = Engine.Handle;
const MessageId = [constants.message_id_length]u8;
const Sessions = @import("sessions.zig").Sessions;
const constants = @import("constants.zig");
const std = @import("std");
const Engine = @import("../quic/Engine.zig");

test "session slots track connection generations" {
    var sessions = try std.testing.allocator.create(Sessions);
    defer std.testing.allocator.destroy(sessions);
    sessions.* = try @import("test_support.zig").sessions(std.testing.allocator, constants.peers_cap);
    defer sessions.deinit(std.testing.allocator);
    const conn = Handle{ .index = 3, .generation = 1 };
    const peer = sessions.addPeer(conn).?;
    try std.testing.expectEqual(@as(?u16, peer.index), sessions.find(conn));

    sessions.removePeer(peer.index);
    try std.testing.expectEqual(@as(?u16, null), sessions.find(conn));
}

test "sessions suppresses ids per peer until monotonic expiry" {
    var sessions = try std.testing.allocator.create(Sessions);
    defer std.testing.allocator.destroy(sessions);
    sessions.* = try @import("test_support.zig").sessions(std.testing.allocator, constants.peers_cap);
    defer sessions.deinit(std.testing.allocator);
    const peer = sessions.addPeer(.{ .index = 1, .generation = 1 }).?;
    const id = [_]u8{7} ** 20;
    try std.testing.expect(!sessions.suppresses(peer.index, id, 0));
    sessions.suppress(peer.index, id, 0, 10);
    try std.testing.expect(!sessions.suppresses(peer.index, id, 10));
    try std.testing.expect(sessions.suppresses(peer.index, id, 0));
}

test "gossip stream cancellation discards unsent work and session reuse preserves receipt identity" {
    const a = std.testing.allocator;
    var sessions = try @import("test_support.zig").sessions(a, 1);
    defer sessions.deinit(a);
    var store = try @import("message_store.zig").Store.init(a, 1, 4096);
    defer store.deinit(a);
    const conn: Handle = .{ .index = 0, .generation = 1 };
    const first = sessions.addPeer(conn).?;
    const peer = &sessions.rows[first.index];
    const id: MessageId = @splat(1);
    peer.suppress(id, 1, 100);
    peer.io.ihave_recv = 10;
    peer.io.write_first = true;
    peer.io.tx.control_burst = 4;
    peer.io.tx.subscriptionChanged(0, 1);
    const token = peer.io.tx.injectFrame("frame", false, 1).?;
    peer.io.tx.drops[0] = 3;
    peer.io.tx.cancelStream(&store);
    try std.testing.expectEqual(@as(usize, 0), peer.io.tx.subscription_dirty.count());
    try std.testing.expectEqual(@as(u8, 0), peer.io.tx.control_burst);
    try std.testing.expect(peer.suppresses(id, 2));
    sessions.removePeer(first.index);
    const next = sessions.addPeer(conn).?;
    try std.testing.expectEqual(first.index, next.index);
    try std.testing.expect(next.generation > first.generation);
    try std.testing.expect(!sessions.matches(first));
    try std.testing.expect(!peer.suppresses(id, 2));
    try std.testing.expectEqual(@as(u16, 0), peer.io.ihave_recv);
    try std.testing.expect(!peer.io.write_first);
    try std.testing.expectEqual(@as(u8, 0), peer.io.tx.control_burst);
    try std.testing.expectEqual(@as(usize, 0), peer.io.tx.subscription_dirty.count());
    try std.testing.expectEqual(@as(u64, 3), peer.io.tx.drops[0]);
    try std.testing.expect(peer.io.tx.injectFrame("next", false, 2).? > token);
    peer.io.tx.cancelStream(&store);
}
