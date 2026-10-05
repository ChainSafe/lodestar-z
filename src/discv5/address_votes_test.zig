const std = @import("std");
const Votes = @import("AddressVotes.zig");
const types = @import("types.zig");
const message = @import("wire/message.zig");
const CallTable = @import("CallTable.zig");

fn peer(id: u16) types.Endpoint {
    var node: types.NodeId = @splat(0);
    std.mem.writeInt(u16, node[0..2], id, .big);
    return .{ .node_id = node, .address = .{ .ip4 = .{ .octets = .{ 203, @intCast(id >> 8), @truncate(id), 1 }, .port = 9000 } } };
}
fn pong(port: u16) message.Pong {
    return .{ .request_id = message.RequestId.init(&.{1}) catch unreachable, .enr_sequence = 1, .recipient_ip = .{ .ip4 = .{ 198, 51, 100, 1 } }, .recipient_port = port };
}

test "address votes need ten prefixes and a strict supermajority, retaining refreshed observations" {
    var votes: Votes = .{};
    votes.init(.{ .{ .enabled = true }, .{} });
    for (0..9) |i| try std.testing.expect(votes.observe(&peer(@intCast(i)), &pong(443), 0) == null);
    try std.testing.expect(votes.observe(&peer(9), &pong(80), 0) == null);
    try std.testing.expect(votes.needsSample(0, 0));
    try std.testing.expectEqual(@as(u16, 443), votes.observe(&peer(10), &pong(443), 1).?.port());
    try std.testing.expectEqual(@as(usize, 11), votes.count(0, 1));
    for (11..15) |i| _ = votes.observe(&peer(@intCast(i)), &pong(80), 1);
    try std.testing.expect(votes.observe(&peer(0), &pong(443), 2) == null);
    try std.testing.expect(votes.observe(&peer(15), &pong(443), 2) != null);
    try std.testing.expectEqual(@as(usize, 7), votes.count(0, Votes.lifetime_ms));
    try std.testing.expectEqual(@as(usize, 0), votes.count(0, Votes.lifetime_ms + 2));
}

test "node movement and multiple identities in one subnet cannot multiply votes" {
    var votes: Votes = .{};
    votes.init(.{ .{ .enabled = true }, .{} });
    _ = votes.observe(&peer(1), &pong(1), 0);
    var other = peer(2);
    other.address = peer(1).address;
    other.address.ip4.octets[3] = 2;
    _ = votes.observe(&other, &pong(1), 1);
    try std.testing.expectEqual(@as(usize, 1), votes.count(0, 1));
    _ = votes.observe(&peer(3), &pong(1), 1);
    other.address = peer(3).address;
    _ = votes.observe(&other, &pong(1), 2);
    try std.testing.expectEqual(@as(usize, 1), votes.count(0, 2));
    for (0..Votes.capacity + 1) |i| _ = votes.observe(&peer(@intCast(i)), &pong(1), 3 + i);
    try std.testing.expectEqual(@as(usize, Votes.capacity), votes.count(0, 204));
    try std.testing.expect(votes.canProbe(&peer(0), 204));
}

test "attempts do not vote and late local failure cannot erase successful evidence" {
    var votes: Votes = .{};
    votes.init(.{ .{ .enabled = true, .fixed_port = 443 }, .{} });
    const handle: CallTable.Handle = .{ .index = 0, .generation = 1 };
    votes.attempted(&peer(1), handle, 0);
    try std.testing.expectEqual(@as(usize, 0), votes.count(0, 0));
    try std.testing.expect(!votes.canProbe(&peer(1), 1));
    _ = votes.observe(&peer(1), &pong(80), 1);
    votes.localFailure(&peer(1), handle);
    for (2..11) |i| _ = votes.observe(&peer(@intCast(i)), &pong(@intCast(i)), 2);
    try std.testing.expectEqual(@as(u16, 443), votes.observe(&peer(1), &pong(1), 3).?.port());
    votes.attempted(&peer(20), handle, 3);
    votes.localFailure(&peer(20), handle);
    try std.testing.expect(votes.canProbe(&peer(20), 4));
    try std.testing.expect(votes.canProbe(&peer(1), Votes.lifetime_ms + 3));
}

test "observations enforce family scope and port, and IPv6 sources use /64" {
    var votes: Votes = .{};
    votes.init(.{ .{ .enabled = true }, .{ .enabled = true } });
    try std.testing.expect(votes.observe(&peer(1), &pong(0), 0) == null);
    var report = pong(443);
    report.recipient_ip = .{ .ip4 = .{ 127, 0, 0, 1 } };
    try std.testing.expect(votes.observe(&peer(1), &report, 0) == null);
    report.recipient_ip = .{ .ip6 = .{ 0x20, 1 } ++ .{0} ** 13 ++ .{1} };
    try std.testing.expect(votes.observe(&peer(1), &report, 0) == null);
    var source = peer(1);
    source.address = .{ .ip6 = .{ .octets = report.recipient_ip.ip6, .port = 9000 } };
    for (0..20) |i| {
        source.node_id[0] = @intCast(i);
        source.address.ip6.octets[15] = @intCast(i);
        source.address.ip6.interface = @intCast(i);
        _ = votes.observe(&source, &report, 0);
    }
    try std.testing.expectEqual(@as(usize, 1), votes.count(1, 0));
    for (1..10) |i| {
        source.node_id[0] = @intCast(i);
        source.address.ip6.octets[7] = @intCast(i);
        _ = votes.observe(&source, &report, 1);
    }
    try std.testing.expect(votes.observe(&source, &report, 2) != null);
    try std.testing.expectEqual(@as(usize, 0), votes.count(0, 2));
}

test "sample sufficiency counts successful observations, independently of agreement" {
    var votes: Votes = .{};
    votes.init(.{ .{ .enabled = true }, .{} });
    for (0..Votes.sample_target) |i| {
        try std.testing.expect(votes.needsSample(0, 0));
        try std.testing.expect(votes.observe(&peer(@intCast(i)), &pong(@intCast(i + 1)), 0) == null);
    }
    try std.testing.expect(!votes.needsSample(0, 1));
    _ = votes.observe(&peer(30), &pong(1), 2);
    try std.testing.expectEqual(@as(usize, Votes.sample_target + 1), votes.count(0, 2));
    try std.testing.expect(votes.needsSample(0, Votes.lifetime_ms));
}
