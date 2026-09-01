const std = @import("std");
const calls = @import("calls.zig");
const message = @import("wire/message.zig");
const types = @import("types.zig");

test "one active call per peer uses stale-safe handles" {
    var table: calls.Table = undefined;
    try table.init(2);
    const peer = endpoint(1, 9_001);
    const ping = pingRequest(1);
    const first = try table.begin(peer, &ping, 10);
    try std.testing.expectError(calls.Error.PeerBusy, table.begin(peer, &ping, 10));
    var moved_peer = peer;
    moved_peer.address.ip4.port = 9_101;
    try std.testing.expectError(
        calls.Error.PeerBusy,
        table.begin(moved_peer, &ping, 10),
    );
    try std.testing.expect(table.cancel(first));
    const second = try table.begin(peer, &ping, 10);
    try std.testing.expect(first.generation != second.generation);
    try std.testing.expect(table.requestBytes(first) == null);
    try std.testing.expect(!table.cancel(first));
}

test "call table owns encoded request bytes and tracks challenge nonce" {
    var table: calls.Table = undefined;
    try table.init(2);
    const peer = endpoint(1, 9_001);
    var protocol = [_]u8{ 'p', 'o', 'r', 't', 'a', 'l' };
    var payload = [_]u8{ 1, 2, 3 };
    const request = message.Message{ .talk_request = .{
        .request_id = try message.RequestId.init(&.{0x01}),
        .protocol = &protocol,
        .request = &payload,
    } };
    const nonce = [_]u8{0x11} ** 12;
    const handle = try table.begin(peer, &request, 10);
    @memset(&protocol, 0);
    @memset(&payload, 0);
    var scratch: message.DecodeScratch = .{};
    const stored = try message.Message.decode(table.requestBytes(handle).?, &scratch);
    try std.testing.expectEqualSlices(u8, "portal", stored.talk_request.protocol);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, stored.talk_request.request);
    try table.markSent(handle, &nonce, 10);
    try std.testing.expectEqual(
        handle,
        (try table.acceptChallenge(peer.address, &nonce, 9)).?,
    );
    try std.testing.expectError(
        calls.Error.HandshakeAttempted,
        table.acceptChallenge(peer.address, &nonce, 9),
    );
    const replacement_nonce = [_]u8{0x22} ** 12;
    try table.markSent(handle, &replacement_nonce, 20);
    try std.testing.expect((try table.acceptChallenge(peer.address, &nonce, 9)) == null);
    try std.testing.expectError(
        calls.Error.HandshakeAttempted,
        table.acceptChallenge(peer.address, &replacement_nonce, 19),
    );
}

test "call table rejects zero and excessive configured capacities" {
    var table: calls.Table = undefined;
    try std.testing.expectError(calls.Error.InvalidCapacity, table.init(0));
    try std.testing.expectError(
        calls.Error.InvalidCapacity,
        table.init(calls.capacity_max + 1),
    );
}

test "only sent calls participate in nonce and response matching" {
    var table: calls.Table = undefined;
    try table.init(2);
    const ping = pingRequest(1);
    const peer_a = endpoint(1, 9_001);
    var peer_b = endpoint(2, 9_002);
    peer_b.address = peer_a.address;
    const handle_a = try table.begin(peer_a, &ping, 100);
    const handle_b = try table.begin(peer_b, &ping, 100);
    const nonce = [_]u8{0x11} ** 12;
    try table.markSent(handle_a, &nonce, 100);
    try std.testing.expectError(
        calls.Error.NonceInUse,
        table.markSent(handle_b, &nonce, 100),
    );
    const pong = message.Message{ .pong = .{
        .request_id = ping.ping.request_id,
        .enr_sequence = 1,
        .recipient_ip = .{ .ip4 = .{ 127, 0, 0, 1 } },
        .recipient_port = 9_001,
    } };
    try std.testing.expectError(calls.Error.UnknownCall, table.accept(peer_b, &pong));
}

test "response matching validates type ID and NODES packet count before mutation" {
    var table: calls.Table = undefined;
    try table.init(2);
    const peer = endpoint(1, 9_001);
    const nonce = [_]u8{0x11} ** 12;
    const request = message.Message{ .find_node = .{
        .request_id = try message.RequestId.init(&.{0x01}),
        .distances = &.{256},
    } };
    const handle = try table.begin(peer, &request, 100);
    try table.markSent(handle, &nonce, 100);
    const wrong_id = nodesResponse(2, 2);
    try std.testing.expectError(calls.Error.RequestIdMismatch, table.accept(peer, &wrong_id));
    const invalid_total = nodesResponse(1, 0);
    try std.testing.expectError(
        calls.Error.InvalidResponseCount,
        table.accept(peer, &invalid_total),
    );

    const first = nodesResponse(1, 2);
    const first_match = try table.accept(peer, &first);
    try std.testing.expectEqual(handle, first_match.handle);
    try std.testing.expect(!first_match.terminal);
    const inconsistent = nodesResponse(1, 3);
    try std.testing.expectError(
        calls.Error.InvalidResponseCount,
        table.accept(peer, &inconsistent),
    );
    const second = nodesResponse(1, 2);
    const second_match = try table.accept(peer, &second);
    try std.testing.expect(second_match.terminal);
    try std.testing.expectEqual(@as(usize, 0), table.count());
}

test "expiry is bounded by caller output and removes exact generations" {
    var table: calls.Table = undefined;
    try table.init(2);
    const ping = pingRequest(1);
    const first = try table.begin(endpoint(1, 9_001), &ping, 10);
    _ = try table.begin(endpoint(2, 9_002), &ping, 10);
    var expired: [1]calls.Handle = undefined;
    try std.testing.expectEqual(@as(usize, 1), table.expire(10, &expired));
    try std.testing.expectEqual(first, expired[0]);
    try std.testing.expectEqual(@as(usize, 1), table.count());
    try std.testing.expectEqual(@as(usize, 1), table.expire(10, &expired));
    try std.testing.expectEqual(@as(usize, 0), table.count());
}

fn pingRequest(id: u8) message.Message {
    return .{ .ping = .{
        .request_id = message.RequestId.init(&.{id}) catch unreachable,
        .enr_sequence = 1,
    } };
}

fn nodesResponse(id: u8, total: u64) message.Message {
    return .{ .nodes = .{
        .request_id = message.RequestId.init(&.{id}) catch unreachable,
        .total = total,
        .enrs = &.{},
    } };
}

fn endpoint(id: u8, port: u16) types.Endpoint {
    return .{
        .node_id = [_]u8{id} ** 32,
        .address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, id }, .port = port } },
    };
}
