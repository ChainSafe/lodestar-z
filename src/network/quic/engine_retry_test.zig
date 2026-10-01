const std = @import("std");
const retry = @import("retry.zig");
const binding = @import("binding.zig");
const limits = @import("limits.zig");
const support = @import("test_support.zig");

test "QUIC Retry admits an address-validated handshake" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{ .handshaking_max = 1 });
    defer pair.deinit();
    _ = try support.connectPair(&pair);
    try std.testing.expectEqual(@as(usize, 1), pair.server.registry.active_len);
}

test "QUIC Retry does not allocate a connection for repeated unvalidated Initials below pressure" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handle = try pair.dial();
    var packet: [@import("../constants.zig").datagram_size_max]u8 = undefined;
    const initial = pair.sendOne(&pair.client, handle.index, &packet).?;
    var out: [packet.len]u8 = undefined;
    for (0..4) |_| {
        const outcome = pair.server.receive(initial, &support.client_address, pair.now, &out);
        try std.testing.expect(outcome == .retry);
        try std.testing.expect(outcome.retry.len <= initial.len);
        try std.testing.expectEqual(@as(usize, 0), pair.server.registry.active_len);
        try std.testing.expectEqual(@as(u16, 0), pair.server.registry.handshaking);
        try std.testing.expectEqual(@as(usize, 0), pair.server.registry.routes.count);
    }
}

test "QUIC cached tokens of bounded wire lengths get Retry without connection allocation" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    var packet: [@import("../constants.zig").datagram_size_max]u8 = undefined;
    var output: [packet.len]u8 = undefined;
    const cached: [1024]u8 = @splat(0xa5);
    for ([_]usize{ 1, 256, 300, 1024 }) |length| {
        const initial = initialWithToken(&packet, cached[0..length]);
        var token: [binding.Header.token_max]u8 = undefined;
        const header = try binding.Header.parse(initial, &token);
        try std.testing.expectEqual(length, header.token.len);
        const outcome = pair.server.receive(initial, &support.client_address, pair.now, &output);
        try std.testing.expect(outcome == .retry);
        try std.testing.expect(outcome.retry.len <= initial.len);
        try std.testing.expectEqual(@as(usize, 0), pair.server.registry.active_len);
        try std.testing.expectEqual(@as(usize, 0), pair.server.registry.routes.count);
    }
}

test "QUIC invalid local Retry tokens do not receive another Retry" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const original = binding.Cid.fromSlice(&(@as([limits.local_cid_length]u8, @splat(3))));
    const scid = binding.Cid.fromSlice(&(@as([limits.local_cid_length]u8, @splat(4))));
    var token: [retry.token_max]u8 = undefined;
    const issued = retry.mint(&pair.server.retry_key, &support.client_address, &original, &scid, pair.now.mono_ms, &token);
    try std.testing.expect(retry.isLocal(issued));
    var packet: [@import("../constants.zig").datagram_size_max]u8 = undefined;
    var output: [packet.len]u8 = undefined;
    for ([_]usize{ 8, 9, issued.len }) |length| {
        const outcome = pair.server.receive(initialWithToken(&packet, issued[0..length]), &support.client_address, pair.now, &output);
        try std.testing.expect(outcome == .dropped);
    }
    token[8] ^= 1;
    try std.testing.expect(retry.isLocal(issued));
    try std.testing.expect(pair.server.receive(initialWithToken(&packet, issued), &support.client_address, pair.now, &output) == .dropped);
    try std.testing.expectEqual(@as(usize, 0), pair.server.registry.active_len);
}

test "QUIC Retry validates a token received after a longer foreign token" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    var packet: [@import("../constants.zig").datagram_size_max]u8 = undefined;
    var output: [packet.len]u8 = undefined;
    const cached: [1024]u8 = @splat(0xa5);
    try std.testing.expect(pair.server.receive(initialWithToken(&packet, &cached), &support.client_address, pair.now, &output) == .retry);
    _ = try support.connectPair(&pair);
    try std.testing.expectEqual(@as(usize, 1), pair.server.registry.active_len);
}

fn initialWithToken(packet: []u8, token: []const u8) []u8 {
    const header = [_]u8{ 0xc3, 0, 0, 0, 1, 8 } ++ [_]u8{0xaa} ** 8 ++ [_]u8{8} ++ [_]u8{0xbb} ** 8;
    std.debug.assert(token.len <= 1024);
    std.debug.assert(packet.len >= limits.client_initial_min);
    @memset(packet[0..limits.client_initial_min], 0);
    @memcpy(packet[0..header.len], &header);
    std.mem.writeInt(u16, packet[header.len..][0..2], 0x4000 | @as(u16, @intCast(token.len)), .big);
    @memcpy(packet[header.len + 2 ..][0..token.len], token);
    return packet[0..limits.client_initial_min];
}
