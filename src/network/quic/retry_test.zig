const std = @import("std");
const retry = @import("retry.zig");
const binding = @import("binding.zig");
const limits = @import("limits.zig");
const support = @import("../test_support.zig");

test "QUIC Retry tokens bind source endpoint CIDs key and lifetime" {
    const key: [32]u8 = @splat(1);
    const other_key: [32]u8 = @splat(2);
    const original = binding.Cid.fromSlice(&(@as([limits.local_cid_length]u8, @splat(3))));
    const scid = binding.Cid.fromSlice(&(@as([limits.local_cid_length]u8, @splat(4))));
    var buffer: [retry.token_max]u8 = undefined;
    const token = retry.mint(&key, &support.client_address, &original, &scid, 100, &buffer);
    const valid = retry.validate(&key, &support.client_address, &scid, token, 109, 10).?;
    try std.testing.expect(valid.eql(&original));
    try std.testing.expect(retry.validate(&key, &support.client_address, &scid, token, 99, 10) == null);
    try std.testing.expect(retry.validate(&key, &support.client_address, &scid, token, 110, 10) == null);
    try std.testing.expect(retry.validate(&other_key, &support.client_address, &scid, token, 100, 10) == null);
    try std.testing.expect(retry.validate(&key, &support.server_address, &scid, token, 100, 10) == null);
    try std.testing.expect(retry.validate(&key, &support.client_address, &original, token, 100, 10) == null);
    for (0..token.len) |length| try std.testing.expect(retry.validate(&key, &support.client_address, &scid, token[0..length], 100, 10) == null);
    for (0..token.len) |index| {
        buffer[index] ^= 1;
        try std.testing.expect(retry.validate(&key, &support.client_address, &scid, token, 100, 10) == null);
        buffer[index] ^= 1;
    }
}

test "QUIC Retry admits an address-validated handshake" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{ .handshaking_max = 1 });
    defer pair.deinit();
    _ = try support.connectPair(&pair);
    try std.testing.expectEqual(@as(u64, 1), pair.server.counters.retries);
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
    try std.testing.expectEqual(@as(u64, 4), pair.server.counters.retries);
}
