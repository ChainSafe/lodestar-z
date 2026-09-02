const std = @import("std");
const engine_mod = @import("engine.zig");
const keys = @import("../wire/keys.zig");
const limits = @import("limits.zig");
const support = @import("../test_support.zig");
const tls = @import("../tls/context.zig");

const Engine = engine_mod.Engine;
const Event = engine_mod.Event;
const Pair = support.Pair;
const client_address = support.client_address;
const server_address = support.server_address;
const now_unix = support.now_unix;
const expectConnected = support.expectConnected;

test "engine handshake connects both sides with verified peer ids" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();

    const dialed = try pair.dial();
    try pair.pump();

    var storage: [8]Event = undefined;
    const client_events = pair.events(&pair.client, &storage);
    try std.testing.expectEqual(@as(usize, 1), client_events.len);
    const client_handle = try expectConnected(client_events[0], .outbound, &pair.server_ctx);
    try std.testing.expectEqual(dialed, client_handle);

    var server_storage: [8]Event = undefined;
    const server_events = pair.events(&pair.server, &server_storage);
    try std.testing.expectEqual(@as(usize, 1), server_events.len);
    const server_handle = try expectConnected(server_events[0], .inbound, &pair.client_ctx);

    try std.testing.expect(pair.client.peerId(client_handle).?.eql(&pair.server_ctx.local_peer_id));
    try std.testing.expect(pair.server.peerId(server_handle).?.eql(&pair.client_ctx.local_peer_id));
    try std.testing.expectEqual(@as(u16, 0), pair.client.handshaking);
    try std.testing.expectEqual(@as(u16, 0), pair.server.handshaking);
    try std.testing.expectEqual(@as(usize, 0), pair.events(&pair.client, &storage).len);
}

test "engine counts only inbound handshakes against the permit bound" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();

    _ = try pair.dial();
    try std.testing.expectEqual(@as(u16, 0), pair.client.handshaking);
    try std.testing.expectEqual(@as(u16, 0), pair.server.handshaking);

    try std.testing.expect(try pair.transfer(&pair.client, &pair.server, client_address, server_address, false));
    try std.testing.expectEqual(@as(u16, 0), pair.client.handshaking);
    try std.testing.expectEqual(@as(u16, 1), pair.server.handshaking);

    try pair.pump();
    try std.testing.expectEqual(@as(u16, 0), pair.client.handshaking);
    try std.testing.expectEqual(@as(u16, 0), pair.server.handshaking);
}

test "engine clamps receive windows to the total budget" {
    const host = try keys.KeyPair.fromSecretKey(&([_]u8{0} ** 31 ++ [_]u8{4}));
    var ctx = try tls.Context.init(&host, now_unix, [_]u8{4} ** 8);
    defer ctx.deinit();

    var few = try Engine.init(std.testing.allocator, &ctx, .{ .connections_max = 4, .handshaking_max = 4 });
    defer few.deinit();
    try std.testing.expectEqual(limits.connection_window_max, few.connection_window);
    try std.testing.expectEqual(limits.connection_window_max / 2, few.stream_window);

    var many = try Engine.init(std.testing.allocator, &ctx, .{ .connections_max = 1_024 });
    defer many.deinit();
    try std.testing.expectEqual(limits.connection_window_min, many.connection_window);
    try std.testing.expectEqual(limits.connection_window_min / 2, many.stream_window);

    var standard = try Engine.init(std.testing.allocator, &ctx, .{});
    defer standard.deinit();
    try std.testing.expectEqual(@as(u64, 4 * 1_024 * 1_024), standard.connection_window);
    try std.testing.expectEqual(@as(u64, 2 * 1_024 * 1_024), standard.stream_window);
}

test "engine rejects invalid limits" {
    const host = try keys.KeyPair.fromSecretKey(&([_]u8{0} ** 31 ++ [_]u8{3}));
    var ctx = try tls.Context.init(&host, now_unix, [_]u8{3} ** 8);
    defer ctx.deinit();
    try std.testing.expectError(error.InvalidLimits, Engine.init(std.testing.allocator, &ctx, .{ .connections_max = 0 }));
    try std.testing.expectError(error.InvalidLimits, Engine.init(std.testing.allocator, &ctx, .{ .connections_max = 2_000 }));
    try std.testing.expectError(error.InvalidLimits, Engine.init(std.testing.allocator, &ctx, .{ .connections_max = 4, .handshaking_max = 8 }));
}
