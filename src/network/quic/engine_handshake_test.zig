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
const connectPair = support.connectPair;
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

test "engine finds a connection by peer id until its slot is released" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const server_id = pair.server_ctx.local_peer_id;
    const client_id = pair.client_ctx.local_peer_id;
    try std.testing.expectEqual(handles.client, pair.client.findByPeerId(&server_id).?);
    try std.testing.expectEqual(handles.server, pair.server.findByPeerId(&client_id).?);
    try std.testing.expect(pair.client.findByPeerId(&client_id) == null);
    try std.testing.expect(pair.server.findByPeerId(&server_id) == null);

    try std.testing.expect(pair.client.close(handles.client, 0));
    try pair.pump();

    var storage: [8]Event = undefined;
    var drains: usize = 0;
    while (drains < 2) : (drains += 1) {
        _ = pair.events(&pair.client, &storage);
        _ = pair.events(&pair.server, &storage);
    }
    try std.testing.expectEqual(@as(usize, 0), pair.client.driverView().activeIndices().len);
    try std.testing.expectEqual(@as(usize, 0), pair.server.driverView().activeIndices().len);
    try std.testing.expect(pair.client.findByPeerId(&server_id) == null);
    try std.testing.expect(pair.server.findByPeerId(&client_id) == null);
}

test "engine reports connection metadata through handles" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const outbound = engine_mod.Direction.outbound;
    const inbound = engine_mod.Direction.inbound;
    try std.testing.expectEqual(outbound, pair.client.direction(handles.client).?);
    try std.testing.expectEqual(inbound, pair.server.direction(handles.server).?);
    try std.testing.expect(pair.client.peerAddress(handles.client).?.eql(server_address));
    try std.testing.expect(pair.server.peerAddress(handles.server).?.eql(client_address));

    pair.advance(250);
    const age = pair.client.connectionAgeMs(handles.client, pair.now).?;
    try std.testing.expectEqual(@as(u64, 250), age);
    try std.testing.expectEqual(pair.client.connectionWindow() / 2, pair.client.streamWindow());

    const stale = engine_mod.Handle{
        .index = handles.client.index,
        .generation = handles.client.generation +% 1,
    };
    try std.testing.expect(pair.client.direction(stale) == null);
    try std.testing.expect(pair.client.peerAddress(stale) == null);
    try std.testing.expect(pair.client.connectionAgeMs(stale, pair.now) == null);
}

test "engine clamps receive windows to the total budget" {
    const host = try keys.KeyPair.fromSecretKey(&([_]u8{0} ** 31 ++ [_]u8{4}));
    var ctx = try tls.Context.init(&host, now_unix, [_]u8{4} ** 8);
    defer ctx.deinit();

    var few = try Engine.init(std.testing.allocator, &ctx, .{ .connections_max = 4, .handshaking_max = 4 });
    defer few.deinit();
    try std.testing.expectEqual(limits.connection_window_max, few.connectionWindow());
    try std.testing.expectEqual(limits.connection_window_max / 2, few.streamWindow());

    var many = try Engine.init(std.testing.allocator, &ctx, .{ .connections_max = 1_024 });
    defer many.deinit();
    try std.testing.expectEqual(limits.connection_window_min, many.connectionWindow());
    try std.testing.expectEqual(limits.connection_window_min / 2, many.streamWindow());

    var standard = try Engine.init(std.testing.allocator, &ctx, .{});
    defer standard.deinit();
    try std.testing.expectEqual(@as(u64, 4 * 1_024 * 1_024), standard.connectionWindow());
    try std.testing.expectEqual(@as(u64, 2 * 1_024 * 1_024), standard.streamWindow());
}

test "engine rejects invalid limits" {
    const host = try keys.KeyPair.fromSecretKey(&([_]u8{0} ** 31 ++ [_]u8{3}));
    var ctx = try tls.Context.init(&host, now_unix, [_]u8{3} ** 8);
    defer ctx.deinit();
    try std.testing.expectError(error.InvalidLimits, Engine.init(std.testing.allocator, &ctx, .{ .connections_max = 0 }));
    try std.testing.expectError(error.InvalidLimits, Engine.init(std.testing.allocator, &ctx, .{ .connections_max = 2_000 }));
    try std.testing.expectError(error.InvalidLimits, Engine.init(std.testing.allocator, &ctx, .{ .connections_max = 4, .handshaking_max = 8 }));
}
