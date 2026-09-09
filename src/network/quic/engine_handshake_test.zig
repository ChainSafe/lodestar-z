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
    try std.testing.expectEqual(@as(u16, 0), pair.client.registry.handshaking);
    try std.testing.expectEqual(@as(u16, 0), pair.server.registry.handshaking);
    try std.testing.expectEqual(@as(usize, 0), pair.events(&pair.client, &storage).len);
    try std.testing.expectEqualSlices(u64, &.{ 0, 1 }, &pair.client.connection_metrics.established);
    try std.testing.expectEqualSlices(u64, &.{ 1, 0 }, &pair.server.connection_metrics.established);
}

test "engine counts only inbound handshakes against the permit bound" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();

    _ = try pair.dial();
    try std.testing.expectEqual(@as(u16, 0), pair.client.registry.handshaking);
    try std.testing.expectEqual(@as(u16, 0), pair.server.registry.handshaking);

    try std.testing.expect(try pair.transfer(&pair.client, &pair.server, client_address, false));
    try std.testing.expectEqual(@as(u16, 0), pair.client.registry.handshaking);
    try std.testing.expectEqual(@as(u16, 1), pair.server.registry.handshaking);

    try pair.pump();
    try std.testing.expectEqual(@as(u16, 0), pair.client.registry.handshaking);
    try std.testing.expectEqual(@as(u16, 0), pair.server.registry.handshaking);
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

test "engine reconnects with the same TLS contexts" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();

    const first = try connectPair(&pair);
    try std.testing.expect(pair.client.close(first.client, 0));
    try pair.pump();

    var storage: [8]Event = undefined;
    for (0..2) |_| {
        _ = pair.events(&pair.client, &storage);
        _ = pair.events(&pair.server, &storage);
    }
    try std.testing.expectEqual(@as(usize, 0), pair.client.driverView().activeIndices().len);
    try std.testing.expectEqual(@as(usize, 0), pair.server.driverView().activeIndices().len);

    const second = try pair.dial();
    try pair.pump();
    const client_events = pair.events(&pair.client, &storage);
    try std.testing.expectEqual(@as(usize, 1), client_events.len);
    const client = try expectConnected(client_events[0], .outbound, &pair.server_ctx);
    try std.testing.expectEqual(second, client);

    const server_events = pair.events(&pair.server, &storage);
    try std.testing.expectEqual(@as(usize, 1), server_events.len);
    _ = try expectConnected(server_events[0], .inbound, &pair.client_ctx);
    try std.testing.expectEqual(@as(u64, 2), pair.client.connection_metrics.established[1]);
    try std.testing.expectEqual(@as(u64, 1), pair.client.connection_metrics.closed[1][@intFromEnum(engine_mod.CloseReason.host)]);
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
    var few = try standaloneEngine(4, .{ .connections_max = 4, .handshaking_max = 4 });
    defer few.deinit();
    try std.testing.expectEqual(limits.connection_window_max, few.connectionWindow());
    try std.testing.expectEqual(limits.connection_window_max / 2, few.streamWindow());

    var many = try standaloneEngine(5, .{ .connections_max = 1_024 });
    defer many.deinit();
    try std.testing.expectEqual(limits.connection_window_min, many.connectionWindow());
    try std.testing.expectEqual(limits.connection_window_min / 2, many.streamWindow());

    var standard = try standaloneEngine(6, .{});
    defer standard.deinit();
    try std.testing.expectEqual(@as(u64, 4 * 1_024 * 1_024), standard.connectionWindow());
    try std.testing.expectEqual(@as(u64, 2 * 1_024 * 1_024), standard.streamWindow());
}

test "engine reports connection stats for live handles only" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const stats = pair.client.connectionStats(handles.client) orelse return error.TestUnexpectedResult;
    try std.testing.expect(stats.sent > 0);
    try std.testing.expect(stats.recv > 0);
    try std.testing.expect(stats.sent_bytes > 0);
    try std.testing.expect(stats.recv_bytes > 0);
    try std.testing.expectEqual(@as(u64, 0), stats.lost);
    try std.testing.expect(stats.rtt_ms <= 1_000);
    try std.testing.expect(stats.min_rtt_ms <= stats.rtt_ms);
    try std.testing.expect(stats.cwnd > 0);

    const stale = engine_mod.Handle{
        .index = handles.client.index,
        .generation = handles.client.generation +% 1,
    };
    try std.testing.expect(pair.client.connectionStats(stale) == null);
}

test "engine captures TLS key material per connection only when keylog is enabled" {
    var pair: Pair = .{};
    try pair.init(.{ .keylog = true }, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    var lines: [tls.keylog_capacity]u8 = undefined;
    const length = pair.client.driverView().takeKeylog(handles.client.index, &lines);
    try std.testing.expect(length > 0);
    try std.testing.expect(std.mem.indexOf(u8, lines[0..length], "CLIENT_TRAFFIC_SECRET_0") != null);
    try std.testing.expect(std.mem.indexOf(u8, lines[0..length], "SERVER_TRAFFIC_SECRET_0") != null);
    try std.testing.expectEqual(@as(usize, 0), pair.client.driverView().takeKeylog(handles.client.index, &lines));
    try std.testing.expectEqual(@as(u16, 0), pair.client.registry.slots[handles.client.index].handshake.keylog_dropped);

    try std.testing.expectEqual(@as(usize, 0), pair.server.registry.keylog_arena.len);
    try std.testing.expectEqual(@as(usize, 0), pair.server.driverView().takeKeylog(handles.server.index, &lines));
    try std.testing.expect(pair.server.registry.slots[handles.server.index].handshake.keylog_dropped > 0);
}

test "handshake state drops key lines that do not fit and counts them" {
    var storage: [tls.keylog_capacity]u8 = undefined;
    var state = tls.HandshakeState{ .keylog = &storage };
    const line = "CLIENT_TRAFFIC_SECRET_0 " ++ "a" ** 200;
    var appended: usize = 0;
    while (state.appendKeylog(line)) appended += 1;
    try std.testing.expectEqual(tls.keylog_capacity / (line.len + 1), appended);
    try std.testing.expectEqual(@as(u16, 1), state.keylog_dropped);

    var out: [tls.keylog_capacity]u8 = undefined;
    const taken = state.takeKeylog(&out);
    try std.testing.expectEqual(appended * (line.len + 1), taken);
    try std.testing.expectEqual(@as(u16, 0), state.keylog_len);
    try std.testing.expect(std.mem.startsWith(u8, out[0..taken], line));
    try std.testing.expect(state.appendKeylog(line));

    var disabled = tls.HandshakeState{};
    try std.testing.expect(!disabled.appendKeylog("x"));
    try std.testing.expectEqual(@as(u16, 1), disabled.keylog_dropped);
    try std.testing.expectEqual(@as(usize, 0), disabled.takeKeylog(&out));
}

fn standaloneEngine(seed: u8, engine_limits: engine_mod.Limits) !Engine {
    const host = try keys.KeyPair.fromSecretKey(&([_]u8{0} ** 31 ++ [_]u8{seed}));
    var ctx = try tls.Context.init(&host, now_unix, [_]u8{seed} ** 8);
    errdefer ctx.deinit();
    return Engine.init(std.testing.allocator, .{
        .tls = ctx,
        .limits = engine_limits,
        .local = client_address,
        .seed = seed,
    });
}

test "engine rejects invalid limits" {
    try std.testing.expectError(error.InvalidLimits, standaloneEngine(3, .{ .connections_max = 0 }));
    try std.testing.expectError(error.InvalidLimits, standaloneEngine(3, .{ .connections_max = 2_000 }));
    try std.testing.expectError(
        error.InvalidLimits,
        standaloneEngine(3, .{ .connections_max = 4, .handshaking_max = 8 }),
    );
}
