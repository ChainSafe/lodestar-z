const std = @import("std");
const Engine = @import("Engine.zig");
const keys = @import("../wire/keys.zig");
const limits = @import("limits.zig");
const support = @import("test_support.zig");
const tls = @import("../tls/context.zig");

const Event = Engine.Event;
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
    try std.testing.expectEqual(@as(u16, 0), pair.server.registry.handshaking);
    try std.testing.expect(try pair.transfer(&pair.client, &pair.server, client_address, false));
    try std.testing.expectEqual(@as(u16, 1), pair.server.registry.handshaking);

    try pair.pump();
    try std.testing.expectEqual(@as(u16, 0), pair.client.registry.handshaking);
    try std.testing.expectEqual(@as(u16, 0), pair.server.registry.handshaking);
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
    try std.testing.expectEqual(@as(usize, 0), pair.client.registry.activeIndices().len);
    try std.testing.expectEqual(@as(usize, 0), pair.server.registry.activeIndices().len);

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
    try std.testing.expectEqual(@as(u64, 1), pair.client.connection_metrics.closed[1][@intFromEnum(Engine.CloseReason.host)]);
}

test "engine reports connection metadata through handles" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const outbound = Engine.Direction.outbound;
    const inbound = Engine.Direction.inbound;
    try std.testing.expectEqual(outbound, pair.client.direction(handles.client).?);
    try std.testing.expectEqual(inbound, pair.server.direction(handles.server).?);
    try std.testing.expect(pair.client.peerAddress(handles.client).?.eql(server_address));
    try std.testing.expect(pair.server.peerAddress(handles.server).?.eql(client_address));

    try std.testing.expectEqual(pair.client.memoryPlan().connection_window_bytes / 2, pair.client.memoryPlan().stream_window_bytes);

    const stale = Engine.Handle{
        .index = handles.client.index,
        .generation = handles.client.generation +% 1,
    };
    try std.testing.expect(pair.client.direction(stale) == null);
    try std.testing.expect(pair.client.peerAddress(stale) == null);
}

test "engine receive windows stay within the configured budget" {
    var few = try standaloneEngine(4, .{ .connections_max = 4, .handshaking_max = 4 });
    defer few.deinit();
    try std.testing.expectEqual(limits.connection_window_max, few.memoryPlan().connection_window_bytes);
    try std.testing.expectEqual(limits.connection_window_max / 2, few.memoryPlan().stream_window_bytes);

    try std.testing.expectError(error.InvalidLimits, standaloneEngine(5, .{ .connections_max = 1_024 }));
    try std.testing.expectError(error.InvalidLimits, standaloneEngine(5, .{ .receive_budget_bytes = 1 }));
    var many = try standaloneEngine(5, .{ .connections_max = 1_024, .receive_budget_bytes = 1_024 * limits.connection_window_min });
    defer many.deinit();
    try std.testing.expectEqual(limits.connection_window_min, many.memoryPlan().connection_window_bytes);
    try std.testing.expectEqual(limits.connection_window_min / 2, many.memoryPlan().stream_window_bytes);

    var standard = try standaloneEngine(6, .{});
    defer standard.deinit();
    try std.testing.expectEqual(@as(u64, 4 * 1_024 * 1_024), standard.memoryPlan().connection_window_bytes);
    try std.testing.expectEqual(@as(u64, 2 * 1_024 * 1_024), standard.memoryPlan().stream_window_bytes);
}

fn standaloneEngine(seed: u8, engine_limits: Engine.Limits) !Engine {
    const host = try keys.KeyPair.fromSecretKey(&([_]u8{0} ** 31 ++ [_]u8{seed}));
    var ctx = try tls.Context.init(&host, now_unix, [_]u8{seed} ** 8);
    errdefer ctx.deinit();
    return Engine.init(std.testing.allocator, .{
        .tls = ctx,
        .limits = engine_limits,
        .local = .{ client_address, null },
        .seed = &@as([32]u8, @splat(seed)),
    });
}

test "engine rejects invalid limits" {
    try std.testing.expectError(error.InvalidLimits, standaloneEngine(3, .{ .connections_max = 0 }));
    try std.testing.expectError(error.InvalidLimits, standaloneEngine(3, .{ .connections_max = 2_000 }));
    try std.testing.expectError(error.InvalidLimits, standaloneEngine(3, .{ .unanswered_dial_timeout_ms = 0 }));
    try std.testing.expectError(
        error.InvalidLimits,
        standaloneEngine(3, .{ .connections_max = 4, .handshaking_max = 8 }),
    );
}
