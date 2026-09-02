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
const expectClosed = support.expectClosed;

fn sleepMs(ms: i64) void {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    std.Io.sleep(threaded.io(), std.Io.Duration.fromMilliseconds(ms), .awake) catch {};
}

test "engine stale handles are rejected" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);
    const stale = engine_mod.Handle{ .index = handles.client.index, .generation = handles.client.generation +% 1 };
    try std.testing.expectError(error.StaleHandle, pair.client.openStream(stale));
    try std.testing.expect(pair.client.peerId(stale) == null);
    const out_of_range = engine_mod.Handle{ .index = 9_999, .generation = 0 };
    try std.testing.expectError(error.StaleHandle, pair.client.openStream(out_of_range));
}

test "engine reports a host close on both sides" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    _ = pair.client.close(handles.client, 42);
    try pair.pump();

    var storage: [8]Event = undefined;
    const client_reason = try expectClosed(pair.events(&pair.client, &storage)[0], handles.client);
    try std.testing.expectEqual(engine_mod.CloseReason.host, client_reason);
    const server_reason = try expectClosed(pair.events(&pair.server, &storage)[0], handles.server);
    try std.testing.expect(server_reason.peer_closed.app);
    try std.testing.expectEqual(@as(u64, 42), server_reason.peer_closed.code);
    try std.testing.expectError(error.StaleHandle, pair.client.openStream(handles.client));
    try std.testing.expectEqual(@as(u16, 0), pair.client.handshaking);
}

test "engine closes on peer id mismatch" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();

    const wrong = pair.client_ctx.local_peer_id;
    const handle = try pair.client.dial(client_address, server_address, wrong, pair.now, pair.nextEntropy());
    try pair.pump();

    var storage: [8]Event = undefined;
    const client_events = pair.events(&pair.client, &storage);
    try std.testing.expectEqual(@as(usize, 1), client_events.len);
    try std.testing.expectEqual(engine_mod.CloseReason.peer_id_mismatch, try expectClosed(client_events[0], handle));

    var server_storage: [8]Event = undefined;
    const server_events = pair.events(&pair.server, &server_storage);
    try std.testing.expectEqual(@as(usize, 2), server_events.len);
    const server_handle = try expectConnected(server_events[0], .inbound, &pair.client_ctx);
    const reason = try expectClosed(server_events[1], server_handle);
    try std.testing.expectEqual(@as(u64, 1), reason.peer_closed.code);
    try std.testing.expectEqual(@as(u16, 0), pair.client.handshaking);
}

test "engine closes on handshake timeout when the server never answers" {
    var pair: Pair = .{};
    try pair.init(.{ .handshake_timeout_ms = 100 }, .{});
    defer pair.deinit();
    pair.drop_to_server = true;

    const handle = try pair.dial();
    try pair.pump();
    pair.advance(100);
    try pair.pump();

    var storage: [8]Event = undefined;
    const client_events = pair.events(&pair.client, &storage);
    try std.testing.expectEqual(@as(usize, 1), client_events.len);
    try std.testing.expectEqual(engine_mod.CloseReason.handshake_timeout, try expectClosed(client_events[0], handle));
    try std.testing.expectEqual(@as(u16, 0), pair.client.handshaking);
}

test "engine rejects a forged certificate with tls_failed" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();

    const server_key = try keys.KeyPair.fromSecretKey(&([_]u8{0} ** 31 ++ [_]u8{2}));
    const other = try keys.KeyPair.fromSecretKey(&([_]u8{0} ** 31 ++ [_]u8{9}));
    const server_public = server_key.publicKey();
    var forged_ctx = try tls.Context.initWith(&server_public, &other, now_unix, [_]u8{7} ** 8);
    defer forged_ctx.deinit();
    pair.server.deinit();
    pair.server = try Engine.init(std.testing.allocator, &forged_ctx, .{});

    const handle = try pair.dial();
    try pair.pump();

    var storage: [8]Event = undefined;
    const client_events = pair.events(&pair.client, &storage);
    try std.testing.expectEqual(@as(usize, 1), client_events.len);
    try std.testing.expectEqual(engine_mod.CloseReason.tls_failed, try expectClosed(client_events[0], handle));
}

test "engine keep-alive survives a short idle timeout" {
    var pair: Pair = .{};
    try pair.init(.{ .idle_timeout_ms = 1_000, .keep_alive_ms = 200 }, .{ .idle_timeout_ms = 1_000, .keep_alive_ms = 200 });
    defer pair.deinit();
    const handles = try connectPair(&pair);

    var round: usize = 0;
    while (round < 8) : (round += 1) {
        sleepMs(200);
        pair.advance(200);
        try pair.pump();
    }
    var storage: [8]Event = undefined;
    try std.testing.expectEqual(@as(usize, 0), pair.events(&pair.client, &storage).len);
    try std.testing.expect(pair.client.peerId(handles.client) != null);
}

test "engine reports idle timeout without keep-alive" {
    var pair: Pair = .{};
    try pair.init(.{ .idle_timeout_ms = 600, .keep_alive_ms = 60_000 }, .{ .idle_timeout_ms = 600, .keep_alive_ms = 60_000 });
    defer pair.deinit();
    const handles = try connectPair(&pair);

    sleepMs(900);
    pair.advance(900);
    try pair.pump();

    var storage: [8]Event = undefined;
    const client_events = pair.events(&pair.client, &storage);
    try std.testing.expectEqual(@as(usize, 1), client_events.len);
    try std.testing.expectEqual(engine_mod.CloseReason.idle_timeout, try expectClosed(client_events[0], handles.client));
}

test "engine reclaims slots across many connection lifetimes" {
    var pair: Pair = .{};
    try pair.init(
        .{ .connections_max = 4, .handshaking_max = 4 },
        .{ .connections_max = 4, .handshaking_max = 4 },
    );
    defer pair.deinit();

    var storage: [8]Event = undefined;
    var round: usize = 0;
    while (round < 100) : (round += 1) {
        const handle = try pair.dial();
        try pair.pump();
        _ = pair.events(&pair.client, &storage);
        _ = pair.events(&pair.server, &storage);
        _ = pair.client.close(handle, 0);
        try pair.pump();
        _ = pair.events(&pair.client, &storage);
        _ = pair.events(&pair.server, &storage);
    }

    var indices: [4]u16 = undefined;
    try std.testing.expectEqual(@as(usize, 1), pair.client.activeIndices(&indices));
    _ = pair.events(&pair.client, &storage);
    _ = pair.events(&pair.server, &storage);
    try std.testing.expectEqual(@as(usize, 0), pair.client.activeIndices(&indices));
    try std.testing.expectEqual(@as(usize, 0), pair.server.activeIndices(&indices));
    try std.testing.expectEqual(@as(u16, 0), pair.client.handshaking);
    try std.testing.expectEqual(@as(u16, 0), pair.server.handshaking);
    for (pair.client.slots) |*slot| try std.testing.expect(slot.conn == null);
    for (pair.server.slots) |*slot| try std.testing.expect(slot.conn == null);
}

test "engine abandon frees a closed slot whose event was never reported" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    try std.testing.expect(pair.client.close(handles.client, 0));
    try pair.pump();
    try std.testing.expect(pair.client.eventsPending());

    try std.testing.expect(pair.client.abandon(handles.client));
    var indices: [limits.connections_max_default]u16 = undefined;
    try std.testing.expectEqual(@as(usize, 0), pair.client.activeIndices(&indices));
    try std.testing.expect(!pair.client.eventsPending());

    var storage: [8]Event = undefined;
    try std.testing.expectEqual(@as(usize, 0), pair.client.pollEvents(&storage));
    try std.testing.expect(!pair.client.abandon(handles.client));
}

test "engine close reports whether it issued the close" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    try std.testing.expect(pair.client.close(handles.client, 0));
    try std.testing.expect(!pair.client.close(handles.client, 0));
}

test "engine abandon frees a dialing slot without an event" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();

    const handle = try pair.dial();
    var indices: [limits.connections_max_default]u16 = undefined;
    try std.testing.expectEqual(@as(usize, 1), pair.client.activeIndices(&indices));

    try std.testing.expect(pair.client.abandon(handle));
    try std.testing.expectEqual(@as(usize, 0), pair.client.activeIndices(&indices));
    try std.testing.expect(!pair.client.abandon(handle));

    var storage: [8]Event = undefined;
    try std.testing.expectEqual(@as(usize, 0), pair.client.pollEvents(&storage));
    try std.testing.expect(!pair.client.eventsPending());
    try std.testing.expectError(error.StaleHandle, pair.client.openStream(handle));
}
