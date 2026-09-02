const std = @import("std");
const engine_mod = @import("engine.zig");
const keys = @import("../wire/keys.zig");
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
const expectStreamOpened = support.expectStreamOpened;

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

    const stream = try pair.client.openStream(handles.client);
    var buffer: [16]u8 = undefined;
    const wrong_slot = engine_mod.StreamHandle{
        .conn = stream.conn,
        .id = stream.id,
        .slot = stream.slot + 1,
    };
    try std.testing.expectError(error.UnknownStream, pair.client.read(wrong_slot, &buffer));
    try std.testing.expectError(error.UnknownStream, pair.client.write(wrong_slot, "x", false));
    try std.testing.expectError(error.UnknownStream, pair.client.streamCapacity(wrong_slot));

    const past_table = engine_mod.StreamHandle{ .conn = stream.conn, .id = stream.id, .slot = 255 };
    try std.testing.expectError(error.UnknownStream, pair.client.read(past_table, &buffer));
    try std.testing.expectError(error.UnknownStream, pair.client.write(past_table, "x", false));

    const other = try pair.client.openStream(handles.client);
    try std.testing.expect(other.slot != stream.slot);
    try std.testing.expect(other.id != stream.id);
    const aliased = engine_mod.StreamHandle{
        .conn = stream.conn,
        .id = stream.id,
        .slot = other.slot,
    };
    try std.testing.expectError(error.UnknownStream, pair.client.read(aliased, &buffer));
    try std.testing.expectError(error.UnknownStream, pair.client.write(aliased, "x", false));
    try std.testing.expectError(error.UnknownStream, pair.client.streamCapacity(aliased));

    const stale_stream = engine_mod.StreamHandle{
        .conn = stale,
        .id = stream.id,
        .slot = stream.slot,
    };
    try std.testing.expectError(error.StaleHandle, pair.client.read(stale_stream, &buffer));
    try std.testing.expectEqual(@as(usize, 1), try pair.client.write(stream, "x", false));
}

test "engine reports a host close on both sides" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    _ = pair.client.close(handles.client, 42);
    try pair.pump();

    var storage: [8]Event = undefined;
    const client_events = pair.events(&pair.client, &storage);
    const client_reason =
        try expectClosed(client_events[0], handles.client, .outbound, &pair.server_ctx);
    try std.testing.expectEqual(engine_mod.CloseReason.host, client_reason);
    const server_events = pair.events(&pair.server, &storage);
    const server_reason =
        try expectClosed(server_events[0], handles.server, .inbound, &pair.client_ctx);
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
    const handle = try pair.client.dial(
        &server_address,
        wrong,
        pair.now,
        pair.nextEntropy(),
    );
    try pair.pump();

    var storage: [8]Event = undefined;
    const client_events = pair.events(&pair.client, &storage);
    try std.testing.expectEqual(@as(usize, 1), client_events.len);
    try std.testing.expectEqual(
        engine_mod.CloseReason.peer_id_mismatch,
        try expectClosed(client_events[0], handle, .outbound, &pair.server_ctx),
    );

    var server_storage: [8]Event = undefined;
    const server_events = pair.events(&pair.server, &server_storage);
    try std.testing.expectEqual(@as(usize, 2), server_events.len);
    const server_handle = try expectConnected(server_events[0], .inbound, &pair.client_ctx);
    const reason = try expectClosed(server_events[1], server_handle, .inbound, &pair.client_ctx);
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
    try std.testing.expectEqual(
        engine_mod.CloseReason.handshake_timeout,
        try expectClosed(client_events[0], handle, .outbound, null),
    );
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
    pair.server = try Engine.init(std.testing.allocator, &forged_ctx, .{}, &server_address);

    const handle = try pair.dial();
    try pair.pump();

    var storage: [8]Event = undefined;
    const client_events = pair.events(&pair.client, &storage);
    try std.testing.expectEqual(@as(usize, 1), client_events.len);
    try std.testing.expectEqual(
        engine_mod.CloseReason.tls_failed,
        try expectClosed(client_events[0], handle, .outbound, null),
    );
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
    try std.testing.expectEqual(
        engine_mod.CloseReason.idle_timeout,
        try expectClosed(client_events[0], handles.client, .outbound, &pair.server_ctx),
    );
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

    try std.testing.expectEqual(@as(usize, 1), pair.client.driverView().activeIndices().len);
    _ = pair.events(&pair.client, &storage);
    _ = pair.events(&pair.server, &storage);
    try std.testing.expectEqual(@as(usize, 0), pair.client.driverView().activeIndices().len);
    try std.testing.expectEqual(@as(usize, 0), pair.server.driverView().activeIndices().len);
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
    try std.testing.expectEqual(@as(usize, 0), pair.client.driverView().activeIndices().len);
    try std.testing.expect(!pair.client.eventsPending());

    var storage: [8]Event = undefined;
    try std.testing.expectEqual(@as(usize, 0), pair.client.pollEvents(&storage));
    try std.testing.expect(!pair.client.abandon(handles.client));
}

test "engine abandon frees a closed slot after its event was reported" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    try std.testing.expect(pair.client.close(handles.client, 0));
    try pair.pump();

    var storage: [8]Event = undefined;
    const events = pair.events(&pair.client, &storage);
    try std.testing.expectEqual(@as(usize, 1), events.len);
    _ = try expectClosed(events[0], handles.client, .outbound, &pair.server_ctx);
    try std.testing.expectEqual(@as(usize, 1), pair.client.driverView().activeIndices().len);
    try std.testing.expect(!pair.client.eventsPending());

    try std.testing.expect(pair.client.abandon(handles.client));
    try std.testing.expectEqual(@as(usize, 0), pair.client.driverView().activeIndices().len);
    try std.testing.expect(!pair.client.abandon(handles.client));
    try std.testing.expect(pair.client.peerId(handles.client) == null);
}

test "engine polling twice keeps handles from the first call valid" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const stream = try pair.client.openStream(handles.client);
    _ = try pair.client.write(stream, "one", false);
    try pair.pump();

    var one: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), pair.server.pollEvents(&one));
    const inbound = try expectStreamOpened(one[0], handles.server);

    try std.testing.expect(pair.client.close(handles.client, 0));
    try pair.pump();

    try std.testing.expectEqual(@as(usize, 1), pair.server.pollEvents(&one));
    _ = try expectClosed(one[0], handles.server, .inbound, &pair.client_ctx);
    try std.testing.expectEqual(@as(usize, 0), pair.server.pollEvents(&one));
    try std.testing.expect(!pair.server.eventsPending());

    var buffer: [16]u8 = undefined;
    const final = try pair.server.read(inbound, &buffer);
    try std.testing.expectEqualStrings("one", buffer[0..final.len]);
    try std.testing.expect(pair.server.peerId(handles.server) != null);

    pair.server.driverView().releaseReported();
    try std.testing.expect(pair.server.peerId(handles.server) == null);
    try std.testing.expectError(error.StaleHandle, pair.server.read(inbound, &buffer));
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
    try std.testing.expectEqual(@as(usize, 1), pair.client.driverView().activeIndices().len);

    try std.testing.expect(pair.client.abandon(handle));
    try std.testing.expectEqual(@as(usize, 0), pair.client.driverView().activeIndices().len);
    try std.testing.expect(!pair.client.abandon(handle));

    var storage: [8]Event = undefined;
    try std.testing.expectEqual(@as(usize, 0), pair.client.pollEvents(&storage));
    try std.testing.expect(!pair.client.eventsPending());
    try std.testing.expectError(error.StaleHandle, pair.client.openStream(handle));
}
