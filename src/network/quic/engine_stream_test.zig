const std = @import("std");
const binding = @import("binding.zig");
const engine_mod = @import("engine.zig");
const limits = @import("limits.zig");
const support = @import("../test_support.zig");

const Engine = engine_mod.Engine;
const Event = engine_mod.Event;
const Pair = support.Pair;
const client_address = support.client_address;
const server_address = support.server_address;
const connectPair = support.connectPair;
const expectClosed = support.expectClosed;
const expectStreamOpened = support.expectStreamOpened;
const expectStreamClosed = support.expectStreamClosed;

test "engine stream errors leak no quiche or openssl member" {
    comptime {
        const leaked = [_][]const u8{ "Done", "OpenSslFailed", "TlsFail", "CryptoFail", "Unknown" };
        for (@typeInfo(engine_mod.StreamError).error_set.?) |member| {
            for (leaked) |name| std.debug.assert(!std.mem.eql(u8, member.name, name));
        }
        std.debug.assert(@typeInfo(engine_mod.StreamError).error_set.?.len == 8);
        std.debug.assert(@typeInfo(engine_mod.DialError).error_set.?.len == 3);
        for (@typeInfo(binding.Error).error_set.?) |member| {
            std.debug.assert(!std.mem.eql(u8, member.name, "Done"));
        }
    }
    try std.testing.expect(@typeInfo(engine_mod.StreamError).error_set != null);
}

test "engine streams echo data with fin in both directions" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const stream = try pair.client.openStream(handles.client);
    try std.testing.expectEqual(@as(u64, 0), stream.id);
    try std.testing.expectEqual(@as(usize, 4), try pair.client.write(stream, "ping", true));
    try pair.pump();

    var storage: [8]Event = undefined;
    const server_events = pair.events(&pair.server, &storage);
    try std.testing.expectEqual(@as(usize, 1), server_events.len);
    const inbound = try expectStreamOpened(server_events[0], handles.server);
    try std.testing.expectEqual(@as(u64, 0), inbound.id);

    var buffer: [16]u8 = undefined;
    const received = try pair.server.read(inbound, &buffer);
    try std.testing.expectEqualStrings("ping", buffer[0..received.len]);
    try std.testing.expect(received.fin);
    try std.testing.expectEqual(@as(usize, 4), try pair.server.write(inbound, "pong", true));
    try pair.pump();

    var readable = pair.client.readable(handles.client);
    defer readable.deinit();
    const ready = readable.next() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(stream.id, ready.id);
    const reply = try pair.client.read(ready, &buffer);
    try std.testing.expectEqualStrings("pong", buffer[0..reply.len]);
    try std.testing.expect(reply.fin);
    try std.testing.expectError(error.UnknownStream, pair.client.read(stream, &buffer));
    try std.testing.expectError(error.UnknownStream, pair.server.read(inbound, &buffer));
}

test "engine server can open a stream toward the client" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const stream = try pair.server.openStream(handles.server);
    try std.testing.expectEqual(@as(u64, 1), stream.id);
    _ = try pair.server.write(stream, "hello", false);
    try pair.pump();

    var storage: [8]Event = undefined;
    const client_events = pair.events(&pair.client, &storage);
    try std.testing.expectEqual(@as(usize, 1), client_events.len);
    const inbound = try expectStreamOpened(client_events[0], handles.client);
    var buffer: [16]u8 = undefined;
    const received = try pair.client.read(inbound, &buffer);
    try std.testing.expectEqualStrings("hello", buffer[0..received.len]);
    try std.testing.expect(!received.fin);

    pair.client.closeStream(inbound, 7);
    try pair.pump();
    try std.testing.expectError(error.UnknownStream, pair.client.read(inbound, &buffer));
    try std.testing.expectError(error.StreamStopped, pair.server.write(stream, "more", false));
}

fn activePeerStreams(engine: *const Engine, handle: engine_mod.Handle) usize {
    var count: usize = 0;
    const peer_half = engine.slots[handle.index].table.entries[limits.streams_per_connection / 2 ..];
    for (peer_half) |*entry| {
        if (entry.claimed) count += 1;
    }
    return count;
}

test "engine releases a peer-reset stream entry and frees the peer half" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const stream = try pair.client.openStream(handles.client);
    _ = try pair.client.write(stream, "x", false);
    try pair.pump();

    var storage: [limits.streams_per_connection]Event = undefined;
    const opened = pair.events(&pair.server, &storage);
    try std.testing.expectEqual(@as(usize, 1), opened.len);
    const inbound = try expectStreamOpened(opened[0], handles.server);

    pair.client.shutdown(stream, .write, 7);
    pair.client.shutdown(stream, .read, 7);
    try pair.pump();

    var buffer: [16]u8 = undefined;
    const reset = try pair.server.read(inbound, &buffer);
    try std.testing.expectEqual(@as(usize, 0), reset.len);
    try std.testing.expect(reset.fin);
    try std.testing.expectEqual(@as(u64, 7), reset.reset_code.?);
    try std.testing.expectError(error.UnknownStream, pair.server.read(inbound, &buffer));
    try std.testing.expectEqual(@as(usize, 1), activePeerStreams(&pair.server, handles.server));

    const closed = pair.events(&pair.server, &storage);
    try std.testing.expectEqual(@as(usize, 1), closed.len);
    try std.testing.expectEqual(@as(u64, 7), (try expectStreamClosed(closed[0], inbound)).?);
    try std.testing.expectEqual(@as(usize, 0), activePeerStreams(&pair.server, handles.server));

    const dialer_closed = pair.events(&pair.client, &storage);
    try std.testing.expectEqual(@as(usize, 1), dialer_closed.len);
    try std.testing.expect(try expectStreamClosed(dialer_closed[0], stream) == null);

    var reopened: usize = 0;
    while (reopened < limits.peer_streams_bidi) : (reopened += 1) {
        const next = try pair.client.openStream(handles.client);
        _ = try pair.client.write(next, "y", false);
        try pair.pump();
    }
    const events = pair.events(&pair.server, &storage);
    try std.testing.expectEqual(@as(usize, limits.peer_streams_bidi), events.len);
    for (events) |event| _ = try expectStreamOpened(event, handles.server);
}

test "engine keeps a queued fin intact when closing a stream" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const stream = try pair.client.openStream(handles.client);
    try std.testing.expectEqual(@as(usize, 4), try pair.client.write(stream, "tail", true));
    pair.client.closeStream(stream, 0);
    try pair.pump();

    var storage: [8]Event = undefined;
    const inbound = try expectStreamOpened(pair.events(&pair.server, &storage)[0], handles.server);
    var buffer: [16]u8 = undefined;
    const received = try pair.server.read(inbound, &buffer);
    try std.testing.expectEqualStrings("tail", buffer[0..received.len]);
    try std.testing.expect(received.fin);
    try std.testing.expect(received.reset_code == null);
}

test "engine releases a stopped and reset stream entry" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const stream = try pair.server.openStream(handles.server);
    _ = try pair.server.write(stream, "hello", false);
    try pair.pump();

    var storage: [8]Event = undefined;
    const inbound = try expectStreamOpened(pair.events(&pair.client, &storage)[0], handles.client);
    pair.client.closeStream(inbound, 9);
    try pair.pump();

    try std.testing.expectError(error.StreamStopped, pair.server.write(stream, "more", false));
    var buffer: [16]u8 = undefined;
    const ended = try pair.server.read(stream, &buffer);
    try std.testing.expect(ended.fin);
    try std.testing.expectError(error.UnknownStream, pair.server.read(stream, &buffer));
}

test "engine reports a stream close on each side of a fin exchange" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const stream = try pair.client.openStream(handles.client);
    _ = try pair.client.write(stream, "ping", true);
    try pair.pump();

    var storage: [8]Event = undefined;
    const inbound = try expectStreamOpened(pair.events(&pair.server, &storage)[0], handles.server);
    var buffer: [16]u8 = undefined;
    _ = try pair.server.read(inbound, &buffer);
    try std.testing.expectEqual(@as(usize, 4), try pair.server.write(inbound, "pong", true));
    try pair.pump();

    const server_events = pair.events(&pair.server, &storage);
    try std.testing.expectEqual(@as(usize, 1), server_events.len);
    try std.testing.expect(try expectStreamClosed(server_events[0], inbound) == null);
    try std.testing.expectEqual(@as(usize, 0), pair.events(&pair.server, &storage).len);

    const reply = try pair.client.read(stream, &buffer);
    try std.testing.expectEqualStrings("pong", buffer[0..reply.len]);
    const client_events = pair.events(&pair.client, &storage);
    try std.testing.expectEqual(@as(usize, 1), client_events.len);
    try std.testing.expect(try expectStreamClosed(client_events[0], stream) == null);
    try std.testing.expectEqual(@as(usize, 0), pair.events(&pair.client, &storage).len);
}

test "engine reports a stream close on both sides of a reset" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const stream = try pair.client.openStream(handles.client);
    _ = try pair.client.write(stream, "x", false);
    try pair.pump();

    var storage: [8]Event = undefined;
    const inbound = try expectStreamOpened(pair.events(&pair.server, &storage)[0], handles.server);
    pair.client.shutdown(stream, .write, 7);
    pair.client.shutdown(stream, .read, 7);
    try pair.pump();

    const client_events = pair.events(&pair.client, &storage);
    try std.testing.expectEqual(@as(usize, 1), client_events.len);
    try std.testing.expect(try expectStreamClosed(client_events[0], stream) == null);
    try std.testing.expectEqual(@as(usize, 0), pair.events(&pair.client, &storage).len);

    var buffer: [16]u8 = undefined;
    const reset = try pair.server.read(inbound, &buffer);
    try std.testing.expectEqual(@as(u64, 7), reset.reset_code.?);
    const server_events = pair.events(&pair.server, &storage);
    try std.testing.expectEqual(@as(usize, 1), server_events.len);
    try std.testing.expectEqual(@as(u64, 7), (try expectStreamClosed(server_events[0], inbound)).?);
    try std.testing.expectEqual(@as(usize, 0), pair.events(&pair.server, &storage).len);
}

test "engine reports a stream close once for a host stream close" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const stream = try pair.client.openStream(handles.client);
    _ = try pair.client.write(stream, "x", false);
    pair.client.closeStream(stream, 9);

    var storage: [8]Event = undefined;
    const events = pair.events(&pair.client, &storage);
    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expect(try expectStreamClosed(events[0], stream) == null);
    try std.testing.expectEqual(@as(usize, 0), pair.events(&pair.client, &storage).len);
    try std.testing.expectError(error.UnknownStream, pair.client.write(stream, "y", false));
    var buffer: [16]u8 = undefined;
    try std.testing.expectError(error.UnknownStream, pair.client.read(stream, &buffer));
}

const bulk_length = 64 * 1_024;

test "engine reports a blocked stream and recovers capacity after a pump" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const stream = try pair.client.openStream(handles.client);
    var payload: [bulk_length]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index *% 31 +% 5);

    var sent = try pair.client.write(stream, &payload, false);
    try std.testing.expect(sent > 0);
    try std.testing.expect(sent < payload.len);
    var blocked = false;
    var attempts: usize = 0;
    while (attempts < 64 and !blocked and sent < payload.len) : (attempts += 1) {
        sent += pair.client.write(stream, payload[sent..], false) catch |err| switch (err) {
            error.WouldBlock => blk: {
                blocked = true;
                break :blk 0;
            },
            else => return err,
        };
    }
    try std.testing.expect(blocked);

    var while_blocked = pair.client.writable(handles.client);
    try std.testing.expect(while_blocked.next() == null);
    while_blocked.deinit();

    try pair.pump();
    try std.testing.expect(try pair.client.streamCapacity(stream) > 0);
    var after_pump = pair.client.writable(handles.client);
    defer after_pump.deinit();
    const ready = after_pump.next() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(stream.id, ready.id);

    var storage: [8]Event = undefined;
    const inbound = try expectStreamOpened(pair.events(&pair.server, &storage)[0], handles.server);
    var received: usize = 0;
    var scratch: [4_096]u8 = undefined;
    var pumps: usize = 0;
    while (pumps < 64 and received < payload.len) : (pumps += 1) {
        var writes: usize = 0;
        while (writes < 64 and sent < payload.len) : (writes += 1) {
            sent += pair.client.write(stream, payload[sent..], false) catch |err| switch (err) {
                error.WouldBlock => break,
                else => return err,
            };
        }
        try pair.pump();
        var reads: usize = 0;
        while (reads < 64) : (reads += 1) {
            const chunk = try pair.server.read(inbound, &scratch);
            if (chunk.len == 0) break;
            try std.testing.expectEqualSlices(u8, payload[received..][0..chunk.len], scratch[0..chunk.len]);
            received += chunk.len;
        }
    }
    try std.testing.expectEqual(payload.len, received);
}

test "engine bounds streams per connection" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    var opened: usize = 0;
    while (opened < limits.peer_streams_bidi) : (opened += 1) {
        const stream = try pair.client.openStream(handles.client);
        _ = try pair.client.write(stream, "x", false);
    }
    try std.testing.expectError(error.StreamLimit, pair.client.openStream(handles.client));
    try pair.pump();

    var storage: [limits.streams_per_connection]Event = undefined;
    const server_events = pair.events(&pair.server, &storage);
    try std.testing.expectEqual(@as(usize, limits.peer_streams_bidi), server_events.len);
    for (server_events) |event| _ = try expectStreamOpened(event, handles.server);
}

test "engine keeps received data readable after a local close" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const stream = try pair.client.openStream(handles.client);
    _ = try pair.client.write(stream, "ping", true);
    try pair.pump();

    var storage: [8]Event = undefined;
    const inbound = try expectStreamOpened(pair.events(&pair.server, &storage)[0], handles.server);
    _ = pair.server.close(handles.server, 0);

    var buffer: [16]u8 = undefined;
    const received = try pair.server.read(inbound, &buffer);
    try std.testing.expectEqualStrings("ping", buffer[0..received.len]);
    try std.testing.expect(received.fin);
}

test "engine keeps received data readable until the closed event is drained" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const stream = try pair.server.openStream(handles.server);
    try std.testing.expectEqual(@as(usize, 3), try pair.server.write(stream, "bye", true));
    _ = try pair.transfer(&pair.server, &pair.client, server_address, client_address, false);
    _ = pair.server.close(handles.server, 0);
    try pair.pump();

    var storage: [8]Event = undefined;
    const events = pair.events(&pair.client, &storage);
    try std.testing.expectEqual(@as(usize, 2), events.len);
    const inbound = try expectStreamOpened(events[0], handles.client);
    _ = try expectClosed(events[1], handles.client, .outbound, &pair.server_ctx);

    var buffer: [16]u8 = undefined;
    const final = try pair.client.read(inbound, &buffer);
    try std.testing.expectEqualStrings("bye", buffer[0..final.len]);
    try std.testing.expect(final.fin);

    try std.testing.expectEqual(@as(usize, 0), pair.events(&pair.client, &storage).len);
    try std.testing.expectError(error.StaleHandle, pair.client.read(inbound, &buffer));
}

test "engine reports stream events one at a time when the slice is full" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const first = try pair.client.openStream(handles.client);
    _ = try pair.client.write(first, "one", false);
    const second = try pair.client.openStream(handles.client);
    _ = try pair.client.write(second, "two", false);
    try pair.pump();

    var storage: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), pair.server.pollEvents(&storage));
    _ = try expectStreamOpened(storage[0], handles.server);
    try std.testing.expectEqual(@as(usize, 1), pair.server.pollEvents(&storage));
    _ = try expectStreamOpened(storage[0], handles.server);
    try std.testing.expectEqual(@as(usize, 0), pair.server.pollEvents(&storage));
}

test "engine reports pending events that did not fit the slice" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const first = try pair.client.openStream(handles.client);
    _ = try pair.client.write(first, "one", false);
    const second = try pair.client.openStream(handles.client);
    _ = try pair.client.write(second, "two", false);
    try pair.pump();

    try std.testing.expect(pair.server.eventsPending());
    var storage: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), pair.server.pollEvents(&storage));
    try std.testing.expect(pair.server.eventsPending());
    try std.testing.expectEqual(@as(usize, 1), pair.server.pollEvents(&storage));
    try std.testing.expect(!pair.server.eventsPending());
    try std.testing.expectEqual(@as(usize, 0), pair.server.pollEvents(&storage));
}
