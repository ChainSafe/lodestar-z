const std = @import("std");
const constants = @import("../constants.zig");
const engine_mod = @import("engine.zig");
const keys = @import("../identity/keys.zig");
const tls = @import("../tls/context.zig");
const types = @import("../types.zig");

const Engine = engine_mod.Engine;
const Event = engine_mod.Event;
const Limits = engine_mod.Limits;
const Now = engine_mod.Now;

pub const client_address = types.Address{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 4_001 } };
pub const server_address = types.Address{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 4_002 } };
pub const now_unix: i64 = 1_700_000_000;

fn sleepMs(ms: i64) void {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    std.Io.sleep(threaded.io(), std.Io.Duration.fromMilliseconds(ms), .awake) catch {};
}

pub const Pair = struct {
    client_ctx: tls.Context = undefined,
    server_ctx: tls.Context = undefined,
    client: Engine = undefined,
    server: Engine = undefined,
    now: Now = .{ .mono_ms = 1_000, .unix_s = now_unix },
    entropy: u8 = 0,
    pool: engine_mod.EntropyPool = .{},
    first_initial: [constants.datagram_size_max]u8 = undefined,
    first_initial_len: usize = 0,
    drop_to_server: bool = false,

    pub fn init(self: *Pair, client_limits: Limits, server_limits: Limits) !void {
        const client_key = try keys.KeyPair.fromSecretKey(&([_]u8{0} ** 31 ++ [_]u8{1}));
        const server_key = try keys.KeyPair.fromSecretKey(&([_]u8{0} ** 31 ++ [_]u8{2}));
        self.client_ctx = try tls.Context.init(&client_key, now_unix, [_]u8{1} ** 8);
        errdefer self.client_ctx.deinit();
        self.server_ctx = try tls.Context.init(&server_key, now_unix, [_]u8{2} ** 8);
        errdefer self.server_ctx.deinit();
        self.client = try Engine.init(std.testing.allocator, &self.client_ctx, client_limits);
        errdefer self.client.deinit();
        self.server = try Engine.init(std.testing.allocator, &self.server_ctx, server_limits);
        self.now = .{ .mono_ms = 1_000, .unix_s = now_unix };
        self.entropy = 0;
        self.first_initial_len = 0;
        self.drop_to_server = false;
    }

    pub fn deinit(self: *Pair) void {
        self.server.deinit();
        self.client.deinit();
        self.server_ctx.deinit();
        self.client_ctx.deinit();
    }

    pub fn nextEntropy(self: *Pair) [constants.local_cid_length]u8 {
        self.entropy +%= 1;
        return [_]u8{self.entropy} ** constants.local_cid_length;
    }

    pub fn nextPool(self: *Pair) *engine_mod.EntropyPool {
        self.pool.fill(self.nextEntropy());
        return &self.pool;
    }

    pub fn dial(self: *Pair) !engine_mod.Handle {
        return self.client.dial(client_address, server_address, self.server_ctx.local_peer_id, self.now, self.nextEntropy());
    }

    pub fn advance(self: *Pair, ms: u64) void {
        self.now.mono_ms += ms;
    }

    pub fn pump(self: *Pair) !void {
        var rounds: usize = 0;
        while (rounds < 64) : (rounds += 1) {
            var moved = try self.transfer(&self.client, &self.server, client_address, server_address, self.drop_to_server);
            moved = try self.transfer(&self.server, &self.client, server_address, client_address, false) or moved;
            self.client.tick(self.now);
            self.server.tick(self.now);
            if (!moved) return;
        }
        return error.PumpDidNotSettle;
    }

    fn transfer(self: *Pair, from: *Engine, to: *Engine, from_address: types.Address, to_address: types.Address, drop: bool) !bool {
        var moved = false;
        var index: u16 = 0;
        while (index < from.slotCount()) : (index += 1) {
            var budget: u32 = 0;
            while (budget < constants.send_burst_max) : (budget += 1) {
                var out: [constants.datagram_size_max]u8 = undefined;
                const datagram = try from.send(index, self.now, &out) orelse break;
                moved = true;
                if (from == &self.client and self.first_initial_len == 0) {
                    @memcpy(self.first_initial[0..datagram.len], datagram);
                    self.first_initial_len = datagram.len;
                }
                if (drop) continue;
                var copy: [constants.datagram_size_max]u8 = undefined;
                @memcpy(copy[0..datagram.len], datagram);
                var response: [constants.datagram_size_max]u8 = undefined;
                _ = to.receive(copy[0..datagram.len], from_address, to_address, self.now, self.nextPool(), &response);
            }
        }
        return moved;
    }

    pub fn events(_: *Pair, engine: *Engine, storage: []Event) []Event {
        return storage[0..engine.pollEvents(storage)];
    }
};

pub fn expectConnected(event: Event, direction: engine_mod.Direction, expected: *const tls.Context) !engine_mod.Handle {
    switch (event) {
        .connected => |connected| {
            try std.testing.expectEqual(direction, connected.direction);
            try std.testing.expect(connected.peer_id.eql(&expected.local_peer_id));
            return connected.conn;
        },
        else => return error.TestUnexpectedResult,
    }
}

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
    try std.testing.expectEqual(constants.connection_window_max, few.connection_window);
    try std.testing.expectEqual(constants.connection_window_max / 2, few.stream_window);

    var many = try Engine.init(std.testing.allocator, &ctx, .{ .connections_max = 1_024 });
    defer many.deinit();
    try std.testing.expectEqual(constants.connection_window_min, many.connection_window);
    try std.testing.expectEqual(constants.connection_window_min / 2, many.stream_window);

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

fn connectPair(pair: *Pair) !struct { client: engine_mod.Handle, server: engine_mod.Handle } {
    _ = try pair.dial();
    try pair.pump();
    var storage: [8]Event = undefined;
    const client_handle = try expectConnected(pair.events(&pair.client, &storage)[0], .outbound, &pair.server_ctx);
    const server_handle = try expectConnected(pair.events(&pair.server, &storage)[0], .inbound, &pair.client_ctx);
    return .{ .client = client_handle, .server = server_handle };
}

fn expectStreamOpened(event: Event, conn: engine_mod.Handle) !engine_mod.StreamHandle {
    switch (event) {
        .stream_opened => |stream| {
            try std.testing.expectEqual(conn, stream.conn);
            return stream;
        },
        else => return error.TestUnexpectedResult,
    }
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
    for (engine.slots[handle.index].streams[constants.streams_per_connection / 2 ..]) |*stream| {
        if (stream.active) count += 1;
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

    var storage: [constants.streams_per_connection]Event = undefined;
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
    try std.testing.expectEqual(@as(usize, 0), activePeerStreams(&pair.server, handles.server));

    var reopened: usize = 0;
    while (reopened < constants.peer_streams_bidi) : (reopened += 1) {
        const next = try pair.client.openStream(handles.client);
        _ = try pair.client.write(next, "y", false);
        try pair.pump();
    }
    const events = pair.events(&pair.server, &storage);
    try std.testing.expectEqual(@as(usize, constants.peer_streams_bidi), events.len);
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
    while (opened < constants.peer_streams_bidi) : (opened += 1) {
        const stream = try pair.client.openStream(handles.client);
        _ = try pair.client.write(stream, "x", false);
    }
    try std.testing.expectError(error.StreamLimit, pair.client.openStream(handles.client));
    try pair.pump();

    var storage: [constants.streams_per_connection]Event = undefined;
    const server_events = pair.events(&pair.server, &storage);
    try std.testing.expectEqual(@as(usize, constants.peer_streams_bidi), server_events.len);
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
    _ = try expectClosed(events[1], handles.client);

    var buffer: [16]u8 = undefined;
    const final = try pair.client.read(inbound, &buffer);
    try std.testing.expectEqualStrings("bye", buffer[0..final.len]);
    try std.testing.expect(final.fin);

    try std.testing.expectEqual(@as(usize, 0), pair.client.pollEvents(&storage));
    try std.testing.expectError(error.StaleHandle, pair.client.read(inbound, &buffer));
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

fn expectClosed(event: Event, conn: engine_mod.Handle) !engine_mod.CloseReason {
    switch (event) {
        .closed => |closed| {
            try std.testing.expectEqual(conn, closed.conn);
            return closed.reason;
        },
        else => return error.TestUnexpectedResult,
    }
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

test "engine drops new handshakes when the server table is full" {
    var pair: Pair = .{};
    try pair.init(.{ .connections_max = 4, .handshaking_max = 4, .handshake_timeout_ms = 100 }, .{ .connections_max = 1, .handshaking_max = 1 });
    defer pair.deinit();
    _ = try connectPair(&pair);

    const second = try pair.dial();
    try pair.pump();
    try std.testing.expect(pair.server.counters.dropped_full > 0);
    pair.advance(100);
    try pair.pump();

    var storage: [8]Event = undefined;
    const client_events = pair.events(&pair.client, &storage);
    try std.testing.expectEqual(@as(usize, 1), client_events.len);
    try std.testing.expectEqual(engine_mod.CloseReason.handshake_timeout, try expectClosed(client_events[0], second));
    try std.testing.expectError(error.TableFull, pair.server.dial(server_address, client_address, pair.client_ctx.local_peer_id, pair.now, pair.nextEntropy()));
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

test "engine drops a routed packet that arrives from another source path" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const stream = try pair.server.openStream(handles.server);
    _ = try pair.server.write(stream, "spoof", false);

    var out: [constants.datagram_size_max]u8 = undefined;
    const datagram = (try pair.server.send(0, pair.now, &out)) orelse return error.TestUnexpectedResult;
    var copy: [constants.datagram_size_max]u8 = undefined;
    @memcpy(copy[0..datagram.len], datagram);

    const wrong_source = types.Address{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 4_003 } };
    const before = pair.client.counters.dropped_unroutable;
    var response: [constants.datagram_size_max]u8 = undefined;
    const outcome = pair.client.receive(
        copy[0..datagram.len],
        wrong_source,
        client_address,
        pair.now,
        pair.nextPool(),
        &response,
    );
    try std.testing.expectEqual(engine_mod.ReceiveOutcome.dropped, outcome);
    try std.testing.expectEqual(before + 1, pair.client.counters.dropped_unroutable);
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

test "engine survives an undecryptable packet routed to a live slot" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    const scid = pair.client.slots[handles.client.index].scid;
    var garbage: [1 + constants.local_cid_length + 32]u8 = undefined;
    garbage[0] = 0x40;
    @memcpy(garbage[1..][0..constants.local_cid_length], scid.slice());
    for (garbage[1 + constants.local_cid_length ..], 0..) |*byte, index| byte.* = @truncate(index *% 7 +% 3);

    const before_errors = pair.client.counters.recv_errors;
    const before_accepted = pair.client.counters.accepted;
    var response: [constants.datagram_size_max]u8 = undefined;
    const outcome = pair.client.receive(
        &garbage,
        server_address,
        client_address,
        pair.now,
        pair.nextPool(),
        &response,
    );
    switch (outcome) {
        .accepted => |handle| try std.testing.expectEqual(handles.client, handle),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(before_errors, pair.client.counters.recv_errors);
    try std.testing.expectEqual(before_accepted + 1, pair.client.counters.accepted);
    try std.testing.expect(pair.client.peerId(handles.client) != null);
}

fn dialInitial(pair: *Pair, out: []u8) ![]u8 {
    const handle = try pair.dial();
    var scratch: [constants.datagram_size_max]u8 = undefined;
    const datagram = (try pair.client.send(handle.index, pair.now, &scratch)) orelse
        return error.TestUnexpectedResult;
    @memcpy(out[0..datagram.len], datagram);
    return out[0..datagram.len];
}

test "engine caps inbound handshakes per source address" {
    var pair: Pair = .{};
    try pair.init(
        .{ .connections_max = 8, .handshaking_max = 8 },
        .{ .connections_max = 8, .handshaking_max = 8 },
    );
    defer pair.deinit();

    var response: [constants.datagram_size_max]u8 = undefined;
    var packet: [constants.datagram_size_max]u8 = undefined;
    var admitted: u16 = 0;
    var attempt: u16 = 0;
    while (attempt < constants.handshaking_per_source_max + 1) : (attempt += 1) {
        const initial = try dialInitial(&pair, &packet);
        try std.testing.expect(initial.len >= constants.client_initial_min);
        switch (pair.server.receive(initial, client_address, server_address, pair.now, pair.nextPool(), &response)) {
            .accepted => admitted += 1,
            else => {},
        }
    }

    try std.testing.expectEqual(constants.handshaking_per_source_max, admitted);
    try std.testing.expectEqual(@as(u64, 1), pair.server.counters.dropped_source_limit);
    try std.testing.expectEqual(constants.handshaking_per_source_max, pair.server.handshaking);

    const elsewhere = types.Address{ .ip4 = .{ .octets = .{ 127, 0, 0, 2 }, .port = 4_001 } };
    const other = try dialInitial(&pair, &packet);
    switch (pair.server.receive(other, elsewhere, server_address, pair.now, pair.nextPool(), &response)) {
        .accepted => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(constants.handshaking_per_source_max + 1, pair.server.handshaking);
}

test "engine drops an inbound Initial when the entropy pool is stale" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();

    var packet: [constants.datagram_size_max]u8 = undefined;
    const initial = try dialInitial(&pair, &packet);

    var stale = engine_mod.EntropyPool{};
    try std.testing.expect(stale.take() == null);
    var response: [constants.datagram_size_max]u8 = undefined;
    try std.testing.expectEqual(
        engine_mod.ReceiveOutcome.dropped,
        pair.server.receive(initial, client_address, server_address, pair.now, &stale, &response),
    );
    try std.testing.expectEqual(@as(u64, 1), pair.server.counters.dropped_no_entropy);
    try std.testing.expectEqual(@as(u16, 0), pair.server.handshaking);

    var indices: [constants.connections_max_default]u16 = undefined;
    try std.testing.expectEqual(@as(usize, 0), pair.server.activeIndices(&indices));
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
    var indices: [constants.connections_max_default]u16 = undefined;
    try std.testing.expectEqual(@as(usize, 0), pair.client.activeIndices(&indices));
    try std.testing.expect(!pair.client.eventsPending());

    var storage: [8]Event = undefined;
    try std.testing.expectEqual(@as(usize, 0), pair.client.pollEvents(&storage));
    try std.testing.expect(!pair.client.abandon(handles.client));
}

test "engine routes a replayed client Initial to the existing connection" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    try std.testing.expect(pair.first_initial_len >= constants.client_initial_min);
    var replay: [constants.datagram_size_max]u8 = undefined;
    @memcpy(replay[0..pair.first_initial_len], pair.first_initial[0..pair.first_initial_len]);

    var response: [constants.datagram_size_max]u8 = undefined;
    const outcome = pair.server.receive(
        replay[0..pair.first_initial_len],
        client_address,
        server_address,
        pair.now,
        pair.nextPool(),
        &response,
    );
    switch (outcome) {
        .accepted => |handle| try std.testing.expectEqual(handles.server, handle),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(u16, 0), pair.server.handshaking);
    var indices: [constants.connections_max_default]u16 = undefined;
    try std.testing.expectEqual(@as(usize, 1), pair.server.activeIndices(&indices));
}

test "engine feeds an unrouted short header from a known peer to its slot" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try connectPair(&pair);

    var reset: [1 + constants.local_cid_length + 24]u8 = undefined;
    reset[0] = 0x40;
    for (reset[1..], 0..) |*byte, index| byte.* = @truncate(index *% 37 +% 11);

    const before_unroutable = pair.client.counters.dropped_unroutable;
    const before_touched = pair.client.counters.accepted + pair.client.counters.recv_errors;
    var response: [constants.datagram_size_max]u8 = undefined;
    const outcome = pair.client.receive(
        &reset,
        server_address,
        client_address,
        pair.now,
        pair.nextPool(),
        &response,
    );
    switch (outcome) {
        .accepted => |handle| try std.testing.expectEqual(handles.client, handle),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(before_unroutable, pair.client.counters.dropped_unroutable);
    try std.testing.expectEqual(
        before_touched + 1,
        pair.client.counters.accepted + pair.client.counters.recv_errors,
    );

    const stranger = types.Address{ .ip4 = .{ .octets = .{ 127, 0, 0, 9 }, .port = 4_009 } };
    try std.testing.expectEqual(
        engine_mod.ReceiveOutcome.dropped,
        pair.client.receive(&reset, stranger, client_address, pair.now, pair.nextPool(), &response),
    );
    try std.testing.expectEqual(before_unroutable + 1, pair.client.counters.dropped_unroutable);
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
    var indices: [constants.connections_max_default]u16 = undefined;
    try std.testing.expectEqual(@as(usize, 1), pair.client.activeIndices(&indices));

    try std.testing.expect(pair.client.abandon(handle));
    try std.testing.expectEqual(@as(usize, 0), pair.client.activeIndices(&indices));
    try std.testing.expect(!pair.client.abandon(handle));

    var storage: [8]Event = undefined;
    try std.testing.expectEqual(@as(usize, 0), pair.client.pollEvents(&storage));
    try std.testing.expect(!pair.client.eventsPending());
    try std.testing.expectError(error.StaleHandle, pair.client.openStream(handle));
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

test "engine drops version negotiation packets instead of reflecting them" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();

    var packet = [_]u8{0} ** constants.client_initial_min;
    packet[0] = 0xc0;
    packet[5] = 0x08;
    @memset(packet[6..14], 0xaa);
    packet[14] = 0x05;
    @memset(packet[15..20], 0xbb);

    var response: [constants.datagram_size_max]u8 = undefined;
    const before = pair.server.counters.dropped_unroutable;
    try std.testing.expectEqual(
        engine_mod.ReceiveOutcome.dropped,
        pair.server.receive(&packet, client_address, server_address, pair.now, pair.nextPool(), &response),
    );
    try std.testing.expectEqual(before + 1, pair.server.counters.dropped_unroutable);
    try std.testing.expectEqual(@as(u64, 0), pair.server.counters.version_negotiations);
}

test "engine answers unsupported versions and drops unroutable packets" {
    var pair: Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();

    var initial = [_]u8{0} ** constants.client_initial_min;
    initial[0] = 0xc3;
    initial[1] = 0xba;
    initial[2] = 0xba;
    initial[3] = 0xba;
    initial[4] = 0xba;
    initial[5] = 0x08;
    @memset(initial[6..14], 0xaa);
    initial[14] = 0x04;
    @memset(initial[15..19], 0xbb);
    initial[19] = 0x00;
    var response: [constants.datagram_size_max]u8 = undefined;
    const outcome = pair.server.receive(&initial, client_address, server_address, pair.now, pair.nextPool(), &response);
    switch (outcome) {
        .version_negotiation => |bytes| try std.testing.expect(bytes.len > 0),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(u64, 1), pair.server.counters.version_negotiations);

    var short = [_]u8{0x40} ++ [_]u8{0xcc} ** constants.local_cid_length ++ [_]u8{0} ** 20;
    try std.testing.expectEqual(engine_mod.ReceiveOutcome.dropped, pair.server.receive(&short, client_address, server_address, pair.now, pair.nextPool(), &response));
    try std.testing.expectEqual(@as(u64, 1), pair.server.counters.dropped_unroutable);

    var tiny = [_]u8{ 0xc3, 0, 0, 0, 1, 0x08 } ++ [_]u8{0xaa} ** 8 ++ [_]u8{0x04} ++ [_]u8{0xbb} ** 4 ++ [_]u8{0x00};
    try std.testing.expectEqual(engine_mod.ReceiveOutcome.dropped, pair.server.receive(&tiny, client_address, server_address, pair.now, pair.nextPool(), &response));
    try std.testing.expectEqual(@as(u64, 1), pair.server.counters.dropped_short_initial);
    try std.testing.expectEqual(@as(u16, 0), pair.server.handshaking);
}
