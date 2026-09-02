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
                if (drop) continue;
                var copy: [constants.datagram_size_max]u8 = undefined;
                @memcpy(copy[0..datagram.len], datagram);
                var response: [constants.datagram_size_max]u8 = undefined;
                _ = to.receive(copy[0..datagram.len], from_address, to_address, self.now, self.nextEntropy(), &response);
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

    pair.client.close(handles.client, 42);
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
        pair.nextEntropy(),
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
        pair.nextEntropy(),
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
    const outcome = pair.server.receive(&initial, client_address, server_address, pair.now, pair.nextEntropy(), &response);
    switch (outcome) {
        .version_negotiation => |bytes| try std.testing.expect(bytes.len > 0),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(u64, 1), pair.server.counters.version_negotiations);

    var short = [_]u8{0x40} ++ [_]u8{0xcc} ** constants.local_cid_length ++ [_]u8{0} ** 20;
    try std.testing.expectEqual(engine_mod.ReceiveOutcome.dropped, pair.server.receive(&short, client_address, server_address, pair.now, pair.nextEntropy(), &response));
    try std.testing.expectEqual(@as(u64, 1), pair.server.counters.dropped_unroutable);

    var tiny = [_]u8{ 0xc3, 0, 0, 0, 1, 0x08 } ++ [_]u8{0xaa} ** 8 ++ [_]u8{0x04} ++ [_]u8{0xbb} ** 4 ++ [_]u8{0x00};
    try std.testing.expectEqual(engine_mod.ReceiveOutcome.dropped, pair.server.receive(&tiny, client_address, server_address, pair.now, pair.nextEntropy(), &response));
    try std.testing.expectEqual(@as(u64, 1), pair.server.counters.dropped_short_initial);
    try std.testing.expectEqual(@as(u16, 0), pair.server.handshaking);
}
