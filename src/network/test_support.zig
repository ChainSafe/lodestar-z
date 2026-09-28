const std = @import("std");
const constants = @import("constants.zig");
const engine_mod = @import("quic/engine.zig");
const keys = @import("wire/keys.zig");
const limits = @import("quic/limits.zig");
const tls = @import("tls/context.zig");
const transport_mod = @import("transport.zig");
const types = @import("types.zig");

const Engine = engine_mod.Engine;
const Event = engine_mod.Event;
const Limits = engine_mod.Limits;
const Now = engine_mod.Now;

pub const client_address = types.Address{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 4_001 } };
pub const server_address = types.Address{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 4_002 } };
pub const now_unix: i64 = 1_700_000_000;

pub const Pair = struct {
    client_ctx: tls.Context = undefined,
    server_ctx: tls.Context = undefined,
    client: Engine = undefined,
    server: Engine = undefined,
    now: Now = .{ .mono_ms = 1_000, .unix_s = now_unix },
    first_initial: [constants.datagram_size_max]u8 = undefined,
    first_initial_len: usize = 0,
    drop_to_server: bool = false,
    client_source: types.Address = client_address,
    drop_to_address: ?types.Address = null,
    /// Datagrams the client accepted from the server.
    client_accepted: u64 = 0,
    batch: transport_mod.SendBatch = undefined,
    client_stash: Stash = .{},
    server_stash: Stash = .{},

    pub fn init(self: *Pair, client_limits: Limits, server_limits: Limits) !void {
        const client_key = try keys.KeyPair.fromSecretKey(&([_]u8{0} ** 31 ++ [_]u8{1}));
        const server_key = try keys.KeyPair.fromSecretKey(&([_]u8{0} ** 31 ++ [_]u8{2}));
        self.client_ctx = try tls.Context.init(&client_key, now_unix, [_]u8{1} ** 8);
        self.server_ctx = tls.Context.init(&server_key, now_unix, [_]u8{2} ** 8) catch |err| {
            self.client_ctx.deinit();
            return err;
        };
        self.client = Engine.init(std.testing.allocator, .{
            .tls = self.client_ctx,
            .limits = client_limits,
            .local = .{ client_address, null },
            .seed = &@as([32]u8, @splat(1)),
        }) catch |err| {
            self.server_ctx.deinit();
            self.client_ctx.deinit();
            return err;
        };
        self.server = Engine.init(std.testing.allocator, .{
            .tls = self.server_ctx,
            .limits = server_limits,
            .local = .{ server_address, null },
            .seed = &@as([32]u8, @splat(2)),
        }) catch |err| {
            self.client.deinit();
            self.server_ctx.deinit();
            return err;
        };
        self.now = .{ .mono_ms = 1_000, .unix_s = now_unix };
        self.first_initial_len = 0;
        self.drop_to_server = false;
        self.client_source = client_address;
        self.drop_to_address = null;
        self.client_stash = .{};
        self.server_stash = .{};
    }

    pub fn deinit(self: *Pair) void {
        self.server.deinit();
        self.client.deinit();
    }

    pub fn sendOne(self: *Pair, engine: *Engine, index: u16, out: []u8) ?[]u8 {
        return (engine.sendOne(index, self.now, out) orelse return null).bytes;
    }

    pub fn dial(self: *Pair) !engine_mod.Handle {
        return self.client.dial(
            &server_address,
            self.server_ctx.local_peer_id,
            self.now,
        );
    }

    pub fn advance(self: *Pair, ms: u64) void {
        self.now.mono_ms += ms;
    }

    /// Delivers datagrams both ways and runs both engines' timer and readiness phases until
    /// neither side has output left.
    pub fn pump(self: *Pair) !void {
        var rounds: usize = 0;
        while (rounds < 64) : (rounds += 1) {
            const source = self.client_source;
            var moved = try self.transfer(&self.client, &self.server, source, self.drop_to_server);
            moved = try self.transfer(&self.server, &self.client, server_address, false) or moved;
            self.settle(&self.client);
            self.settle(&self.server);
            if (!moved and !self.client.backlog() and !self.server.backlog()) return;
        }
        return error.PumpDidNotSettle;
    }

    /// Delivers one engine's pending output to its peer.
    pub fn flush(self: *Pair, engine: *Engine) !void {
        if (engine == &self.client) {
            _ = try self.transfer(&self.client, &self.server, self.client_source, self.drop_to_server);
        } else _ = try self.transfer(&self.server, &self.client, server_address, false);
    }

    /// Runs one engine's timer and readiness phases at the pair's clock.
    pub fn settle(self: *Pair, engine: *Engine) void {
        engine.expire(self.now);
        engine.collect(self.now);
    }

    /// Flushes the sender's dirty connections into the receiver, as the transport does.
    pub fn transfer(
        self: *Pair,
        from: *Engine,
        to: *Engine,
        from_address: types.Address,
        drop: bool,
    ) !bool {
        var moved = false;
        var remaining = from.dirtyCount();
        while (remaining > 0) : (remaining -= 1) {
            const index = from.nextDirty() orelse break;
            var retry: ?struct { bytes: [constants.datagram_size_max]u8, len: usize, from: types.Address } = null;
            var budget: u32 = 0;
            var drained = false;
            while (budget < transport_mod.send_burst_max) {
                const count = sendBatch(from, index, self.now, &self.batch);
                budget += count;
                moved = moved or count > 0;
                for (self.batch.sent[0..count]) |sent| {
                    const datagram = sent.bytes;
                    if (from == &self.client and self.first_initial_len == 0) {
                        @memcpy(self.first_initial[0..datagram.len], datagram);
                    }
                    if (drop) continue;
                    if (self.drop_to_address) |blocked| if (sent.to.eql(blocked)) continue;
                    var response: [constants.datagram_size_max]u8 = undefined;
                    const outcome = to.receive(
                        datagram,
                        &from_address,
                        self.now,
                        &response,
                    );
                    if (from == &self.client and self.first_initial_len == 0 and outcome == .accepted) {
                        self.first_initial_len = datagram.len;
                    }
                    if (to == &self.client and outcome == .accepted) self.client_accepted += 1;
                    if (outcome == .retry) {
                        std.debug.assert(retry == null);
                        retry = .{ .bytes = undefined, .len = outcome.retry.len, .from = sent.to };
                        @memcpy(retry.?.bytes[0..outcome.retry.len], outcome.retry);
                    }
                }
                if (count < constants.send_batch_max) {
                    drained = true;
                    break;
                }
            }
            from.sent(index, self.now, drained);
            // The reply re-dirties the sender after its burst ended, as a later turn would.
            if (retry) |*reply| {
                var out: [constants.datagram_size_max]u8 = undefined;
                _ = from.receive(reply.bytes[0..reply.len], &reply.from, self.now, &out);
            }
        }
        from.finishFlush(self.now);
        return moved;
    }

    /// Events polled by `forward` wait here for the next `events` call.
    fn stash(self: *Pair, engine: *const Engine) *Stash {
        std.debug.assert(engine == &self.client or engine == &self.server);
        return if (engine == &self.client) &self.client_stash else &self.server_stash;
    }

    pub fn events(self: *Pair, engine: *Engine, storage: []Event) []Event {
        const held = self.stash(engine);
        if (held.len == 0) engine.releaseReported();
        const taken = @min(held.len, storage.len);
        @memcpy(storage[0..taken], held.events[0..taken]);
        std.mem.copyForwards(Event, held.events[0 .. held.len - taken], held.events[taken..held.len]);
        held.len -= taken;
        if (held.len > 0) return storage[0..taken];
        const polled = engine.pollEvents(storage[taken..]);
        held.noteStreams(storage[taken..][0..polled]);
        return storage[0 .. taken + polled];
    }

    /// Routes the stream events polled since the last call, here or by `events`, to the owners
    /// their routes name, as Service.dispatch does. Events polled here stay available to `events`.
    pub fn forward(self: *Pair, engine: *Engine, owners: Owners) void {
        const held = self.stash(engine);
        const start = held.len;
        held.len += engine.pollEvents(held.events[start..]);
        held.noteStreams(held.events[start..held.len]);
        owners.route(engine, held.unrouted[0..held.unrouted_len]);
        held.unrouted_len = 0;
    }
};

const Stash = struct {
    events: [256]Event = undefined,
    len: usize = 0,
    /// Stream events not yet routed by `forward`.
    unrouted: [256]Event = undefined,
    unrouted_len: usize = 0,
    /// Streams the remote side opened, as this engine claimed them.
    peer_streams: u64 = 0,

    fn noteStreams(self: *Stash, polled: []const Event) void {
        for (polled) |event| {
            if (event == .stream_opened) self.peer_streams += 1;
            if (event != .stream_ready and event != .stream_closed) continue;
            // Harnesses that never forward keep only the newest events.
            if (self.unrouted_len == self.unrouted.len) {
                const kept = self.unrouted.len / 2;
                std.mem.copyForwards(Event, self.unrouted[0..kept], self.unrouted[self.unrouted.len - kept ..]);
                self.unrouted_len = kept;
            }
            self.unrouted[self.unrouted_len] = event;
            self.unrouted_len += 1;
        }
    }
};

/// The owners a test drives directly, reached by stream route. A readable, writable or close event
/// marks the owner's row ready; gossip takes readiness events only. Lifecycle handling stays with
/// the test.
pub const Owners = struct {
    negotiator: ?*@import("negotiate.zig").Negotiator = null,
    identify: ?*@import("identify/handler.zig").Handler = null,
    reqresp: ?*@import("reqresp/reqresp.zig").ReqResp = null,
    gossip: ?*@import("gossipsub/gossipsub.zig").Gossipsub = null,

    pub fn route(self: Owners, engine: *Engine, events: []const Event) void {
        for (events) |event| {
            const stream, const bound = switch (event) {
                .stream_ready => |ready| .{ ready.stream, engine.route(ready.stream) orelse continue },
                .stream_closed => |closed| .{ closed.stream, closed.route },
                else => continue,
            };
            switch (bound.owner) {
                .negotiation => if (self.negotiator) |owner| owner.streamReady(bound.row, stream),
                .identify => if (self.identify) |owner| owner.streamReady(bound.row, stream),
                .reqresp_outbound, .reqresp_inbound => if (self.reqresp) |owner| owner.streamReady(bound, stream),
                .gossip_inbound, .gossip_outbound => if (self.gossip) |owner| if (event == .stream_ready) owner.streamReady(engine, bound, stream, event.stream_ready.ready),
                .none => {},
            }
        }
    }
};

pub const Node = struct {
    transport: transport_mod.Transport = .{},

    pub fn init(self: *Node, seed: u8) !void {
        const key = try keys.KeyPair.fromSecretKey(&([_]u8{0} ** 31 ++ [_]u8{seed}));
        try self.transport.init(std.testing.allocator, std.testing.io, .{
            .host = &key,
            .bind = .{ .ip4 = .loopback(0) },
        });
    }

    pub fn deinit(self: *Node) void {
        self.transport.deinit(std.testing.io);
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

pub fn connectPair(pair: *Pair) !struct { client: engine_mod.Handle, server: engine_mod.Handle } {
    _ = try pair.dial();
    try pair.pump();
    var storage: [8]Event = undefined;
    const client_handle = try expectConnected(pair.events(&pair.client, &storage)[0], .outbound, &pair.server_ctx);
    const server_handle = try expectConnected(pair.events(&pair.server, &storage)[0], .inbound, &pair.client_ctx);
    return .{ .client = client_handle, .server = server_handle };
}

pub fn expectStreamOpened(event: Event, conn: engine_mod.Handle) !engine_mod.StreamHandle {
    switch (event) {
        .stream_opened => |stream| {
            try std.testing.expectEqual(conn, stream.conn);
            return stream;
        },
        else => return error.TestUnexpectedResult,
    }
}

pub fn expectClosed(
    event: Event,
    conn: engine_mod.Handle,
    direction: engine_mod.Direction,
    peer: ?*const tls.Context,
) !engine_mod.CloseReason {
    switch (event) {
        .closed => |closed| {
            try std.testing.expectEqual(conn, closed.conn);
            try std.testing.expectEqual(direction, closed.direction);
            if (peer) |ctx| {
                try std.testing.expect(closed.peer_id != null);
                try std.testing.expect(closed.peer_id.?.eql(&ctx.local_peer_id));
            } else {
                try std.testing.expect(closed.peer_id == null);
            }
            return closed.reason;
        },
        else => return error.TestUnexpectedResult,
    }
}

pub fn expectStreamClosed(event: Event, stream: engine_mod.StreamHandle) !?u64 {
    switch (event) {
        .stream_closed => |closed| {
            try std.testing.expectEqual(stream, closed.stream);
            return closed.reset_code;
        },
        else => return error.TestUnexpectedResult,
    }
}

pub fn sendBatch(engine: *Engine, index: u16, now: Now, batch: *transport_mod.SendBatch) u8 {
    var count: u8 = 0;
    while (count < constants.send_batch_max) : (count += 1) {
        batch.sent[count] = engine.sendOne(index, now, &batch.buffers[count]) orelse break;
    }
    return count;
}

pub fn step(transport: *transport_mod.Transport, io: std.Io, events: []Event, options: transport_mod.StepOptions) transport_mod.StepError!transport_mod.StepResult {
    const result = transport.step(io, events, options);
    if (result.failure) |err| return err;
    return result.progress;
}

pub const NetworkOptions = struct {
    resolved: @import("configuration.zig").Resolved,
    startup: @import("network_core.zig").Startup,
};

/// The owner harness request resolved for a NetworkCore on loopback.
pub fn networkOptions(key: *const keys.KeyPair) NetworkOptions {
    const owner_support = @import("network_core_test_support.zig");
    var request = owner_support.request();
    request.forks = &.{
        .{ .digest = @splat(0), .fork = .phase0 },
        .{ .digest = .{ 1, 2, 3, 4 }, .fork = .fulu },
    };
    request.reqresp.outbound_per_peer_max = 4;
    request.gossip.topic_policy = comptime &.{
        @import("gossipsub/topic_fixture.zig").bytes(@splat(0)),
        @import("gossipsub/topic_fixture.zig").bytes(.{ 1, 2, 3, 4 }),
    };
    return .{
        .resolved = @import("configuration.zig").resolve(request) catch unreachable,
        .startup = .{
            .host = key,
            .bind = .{ .ip4 = .loopback(0) },
            .local = owner_support.localState(.{}),
            .slot = 100,
        },
    };
}

const core = @import("network_core.zig");
const local_intent = @import("gossipsub/local_intent.zig");
const topic_policy = @import("gossipsub/topic_policy.zig");

pub fn intent(node: *const core.NetworkCore, subscriptions: []const local_intent.Boundary) core.LocalIntent {
    return .{
        .update = .{
            .local = node.localState(),
            .schedule = node.schedule,
            .endpoints = node.advertisementEndpoints(),
            .capabilities = node.service.router.capabilities(),
        },
        .demand = node.peer_manager.demand,
        .subscriptions = subscriptions,
        .slot = node.service.gossipsub.overlay.slot,
    };
}

pub fn subscribe(node: *core.NetworkCore, name: []const u8) !void {
    try setSubscription(node, name, true);
}

pub fn unsubscribe(node: *core.NetworkCore, name: []const u8) !void {
    try setSubscription(node, name, false);
}

fn setSubscription(node: *core.NetworkCore, name: []const u8, subscribed: bool) !void {
    var boundaries: [topic_policy.boundary_max]local_intent.Boundary = undefined;
    const desired = intent(node, try @import("gossipsub/test_support.zig").subscriptionUpdate(node.service.gossipsub, name, subscribed, &boundaries));
    _ = try node.applyIntent(&desired, node.last_now);
}
