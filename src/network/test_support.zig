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
    entropy: u8 = 0,
    pool: engine_mod.EntropyPool = .{},
    first_initial: [constants.datagram_size_max]u8 = undefined,
    first_initial_len: usize = 0,
    drop_to_server: bool = false,
    client_source: types.Address = client_address,
    drop_to_address: ?types.Address = null,
    batch: engine_mod.SendBatch = undefined,

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
            .local = client_address,
            .seed = 1,
        }) catch |err| {
            self.server_ctx.deinit();
            self.client_ctx.deinit();
            return err;
        };
        self.server = Engine.init(std.testing.allocator, .{
            .tls = self.server_ctx,
            .limits = server_limits,
            .local = server_address,
            .seed = 2,
        }) catch |err| {
            self.client.deinit();
            self.server_ctx.deinit();
            return err;
        };
        self.now = .{ .mono_ms = 1_000, .unix_s = now_unix };
        self.entropy = 0;
        self.first_initial_len = 0;
        self.drop_to_server = false;
        self.client_source = client_address;
        self.drop_to_address = null;
    }

    pub fn deinit(self: *Pair) void {
        self.server.deinit();
        self.client.deinit();
    }

    pub fn sendOne(self: *Pair, engine: *Engine, index: u16, out: []u8) ?[]u8 {
        const count = engine.driverView().sendBatch(index, self.now, &self.batch);
        if (count == 0) return null;
        const first = self.batch.sent[0].bytes;
        @memcpy(out[0..first.len], first);
        return out[0..first.len];
    }

    pub fn nextEntropy(self: *Pair) [limits.local_cid_length]u8 {
        self.entropy +%= 1;
        return [_]u8{self.entropy} ** limits.local_cid_length;
    }

    pub fn nextPool(self: *Pair) *engine_mod.EntropyPool {
        self.pool.fill(self.nextEntropy());
        return &self.pool;
    }

    pub fn dial(self: *Pair) !engine_mod.Handle {
        return self.client.dial(
            &server_address,
            self.server_ctx.local_peer_id,
            self.now,
            self.nextEntropy(),
        );
    }

    pub fn advance(self: *Pair, ms: u64) void {
        self.now.mono_ms += ms;
    }

    pub fn pump(self: *Pair) !void {
        var rounds: usize = 0;
        while (rounds < 64) : (rounds += 1) {
            const source = self.client_source;
            var moved = try self.transfer(&self.client, &self.server, source, self.drop_to_server);
            moved = try self.transfer(&self.server, &self.client, server_address, false) or moved;
            self.client.driverView().tick(self.now);
            self.server.driverView().tick(self.now);
            if (!moved) return;
        }
        return error.PumpDidNotSettle;
    }

    pub fn transfer(
        self: *Pair,
        from: *Engine,
        to: *Engine,
        from_address: types.Address,
        drop: bool,
    ) !bool {
        var moved = false;
        var index: u16 = 0;
        while (index < from.driverView().slotCount()) : (index += 1) {
            var budget: u32 = 0;
            while (budget < limits.send_burst_max) {
                const count = from.driverView().sendBatch(index, self.now, &self.batch);
                if (count == 0) break;
                budget += count;
                moved = true;
                for (self.batch.sent[0..count]) |sent| {
                    const datagram = sent.bytes;
                    if (from == &self.client and self.first_initial_len == 0) {
                        @memcpy(self.first_initial[0..datagram.len], datagram);
                        self.first_initial_len = datagram.len;
                    }
                    if (drop) continue;
                    if (self.drop_to_address) |blocked| if (sent.to.eql(blocked)) continue;
                    var response: [constants.datagram_size_max]u8 = undefined;
                    _ = to.driverView().receive(
                        datagram,
                        &from_address,
                        self.now,
                        self.nextPool(),
                        &response,
                    );
                }
                if (count < constants.send_batch_max) break;
            }
        }
        return moved;
    }

    pub fn events(_: *Pair, engine: *Engine, storage: []Event) []Event {
        engine.driverView().releaseReported();
        return storage[0..engine.pollEvents(storage)];
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
