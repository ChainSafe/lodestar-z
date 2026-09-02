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

test "engine rejects invalid limits" {
    const host = try keys.KeyPair.fromSecretKey(&([_]u8{0} ** 31 ++ [_]u8{3}));
    var ctx = try tls.Context.init(&host, now_unix, [_]u8{3} ** 8);
    defer ctx.deinit();
    try std.testing.expectError(error.InvalidLimits, Engine.init(std.testing.allocator, &ctx, .{ .connections_max = 0 }));
    try std.testing.expectError(error.InvalidLimits, Engine.init(std.testing.allocator, &ctx, .{ .connections_max = 2_000 }));
    try std.testing.expectError(error.InvalidLimits, Engine.init(std.testing.allocator, &ctx, .{ .connections_max = 4, .handshaking_max = 8 }));
}
