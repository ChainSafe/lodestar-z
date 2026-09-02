const std = @import("std");
const constants = @import("constants.zig");
const driver_mod = @import("driver.zig");
const engine_mod = @import("quic/engine.zig");
const keys = @import("identity/keys.zig");
const multistream = @import("multistream.zig");
const runtime = @import("runtime.zig");
const tls = @import("tls/context.zig");

const net = std.Io.net;

const ping_protocol = "/ipfs/ping/1.0.0";

const Node = struct {
    ctx: tls.Context = undefined,
    engine: engine_mod.Engine = undefined,
    udp: runtime.Udp = undefined,
    driver: driver_mod.Driver = undefined,

    fn init(self: *Node, seed: u8) !void {
        const key = try keys.KeyPair.fromSecretKey(&([_]u8{0} ** 31 ++ [_]u8{seed}));
        self.ctx = try tls.Context.init(&key, (try driver_mod.currentTime(std.testing.io)).unix_s, [_]u8{seed} ** 8);
        errdefer self.ctx.deinit();
        self.engine = try engine_mod.Engine.init(std.testing.allocator, &self.ctx, .{});
        errdefer self.engine.deinit();
        self.udp = try runtime.Udp.bind(std.testing.io, .{ .ip4 = .loopback(0) });
        errdefer self.udp.close(std.testing.io);
        self.driver = try driver_mod.Driver.initWithConfig(&self.engine, &self.udp, .{ .poll_interval_ms = 10 });
    }

    fn deinit(self: *Node) void {
        self.udp.close(std.testing.io);
        self.engine.deinit();
        self.ctx.deinit();
    }
};

fn stepBoth(a: *Node, b: *Node, events_a: []engine_mod.Event, events_b: []engine_mod.Event) !struct { a: usize, b: usize } {
    const ra = try a.driver.step(std.testing.io, events_a);
    const rb = try b.driver.step(std.testing.io, events_b);
    return .{ .a = ra.events, .b = rb.events };
}

test "driver rejects a zero poll interval" {
    var core: engine_mod.Engine = undefined;
    var udp = runtime.Udp.init(undefined);
    try std.testing.expectError(error.InvalidPollInterval, driver_mod.Driver.initWithConfig(&core, &udp, .{ .poll_interval_ms = 0 }));
}

test "driver completes a libp2p ping over loopback sockets" {
    var client: Node = .{};
    try client.init(1);
    defer client.deinit();
    var server: Node = .{};
    try server.init(2);
    defer server.deinit();

    const handle = try client.driver.dial(std.testing.io, server.udp.localAddress(), server.ctx.local_peer_id);

    var client_events: [8]engine_mod.Event = undefined;
    var server_events: [8]engine_mod.Event = undefined;
    var server_handle: ?engine_mod.Handle = null;
    var client_connected = false;
    var rounds: usize = 0;
    while (rounds < 200 and (server_handle == null or !client_connected)) : (rounds += 1) {
        const counts = try stepBoth(&client, &server, &client_events, &server_events);
        for (client_events[0..counts.a]) |event| if (event == .connected) {
            try std.testing.expectEqual(handle, event.connected.conn);
            client_connected = true;
        };
        for (server_events[0..counts.b]) |event| if (event == .connected) {
            try std.testing.expect(event.connected.peer_id.eql(&client.ctx.local_peer_id));
            server_handle = event.connected.conn;
        };
    }
    try std.testing.expect(client_connected);
    try std.testing.expect(server_handle != null);

    const stream = try client.engine.openStream(handle);
    var dialer = try multistream.Dialer.init(ping_protocol);
    var hello: [2 * multistream.message_length_max]u8 = undefined;
    const hello_bytes = try dialer.initialWrite(&hello);
    try std.testing.expectEqual(hello_bytes.len, try client.engine.write(stream, hello_bytes, false));

    var listener = multistream.Listener.init(&.{ping_protocol});
    var inbound: ?engine_mod.StreamHandle = null;
    var negotiated = false;
    var accepted = false;
    const payload = [_]u8{0xab} ** 32;
    var echo: [32]u8 = undefined;
    var echoed: usize = 0;
    rounds = 0;
    while (rounds < 400 and echoed < 32) : (rounds += 1) {
        const counts = try stepBoth(&client, &server, &client_events, &server_events);
        for (server_events[0..counts.b]) |event| if (event == .stream_opened) {
            inbound = event.stream_opened;
        };
        if (inbound) |server_stream| {
            var buffer: [256]u8 = undefined;
            const read = try server.engine.read(server_stream, &buffer);
            var cursor: usize = 0;
            if (read.len > 0 and !negotiated) {
                var reply: [2 * multistream.message_length_max]u8 = undefined;
                const outcome = try listener.feed(buffer[0..read.len], &reply);
                if (outcome.write.len > 0) _ = try server.engine.write(server_stream, outcome.write, false);
                if (outcome.status == .selected) negotiated = true;
                cursor = outcome.consumed;
            }
            if (negotiated and cursor < read.len) _ = try server.engine.write(server_stream, buffer[cursor..read.len], false);
        }
        var client_buffer: [256]u8 = undefined;
        const client_read = try client.engine.read(stream, &client_buffer);
        if (client_read.len > 0 and !accepted) {
            const outcome = try dialer.feed(client_buffer[0..client_read.len]);
            if (outcome.status == .accepted) {
                accepted = true;
                try std.testing.expectEqual(@as(usize, 32), try client.engine.write(stream, &payload, false));
            }
        } else if (client_read.len > 0) {
            @memcpy(echo[echoed..][0..client_read.len], client_buffer[0..client_read.len]);
            echoed += client_read.len;
        }
    }
    try std.testing.expect(accepted);
    try std.testing.expectEqualSlices(u8, &payload, &echo);

    client.engine.close(handle, 0);
    var closed = false;
    rounds = 0;
    while (rounds < 100 and !closed) : (rounds += 1) {
        const counts = try stepBoth(&client, &server, &client_events, &server_events);
        for (server_events[0..counts.b]) |event| if (event == .closed) {
            try std.testing.expectEqual(server_handle.?, event.closed.conn);
            closed = true;
        };
    }
    try std.testing.expect(closed);
}
