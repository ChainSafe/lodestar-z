const std = @import("std");
const driver_mod = @import("driver.zig");
const engine_mod = @import("quic/engine.zig");
const limits = @import("quic/limits.zig");
const multistream = @import("wire/multistream.zig");
const support = @import("test_support.zig");
const types = @import("types.zig");
const udp_mod = @import("udp.zig");

const net = std.Io.net;
const Node = support.Node;

const ping_protocol = "/ipfs/ping/1.0.0";
const step_options = driver_mod.StepOptions{ .wait_max_ms = 10 };

fn writeSome(engine: *engine_mod.Engine, stream: engine_mod.StreamHandle, bytes: []const u8, fin: bool) !usize {
    return engine.write(stream, bytes, fin) catch |err| switch (err) {
        error.WouldBlock => 0,
        else => err,
    };
}

fn stepBoth(a: *Node, b: *Node, events_a: []engine_mod.Event, events_b: []engine_mod.Event) !struct { a: usize, b: usize } {
    var activity: [4]engine_mod.Handle = undefined;
    const ra = try a.transport.driver.step(std.testing.io, events_a, &activity, step_options);
    const rb = try b.transport.driver.step(std.testing.io, events_b, &activity, step_options);
    try std.testing.expectEqual(@as(u32, 0), ra.send_failures);
    try std.testing.expectEqual(@as(u32, 0), rb.send_failures);
    return .{ .a = ra.events, .b = rb.events };
}

test "driver bounds an idle step by the requested wait" {
    var node: Node = .{};
    try node.init(6);
    defer node.deinit();

    var events: [4]engine_mod.Event = undefined;
    var activity: [4]engine_mod.Handle = undefined;
    const started = std.Io.Clock.awake.now(std.testing.io).toMilliseconds();
    const result = try node.transport.driver.step(std.testing.io, &events, &activity, .{ .wait_max_ms = 5 });
    const elapsed = std.Io.Clock.awake.now(std.testing.io).toMilliseconds() - started;
    try std.testing.expect(elapsed < 200);
    try std.testing.expectEqual(@as(usize, 0), result.events);
    try std.testing.expectEqual(@as(usize, 0), result.activity);
    try std.testing.expect(!result.activity_pending);
    try std.testing.expect(node.transport.driver.nextTimeoutMs() == null);

    const floored = try node.transport.driver.step(std.testing.io, &events, &activity, .{ .wait_max_ms = 0 });
    try std.testing.expectEqual(@as(u32, 0), floored.datagrams_received);
}

test "driver reports activity for the connections that received datagrams" {
    var client: Node = .{};
    try client.init(7);
    defer client.deinit();
    var server: Node = .{};
    try server.init(8);
    defer server.deinit();

    const handle = try client.transport.driver.dial(
        std.testing.io,
        server.transport.udp.localAddress(),
        server.transport.tls.local_peer_id,
    );

    var client_events: [8]engine_mod.Event = undefined;
    var server_events: [8]engine_mod.Event = undefined;
    var activity: [4]engine_mod.Handle = undefined;
    var none: [0]engine_mod.Handle = undefined;
    var stream: ?engine_mod.StreamHandle = null;
    var reported: usize = 0;
    var deferred: usize = 0;
    var rounds: usize = 0;
    while (rounds < 50 and (reported == 0 or deferred == 0)) : (rounds += 1) {
        if (stream) |open| _ = try writeSome(&client.transport.engine, open, "ping", false);
        _ = try server.transport.driver.step(std.testing.io, &server_events, &activity, step_options);
        const narrow =
            try client.transport.driver.step(std.testing.io, client_events[0..0], none[0..0], step_options);
        try std.testing.expectEqual(@as(usize, 0), narrow.activity);
        if (narrow.activity_pending) deferred += 1;
        const wide =
            try client.transport.driver.step(std.testing.io, &client_events, &activity, step_options);
        for (activity[0..wide.activity]) |seen| try std.testing.expectEqual(handle, seen);
        if (wide.activity > 0) try std.testing.expect(!wide.activity_pending);
        reported += wide.activity;
        for (client_events[0..wide.events]) |event| {
            if (event != .connected) continue;
            if (stream == null) stream = try client.transport.engine.openStream(handle);
        }
    }
    try std.testing.expect(reported > 0);
    try std.testing.expect(deferred > 0);

    var quiet = false;
    var idle: usize = 0;
    while (idle < 50 and !quiet) : (idle += 1) {
        _ = try server.transport.driver.step(std.testing.io, &server_events, &activity, step_options);
        const result =
            try client.transport.driver.step(std.testing.io, &client_events, &activity, step_options);
        for (activity[0..result.activity]) |seen| try std.testing.expectEqual(handle, seen);
        if (result.datagrams_accepted > 0) continue;
        if (result.activity > 0) continue;
        try std.testing.expect(!result.activity_pending);
        quiet = true;
    }
    try std.testing.expect(quiet);
}

test "driver counts a hostile oversized datagram and keeps stepping" {
    var node: Node = .{};
    try node.init(3);
    defer node.deinit();

    const loopback = net.IpAddress{ .ip4 = .loopback(0) };
    var stranger = try loopback.bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer stranger.close(std.testing.io);

    const oversized = [_]u8{0x5a} ** 2_000;
    const destination = udp_mod.toNetwork(node.transport.udp.localAddress(), node.transport.udp.family);
    try stranger.send(std.testing.io, &destination, &oversized);

    var events: [4]engine_mod.Event = undefined;
    var activity: [4]engine_mod.Handle = undefined;
    var errors: u32 = 0;
    var rounds: usize = 0;
    while (rounds < 50 and errors == 0) : (rounds += 1) {
        const result = try node.transport.driver.step(std.testing.io, &events, &activity, step_options);
        try std.testing.expectEqual(@as(u32, 0), result.datagrams_accepted);
        try std.testing.expectEqual(@as(u32, 0), result.datagrams_received);
        try std.testing.expectEqual(@as(usize, 0), result.events);
        errors += result.receive_errors;
    }
    try std.testing.expectEqual(@as(u32, 1), errors);

    const after = try node.transport.driver.step(std.testing.io, &events, &activity, step_options);
    try std.testing.expectEqual(@as(u32, 0), after.receive_errors);
    try std.testing.expectEqual(@as(u32, 0), after.datagrams_accepted);
}

test "driver keeps batching past a counted receive error" {
    var node: Node = .{};
    try node.init(5);
    defer node.deinit();

    const loopback = net.IpAddress{ .ip4 = .loopback(0) };
    var stranger = try loopback.bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer stranger.close(std.testing.io);

    const oversized = [_]u8{0x5a} ** 2_000;
    const destination = udp_mod.toNetwork(node.transport.udp.localAddress(), node.transport.udp.family);
    var sent: usize = 0;
    while (sent < 3) : (sent += 1) try stranger.send(std.testing.io, &destination, &oversized);

    var events: [4]engine_mod.Event = undefined;
    var activity: [4]engine_mod.Handle = undefined;
    const result = try node.transport.driver.step(std.testing.io, &events, &activity, step_options);
    try std.testing.expect(result.receive_errors >= 2);
    try std.testing.expectEqual(@as(u32, 0), result.datagrams_received);
    try std.testing.expectEqual(@as(u32, 0), result.datagrams_accepted);
}

test "driver surfaces a send failure to an unreachable destination" {
    var node: Node = .{};
    try node.init(4);
    defer node.deinit();

    const unreachable_peer = types.Address{ .ip6 = .{
        .octets = [_]u8{0} ** 15 ++ [_]u8{1},
        .port = 4_001,
    } };
    const now = try driver_mod.currentTime(std.testing.io);
    _ = try node.transport.engine.dial(
        &unreachable_peer,
        node.transport.tls.local_peer_id,
        now,
        [_]u8{7} ** limits.local_cid_length,
    );

    var events: [4]engine_mod.Event = undefined;
    var activity: [4]engine_mod.Handle = undefined;
    const result = try node.transport.driver.step(std.testing.io, &events, &activity, step_options);
    try std.testing.expectEqual(@as(u32, 1), result.send_failures);
    try std.testing.expectEqual(@as(u32, 0), result.datagrams_sent);
    try std.testing.expectEqual(@as(usize, 1), result.events);
    switch (events[0]) {
        .closed => |closed| {
            try std.testing.expectEqual(engine_mod.Direction.outbound, closed.direction);
            try std.testing.expect(closed.reason == .send_failed);
            try std.testing.expect(closed.peer_id == null);
            try std.testing.expectEqual(@as(u16, 0), closed.conn.index);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(u16, 0), node.transport.engine.outbound);

    try std.testing.expectError(
        error.DestinationUnreachable,
        node.transport.driver.dial(std.testing.io, unreachable_peer, node.transport.tls.local_peer_id),
    );
}

test "driver completes a libp2p ping over loopback sockets" {
    var client: Node = .{};
    try client.init(1);
    defer client.deinit();
    var server: Node = .{};
    try server.init(2);
    defer server.deinit();

    const handle = try client.transport.driver.dial(std.testing.io, server.transport.udp.localAddress(), server.transport.tls.local_peer_id);

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
            try std.testing.expect(event.connected.peer_id.eql(&client.transport.tls.local_peer_id));
            server_handle = event.connected.conn;
        };
    }
    try std.testing.expect(client_connected);
    try std.testing.expect(server_handle != null);

    const stream = try client.transport.engine.openStream(handle);
    var dialer = try multistream.Dialer.init(ping_protocol);
    var hello: [2 * multistream.message_length_max]u8 = undefined;
    const hello_bytes = try dialer.initialWrite(&hello);
    try std.testing.expectEqual(hello_bytes.len, try writeSome(&client.transport.engine, stream, hello_bytes, false));

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
            const read = try server.transport.engine.read(server_stream, &buffer);
            var cursor: usize = 0;
            if (read.len > 0 and !negotiated) {
                var reply: [multistream.listener_write_max]u8 = undefined;
                const outcome = try listener.feed(buffer[0..read.len], &reply);
                if (outcome.write.len > 0) _ = try writeSome(&server.transport.engine, server_stream, outcome.write, false);
                if (outcome.status == .selected) negotiated = true;
                cursor = outcome.consumed;
            }
            if (negotiated and cursor < read.len) _ = try writeSome(&server.transport.engine, server_stream, buffer[cursor..read.len], false);
        }
        var client_buffer: [256]u8 = undefined;
        const client_read = try client.transport.engine.read(stream, &client_buffer);
        if (client_read.len > 0 and !accepted) {
            const outcome = try dialer.feed(client_buffer[0..client_read.len]);
            if (outcome.status == .accepted) {
                accepted = true;
                try std.testing.expectEqual(@as(usize, 32), try writeSome(&client.transport.engine, stream, &payload, false));
            }
        } else if (client_read.len > 0) {
            @memcpy(echo[echoed..][0..client_read.len], client_buffer[0..client_read.len]);
            echoed += client_read.len;
        }
    }
    try std.testing.expect(accepted);
    try std.testing.expectEqualSlices(u8, &payload, &echo);

    _ = client.transport.engine.close(handle, 0);
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
