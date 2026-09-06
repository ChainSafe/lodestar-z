const std = @import("std");
const driver_mod = @import("driver.zig");
const engine_mod = @import("quic/engine.zig");
const keys = @import("wire/keys.zig");
const multiaddr = @import("wire/multiaddr.zig");
const transport_mod = @import("transport.zig");

const Transport = transport_mod.Transport;
const step_options = driver_mod.StepOptions{ .wait_max_ms = 10 };
const payload_len = 64 * 1024;

fn initTransport(target: *Transport, seed: u8) !void {
    const key = try keys.KeyPair.fromSecretKey(&([_]u8{0} ** 31 ++ [_]u8{seed}));
    try target.init(std.testing.allocator, std.testing.io, .{
        .host = &key,
        .bind = .{ .ip4 = .loopback(0) },
    });
}

fn writeSome(
    engine: *engine_mod.Engine,
    stream: engine_mod.StreamHandle,
    bytes: []const u8,
) !usize {
    return engine.write(stream, bytes, false) catch |err| switch (err) {
        error.WouldBlock => 0,
        else => err,
    };
}

test "transport moves a bulk payload over loopback sockets with batched sends" {
    var dialer: Transport = .{};
    try initTransport(&dialer, 21);
    defer dialer.deinit(std.testing.io);
    var listener: Transport = .{};
    try initTransport(&listener, 22);
    defer listener.deinit(std.testing.io);

    const target = listener.localMultiaddr();
    try std.testing.expect(target.peer.?.eql(&listener.peerId()));
    const handle = try dialer.dial(std.testing.io, &target);

    var dialer_events: [8]engine_mod.Event = undefined;
    var listener_events: [8]engine_mod.Event = undefined;
    var activity: [4]engine_mod.Handle = undefined;
    var connected = false;
    var rounds: usize = 0;
    while (rounds < 200 and !connected) : (rounds += 1) {
        const dialed = try dialer.step(std.testing.io, &dialer_events, &activity, step_options);
        _ = try listener.step(std.testing.io, &listener_events, &activity, step_options);
        for (dialer_events[0..dialed.events]) |event| {
            if (event == .connected) connected = true;
        }
    }
    try std.testing.expect(connected);

    var payload: [payload_len]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index *% 31 +% 7);
    const stream = try dialer.engine.openStream(handle);
    var sink: [payload_len]u8 = undefined;
    var written: usize = 0;
    var received: usize = 0;
    var inbound: ?engine_mod.StreamHandle = null;
    var datagrams_sent: u32 = 0;
    var send_calls: u32 = 0;
    rounds = 0;
    while (rounds < 2_000 and received < payload_len) : (rounds += 1) {
        if (written < payload_len) {
            written += try writeSome(&dialer.engine, stream, payload[written..]);
        }
        const sent = try dialer.step(std.testing.io, &dialer_events, &activity, step_options);
        try std.testing.expectEqual(@as(u32, 0), sent.send_failures);
        datagrams_sent += sent.datagrams_sent;
        send_calls += sent.send_calls;
        const got = try listener.step(std.testing.io, &listener_events, &activity, step_options);
        for (listener_events[0..got.events]) |event| {
            if (event == .stream_opened) inbound = event.stream_opened;
        }
        const open = inbound orelse continue;
        var reads: usize = 0;
        while (reads < 8 and received < payload_len) : (reads += 1) {
            const read = try listener.engine.read(open, sink[received..]);
            if (read.len == 0) break;
            received += read.len;
        }
    }
    try std.testing.expectEqual(@as(usize, payload_len), received);
    try std.testing.expectEqualSlices(u8, &payload, &sink);
    try std.testing.expect(send_calls > 0);
    try std.testing.expect(send_calls < datagrams_sent);
}

test "transport appends TLS key material to the configured keylog file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var keylog: [80]u8 = undefined;
    const keylog_path = try std.fmt.bufPrint(&keylog, ".zig-cache/tmp/{s}/keys.log", .{&tmp.sub_path});
    const key = try keys.KeyPair.fromSecretKey(&([_]u8{0} ** 31 ++ [_]u8{24}));

    var dialer: Transport = .{};
    try dialer.init(std.testing.allocator, std.testing.io, .{
        .host = &key,
        .bind = .{ .ip4 = .loopback(0) },
        .keylog_path = keylog_path,
    });
    defer dialer.deinit(std.testing.io);
    var listener: Transport = .{};
    try initTransport(&listener, 25);
    defer listener.deinit(std.testing.io);

    const target = listener.localMultiaddr();
    _ = try dialer.dial(std.testing.io, &target);
    var dialer_events: [8]engine_mod.Event = undefined;
    var listener_events: [8]engine_mod.Event = undefined;
    var activity: [4]engine_mod.Handle = undefined;
    var connected = false;
    var rounds: usize = 0;
    while (rounds < 200 and !connected) : (rounds += 1) {
        const dialed = try dialer.step(std.testing.io, &dialer_events, &activity, step_options);
        _ = try listener.step(std.testing.io, &listener_events, &activity, step_options);
        for (dialer_events[0..dialed.events]) |event| {
            if (event == .connected) connected = true;
        }
    }
    try std.testing.expect(connected);
    try std.testing.expect(dialer.keylog != null);
    _ = try dialer.step(std.testing.io, &dialer_events, &activity, .{ .wait_max_ms = 0 });
    const written = try tmp.dir.statFile(std.testing.io, "keys.log", .{});
    try std.testing.expect(written.size > 0);
    try std.testing.expectEqual(written.size, dialer.keylog_offset);
}

fn failKeylog(_: ?*anyopaque, _: std.Io.File, _: []const u8, _: []const []const u8, _: usize, _: u64) std.Io.File.WritePositionalError!usize {
    return error.NoSpaceLeft;
}

test "transport keylog failure preserves legacy and progress lifecycle delivery" {
    for ([_]bool{ false, true }) |preserve_progress| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var path: [80]u8 = undefined;
        const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{29}));
        var node: Transport = .{};
        try node.init(std.testing.allocator, std.testing.io, .{
            .host = &key,
            .bind = .{ .ip4 = .loopback(0) },
            .keylog_path = try std.fmt.bufPrint(&path, ".zig-cache/tmp/{s}/keys.log", .{&tmp.sub_path}),
        });
        defer node.deinit(std.testing.io);
        var remote: Transport = .{};
        try initTransport(&remote, 30);
        defer remote.deinit(std.testing.io);
        const now = try driver_mod.currentTime(std.testing.io);
        const handle = try node.engine.dial(&remote.localAddress(), remote.peerId(), now, @splat(1));
        try std.testing.expect(node.engine.close(handle, 0));
        try std.testing.expect(node.engine.registry.slots[handle.index].handshake.appendKeylog("test material"));
        var vtable = std.testing.io.vtable.*;
        vtable.fileWritePositional = failKeylog;
        const failed_io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
        var events: [8]engine_mod.Event = undefined;
        var activity: [128]engine_mod.Handle = undefined;
        if (preserve_progress) {
            const result = node.stepProgress(failed_io, &events, &activity, .{ .wait_max_ms = 0 });
            try std.testing.expectEqual(error.KeylogWriteFailed, result.failure.?);
            try std.testing.expectEqual(@as(usize, 1), result.progress.events);
            try std.testing.expect(events[0] == .closed);
        } else {
            try std.testing.expectError(error.KeylogWriteFailed, node.step(failed_io, &events, &activity, .{ .wait_max_ms = 0 }));
            const next = try node.step(std.testing.io, &events, &activity, .{ .wait_max_ms = 0 });
            try std.testing.expectEqual(@as(usize, 1), next.events);
            try std.testing.expect(events[0] == .closed);
        }
        const next = try node.step(std.testing.io, &events, &activity, .{ .wait_max_ms = 0 });
        try std.testing.expectEqual(@as(usize, 0), next.events);
        try std.testing.expectEqual(@as(u16, 0), node.engine.registry.active_len);
    }
}

test "transport socket refuses a batch that carries an oversized datagram" {
    var node: Transport = .{};
    try initTransport(&node, 26);
    defer node.deinit(std.testing.io);

    var oversized: [1_501]u8 = undefined;
    @memset(&oversized, 0x5a);
    var fitting: [8]u8 = undefined;
    @memset(&fitting, 0x5b);
    const to = node.localAddress();
    const batch = [_]engine_mod.Sent{
        .{ .bytes = &fitting, .to = to },
        .{ .bytes = &oversized, .to = to },
    };
    try std.testing.expectError(error.DatagramTooLarge, node.udp.sendMany(std.testing.io, &batch));
    try node.udp.sendMany(std.testing.io, batch[0..1]);
}

test "transport refuses to dial a multiaddr without a peer id" {
    var dialer: Transport = .{};
    try initTransport(&dialer, 23);
    defer dialer.deinit(std.testing.io);

    const target = multiaddr.Multiaddr{ .address = dialer.localAddress() };
    try std.testing.expectError(error.MissingPeerId, dialer.dial(std.testing.io, &target));
    try std.testing.expectEqual(@as(usize, 0), dialer.engine.driverView().activeIndices().len);
}
