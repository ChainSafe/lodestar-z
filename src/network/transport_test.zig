const std = @import("std");
const support = @import("test_support.zig");
const engine_mod = @import("quic/engine.zig");
const keys = @import("wire/keys.zig");
const multiaddr = @import("wire/multiaddr.zig");
const transport_mod = @import("transport.zig");

const Transport = transport_mod.Transport;
const step_options = transport_mod.StepOptions{ .wait_max_ms = 10 };
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
        const dialed = try support.step(&dialer, std.testing.io, &dialer_events, &activity, step_options);
        _ = try support.step(&listener, std.testing.io, &listener_events, &activity, step_options);
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
        const sent = try support.step(&dialer, std.testing.io, &dialer_events, &activity, step_options);
        try std.testing.expectEqual(@as(u32, 0), sent.send_failures);
        datagrams_sent += sent.datagrams_sent;
        send_calls += sent.send_calls;
        const got = try support.step(&listener, std.testing.io, &listener_events, &activity, step_options);
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
        const dialed = try support.step(&dialer, std.testing.io, &dialer_events, &activity, step_options);
        _ = try support.step(&listener, std.testing.io, &listener_events, &activity, step_options);
        for (dialer_events[0..dialed.events]) |event| {
            if (event == .connected) connected = true;
        }
    }
    try std.testing.expect(connected);
    try std.testing.expect(dialer.keylog != null);
    _ = try support.step(&dialer, std.testing.io, &dialer_events, &activity, .{ .wait_max_ms = 0 });
    const written = try tmp.dir.statFile(std.testing.io, "keys.log", .{});
    try std.testing.expect(written.size > 0);
    try std.testing.expectEqual(written.size, dialer.keylog_offset);
}

fn failKeylog(_: ?*anyopaque, _: std.Io.File, _: []const u8, _: []const []const u8, _: usize, _: u64) std.Io.File.WritePositionalError!usize {
    return error.NoSpaceLeft;
}

test "transport keylog failure preserves completed lifecycle delivery" {
    {
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
        const now = try transport_mod.currentTime(std.testing.io);
        const handle = try node.engine.dial(&remote.localAddress(), remote.peerId(), now);
        try std.testing.expect(node.engine.close(handle, 0));
        try std.testing.expect(node.engine.registry.slots[handle.index].handshake.appendKeylog("test material"));
        var vtable = std.testing.io.vtable.*;
        vtable.fileWritePositional = failKeylog;
        const failed_io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
        var events: [8]engine_mod.Event = undefined;
        var activity: [128]engine_mod.Handle = undefined;
        const result = node.step(failed_io, &events, &activity, .{ .wait_max_ms = 0 });
        try std.testing.expectEqual(error.KeylogWriteFailed, result.failure.?);
        try std.testing.expectEqual(@as(usize, 1), result.progress.events);
        try std.testing.expect(events[0] == .closed);

        const next = try support.step(&node, std.testing.io, &events, &activity, .{ .wait_max_ms = 0 });
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
    try std.testing.expectEqual(@as(usize, 0), dialer.engine.activeIndices().len);
}

test "dual-stack transport authenticates both families through one connection budget" {
    for ([_]bool{ false, true }) |inbound| {
        const hub_key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{101}));
        const key4 = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{102}));
        const key6 = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{103}));
        const limits: engine_mod.Limits = .{ .connections_max = 2, .handshaking_max = 2, .dialing_max = 2, .outbound_max = 2 };
        var hub: Transport = .{};
        try hub.init(std.testing.allocator, std.testing.io, .{ .host = &hub_key, .bind = .{ .dual = .{ .ip4 = .loopback(0), .ip6 = .loopback(0) } }, .limits = limits });
        defer hub.deinit(std.testing.io);
        var peer4: Transport = .{};
        try peer4.init(std.testing.allocator, std.testing.io, .{ .host = &key4, .bind = .{ .ip4 = .loopback(0) }, .limits = limits });
        defer peer4.deinit(std.testing.io);
        var peer6: Transport = .{};
        try peer6.init(std.testing.allocator, std.testing.io, .{ .host = &key6, .bind = .{ .ip6 = .loopback(0) }, .limits = limits });
        defer peer6.deinit(std.testing.io);
        const addresses = hub.udp.localAddresses();
        if (inbound) {
            _ = try peer4.dialPeer(std.testing.io, addresses[0].?, hub.peerId());
            _ = try peer6.dialPeer(std.testing.io, addresses[1].?, hub.peerId());
        } else {
            _ = try hub.dialPeer(std.testing.io, peer4.localAddress(), peer4.peerId());
            _ = try hub.dialPeer(std.testing.io, peer6.localAddress(), peer6.peerId());
        }
        var connected: [2]bool = .{ false, false };
        var events: [8]engine_mod.Event = undefined;
        var activity: [2]engine_mod.Handle = undefined;
        for (0..400) |_| {
            const result = try support.step(&hub, std.testing.io, &events, &activity, .{ .wait_max_ms = 1 });
            for (events[0..result.events]) |event| if (event == .connected) {
                const peer = hub.engine.peerAddress(event.connected.conn).?;
                connected[if (peer == .ip4) @as(usize, 0) else 1] = true;
            };
            _ = try support.step(&peer4, std.testing.io, &events, &activity, .{ .wait_max_ms = 1 });
            _ = try support.step(&peer6, std.testing.io, &events, &activity, .{ .wait_max_ms = 1 });
            if (connected[0] and connected[1]) break;
        }
        try std.testing.expect(connected[0] and connected[1]);
        try std.testing.expectEqual(@as(usize, 2), hub.engine.registry.active_len);
        try std.testing.expectEqual(@as(usize, 2), hub.engine.registry.slots.len);
        try std.testing.expectError(error.DestinationUnreachable, peer4.dialPeer(std.testing.io, addresses[1].?, hub.peerId()));
        if (!inbound) try std.testing.expectError(error.DialLimit, hub.dialPeer(std.testing.io, peer4.localAddress(), peer4.peerId()));
    }
}

test "transport validates socket work limits before startup allocation" {
    const key = try keys.KeyPair.fromSecretKey(&([_]u8{0} ** 31 ++ [_]u8{27}));
    const invalid = [_]transport_mod.WorkLimits{
        .{ .send_per_step_max = 0 },
        .{ .send_per_step_max = transport_mod.send_burst_max + 1 },
        .{ .receive_per_step_max = 0 },
        .{ .receive_per_step_max = @import("constants.zig").receive_batch_max + 1 },
        .{ .work_per_step_max = 1 },
        .{ .work_per_step_max = transport_mod.work_per_step_ceiling + 1 },
    };
    for (invalid) |work_limits| {
        var target: Transport = .{};
        try std.testing.expectError(error.InvalidLimits, target.init(std.testing.failing_allocator, std.testing.io, .{
            .host = &key,
            .bind = .{ .ip4 = .loopback(0) },
            .work_limits = work_limits,
        }));
    }
    try (transport_mod.WorkLimits{ .send_per_step_max = 1, .receive_per_step_max = 1, .work_per_step_max = 2 }).validate();
    try (transport_mod.WorkLimits{ .work_per_step_max = transport_mod.work_per_step_ceiling }).validate();
}

test "transport memory plan accounts for its pacing queue and send batch" {
    var node: Transport = .{};
    try initTransport(&node, 28);
    defer node.deinit(std.testing.io);
    const plan = node.memoryPlan();
    try std.testing.expectEqual(node.engine.memoryPlan(), plan.engine);
    try std.testing.expectEqual(node.engine.limits.connections_max, plan.scheduled_datagrams);
    try std.testing.expectEqual(@as(u64, node.pending.entries.len * @import("constants.zig").datagram_size_max), plan.scheduled_payload_bytes);
    try std.testing.expectEqual(@as(u64, std.mem.sliceAsBytes(node.pending.entries).len), plan.scheduled_storage_bytes);
    try std.testing.expect(plan.scheduled_storage_bytes >= plan.scheduled_payload_bytes);
    try std.testing.expectEqual(node.batch.buffers.len, plan.ready_batch_datagrams);
    try std.testing.expectEqual(@sizeOf(@TypeOf(node.batch)), plan.ready_batch_storage_bytes);
}
