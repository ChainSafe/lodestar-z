const std = @import("std");
const constants = struct {
    const datagram_size_max = 1500;
    const send_batch_max = 16;
};
const limits = struct {
    const client_initial_min = 1200;
};
const types = struct {
    const Address = udp_mod.Address;
    const Sent = udp_mod.Outgoing;
};
const udp_mod = @import("root.zig");

const net = std.Io.net;

fn oneSecond() std.Io.Timeout {
    return .{ .duration = .{ .raw = .fromMilliseconds(1_000), .clock = .awake } };
}

test "UDP receives into caller storage and recovers after truncation" {
    var buffer: [constants.datagram_size_max]u8 = undefined;
    const loopback = net.IpAddress{ .ip4 = .loopback(0) };
    var receiver = try udp_mod.Sockets.bind(std.testing.io, .single(loopback));
    defer receiver.close(std.testing.io);
    var sender = try udp_mod.Sockets.bind(std.testing.io, .single(loopback));
    defer sender.close(std.testing.io);
    try std.testing.expect(receiver.localAddress().port() != 0);

    const payload = [_]u8{0x44} ** limits.client_initial_min;
    const receiver_address = receiver.localAddress();
    try sender.sendTo(std.testing.io, receiver_address, &payload, constants.datagram_size_max);
    const first = try receiver.receiveDatagram(std.testing.io, &buffer, oneSecond());
    try std.testing.expectEqualSlices(u8, &payload, first.bytes);
    try std.testing.expect(first.bytes.ptr == &buffer);
    first.bytes[0] = 0x00;
    try std.testing.expectEqual(sender.localAddress().port(), first.from.port());

    var raw_sender = try loopback.bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer raw_sender.close(std.testing.io);
    const oversized = [_]u8{0x55} ** (constants.datagram_size_max + 1);
    const destination = udp_mod.Address.toNetwork(receiver.localAddress());
    try raw_sender.send(std.testing.io, &destination, &oversized);
    try std.testing.expectError(error.DatagramTooLarge, receiver.receiveDatagram(std.testing.io, &buffer, oneSecond()));

    try sender.sendTo(std.testing.io, receiver_address, &payload, constants.datagram_size_max);
    const second = try receiver.receiveDatagram(std.testing.io, &buffer, oneSecond());
    try std.testing.expectEqualSlices(u8, &payload, second.bytes);
}

test "UDP receive times out without traffic" {
    var buffer: [constants.datagram_size_max]u8 = undefined;
    const loopback = net.IpAddress{ .ip4 = .loopback(0) };
    var receiver = try udp_mod.Sockets.bind(std.testing.io, .single(loopback));
    defer receiver.close(std.testing.io);
    const short = std.Io.Timeout{ .duration = .{ .raw = .fromMilliseconds(20), .clock = .awake } };
    try std.testing.expectError(error.Timeout, receiver.receiveDatagram(std.testing.io, &buffer, short));
}

test "UDP rejects oversized sends before I/O" {
    var transport = try udp_mod.Sockets.bind(std.testing.io, .{ .ip4 = .loopback(0) });
    defer transport.close(std.testing.io);
    const oversized = [_]u8{0x44} ** (constants.datagram_size_max + 1);
    const destination = types.Address{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 9_001 } };
    try std.testing.expectError(
        error.DatagramTooLarge,
        transport.sendTo(undefined, destination, &oversized, constants.datagram_size_max),
    );
}

test "UDP address conversion normalizes mapped IPv4" {
    const mapped = net.IpAddress{ .ip6 = .{
        .bytes = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff, 10, 0, 0, 7 },
        .port = 4_001,
        .flow = 0,
        .interface = .{ .index = 0 },
    } };
    const address = udp_mod.Address.fromNetwork(mapped);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 7 }, &address.ip4.octets);
    try std.testing.expectEqual(@as(u16, 4_001), address.port());
    const back = udp_mod.Address.toNetwork(address);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 7 }, &back.ip4.bytes);
    try std.testing.expectEqual(@as(u16, 4_001), back.ip4.port);
}

test "UDP reports successful batch prefixes when a later send fails" {
    const Fake = struct {
        fn send(_: ?*anyopaque, _: net.Socket.Handle, messages: []net.OutgoingMessage, _: net.SendFlags) struct { ?net.Socket.SendError, usize } {
            std.debug.assert(messages.len == 2);
            return .{ error.NetworkUnreachable, 1 };
        }
    };
    var socket = try udp_mod.Sockets.bind(std.testing.io, .{ .ip4 = .loopback(0) });
    defer socket.close(std.testing.io);
    var vtable = std.testing.io.vtable.*;
    vtable.netSend = Fake.send;
    const io: std.Io = .{ .userdata = null, .vtable = &vtable };
    const destination = socket.localAddress();
    var first = "first".*;
    var unsent = "unsent".*;
    var scratch1: udp_mod.BatchScratch = undefined;
    const outcome = socket.sendMany(io, &.{
        .{ .to = destination, .bytes = &first },
        .{ .to = destination, .bytes = &unsent },
    }, constants.datagram_size_max, &scratch1);
    try std.testing.expectEqual(@as(usize, 1), outcome.sent);
    try std.testing.expectEqual(error.NetworkUnreachable, outcome.failure.?);
}

test "dual-stack UDP stops at pressure without waiting or retaining the suffix" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var buffer: [constants.datagram_size_max]u8 = undefined;
    var target = try udp_mod.Sockets.bind(std.testing.io, .{ .dual = .{ .ip4 = .loopback(0), .ip6 = .loopback(0) } });
    defer target.close(std.testing.io);
    // A successful IPv4 prefix followed by IPv6 pressure also drops the remaining IPv4 suffix.
    const Refused = struct {
        installed: bool = false,
        outcomes: [2]udp_mod.SendOutcome = undefined,

        var socket: std.Io.net.Socket.Handle = -1;
        var waits: usize = 0;

        fn run(self: *@This(), udp: *udp_mod.Sockets) void {
            const filter = @import("root.zig").testing.SendFilter;
            socket = udp.values[1].?.handle;
            if (!filter.install(&.{.{ .socket = socket, .errno = .AGAIN, .nonblocking_only = true }})) return;
            self.installed = true;
            var vtable = std.testing.io.vtable.*;
            vtable.batchAwaitConcurrent = wait;
            const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
            const local = udp.localAddresses();
            var payload = [_]u8{ 1, 2, 3 };
            const batch = [_]types.Sent{
                .{ .to = local[0].?, .bytes = payload[0..1] },
                .{ .to = local[1].?, .bytes = payload[1..2] },
                .{ .to = local[0].?, .bytes = payload[2..3] },
            };
            var scratch2: udp_mod.BatchScratch = undefined;
            self.outcomes[0] = udp.sendMany(io, &batch, constants.datagram_size_max, &scratch2);
            var fresh: [1]u8 = .{4};
            var scratch3: udp_mod.BatchScratch = undefined;
            self.outcomes[1] = udp.sendMany(io, &.{.{ .to = local[0].?, .bytes = &fresh }}, constants.datagram_size_max, &scratch3);
        }

        fn wait(_: ?*anyopaque, _: *std.Io.Batch, _: std.Io.Timeout) std.Io.Batch.AwaitConcurrentError!void {
            waits += 1;
            return error.Canceled;
        }
    };
    Refused.waits = 0;
    var refused: Refused = .{};
    const thread = try std.Thread.spawn(.{}, Refused.run, .{ &refused, &target });
    thread.join();
    // Kernels without seccomp filters cannot produce the errnos.
    if (!refused.installed) return error.SkipZigTest;
    try std.testing.expectEqual(@as(usize, 0), Refused.waits);
    try std.testing.expectEqual(udp_mod.SendOutcome{ .sent = 1, .failure = error.WouldBlock }, refused.outcomes[0]);
    try std.testing.expectEqual(udp_mod.SendOutcome{ .sent = 1, .failure = null }, refused.outcomes[1]);
    var ready: [2]bool = @splat(true);
    for ([_]u8{ 1, 4 }) |expected| {
        const message = (try target.receiveReadyDatagram(std.testing.io, &buffer, &ready)).?;
        try std.testing.expectEqualSlices(u8, &.{expected}, message.bytes);
        try std.testing.expect(message.from == .ip4);
    }
    try std.testing.expectEqual(null, try target.receiveReadyDatagram(std.testing.io, &buffer, &ready));
}

test "UDP sends each batch's own datagrams after a larger batch and a failed prefix" {
    const Recorder = struct {
        calls: usize = 0,
        fail_after: ?usize = null,
        ports: [constants.send_batch_max]u16 = undefined,
        payloads: [constants.send_batch_max][]const u8 = undefined,
        len: usize = 0,

        fn send(userdata: ?*anyopaque, _: net.Socket.Handle, messages: []net.OutgoingMessage, _: net.SendFlags) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.calls += 1;
            self.len = messages.len;
            for (messages, 0..) |message, i| {
                self.ports[i] = udp_mod.Address.fromNetwork(message.address.*).port();
                self.payloads[i] = message.data_ptr[0..message.data_len];
            }
            if (self.fail_after) |sent| return .{ error.NetworkUnreachable, sent };
            return .{ null, messages.len };
        }
    };
    var socket = try udp_mod.Sockets.bind(std.testing.io, .{ .ip4 = .loopback(0) });
    defer socket.close(std.testing.io);
    var recorder: Recorder = .{};
    var vtable = std.testing.io.vtable.*;
    vtable.netSend = Recorder.send;
    const io: std.Io = .{ .userdata = &recorder, .vtable = &vtable };
    const first: types.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 9_001 } };
    const second: types.Address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 9_002 } };
    var payloads = [_]u8{ 1, 2, 3, 4 };
    recorder.fail_after = 1;
    var scratch4: udp_mod.BatchScratch = undefined;
    const failed = socket.sendMany(io, &.{
        .{ .to = first, .bytes = payloads[0..1] },
        .{ .to = first, .bytes = payloads[1..2] },
        .{ .to = first, .bytes = payloads[2..3] },
    }, constants.datagram_size_max, &scratch4);
    try std.testing.expectEqual(@as(usize, 1), failed.sent);
    try std.testing.expectEqual(@as(usize, 3), recorder.len);
    recorder.fail_after = null;
    var scratch5: udp_mod.BatchScratch = undefined;
    const outcome = socket.sendMany(io, &.{.{ .to = second, .bytes = payloads[3..4] }}, constants.datagram_size_max, &scratch5);
    try std.testing.expectEqual(@as(usize, 1), outcome.sent);
    try std.testing.expect(outcome.failure == null);
    try std.testing.expectEqual(@as(usize, 2), recorder.calls);
    try std.testing.expectEqual(@as(usize, 1), recorder.len);
    try std.testing.expectEqual(@as(u16, 9_002), recorder.ports[0]);
    try std.testing.expectEqualSlices(u8, &.{4}, recorder.payloads[0]);
}

test "dual-stack UDP services both families fairly" {
    var buffer: [constants.datagram_size_max]u8 = undefined;
    var target = try udp_mod.Sockets.bind(std.testing.io, .{ .dual = .{ .ip4 = .loopback(0), .ip6 = .loopback(0) } });
    defer target.close(std.testing.io);
    const local = target.localAddresses();
    try std.testing.expect(local[0].? == .ip4 and local[1].? == .ip6);
    var payload = [_]u8{ 1, 2, 3 };
    const batch = [_]types.Sent{
        .{ .to = local[0].?, .bytes = payload[0..1] },
        .{ .to = local[1].?, .bytes = payload[1..2] },
        .{ .to = local[0].?, .bytes = payload[2..3] },
    };
    var scratch6: udp_mod.BatchScratch = undefined;
    const outcome = target.sendMany(std.testing.io, &batch, constants.datagram_size_max, &scratch6);
    try std.testing.expectEqual(batch.len, outcome.sent);
    try std.testing.expect(outcome.failure == null);
    for ([_]u8{ 1, 2, 3 }, 0..) |expected, i| {
        const message = try target.receiveDatagram(std.testing.io, &buffer, oneSecond());
        try std.testing.expectEqualSlices(u8, &.{expected}, message.bytes);
        try std.testing.expectEqual(i == 1, message.from == .ip6);
    }
}

test "dual-stack UDP binds explicit addresses on the same port and rolls back partial binding" {
    const bindings: udp_mod.Bindings = blk: {
        var ipv6 = try udp_mod.Sockets.bind(std.testing.io, .{ .ip6 = .loopback(0) });
        defer ipv6.close(std.testing.io);
        const port = ipv6.localAddress().port();
        const pair: udp_mod.Bindings = .{ .dual = .{
            .ip4 = .loopback(port),
            .ip6 = .loopback(port),
        } };
        try std.testing.expectError(error.AddressInUse, udp_mod.Sockets.bind(std.testing.io, pair));
        var ipv4 = try udp_mod.Sockets.bind(std.testing.io, .{ .ip4 = .loopback(port) });
        defer ipv4.close(std.testing.io);
        break :blk pair;
    };
    var both = try udp_mod.Sockets.bind(std.testing.io, bindings);
    defer both.close(std.testing.io);
    for (both.localAddresses()) |address| try std.testing.expectEqual(bindings.dual.ip4.port, address.?.port());
}

test "dual-stack UDP waits without consuming a second datagram and cancels an indefinite wait" {
    var buffer: [constants.datagram_size_max]u8 = undefined;
    var target = try udp_mod.Sockets.bind(std.testing.io, .{ .dual = .{ .ip4 = .loopback(0), .ip6 = .loopback(0) } });
    defer target.close(std.testing.io);
    const Worker = struct {
        fn send(addresses: [2]?types.Address) !void {
            try std.Io.sleep(std.testing.io, .fromMilliseconds(10), .awake);
            var sender = try udp_mod.Sockets.bind(std.testing.io, .{ .dual = .{ .ip4 = .loopback(0), .ip6 = .loopback(0) } });
            defer sender.close(std.testing.io);
            for (addresses) |address| try sender.sendTo(std.testing.io, address.?, "ready", constants.datagram_size_max);
        }
        fn receive(receiver: *udp_mod.Sockets) udp_mod.DatagramError!void {
            var receive_buffer: [constants.datagram_size_max]u8 = undefined;
            _ = try receiver.receiveDatagram(std.testing.io, &receive_buffer, .none);
        }
    };
    var sender = try std.testing.io.concurrent(Worker.send, .{target.localAddresses()});
    defer _ = sender.cancel(std.testing.io) catch {};
    for (0..2) |_| {
        const packet = try target.receiveDatagram(std.testing.io, &buffer, oneSecond());
        try std.testing.expectEqualSlices(u8, "ready", packet.bytes);
    }
    try sender.await(std.testing.io);
    var receiver = try std.testing.io.concurrent(Worker.receive, .{&target});
    try std.Io.sleep(std.testing.io, .fromMilliseconds(10), .awake);
    try std.testing.expectError(error.Canceled, receiver.cancel(std.testing.io));
}

test "dual-stack UDP ready reads reject a truncated datagram and keep reading its family" {
    var buffer: [constants.datagram_size_max]u8 = undefined;
    var target = try udp_mod.Sockets.bind(std.testing.io, .{ .dual = .{ .ip4 = .loopback(0), .ip6 = .loopback(0) } });
    defer target.close(std.testing.io);
    const local = target.localAddresses();
    var raw_sender = try (net.IpAddress{ .ip4 = .loopback(0) }).bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer raw_sender.close(std.testing.io);
    const oversized = [_]u8{0x55} ** (constants.datagram_size_max + 1);
    try raw_sender.send(std.testing.io, &udp_mod.Address.toNetwork(local[0].?), &oversized);
    try target.sendTo(std.testing.io, local[0].?, "ip4", constants.datagram_size_max);
    try target.sendTo(std.testing.io, local[1].?, "ip6", constants.datagram_size_max);
    var ready: [2]bool = @splat(true);
    try std.testing.expectError(error.DatagramTooLarge, target.receiveReadyDatagram(std.testing.io, &buffer, &ready));
    try std.testing.expectEqualSlices(u8, "ip6", (try target.receiveReadyDatagram(std.testing.io, &buffer, &ready)).?.bytes);
    try std.testing.expectEqualSlices(u8, "ip4", (try target.receiveReadyDatagram(std.testing.io, &buffer, &ready)).?.bytes);
    try std.testing.expectEqual([2]bool{ true, true }, ready);
    try std.testing.expectEqual(null, try target.receiveReadyDatagram(std.testing.io, &buffer, &ready));
    try std.testing.expectEqual([2]bool{ false, false }, ready);
}

test "ordered UDP batches preserve every prefix across chunks families and invalid lengths" {
    const Recorder = struct {
        seen: usize = 0,
        stop: ?usize = null,
        fn send(context: ?*anyopaque, _: net.Socket.Handle, messages: []net.OutgoingMessage, _: net.SendFlags) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            for (messages, 0..) |message, i| {
                if (self.stop == self.seen) return .{ error.NetworkUnreachable, i };
                std.debug.assert(message.data_len == 1);
                std.debug.assert(message.data_ptr[0] == self.seen);
                std.debug.assert(message.address.getPort() == 9000 + self.seen);
                self.seen += 1;
            }
            return .{ null, messages.len };
        }
    };
    var sockets = try udp_mod.Sockets.bind(std.testing.io, .{ .dual = .{ .ip4 = .loopback(0), .ip6 = .loopback(0) } });
    defer sockets.close(std.testing.io);
    var scratch: udp_mod.BatchScratch = undefined;
    var payload: [21]u8 = undefined;
    var outgoing: [21]udp_mod.Outgoing = undefined;
    for (&payload, &outgoing, 0..) |*byte, *packet, i| {
        byte.* = @intCast(i);
        // The first run crosses scratch capacity; later runs alternate families.
        const address: net.IpAddress = if (i < 17 or i % 2 == 0) .{ .ip4 = .loopback(@intCast(9000 + i)) } else .{ .ip6 = .loopback(@intCast(9000 + i)) };
        packet.* = .{ .to = udp_mod.Address.fromNetwork(address), .bytes = byte[0..1] };
    }
    var recorder: Recorder = .{};
    var vtable = std.testing.io.vtable.*;
    vtable.netSend = Recorder.send;
    const io: std.Io = .{ .userdata = &recorder, .vtable = &vtable };
    for (0..outgoing.len + 1) |prefix| {
        recorder = .{ .stop = prefix };
        const result = sockets.sendMany(io, &outgoing, 1, &scratch);
        try std.testing.expectEqual(prefix, result.sent);
        try std.testing.expectEqual(prefix, recorder.seen);
        if (prefix == outgoing.len) {
            try std.testing.expect(result.failure == null);
        } else try std.testing.expectEqual(error.NetworkUnreachable, result.failure.?);
    }
    for (0..outgoing.len) |invalid| {
        const bytes = outgoing[invalid].bytes;
        outgoing[invalid].bytes = "oversized";
        recorder = .{};
        try std.testing.expectEqual(udp_mod.SendOutcome{ .sent = invalid, .failure = error.DatagramTooLarge }, sockets.sendMany(io, &outgoing, 1, &scratch));
        if (invalid > 0) {
            recorder = .{ .stop = invalid - 1 };
            try std.testing.expectEqual(udp_mod.SendOutcome{ .sent = invalid - 1, .failure = error.NetworkUnreachable }, sockets.sendMany(io, &outgoing, 1, &scratch));
        }
        outgoing[invalid].bytes = bytes;
    }
    // Reusing provider scratch for native sends must replace every descriptor.
    try std.testing.expectEqual(udp_mod.SendOutcome{ .sent = 1, .failure = null }, sockets.sendMany(std.testing.io, &.{.{ .to = sockets.localAddress(), .bytes = "native" }}, 6, &scratch));
    var buffer: [8]u8 = undefined;
    try std.testing.expectEqualStrings("native", (try sockets.receiveDatagram(std.testing.io, &buffer, oneSecond())).bytes);
    recorder = .{};
    try std.testing.expectEqual(@as(usize, 1), sockets.sendMany(io, outgoing[0..1], 1, &scratch).sent);
}

test "UDP missing family and native cancellation retain the exact mixed prefix" {
    var sockets = try udp_mod.Sockets.bind(std.testing.io, .{ .ip4 = .loopback(0) });
    defer sockets.close(std.testing.io);
    var scratch: udp_mod.BatchScratch = undefined;
    const batch = [_]udp_mod.Outgoing{
        .{ .to = sockets.localAddress(), .bytes = "first" },
        .{ .to = udp_mod.Address.fromNetwork(.{ .ip6 = .loopback(9) }), .bytes = "second" },
        .{ .to = sockets.localAddress(), .bytes = "third" },
    };
    try std.testing.expectEqual(udp_mod.SendOutcome{ .sent = 1, .failure = error.AddressFamilyUnsupported }, sockets.sendMany(std.testing.io, &batch, 8, &scratch));
    var buffer: [8]u8 = undefined;
    try std.testing.expectEqualStrings("first", (try sockets.receiveDatagram(std.testing.io, &buffer, oneSecond())).bytes);
    if (@import("builtin").os.tag != .linux and @import("builtin").os.tag != .macos) return;
    var dual = try udp_mod.Sockets.bind(std.testing.io, .{ .dual = .{ .ip4 = .loopback(0), .ip6 = .loopback(0) } });
    defer dual.close(std.testing.io);
    const Cancel = struct {
        checks: usize = 0,
        fn check(context: ?*anyopaque) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.checks += 1;
            if (self.checks == 2) return error.Canceled;
        }
    };
    var cancel: Cancel = .{};
    var vtable = std.testing.io.vtable.*;
    vtable.checkCancel = Cancel.check;
    const io: std.Io = .{ .userdata = &cancel, .vtable = &vtable };
    try std.testing.expectEqual(udp_mod.SendOutcome{ .sent = 1, .failure = error.Canceled }, dual.sendMany(io, &batch, 8, &scratch));
    try std.testing.expectEqual(@as(usize, 2), cancel.checks);
    try std.testing.expectEqualStrings("first", (try sockets.receiveDatagram(std.testing.io, &buffer, oneSecond())).bytes);
}

test "UDP provider lifetime clears descriptors and telemetry without probing fabricated handles" {
    const Provider = struct {
        closes: usize = 0,
        fn bind(_: ?*anyopaque, address: *const net.IpAddress, _: net.IpAddress.BindOptions) net.IpAddress.BindError!net.Socket {
            return .{ .handle = 73, .address = address.* };
        }
        fn close(context: ?*anyopaque, handles: []const net.Socket.Handle) void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            std.debug.assert(handles.len == 1 and handles[0] == 73);
            self.closes += 1;
        }
    };
    var provider: Provider = .{};
    var vtable = std.testing.io.vtable.*;
    vtable.netBindIp = Provider.bind;
    vtable.netClose = Provider.close;
    const io: std.Io = .{ .userdata = &provider, .vtable = &vtable };
    var sockets = try udp_mod.Sockets.bind(io, .{ .ip4 = .loopback(0) });
    try std.testing.expectEqual([2]bool{ false, false }, sockets.native);
    _ = sockets.requestBuffers(std.testing.io, .{ .receive = udp_mod.Buffers.bytes_min, .send = udp_mod.Buffers.bytes_min });
    try std.testing.expectEqual([2]?udp_mod.Buffers.Reported{ null, null }, sockets.buffers);
    try std.testing.expectEqual([2]?u64{ null, null }, sockets.drops());
    try std.testing.expectError(error.IncompatibleProvider, sockets.sendTo(std.testing.io, sockets.localAddress(), "fake", 4));
    var buffer: [8]u8 = undefined;
    try std.testing.expectError(error.IncompatibleProvider, sockets.receiveDatagram(std.testing.io, &buffer, .none));
    sockets.close(io);
    sockets.close(io);
    try std.testing.expectEqual(@as(usize, 1), provider.closes);
    try std.testing.expectEqual([2]?net.Socket.Handle{ null, null }, sockets.handles());
    try std.testing.expectEqual([2]?u64{ null, null }, sockets.drops());
    sockets = try udp_mod.Sockets.bind(std.testing.io, .{ .ip4 = .loopback(0) });
    defer sockets.close(std.testing.io);
    try std.testing.expect(sockets.localAddress().port() > 0);
    if (sockets.drops()[0]) |drops| try std.testing.expectEqual(@as(u64, 0), drops);
}
