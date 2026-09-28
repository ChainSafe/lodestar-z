const std = @import("std");
const constants = @import("constants.zig");
const limits = @import("quic/limits.zig");
const types = @import("types.zig");
const udp_mod = @import("udp.zig");

const net = std.Io.net;

fn oneSecond() std.Io.Timeout {
    return .{ .duration = .{ .raw = .fromMilliseconds(1_000), .clock = .awake } };
}

test "UDP receives into caller storage and recovers after truncation" {
    var buffer: [constants.datagram_size_max]u8 = undefined;
    const loopback = net.IpAddress{ .ip4 = .loopback(0) };
    var receiver = try udp_mod.Udp.bind(std.testing.io, .single(loopback));
    defer receiver.close(std.testing.io);
    var sender = try udp_mod.Udp.bind(std.testing.io, .single(loopback));
    defer sender.close(std.testing.io);
    try std.testing.expect(receiver.localAddress().port() != 0);

    const payload = [_]u8{0x44} ** limits.client_initial_min;
    const receiver_address = receiver.localAddress();
    try sender.send(std.testing.io, &receiver_address, &payload);
    const first = try receiver.receiveTimeout(std.testing.io, &buffer, oneSecond());
    try std.testing.expectEqualSlices(u8, &payload, first.bytes);
    try std.testing.expect(first.bytes.ptr == &buffer);
    first.bytes[0] = 0x00;
    try std.testing.expectEqual(sender.localAddress().port(), first.from.port());

    var raw_sender = try loopback.bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer raw_sender.close(std.testing.io);
    const oversized = [_]u8{0x55} ** (constants.datagram_size_max + 1);
    const destination = udp_mod.toNetwork(receiver.localAddress());
    try raw_sender.send(std.testing.io, &destination, &oversized);
    try std.testing.expectError(error.DatagramTooLarge, receiver.receiveTimeout(std.testing.io, &buffer, oneSecond()));

    try sender.send(std.testing.io, &receiver_address, &payload);
    const second = try receiver.receiveTimeout(std.testing.io, &buffer, oneSecond());
    try std.testing.expectEqualSlices(u8, &payload, second.bytes);
    try std.testing.expectEqual(@as(u64, 2), sender.counters.sent_datagrams);
    try std.testing.expectEqual(@as(u64, 3), receiver.counters.received_datagrams);
    try std.testing.expectEqual(@as(u64, 2 * payload.len), sender.counters.sent_bytes);
    try std.testing.expectEqual(sender.counters.sent_bytes, receiver.counters.received_bytes);
}

test "UDP receive times out without traffic" {
    var buffer: [constants.datagram_size_max]u8 = undefined;
    const loopback = net.IpAddress{ .ip4 = .loopback(0) };
    var receiver = try udp_mod.Udp.bind(std.testing.io, .single(loopback));
    defer receiver.close(std.testing.io);
    const short = std.Io.Timeout{ .duration = .{ .raw = .fromMilliseconds(20), .clock = .awake } };
    try std.testing.expectError(error.Timeout, receiver.receiveTimeout(std.testing.io, &buffer, short));
}

test "UDP rejects oversized sends before I/O" {
    var transport = try udp_mod.Udp.bind(std.testing.io, .{ .ip4 = .loopback(0) });
    defer transport.close(std.testing.io);
    const oversized = [_]u8{0x44} ** (constants.datagram_size_max + 1);
    const destination = types.Address{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 9_001 } };
    try std.testing.expectError(
        error.DatagramTooLarge,
        transport.send(undefined, &destination, &oversized),
    );
}

test "UDP address conversion normalizes mapped IPv4" {
    const mapped = net.IpAddress{ .ip6 = .{
        .bytes = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff, 10, 0, 0, 7 },
        .port = 4_001,
        .flow = 0,
        .interface = .{ .index = 0 },
    } };
    const address = udp_mod.fromNetwork(mapped);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 7 }, &address.ip4.octets);
    try std.testing.expectEqual(@as(u16, 4_001), address.port());
    const back = udp_mod.toNetwork(address);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 7 }, &back.ip4.bytes);
    try std.testing.expectEqual(@as(u16, 4_001), back.ip4.port);
}

test "UDP metrics count successful batch prefixes when a later send fails" {
    const Fake = struct {
        fn send(_: ?*anyopaque, _: net.Socket.Handle, messages: []net.OutgoingMessage, _: net.SendFlags) struct { ?net.Socket.SendError, usize } {
            std.debug.assert(messages.len == 2);
            return .{ error.NetworkUnreachable, 1 };
        }
    };
    var socket = try udp_mod.Udp.bind(std.testing.io, .{ .ip4 = .loopback(0) });
    defer socket.close(std.testing.io);
    var vtable = std.testing.io.vtable.*;
    vtable.netSend = Fake.send;
    const io: std.Io = .{ .userdata = null, .vtable = &vtable };
    const destination = socket.localAddress();
    var first = "first".*;
    var unsent = "unsent".*;
    const outcome = socket.sendMany(io, &.{
        .{ .to = destination, .bytes = &first },
        .{ .to = destination, .bytes = &unsent },
    });
    try std.testing.expectEqual(@as(usize, 1), outcome.sent);
    try std.testing.expectEqual(error.NetworkUnreachable, outcome.failure.?);
    try std.testing.expectEqual(@as(u64, 1), socket.counters.sent_datagrams);
    try std.testing.expectEqual(@as(u64, 5), socket.counters.sent_bytes);
}

test "dual-stack UDP services both families fairly" {
    var buffer: [constants.datagram_size_max]u8 = undefined;
    var target = try udp_mod.Udp.bind(std.testing.io, .{ .dual = .{ .ip4 = .loopback(0), .ip6 = .loopback(0) } });
    defer target.close(std.testing.io);
    const local = target.localAddresses();
    try std.testing.expect(local[0].? == .ip4 and local[1].? == .ip6);
    var payload = [_]u8{ 1, 2, 3 };
    const batch = [_]types.Sent{
        .{ .to = local[0].?, .bytes = payload[0..1] },
        .{ .to = local[1].?, .bytes = payload[1..2] },
        .{ .to = local[0].?, .bytes = payload[2..3] },
    };
    const outcome = target.sendMany(std.testing.io, &batch);
    try std.testing.expectEqual(batch.len, outcome.sent);
    try std.testing.expect(outcome.failure == null);
    for ([_]u8{ 1, 2, 3 }, 0..) |expected, i| {
        const message = try target.receiveTimeout(std.testing.io, &buffer, oneSecond());
        try std.testing.expectEqualSlices(u8, &.{expected}, message.bytes);
        try std.testing.expectEqual(i == 1, message.from == .ip6);
    }
    try std.testing.expectEqual(@as(u64, 3), target.counters.sent_datagrams);
    try std.testing.expectEqual(target.counters.sent_datagrams, target.counters.received_datagrams);
}

test "dual-stack UDP binds explicit addresses on the same port and rolls back partial binding" {
    const bindings: udp_mod.Bindings = blk: {
        var ipv6 = try udp_mod.Udp.bind(std.testing.io, .{ .ip6 = .loopback(0) });
        defer ipv6.close(std.testing.io);
        const port = ipv6.localAddress().port();
        const pair: udp_mod.Bindings = .{ .dual = .{
            .ip4 = .loopback(port),
            .ip6 = .loopback(port),
        } };
        try std.testing.expectError(error.AddressInUse, udp_mod.Udp.bind(std.testing.io, pair));
        var ipv4 = try udp_mod.Udp.bind(std.testing.io, .{ .ip4 = .loopback(port) });
        defer ipv4.close(std.testing.io);
        break :blk pair;
    };
    var both = try udp_mod.Udp.bind(std.testing.io, bindings);
    defer both.close(std.testing.io);
    for (both.localAddresses()) |address| try std.testing.expectEqual(bindings.dual.ip4.port, address.?.port());
}

test "dual-stack UDP waits without consuming a second datagram and cancels an indefinite wait" {
    var buffer: [constants.datagram_size_max]u8 = undefined;
    var target = try udp_mod.Udp.bind(std.testing.io, .{ .dual = .{ .ip4 = .loopback(0), .ip6 = .loopback(0) } });
    defer target.close(std.testing.io);
    const Worker = struct {
        fn send(addresses: [2]?types.Address) !void {
            try std.Io.sleep(std.testing.io, .fromMilliseconds(10), .awake);
            var sender = try udp_mod.Udp.bind(std.testing.io, .{ .dual = .{ .ip4 = .loopback(0), .ip6 = .loopback(0) } });
            defer sender.close(std.testing.io);
            for (addresses) |address| try sender.send(std.testing.io, &address.?, "ready");
        }
        fn receive(receiver: *udp_mod.Udp) udp_mod.ReceiveTimeoutError!void {
            var receive_buffer: [constants.datagram_size_max]u8 = undefined;
            _ = try receiver.receiveTimeout(std.testing.io, &receive_buffer, .none);
        }
    };
    var sender = try std.testing.io.concurrent(Worker.send, .{target.localAddresses()});
    defer _ = sender.cancel(std.testing.io) catch {};
    for (0..2) |_| {
        const packet = try target.receiveTimeout(std.testing.io, &buffer, oneSecond());
        try std.testing.expectEqualSlices(u8, "ready", packet.bytes);
    }
    try sender.await(std.testing.io);
    var receiver = try std.testing.io.concurrent(Worker.receive, .{&target});
    try std.Io.sleep(std.testing.io, .fromMilliseconds(10), .awake);
    try std.testing.expectError(error.Canceled, receiver.cancel(std.testing.io));
}

test "dual-stack UDP ready reads count a truncated datagram and keep reading its family" {
    var buffer: [constants.datagram_size_max]u8 = undefined;
    var target = try udp_mod.Udp.bind(std.testing.io, .{ .dual = .{ .ip4 = .loopback(0), .ip6 = .loopback(0) } });
    defer target.close(std.testing.io);
    const local = target.localAddresses();
    var raw_sender = try (net.IpAddress{ .ip4 = .loopback(0) }).bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer raw_sender.close(std.testing.io);
    const oversized = [_]u8{0x55} ** (constants.datagram_size_max + 1);
    try raw_sender.send(std.testing.io, &udp_mod.toNetwork(local[0].?), &oversized);
    try target.send(std.testing.io, &local[0].?, "ip4");
    try target.send(std.testing.io, &local[1].?, "ip6");
    var ready: [2]bool = @splat(true);
    try std.testing.expectError(error.DatagramTooLarge, target.receiveReady(std.testing.io, &buffer, &ready));
    try std.testing.expectEqualSlices(u8, "ip6", (try target.receiveReady(std.testing.io, &buffer, &ready)).bytes);
    try std.testing.expectEqualSlices(u8, "ip4", (try target.receiveReady(std.testing.io, &buffer, &ready)).bytes);
    try std.testing.expectEqual([2]bool{ true, true }, ready);
    try std.testing.expectError(error.Timeout, target.receiveReady(std.testing.io, &buffer, &ready));
    try std.testing.expectEqual([2]bool{ false, false }, ready);
    try std.testing.expectEqual(@as(u64, 3), target.counters.received_datagrams);
    try std.testing.expectEqual(@as(u64, 6), target.counters.received_bytes);
}
