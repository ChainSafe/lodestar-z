const std = @import("std");
const constants = @import("constants.zig");
const limits = @import("quic/limits.zig");
const types = @import("types.zig");
const udp_mod = @import("udp.zig");

const net = std.Io.net;

fn oneSecond() std.Io.Timeout {
    return .{ .duration = .{ .raw = .fromMilliseconds(1_000), .clock = .awake } };
}

test "UDP admits one mutable datagram at a time" {
    const loopback = net.IpAddress{ .ip4 = .loopback(0) };
    var receiver = try udp_mod.Udp.bind(std.testing.io, .single(loopback));
    defer receiver.close(std.testing.io);
    var sender = try udp_mod.Udp.bind(std.testing.io, .single(loopback));
    defer sender.close(std.testing.io);
    try std.testing.expect(receiver.localAddress().port() != 0);

    const payload = [_]u8{0x44} ** limits.client_initial_min;
    const receiver_address = receiver.localAddress();
    try sender.send(std.testing.io, &receiver_address, &payload);
    const first = try receiver.receiveTimeout(std.testing.io, oneSecond());
    try std.testing.expectEqualSlices(u8, &payload, first.bytes);
    first.bytes[0] = 0x00;
    try std.testing.expectEqual(sender.localAddress().port(), first.from.port());
    try std.testing.expectError(error.AdmissionUnavailable, receiver.receiveTimeout(std.testing.io, oneSecond()));
    try std.testing.expectError(error.StaleDatagram, receiver.release(.{ .generation = first.handle.generation + 1 }));
    try receiver.release(first.handle);
    try std.testing.expectError(error.StaleDatagram, receiver.release(first.handle));

    var raw_sender = try loopback.bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer raw_sender.close(std.testing.io);
    const oversized = [_]u8{0x55} ** (constants.datagram_size_max + 1);
    const destination = udp_mod.toNetwork(receiver.localAddress());
    try raw_sender.send(std.testing.io, &destination, &oversized);
    try std.testing.expectError(error.DatagramTooLarge, receiver.receiveTimeout(std.testing.io, oneSecond()));

    try sender.send(std.testing.io, &receiver_address, &payload);
    const second = try receiver.receiveTimeout(std.testing.io, oneSecond());
    try std.testing.expect(second.handle.generation > first.handle.generation);
    try receiver.release(second.handle);
    try std.testing.expectEqual(@as(u64, 2), sender.counters.sent_datagrams);
    try std.testing.expectEqual(@as(u64, 3), receiver.counters.received_datagrams);
    try std.testing.expectEqual(@as(u64, 2 * payload.len), sender.counters.sent_bytes);
    try std.testing.expectEqual(sender.counters.sent_bytes, receiver.counters.received_bytes);
    try std.testing.expectEqual(@as(u64, 1), receiver.counters.truncated_datagrams);
}

test "UDP receive times out without traffic" {
    const loopback = net.IpAddress{ .ip4 = .loopback(0) };
    var receiver = try udp_mod.Udp.bind(std.testing.io, .single(loopback));
    defer receiver.close(std.testing.io);
    const short = std.Io.Timeout{ .duration = .{ .raw = .fromMilliseconds(20), .clock = .awake } };
    try std.testing.expectError(error.Timeout, receiver.receiveTimeout(std.testing.io, short));
}

test "UDP rejects oversized sends before I/O" {
    const loopback = net.IpAddress{ .ip4 = .loopback(0) };
    const socket = try loopback.bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    var transport = udp_mod.Udp.init(socket);
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
    try std.testing.expectError(error.NetworkUnreachable, socket.sendMany(io, &.{
        .{ .to = destination, .bytes = &first },
        .{ .to = destination, .bytes = &unsent },
    }));
    try std.testing.expectEqual(@as(u64, 1), socket.counters.sent_datagrams);
    try std.testing.expectEqual(@as(u64, 5), socket.counters.sent_bytes);
}

test "dual-stack UDP shares one receive lease and services both families fairly" {
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
    try target.sendMany(std.testing.io, &batch);
    for ([_]u8{ 1, 2, 3 }, 0..) |expected, i| {
        const message = try target.receiveTimeout(std.testing.io, oneSecond());
        try std.testing.expectEqualSlices(u8, &.{expected}, message.bytes);
        try std.testing.expectEqual(i == 1, message.from == .ip6);
        try std.testing.expectError(error.AdmissionUnavailable, target.receiveTimeout(std.testing.io, oneSecond()));
        try target.release(message.handle);
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
            _ = try receiver.receiveTimeout(std.testing.io, .none);
        }
    };
    var sender = try std.testing.io.concurrent(Worker.send, .{target.localAddresses()});
    defer _ = sender.cancel(std.testing.io) catch {};
    for (0..2) |_| {
        const packet = try target.receiveTimeout(std.testing.io, oneSecond());
        try std.testing.expectEqualSlices(u8, "ready", packet.bytes);
        try target.release(packet.handle);
    }
    try sender.await(std.testing.io);
    var receiver = try std.testing.io.concurrent(Worker.receive, .{&target});
    try std.Io.sleep(std.testing.io, .fromMilliseconds(10), .awake);
    try std.testing.expectError(error.Canceled, receiver.cancel(std.testing.io));
}
