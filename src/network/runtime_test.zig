const std = @import("std");
const constants = @import("constants.zig");
const runtime = @import("runtime.zig");
const types = @import("types.zig");

const net = std.Io.net;

fn oneSecond() std.Io.Timeout {
    return .{ .duration = .{ .raw = .fromMilliseconds(1_000), .clock = .awake } };
}

test "UDP admits one mutable datagram at a time" {
    const loopback = net.IpAddress{ .ip4 = .loopback(0) };
    var receiver = try runtime.Udp.bind(std.testing.io, loopback);
    defer receiver.close(std.testing.io);
    var sender = try runtime.Udp.bind(std.testing.io, loopback);
    defer sender.close(std.testing.io);
    try std.testing.expect(receiver.localAddress().port() != 0);

    const payload = [_]u8{0x44} ** constants.client_initial_min;
    try sender.send(std.testing.io, receiver.localAddress(), &payload);
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
    const destination = runtime.toNetwork(receiver.localAddress(), receiver.family);
    try raw_sender.send(std.testing.io, &destination, &oversized);
    try std.testing.expectError(error.DatagramTooLarge, receiver.receiveTimeout(std.testing.io, oneSecond()));

    try sender.send(std.testing.io, receiver.localAddress(), &payload);
    const second = try receiver.receiveTimeout(std.testing.io, oneSecond());
    try std.testing.expect(second.handle.generation > first.handle.generation);
    try receiver.release(second.handle);
}

test "UDP receive times out without traffic" {
    const loopback = net.IpAddress{ .ip4 = .loopback(0) };
    var receiver = try runtime.Udp.bind(std.testing.io, loopback);
    defer receiver.close(std.testing.io);
    const short = std.Io.Timeout{ .duration = .{ .raw = .fromMilliseconds(20), .clock = .awake } };
    try std.testing.expectError(error.Timeout, receiver.receiveTimeout(std.testing.io, short));
}

test "UDP rejects oversized sends before I/O" {
    const loopback = net.IpAddress{ .ip4 = .loopback(0) };
    const socket = try loopback.bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    var transport = runtime.Udp.init(socket);
    defer transport.close(std.testing.io);
    const oversized = [_]u8{0x44} ** (constants.datagram_size_max + 1);
    try std.testing.expectError(
        error.DatagramTooLarge,
        transport.send(undefined, .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 9_001 } }, &oversized),
    );
}

test "UDP address conversion normalizes mapped IPv4" {
    const mapped = net.IpAddress{ .ip6 = .{
        .bytes = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff, 10, 0, 0, 7 },
        .port = 4_001,
        .flow = 0,
        .interface = .{ .index = 0 },
    } };
    const address = runtime.fromNetwork(mapped);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 7 }, &address.ip4.octets);
    try std.testing.expectEqual(@as(u16, 4_001), address.port());
    const back = runtime.toNetwork(address, .ip4);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 7 }, &back.ip4.bytes);
    try std.testing.expectEqual(@as(u16, 4_001), back.ip4.port);
}

test "UDP address conversion maps IPv4 destinations onto IPv6 sockets" {
    const ip4 = types.Address{ .ip4 = .{ .octets = .{ 10, 0, 0, 7 }, .port = 4_001 } };
    const mapped = runtime.toNetwork(ip4, .ip6);
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff, 10, 0, 0, 7 }),
        &mapped.ip6.bytes,
    );
    try std.testing.expectEqual(@as(u16, 4_001), mapped.ip6.port);
    try std.testing.expectEqual(@as(u32, 0), mapped.ip6.interface.index);

    const plain = runtime.toNetwork(ip4, .ip4);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 7 }, &plain.ip4.bytes);
    try std.testing.expectEqual(@as(u16, 4_001), plain.ip4.port);
}
