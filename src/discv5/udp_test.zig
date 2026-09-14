const std = @import("std");
const Udp = @import("Udp.zig");
const constants = @import("wire/constants.zig");

const net = std.Io.net;

test "UDP receives into caller storage and recovers after truncation" {
    var buffer: [constants.packet_size_max]u8 = undefined;
    const loopback = net.IpAddress{ .ip4 = .loopback(0) };
    var receiver = try Udp.bind(std.testing.io, .single(loopback));
    defer receiver.close(std.testing.io);
    var sender = try Udp.bind(std.testing.io, .single(loopback));
    defer sender.close(std.testing.io);

    const payload = [_]u8{0x44} ** constants.packet_size_min;
    try sender.send(std.testing.io, receiver.localAddress(), &payload);
    const first = try receiver.receiveTimeout(std.testing.io, &buffer, .none);
    try std.testing.expectEqualSlices(u8, &payload, first.bytes);
    var raw_sender = try loopback.bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer raw_sender.close(std.testing.io);
    const oversized = [_]u8{0x55} ** (constants.packet_size_max + 1);
    const destination = receiver.localAddress().toNetwork();
    try raw_sender.send(std.testing.io, &destination, &oversized);
    try std.testing.expectError(error.DatagramTooLarge, receiver.receiveTimeout(std.testing.io, &buffer, .none));

    try sender.send(std.testing.io, receiver.localAddress(), &payload);
    const second = try receiver.receiveTimeout(std.testing.io, &buffer, .none);
    try std.testing.expectEqualSlices(u8, &payload, second.bytes);
}

test "UDP rejects oversized sends before I/O" {
    var adapter = try Udp.bind(std.testing.io, .{ .ip4 = .loopback(0) });
    defer adapter.close(std.testing.io);
    const oversized = [_]u8{0x44} ** (constants.packet_size_max + 1);
    try std.testing.expectError(
        error.DatagramTooLarge,
        adapter.send(
            undefined,
            .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 9_001 } },
            &oversized,
        ),
    );
}
