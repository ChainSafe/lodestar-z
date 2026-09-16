const std = @import("std");
const Sockets = @import("udp").Sockets;
const constants = @import("wire/constants.zig");

const net = std.Io.net;

test "UDP receives into caller storage and recovers after truncation" {
    var buffer: [constants.packet_size_max]u8 = undefined;
    const loopback = net.IpAddress{ .ip4 = .loopback(0) };
    var receiver = try Sockets.bind(std.testing.io, .single(loopback));
    defer receiver.close(std.testing.io);
    var sender = try Sockets.bind(std.testing.io, .single(loopback));
    defer sender.close(std.testing.io);

    const payload = [_]u8{0x44} ** constants.packet_size_min;
    try sender.sendTo(std.testing.io, @import("types.zig").Address.fromNetwork(receiver.primary().address), &payload, constants.packet_size_max);
    const first = try receiver.receiveDatagram(std.testing.io, &buffer, .none);
    try std.testing.expectEqualSlices(u8, &payload, first.bytes);
    var raw_sender = try loopback.bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer raw_sender.close(std.testing.io);
    const oversized = [_]u8{0x55} ** (constants.packet_size_max + 1);
    const destination = @import("types.zig").Address.fromNetwork(receiver.primary().address).toNetwork();
    try raw_sender.send(std.testing.io, &destination, &oversized);
    try std.testing.expectError(error.DatagramTooLarge, receiver.receiveDatagram(std.testing.io, &buffer, .none));

    try sender.sendTo(std.testing.io, @import("types.zig").Address.fromNetwork(receiver.primary().address), &payload, constants.packet_size_max);
    const second = try receiver.receiveDatagram(std.testing.io, &buffer, .none);
    try std.testing.expectEqualSlices(u8, &payload, second.bytes);
}

test "UDP rejects oversized sends before I/O" {
    var adapter = try Sockets.bind(std.testing.io, .{ .ip4 = .loopback(0) });
    defer adapter.close(std.testing.io);
    const oversized = [_]u8{0x44} ** (constants.packet_size_max + 1);
    try std.testing.expectError(
        error.DatagramTooLarge,
        adapter.sendTo(
            undefined,
            .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 9_001 } },
            &oversized,
            constants.packet_size_max,
        ),
    );
}
