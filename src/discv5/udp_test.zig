const std = @import("std");
const Udp = @import("Udp.zig");
const types = @import("types.zig");
const constants = @import("wire/constants.zig");

const net = std.Io.net;

test "UDP admits one borrowed datagram at a time" {
    const loopback = net.IpAddress{ .ip4 = .loopback(0) };
    var receiver = try Udp.bind(std.testing.io, loopback);
    defer receiver.close(std.testing.io);
    var sender = try Udp.bind(std.testing.io, loopback);
    defer sender.close(std.testing.io);

    const payload = [_]u8{0x44} ** constants.packet_size_min;
    try sender.send(std.testing.io, receiver.localAddress(), &payload);
    const first = try receiver.receive(std.testing.io);
    try std.testing.expectEqualSlices(u8, &payload, first.bytes);
    try std.testing.expectError(
        error.AdmissionUnavailable,
        receiver.receive(std.testing.io),
    );
    try std.testing.expectError(
        error.StaleDatagram,
        receiver.release(.{ .generation = first.handle.generation + 1 }),
    );
    try receiver.release(first.handle);
    try std.testing.expectError(error.StaleDatagram, receiver.release(first.handle));

    var raw_sender = try loopback.bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer raw_sender.close(std.testing.io);
    const oversized = [_]u8{0x55} ** (constants.packet_size_max + 1);
    const destination = networkAddress(receiver.localAddress());
    try raw_sender.send(std.testing.io, &destination, &oversized);
    try std.testing.expectError(error.DatagramTooLarge, receiver.receive(std.testing.io));

    try sender.send(std.testing.io, receiver.localAddress(), &payload);
    const second = try receiver.receive(std.testing.io);
    try std.testing.expect(second.handle.generation > first.handle.generation);
    try receiver.release(second.handle);
}

test "UDP rejects oversized sends before I/O" {
    var adapter = Udp.init(undefined);
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

fn networkAddress(address: types.Address) net.IpAddress {
    return switch (address) {
        .ip4 => |value| .{ .ip4 = .{ .bytes = value.octets, .port = value.port } },
        .ip6 => |value| .{ .ip6 = .{
            .bytes = value.octets,
            .port = value.port,
            .flow = 0,
            .interface = .{ .index = value.interface },
        } },
    };
}
