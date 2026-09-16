const std = @import("std");
const types = @import("types.zig");
const constants = @import("wire/constants.zig");

const sockets_mod = @import("udp");
pub const Bindings = sockets_mod.Bindings;
pub const Mode = types.Mode;

pub const Datagram = sockets_mod.Datagram;
pub const ReceiveTimeoutError = sockets_mod.DatagramError;
pub const SendError = sockets_mod.SendError;

const Udp = @This();

sockets: sockets_mod.Sockets,

pub fn bind(io: std.Io, addresses: Bindings) sockets_mod.BindError!Udp {
    return .{ .sockets = try sockets_mod.Sockets.bind(io, addresses) };
}

pub fn close(self: *const Udp, io: std.Io) void {
    self.sockets.close(io);
}

pub fn localAddress(self: *const Udp) types.Address {
    return fromNetwork(self.sockets.primary().address);
}

pub fn receiveTimeout(
    self: *Udp,
    io: std.Io,
    buffer: *[constants.packet_size_max]u8,
    timeout: std.Io.Timeout,
) ReceiveTimeoutError!Datagram {
    return self.sockets.receiveDatagram(io, buffer, timeout);
}

pub fn send(
    self: *const Udp,
    io: std.Io,
    destination: types.Address,
    bytes: []const u8,
) SendError!void {
    return self.sockets.sendTo(io, destination, bytes, constants.packet_size_max);
}

/// Normalizes IPv4-mapped IPv6 sources to IPv4 so both forms share one session key.
pub const fromNetwork = types.Address.fromNetwork;
pub const toNetwork = types.Address.toNetwork;
