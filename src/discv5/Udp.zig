const std = @import("std");
const types = @import("types.zig");
const constants = @import("wire/constants.zig");

const net = std.Io.net;
const sockets_mod = @import("udp");
pub const Bindings = sockets_mod.Bindings;
pub const Mode = sockets_mod.Mode;

pub const Datagram = struct {
    from: types.Address,
    bytes: []const u8,
};

pub const ReceiveTimeoutError = sockets_mod.ReceiveError || error{DatagramTooLarge};

pub const SendError = net.Socket.SendError || error{
    DatagramTooLarge,
};

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
    const incoming = try self.sockets.receiveTimeout(io, buffer, timeout);
    if (incoming.flags.trunc) return error.DatagramTooLarge;
    std.debug.assert(incoming.data.len <= buffer.len);
    return .{ .from = fromNetwork(incoming.from), .bytes = incoming.data };
}

pub fn send(
    self: *const Udp,
    io: std.Io,
    destination: types.Address,
    bytes: []const u8,
) SendError!void {
    if (bytes.len > constants.packet_size_max) return error.DatagramTooLarge;
    const address = toNetwork(destination);
    const socket = self.sockets.get(address) orelse return error.AddressFamilyUnsupported;
    return socket.send(io, &address, bytes);
}

/// Normalizes IPv4-mapped IPv6 sources to IPv4 so both forms share one session key.
pub const fromNetwork = types.Address.fromNetwork;
pub const toNetwork = types.Address.toNetwork;

comptime {
    std.debug.assert(@sizeOf(Udp) <= 2 * 1_024);
}
