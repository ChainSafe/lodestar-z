const std = @import("std");
const types = @import("types.zig");
const constants = @import("wire/constants.zig");

const net = std.Io.net;

pub const Handle = struct {
    generation: u64,
};

pub const Datagram = struct {
    handle: Handle,
    from: types.Address,
    bytes: []const u8,
};

pub const ReceiveError = net.Socket.ReceiveError || error{
    AdmissionUnavailable,
    DatagramTooLarge,
    GenerationExhausted,
};

pub const ReceiveTimeoutError = net.Socket.ReceiveTimeoutError || error{
    AdmissionUnavailable,
    DatagramTooLarge,
    GenerationExhausted,
};

pub const ReleaseError = error{
    StaleDatagram,
};

pub const SendError = net.Socket.SendError || error{
    DatagramTooLarge,
};

/// Caller serializes all methods and releases each datagram before receiving another.
const Udp = @This();

socket: net.Socket,
buffer: [constants.packet_size_max]u8 = undefined,
admitted: ?u64 = null,
next_generation: u64 = 1,

pub fn bind(io: std.Io, address: net.IpAddress) net.IpAddress.BindError!Udp {
    const socket = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    return .{ .socket = socket };
}

pub fn init(socket: net.Socket) Udp {
    return .{ .socket = socket };
}

pub fn close(self: *const Udp, io: std.Io) void {
    self.socket.close(io);
}

pub fn localAddress(self: *const Udp) types.Address {
    return fromNetwork(self.socket.address);
}

pub fn receive(self: *Udp, io: std.Io) ReceiveError!Datagram {
    if (self.admitted != null) return error.AdmissionUnavailable;
    const incoming = try self.socket.receive(io, &self.buffer);
    return self.admit(incoming);
}

pub fn receiveTimeout(
    self: *Udp,
    io: std.Io,
    timeout: std.Io.Timeout,
) ReceiveTimeoutError!Datagram {
    if (self.admitted != null) return error.AdmissionUnavailable;
    const incoming = try self.socket.receiveTimeout(io, &self.buffer, timeout);
    return self.admit(incoming);
}

fn admit(self: *Udp, incoming: net.IncomingMessage) ReceiveError!Datagram {
    const successor = std.math.add(u64, self.next_generation, 1) catch
        return error.GenerationExhausted;
    if (incoming.flags.trunc) return error.DatagramTooLarge;
    std.debug.assert(incoming.data.len <= self.buffer.len);
    const generation = self.next_generation;
    self.next_generation = successor;
    self.admitted = generation;
    return .{
        .handle = .{ .generation = generation },
        .from = fromNetwork(incoming.from),
        .bytes = incoming.data,
    };
}

pub fn release(self: *Udp, handle: Handle) ReleaseError!void {
    const admitted = self.admitted orelse return error.StaleDatagram;
    if (admitted != handle.generation) return error.StaleDatagram;
    self.admitted = null;
}

pub fn send(
    self: *const Udp,
    io: std.Io,
    destination: types.Address,
    bytes: []const u8,
) SendError!void {
    if (bytes.len > constants.packet_size_max) return error.DatagramTooLarge;
    const address = toNetwork(destination);
    return self.socket.send(io, &address, bytes);
}

pub fn fromNetwork(address: net.IpAddress) types.Address {
    return switch (address) {
        .ip4 => |value| .{ .ip4 = .{
            .octets = value.bytes,
            .port = value.port,
        } },
        .ip6 => |value| if (isMappedIp4(value.bytes))
            .{ .ip4 = .{
                .octets = value.bytes[12..16].*,
                .port = value.port,
            } }
        else
            .{ .ip6 = .{
                .octets = value.bytes,
                .port = value.port,
                .interface = value.interface.index,
            } },
    };
}

fn toNetwork(address: types.Address) net.IpAddress {
    return switch (address) {
        .ip4 => |value| .{ .ip4 = .{
            .bytes = value.octets,
            .port = value.port,
        } },
        .ip6 => |value| .{ .ip6 = .{
            .bytes = value.octets,
            .port = value.port,
            .flow = 0,
            .interface = .{ .index = value.interface },
        } },
    };
}

fn isMappedIp4(ip: [16]u8) bool {
    return std.mem.eql(u8, ip[0..10], &([_]u8{0} ** 10)) and
        ip[10] == 0xff and ip[11] == 0xff;
}

comptime {
    std.debug.assert(@sizeOf(Udp) <= 2 * 1_024);
}
