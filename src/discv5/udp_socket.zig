//! Concrete UDP socket support for discv5 using std.Io.net.

const std = @import("std");
const Io = std.Io;
const net = Io.net;

pub const Address = net.Ip4Address;

pub const RecvResult = struct {
    data: []u8,
    from: Address,
};

pub const Socket = struct {
    io: Io,
    socket: net.Socket,
    address: Address,

    pub fn bind(io: Io, address: Address) !Socket {
        const bound = try net.IpAddress.bind(&.{ .ip4 = address }, io, .{
            .mode = .dgram,
        });
        errdefer bound.close(io);

        const bound_address = switch (bound.address) {
            .ip4 => |ip4| ip4,
            else => return error.UnsupportedAddressFamily,
        };

        return .{
            .io = io,
            .socket = bound,
            .address = bound_address,
        };
    }

    pub fn close(self: *const Socket) void {
        self.socket.close(self.io);
    }

    pub fn send(self: *const Socket, dest: Address, data: []const u8) !void {
        try self.socket.send(self.io, &.{ .ip4 = dest }, data);
    }

    pub fn receive(self: *const Socket, buffer: []u8) !RecvResult {
        const message = try self.socket.receive(self.io, buffer);
        return .{
            .data = message.data,
            .from = switch (message.from) {
                .ip4 => |ip4| ip4,
                else => return error.UnsupportedAddressFamily,
            },
        };
    }

    pub fn receiveTimeout(self: *const Socket, buffer: []u8, timeout: Io.Timeout) !RecvResult {
        const message = try self.socket.receiveTimeout(self.io, buffer, timeout);
        return .{
            .data = message.data,
            .from = switch (message.from) {
                .ip4 => |ip4| ip4,
                else => return error.UnsupportedAddressFamily,
            },
        };
    }
};

test "udp socket loopback send and receive" {
    const io = std.Options.debug_io;

    var socket_a = try Socket.bind(io, .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 });
    defer socket_a.close();

    var socket_b = try Socket.bind(io, .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 });
    defer socket_b.close();

    try socket_a.send(socket_b.address, "ping");

    var recv_buf: [64]u8 = undefined;
    const result = try socket_b.receiveTimeout(&recv_buf, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });

    try std.testing.expectEqualSlices(u8, "ping", result.data);
    try std.testing.expectEqualDeep(socket_a.address, result.from);
}
