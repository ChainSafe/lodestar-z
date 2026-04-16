//! Concrete UDP socket support for discv5 using std.Io.net.

const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;
const net = Io.net;
const posix = std.posix;
const ThreadedIo = Io.Threaded;

pub const Address = net.IpAddress;

pub const RecvResult = struct {
    data: []u8,
    from: Address,
};

pub const Socket = struct {
    io: Io,
    socket: net.Socket,
    address: Address,

    pub fn bind(io: Io, address: Address) !Socket {
        const bound = try net.IpAddress.bind(&address, io, .{
            .mode = .dgram,
            .ip6_only = switch (address) {
                .ip4 => false,
                .ip6 => true,
            },
        });
        errdefer bound.close(io);

        return .{
            .io = io,
            .socket = bound,
            .address = normalizeAddress(bound.address),
        };
    }

    pub fn close(self: *const Socket) void {
        self.socket.close(self.io);
    }

    pub fn send(self: *const Socket, dest: Address, data: []const u8) !void {
        if (builtin.os.tag == .windows or builtin.os.tag == .wasi) {
            try self.socket.send(self.io, &dest, data);
            return;
        }
        try sendDatagramPosix(self.socket.handle, dest, data);
    }

    pub fn receive(self: *const Socket, buffer: []u8) !RecvResult {
        const message = try self.socket.receive(self.io, buffer);
        return .{
            .data = message.data,
            .from = normalizeAddress(message.from),
        };
    }

    pub fn receiveTimeout(self: *const Socket, buffer: []u8, timeout: Io.Timeout) !RecvResult {
        const message = try self.socket.receiveTimeout(self.io, buffer, timeout);
        return .{
            .data = message.data,
            .from = normalizeAddress(message.from),
        };
    }
};

fn normalizeAddress(address: Address) Address {
    return switch (address) {
        .ip4 => address,
        .ip6 => |ip6| net.IpAddress.fromIp6(ip6),
    };
}

fn sendDatagramPosix(handle: net.Socket.Handle, dest: Address, data: []const u8) net.Socket.SendError!void {
    // Linux can return sendmsg/sendmmsg EPERM for datagrams blocked by local
    // policy. Treat that like EACCES so discv5 lookup failures stay local to
    // the offending ENR instead of surfacing as unexpectedErrno noise.
    var storage: ThreadedIo.PosixAddress = undefined;
    var iovec: posix.iovec_const = .{ .base = @constCast(data.ptr), .len = data.len };
    const msg: posix.msghdr_const = .{
        .name = &storage.any,
        .namelen = ThreadedIo.addressToPosix(&dest, &storage),
        .iov = (&iovec)[0..1],
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };
    const send_flags: u32 = if (@hasDecl(posix.MSG, "NOSIGNAL")) posix.MSG.NOSIGNAL else 0;

    while (true) {
        const rc = posix.system.sendmsg(handle, &msg, send_flags);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                if (@as(usize, @intCast(rc)) != data.len) return error.MessageOversize;
                return;
            },
            .INTR => continue,
            .ACCES, .PERM => return error.AccessDenied,
            .ALREADY => return error.FastOpenAlreadyInProgress,
            .CONNRESET => return error.ConnectionResetByPeer,
            .MSGSIZE => return error.MessageOversize,
            .NOBUFS, .NOMEM => return error.SystemResources,
            .PIPE, .NOTCONN => return error.SocketUnconnected,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            .HOSTUNREACH => return error.HostUnreachable,
            .NETUNREACH => return error.NetworkUnreachable,
            .NETDOWN => return error.NetworkDown,
            else => return error.Unexpected,
        }
    }
}

test "udp socket loopback send and receive" {
    const io = std.Options.debug_io;

    var socket_a = try Socket.bind(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_a.close();

    var socket_b = try Socket.bind(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
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
    try std.testing.expect(result.from.eql(&socket_a.address));
}

test "udp socket ipv6 loopback send and receive" {
    const io = std.Options.debug_io;
    const loopback6 = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

    var socket_a = try Socket.bind(io, .{ .ip6 = .{ .bytes = loopback6, .port = 0 } });
    defer socket_a.close();

    var socket_b = try Socket.bind(io, .{ .ip6 = .{ .bytes = loopback6, .port = 0 } });
    defer socket_b.close();

    try socket_a.send(socket_b.address, "ping6");

    var recv_buf: [64]u8 = undefined;
    const result = try socket_b.receiveTimeout(&recv_buf, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });

    try std.testing.expectEqualSlices(u8, "ping6", result.data);
    try std.testing.expect(result.from.eql(&socket_a.address));
}
