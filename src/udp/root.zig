pub const testing = if (@import("builtin").is_test) @import("test_io.zig") else struct {};
const std = @import("std");
const net = std.Io.net;
const assert = std.debug.assert;
pub const Address = @import("address.zig").Address;

pub const Mode = enum {
    ip4,
    ip6,
    dual,
    pub fn supports(self: Mode, address: Address) bool {
        return switch (address) {
            .ip4 => self != .ip6,
            .ip6 => self != .ip4,
        };
    }
};

pub const Bindings = union(enum) {
    ip4: net.Ip4Address,
    ip6: net.Ip6Address,
    dual: struct { ip4: net.Ip4Address, ip6: net.Ip6Address },

    pub fn single(address: net.IpAddress) Bindings {
        return switch (address) {
            .ip4 => |ip| .{ .ip4 = ip },
            .ip6 => |ip| .{ .ip6 = ip },
        };
    }
};

pub const BindError = net.IpAddress.BindError;
pub const ReceiveError = net.Socket.ReceiveTimeoutError;
pub const DatagramError = ReceiveError || error{DatagramTooLarge};
pub const SendError = net.Socket.SendError || error{DatagramTooLarge};
pub const Datagram = struct { from: Address, bytes: []u8 };

/// Owns at most one socket per configured address family. The caller serializes
/// receives and close, and does not receive directly from the owned sockets.
pub const Sockets = struct {
    values: [2]?net.Socket = .{ null, null },
    cursor: u1 = 0,

    /// IPv6 sockets accept IPv6 only, including when both families share a port.
    pub fn bind(io: std.Io, addresses: Bindings) BindError!Sockets {
        const ip6 = switch (addresses) {
            .ip4 => null,
            .ip6 => |ip| ip,
            .dual => |ips| ips.ip6,
        };
        if (ip6) |ip| if (Address.isIp4Mapped(ip.bytes)) return error.AddressFamilyUnsupported;
        var result: Sockets = .{};
        errdefer result.close(io);
        switch (addresses) {
            .ip4 => |ip| result.values[0] = try (net.IpAddress{ .ip4 = ip }).bind(io, .{ .mode = .dgram, .protocol = .udp }),
            .ip6 => |ip| result.values[1] = try bindIp6(io, ip),
            .dual => |ips| {
                result.values[0] = try (net.IpAddress{ .ip4 = ips.ip4 }).bind(io, .{ .mode = .dgram, .protocol = .udp });
                result.values[1] = try bindIp6(io, ips.ip6);
            },
        }
        return result;
    }

    pub fn close(self: *const Sockets, io: std.Io) void {
        for (self.values) |socket| if (socket) |value| value.close(io);
    }

    pub fn mode(self: *const Sockets) Mode {
        assert(self.values[0] != null or self.values[1] != null);
        return if (self.values[0] == null) .ip6 else if (self.values[1] == null) .ip4 else .dual;
    }

    pub fn primary(self: *const Sockets) net.Socket {
        return self.values[0] orelse self.values[1].?;
    }

    pub fn get(self: *const Sockets, address: net.IpAddress) ?net.Socket {
        return self.values[index(address)];
    }

    pub fn handles(self: *const Sockets) [2]?net.Socket.Handle {
        var result: [2]?net.Socket.Handle = .{ null, null };
        for (self.values, 0..) |socket, i| if (socket) |value| {
            result[i] = value.handle;
        };
        return result;
    }

    /// Blocking on both sockets requires two units of Io concurrency. Ready reads
    /// use no tasks. The returned data borrows buffer until the caller reuses it.
    pub fn receiveTimeout(self: *Sockets, io: std.Io, buffer: []u8, timeout: std.Io.Timeout) ReceiveError!net.IncomingMessage {
        if (self.values[0] == null or self.values[1] == null) return self.primary().receiveTimeout(io, buffer, timeout);
        const deadline = timeout.toDeadline(io);
        if (try self.receiveReady(io, buffer)) |message| return message;
        if (deadline.toDurationFromNow(io)) |duration| if (duration.raw.nanoseconds <= 0) return error.Timeout;
        {
            const Ready = union(enum) { ip4: ReceiveError!void, ip6: ReceiveError!void };
            var completions: [2]Ready = undefined;
            var select: std.Io.Select(Ready) = .init(io, &completions);
            defer select.cancelDiscard();
            try select.concurrent(.ip4, waitReadable, .{ io, self.values[0].?, deadline });
            try select.concurrent(.ip6, waitReadable, .{ io, self.values[1].?, deadline });
            switch (try select.await()) {
                inline else => |result| try result,
            }
        }
        return (try self.receiveReady(io, buffer)) orelse error.Timeout;
    }

    pub fn receiveReady(self: *Sockets, io: std.Io, buffer: []u8) ReceiveError!?net.IncomingMessage {
        for (0..2) |_| {
            const at = self.cursor;
            self.cursor +%= 1;
            const socket = self.values[at] orelse continue;
            return socket.receiveTimeout(io, buffer, .{ .duration = .{ .raw = .zero, .clock = .awake } }) catch |err| switch (err) {
                error.Timeout => continue,
                else => return err,
            };
        }
        return null;
    }

    pub fn receiveDatagram(self: *Sockets, io: std.Io, buffer: []u8, timeout: std.Io.Timeout) DatagramError!Datagram {
        const incoming = try self.receiveTimeout(io, buffer, timeout);
        if (incoming.flags.trunc) return error.DatagramTooLarge;
        assert(incoming.data.len <= buffer.len);
        return .{ .from = Address.fromNetwork(incoming.from), .bytes = buffer[0..incoming.data.len] };
    }

    pub fn sendTo(self: *const Sockets, io: std.Io, destination: Address, bytes: []const u8, payload_max: usize) SendError!void {
        if (bytes.len > payload_max) return error.DatagramTooLarge;
        const address = destination.toNetwork();
        const socket = self.get(address) orelse return error.AddressFamilyUnsupported;
        try socket.send(io, &address, bytes);
    }
};

fn index(address: net.IpAddress) u1 {
    return switch (address) {
        .ip4 => 0,
        .ip6 => 1,
    };
}

fn waitReadable(io: std.Io, socket: net.Socket, timeout: std.Io.Timeout) ReceiveError!void {
    var message: [1]net.IncomingMessage = .{.init};
    var probe: [1]u8 = undefined;
    // Both tasks may finish before cancellation. Peeking keeps every datagram in
    // its socket until the serialized receiver lends the caller's buffer to it.
    const failure, const count = socket.receiveManyTimeout(io, &message, &probe, .{ .peek = true }, timeout);
    if (failure) |err| return err;
    assert(count == 1);
}

fn bindIp6(io: std.Io, ip: net.Ip6Address) BindError!net.Socket {
    const address: net.IpAddress = .{ .ip6 = ip };
    const os = @import("builtin").os.tag;
    if (std.options.networking and (os == .linux or os == .macos)) {
        // Zig 0.16 Threaded sets IPV6_V6ONLY to zero for ip6_only. Set it before
        // binding its native sockets; other I/O providers retain their own bind contract.
        if (io.vtable.netBindIp == std.Io.Threaded.global_single_threaded.io().vtable.netBindIp) {
            try io.checkCancel();
            const p = std.posix;
            const flags = p.SOCK.DGRAM | if (os == .linux) p.SOCK.CLOEXEC else 0;
            const opened = p.system.socket(p.AF.INET6, flags, p.IPPROTO.UDP);
            try checkBindError(p.errno(opened));
            const fd: net.Socket.Handle = @intCast(opened);
            errdefer io.vtable.netClose(io.userdata, &.{fd});
            if (os != .linux) try checkBindError(p.errno(p.system.fcntl(fd, p.F.SETFD, @as(usize, p.FD_CLOEXEC))));
            const enabled: c_int = 1;
            // Darwin's IPV6_V6ONLY from netinet6/in6.h is absent in Zig 0.16.
            const ipv6_only = if (os == .macos) 27 else p.IPV6.V6ONLY;
            try checkBindError(p.errno(p.system.setsockopt(fd, p.IPPROTO.IPV6, ipv6_only, std.mem.asBytes(&enabled), @sizeOf(c_int))));
            var storage: std.Io.Threaded.PosixAddress = undefined;
            var len = std.Io.Threaded.addressToPosix(&address, &storage);
            try checkBindError(p.errno(p.system.bind(fd, &storage.any, len)));
            try checkBindError(p.errno(p.system.getsockname(fd, &storage.any, &len)));
            return .{ .handle = fd, .address = std.Io.Threaded.addressFromPosix(&storage) };
        }
    }
    return address.bind(io, .{ .mode = .dgram, .protocol = .udp, .ip6_only = true });
}

fn checkBindError(err: std.posix.E) BindError!void {
    return switch (err) {
        .SUCCESS => {},
        .ADDRINUSE => error.AddressInUse,
        .ADDRNOTAVAIL => error.AddressUnavailable,
        .AFNOSUPPORT => error.AddressFamilyUnsupported,
        .NOMEM, .NOBUFS => error.SystemResources,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .NETDOWN => error.NetworkDown,
        .PROTONOSUPPORT => error.ProtocolUnsupportedByAddressFamily,
        .PROTOTYPE => error.SocketModeUnsupported,
        .NOPROTOOPT => error.OptionUnsupported,
        else => std.posix.unexpectedErrno(err),
    };
}

test {
    _ = @import("root_test.zig");
}
