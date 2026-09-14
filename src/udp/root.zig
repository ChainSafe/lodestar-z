const std = @import("std");
const builtin = @import("builtin");
const net = std.Io.net;
const assert = std.debug.assert;

pub const Mode = enum {
    ip4,
    ip6,
    dual,
    pub fn supports(self: Mode, address: anytype) bool {
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

pub const BindError = net.IpAddress.BindError || error{AccessDenied};
pub const ReceiveError = net.Socket.ReceiveTimeoutError;

/// Owns at most one socket per address family.
pub const Sockets = struct {
    values: [2]?net.Socket = .{ null, null },
    cursor: u1 = 0,

    pub fn bind(io: std.Io, addresses: Bindings) BindError!Sockets {
        var result: Sockets = .{};
        errdefer result.close(io);
        switch (addresses) {
            .ip4 => |ip| result.values[0] = try (net.IpAddress{ .ip4 = ip }).bind(io, .{ .mode = .dgram, .protocol = .udp }),
            .ip6 => |ip| result.values[1] = try bind6(io, ip),
            .dual => |ips| {
                result.values[0] = try (net.IpAddress{ .ip4 = ips.ip4 }).bind(io, .{ .mode = .dgram, .protocol = .udp });
                result.values[1] = try bind6(io, ips.ip6);
            },
        }
        return result;
    }

    /// Takes ownership. An IPv6 socket must have IPV6_V6ONLY enabled.
    pub fn init(socket: net.Socket) Sockets {
        var result: Sockets = .{};
        result.values[index(socket.address)] = socket;
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

    pub fn handles(self: *const Sockets) [2]?i32 {
        var result: [2]?i32 = .{ null, null };
        for (self.values, 0..) |socket, i| if (socket) |value| {
            result[i] = value.handle;
        };
        return result;
    }

    pub fn receiveTimeout(self: *Sockets, io: std.Io, buffer: []u8, timeout: std.Io.Timeout) ReceiveError!net.IncomingMessage {
        if (self.values[0] == null or self.values[1] == null) return self.primary().receiveTimeout(io, buffer, timeout);
        const deadline = timeout.toDeadline(io);
        if (try self.receiveReady(io, buffer)) |message| return message;
        if (deadline.toDurationFromNow(io)) |duration| if (duration.raw.nanoseconds <= 0) return error.Timeout;
        var storage: [2]std.Io.Operation.Storage = undefined;
        var messages: [2]net.IncomingMessage = @splat(.init);
        var probes: [2][1]u8 = undefined;
        var batch: std.Io.Batch = .init(&storage);
        defer batch.cancel(io);
        // Peek leaves both datagrams queued, even if both waits complete before cancellation.
        for (self.values, 0..) |socket, i| batch.addAt(@intCast(i), .{ .net_receive = .{
            .socket_handle = socket.?.handle,
            .message_buffer = messages[i .. i + 1],
            .data_buffer = &probes[i],
            .flags = .{ .peek = true },
        } });
        try batch.awaitConcurrent(io, deadline);
        batch.cancel(io);
        for (0..2) |_| {
            const completion = batch.next() orelse break;
            if (completion.result.net_receive[0]) |err| return err;
        }
        return (try self.receiveReady(io, buffer)) orelse error.Timeout;
    }

    fn receiveReady(self: *Sockets, io: std.Io, buffer: []u8) ReceiveError!?net.IncomingMessage {
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
};

fn index(address: net.IpAddress) u1 {
    return switch (address) {
        .ip4 => 0,
        .ip6 => 1,
    };
}

// Zig 0.16's Threaded.netBindIpPosix writes zero for ip6_only=true. Set V6ONLY
// before bind so wildcard listeners can share a port independently of OS defaults.
fn bind6(io: std.Io, ip: net.Ip6Address) BindError!net.Socket {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.OptionUnsupported;
    try io.checkCancel();
    const p = std.posix;
    const flags = p.SOCK.DGRAM | if (builtin.os.tag == .linux) p.SOCK.CLOEXEC else 0;
    const rc = p.system.socket(p.AF.INET6, flags, p.IPPROTO.UDP);
    if (p.errno(rc) != .SUCCESS) return socketError(p.errno(rc));
    const fd: p.fd_t = @intCast(rc);
    errdefer _ = p.system.close(fd);
    if (builtin.os.tag == .macos and std.c.fcntl(fd, p.F.SETFD, @as(c_int, p.FD_CLOEXEC)) < 0) return error.Unexpected;
    const enabled: c_int = 1;
    // Zig 0.16 omits Darwin IPV6 constants from std.posix.
    const ipv6_only = if (builtin.os.tag == .macos) 27 else p.IPV6.V6ONLY;
    if (p.errno(p.system.setsockopt(fd, p.IPPROTO.IPV6, ipv6_only, @ptrCast(&enabled), @sizeOf(c_int))) != .SUCCESS) return error.OptionUnsupported;
    var address: p.sockaddr.in6 = .{ .port = std.mem.nativeToBig(u16, ip.port), .addr = ip.bytes, .flowinfo = ip.flow, .scope_id = ip.interface.index };
    const bound = p.system.bind(fd, @ptrCast(&address), @sizeOf(@TypeOf(address)));
    if (p.errno(bound) != .SUCCESS) return socketError(p.errno(bound));
    var length: p.socklen_t = @sizeOf(@TypeOf(address));
    if (p.errno(p.system.getsockname(fd, @ptrCast(&address), &length)) != .SUCCESS) return error.Unexpected;
    assert(length == @sizeOf(@TypeOf(address)));
    try io.checkCancel();
    return .{ .handle = fd, .address = .{ .ip6 = .{ .bytes = address.addr, .port = std.mem.bigToNative(u16, address.port), .flow = address.flowinfo, .interface = .{ .index = address.scope_id } } } };
}

fn socketError(err: std.posix.E) BindError {
    return switch (err) {
        .ACCES, .PERM => error.AccessDenied,
        .ADDRINUSE => error.AddressInUse,
        .ADDRNOTAVAIL => error.AddressUnavailable,
        .AFNOSUPPORT => error.AddressFamilyUnsupported,
        .PROTONOSUPPORT => error.ProtocolUnsupportedByAddressFamily,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => error.SystemResources,
        .NETDOWN => error.NetworkDown,
        else => error.Unexpected,
    };
}
