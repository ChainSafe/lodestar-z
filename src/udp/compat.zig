//! Zig 0.16.0 Threaded compatibility: native descriptors, errno mappings and V6ONLY.
//! Re-audit these assumptions when upgrading Zig, including the Darwin socket ABI.
const std = @import("std");
const builtin = @import("builtin");
const Sockets = @import("sockets.zig").Sockets;
const net = std.Io.net;
const assert = std.debug.assert;
const SendError = Sockets.SendError;
const SendOutcome = Sockets.SendOutcome;
const ReceiveError = Sockets.ReceiveError;
const BindError = Sockets.BindError;
const os = builtin.os.tag;
pub const native_sockets = std.options.networking and (os == .linux or os == .macos);
comptime {
    if (!std.mem.eql(u8, builtin.zig_version_string, "0.16.0"))
        @compileError("UDP Threaded compatibility requires an audit for this Zig version");
}

pub fn threaded(io: std.Io) bool {
    return io.vtable.netBindIp == std.Io.Threaded.global_single_threaded.io().vtable.netBindIp;
}

pub fn threadedSend(io: std.Io) bool {
    return io.vtable.netSend == std.Io.Threaded.global_single_threaded.io().vtable.netSend;
}

pub fn threadedReceive(io: std.Io) bool {
    return io.vtable.batchAwaitConcurrent == std.Io.Threaded.global_single_threaded.io().vtable.batchAwaitConcurrent;
}

pub fn receiveNative(io: std.Io, handle: net.Socket.Handle, buffer: []u8) ReceiveError!?net.IncomingMessage {
    const p = std.posix;
    var storage: std.Io.Threaded.PosixAddress = undefined;
    var vector: p.iovec = .{ .base = buffer.ptr, .len = buffer.len };
    var header: p.msghdr = .{
        .name = &storage.any,
        .namelen = @sizeOf(std.Io.Threaded.PosixAddress),
        .iov = (&vector)[0..1],
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };
    try io.checkCancel();
    const received = p.system.recvmsg(handle, &header, p.MSG.NOSIGNAL | p.MSG.DONTWAIT);
    return switch (p.errno(received)) {
        .SUCCESS => .{
            .from = std.Io.Threaded.addressFromPosix(&storage),
            .data = buffer[0..@intCast(received)],
            .control = &.{},
            .flags = .{
                .eor = (header.flags & p.MSG.EOR) != 0,
                .trunc = (header.flags & p.MSG.TRUNC) != 0,
                .ctrunc = (header.flags & p.MSG.CTRUNC) != 0,
                .oob = (header.flags & p.MSG.OOB) != 0,
                .errqueue = if (@hasDecl(p.MSG, "ERRQUEUE")) (header.flags & p.MSG.ERRQUEUE) != 0 else false,
            },
        },
        .AGAIN, .INTR => null,
        .NFILE => error.SystemFdQuotaExceeded,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NOBUFS, .NOMEM => error.SystemResources,
        .NOTCONN, .PIPE => error.SocketUnconnected,
        .MSGSIZE => error.MessageOversize,
        .CONNRESET => error.ConnectionResetByPeer,
        .NETDOWN => error.NetworkDown,
        .BADF, .FAULT, .INVAL, .NOTSOCK, .OPNOTSUPP => |err| std.Io.Threaded.errnoBug(err),
        else => |err| p.unexpectedErrno(err),
    };
}

pub fn sendNative(io: std.Io, handle: net.Socket.Handle, address: *const net.IpAddress, bytes: []const u8) SendError!void {
    const p = std.posix;
    var storage: std.Io.Threaded.PosixAddress = undefined;
    const length = std.Io.Threaded.addressToPosix(address, &storage);
    try io.checkCancel();
    const sent = p.system.sendto(handle, bytes.ptr, bytes.len, p.MSG.NOSIGNAL | p.MSG.DONTWAIT, &storage.any, length);
    return switch (p.errno(sent)) {
        .SUCCESS => assert(@as(usize, @intCast(sent)) == bytes.len),
        else => |err| sendError(err),
    };
}

pub const NativeScratch = if (os == .linux) struct {
    headers: [Sockets.BatchScratch.capacity]std.posix.system.mmsghdr,
    addresses: [Sockets.BatchScratch.capacity]std.Io.Threaded.PosixAddress,
    vectors: [Sockets.BatchScratch.capacity]std.posix.iovec,
} else struct {};

/// Positive sendmmsg results hide the next datagram's errno. Retry exactly that suffix.
pub fn sendManyNative(io: std.Io, handle: net.Socket.Handle, messages: []const Sockets.Outgoing, scratch: *NativeScratch) SendOutcome {
    const p = std.posix;
    assert(messages.len > 0 and messages.len <= Sockets.BatchScratch.capacity);
    if (comptime os != .linux) {
        for (messages, 0..) |message, sent| {
            const address = message.to.toNetwork();
            sendNative(io, handle, &address, message.bytes) catch |err|
                return .{ .sent = sent, .failure = err };
        }
        return .{ .sent = messages.len, .failure = null };
    }
    for (messages, 0..) |message, i| {
        const address = message.to.toNetwork();
        scratch.vectors[i] = .{ .base = @constCast(message.bytes.ptr), .len = message.bytes.len };
        scratch.headers[i] = .{ .hdr = .{
            .name = &scratch.addresses[i].any,
            .namelen = std.Io.Threaded.addressToPosix(&address, &scratch.addresses[i]),
            .iov = scratch.vectors[i..][0..1],
            .iovlen = 1,
            .control = null,
            .controllen = 0,
            .flags = 0,
        }, .len = 0 };
    }
    var sent: usize = 0;
    for (0..messages.len) |_| {
        if (sent == messages.len) break;
        io.checkCancel() catch |err| return .{ .sent = sent, .failure = err };
        const result = p.system.sendmmsg(handle, scratch.headers[sent..].ptr, @intCast(messages.len - sent), p.MSG.NOSIGNAL | p.MSG.DONTWAIT);
        switch (p.errno(result)) {
            .SUCCESS => {
                const count: usize = @intCast(result);
                assert(count > 0 and count <= messages.len - sent);
                for (messages[sent..][0..count], scratch.headers[sent..][0..count]) |message, header|
                    assert(message.bytes.len == header.len);
                sent += count;
            },
            else => |err| return .{ .sent = sent, .failure = sendError(err) },
        }
    }
    assert(sent == messages.len);
    return .{ .sent = sent, .failure = null };
}

pub fn sendError(errno: std.posix.E) SendError {
    return switch (errno) {
        .SUCCESS => unreachable,
        // UDP destinations with port zero produce EINVAL on Linux.
        .PERM, .INVAL => error.DestinationRefused,
        .ACCES => error.AccessDenied,
        .ALREADY => error.FastOpenAlreadyInProgress,
        .CONNRESET => error.ConnectionResetByPeer,
        .MSGSIZE => error.MessageOversize,
        .AGAIN => error.WouldBlock,
        .NOBUFS, .NOMEM => error.SystemResources,
        .PIPE, .NOTCONN => error.SocketUnconnected,
        .AFNOSUPPORT => error.AddressFamilyUnsupported,
        .HOSTUNREACH => error.HostUnreachable,
        .NETUNREACH => error.NetworkUnreachable,
        .NETDOWN => error.NetworkDown,
        .BADF, .DESTADDRREQ, .FAULT, .ISCONN, .NOTSOCK, .OPNOTSUPP => |err| std.Io.Threaded.errnoBug(err),
        else => |err| std.posix.unexpectedErrno(err),
    };
}

pub fn capped(reported: ?u32, requested: u32) bool {
    const full: u64 = if (os == .linux) @as(u64, requested) * 2 else requested;
    return (reported orelse return false) < full;
}

pub fn setBuffer(handle: net.Socket.Handle, option: u32, bytes: u32) void {
    const p = std.posix;
    const value: c_int = @intCast(bytes);
    // The kernel caps the size silently on Linux and refuses it elsewhere. Reading the size back
    // decides the outcome, so the result is ignored.
    _ = p.system.setsockopt(handle, p.SOL.SOCKET, option, std.mem.asBytes(&value), @sizeOf(c_int));
}

pub fn readBuffer(handle: net.Socket.Handle, option: u32) ?u32 {
    const p = std.posix;
    var value: c_int = 0;
    var len: p.socklen_t = @sizeOf(c_int);
    if (p.errno(p.system.getsockopt(handle, p.SOL.SOCKET, option, std.mem.asBytes(&value), &len)) != .SUCCESS) return null;
    if (len != @sizeOf(c_int)) return null;
    return std.math.cast(u32, value);
}

pub fn readDrops(handle: net.Socket.Handle) ?u32 {
    const p = std.posix;
    // SK_MEMINFO_DROPS in linux/sock_diag.h. SO_MEMINFO reads the counter SO_RXQ_OVFL reports,
    // without ancillary data on every receive.
    const drops_index = 8;
    var meminfo: [drops_index + 1]u32 = @splat(0);
    var len: p.socklen_t = @sizeOf(@TypeOf(meminfo));
    if (p.errno(p.system.getsockopt(handle, p.SOL.SOCKET, p.SO.MEMINFO, std.mem.asBytes(&meminfo), &len)) != .SUCCESS) return null;
    if (len < @sizeOf(@TypeOf(meminfo))) return null;
    return meminfo[drops_index];
}

pub fn bindIp6(io: std.Io, ip: net.Ip6Address) BindError!net.Socket {
    const address: net.IpAddress = .{ .ip6 = ip };
    if (native_sockets) {
        // Zig 0.16 Threaded sets IPV6_V6ONLY to zero for ip6_only. Set it before
        // binding its native sockets; other I/O providers retain their own bind contract.
        if (threaded(io)) {
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

pub fn checkBindError(err: std.posix.E) BindError!void {
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
