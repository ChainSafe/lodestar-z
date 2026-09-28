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
pub const SendError = net.Socket.SendError || error{
    DatagramTooLarge,
    /// Local policy, such as an egress firewall rule, refused the datagram to this destination
    /// (EPERM).
    DestinationRefused,
};
pub const Datagram = struct { from: Address, bytes: []u8 };

/// Kernel socket buffer sizes in bytes.
pub const Buffers = struct {
    receive: u32,
    send: u32,

    pub const bytes_min: u32 = 64 * 1024;
    pub const bytes_max: u32 = 64 * 1024 * 1024;

    pub fn valid(self: Buffers) bool {
        return self.receive >= bytes_min and self.receive <= bytes_max and
            self.send >= bytes_min and self.send <= bytes_max;
    }

    /// Sizes as getsockopt reported them. Null where the read failed.
    pub const Reported = struct { receive: ?u32, send: ?u32 };
};

/// Owns at most one socket per configured address family. The caller serializes
/// receives and close, and does not receive directly from the owned sockets.
pub const Sockets = struct {
    values: [2]?net.Socket = .{ null, null },
    /// Buffer sizes per family as getsockopt reported them after `requestBuffers`. Linux reports
    /// double the size it grants.
    buffers: [2]?Buffers.Reported = .{ null, null },
    /// Kernel drop counts per family, extended past their 32-bit wrap by `drops`.
    drop_counts: [2]DropCount = @splat(.{}),
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

    /// Requests `request` on each socket and records what the kernel reports. The kernel caps a
    /// request at its limit (net.core.rmem_max and wmem_max on Linux), so a smaller size is not
    /// an error. Returns the families whose sockets the kernel granted less than the request; an
    /// unknown size does not count. Sockets of other I/O providers and platforms keep their sizes
    /// and record nothing.
    pub fn requestBuffers(self: *Sockets, io: std.Io, request: Buffers) [2]bool {
        assert(request.valid());
        var short: [2]bool = .{ false, false };
        if (native_sockets) {
            if (!threaded(io)) return short;
            const p = std.posix;
            for (self.values, &self.buffers, &short) |socket, *reported, *below| {
                const handle = (socket orelse continue).handle;
                setBuffer(handle, p.SO.RCVBUF, request.receive);
                setBuffer(handle, p.SO.SNDBUF, request.send);
                const sizes: Buffers.Reported = .{ .receive = readBuffer(handle, p.SO.RCVBUF), .send = readBuffer(handle, p.SO.SNDBUF) };
                reported.* = sizes;
                below.* = capped(sizes.receive, request.receive) or capped(sizes.send, request.send);
            }
        }
        return short;
    }

    /// Datagrams the kernel dropped at each socket over its lifetime, mostly on a full receive
    /// buffer. Each call extends Linux's wrapping 32-bit count. Null off Linux, for sockets without
    /// recorded buffers and where the kernel reports no count.
    pub fn drops(self: *Sockets) [2]?u64 {
        var result: [2]?u64 = .{ null, null };
        if (comptime os != .linux) return result;
        for (self.values, self.buffers, &self.drop_counts, &result) |socket, reported, *count, *total| {
            if (reported == null) continue;
            total.* = count.add(readDrops(socket.?.handle) orelse continue);
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
        if (native_sockets) {
            if (threadedSend(io)) return sendNative(io, socket.handle, &address, bytes);
        }
        try socket.send(io, &address, bytes);
    }
};

const os = @import("builtin").os.tag;
const native_sockets = std.options.networking and (os == .linux or os == .macos);

/// Zig 0.16 Threaded hands out native descriptors; other I/O providers keep their own contract.
fn threaded(io: std.Io) bool {
    return io.vtable.netBindIp == std.Io.Threaded.global_single_threaded.io().vtable.netBindIp;
}

/// A provider that replaces only the send keeps its own send contract.
fn threadedSend(io: std.Io) bool {
    return threaded(io) and io.vtable.netSend == std.Io.Threaded.global_single_threaded.io().vtable.netSend;
}

/// Sends as Zig 0.16 Threaded does, keeping its errno mapping, but names EPERM, which Threaded
/// reports as `error.Unexpected`. The errno is read straight from this send's return. The send
/// never waits: a full send buffer reports `SystemResources`, so the cancellation check before it
/// covers the whole send.
fn sendNative(io: std.Io, handle: net.Socket.Handle, address: *const net.IpAddress, bytes: []const u8) SendError!void {
    const p = std.posix;
    var storage: std.Io.Threaded.PosixAddress = undefined;
    const length = std.Io.Threaded.addressToPosix(address, &storage);
    try io.checkCancel();
    const sent = p.system.sendto(handle, bytes.ptr, bytes.len, p.MSG.NOSIGNAL | p.MSG.DONTWAIT, &storage.any, length);
    return switch (p.errno(sent)) {
        .SUCCESS => if (@as(usize, @intCast(sent)) == bytes.len) {} else error.MessageOversize,
        .PERM => error.DestinationRefused,
        .ACCES => error.AccessDenied,
        .ALREADY => error.FastOpenAlreadyInProgress,
        .CONNRESET => error.ConnectionResetByPeer,
        .MSGSIZE => error.MessageOversize,
        .AGAIN, .NOBUFS, .NOMEM => error.SystemResources,
        .PIPE, .NOTCONN => error.SocketUnconnected,
        .AFNOSUPPORT => error.AddressFamilyUnsupported,
        .HOSTUNREACH => error.HostUnreachable,
        .NETUNREACH => error.NetworkUnreachable,
        .NETDOWN => error.NetworkDown,
        .BADF, .DESTADDRREQ, .FAULT, .INVAL, .ISCONN, .NOTSOCK, .OPNOTSUPP => |err| std.Io.Threaded.errnoBug(err),
        else => |err| p.unexpectedErrno(err),
    };
}

/// Linux doubles a granted size for bookkeeping and reports the doubled value. An unknown size
/// is not a cap.
fn capped(reported: ?u32, requested: u32) bool {
    const full: u64 = if (os == .linux) @as(u64, requested) * 2 else requested;
    return (reported orelse return false) < full;
}

fn setBuffer(handle: net.Socket.Handle, option: u32, bytes: u32) void {
    const p = std.posix;
    const value: c_int = @intCast(bytes);
    // The kernel caps the size silently on Linux and refuses it elsewhere. Reading the size back
    // decides the outcome, so the result is ignored.
    _ = p.system.setsockopt(handle, p.SOL.SOCKET, option, std.mem.asBytes(&value), @sizeOf(c_int));
}

fn readBuffer(handle: net.Socket.Handle, option: u32) ?u32 {
    const p = std.posix;
    var value: c_int = 0;
    var len: p.socklen_t = @sizeOf(c_int);
    if (p.errno(p.system.getsockopt(handle, p.SOL.SOCKET, option, std.mem.asBytes(&value), &len)) != .SUCCESS) return null;
    if (len != @sizeOf(c_int)) return null;
    return std.math.cast(u32, value);
}

fn readDrops(handle: net.Socket.Handle) ?u32 {
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

/// The kernel's 32-bit drop count extended to a socket-lifetime total. The kernel count starts at
/// zero with the socket.
const DropCount = struct {
    last: u32 = 0,
    total: u64 = 0,

    fn add(self: *DropCount, raw: u32) u64 {
        // Exact while fewer than 2^32 drops happen between two reads; every metrics scrape reads.
        self.total += raw -% self.last;
        self.last = raw;
        return self.total;
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

test "UDP drop totals keep counting across the kernel count's 32-bit wrap" {
    _ = @import("root_test.zig");
    const max = std.math.maxInt(u32);
    var count: DropCount = .{};
    try std.testing.expectEqual(@as(u64, 5), count.add(5));
    try std.testing.expectEqual(@as(u64, 5), count.add(5));
    try std.testing.expectEqual(@as(u64, max), count.add(max));
    try std.testing.expectEqual(@as(u64, max) + 4, count.add(3));
    try std.testing.expectEqual(@as(u64, max) + 4 + max, count.add(2));
}
