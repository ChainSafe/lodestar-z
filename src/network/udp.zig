const std = @import("std");
const constants = @import("constants.zig");
const types = @import("types.zig");

const net = std.Io.net;
const sockets_mod = @import("udp");
pub const Bindings = sockets_mod.Bindings;

pub const Datagram = sockets_mod.Datagram;
pub const ReceiveTimeoutError = sockets_mod.DatagramError;
pub const SendError = sockets_mod.SendError;

pub const SendOutcome = sockets_mod.SendOutcome;
pub const Buffers = sockets_mod.Buffers;

const mib = 1024 * 1024;

/// Kernel buffer sizes requested for each UDP socket role. The kernel default of 208 KiB holds
/// about 20 ms of traffic at 8,000 datagrams/s, so a longer owner pause drops datagrams. Linux
/// caps a request at net.core.rmem_max or wmem_max and doubles it: at a 16 MiB rmem_max, the QUIC
/// receive buffer holds about 14,560 datagrams at a truesize of 2,304 bytes.
pub const SocketBuffers = struct {
    quic: Buffers = .{ .receive = 16 * mib, .send = 4 * mib },
    discovery: Buffers = .{ .receive = 2 * mib, .send = 1 * mib },

    pub fn validate(self: SocketBuffers) error{InvalidLimits}!void {
        if (!self.quic.valid() or !self.discovery.valid()) return error.InvalidLimits;
    }
};

/// Requests `request` on every socket and logs one warning per socket the kernel caps below it.
pub fn requestBuffers(sockets: *sockets_mod.Sockets, io: std.Io, request: Buffers, comptime scope: @EnumLiteral()) void {
    const short = sockets.requestBuffers(io, request);
    for (short, sockets.buffers, [_][]const u8{ "ip4", "ip6" }) |below, reported, family| {
        if (!below) continue;
        std.log.scoped(scope).warn("socket_buffers_below_request family={s} receive_bytes={?d} receive_requested={d} send_bytes={?d} send_requested={d}", .{ family, reported.?.receive, request.receive, reported.?.send, request.send });
    }
}

pub const Counters = struct {
    received_bytes: u64 = 0,
    sent_bytes: u64 = 0,
    received_datagrams: u64 = 0,
    sent_datagrams: u64 = 0,
};

pub const Udp = struct {
    counters: Counters = .{},
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

    pub fn localAddresses(self: *const Udp) [2]?types.Address {
        var result: [2]?types.Address = .{ null, null };
        for (self.sockets.values, 0..) |socket, i| if (socket) |value| {
            result[i] = fromNetwork(value.address);
        };
        return result;
    }

    pub fn receiveTimeout(
        self: *Udp,
        io: std.Io,
        buffer: *[constants.datagram_size_max]u8,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!Datagram {
        return self.counted(self.sockets.receiveDatagram(io, buffer, timeout));
    }

    /// Reads one datagram without waiting from a family `ready` marks, and times out once none
    /// remains. See `Sockets.receiveReady`.
    pub fn receiveReady(
        self: *Udp,
        io: std.Io,
        buffer: *[constants.datagram_size_max]u8,
        ready: *[2]bool,
    ) ReceiveTimeoutError!Datagram {
        const received = self.sockets.receiveReadyDatagram(io, buffer, ready) catch |err| return self.counted(err);
        return self.counted(received orelse error.Timeout);
    }

    fn counted(self: *Udp, received: ReceiveTimeoutError!Datagram) ReceiveTimeoutError!Datagram {
        const incoming = received catch |err| {
            if (err == error.DatagramTooLarge) self.counters.received_datagrams +|= 1;
            return err;
        };
        self.counters.received_datagrams +|= 1;
        self.counters.received_bytes +|= incoming.bytes.len;
        return incoming;
    }

    pub fn send(
        self: *Udp,
        io: std.Io,
        destination: *const types.Address,
        bytes: []const u8,
    ) SendError!void {
        std.debug.assert(bytes.len > 0);
        try self.sockets.sendTo(io, destination.*, bytes, constants.datagram_size_max);
        self.counters.sent_bytes +|= bytes.len;
        self.counters.sent_datagrams +|= 1;
    }

    /// Sends the batch in order, one sendmmsg call per run of one address family. It stops at
    /// the first datagram that fails: `sent` datagrams went out and `failure` is that datagram's error.
    pub fn sendMany(self: *Udp, io: std.Io, batch: []const types.Sent) SendOutcome {
        std.debug.assert(batch.len <= constants.send_batch_max);
        std.debug.assert(batch.len > 0);
        var addresses: [constants.send_batch_max]net.IpAddress = undefined;
        var messages: [constants.send_batch_max]net.OutgoingMessage = undefined;
        for (batch, 0..) |sent, position| {
            if (sent.bytes.len > constants.datagram_size_max) return .{ .sent = 0, .failure = error.DatagramTooLarge };
            addresses[position] = toNetwork(sent.to);
            messages[position] = .{
                .address = &addresses[position],
                .data_ptr = sent.bytes.ptr,
                .data_len = sent.bytes.len,
            };
        }
        var begin: usize = 0;
        while (begin < batch.len) {
            var end = begin + 1;
            while (end < batch.len and std.meta.activeTag(addresses[end]) == std.meta.activeTag(addresses[begin])) : (end += 1) {}
            const run = self.sockets.sendMany(io, messages[begin..end]);
            std.debug.assert(run.sent <= end - begin);
            for (messages[begin..][0..run.sent], batch[begin..][0..run.sent], 0..) |message, sent, offset| {
                if (message.data_len != sent.bytes.len) return .{ .sent = begin + offset, .failure = error.MessageOversize };
                self.counters.sent_bytes +|= message.data_len;
                self.counters.sent_datagrams +|= 1;
            }
            if (run.sent != end - begin) return .{ .sent = begin + run.sent, .failure = run.failure.? };
            begin = end;
        }
        return .{ .sent = batch.len, .failure = null };
    }
};

pub const fromNetwork = types.Address.fromNetwork;
pub const toNetwork = types.Address.toNetwork;

test {
    _ = @import("udp_test.zig");
}
