const std = @import("std");
const constants = @import("constants.zig");
const types = @import("types.zig");

const net = std.Io.net;
const sockets_mod = @import("udp");
pub const Bindings = sockets_mod.Bindings;

pub const Datagram = sockets_mod.Datagram;
pub const ReceiveTimeoutError = sockets_mod.DatagramError;
pub const SendError = sockets_mod.SendError;

pub const Counters = struct {
    received_bytes: u64 = 0,
    sent_bytes: u64 = 0,
    received_datagrams: u64 = 0,
    sent_datagrams: u64 = 0,
    truncated_datagrams: u64 = 0,
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
        const incoming = self.sockets.receiveDatagram(io, buffer, timeout) catch |err| {
            if (err == error.DatagramTooLarge) {
                self.counters.received_datagrams +|= 1;
                self.counters.truncated_datagrams +|= 1;
            }
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

    pub fn sendMany(self: *Udp, io: std.Io, batch: []const types.Sent) SendError!void {
        std.debug.assert(batch.len <= constants.send_batch_max);
        std.debug.assert(batch.len > 0);
        var addresses: [constants.send_batch_max]net.IpAddress = undefined;
        var messages: [constants.send_batch_max]net.OutgoingMessage = undefined;
        for (batch, 0..) |sent, position| {
            if (sent.bytes.len > constants.datagram_size_max) return error.DatagramTooLarge;
            addresses[position] = toNetwork(sent.to);
            messages[position] = .{
                .address = &addresses[position],
                .data_ptr = sent.bytes.ptr,
                .data_len = sent.bytes.len,
            };
        }
        var begin: usize = 0;
        while (begin < batch.len) {
            const socket = self.sockets.get(addresses[begin]) orelse return error.AddressFamilyUnsupported;
            var end = begin + 1;
            while (end < batch.len and std.meta.activeTag(addresses[end]) == std.meta.activeTag(addresses[begin])) : (end += 1) {}
            const failure, const count = io.vtable.netSend(io.userdata, socket.handle, messages[begin..end], .{});
            std.debug.assert(count <= end - begin);
            for (messages[begin..][0..count]) |message| {
                self.counters.sent_bytes +|= message.data_len;
                self.counters.sent_datagrams +|= 1;
            }
            if (count != end - begin) return failure.?;
            for (messages[begin..end], batch[begin..end]) |message, sent| {
                if (message.data_len != sent.bytes.len) return error.MessageOversize;
            }
            begin = end;
        }
    }
};

pub const fromNetwork = types.Address.fromNetwork;
pub const toNetwork = types.Address.toNetwork;

test {
    _ = @import("udp_test.zig");
}
