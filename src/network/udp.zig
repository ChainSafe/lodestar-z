const std = @import("std");
const constants = @import("constants.zig");
const types = @import("types.zig");

const net = std.Io.net;
const sockets_mod = @import("udp");
pub const Bindings = sockets_mod.Bindings;

pub const Handle = struct {
    generation: u64,
};

pub const Datagram = struct {
    handle: Handle,
    from: types.Address,
    bytes: []u8,
};

pub const ReceiveTimeoutError = sockets_mod.ReceiveError || error{
    AdmissionUnavailable,
    DatagramTooLarge,
    GenerationExhausted,
};

pub const ReleaseError = error{StaleDatagram};

pub const SendError = net.Socket.SendError || error{DatagramTooLarge};

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
    buffer: [constants.datagram_size_max]u8 = undefined,
    admitted: ?u64 = null,
    next_generation: u64 = 1,

    pub fn bind(io: std.Io, addresses: Bindings) sockets_mod.BindError!Udp {
        return .{ .sockets = try sockets_mod.Sockets.bind(io, addresses) };
    }

    pub fn close(self: *const Udp, io: std.Io) void {
        std.debug.assert(self.admitted == null);
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
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!Datagram {
        if (self.admitted != null) return error.AdmissionUnavailable;
        const incoming = try self.sockets.receiveTimeout(io, &self.buffer, timeout);
        self.counters.received_datagrams +|= 1;
        if (incoming.flags.trunc) {
            std.log.scoped(.network_quic).debug("datagram_refused reason=oversize capacity={d}", .{self.buffer.len});
            self.counters.truncated_datagrams +|= 1;
            return error.DatagramTooLarge;
        }
        self.counters.received_bytes +|= incoming.data.len;
        const successor = std.math.add(u64, self.next_generation, 1) catch
            return error.GenerationExhausted;
        std.debug.assert(incoming.data.len <= self.buffer.len);
        const generation = self.next_generation;
        self.next_generation = successor;
        self.admitted = generation;
        return .{
            .handle = .{ .generation = generation },
            .from = fromNetwork(incoming.from),
            .bytes = self.buffer[0..incoming.data.len],
        };
    }

    pub fn release(self: *Udp, handle: Handle) ReleaseError!void {
        std.debug.assert(handle.generation > 0);
        const admitted = self.admitted orelse return error.StaleDatagram;
        if (admitted != handle.generation) return error.StaleDatagram;
        self.admitted = null;
        std.debug.assert(self.next_generation > handle.generation);
    }

    pub fn send(
        self: *Udp,
        io: std.Io,
        destination: *const types.Address,
        bytes: []const u8,
    ) SendError!void {
        std.debug.assert(bytes.len > 0);
        if (bytes.len > constants.datagram_size_max) return error.DatagramTooLarge;
        const address = toNetwork(destination.*);
        const socket = self.sockets.get(address) orelse return error.AddressFamilyUnsupported;
        try socket.send(io, &address, bytes);
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

pub fn fromNetwork(address: net.IpAddress) types.Address {
    return switch (address) {
        .ip4 => |value| .{ .ip4 = .{ .octets = value.bytes, .port = value.port } },
        .ip6 => |value| if (isMappedIp4(value.bytes))
            .{ .ip4 = .{ .octets = value.bytes[12..16].*, .port = value.port } }
        else
            .{ .ip6 = .{
                .octets = value.bytes,
                .port = value.port,
                .interface = value.interface.index,
            } },
    };
}

pub fn toNetwork(address: types.Address) net.IpAddress {
    return switch (address) {
        .ip4 => |value| .{ .ip4 = .{ .bytes = value.octets, .port = value.port } },
        .ip6 => |value| .{ .ip6 = .{
            .bytes = value.octets,
            .port = value.port,
            .flow = 0,
            .interface = .{ .index = value.interface },
        } },
    };
}

fn isMappedIp4(ip: [16]u8) bool {
    return std.mem.eql(u8, ip[0..10], &([_]u8{0} ** 10)) and ip[10] == 0xff and ip[11] == 0xff;
}

comptime {
    std.debug.assert(@sizeOf(Udp) <= 2 * 1_024);
}
