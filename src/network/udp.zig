const std = @import("std");
const constants = @import("constants.zig");
const types = @import("types.zig");

const net = std.Io.net;

pub const Handle = struct {
    generation: u64,
};

pub const Datagram = struct {
    handle: Handle,
    from: types.Address,
    bytes: []u8,
};

pub const ReceiveTimeoutError = net.Socket.ReceiveTimeoutError || error{
    AdmissionUnavailable,
    DatagramTooLarge,
    GenerationExhausted,
};

pub const ReleaseError = error{StaleDatagram};

pub const SendError = net.Socket.SendError || error{DatagramTooLarge};

pub const Family = enum { ip4, ip6 };

pub const Counters = struct {
    received_bytes: u64 = 0,
    sent_bytes: u64 = 0,
    received_datagrams: u64 = 0,
    sent_datagrams: u64 = 0,
    truncated_datagrams: u64 = 0,
};

pub const Udp = struct {
    counters: Counters = .{},
    socket: net.Socket,
    family: Family,
    buffer: [constants.datagram_size_max]u8 = undefined,
    admitted: ?u64 = null,
    next_generation: u64 = 1,

    pub fn bind(io: std.Io, address: net.IpAddress) net.IpAddress.BindError!Udp {
        const socket = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
        std.debug.assert(familyOf(socket.address) == familyOf(address));
        std.debug.assert(socket.address.getPort() != 0 or address.getPort() == 0);
        return .{ .socket = socket, .family = familyOf(socket.address) };
    }

    pub fn init(socket: net.Socket) Udp {
        return .{ .socket = socket, .family = familyOf(socket.address) };
    }

    pub fn close(self: *const Udp, io: std.Io) void {
        std.debug.assert(self.admitted == null);
        self.socket.close(io);
    }

    pub fn localAddress(self: *const Udp) types.Address {
        const address = fromNetwork(self.socket.address);
        std.debug.assert(self.family == .ip6 or address == .ip4);
        return address;
    }

    pub fn receiveTimeout(
        self: *Udp,
        io: std.Io,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!Datagram {
        if (self.admitted != null) return error.AdmissionUnavailable;
        const incoming = try self.socket.receiveTimeout(io, &self.buffer, timeout);
        self.counters.received_datagrams +|= 1;
        if (incoming.flags.trunc) {
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
        const address = toNetwork(destination.*, self.family);
        try self.socket.send(io, &address, bytes);
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
            addresses[position] = toNetwork(sent.to, self.family);
            messages[position] = .{
                .address = &addresses[position],
                .data_ptr = sent.bytes.ptr,
                .data_len = sent.bytes.len,
            };
        }
        // Socket.sendMany discards the successful prefix on error. Count that prefix too.
        const failure, const count = io.vtable.netSend(io.userdata, self.socket.handle, messages[0..batch.len], .{});
        std.debug.assert(count <= batch.len);
        for (messages[0..count]) |message| {
            self.counters.sent_bytes +|= message.data_len;
            self.counters.sent_datagrams +|= 1;
        }
        if (count != batch.len) return failure.?;
        for (messages[0..batch.len], batch) |message, sent| {
            if (message.data_len != sent.bytes.len) return error.MessageOversize;
        }
    }
};

fn familyOf(address: net.IpAddress) Family {
    return switch (address) {
        .ip4 => .ip4,
        .ip6 => .ip6,
    };
}

fn mappedIp4(octets: [4]u8) [16]u8 {
    var bytes = [_]u8{0} ** 16;
    bytes[10] = 0xff;
    bytes[11] = 0xff;
    @memcpy(bytes[12..16], &octets);
    return bytes;
}

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

pub fn toNetwork(address: types.Address, family: Family) net.IpAddress {
    return switch (address) {
        .ip4 => |value| if (family == .ip6) .{ .ip6 = .{
            .bytes = mappedIp4(value.octets),
            .port = value.port,
            .flow = 0,
            .interface = .{ .index = 0 },
        } } else .{ .ip4 = .{ .bytes = value.octets, .port = value.port } },
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
