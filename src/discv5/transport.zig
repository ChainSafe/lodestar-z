//! UDP transport interface for discv5

const std = @import("std");
const Allocator = std.mem.Allocator;
const net = std.net;

pub const Address = struct {
    ip: [4]u8,
    port: u16,
};

pub const RecvResult = struct {
    data: []const u8,
    from: Address,
};

pub const Error = error{
    SocketError,
    RecvError,
    SendError,
    OutOfMemory,
    Closed,
};

pub const Transport = struct {
    ptr: *anyopaque,
    sendFn: *const fn (ptr: *anyopaque, dest: Address, data: []const u8) anyerror!void,
    recvFn: *const fn (ptr: *anyopaque, buf: []u8) anyerror!RecvResult,
    closeFn: *const fn (ptr: *anyopaque) void,

    pub fn send(self: Transport, dest: Address, data: []const u8) !void {
        return self.sendFn(self.ptr, dest, data);
    }

    pub fn recv(self: Transport, buf: []u8) !RecvResult {
        return self.recvFn(self.ptr, buf);
    }

    pub fn close(self: Transport) void {
        self.closeFn(self.ptr);
    }
};

// =========== UDP Transport ===========

pub const UdpTransport = struct {
    socket: std.posix.socket_t,
    alloc: Allocator,

    pub fn init(alloc: Allocator, bind_ip: [4]u8, bind_port: u16) !UdpTransport {
        const sockfd = try std.posix.socket(
            std.posix.AF.INET,
            std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC,
            0,
        );
        errdefer closeSocket(sockfd);

        const addr = net.Address.initIp4(bind_ip, bind_port);
        try std.posix.bind(sockfd, &addr.any, addr.getOsSockLen());

        return .{ .socket = sockfd, .alloc = alloc };
    }

    pub fn deinit(self: *UdpTransport) void {
        closeSocket(self.socket);
    }

    pub fn transport(self: *UdpTransport) Transport {
        return .{
            .ptr = self,
            .sendFn = sendImpl,
            .recvFn = recvImpl,
            .closeFn = closeImpl,
        };
    }

    fn sendImpl(ptr: *anyopaque, dest: Address, data: []const u8) anyerror!void {
        const self: *UdpTransport = @ptrCast(@alignCast(ptr));
        const addr = net.Address.initIp4(dest.ip, dest.port);
        _ = try std.posix.sendto(self.socket, data, 0, &addr.any, addr.getOsSockLen());
    }

    fn recvImpl(ptr: *anyopaque, buf: []u8) anyerror!RecvResult {
        const self: *UdpTransport = @ptrCast(@alignCast(ptr));
        var src_addr: std.posix.sockaddr = undefined;
        var src_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
        const n = try std.posix.recvfrom(self.socket, buf, 0, &src_addr, &src_len);
        const net_addr = net.Address{ .any = src_addr };
        return .{
            .data = buf[0..n],
            .from = Address{
                .ip = net_addr.in.sa.addr,
                .port = net_addr.getPort(),
            },
        };
    }

    fn closeImpl(ptr: *anyopaque) void {
        const self: *UdpTransport = @ptrCast(@alignCast(ptr));
        closeSocket(self.socket);
    }
};

fn closeSocket(sockfd: std.posix.socket_t) void {
    switch (std.posix.errno(std.posix.system.close(sockfd))) {
        .SUCCESS, .INTR => {},
        else => {},
    }
}

// =========== Mock Transport ===========

pub const Packet = struct {
    dest: Address,
    data: []u8,
    alloc: Allocator,

    pub fn deinit(self: *Packet) void {
        self.alloc.free(self.data);
    }
};

pub const MockTransport = struct {
    alloc: Allocator,
    sent: std.ArrayListUnmanaged(Packet),
    recv_queue: std.ArrayListUnmanaged(Packet),
    local_addr: Address,
    closed: bool,

    pub fn init(alloc: Allocator, local_addr: Address) MockTransport {
        return .{
            .alloc = alloc,
            .sent = .empty,
            .recv_queue = .empty,
            .local_addr = local_addr,
            .closed = false,
        };
    }

    pub fn deinit(self: *MockTransport) void {
        for (self.sent.items) |*p| p.deinit();
        self.sent.deinit(self.alloc);
        for (self.recv_queue.items) |*p| p.deinit();
        self.recv_queue.deinit(self.alloc);
    }

    pub fn queueRecv(self: *MockTransport, from: Address, data: []const u8) !void {
        const copy = try self.alloc.dupe(u8, data);
        try self.recv_queue.append(self.alloc, .{ .dest = from, .data = copy, .alloc = self.alloc });
    }

    pub fn transport(self: *MockTransport) Transport {
        return .{
            .ptr = self,
            .sendFn = sendImpl,
            .recvFn = recvImpl,
            .closeFn = closeImpl,
        };
    }

    fn sendImpl(ptr: *anyopaque, dest: Address, data: []const u8) anyerror!void {
        const self: *MockTransport = @ptrCast(@alignCast(ptr));
        if (self.closed) return Error.Closed;
        const copy = try self.alloc.dupe(u8, data);
        try self.sent.append(self.alloc, .{ .dest = dest, .data = copy, .alloc = self.alloc });
    }

    fn recvImpl(ptr: *anyopaque, buf: []u8) anyerror!RecvResult {
        const self: *MockTransport = @ptrCast(@alignCast(ptr));
        if (self.closed) return Error.Closed;
        if (self.recv_queue.items.len == 0) return Error.RecvError;
        var p = self.recv_queue.orderedRemove(0);
        defer p.deinit();
        const n = @min(buf.len, p.data.len);
        @memcpy(buf[0..n], p.data[0..n]);
        return .{ .data = buf[0..n], .from = p.dest };
    }

    fn closeImpl(ptr: *anyopaque) void {
        const self: *MockTransport = @ptrCast(@alignCast(ptr));
        self.closed = true;
    }
};

// =========== Tests ===========

test "transport: MockTransport send/recv" {
    const alloc = std.testing.allocator;
    var mock = MockTransport.init(alloc, .{ .ip = [4]u8{ 127, 0, 0, 1 }, .port = 9000 });
    defer mock.deinit();

    const t = mock.transport();

    try mock.queueRecv(.{ .ip = [4]u8{ 192, 168, 1, 1 }, .port = 30303 }, "hello");

    var buf: [1280]u8 = undefined;
    const result = try t.recv(&buf);
    try std.testing.expectEqualSlices(u8, "hello", result.data);
    try std.testing.expectEqual(@as(u16, 30303), result.from.port);

    try t.send(.{ .ip = [4]u8{ 10, 0, 0, 1 }, .port = 9001 }, "world");
    try std.testing.expectEqual(@as(usize, 1), mock.sent.items.len);
    try std.testing.expectEqualSlices(u8, "world", mock.sent.items[0].data);
}
