const std = @import("std");
const http = std.http;
const net = std.Io.net;
const Io = std.Io;
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.metrics_server);

const Route = enum {
    metrics,
    not_found,
    method_not_allowed,
};

pub fn Server(comptime SurfaceType: type, comptime server_label: []const u8) type {
    return struct {
        const Self = @This();

        pub const StartupStatus = enum(u8) {
            idle,
            started,
            failed,
        };

        allocator: Allocator,
        metrics: *SurfaceType,
        address: []const u8,
        port: u16,
        shutdown_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        startup_status: std.atomic.Value(u8) = std.atomic.Value(u8).init(@intFromEnum(StartupStatus.idle)),
        startup_ready: Io.Event = .unset,
        listener: ?net.Server = null,
        listener_mutex: Io.Mutex = .init,

        pub fn init(
            allocator: Allocator,
            metrics: *SurfaceType,
            address: []const u8,
            port: u16,
        ) Self {
            return .{
                .allocator = allocator,
                .metrics = metrics,
                .address = address,
                .port = port,
            };
        }

        pub fn startupStatus(self: *const Self) StartupStatus {
            return @enumFromInt(self.startup_status.load(.acquire));
        }

        pub fn waitReady(self: *Self, io: Io) !void {
            if (!self.startup_ready.isSet()) {
                try self.startup_ready.wait(io);
            }
        }

        pub fn shutdown(self: *Self, io: Io) void {
            self.shutdown_requested.store(true, .release);
            self.wakeListener(io);
            self.listener_mutex.lock(io) catch return;
            defer self.listener_mutex.unlock(io);
            if (self.listener) |*listener| {
                listener.deinit(io);
                self.listener = null;
            }
        }

        pub fn serve(self: *Self, io: Io) !void {
            const ip = parseIpAddress(self.address, self.port) catch |err| {
                self.markStartup(io, .failed);
                return err;
            };
            var tcp_server = ip.listen(io, .{ .reuse_address = true }) catch |err| {
                self.markStartup(io, .failed);
                return err;
            };
            try self.listener_mutex.lock(io);
            self.listener = tcp_server;
            self.listener_mutex.unlock(io);
            defer {
                if (self.listener_mutex.lock(io)) |_| {
                    defer self.listener_mutex.unlock(io);
                    if (self.listener) |*listener| {
                        listener.deinit(io);
                        self.listener = null;
                    }
                } else |_| {}
            }

            self.markStartup(io, .started);
            log.info("{s} metrics endpoint: http://{s}:{d}/metrics", .{ server_label, self.address, self.port });

            while (!self.shutdown_requested.load(.acquire)) {
                const stream = tcp_server.accept(io) catch |err| {
                    if (self.shutdown_requested.load(.acquire)) break;
                    switch (err) {
                        error.SocketNotListening,
                        error.ConnectionAborted,
                        => break,
                        else => {},
                    }
                    log.err("accept failed: {s}", .{@errorName(err)});
                    continue;
                };
                if (self.shutdown_requested.load(.acquire)) {
                    var copy = stream;
                    copy.close(io);
                    break;
                }

                self.handleConnection(io, stream) catch |err| {
                    log.debug("connection error: {s}", .{@errorName(err)});
                };
            }
        }

        fn markStartup(self: *Self, io: Io, status: StartupStatus) void {
            self.startup_status.store(@intFromEnum(status), .release);
            self.startup_ready.set(io);
        }

        fn handleConnection(self: *Self, io: Io, stream: net.Stream) !void {
            defer {
                var copy = stream;
                copy.close(io);
            }

            var send_buf: [65536]u8 = undefined;
            var recv_buf: [4096]u8 = undefined;
            var conn_reader = stream.reader(io, &recv_buf);
            var conn_writer = stream.writer(io, &send_buf);
            var server: http.Server = .init(&conn_reader.interface, &conn_writer.interface);

            while (true) {
                var request = server.receiveHead() catch |err| switch (err) {
                    error.HttpConnectionClosing => return,
                    else => return err,
                };
                try self.handleHttpRequest(&request);
            }
        }

        fn handleHttpRequest(self: *Self, request: *http.Server.Request) !void {
            switch (classifyRequest(request.head.method, request.head.target)) {
                .not_found => {
                    try request.respond("Not Found\n", .{
                        .status = .not_found,
                        .extra_headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
                    });
                },
                .method_not_allowed => {
                    try request.respond("Method Not Allowed\n", .{
                        .status = .method_not_allowed,
                        .extra_headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
                    });
                },
                .metrics => {
                    var body: std.Io.Writer.Allocating = .init(self.allocator);
                    defer body.deinit();
                    try self.metrics.write(&body.writer);

                    try request.respond(body.writer.buffered(), .{
                        .status = .ok,
                        .extra_headers = &.{
                            .{ .name = "Content-Type", .value = "text/plain; version=0.0.4; charset=utf-8" },
                        },
                    });
                },
            }
        }

        fn wakeListener(self: *Self, io: Io) void {
            const wake_addr = switch (parseIpAddress(self.address, self.port) catch return) {
                .ip4 => |ip4| blk: {
                    if (std.mem.eql(u8, &ip4.bytes, &[_]u8{ 0, 0, 0, 0 })) {
                        break :blk net.IpAddress.parseIp4("127.0.0.1", self.port) catch return;
                    }
                    break :blk net.IpAddress.parseIp4(self.address, self.port) catch return;
                },
                .ip6 => |ip6| blk: {
                    if (std.mem.eql(u8, &ip6.bytes, &([_]u8{0} ** 16))) {
                        break :blk net.IpAddress.parseIp6("::1", self.port) catch return;
                    }
                    break :blk net.IpAddress.parseIp6(self.address, self.port) catch return;
                },
            };

            var stream = net.IpAddress.connect(&wake_addr, io, .{ .mode = .stream }) catch return;
            stream.close(io);
        }
    };
}

fn requestPath(target: []const u8) []const u8 {
    return if (std.mem.indexOfScalar(u8, target, '?')) |q| target[0..q] else target;
}

fn classifyRequest(method: http.Method, target: []const u8) Route {
    if (!std.mem.eql(u8, requestPath(target), "/metrics")) return .not_found;
    if (method != .GET) return .method_not_allowed;
    return .metrics;
}

fn parseIpAddress(addr: []const u8, port: u16) !net.IpAddress {
    if (net.IpAddress.parseIp4(addr, port)) |ip4| {
        return ip4;
    } else |_| {}
    if (net.IpAddress.parseIp6(addr, port)) |ip6| {
        return ip6;
    } else |_| {}
    return error.InvalidListenAddress;
}

const testing = std.testing;

test "requestPath strips query strings" {
    try testing.expectEqualStrings("/metrics", requestPath("/metrics?foo=bar"));
    try testing.expectEqualStrings("/metrics", requestPath("/metrics"));
}

test "classifyRequest routes metrics endpoint" {
    try testing.expectEqual(Route.metrics, classifyRequest(.GET, "/metrics"));
    try testing.expectEqual(Route.metrics, classifyRequest(.GET, "/metrics?format=prom"));
    try testing.expectEqual(Route.not_found, classifyRequest(.GET, "/health"));
    try testing.expectEqual(Route.method_not_allowed, classifyRequest(.POST, "/metrics"));
}

test "parseIpAddress accepts ipv4 and ipv6" {
    const ip4 = try parseIpAddress("127.0.0.1", 8008);
    try testing.expectEqual(@as(u16, 8008), ip4.getPort());

    const ip6 = try parseIpAddress("::1", 8008);
    try testing.expectEqual(@as(u16, 8008), ip6.getPort());
}

test "parseIpAddress rejects invalid addresses" {
    try testing.expectError(error.InvalidListenAddress, parseIpAddress("not-an-ip", 8008));
}
