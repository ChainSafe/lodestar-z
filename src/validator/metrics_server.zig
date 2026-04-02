//! Simple Prometheus HTTP server for validator metrics.

const std = @import("std");
const http = std.http;
const net = std.Io.net;
const Io = std.Io;
const Allocator = std.mem.Allocator;

const ValidatorMetrics = @import("metrics.zig").ValidatorMetrics;

const log = std.log.scoped(.validator_metrics_server);

pub const MetricsServer = struct {
    pub const StartupStatus = enum(u8) {
        idle,
        started,
        failed,
    };

    allocator: Allocator,
    metrics: *ValidatorMetrics,
    address: []const u8,
    port: u16,
    shutdown_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    startup_status: std.atomic.Value(u8) = std.atomic.Value(u8).init(@intFromEnum(StartupStatus.idle)),
    listener: ?net.Server = null,
    listener_mutex: std.Io.Mutex = .init,

    pub fn init(
        allocator: Allocator,
        metrics: *ValidatorMetrics,
        address: []const u8,
        port: u16,
    ) MetricsServer {
        return .{
            .allocator = allocator,
            .metrics = metrics,
            .address = address,
            .port = port,
        };
    }

    pub fn startupStatus(self: *const MetricsServer) StartupStatus {
        return @enumFromInt(self.startup_status.load(.acquire));
    }

    pub fn shutdown(self: *MetricsServer, io: Io) void {
        self.shutdown_requested.store(true, .release);
        self.listener_mutex.lock(io) catch return;
        defer self.listener_mutex.unlock(io);
        if (self.listener) |*listener| {
            listener.deinit(io);
            self.listener = null;
        }
    }

    pub fn serve(self: *MetricsServer, io: Io) !void {
        const ip = parseIpAddress(self.address, self.port) catch |err| {
            self.startup_status.store(@intFromEnum(StartupStatus.failed), .release);
            return err;
        };
        var tcp_server = ip.listen(io, .{ .reuse_address = true }) catch |err| {
            self.startup_status.store(@intFromEnum(StartupStatus.failed), .release);
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

        self.startup_status.store(@intFromEnum(StartupStatus.started), .release);
        log.info("validator metrics endpoint: http://{s}:{d}/metrics", .{ self.address, self.port });

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

            self.handleConnection(io, stream) catch |err| {
                log.err("connection error: {s}", .{@errorName(err)});
            };
        }
    }

    fn handleConnection(self: *MetricsServer, io: Io, stream: net.Stream) !void {
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

    fn handleHttpRequest(self: *MetricsServer, request: *http.Server.Request) !void {
        const target = request.head.target;
        const path = if (std.mem.indexOfScalar(u8, target, '?')) |q| target[0..q] else target;

        if (!std.mem.eql(u8, path, "/metrics")) {
            try request.respond("Not Found\n", .{
                .status = .not_found,
                .extra_headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
            });
            return;
        }

        if (request.head.method != .GET) {
            try request.respond("Method Not Allowed\n", .{
                .status = .method_not_allowed,
                .extra_headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
            });
            return;
        }

        var body: std.Io.Writer.Allocating = .init(self.allocator);
        defer body.deinit();
        try self.metrics.write(&body.writer);

        try request.respond(body.writer.buffered(), .{
            .status = .ok,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "text/plain; version=0.0.4; charset=utf-8" },
            },
        });
    }
};

fn parseIpAddress(addr: []const u8, port: u16) !net.IpAddress {
    if (net.IpAddress.parseIp4(addr, port)) |ip4| {
        return ip4;
    } else |_| {}
    if (net.IpAddress.parseIp6(addr, port)) |ip6| {
        return ip6;
    } else |_| {}
    return error.InvalidListenAddress;
}
