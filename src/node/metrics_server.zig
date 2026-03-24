//! MetricsServer — simple HTTP server that serves Prometheus metrics.
//!
//! Listens on a configurable port and responds to GET /metrics with
//! the full Prometheus text exposition format output from BeaconMetrics.
//!
//! Non-/metrics paths return 404. Only GET is supported on /metrics.
//!
//! Usage:
//!   var server = MetricsServer.init(allocator, metrics_ptr, port);
//!   try server.serve(io);   // blocking — use Io.Group.async

const std = @import("std");
const http = std.http;
const net = std.Io.net;
const Io = std.Io;
const Allocator = std.mem.Allocator;

const metrics_lib = @import("metrics");
const BeaconMetrics = @import("metrics.zig").BeaconMetrics;

const log = std.log.scoped(.metrics_server);

pub const MetricsServer = struct {
    allocator: Allocator,
    metrics: *BeaconMetrics,
    port: u16,

    pub fn init(allocator: Allocator, metrics: *BeaconMetrics, port: u16) MetricsServer {
        return .{
            .allocator = allocator,
            .metrics = metrics,
            .port = port,
        };
    }

    /// Start serving metrics requests (blocking).
    ///
    /// Listens on 0.0.0.0:<port>. On each request:
    ///   GET /metrics  → 200 text/plain; version=0.0.4 with Prometheus output
    ///   anything else → 404
    pub fn serve(self: *MetricsServer, io: Io) !void {
        const addr = net.IpAddress{ .ip4 = try net.Ip4Address.parse("0.0.0.0", self.port) };
        var tcp_server = try addr.listen(io, .{ .reuse_address = true });
        defer tcp_server.deinit(io);

        log.info("Prometheus metrics endpoint: http://0.0.0.0:{d}/metrics", .{self.port});

        while (true) {
            const stream = tcp_server.accept(io) catch |err| {
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

        // Handle requests on this connection (keep-alive).
        while (true) {
            var request = server.receiveHead() catch |err| switch (err) {
                error.HttpConnectionClosing => return,
                else => {
                    log.err("receive head failed: {s}", .{@errorName(err)});
                    return;
                },
            };
            try self.handleHttpRequest(&request);
        }
    }

    fn handleHttpRequest(self: *MetricsServer, request: *http.Server.Request) !void {
        const target = request.head.target;

        // Strip query string.
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

        // Serialize all metrics into a temporary buffer.
        var body: std.Io.Writer.Allocating = .init(self.allocator);
        defer body.deinit();
        try self.metrics.write(&body.writer);

        const prometheus_headers: []const http.Header = &.{
            .{ .name = "Content-Type", .value = "text/plain; version=0.0.4; charset=utf-8" },
        };

        try request.respond(body.writer.buffered(), .{
            .status = .ok,
            .extra_headers = prometheus_headers,
        });
    }
};
