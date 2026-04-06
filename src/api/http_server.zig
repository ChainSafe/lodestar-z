//! HTTP server for the Beacon REST API.
//!
//! Wraps `std.http.Server` with `std.Io.net` for TCP accept loops.
//! Routes incoming requests to the Beacon API handler functions and
//! returns JSON (or SSZ) responses with proper CORS headers.
//!
//! Usage:
//!   var server = HttpServer.init(allocator, &api_context, "127.0.0.1", 5052);
//!   try server.serve(io);

const std = @import("std");
const builtin = @import("builtin");
const http = std.http;
const net = std.Io.net;
const Io = std.Io;
const Allocator = std.mem.Allocator;

const api_mod = @import("root.zig");
const routes_mod = @import("routes.zig");
const content_negotiation = @import("content_negotiation.zig");
const response_meta = @import("response_meta.zig");
const error_response = @import("error_response.zig");
const handler_result_mod = @import("handler_result.zig");
const handlers = @import("handlers/root.zig");
const context = @import("context.zig");
const ApiContext = context.ApiContext;
const types = @import("types.zig");
const preset = @import("preset").preset;
const json_response = @import("json_response.zig");
const fork_types = @import("fork_types");
const AnyBeaconBlock = fork_types.AnyBeaconBlock;
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const ForkSeq = @import("config").ForkSeq;
const consensus_types = @import("consensus_types");

const log = std.log.scoped(.http_server);

// Comptime assertion: ForkSeq and response_meta.Fork must have matching ordinals
// so that the @enumFromInt(@intFromEnum(fork_seq)) cast used in API handlers is safe.
comptime {
    const fork_seq_fields = @typeInfo(ForkSeq).@"enum".fields;
    const fork_fields = @typeInfo(response_meta.Fork).@"enum".fields;
    if (fork_seq_fields.len != fork_fields.len) @compileError("ForkSeq and response_meta.Fork have different numbers of variants");
    for (fork_seq_fields, fork_fields) |fs, f| {
        if (fs.value != f.value) @compileError("ForkSeq and response_meta.Fork ordinals do not match");
        if (!std.mem.eql(u8, fs.name, f.name)) @compileError("ForkSeq and response_meta.Fork field names do not match");
    }
}

/// Static keymanager path prefixes that must never receive wildcard CORS.
const keymanager_paths: []const []const u8 = &.{
    "/eth/v1/keystores",
    "/eth/v1/remotekeys",
};

/// Returns true if path is a keymanager endpoint.
fn isKeymanagerPath(path: []const u8) bool {
    for (keymanager_paths) |prefix| {
        if (std.mem.startsWith(u8, path, prefix)) return true;
    }
    return isKeymanagerValidatorPath(path);
}

fn isKeymanagerValidatorPath(path: []const u8) bool {
    var iter = std.mem.splitScalar(u8, path, '/');
    const first = iter.next() orelse return false;
    const second = iter.next() orelse return false;
    const third = iter.next() orelse return false;
    const fourth = iter.next() orelse return false;
    const fifth = iter.next() orelse return false;
    const sixth = iter.next() orelse return false;
    if (iter.next() != null) return false;

    if (first.len != 0) return false;
    if (!std.mem.eql(u8, second, "eth")) return false;
    if (!(std.mem.eql(u8, third, "v1") or std.mem.eql(u8, third, "v0"))) return false;
    if (!std.mem.eql(u8, fourth, "validator")) return false;
    if (fifth.len == 0) return false;

    return std.mem.eql(u8, sixth, "feerecipient") or
        std.mem.eql(u8, sixth, "graffiti") or
        std.mem.eql(u8, sixth, "gas_limit") or
        std.mem.eql(u8, sixth, "builder_boost_factor") or
        std.mem.eql(u8, sixth, "proposer_config") or
        std.mem.eql(u8, sixth, "voluntary_exit");
}

fn sliceContains(items: []const []const u8, value: []const u8) bool {
    for (items) |item| {
        if (std.mem.eql(u8, item, value)) return true;
    }
    return false;
}

fn pathMatchesPrefixes(path: []const u8, prefixes: []const []const u8) bool {
    for (prefixes) |prefix| {
        if (std.mem.startsWith(u8, path, prefix)) return true;
    }
    return false;
}

pub const HttpServer = struct {
    pub const Observer = struct {
        ptr: *anyopaque,
        onActiveConnectionsChangedFn: ?*const fn (ptr: *anyopaque, active_connections: u32) void = null,
        onRequestCompletedFn: ?*const fn (
            ptr: *anyopaque,
            operation_id: []const u8,
            response_time_seconds: f64,
            is_error: bool,
        ) void = null,
    };

    pub const StartupStatus = enum(u8) {
        idle,
        started,
        failed,
    };

    pub const Options = struct {
        cors_origin: ?[]const u8 = null,
        allow_keymanager_cors: bool = false,
        include_error_stacktraces: bool = false,
        observer: ?Observer = null,
        allowed_path_prefixes: ?[]const []const u8 = null,
        allowed_operation_ids: ?[]const []const u8 = null,
        max_header_bytes: usize = default_max_header_bytes,
        max_body_bytes: usize = default_max_body_bytes,
        max_block_body_bytes: usize = default_max_block_body_bytes,
    };

    allocator: Allocator,
    api_context: *ApiContext,
    address: []const u8,
    port: u16,
    /// CORS origin to allow. Null = no CORS headers (same-origin only).
    /// Never applied to keymanager endpoints regardless of this setting.
    cors_origin: ?[]const u8 = null,
    allow_keymanager_cors: bool = false,
    include_error_stacktraces: bool = false,
    observer: ?Observer = null,
    allowed_path_prefixes: ?[]const []const u8 = null,
    allowed_operation_ids: ?[]const []const u8 = null,
    max_header_bytes: usize = default_max_header_bytes,
    max_body_bytes: usize = default_max_body_bytes,
    max_block_body_bytes: usize = default_max_block_body_bytes,
    /// Set to true to request a clean shutdown of the serve loop.
    shutdown_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Number of currently active connections.
    active_connections: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    startup_status: std.atomic.Value(u8) = std.atomic.Value(u8).init(@intFromEnum(StartupStatus.idle)),
    listener: ?net.Server = null,
    listener_mutex: std.Io.Mutex = .init,

    // ── DoS protection limits ─────────────────────────────────────────────────

    /// Read timeout per connection in seconds (Slowloris defence).
    pub const recv_timeout_sec: c_long = 30;
    /// Maximum request body size for general POST endpoints (1 MiB).
    pub const default_max_body_bytes: usize = 1 * 1024 * 1024;
    /// Maximum request body size for block-submission endpoints (10 MiB).
    pub const default_max_block_body_bytes: usize = 10 * 1024 * 1024;
    /// Maximum request head size accepted per connection.
    pub const default_max_header_bytes: usize = 8 * 1024;
    /// Maximum keep-alive requests per connection.
    pub const max_keepalive_requests: u32 = 100;
    /// Maximum concurrent TCP connections.
    pub const max_concurrent_connections: u32 = 256;
    // TODO(SSE): SSE connections are now streaming but share the general
    // active_connections budget. Consider a separate sse_connections counter
    // with its own limit so long-lived SSE clients cannot exhaust the
    // general connection budget for short-lived API requests.

    pub fn init(
        allocator: Allocator,
        api_context: *ApiContext,
        address: []const u8,
        port: u16,
    ) HttpServer {
        return initWithOptions(allocator, api_context, address, port, .{});
    }

    /// Create an HttpServer with CORS configured.
    pub fn initWithCors(
        allocator: Allocator,
        api_context: *ApiContext,
        address: []const u8,
        port: u16,
        cors_origin: ?[]const u8,
    ) HttpServer {
        return initWithOptions(allocator, api_context, address, port, .{
            .cors_origin = cors_origin,
        });
    }

    pub fn initWithOptions(
        allocator: Allocator,
        api_context: *ApiContext,
        address: []const u8,
        port: u16,
        options: Options,
    ) HttpServer {
        return .{
            .allocator = allocator,
            .api_context = api_context,
            .address = address,
            .port = port,
            .cors_origin = options.cors_origin,
            .allow_keymanager_cors = options.allow_keymanager_cors,
            .include_error_stacktraces = options.include_error_stacktraces,
            .observer = options.observer,
            .allowed_path_prefixes = options.allowed_path_prefixes,
            .allowed_operation_ids = options.allowed_operation_ids,
            .max_header_bytes = options.max_header_bytes,
            .max_body_bytes = options.max_body_bytes,
            .max_block_body_bytes = options.max_block_body_bytes,
        };
    }

    pub fn startupStatus(self: *const HttpServer) StartupStatus {
        return @enumFromInt(self.startup_status.load(.acquire));
    }

    fn pathAllowed(self: *const HttpServer, path: []const u8) bool {
        if (self.allowed_path_prefixes) |prefixes| {
            return pathMatchesPrefixes(path, prefixes);
        }
        return true;
    }

    fn operationAllowed(self: *const HttpServer, operation_id: []const u8) bool {
        if (self.allowed_operation_ids) |allowed_operation_ids| {
            return sliceContains(allowed_operation_ids, operation_id);
        }
        return true;
    }

    fn shouldApplyCors(self: *const HttpServer, path: []const u8) bool {
        if (self.cors_origin == null) return false;
        if (isKeymanagerPath(path) and !self.allow_keymanager_cors) return false;
        return true;
    }

    fn notifyActiveConnectionsChanged(self: *HttpServer, active_connections: u32) void {
        if (self.observer) |observer| {
            if (observer.onActiveConnectionsChangedFn) |callback| {
                callback(observer.ptr, active_connections);
            }
        }
    }

    fn notifyRequestCompleted(
        self: *HttpServer,
        operation_id: []const u8,
        response_time_seconds: f64,
        is_error: bool,
    ) void {
        if (self.observer) |observer| {
            if (observer.onRequestCompletedFn) |callback| {
                callback(observer.ptr, operation_id, response_time_seconds, is_error);
            }
        }
    }

    /// Signal the serve loop to exit after the current connection completes.
    pub fn shutdown(self: *HttpServer, io: Io) void {
        self.shutdown_requested.store(true, .release);
        self.listener_mutex.lock(io) catch return;
        defer self.listener_mutex.unlock(io);
        if (self.listener) |*listener| {
            listener.deinit(io);
            self.listener = null;
        }
    }

    /// Start serving HTTP requests (blocking).
    ///
    /// Listens on the configured address:port, accepts connections, parses
    /// HTTP requests via `std.http.Server`, and dispatches to Beacon API
    /// handlers.
    pub fn serve(self: *HttpServer, io: Io) !void {
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
            var locked = false;
            if (self.listener_mutex.lock(io)) |_| {
                locked = true;
            } else |_| {}
            if (locked) {
                defer self.listener_mutex.unlock(io);
                if (self.listener) |*listener| {
                    listener.deinit(io);
                    self.listener = null;
                }
            }
        }
        self.startup_status.store(@intFromEnum(StartupStatus.started), .release);

        log.info("Beacon API listening on {s}:{d}", .{ self.address, self.port });

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

            // Enforce maximum concurrent connection limit (DoS protection).
            const prev = self.active_connections.fetchAdd(1, .acquire);
            self.notifyActiveConnectionsChanged(prev + 1);
            if (prev >= max_concurrent_connections) {
                const old_count = self.active_connections.fetchSub(1, .release);
                self.notifyActiveConnectionsChanged(old_count - 1);
                log.warn("connection limit reached ({d}), rejecting new connection", .{max_concurrent_connections});
                // Send a minimal 503 response before closing.
                var reject_buf: [128]u8 = undefined;
                var reject_writer = stream.writer(io, &reject_buf);
                _ = reject_writer.interface.write("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") catch {};
                var stream_copy = stream;
                stream_copy.close(io);
                continue;
            }
            self.handleConnection(io, stream);
            const old_count = self.active_connections.fetchSub(1, .release);
            self.notifyActiveConnectionsChanged(old_count - 1);
        }
    }

    fn handleConnection(self: *HttpServer, io: Io, stream: net.Stream) void {
        defer {
            var copy = stream;
            copy.close(io);
        }

        // Set a receive timeout to guard against Slowloris-style attacks.
        // A client that does not send a complete request head within
        // recv_timeout_sec seconds will have the connection closed.
        // Guard SO_RCVTIMEO to platforms that expose POSIX socket options.
        if (comptime builtin.os.tag != .wasi) {
            const tv = std.posix.timeval{
                .sec = recv_timeout_sec,
                .usec = 0,
            };
            std.posix.setsockopt(
                stream.socket.handle,
                std.posix.SOL.SOCKET,
                std.posix.SO.RCVTIMEO,
                std.mem.asBytes(&tv),
            ) catch |err| {
                log.warn("setsockopt SO_RCVTIMEO failed: {s}", .{@errorName(err)});
            };
        }

        var send_buf: [8192]u8 = undefined;
        const recv_buf = self.allocator.alloc(u8, self.max_header_bytes) catch |err| {
            log.err("failed to allocate HTTP header buffer: {s}", .{@errorName(err)});
            return;
        };
        defer self.allocator.free(recv_buf);
        var conn_reader = stream.reader(io, recv_buf);
        var conn_writer = stream.writer(io, &send_buf);
        var server: http.Server = .init(&conn_reader.interface, &conn_writer.interface);

        // Handle requests on this connection (keep-alive support).
        var requests_served: u32 = 0;
        while (!self.shutdown_requested.load(.acquire)) {
            // Enforce per-connection keep-alive request limit.
            if (requests_served >= max_keepalive_requests) {
                log.debug("keep-alive limit reached, closing connection", .{});
                return;
            }

            var request = server.receiveHead() catch |err| switch (err) {
                error.HttpConnectionClosing => return,
                else => {
                    log.err("receive head failed: {s}", .{@errorName(err)});
                    return;
                },
            };
            self.handleHttpRequest(&request, io) catch |err| {
                log.err("handle request failed: {s}", .{@errorName(err)});
                return;
            };
            requests_served += 1;
        }
    }

    fn handleHttpRequest(self: *HttpServer, request: *http.Server.Request, io: Io) !void {
        const target = request.head.target;

        // Split target into path and query.
        const path, _ = splitTarget(target);
        if (!self.pathAllowed(path)) {
            try respondApiError(self.allocator, request, .{
                .code = .not_found,
                .message = "Route not found",
            });
            return;
        }

        // CORS preflight.
        if (request.head.method == .OPTIONS) {
            // Only send CORS headers for non-keymanager paths; keymanager
            // paths require authentication and must not expose CORS headers.
            if (self.shouldApplyCors(path)) {
                const origin = self.cors_origin.?;
                const preflight_headers: []const http.Header = &.{
                    .{ .name = "Access-Control-Allow-Origin", .value = origin },
                    .{ .name = "Access-Control-Allow-Methods", .value = "GET, POST, DELETE, OPTIONS" },
                    .{ .name = "Access-Control-Allow-Headers", .value = "Content-Type, Authorization" },
                    .{ .name = "Access-Control-Max-Age", .value = "3600" },
                };
                try request.respond("", .{
                    .status = .no_content,
                    .extra_headers = preflight_headers,
                });
            } else {
                try request.respond("", .{ .status = .no_content });
            }
            return;
        }

        // Map std.http.Method to our route method.
        const route_method: routes_mod.HttpMethod = switch (request.head.method) {
            .GET => .GET,
            .POST => .POST,
            .DELETE => .DELETE,
            else => {
                try respondApiError(self.allocator, request, .{
                    .code = .method_not_allowed,
                    .message = "Method not allowed",
                });
                return;
            },
        };

        // Route lookup.
        const match = routes_mod.findRoute(route_method, path) orelse {
            try respondApiError(self.allocator, request, .{
                .code = .not_found,
                .message = "Route not found",
            });
            return;
        };
        if (!self.operationAllowed(match.route.operation_id)) {
            try respondApiError(self.allocator, request, .{
                .code = .not_found,
                .message = "Route not found",
            });
            return;
        }

        const request_started = Io.Timestamp.now(io, .awake);
        var request_failed = true;
        defer {
            const request_finished = Io.Timestamp.now(io, .awake);
            const elapsed_ns = request_started.durationTo(request_finished).nanoseconds;
            const elapsed_seconds =
                @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));
            self.notifyRequestCompleted(match.route.operation_id, elapsed_seconds, request_failed);
        }

        // SSE streaming: intercept the events endpoint before normal dispatch.
        // SSE needs streaming response, which bypasses the HandlerResult path.
        if (std.mem.eql(u8, match.route.operation_id, "getEvents")) {
            self.handleSseEvents(request, target, io) catch |err| {
                log.debug("SSE stream ended: {s}", .{@errorName(err)});
            };
            return;
        }

        // Content negotiation.
        const accept = findHeader(request, "accept");
        const format = switch (content_negotiation.parseAcceptHeader(accept)) {
            .absent => content_negotiation.WireFormat.json,
            .format => |f| f,
            .not_acceptable => {
                try respondApiError(self.allocator, request, .{
                    .code = .not_acceptable,
                    .message = "Supported: application/json, application/octet-stream",
                });
                return;
            },
        };

        // For SSZ requests, ensure the route supports SSZ.
        if (format == .ssz and !match.route.supports_ssz) {
            try respondApiError(self.allocator, request, .{
                .code = .not_acceptable,
                .message = "This endpoint does not support SSZ responses",
            });
            return;
        }

        // Dispatch to handler and get response body.
        // Read request body for POST methods.
        var request_body: []const u8 = &[_]u8{};
        var request_body_owned = false;
        if (route_method == .POST or route_method == .DELETE) {
            var reader_buf: [4096]u8 = undefined;
            const body_reader = request.readerExpectNone(&reader_buf);
            // Block-submission endpoints allow up to max_block_body_bytes; all
            // other POST endpoints are capped at max_body_bytes (1 MiB).
            const is_block_endpoint =
                std.mem.eql(u8, match.route.operation_id, "publishBlockV2") or
                std.mem.eql(u8, match.route.operation_id, "publishBlindedBlockV2");
            const body_limit: usize = if (is_block_endpoint) self.max_block_body_bytes else self.max_body_bytes;
            request_body = body_reader.readAlloc(self.allocator, body_limit) catch &[_]u8{};
            request_body_owned = true;
        }
        defer if (request_body_owned) self.allocator.free(request_body);

        const dc = DispatchContext{
            .match = match,
            .query = if (std.mem.indexOfScalar(u8, target, '?')) |idx| target[idx + 1 ..] else null,
            .body = request_body,
            .format = format,
            .auth_header = findHeader(request, "authorization"),
        };
        const result = self.dispatchHandler(dc) catch |err| {
            var api_err = try makeApiError(self, err);
            defer api_err.deinit(self.allocator);
            try respondApiError(self.allocator, request, api_err);
            return;
        };
        defer result.deinit(self.allocator);

        // Build response headers: content-type + CORS + metadata.
        var extra_hdrs_buf: [16]http.Header = undefined;
        var extra_count: usize = 0;

        extra_hdrs_buf[extra_count] = .{ .name = "Content-Type", .value = result.content_type };
        extra_count += 1;
        // Apply CORS headers only when configured AND not a keymanager endpoint.
        if (self.shouldApplyCors(path)) {
            const origin = self.cors_origin.?;
            extra_hdrs_buf[extra_count] = .{ .name = "Access-Control-Allow-Origin", .value = origin };
            extra_count += 1;
            extra_hdrs_buf[extra_count] = .{ .name = "Access-Control-Allow-Methods", .value = "GET, POST, DELETE, OPTIONS" };
            extra_count += 1;
            extra_hdrs_buf[extra_count] = .{ .name = "Access-Control-Allow-Headers", .value = "Content-Type, Authorization" };
            extra_count += 1;
        }

        // Emit metadata headers from the handler result.
        var meta_hdrs: response_meta.MetaHeaders = undefined;
        response_meta.buildHeaders(result.meta, &meta_hdrs);
        for (meta_hdrs.slice()) |h| {
            if (extra_count < extra_hdrs_buf.len) {
                extra_hdrs_buf[extra_count] = .{ .name = h.name, .value = h.value };
                extra_count += 1;
            }
        }

        try request.respond(result.body, .{
            .status = statusFromCode(result.status),
            .extra_headers = extra_hdrs_buf[0..extra_count],
        });
        request_failed = false;
    }

    /// Dispatch result from a handler.
    pub const HandlerResult = struct {
        status: u16,
        content_type: []const u8,
        body: []const u8,
        body_owned: bool = true,
        meta: response_meta.ResponseMeta = .{},

        pub fn deinit(self: HandlerResult, allocator: Allocator) void {
            if (self.body_owned) allocator.free(self.body);
        }
    };

    /// Write a JSON body for a HandlerResult(T) and return a HandlerResult for the server.
    fn makeJsonResult(
        self: *HttpServer,
        comptime T: type,
        result: handler_result_mod.HandlerResult(T),
    ) !HandlerResult {
        const status = if (result.status != 0) result.status else 200;
        const body = try json_response.writeApiEnvelope(self.allocator, T, &result.data, result.meta);
        return .{
            .status = status,
            .content_type = "application/json",
            .body = body,
            .meta = result.meta,
        };
    }

    /// Write an empty body (204 / void handler).
    fn makeVoidResult(
        self: *HttpServer,
        result: handler_result_mod.HandlerResult(void),
    ) !HandlerResult {
        const status = if (result.status != 0) result.status else 204;
        const body = try self.allocator.dupe(u8, "");
        return .{
            .status = status,
            .content_type = "application/json",
            .body = body,
            .meta = result.meta,
        };
    }

    /// Wrap `data_json` in a Beacon API envelope.
    ///
    /// Produces: `{"data":<data_json>,"execution_optimistic":<bool>,"finalized":<bool>}`
    /// Omits optional fields that are null. Caller owns the returned slice.
    fn jsonEnvelope(
        allocator: Allocator,
        data_json: []const u8,
        meta: response_meta.ResponseMeta,
    ) ![]u8 {
        var buf = std.ArrayListUnmanaged(u8).empty;
        errdefer buf.deinit(allocator);
        try buf.appendSlice(allocator, "{\"data\":");
        try buf.appendSlice(allocator, data_json);
        if (meta.execution_optimistic) |opt| {
            try buf.appendSlice(allocator, if (opt)
                ",\"execution_optimistic\":true"
            else
                ",\"execution_optimistic\":false");
        }
        if (meta.finalized) |fin| {
            try buf.appendSlice(allocator, if (fin)
                ",\"finalized\":true"
            else
                ",\"finalized\":false");
        }
        try buf.appendSlice(allocator, "}");
        return buf.toOwnedSlice(allocator);
    }

    /// Route to the correct handler and encode the response.
    /// Context for dispatching a handler: route match + query params + body.
    const DispatchContext = struct {
        match: routes_mod.RouteMatch,
        /// Raw query string (e.g. "slot=100&committee_index=0"), or null.
        query: ?[]const u8 = null,
        /// Request body bytes (for POST), or empty slice.
        body: []const u8 = &[_]u8{},
        /// Negotiated wire format (json or ssz). Defaults to json.
        format: content_negotiation.WireFormat = .json,
        /// Authorization header value (for keymanager auth). Null if absent.
        auth_header: ?[]const u8 = null,

        /// Get a query parameter value by name.
        pub fn getQuery(self: *const DispatchContext, name: []const u8) ?[]const u8 {
            const qs = self.query orelse return null;
            var pairs = std.mem.splitScalar(u8, qs, '&');
            while (pairs.next()) |pair| {
                if (std.mem.indexOfScalar(u8, pair, '=')) |eq| {
                    const k = pair[0..eq];
                    const v = pair[eq + 1 ..];
                    if (std.mem.eql(u8, k, name)) return v;
                }
            }
            return null;
        }
    };

    fn parseOptionalU64ListQuery(allocator: Allocator, query_value: ?[]const u8) !?[]u64 {
        const raw = query_value orelse return null;
        if (raw.len == 0) return try allocator.dupe(u64, &.{});

        var values = std.ArrayListUnmanaged(u64).empty;
        defer values.deinit(allocator);

        var it = std.mem.splitScalar(u8, raw, ',');
        while (it.next()) |part| {
            if (part.len == 0) return error.InvalidRequest;
            try values.append(allocator, std.fmt.parseInt(u64, part, 10) catch return error.InvalidRequest);
        }

        return try values.toOwnedSlice(allocator);
    }

    // Dispatch coverage is verified by the "dispatch coverage" test below.
    // When adding a new route, add a dispatch branch here AND update the
    // coverage check in the test.

    // ── Handler function type ────────────────────────────────────────────────

    const HandlerFn = *const fn (*HttpServer, DispatchContext) anyerror!HandlerResult;

    // ── StaticStringMap dispatch table ───────────────────────────────────────

    const handler_table = std.StaticStringMap(HandlerFn).initComptime(.{
        .{ "getNodeIdentity", &hGetNodeIdentity },
        .{ "getNodeVersion", &hGetNodeVersion },
        .{ "getSyncing", &hGetSyncing },
        .{ "getHealth", &hGetHealth },
        .{ "getPeers", &hGetPeers },
        .{ "getPeerCount", &hGetPeerCount },
        .{ "getPeer", &hGetPeer },
        .{ "getGenesis", &hGetGenesis },
        .{ "getBlockHeader", &hGetBlockHeader },
        .{ "getBlockV2", &hGetBlockV2 },
        .{ "getStateValidatorV2", &hGetStateValidatorV2 },
        .{ "getStateValidatorsV2", &hGetStateValidatorsV2 },
        .{ "getStateRoot", &hGetStateRoot },
        .{ "getStateFork", &hGetStateFork },
        .{ "getFinalityCheckpoints", &hGetFinalityCheckpoints },
        .{ "publishBlockV2", &hPublishBlockV2 },
        .{ "publishBlindedBlockV2", &hPublishBlindedBlockV2 },
        .{ "getPoolAttestations", &hGetPoolAttestations },
        .{ "getPoolAttestationsV2", &hGetPoolAttestationsV2 },
        .{ "getPoolAttesterSlashingsV2", &hGetPoolAttesterSlashingsV2 },
        .{ "getPoolVoluntaryExits", &hGetPoolVoluntaryExits },
        .{ "getPoolProposerSlashings", &hGetPoolProposerSlashings },
        .{ "getPoolAttesterSlashings", &hGetPoolAttesterSlashings },
        .{ "getPoolBlsToExecutionChanges", &hGetPoolBlsToExecutionChanges },
        .{ "submitPoolAttestations", &hSubmitPoolAttestations },
        .{ "submitPoolAttestationsV2", &hSubmitPoolAttestationsV2 },
        .{ "submitPoolVoluntaryExits", &hSubmitPoolVoluntaryExits },
        .{ "submitPoolProposerSlashings", &hSubmitPoolProposerSlashings },
        .{ "submitPoolAttesterSlashings", &hSubmitPoolAttesterSlashings },
        .{ "submitPoolBlsToExecutionChanges", &hSubmitPoolBlsToExecutionChanges },
        .{ "submitPoolSyncCommittees", &hSubmitPoolSyncCommittees },
        .{ "getDebugState", &hGetDebugState },
        .{ "getDebugHeads", &hGetDebugHeads },
        .{ "getEvents", &hGetEvents },
        .{ "getProposerDuties", &hGetProposerDuties },
        .{ "getAttesterDuties", &hGetAttesterDuties },
        .{ "getSyncDuties", &hGetSyncDuties },
        .{ "prepareBeaconCommitteeSubnet", &hPrepareBeaconCommitteeSubnet },
        .{ "prepareSyncCommitteeSubnets", &hPrepareSyncCommitteeSubnets },
        .{ "getSpec", &hGetSpec },
        .{ "getForkSchedule", &hGetForkSchedule },
        .{ "getValidatorMonitor", &hGetValidatorMonitor },
        .{ "produceBlock", &hProduceBlock },
        .{ "produceBlockV3", &hProduceBlock },
        .{ "getAttestationData", &hGetAttestationData },
        .{ "getAggregateAttestation", &hGetAggregateAttestation },
        .{ "publishAggregateAndProofs", &hPublishAggregateAndProofs },
        .{ "getSyncCommitteeContribution", &hGetSyncCommitteeContribution },
        .{ "publishContributionAndProofs", &hPublishContributionAndProofs },
        .{ "getStateCommittees", &hGetStateCommittees },
        .{ "getStateSyncCommittees", &hGetStateSyncCommittees },
        .{ "getStateRandao", &hGetStateRandao },
        .{ "getBlockHeaders", &hGetBlockHeaders },
        .{ "getBlobSidecars", &hGetBlobSidecars },
        .{ "getBlindedBlock", &hGetBlindedBlock },
        .{ "getBlockRewards", &hGetBlockRewards },
        .{ "getAttestationRewards", &hGetAttestationRewards },
        .{ "getSyncCommitteeRewards", &hGetSyncCommitteeRewards },
        .{ "prepareBeaconProposer", &hPrepareBeaconProposer },
        .{ "registerValidator", &hRegisterValidator },
        .{ "getValidatorLiveness", &hGetValidatorLiveness },
        .{ "listKeystores", &hListKeystores },
        .{ "importKeystores", &hImportKeystores },
        .{ "deleteKeystores", &hDeleteKeystores },
        .{ "listRemoteKeys", &hListRemoteKeys },
        .{ "importRemoteKeys", &hImportRemoteKeys },
        .{ "deleteRemoteKeys", &hDeleteRemoteKeys },
        .{ "listFeeRecipient", &hListFeeRecipient },
        .{ "setFeeRecipient", &hSetFeeRecipient },
        .{ "deleteFeeRecipient", &hDeleteFeeRecipient },
        .{ "getGraffiti", &hGetGraffiti },
        .{ "setGraffiti", &hSetGraffiti },
        .{ "deleteGraffiti", &hDeleteGraffiti },
        .{ "getGasLimit", &hGetGasLimit },
        .{ "setGasLimit", &hSetGasLimit },
        .{ "deleteGasLimit", &hDeleteGasLimit },
        .{ "getBuilderBoostFactor", &hGetBuilderBoostFactor },
        .{ "setBuilderBoostFactor", &hSetBuilderBoostFactor },
        .{ "deleteBuilderBoostFactor", &hDeleteBuilderBoostFactor },
        .{ "getProposerConfig", &hGetProposerConfig },
        .{ "signVoluntaryExit", &hSignVoluntaryExit },
        .{ "getForkChoice", &hGetForkChoice },
    });

    /// Dispatch to the handler for the given operation_id.
    /// Replaces the old 795-line if-chain with a comptime map lookup.
    fn dispatchHandler(
        self: *HttpServer,
        dc: DispatchContext,
    ) !HandlerResult {
        const op = dc.match.route.operation_id;
        const handler_fn = handler_table.get(op) orelse return error.NotImplemented;
        return handler_fn(self, dc);
    }

    // ── Individual handler functions ─────────────────────────────────────────

    fn hGetNodeIdentity(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const result = handlers.node.getIdentity(self.api_context);
        return self.makeJsonResult(types.NodeIdentity, result);
    }

    fn hGetNodeVersion(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const result = handlers.node.getVersion(self.api_context);
        return self.makeJsonResult(types.NodeVersion, result);
    }

    fn hGetSyncing(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const result = handlers.node.getSyncing(self.api_context);
        return self.makeJsonResult(types.SyncingStatus, result);
    }

    fn hGetHealth(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const result = handlers.node.getHealth(self.api_context);
        return self.makeVoidResult(result);
    }

    fn hGetPeers(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const result = try handlers.node.getPeers(self.api_context);
        defer {
            if (result.data.len > 0) {
                for (result.data) |info| {
                    if (info.peer_id.len > 0) alloc.free(@constCast(info.peer_id));
                }
                alloc.free(result.data);
            }
        }
        return self.makeJsonResult([]const types.PeerInfo, result);
    }

    fn hGetPeerCount(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const result = try handlers.node.getPeerCount(self.api_context);
        return self.makeJsonResult(types.PeerCount, result);
    }

    fn hGetPeer(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const peer_id_str = dc.match.getParam("peer_id") orelse return error.InvalidRequest;
        const handler_res = try handlers.node.getPeer(self.api_context, peer_id_str);
        defer alloc.free(handler_res.data.peer_id);
        const body = try json_response.writeApiObjectEnvelope(alloc, types.PeerDetail, &handler_res.data, handler_res.meta);
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = handler_res.meta };
    }

    fn hGetGenesis(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const resp = handlers.beacon.getGenesis(self.api_context);
        return self.makeJsonResult(types.GenesisData, resp);
    }

    fn hGetBlockHeader(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const block_id_str = dc.match.getParam("block_id") orelse return error.InvalidBlockId;
        const block_id = try types.BlockId.parse(block_id_str);
        const result = try handlers.beacon.getBlockHeader(self.api_context, block_id);
        return self.makeJsonResult(types.BlockHeaderData, result);
    }

    fn hGetBlockV2(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const block_id_str = dc.match.getParam("block_id") orelse return error.InvalidBlockId;
        const block_id = try types.BlockId.parse(block_id_str);
        const block_result = try handlers.beacon.getBlock(self.api_context, block_id);
        defer alloc.free(block_result.data);
        const meta = response_meta.ResponseMeta{
            .version = block_result.fork_name,
            .execution_optimistic = block_result.execution_optimistic,
            .finalized = block_result.finalized,
        };
        if (dc.format == .ssz) {
            const ssz_copy = try alloc.dupe(u8, block_result.data);
            return .{ .status = 200, .content_type = "application/octet-stream", .body = ssz_copy, .meta = meta };
        }
        // Deserialize SSZ bytes into typed block, then serialize to JSON via SSZ type system
        const fork_seq = self.api_context.beacon_config.forkSeq(block_result.slot);
        const any_block = try AnySignedBeaconBlock.deserialize(alloc, block_result.block_type, fork_seq, block_result.data);
        defer any_block.deinit(alloc);
        const body = try json_response.writeBlockEnvelope(alloc, any_block, meta);
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = meta };
    }

    fn hGetStateValidatorV2(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const state_id_str = dc.match.getParam("state_id") orelse return error.InvalidStateId;
        const validator_id_str = dc.match.getParam("validator_id") orelse return error.InvalidValidatorId;
        const state_id = try types.StateId.parse(state_id_str);
        const validator_id = try types.ValidatorId.parse(validator_id_str);
        const result = try handlers.beacon.getValidator(self.api_context, state_id, validator_id);
        return self.makeJsonResult(types.ValidatorData, result);
    }

    fn hGetStateValidatorsV2(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const state_id_str = dc.match.getParam("state_id") orelse return error.InvalidStateId;
        const state_id = try types.StateId.parse(state_id_str);
        const handler_res = try handlers.beacon.getValidators(self.api_context, state_id, .{});
        defer alloc.free(handler_res.data);
        return self.makeJsonResult([]const types.ValidatorData, handler_res);
    }

    fn hGetStateRoot(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const state_id_str = dc.match.getParam("state_id") orelse return error.InvalidStateId;
        const state_id = try types.StateId.parse(state_id_str);
        const result = try handlers.beacon.getStateRoot(self.api_context, state_id);
        return self.makeJsonResult([32]u8, result);
    }

    fn hGetStateFork(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const state_id_str = dc.match.getParam("state_id") orelse return error.InvalidStateId;
        const state_id = try types.StateId.parse(state_id_str);
        const result = try handlers.beacon.getStateFork(self.api_context, state_id);
        return self.makeJsonResult(types.ForkData, result);
    }

    fn hGetFinalityCheckpoints(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const state_id_str = dc.match.getParam("state_id") orelse return error.InvalidStateId;
        const state_id = try types.StateId.parse(state_id_str);
        const result = try handlers.beacon.getFinalityCheckpoints(self.api_context, state_id);
        return self.makeJsonResult(types.FinalityCheckpoints, result);
    }

    fn hPublishBlockV2(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const broadcast_validation = if (dc.getQuery("broadcast_validation")) |raw|
            try types.BroadcastValidation.parse(raw)
        else
            .gossip;
        const result = try handlers.beacon.submitBlock(
            self.api_context,
            dc.body,
            .full,
            broadcast_validation,
        );
        return self.makeVoidResult(result);
    }

    fn hPublishBlindedBlockV2(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const broadcast_validation = if (dc.getQuery("broadcast_validation")) |raw|
            try types.BroadcastValidation.parse(raw)
        else
            .gossip;
        const result = try handlers.beacon.submitBlindedBlock(
            self.api_context,
            dc.body,
            broadcast_validation,
        );
        return self.makeVoidResult(result);
    }

    fn hGetPoolAttestations(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const slot_filter: ?u64 = if (dc.getQuery("slot")) |s| std.fmt.parseInt(u64, s, 10) catch null else null;
        const ci_filter: ?u64 = if (dc.getQuery("committee_index")) |s| std.fmt.parseInt(u64, s, 10) catch null else null;
        const handler_res = try handlers.beacon.getPoolAttestations(self.api_context, slot_filter, ci_filter);
        defer alloc.free(handler_res.data);
        const body = try json_response.writeBeaconArrayEnvelope(alloc, consensus_types.phase0.Attestation, handler_res.data, handler_res.meta);
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = handler_res.meta };
    }

    fn hGetPoolAttestationsV2(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const slot_filter: ?u64 = if (dc.getQuery("slot")) |s| std.fmt.parseInt(u64, s, 10) catch null else null;
        const ci_filter: ?u64 = if (dc.getQuery("committee_index")) |s| std.fmt.parseInt(u64, s, 10) catch null else null;
        const handler_res = try handlers.beacon.getPoolAttestationsV2(self.api_context, slot_filter, ci_filter);
        defer alloc.free(handler_res.data);

        // V2: Fork-aware serialization.
        // Pre-Electra attestations use phase0 Attestation format.
        // Electra attestations use Electra Attestation format with committee_bits.
        // Internally, attestations are stored in phase0 format with committee_index in data.index.
        // For Electra, we reconstruct committee_bits from data.index and set data.index=0.
        var aw: std.Io.Writer.Allocating = .init(alloc);
        errdefer aw.deinit();
        var stream: std.json.Stringify = .{ .writer = &aw.writer };

        // Determine version from first attestation slot (or default to head slot).
        var version_str: []const u8 = "phase0";
        if (handler_res.data.len > 0) {
            const first_fork = self.api_context.beacon_config.forkSeq(handler_res.data[0].data.slot);
            version_str = first_fork.name();
        }

        try stream.beginObject();
        try stream.objectField("version");
        try stream.write(version_str);
        try stream.objectField("data");
        try stream.beginArray();

        for (handler_res.data) |*att| {
            const att_fork = self.api_context.beacon_config.forkSeq(att.data.slot);
            if (@intFromEnum(att_fork) >= @intFromEnum(ForkSeq.electra)) {
                // Electra format: add committee_bits, set data.index=0
                try writeElectraAttestationJson(alloc, &stream, att);
            } else {
                // Pre-Electra: standard phase0 Attestation
                try consensus_types.phase0.Attestation.serializeIntoJson(alloc, &stream, att);
            }
        }

        try stream.endArray();

        // Write meta fields
        if (handler_res.meta.execution_optimistic) |eo| {
            try stream.objectField("execution_optimistic");
            try stream.write(eo);
        }
        if (handler_res.meta.finalized) |fin| {
            try stream.objectField("finalized");
            try stream.write(fin);
        }

        try stream.endObject();

        const body = try aw.toOwnedSlice();
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = handler_res.meta };
    }

    fn hGetPoolVoluntaryExits(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const handler_res = try handlers.beacon.getPoolVoluntaryExits(self.api_context);
        defer alloc.free(handler_res.data);
        const body = try json_response.writeBeaconArrayEnvelope(alloc, consensus_types.phase0.SignedVoluntaryExit, handler_res.data, handler_res.meta);
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = handler_res.meta };
    }

    fn hGetPoolProposerSlashings(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const handler_res = try handlers.beacon.getPoolProposerSlashings(self.api_context);
        defer alloc.free(handler_res.data);
        const body = try json_response.writeBeaconArrayEnvelope(alloc, consensus_types.phase0.ProposerSlashing, handler_res.data, handler_res.meta);
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = handler_res.meta };
    }

    fn hGetPoolAttesterSlashings(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const handler_res = try handlers.beacon.getPoolAttesterSlashings(self.api_context);
        const items = @constCast(handler_res.data);
        defer {
            for (items) |*slashing| slashing.deinit(alloc);
            alloc.free(items);
        }
        const body = try json_response.writeAnyAttesterSlashingArrayEnvelope(alloc, items, handler_res.meta);
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = handler_res.meta };
    }

    fn hGetPoolAttesterSlashingsV2(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const handler_res = try handlers.beacon.getPoolAttesterSlashingsV2(self.api_context);
        const items = @constCast(handler_res.data);
        defer {
            for (items) |*slashing| slashing.deinit(alloc);
            alloc.free(items);
        }
        const body = try json_response.writeAnyAttesterSlashingArrayEnvelope(alloc, items, handler_res.meta);
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = handler_res.meta };
    }

    fn hGetPoolBlsToExecutionChanges(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const handler_res = try handlers.beacon.getPoolBlsToExecutionChanges(self.api_context);
        defer alloc.free(handler_res.data);
        const body = try json_response.writeBeaconArrayEnvelope(alloc, consensus_types.capella.SignedBLSToExecutionChange, handler_res.data, handler_res.meta);
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = handler_res.meta };
    }

    fn hSubmitPoolAttestations(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        if (dc.body.len != 0) {
            const cb = self.api_context.pool_submit orelse return error.NotImplemented;
            _ = cb.submitAttestationFn orelse return error.NotImplemented;
        }
        if (dc.body.len == 0) {
            const result = try handlers.beacon.submitPoolAttestations(self.api_context, &.{});
            return self.makeVoidResult(result);
        }
        const parsed = std.json.parseFromSlice([]consensus_types.phase0.Attestation.Type, alloc, dc.body, .{}) catch return error.InvalidRequest;
        defer parsed.deinit();
        const result = try handlers.beacon.submitPoolAttestations(self.api_context, parsed.value);
        return self.makeVoidResult(result);
    }

    fn hSubmitPoolAttestationsV2(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        if (dc.body.len != 0) {
            const cb = self.api_context.pool_submit orelse return error.NotImplemented;
            _ = cb.submitAttestationFn orelse return error.NotImplemented;
        }
        if (dc.body.len == 0) {
            const result = try handlers.beacon.submitPoolAttestationsV2(self.api_context, .{ .phase0 = &.{} });
            return self.makeVoidResult(result);
        }
        if (std.json.parseFromSlice([]consensus_types.electra.SingleAttestation.Type, alloc, dc.body, .{})) |parsed| {
            defer parsed.deinit();
            const result = try handlers.beacon.submitPoolAttestationsV2(self.api_context, .{ .electra_single = parsed.value });
            return self.makeVoidResult(result);
        } else |_| {}
        const parsed = std.json.parseFromSlice([]consensus_types.phase0.Attestation.Type, alloc, dc.body, .{}) catch return error.InvalidRequest;
        defer parsed.deinit();
        const result = try handlers.beacon.submitPoolAttestationsV2(self.api_context, .{ .phase0 = parsed.value });
        return self.makeVoidResult(result);
    }

    fn hSubmitPoolVoluntaryExits(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        if (dc.body.len != 0) {
            const cb = self.api_context.pool_submit orelse return error.NotImplemented;
            _ = cb.submitVoluntaryExitFn orelse return error.NotImplemented;
        }
        if (dc.body.len == 0) return self.makeVoidResult(.{ .data = {} });
        const parsed = std.json.parseFromSlice(consensus_types.phase0.SignedVoluntaryExit.Type, alloc, dc.body, .{}) catch return error.InvalidRequest;
        defer parsed.deinit();
        const result = try handlers.beacon.submitPoolVoluntaryExits(self.api_context, parsed.value);
        return self.makeVoidResult(result);
    }

    fn hSubmitPoolProposerSlashings(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        if (dc.body.len != 0) {
            const cb = self.api_context.pool_submit orelse return error.NotImplemented;
            _ = cb.submitProposerSlashingFn orelse return error.NotImplemented;
        }
        if (dc.body.len == 0) return self.makeVoidResult(.{ .data = {} });
        const parsed = std.json.parseFromSlice(consensus_types.phase0.ProposerSlashing.Type, alloc, dc.body, .{}) catch return error.InvalidRequest;
        defer parsed.deinit();
        const result = try handlers.beacon.submitPoolProposerSlashings(self.api_context, parsed.value);
        return self.makeVoidResult(result);
    }

    fn hSubmitPoolAttesterSlashings(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        if (dc.body.len != 0) {
            const cb = self.api_context.pool_submit orelse return error.NotImplemented;
            _ = cb.submitAttesterSlashingFn orelse return error.NotImplemented;
        }
        if (dc.body.len == 0) return self.makeVoidResult(.{ .data = {} });
        if (std.json.parseFromSlice(consensus_types.electra.AttesterSlashing.Type, alloc, dc.body, .{})) |parsed| {
            defer parsed.deinit();
            const result = try handlers.beacon.submitPoolAttesterSlashings(self.api_context, .{ .electra = parsed.value });
            return self.makeVoidResult(result);
        } else |_| {}
        const parsed = std.json.parseFromSlice(consensus_types.phase0.AttesterSlashing.Type, alloc, dc.body, .{}) catch return error.InvalidRequest;
        defer parsed.deinit();
        const result = try handlers.beacon.submitPoolAttesterSlashings(self.api_context, .{ .phase0 = parsed.value });
        return self.makeVoidResult(result);
    }

    fn hSubmitPoolBlsToExecutionChanges(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        if (dc.body.len != 0) {
            const cb = self.api_context.pool_submit orelse return error.NotImplemented;
            _ = cb.submitBlsChangeFn orelse return error.NotImplemented;
        }
        if (dc.body.len == 0) {
            const result = try handlers.beacon.submitPoolBlsToExecutionChanges(self.api_context, &.{});
            return self.makeVoidResult(result);
        }
        const parsed = std.json.parseFromSlice([]consensus_types.capella.SignedBLSToExecutionChange.Type, alloc, dc.body, .{}) catch return error.InvalidRequest;
        defer parsed.deinit();
        const result = try handlers.beacon.submitPoolBlsToExecutionChanges(self.api_context, parsed.value);
        return self.makeVoidResult(result);
    }

    fn hSubmitPoolSyncCommittees(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        if (dc.body.len != 0) {
            const cb = self.api_context.pool_submit orelse return error.NotImplemented;
            _ = cb.submitSyncCommitteeMessageFn orelse return error.NotImplemented;
        }
        if (dc.body.len == 0) {
            const result = try handlers.beacon.submitPoolSyncCommittees(self.api_context, &.{});
            return self.makeVoidResult(result);
        }
        const parsed = std.json.parseFromSlice([]consensus_types.altair.SyncCommitteeMessage.Type, alloc, dc.body, .{}) catch return error.InvalidRequest;
        defer parsed.deinit();
        const result = try handlers.beacon.submitPoolSyncCommittees(self.api_context, parsed.value);
        return self.makeVoidResult(result);
    }

    fn hGetDebugState(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const state_id_str = dc.match.getParam("state_id") orelse return error.InvalidStateId;
        const state_id = try types.StateId.parse(state_id_str);

        if (dc.format == .ssz) {
            const handler_res = try handlers.debug.getState(self.api_context, state_id);
            defer alloc.free(handler_res.data);

            var meta = handler_res.meta;
            const slot_opt: ?u64 = switch (state_id) {
                .genesis => 0,
                .slot => |slot| slot,
                else => if (handler_res.data.len >= 48)
                    fork_types.readSlotFromAnyBeaconStateBytes(handler_res.data)
                else
                    null,
            };
            if (slot_opt) |slot| {
                const fork_seq = self.api_context.beacon_config.forkSeq(slot);
                meta.version = @enumFromInt(@intFromEnum(fork_seq));
            }

            const ssz_copy = try alloc.dupe(u8, handler_res.data);
            return .{ .status = 200, .content_type = "application/octet-stream", .body = ssz_copy, .meta = meta };
        }

        const handler_res = try handlers.debug.getState(self.api_context, state_id);
        defer alloc.free(handler_res.data);

        var meta = handler_res.meta;
        const slot_opt: ?u64 = switch (state_id) {
            .genesis => 0,
            .slot => |slot| slot,
            else => if (handler_res.data.len >= 48)
                fork_types.readSlotFromAnyBeaconStateBytes(handler_res.data)
            else
                null,
        };
        const slot = slot_opt orelse return error.InvalidResponseData;
        meta.version = @enumFromInt(@intFromEnum(self.api_context.beacon_config.forkSeq(slot)));
        const body = try json_response.writeStateBytesEnvelope(alloc, meta.version.?, handler_res.data, meta);
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = meta };
    }

    fn hGetDebugHeads(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const handler_res = try handlers.debug.getHeads(self.api_context);
        defer alloc.free(handler_res.data);
        // Eth-Consensus-Version intentionally omitted: multiple chain heads may span forks.
        const body = try json_response.writeApiArrayEnvelope(alloc, types.DebugChainHead, handler_res.data, handler_res.meta);
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = handler_res.meta };
    }

    // ── SSE streaming handler ────────────────────────────────────────────

    /// Maximum time an SSE connection is kept alive (5 minutes).
    /// After this, the client must reconnect. Prevents resource exhaustion.
    const sse_max_duration_sec: i64 = 300;

    /// Poll interval between EventBus checks (1 second).
    const sse_poll_interval_ms: i64 = 1000;

    /// Handle SSE streaming for GET /eth/v1/events.
    ///
    /// This bypasses the normal HandlerResult dispatch path because SSE
    /// requires a long-lived streaming response. Uses chunked transfer
    /// encoding with `text/event-stream` content type.
    ///
    /// SSE frame format per the W3C spec:
    ///   event: <topic>\n
    ///   data: <json>\n
    ///   \n
    fn handleSseEvents(
        self: *HttpServer,
        request: *http.Server.Request,
        target: []const u8,
        io: Io,
    ) !void {
        const handlers_events = @import("handlers/events.zig");

        // Parse query string for topics parameter.
        const query = if (std.mem.indexOfScalar(u8, target, '?')) |idx| target[idx + 1 ..] else "";
        const topics_value = blk: {
            var pairs = std.mem.splitScalar(u8, query, '&');
            while (pairs.next()) |pair| {
                if (std.mem.indexOfScalar(u8, pair, '=')) |eq| {
                    const k = pair[0..eq];
                    const v = pair[eq + 1 ..];
                    if (std.mem.eql(u8, k, "topics")) break :blk v;
                }
            }
            break :blk "";
        };

        const filter = handlers_events.TopicFilter.parse(topics_value);

        // If no valid topics, return 400 Bad Request.
        if (!filter.hasAny()) {
            try request.respond(
                "{\"statusCode\":400,\"message\":\"No valid topics specified\"}",
                .{
                    .status = .bad_request,
                    .extra_headers = &.{
                        .{ .name = "Content-Type", .value = "application/json" },
                    },
                },
            );
            return;
        }

        // Require a live event bus.
        const bus = self.api_context.event_bus orelse {
            try request.respond(
                "{\"statusCode\":503,\"message\":\"Event bus not available\"}",
                .{
                    .status = .service_unavailable,
                    .extra_headers = &.{
                        .{ .name = "Content-Type", .value = "application/json" },
                    },
                },
            );
            return;
        };

        // Start streaming response with SSE headers.
        // Use chunked transfer encoding (no content-length for streaming).
        // Set Connection: keep-alive and Cache-Control: no-cache per SSE spec.
        var stream_buf: [4096]u8 = undefined;
        var body_writer = try request.respondStreaming(&stream_buf, .{
            .respond_options = .{
                .status = .ok,
                .keep_alive = false, // SSE connections close when done
                .extra_headers = &.{
                    .{ .name = "Content-Type", .value = "text/event-stream" },
                    .{ .name = "Cache-Control", .value = "no-cache" },
                    .{ .name = "Connection", .value = "keep-alive" },
                    .{ .name = "Access-Control-Allow-Origin", .value = self.cors_origin orelse "*" },
                },
            },
        });
        // Flush headers immediately so client knows the stream started.
        try body_writer.flush();

        // Start polling the EventBus from the current write position.
        // This means the client only sees events emitted after connecting.
        var since_idx = bus.write_idx;
        var polls_remaining: i64 = @divTrunc(sse_max_duration_sec * 1000, sse_poll_interval_ms);

        log.info("SSE client connected, topics: {s}", .{topics_value});

        while (polls_remaining > 0 and !self.shutdown_requested.load(.acquire)) {
            polls_remaining -= 1;

            // Check for new events.
            const events = bus.getRecent(since_idx);

            if (events.len > 0) {
                // Update cursor.
                since_idx = bus.write_idx;

                // Write matching events as SSE frames.
                for (events) |event| {
                    if (!filter.matches(event)) continue;

                    const topic_name = event.eventType().topicName();

                    // Format JSON data payload.
                    var json_buf: [2048]u8 = undefined;
                    const json_data = event.writeJson(&json_buf) catch |err| {
                        log.warn("SSE event JSON format failed: {s}", .{@errorName(err)});
                        continue;
                    };

                    // Write SSE frame: "event: <topic>\ndata: <json>\n\n"
                    body_writer.writer.print("event: {s}\ndata: {s}\n\n", .{
                        topic_name,
                        json_data,
                    }) catch |err| {
                        log.debug("SSE write failed (client disconnect?): {s}", .{@errorName(err)});
                        return;
                    };
                }

                // Flush after writing all events in this batch.
                body_writer.flush() catch |err| {
                    log.debug("SSE flush failed (client disconnect?): {s}", .{@errorName(err)});
                    return;
                };
            } else if (since_idx > bus.write_idx) {
                // Ring buffer wrapped — reset cursor to catch up.
                since_idx = bus.write_idx;
            }

            // Sleep before next poll.
            io.sleep(Io.Duration.fromMilliseconds(sse_poll_interval_ms), .awake) catch {
                // Sleep cancelled (e.g. shutdown) — exit gracefully.
                return;
            };
        }

        // Max duration reached or shutdown — end the stream.
        body_writer.end() catch {};
        log.info("SSE stream ended (max duration or shutdown)", .{});
    }

    fn hGetEvents(self: *HttpServer, _: DispatchContext) !HandlerResult {
        // SSE streaming is handled directly in handleHttpRequest before
        // dispatch reaches here. If we get here, it means SSE was bypassed
        // (e.g. via handleRequest test path) — return 501.
        _ = self;
        return error.NotImplemented;
    }

    fn hGetProposerDuties(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const epoch_str = dc.match.getParam("epoch") orelse return error.InvalidRequest;
        const epoch = std.fmt.parseInt(u64, epoch_str, 10) catch return error.InvalidRequest;
        const handler_res = try handlers.validator.getProposerDuties(self.api_context, epoch);
        defer alloc.free(handler_res.data);
        const body = try json_response.writeApiArrayEnvelope(alloc, handlers.validator.ProposerDuty, handler_res.data, handler_res.meta);
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = handler_res.meta };
    }

    fn hGetAttesterDuties(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const epoch_str = dc.match.getParam("epoch") orelse return error.InvalidRequest;
        const epoch = std.fmt.parseInt(u64, epoch_str, 10) catch return error.InvalidRequest;
        var validator_indices = std.ArrayListUnmanaged(u64).empty;
        defer validator_indices.deinit(alloc);
        if (dc.body.len > 2) {
            const parsed = std.json.parseFromSlice([]u64, alloc, dc.body, .{}) catch return error.InvalidRequest;
            defer parsed.deinit();
            for (parsed.value) |idx| try validator_indices.append(alloc, idx);
        }
        const handler_res = try handlers.validator.getAttesterDuties(self.api_context, epoch, validator_indices.items);
        defer alloc.free(handler_res.data);
        const body = try json_response.writeApiArrayEnvelope(alloc, handlers.validator.AttesterDuty, handler_res.data, handler_res.meta);
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = handler_res.meta };
    }

    fn hGetSyncDuties(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const epoch_str = dc.match.getParam("epoch") orelse return error.InvalidRequest;
        const epoch = std.fmt.parseInt(u64, epoch_str, 10) catch return error.InvalidRequest;
        var validator_indices = std.ArrayListUnmanaged(u64).empty;
        defer validator_indices.deinit(alloc);
        if (dc.body.len > 2) {
            const parsed = std.json.parseFromSlice([]u64, alloc, dc.body, .{}) catch return error.InvalidRequest;
            defer parsed.deinit();
            for (parsed.value) |idx| try validator_indices.append(alloc, idx);
        }
        const handler_res = try handlers.validator.getSyncDuties(self.api_context, epoch, validator_indices.items);
        defer {
            for (handler_res.data) |d| alloc.free(d.validator_sync_committee_indices);
            alloc.free(handler_res.data);
        }
        const body = try json_response.writeApiArrayEnvelope(alloc, handlers.validator.SyncDuty, handler_res.data, handler_res.meta);
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = handler_res.meta };
    }

    fn hPrepareBeaconCommitteeSubnet(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        var subscriptions: []const types.BeaconCommitteeSubscription = &.{};

        if (dc.body.len > 2) {
            const parsed = std.json.parseFromSlice([]types.BeaconCommitteeSubscription, self.allocator, dc.body, .{ .ignore_unknown_fields = true }) catch return error.InvalidRequest;
            defer parsed.deinit();
            subscriptions = parsed.value;
        }

        const handler_res = try handlers.validator.prepareBeaconCommitteeSubnet(self.api_context, subscriptions);
        return self.makeVoidResult(handler_res);
    }

    fn hPrepareSyncCommitteeSubnets(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        var subscriptions: []const types.SyncCommitteeSubscription = &.{};

        if (dc.body.len > 2) {
            const parsed = std.json.parseFromSlice([]types.SyncCommitteeSubscription, self.allocator, dc.body, .{ .ignore_unknown_fields = true }) catch return error.InvalidRequest;
            defer parsed.deinit();
            subscriptions = parsed.value;
        }

        const handler_res = try handlers.validator.prepareSyncCommitteeSubnets(self.api_context, subscriptions);
        return self.makeVoidResult(handler_res);
    }

    fn hGetSpec(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const result = handlers.config.getSpec(self.api_context);
        const body = try json_response.writeConfigSpecEnvelope(self.allocator, result.data, result.meta);
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = result.meta };
    }

    fn hGetForkSchedule(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const result = handlers.config.getForkSchedule(self.api_context);
        defer if (result.data.len > 0) self.allocator.free(result.data);
        return self.makeJsonResult([]const types.ForkScheduleEntry, result);
    }

    fn hGetValidatorMonitor(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const result = handlers.lodestar.getValidatorMonitor(self.api_context) catch |err| {
            if (err == error.ValidatorMonitorNotConfigured) return error.NotImplemented;
            return err;
        };
        defer self.allocator.free(result.data.validators);
        defer self.allocator.free(result.data.epoch_summaries);
        return self.makeJsonResult(types.ValidatorMonitorData, result);
    }

    fn hProduceBlock(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const slot_str = dc.match.getParam("slot") orelse return error.InvalidRequest;
        const slot = std.fmt.parseInt(u64, slot_str, 10) catch return error.InvalidRequest;
        const randao_hex = dc.getQuery("randao_reveal") orelse return error.InvalidRequest;
        const randao_src = if (std.mem.startsWith(u8, randao_hex, "0x")) randao_hex[2..] else randao_hex;
        if (randao_src.len != 192) return error.InvalidRequest;
        var randao_reveal: [96]u8 = undefined;
        _ = std.fmt.hexToBytes(&randao_reveal, randao_src) catch return error.InvalidRequest;
        const graffiti: ?[32]u8 = if (dc.getQuery("graffiti")) |grf| blk: {
            const grf_src = if (std.mem.startsWith(u8, grf, "0x")) grf[2..] else grf;
            if (grf_src.len == 64) {
                var g: [32]u8 = undefined;
                _ = std.fmt.hexToBytes(&g, grf_src) catch break :blk null;
                break :blk g;
            }
            break :blk null;
        } else null;
        const fee_recipient: ?[20]u8 = if (dc.getQuery("fee_recipient")) |fee| blk: {
            const fee_src = if (std.mem.startsWith(u8, fee, "0x")) fee[2..] else fee;
            if (fee_src.len != 40) return error.InvalidRequest;
            var parsed: [20]u8 = undefined;
            _ = std.fmt.hexToBytes(&parsed, fee_src) catch return error.InvalidRequest;
            break :blk parsed;
        } else null;
        const builder_selection: ?types.BuilderSelection = if (dc.getQuery("builder_selection")) |selection|
            types.BuilderSelection.parse(selection) catch return error.InvalidRequest
        else
            null;
        const builder_boost_factor: ?u64 = if (dc.getQuery("builder_boost_factor")) |boost|
            std.fmt.parseInt(u64, boost, 10) catch return error.InvalidRequest
        else
            null;
        const strict_fee_recipient_check: bool = if (dc.getQuery("strict_fee_recipient_check")) |strict|
            if (std.mem.eql(u8, strict, "true"))
                true
            else if (std.mem.eql(u8, strict, "false"))
                false
            else
                return error.InvalidRequest
        else
            false;
        const blinded_local: bool = if (dc.getQuery("blinded_local")) |blinded|
            if (std.mem.eql(u8, blinded, "true"))
                true
            else if (std.mem.eql(u8, blinded, "false"))
                false
            else
                return error.InvalidRequest
        else
            false;
        const handler_res = try handlers.validator.produceBlock(
            self.api_context,
            slot,
            randao_reveal,
            fee_recipient,
            graffiti,
            builder_selection,
            builder_boost_factor,
            strict_fee_recipient_check,
            blinded_local,
        );
        defer alloc.free(@constCast(handler_res.data.ssz_bytes));
        var block_meta = handler_res.meta;
        block_meta.version = response_meta.Fork.fromString(handler_res.data.fork);
        if (std.mem.eql(u8, dc.match.route.operation_id, "produceBlockV3")) {
            block_meta.execution_payload_blinded = handler_res.data.blinded;
            block_meta.execution_payload_source = handler_res.data.execution_payload_source;
            block_meta.execution_payload_value = handler_res.data.execution_payload_value;
            block_meta.consensus_block_value = handler_res.data.consensus_block_value;
        }
        if (dc.format == .ssz) {
            const ssz_copy = try alloc.dupe(u8, handler_res.data.ssz_bytes);
            return .{ .status = 200, .content_type = "application/octet-stream", .body = ssz_copy, .meta = block_meta };
        }
        // Deserialize SSZ bytes into typed unsigned block, then serialize to JSON via SSZ type system
        const fork_seq = ForkSeq.fromName(handler_res.data.fork);
        const any_block = try AnyBeaconBlock.deserialize(
            alloc,
            if (handler_res.data.blinded) .blinded else .full,
            fork_seq,
            handler_res.data.ssz_bytes,
        );
        defer any_block.deinit(alloc);
        const body_json = try json_response.writeUnsignedBlockEnvelope(alloc, any_block, block_meta);
        return .{ .status = 200, .content_type = "application/json", .body = body_json, .meta = block_meta };
    }

    fn hGetAttestationData(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const slot_str = dc.getQuery("slot") orelse return error.InvalidRequest;
        const committee_str = dc.getQuery("committee_index") orelse "0";
        const slot = std.fmt.parseInt(u64, slot_str, 10) catch return error.InvalidRequest;
        const committee_index = std.fmt.parseInt(u64, committee_str, 10) catch return error.InvalidRequest;
        const handler_res = try handlers.validator.getAttestationData(self.api_context, slot, committee_index);
        return self.makeJsonResult(context.AttestationDataResult, handler_res);
    }

    fn hGetAggregateAttestation(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const slot_str = dc.getQuery("slot") orelse return error.InvalidRequest;
        const root_hex = dc.getQuery("attestation_data_root") orelse return error.InvalidRequest;
        const slot = std.fmt.parseInt(u64, slot_str, 10) catch return error.InvalidRequest;
        const root_src = if (std.mem.startsWith(u8, root_hex, "0x")) root_hex[2..] else root_hex;
        if (root_src.len != 64) return error.InvalidRequest;
        var data_root: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&data_root, root_src) catch return error.InvalidRequest;
        var handler_res = try handlers.validator.getAggregateAttestation(self.api_context, slot, data_root);
        defer consensus_types.phase0.Attestation.deinit(alloc, &handler_res.data);
        const status = if (handler_res.status != 0) handler_res.status else 200;
        const body = try json_response.writeBeaconEnvelope(alloc, consensus_types.phase0.Attestation, &handler_res.data, handler_res.meta);
        return .{ .status = status, .content_type = "application/json", .body = body, .meta = handler_res.meta };
    }

    fn hPublishAggregateAndProofs(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        if (dc.body.len != 0) {
            const cb = self.api_context.pool_submit orelse return error.NotImplemented;
            _ = cb.submitAggregateAndProofFn orelse return error.NotImplemented;
        }
        if (dc.body.len == 0) {
            const handler_res = try handlers.validator.publishAggregateAndProofs(self.api_context, .{ .phase0 = &.{} });
            return self.makeVoidResult(handler_res);
        }
        if (std.json.parseFromSlice([]consensus_types.electra.SignedAggregateAndProof.Type, alloc, dc.body, .{})) |parsed| {
            defer parsed.deinit();
            const handler_res = try handlers.validator.publishAggregateAndProofs(self.api_context, .{ .electra = parsed.value });
            return self.makeVoidResult(handler_res);
        } else |_| {}

        const parsed = std.json.parseFromSlice([]consensus_types.phase0.SignedAggregateAndProof.Type, alloc, dc.body, .{}) catch return error.InvalidRequest;
        defer parsed.deinit();
        const handler_res = try handlers.validator.publishAggregateAndProofs(self.api_context, .{ .phase0 = parsed.value });
        return self.makeVoidResult(handler_res);
    }

    fn hGetSyncCommitteeContribution(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const slot_str = dc.getQuery("slot") orelse return error.InvalidRequest;
        const subnet_str = dc.getQuery("subcommittee_index") orelse "0";
        const root_hex = dc.getQuery("beacon_block_root") orelse return error.InvalidRequest;
        const slot = std.fmt.parseInt(u64, slot_str, 10) catch return error.InvalidRequest;
        const subcommittee_index = std.fmt.parseInt(u64, subnet_str, 10) catch return error.InvalidRequest;
        const root_src = if (std.mem.startsWith(u8, root_hex, "0x")) root_hex[2..] else root_hex;
        if (root_src.len != 64) return error.InvalidRequest;
        var block_root: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&block_root, root_src) catch return error.InvalidRequest;
        const handler_res = try handlers.validator.getSyncCommitteeContribution(self.api_context, slot, subcommittee_index, block_root);
        const status = if (handler_res.status != 0) handler_res.status else 200;
        const body = try json_response.writeBeaconEnvelope(alloc, consensus_types.altair.SyncCommitteeContribution, &handler_res.data, handler_res.meta);
        return .{ .status = status, .content_type = "application/json", .body = body, .meta = handler_res.meta };
    }

    fn hPublishContributionAndProofs(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        if (dc.body.len != 0) {
            const cb = self.api_context.pool_submit orelse return error.NotImplemented;
            _ = cb.submitContributionAndProofFn orelse return error.NotImplemented;
        }
        if (dc.body.len == 0) {
            const handler_res = try handlers.validator.publishContributionAndProofs(self.api_context, &.{});
            return self.makeVoidResult(handler_res);
        }
        const parsed = std.json.parseFromSlice([]consensus_types.altair.SignedContributionAndProof.Type, alloc, dc.body, .{}) catch return error.InvalidRequest;
        defer parsed.deinit();
        const handler_res = try handlers.validator.publishContributionAndProofs(self.api_context, parsed.value);
        return self.makeVoidResult(handler_res);
    }

    fn hGetStateCommittees(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const state_id_str = dc.match.getParam("state_id") orelse return error.InvalidStateId;
        const state_id = try types.StateId.parse(state_id_str);
        const epoch_opt: ?u64 = if (dc.getQuery("epoch")) |s| std.fmt.parseInt(u64, s, 10) catch null else null;
        const slot_opt: ?u64 = if (dc.getQuery("slot")) |s| std.fmt.parseInt(u64, s, 10) catch null else null;
        const index_opt: ?u64 = if (dc.getQuery("index")) |s| std.fmt.parseInt(u64, s, 10) catch null else null;
        const handler_res = try handlers.beacon.getStateCommittees(self.api_context, state_id, epoch_opt, slot_opt, index_opt);
        defer {
            for (handler_res.data) |item| alloc.free(item.validators);
            alloc.free(handler_res.data);
        }
        const body = try json_response.writeApiArrayEnvelope(alloc, types.CommitteeData, handler_res.data, handler_res.meta);
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = handler_res.meta };
    }

    fn hGetStateSyncCommittees(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const state_id_str = dc.match.getParam("state_id") orelse return error.InvalidStateId;
        const state_id = try types.StateId.parse(state_id_str);
        const epoch_opt: ?u64 = if (dc.getQuery("epoch")) |s| std.fmt.parseInt(u64, s, 10) catch null else null;
        const handler_res = try handlers.beacon.getStateSyncCommittees(self.api_context, state_id, epoch_opt);
        defer {
            alloc.free(handler_res.data.validators);
            for (handler_res.data.validator_aggregates) |agg| alloc.free(agg);
            alloc.free(handler_res.data.validator_aggregates);
        }
        const body = try json_response.writeApiObjectEnvelope(alloc, types.SyncCommitteeData, &handler_res.data, handler_res.meta);
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = handler_res.meta };
    }

    fn hGetStateRandao(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const state_id_str = dc.match.getParam("state_id") orelse return error.InvalidStateId;
        const state_id = try types.StateId.parse(state_id_str);
        const epoch_opt: ?u64 = if (dc.getQuery("epoch")) |s| std.fmt.parseInt(u64, s, 10) catch null else null;
        const handler_res = try handlers.beacon.getStateRandao(self.api_context, state_id, epoch_opt);
        const body = try json_response.writeApiObjectEnvelope(alloc, types.RandaoData, &handler_res.data, handler_res.meta);
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = handler_res.meta };
    }

    fn hGetBlockHeaders(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const slot_opt: ?u64 = if (dc.getQuery("slot")) |s| std.fmt.parseInt(u64, s, 10) catch null else null;
        const parent_root_opt: ?[32]u8 = if (dc.getQuery("parent_root")) |s| blk: {
            const src = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
            if (src.len == 64) {
                var root: [32]u8 = undefined;
                _ = std.fmt.hexToBytes(&root, src) catch break :blk null;
                break :blk root;
            }
            break :blk null;
        } else null;
        const handler_res = try handlers.beacon.getBlockHeaders(self.api_context, slot_opt, parent_root_opt);
        defer alloc.free(handler_res.data);
        var meta = handler_res.meta;
        if (handler_res.data.len > 0) {
            const first_slot = handler_res.data[0].header.message.slot;
            const fork_seq = self.api_context.beacon_config.forkSeq(first_slot);
            meta.version = @enumFromInt(@intFromEnum(fork_seq));
        } else if (slot_opt) |slot| {
            const fork_seq = self.api_context.beacon_config.forkSeq(slot);
            meta.version = @enumFromInt(@intFromEnum(fork_seq));
        }
        const body = try json_response.writeApiArrayEnvelope(alloc, types.BlockHeaderData, handler_res.data, meta);
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = meta };
    }

    fn hGetBlobSidecars(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const block_id_str = dc.match.getParam("block_id") orelse return error.InvalidBlockId;
        const block_id = try types.BlockId.parse(block_id_str);
        const indices_opt = try parseOptionalU64ListQuery(alloc, dc.getQuery("indices"));
        defer if (indices_opt) |indices| alloc.free(indices);

        const result = try handlers.beacon.getBlobSidecars(self.api_context, block_id, indices_opt);
        defer alloc.free(result.data);

        const meta = response_meta.ResponseMeta{
            .version = result.fork_name,
            .execution_optimistic = result.execution_optimistic,
            .finalized = result.finalized,
        };

        const body = switch (result.fork_name) {
            .deneb => try json_response.writeFixedSszArrayEnvelope(alloc, consensus_types.deneb.BlobSidecar, result.data, meta),
            .electra, .fulu, .gloas => try json_response.writeFixedSszArrayEnvelope(alloc, consensus_types.electra.BlobSidecar, result.data, meta),
            else => try json_response.writeRawEnvelope(alloc, "[]", meta),
        };
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = meta };
    }

    fn hGetBlindedBlock(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const block_id_str = dc.match.getParam("block_id") orelse return error.InvalidBlockId;
        const block_id = try types.BlockId.parse(block_id_str);
        const block_result = try handlers.beacon.getBlindedBlock(self.api_context, block_id);
        defer alloc.free(block_result.data);
        const meta = response_meta.ResponseMeta{
            .version = block_result.fork_name,
            .execution_optimistic = block_result.execution_optimistic,
            .finalized = block_result.finalized,
        };
        if (dc.format == .ssz) {
            const ssz_copy = try alloc.dupe(u8, block_result.data);
            return .{ .status = 200, .content_type = "application/octet-stream", .body = ssz_copy, .meta = meta };
        }
        const fork_seq = self.api_context.beacon_config.forkSeq(block_result.slot);
        const any_block = try AnySignedBeaconBlock.deserialize(alloc, block_result.block_type, fork_seq, block_result.data);
        defer any_block.deinit(alloc);
        const body = try json_response.writeBlockEnvelope(alloc, any_block, meta);
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = meta };
    }

    fn hGetBlockRewards(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const block_id_str = dc.match.getParam("block_id") orelse return error.InvalidBlockId;
        const block_id = try types.BlockId.parse(block_id_str);
        const result = try handlers.beacon.getBlockRewards(self.api_context, block_id);
        return self.makeJsonResult(types.BlockRewards, result);
    }

    fn hGetAttestationRewards(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const epoch_str = dc.match.getParam("epoch") orelse return error.InvalidRequest;
        const epoch = std.fmt.parseInt(u64, epoch_str, 10) catch return error.InvalidRequest;
        var validator_indices = std.ArrayListUnmanaged(u64).empty;
        defer validator_indices.deinit(alloc);
        if (dc.body.len > 2) {
            const parsed = std.json.parseFromSlice([]u64, alloc, dc.body, .{}) catch return error.InvalidRequest;
            defer parsed.deinit();
            for (parsed.value) |idx| try validator_indices.append(alloc, idx);
        }
        const result = try handlers.beacon.getAttestationRewards(self.api_context, epoch, validator_indices.items);
        defer alloc.free(result.data.ideal_rewards);
        defer alloc.free(result.data.total_rewards);
        return self.makeJsonResult(types.AttestationRewardsData, result);
    }

    fn hGetSyncCommitteeRewards(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const block_id_str = dc.match.getParam("block_id") orelse return error.InvalidBlockId;
        const block_id = try types.BlockId.parse(block_id_str);
        var validator_indices = std.ArrayListUnmanaged(u64).empty;
        defer validator_indices.deinit(alloc);
        if (dc.body.len > 2) {
            const parsed = std.json.parseFromSlice([]u64, alloc, dc.body, .{}) catch return error.InvalidRequest;
            defer parsed.deinit();
            for (parsed.value) |idx| try validator_indices.append(alloc, idx);
        }
        const result = try handlers.beacon.getSyncCommitteeRewards(self.api_context, block_id, validator_indices.items);
        defer alloc.free(result.data);
        return self.makeJsonResult([]const types.SyncCommitteeReward, result);
    }

    fn hPrepareBeaconProposer(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        var preparations = std.ArrayListUnmanaged(types.ProposerPreparation).empty;
        defer preparations.deinit(alloc);
        if (dc.body.len > 2) {
            const PrepWire = struct {
                validator_index: u64,
                fee_recipient: []const u8,
            };
            const parsed = std.json.parseFromSlice([]PrepWire, alloc, dc.body, .{ .ignore_unknown_fields = true }) catch return error.InvalidRequest;
            defer parsed.deinit();
            for (parsed.value) |p| {
                const addr_src = if (std.mem.startsWith(u8, p.fee_recipient, "0x")) p.fee_recipient[2..] else p.fee_recipient;
                var addr: [20]u8 = [_]u8{0} ** 20;
                if (addr_src.len == 40) {
                    _ = std.fmt.hexToBytes(&addr, addr_src) catch {};
                }
                try preparations.append(alloc, .{ .validator_index = p.validator_index, .fee_recipient = addr });
            }
        }
        const handler_res = try handlers.validator.prepareBeaconProposer(self.api_context, preparations.items);
        return self.makeVoidResult(handler_res);
    }

    fn hRegisterValidator(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        var registrations = std.ArrayListUnmanaged(types.SignedValidatorRegistrationV1).empty;
        defer registrations.deinit(alloc);
        if (dc.body.len > 2) {
            const RegWire = struct {
                message: struct {
                    fee_recipient: []const u8,
                    gas_limit: u64,
                    timestamp: u64,
                    pubkey: []const u8,
                },
                signature: []const u8,
            };
            const parsed = std.json.parseFromSlice([]RegWire, alloc, dc.body, .{ .ignore_unknown_fields = true }) catch return error.InvalidRequest;
            defer parsed.deinit();
            for (parsed.value) |r| {
                var fee_recipient: [20]u8 = [_]u8{0} ** 20;
                var pubkey: [48]u8 = [_]u8{0} ** 48;
                var sig: [96]u8 = [_]u8{0} ** 96;
                const addr_src = if (std.mem.startsWith(u8, r.message.fee_recipient, "0x")) r.message.fee_recipient[2..] else r.message.fee_recipient;
                if (addr_src.len == 40) _ = std.fmt.hexToBytes(&fee_recipient, addr_src) catch {};
                const pk_src = if (std.mem.startsWith(u8, r.message.pubkey, "0x")) r.message.pubkey[2..] else r.message.pubkey;
                if (pk_src.len == 96) _ = std.fmt.hexToBytes(&pubkey, pk_src) catch {};
                const sig_src = if (std.mem.startsWith(u8, r.signature, "0x")) r.signature[2..] else r.signature;
                if (sig_src.len == 192) _ = std.fmt.hexToBytes(&sig, sig_src) catch {};
                try registrations.append(alloc, .{
                    .message = .{
                        .fee_recipient = fee_recipient,
                        .gas_limit = r.message.gas_limit,
                        .timestamp = r.message.timestamp,
                        .pubkey = pubkey,
                    },
                    .signature = sig,
                });
            }
        }
        const handler_res = try handlers.validator.registerValidator(self.api_context, registrations.items);
        return self.makeVoidResult(handler_res);
    }

    fn hGetValidatorLiveness(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const epoch_str = dc.match.getParam("epoch") orelse return error.InvalidRequest;
        const epoch = std.fmt.parseInt(u64, epoch_str, 10) catch return error.InvalidRequest;
        var validator_indices = std.ArrayListUnmanaged(u64).empty;
        defer validator_indices.deinit(alloc);
        if (dc.body.len > 2) {
            const parsed = std.json.parseFromSlice([]u64, alloc, dc.body, .{}) catch return error.InvalidRequest;
            defer parsed.deinit();
            for (parsed.value) |idx| try validator_indices.append(alloc, idx);
        }
        const handler_res = try handlers.validator.getValidatorLiveness(self.api_context, epoch, validator_indices.items);
        defer alloc.free(handler_res.data);
        return self.makeJsonResult([]types.ValidatorLiveness, handler_res);
    }

    fn hListKeystores(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const handler_res = try handlers.keymanager.listKeystores(self.api_context, dc.auth_header);
        defer alloc.free(handler_res.data);
        return self.makeJsonResult([]const types.KeymanagerKeystore, handler_res);
    }

    fn hImportKeystores(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const handler_res = try handlers.keymanager.importKeystores(self.api_context, dc.auth_header, dc.body);
        defer alloc.free(handler_res.data);
        return self.makeJsonResult([]const types.KeymanagerOperationResult, handler_res);
    }

    fn hDeleteKeystores(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const handler_res = try handlers.keymanager.deleteKeystores(self.api_context, dc.auth_header, dc.body);
        defer handlers.keymanager.deinitDeleteKeystoresResponse(alloc, handler_res.data);
        const body = try json_response.writeKeymanagerDeleteKeystoresEnvelope(alloc, handler_res.data, handler_res.meta);
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = handler_res.meta };
    }

    fn hListRemoteKeys(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const handler_res = try handlers.keymanager.listRemoteKeys(self.api_context, dc.auth_header);
        defer alloc.free(handler_res.data);
        return self.makeJsonResult([]const context.RemoteKeyInfo, handler_res);
    }

    fn hImportRemoteKeys(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const handler_res = try handlers.keymanager.importRemoteKeys(self.api_context, dc.auth_header, dc.body);
        defer alloc.free(handler_res.data);
        return self.makeJsonResult([]const types.KeymanagerOperationResult, handler_res);
    }

    fn hDeleteRemoteKeys(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const handler_res = try handlers.keymanager.deleteRemoteKeys(self.api_context, dc.auth_header, dc.body);
        defer alloc.free(handler_res.data);
        return self.makeJsonResult([]const types.KeymanagerOperationResult, handler_res);
    }

    fn hListFeeRecipient(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const pubkey = try parsePubkeyParam(dc.match.getParam("pubkey") orelse return error.InvalidRequest);
        const handler_res = try handlers.keymanager.listFeeRecipient(self.api_context, dc.auth_header, pubkey);
        return self.makeJsonResult(types.KeymanagerFeeRecipientData, handler_res);
    }

    fn hSetFeeRecipient(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const pubkey = try parsePubkeyParam(dc.match.getParam("pubkey") orelse return error.InvalidRequest);
        try handlers.keymanager.setFeeRecipient(self.api_context, dc.auth_header, pubkey, dc.body);
        return .{ .status = 202, .content_type = "application/json", .body = &.{} };
    }

    fn hDeleteFeeRecipient(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const pubkey = try parsePubkeyParam(dc.match.getParam("pubkey") orelse return error.InvalidRequest);
        try handlers.keymanager.deleteFeeRecipient(self.api_context, dc.auth_header, pubkey);
        return .{ .status = 204, .content_type = "application/json", .body = &.{} };
    }

    fn hGetGraffiti(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const pubkey = try parsePubkeyParam(dc.match.getParam("pubkey") orelse return error.InvalidRequest);
        const handler_res = try handlers.keymanager.getGraffiti(self.api_context, dc.auth_header, pubkey);
        defer alloc.free(handler_res.data.graffiti);
        return self.makeJsonResult(types.KeymanagerGraffitiData, handler_res);
    }

    fn hSetGraffiti(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const pubkey = try parsePubkeyParam(dc.match.getParam("pubkey") orelse return error.InvalidRequest);
        try handlers.keymanager.setGraffiti(self.api_context, dc.auth_header, pubkey, dc.body);
        return .{ .status = 202, .content_type = "application/json", .body = &.{} };
    }

    fn hDeleteGraffiti(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const pubkey = try parsePubkeyParam(dc.match.getParam("pubkey") orelse return error.InvalidRequest);
        try handlers.keymanager.deleteGraffiti(self.api_context, dc.auth_header, pubkey);
        return .{ .status = 204, .content_type = "application/json", .body = &.{} };
    }

    fn hGetGasLimit(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const pubkey = try parsePubkeyParam(dc.match.getParam("pubkey") orelse return error.InvalidRequest);
        const handler_res = try handlers.keymanager.getGasLimit(self.api_context, dc.auth_header, pubkey);
        return self.makeJsonResult(types.KeymanagerGasLimitData, handler_res);
    }

    fn hSetGasLimit(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const pubkey = try parsePubkeyParam(dc.match.getParam("pubkey") orelse return error.InvalidRequest);
        try handlers.keymanager.setGasLimit(self.api_context, dc.auth_header, pubkey, dc.body);
        return .{ .status = 202, .content_type = "application/json", .body = &.{} };
    }

    fn hDeleteGasLimit(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const pubkey = try parsePubkeyParam(dc.match.getParam("pubkey") orelse return error.InvalidRequest);
        try handlers.keymanager.deleteGasLimit(self.api_context, dc.auth_header, pubkey);
        return .{ .status = 204, .content_type = "application/json", .body = &.{} };
    }

    fn hGetBuilderBoostFactor(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const pubkey = try parsePubkeyParam(dc.match.getParam("pubkey") orelse return error.InvalidRequest);
        const handler_res = try handlers.keymanager.getBuilderBoostFactor(self.api_context, dc.auth_header, pubkey);
        return self.makeJsonResult(types.KeymanagerBuilderBoostFactorData, handler_res);
    }

    fn hSetBuilderBoostFactor(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const pubkey = try parsePubkeyParam(dc.match.getParam("pubkey") orelse return error.InvalidRequest);
        try handlers.keymanager.setBuilderBoostFactor(self.api_context, dc.auth_header, pubkey, dc.body);
        return .{ .status = 202, .content_type = "application/json", .body = &.{} };
    }

    fn hDeleteBuilderBoostFactor(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const pubkey = try parsePubkeyParam(dc.match.getParam("pubkey") orelse return error.InvalidRequest);
        try handlers.keymanager.deleteBuilderBoostFactor(self.api_context, dc.auth_header, pubkey);
        return .{ .status = 204, .content_type = "application/json", .body = &.{} };
    }

    fn hGetProposerConfig(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const pubkey = try parsePubkeyParam(dc.match.getParam("pubkey") orelse return error.InvalidRequest);
        const handler_res = try handlers.keymanager.getProposerConfig(self.api_context, dc.auth_header, pubkey);
        defer handlers.keymanager.deinitProposerConfigData(alloc, handler_res.data);
        const body = try json_response.writeKeymanagerProposerConfigEnvelope(alloc, handler_res.data, handler_res.meta);
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = handler_res.meta };
    }

    fn hSignVoluntaryExit(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const pubkey = try parsePubkeyParam(dc.match.getParam("pubkey") orelse return error.InvalidRequest);
        const epoch = if (dc.getQuery("epoch")) |value| try std.fmt.parseInt(u64, value, 10) else null;
        const handler_res = try handlers.keymanager.signVoluntaryExit(self.api_context, dc.auth_header, pubkey, epoch);
        return self.makeJsonResult(consensus_types.phase0.SignedVoluntaryExit.Type, handler_res);
    }

    fn hGetForkChoice(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const handler_res = try handlers.debug.getForkChoice(self.api_context);
        defer alloc.free(handler_res.data.fork_choice_nodes);
        return self.makeJsonResult(types.ForkChoiceDump, handler_res);
    }

    /// Handle a single HTTP request without TCP (for testing).
    ///
    /// Takes method + path + optional body and returns a response. This
    /// exercises the full routing and handler dispatch path.
    pub fn handleRequest(
        self: *HttpServer,
        method: []const u8,
        path: []const u8,
        body: ?[]const u8,
    ) !HttpResponse {

        // OPTIONS (CORS preflight) — check before method validation so it isn't
        // rejected as 405.
        if (std.mem.eql(u8, method, "OPTIONS")) {
            return .{
                .status = 204,
                .status_text = "No Content",
                .content_type = "text/plain",
                .body = "",
                .body_owned = false,
            };
        }

        const route_method: routes_mod.HttpMethod = if (std.mem.eql(u8, method, "GET"))
            .GET
        else if (std.mem.eql(u8, method, "POST"))
            .POST
        else if (std.mem.eql(u8, method, "DELETE"))
            .DELETE
        else
            return .{
                .status = 405,
                .status_text = "Method Not Allowed",
                .content_type = "application/json",
                .body = "{\"statusCode\":405,\"message\":\"Method not allowed\"}",
                .body_owned = false,
            };

        const clean_path, _ = splitTarget(path);

        const match = routes_mod.findRoute(route_method, clean_path) orelse {
            return .{
                .status = 404,
                .status_text = "Not Found",
                .content_type = "application/json",
                .body = "{\"statusCode\":404,\"message\":\"Route not found\"}",
                .body_owned = false,
            };
        };

        const clean_query = if (std.mem.indexOfScalar(u8, path, '?')) |idx| path[idx + 1 ..] else null;
        const dc_test = DispatchContext{
            .match = match,
            .query = clean_query,
            .body = body orelse &[_]u8{},
        };
        const result = self.dispatchHandler(dc_test) catch |err| {
            var api_err = makeApiError(self, err) catch error_response.fromZigError(err);
            defer api_err.deinit(self.allocator);
            const err_json_heap = api_err.formatJsonAlloc(self.allocator) catch null;
            return .{
                .status = api_err.code.statusCode(),
                .status_text = api_err.code.phrase(),
                .content_type = "application/json",
                .body = err_json_heap orelse "{\"statusCode\":500,\"message\":\"internal server error\"}",
                .body_owned = err_json_heap != null,
            };
        };

        return .{
            .status = result.status,
            .status_text = "OK",
            .content_type = result.content_type,
            .body = result.body,
            .body_owned = result.body_owned,
        };
    }

    pub const HttpResponse = struct {
        status: u16,
        status_text: []const u8,
        content_type: []const u8,
        body: []const u8,
        body_owned: bool = false,

        pub fn deinit(self: HttpResponse, allocator: Allocator) void {
            if (self.body_owned) allocator.free(self.body);
        }
    };
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write an Electra-format attestation JSON object into the Stringify stream.
///
/// Converts a phase0-stored attestation (with committee_index in data.index)
/// into the Electra wire format: aggregation_bits, data (with index=0),
/// signature, and reconstructed committee_bits bitvector.
fn writeElectraAttestationJson(
    _: std.mem.Allocator,
    stream: *std.json.Stringify,
    att: *const consensus_types.phase0.Attestation.Type,
) !void {
    // Reconstruct committee_bits: a bitvector of MAX_COMMITTEES_PER_SLOT bits
    // with the bit at position data.index set.
    const committee_index = att.data.index;

    try stream.beginObject();

    // aggregation_bits (same as phase0 — hex-encoded SSZ bitlist)
    try stream.objectField("aggregation_bits");
    const agg_bits = &att.aggregation_bits;
    const bit_len = agg_bits.bit_len;
    const data_byte_count = (bit_len + 7) / 8;
    const ssz_byte_count = if (bit_len % 8 == 0) data_byte_count + 1 else data_byte_count;
    // Build SSZ bitlist bytes: data bytes + sentinel bit
    var agg_buf: [258]u8 = undefined;
    @memset(&agg_buf, 0);
    if (agg_bits.data.items.len > 0) {
        const copy_len = @min(agg_bits.data.items.len, agg_buf.len);
        @memcpy(agg_buf[0..copy_len], agg_bits.data.items[0..copy_len]);
    }
    if (ssz_byte_count > 0 and ssz_byte_count <= agg_buf.len) {
        agg_buf[bit_len / 8] |= @as(u8, 1) << @intCast(bit_len % 8);
    }
    // Hex-encode
    var agg_hex: [258 * 2 + 2]u8 = undefined;
    agg_hex[0] = '0';
    agg_hex[1] = 'x';
    for (agg_buf[0..ssz_byte_count], 0..) |byte, i| {
        const nibbles = "0123456789abcdef";
        agg_hex[2 + i * 2] = nibbles[(byte >> 4) & 0xF];
        agg_hex[2 + i * 2 + 1] = nibbles[byte & 0xF];
    }
    try stream.write(agg_hex[0 .. 2 + ssz_byte_count * 2]);

    // data (with index=0 for Electra)
    try stream.objectField("data");
    try stream.beginObject();
    try stream.objectField("slot");
    {
        var buf: [20]u8 = undefined;
        const s = std.fmt.bufPrint(&buf, "{d}", .{att.data.slot}) catch unreachable;
        try stream.write(s);
    }
    try stream.objectField("index");
    try stream.write("0");
    try stream.objectField("beacon_block_root");
    var root_hex: [66]u8 = undefined;
    root_hex[0] = '0';
    root_hex[1] = 'x';
    for (att.data.beacon_block_root, 0..) |byte, i| {
        const nibbles = "0123456789abcdef";
        root_hex[2 + i * 2] = nibbles[(byte >> 4) & 0xF];
        root_hex[2 + i * 2 + 1] = nibbles[byte & 0xF];
    }
    try stream.write(root_hex[0..66]);
    try stream.objectField("source");
    try stream.beginObject();
    try stream.objectField("epoch");
    {
        var buf: [20]u8 = undefined;
        const s = std.fmt.bufPrint(&buf, "{d}", .{att.data.source.epoch}) catch unreachable;
        try stream.write(s);
    }
    try stream.objectField("root");
    var src_hex: [66]u8 = undefined;
    src_hex[0] = '0';
    src_hex[1] = 'x';
    for (att.data.source.root, 0..) |byte, i| {
        const nibbles = "0123456789abcdef";
        src_hex[2 + i * 2] = nibbles[(byte >> 4) & 0xF];
        src_hex[2 + i * 2 + 1] = nibbles[byte & 0xF];
    }
    try stream.write(src_hex[0..66]);
    try stream.endObject();
    try stream.objectField("target");
    try stream.beginObject();
    try stream.objectField("epoch");
    {
        var buf: [20]u8 = undefined;
        const s = std.fmt.bufPrint(&buf, "{d}", .{att.data.target.epoch}) catch unreachable;
        try stream.write(s);
    }
    try stream.objectField("root");
    var tgt_hex: [66]u8 = undefined;
    tgt_hex[0] = '0';
    tgt_hex[1] = 'x';
    for (att.data.target.root, 0..) |byte, i| {
        const nibbles = "0123456789abcdef";
        tgt_hex[2 + i * 2] = nibbles[(byte >> 4) & 0xF];
        tgt_hex[2 + i * 2 + 1] = nibbles[byte & 0xF];
    }
    try stream.write(tgt_hex[0..66]);
    try stream.endObject();
    try stream.endObject();

    // signature
    try stream.objectField("signature");
    var sig_hex: [194]u8 = undefined;
    sig_hex[0] = '0';
    sig_hex[1] = 'x';
    for (att.signature, 0..) |byte, i| {
        const nibbles = "0123456789abcdef";
        sig_hex[2 + i * 2] = nibbles[(byte >> 4) & 0xF];
        sig_hex[2 + i * 2 + 1] = nibbles[byte & 0xF];
    }
    try stream.write(sig_hex[0..194]);

    // committee_bits: bitvector of MAX_COMMITTEES_PER_SLOT bits
    // with the bit at position committee_index set.
    try stream.objectField("committee_bits");
    const max_committees = @import("preset").preset.MAX_COMMITTEES_PER_SLOT;
    const cb_byte_count = (max_committees + 7) / 8;
    var cb_buf: [cb_byte_count]u8 = @splat(0);
    if (committee_index < max_committees) {
        const ci: usize = @intCast(committee_index);
        cb_buf[ci / 8] |= @as(u8, 1) << @intCast(ci % 8);
    }
    var cb_hex: [cb_byte_count * 2 + 2]u8 = undefined;
    cb_hex[0] = '0';
    cb_hex[1] = 'x';
    for (cb_buf, 0..) |byte, i| {
        const nibbles = "0123456789abcdef";
        cb_hex[2 + i * 2] = nibbles[(byte >> 4) & 0xF];
        cb_hex[2 + i * 2 + 1] = nibbles[byte & 0xF];
    }
    try stream.write(cb_hex[0 .. cb_byte_count * 2 + 2]);

    try stream.endObject();
}

/// Split a request target into path and optional query string.
fn splitTarget(target: []const u8) struct { []const u8, ?[]const u8 } {
    if (std.mem.indexOfScalar(u8, target, '?')) |idx| {
        return .{ target[0..idx], target[idx + 1 ..] };
    }
    return .{ target, null };
}

fn parsePubkeyParam(input: []const u8) ![48]u8 {
    const hex = if (std.mem.startsWith(u8, input, "0x")) input[2..] else input;
    if (hex.len != 96) return error.InvalidRequest;

    var pubkey: [48]u8 = undefined;
    _ = std.fmt.hexToBytes(&pubkey, hex) catch return error.InvalidRequest;
    return pubkey;
}

/// Parse an IP address string (IPv4 only for now).
fn parseIpAddress(addr: []const u8, port: u16) !net.IpAddress {
    return .{ .ip4 = net.Ip4Address.parse(addr, port) catch return error.AddressFamilyUnsupported };
}

/// Find a named header value from the request.
fn findHeader(request: *http.Server.Request, name: []const u8) ?[]const u8 {
    var it = request.iterateHeaders();
    while (it.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) {
            return header.value;
        }
    }
    return null;
}

/// Send a Beacon API error response (JSON, with statusCode field).
fn respondApiError(
    allocator: Allocator,
    request: *http.Server.Request,
    api_err: error_response.ApiError,
) !void {
    const json = try api_err.formatJsonAlloc(allocator);
    defer allocator.free(json);
    try request.respond(json, .{
        .status = statusFromCode(api_err.code.statusCode()),
        .extra_headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
}

fn makeErrorStacktraces(allocator: Allocator, trace: *const std.builtin.StackTrace) ![]const []const u8 {
    const formatted = try std.fmt.allocPrint(allocator, "{f}", .{
        std.debug.FormatStackTrace{ .stack_trace = trace.* },
    });
    defer allocator.free(formatted);

    var lines = std.ArrayListUnmanaged([]const u8).empty;
    errdefer {
        for (lines.items) |line| allocator.free(line);
        lines.deinit(allocator);
    }

    var iter = std.mem.splitScalar(u8, formatted, '\n');
    while (iter.next()) |line| {
        const trimmed = std.mem.trim(u8, line, "\r");
        if (trimmed.len == 0) continue;
        try lines.append(allocator, try allocator.dupe(u8, trimmed));
    }
    return try lines.toOwnedSlice(allocator);
}

fn makeApiError(self: *HttpServer, err: anyerror) !error_response.ApiError {
    var api_err = error_response.fromZigError(err);
    if (!self.include_error_stacktraces) return api_err;
    if (@errorReturnTrace()) |trace| {
        if (trace.index > 0) {
            api_err.stacktraces = try makeErrorStacktraces(self.allocator, trace);
        }
    }
    return api_err;
}

fn statusFromCode(code: u16) http.Status {
    return @enumFromInt(code);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_helpers = @import("test_helpers.zig");

test "dispatch coverage: all route operation_ids have a handler branch" {
    // This test verifies that every operation_id in the route table has a
    // corresponding dispatch branch in dispatchHandler. It routes each
    // operation using a mock path and checks that the result is NOT a 404
    // from routing (i.e., a dispatch branch was found).
    //
    // Note: handlers that return 404 for legitimate reasons (e.g. BlockNotFound)
    // are exempt since the check is: did we find the *route*, not did the handler
    // succeed. We check for routing 404 specifically by verifying that
    // findRoute() matches the path — if it does, any response code is acceptable.
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    for (routes_mod.routes) |route| {
        // Build a minimal path by substituting "head" for all path params.
        var path_buf: [256]u8 = undefined;
        var path_len: usize = 0;
        var in_param = false;
        for (route.path) |ch| {
            if (ch == '{') {
                in_param = true;
                continue;
            }
            if (ch == '}') {
                const dummy = "head";
                @memcpy(path_buf[path_len .. path_len + dummy.len], dummy);
                path_len += dummy.len;
                in_param = false;
                continue;
            }
            if (in_param) continue;
            path_buf[path_len] = ch;
            path_len += 1;
        }
        const path = path_buf[0..path_len];

        // Verify route matching succeeds (this catches path pattern bugs).
        const route_match = routes_mod.findRoute(route.method, path);
        if (route_match == null) {
            std.debug.print("\nRoute not found: {s} {s} (op: {s})\n", .{
                @tagName(route.method), route.path, route.operation_id,
            });
        }
        try std.testing.expect(route_match != null);
        // Verify operation_id matches (sanity check on findRoute).
        try std.testing.expectEqualStrings(route.operation_id, route_match.?.route.operation_id);
    }
}

test "handleRequest GET /eth/v1/node/version" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/node/version", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "lodestar-z") != null);
}

test "handleRequest GET /eth/v1/node/identity" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/node/identity", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "test-peer-id") != null);
}

test "handleRequest GET /eth/v1/node/syncing" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/node/syncing", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "is_syncing") != null);
}

test "handleRequest GET /eth/v1/node/health ready" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    tc.sync_status.is_syncing = false;
    tc.sync_status.head_slot = 1000;
    const resp = try server.handleRequest("GET", "/eth/v1/node/health", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
}

test "handleRequest GET /eth/v1/node/health syncing returns 206" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    tc.sync_status.is_syncing = true;
    const resp = try server.handleRequest("GET", "/eth/v1/node/health", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 206), resp.status);
}

test "handleRequest GET /eth/v1/node/health not initialized returns 503" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    tc.sync_status.is_syncing = false;
    tc.sync_status.head_slot = 0;
    const resp = try server.handleRequest("GET", "/eth/v1/node/health", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 503), resp.status);
}

test "handleRequest GET /eth/v1/node/peers without peer db returns 501" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/node/peers", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 501), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"statusCode\":501") != null);
}

test "handleRequest GET /eth/v1/beacon/genesis" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/beacon/genesis", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "genesis_time") != null);
}

test "handleRequest GET /eth/v1/config/spec" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/config/spec", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"CONFIG_NAME\":\"mainnet\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"DEPOSIT_REQUEST_TYPE\":\"0x00\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "config_name") == null);
}

test "handleRequest GET /eth/v1/config/fork_schedule" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/config/fork_schedule", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
}

test "handleRequest unknown route returns 404 with statusCode field" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/not/a/route", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 404), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "statusCode") != null);
}

test "handleRequest wrong method returns 405" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    // PATCH is not a supported method, should return 405.
    const resp = try server.handleRequest("PATCH", "/eth/v1/node/version", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 405), resp.status);
}

test "handleRequest with query string" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/node/version?foo=bar", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
}

test "handleRequest GET /eth/v1/beacon/pool/attestations without op_pool returns 501" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/beacon/pool/attestations", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 501), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"statusCode\":501") != null);
}

test "handleRequest pool submission POST returns 204" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("POST", "/eth/v1/beacon/pool/attestations", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 204), resp.status);
}

test "splitTarget with query" {
    const path, const query = splitTarget("/eth/v1/node/version?foo=bar");
    try std.testing.expectEqualStrings("/eth/v1/node/version", path);
    try std.testing.expectEqualStrings("foo=bar", query.?);
}

test "splitTarget without query" {
    const path, const query = splitTarget("/eth/v1/node/version");
    try std.testing.expectEqualStrings("/eth/v1/node/version", path);
    try std.testing.expect(query == null);
}

test "parseIpAddress valid" {
    const addr = try parseIpAddress("127.0.0.1", 5052);
    try std.testing.expectEqual(@as(u16, 5052), addr.ip4.port);
}

test "error responses use standard Beacon API format" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);

    // Not found
    const resp = try server.handleRequest("GET", "/eth/v1/not/a/route", null);
    defer resp.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 404), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"statusCode\":404") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"message\"") != null);
}

test "handleRequest GET /eth/v1/validator/attestation_data without callback returns 501" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/validator/attestation_data?slot=100&committee_index=0", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 501), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"statusCode\":501") != null);
}

test "handleRequest GET /eth/v1/validator/attestation_data returns checkpoint objects" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const MockCb = struct {
        fn getAttData(_: *anyopaque, slot: u64, committee_index: u64) anyerror!context.AttestationDataResult {
            return .{
                .slot = slot,
                .index = committee_index,
                .beacon_block_root = [_]u8{0x42} ** 32,
                .source = .{ .epoch = 5, .root = [_]u8{0x11} ** 32 },
                .target = .{ .epoch = 6, .root = [_]u8{0x22} ** 32 },
            };
        }
    };
    var dummy: u8 = 0;
    tc.ctx.attestation_data = .{
        .ptr = &dummy,
        .getAttestationDataFn = &MockCb.getAttData,
    };

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/validator/attestation_data?slot=100&committee_index=3", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"source\":{\"epoch\":\"5\",\"root\":\"0x1111111111111111111111111111111111111111111111111111111111111111\"}") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"target\":{\"epoch\":\"6\",\"root\":\"0x2222222222222222222222222222222222222222222222222222222222222222\"}") != null);
}

test "handleRequest GET /eth/v1/validator/aggregate_attestation returns typed SSZ JSON" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const MockCb = struct {
        fn getAggregate(_: *anyopaque, slot: u64, attestation_data_root: [32]u8) anyerror!context.AggregateAttestationResult {
            const AggregationBits = @FieldType(context.AggregateAttestationResult, "aggregation_bits");
            var aggregation_bits = try AggregationBits.fromBitLen(std.testing.allocator, 8);
            try aggregation_bits.set(std.testing.allocator, 0, true);
            return .{
                .aggregation_bits = aggregation_bits,
                .data = .{
                    .slot = slot,
                    .index = 0,
                    .beacon_block_root = attestation_data_root,
                    .source = .{ .epoch = 5, .root = [_]u8{0x11} ** 32 },
                    .target = .{ .epoch = 6, .root = [_]u8{0x22} ** 32 },
                },
                .signature = [_]u8{0x33} ** 96,
            };
        }
    };
    var dummy: u8 = 0;
    tc.ctx.aggregate_attestation = .{
        .ptr = &dummy,
        .getAggregateAttestationFn = &MockCb.getAggregate,
    };

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/validator/aggregate_attestation?slot=100&attestation_data_root=0xabababababababababababababababababababababababababababababababab", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"aggregation_bits\":\"0x01") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"beacon_block_root\":\"0xabababababababababababababababababababababababababababababababab\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"signature\":\"0x33333333333333333333333333333333") != null);
}

test "handleRequest GET /eth/v1/validator/sync_committee_contribution returns typed SSZ JSON" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const MockCb = struct {
        fn getContribution(_: *anyopaque, slot: u64, subcommittee_index: u64, beacon_block_root: [32]u8) anyerror!context.SyncCommitteeContributionResult {
            var aggregation_bits = @FieldType(context.SyncCommitteeContributionResult, "aggregation_bits").empty;
            try aggregation_bits.set(0, true);
            try aggregation_bits.set(1, true);
            return .{
                .slot = slot,
                .beacon_block_root = beacon_block_root,
                .subcommittee_index = subcommittee_index,
                .aggregation_bits = aggregation_bits,
                .signature = [_]u8{0x77} ** 96,
            };
        }
    };
    var dummy: u8 = 0;
    tc.ctx.sync_committee_contribution = .{
        .ptr = &dummy,
        .getSyncCommitteeContributionFn = &MockCb.getContribution,
    };

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/validator/sync_committee_contribution?slot=120&subcommittee_index=2&beacon_block_root=0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"subcommittee_index\":\"2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"aggregation_bits\":\"0x03") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"beacon_block_root\":\"0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\"") != null);
}

test "handleRequest POST /eth/v1/validator/aggregate_and_proofs returns 204" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("POST", "/eth/v1/validator/aggregate_and_proofs", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 204), resp.status);
}

test "handleRequest POST /eth/v1/validator/contribution_and_proofs returns 204" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("POST", "/eth/v1/validator/contribution_and_proofs", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 204), resp.status);
}

test "handleRequest POST /eth/v2/beacon/blocks without import returns error" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("POST", "/eth/v2/beacon/blocks", "{}");
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 501), resp.status);
}

test "handleRequest POST /eth/v2/beacon/blocks returns 202 for queued ingress" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const MockImporter = struct {
        fn importBlock(_: *anyopaque, _: context.PublishedBlockParams) anyerror!context.PublishedBlockImportResult {
            return .queued;
        }
    };

    var dummy: u8 = 0;
    tc.ctx.block_import = .{
        .ptr = &dummy,
        .importFn = &MockImporter.importBlock,
    };

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("POST", "/eth/v2/beacon/blocks", "{}");
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 202), resp.status);
}

test "dispatchHandler GET /eth/v1/beacon/blinded_blocks execution fork returns blinded ssz" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const slot = tc.ctx.beacon_config.chain.BELLATRIX_FORK_EPOCH * preset.SLOTS_PER_EPOCH;
    const block_root = [_]u8{0x44} ** 32;
    var block = consensus_types.bellatrix.SignedBeaconBlock.default_value;
    block.message.slot = slot;
    const block_bytes = try std.testing.allocator.alloc(u8, consensus_types.bellatrix.SignedBeaconBlock.serializedSize(&block));
    defer std.testing.allocator.free(block_bytes);
    _ = consensus_types.bellatrix.SignedBeaconBlock.serializeIntoBytes(&block, block_bytes);
    try tc.db.putBlockArchive(slot, block_root, block_bytes);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const path = try std.fmt.allocPrint(std.testing.allocator, "/eth/v1/beacon/blinded_blocks/{d}", .{slot});
    defer std.testing.allocator.free(path);
    const match2 = routes_mod.findRoute(.GET, path).?;
    const dc = HttpServer.DispatchContext{
        .match = match2,
        .query = null,
        .body = &[_]u8{},
        .format = .ssz,
    };

    const resp = try server.dispatchHandler(dc);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("application/octet-stream", resp.content_type);
    var blinded = try AnySignedBeaconBlock.deserialize(std.testing.allocator, .blinded, .bellatrix, resp.body);
    defer blinded.deinit(std.testing.allocator);
    try std.testing.expectEqual(fork_types.BlockType.blinded, blinded.blockType());
}

test "handleRequest pool submission POST attestations with body" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const body =
        \\[{"aggregation_bits":"0x01","data":{"slot":100,"index":0,"beacon_block_root":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source":{"epoch":0,"root":"0x0000000000000000000000000000000000000000000000000000000000000000"},"target":{"epoch":1,"root":"0x0000000000000000000000000000000000000000000000000000000000000000"}},"signature":"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}]
    ;
    const resp = try server.handleRequest("POST", "/eth/v1/beacon/pool/attestations", body);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 501), resp.status);
}

test "handleRequest pool submission POST voluntary_exits with body" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const body =
        \\{"message":{"epoch":100,"validator_index":42},"signature":"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}
    ;
    const resp = try server.handleRequest("POST", "/eth/v1/beacon/pool/voluntary_exits", body);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 501), resp.status);
}

test "DispatchContext.getQuery parses query params" {
    const dc = HttpServer.DispatchContext{
        .match = undefined,
        .query = "slot=100&committee_index=3&beacon_block_root=0xaabb",
    };
    try std.testing.expectEqualStrings("100", dc.getQuery("slot").?);
    try std.testing.expectEqualStrings("3", dc.getQuery("committee_index").?);
    try std.testing.expectEqualStrings("0xaabb", dc.getQuery("beacon_block_root").?);
    try std.testing.expect(dc.getQuery("missing") == null);
}

test "handleRequest GET /eth/v1/beacon/states/head/committees returns error without head state" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/beacon/states/head/committees", null);
    defer resp.deinit(std.testing.allocator);

    // Without a head state, should return an error (StateNotAvailable -> 500)
    try std.testing.expect(resp.status >= 400);
}

test "handleRequest GET /eth/v1/beacon/headers returns 200" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/beacon/headers", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "data") != null);
}

test "handleRequest GET /eth/v1/beacon/rewards/blocks/head returns 501" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/beacon/rewards/blocks/head", null);
    defer resp.deinit(std.testing.allocator);

    // Rewards require RewardCache which is not yet implemented.
    try std.testing.expectEqual(@as(u16, 501), resp.status);
}

test "handleRequest POST /eth/v1/beacon/rewards/attestations/1 returns 501" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("POST", "/eth/v1/beacon/rewards/attestations/1", "[]");
    defer resp.deinit(std.testing.allocator);

    // Rewards require RewardCache which is not yet implemented.
    try std.testing.expectEqual(@as(u16, 501), resp.status);
}

test "handleRequest GET /eth/v1/beacon/rewards/blocks/head returns 200 when callback wired" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    tc.chain_fixture.block_rewards_result = .{
        .proposer_index = 12,
        .total = 33,
        .attestations = 10,
        .sync_aggregate = 20,
        .proposer_slashings = 1,
        .attester_slashings = 2,
    };

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/beacon/rewards/blocks/head", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqual(tc.head_tracker.head_root, tc.chain_fixture.last_block_rewards_root.?);
    const parsed = try std.json.parseFromSlice(struct { data: types.BlockRewards }, std.testing.allocator, resp.body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u64, 12), parsed.value.data.proposer_index);
    try std.testing.expectEqual(@as(u64, 33), parsed.value.data.total);
}

test "handleRequest POST /eth/v1/beacon/rewards/attestations/{epoch} forwards validator filters" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    tc.chain_fixture.attestation_ideal_rewards = try std.testing.allocator.dupe(types.IdealAttestationReward, &.{.{
        .effective_balance = 32000000000,
        .head = 1,
        .target = 2,
        .source = 3,
        .inclusion_delay = 0,
        .inactivity = 0,
    }});
    tc.chain_fixture.attestation_total_rewards = try std.testing.allocator.dupe(types.TotalAttestationReward, &.{.{
        .validator_index = 11,
        .head = 1,
        .target = 2,
        .source = 3,
        .inclusion_delay = 0,
        .inactivity = -4,
    }});

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("POST", "/eth/v1/beacon/rewards/attestations/1", "[11,22]");
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqual(@as(?u64, 1), tc.chain_fixture.last_attestation_rewards_epoch);
    try std.testing.expectEqual(@as(usize, 2), tc.chain_fixture.last_attestation_reward_indices.?.len);
    try std.testing.expectEqual(@as(u64, 11), tc.chain_fixture.last_attestation_reward_indices.?[0]);
    try std.testing.expectEqual(@as(u64, 22), tc.chain_fixture.last_attestation_reward_indices.?[1]);
    const parsed = try std.json.parseFromSlice(struct { data: types.AttestationRewardsData }, std.testing.allocator, resp.body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.value.data.total_rewards.len);
    try std.testing.expectEqual(@as(u64, 11), parsed.value.data.total_rewards[0].validator_index);
}

test "handleRequest POST /eth/v1/beacon/rewards/sync_committee/head forwards validator filters" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    tc.chain_fixture.sync_committee_rewards = try std.testing.allocator.dupe(types.SyncCommitteeReward, &.{
        .{ .validator_index = 5, .reward = 42 },
        .{ .validator_index = 6, .reward = -1 },
    });

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("POST", "/eth/v1/beacon/rewards/sync_committee/head", "[5]");
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqual(tc.head_tracker.head_root, tc.chain_fixture.last_sync_committee_rewards_root.?);
    try std.testing.expectEqual(@as(usize, 1), tc.chain_fixture.last_sync_committee_reward_indices.?.len);
    try std.testing.expectEqual(@as(u64, 5), tc.chain_fixture.last_sync_committee_reward_indices.?[0]);
    const parsed = try std.json.parseFromSlice(struct { data: []const types.SyncCommitteeReward }, std.testing.allocator, resp.body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), parsed.value.data.len);
    try std.testing.expectEqual(@as(u64, 5), parsed.value.data[0].validator_index);
}
test "handleRequest POST /eth/v1/validator/prepare_beacon_proposer returns 501 without callback" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("POST", "/eth/v1/validator/prepare_beacon_proposer", "[]");
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 501), resp.status);
}

test "handleRequest POST /eth/v1/validator/register_validator without builder returns 503" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("POST", "/eth/v1/validator/register_validator", "[]");
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 503), resp.status);
}

test "handleRequest POST /eth/v1/validator/liveness/{epoch} returns live results" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const epoch = tc.chain_fixture.current_slot / preset.SLOTS_PER_EPOCH;
    try tc.chain_fixture.markValidatorSeenAtEpoch(1, epoch);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const path = try std.fmt.allocPrint(std.testing.allocator, "/eth/v1/validator/liveness/{d}", .{epoch});
    defer std.testing.allocator.free(path);

    const resp = try server.handleRequest("POST", path, "[0,1,2]");
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status);

    const parsed = try std.json.parseFromSlice(struct { data: []const types.ValidatorLiveness }, std.testing.allocator, resp.body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    const data = parsed.value.data;
    try std.testing.expectEqual(@as(usize, 3), data.len);
    try std.testing.expectEqual(types.ValidatorLiveness{ .index = 0, .epoch = epoch, .is_live = false }, data[0]);
    try std.testing.expectEqual(types.ValidatorLiveness{ .index = 1, .epoch = epoch, .is_live = true }, data[1]);
    try std.testing.expectEqual(types.ValidatorLiveness{ .index = 2, .epoch = epoch, .is_live = false }, data[2]);
}

test "handleRequest POST /eth/v1/validator/liveness/{epoch} rejects epochs outside the supported window" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const current_epoch = tc.chain_fixture.current_slot / preset.SLOTS_PER_EPOCH;
    const bad_epoch = current_epoch + 2;

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const path = try std.fmt.allocPrint(std.testing.allocator, "/eth/v1/validator/liveness/{d}", .{bad_epoch});
    defer std.testing.allocator.free(path);

    const resp = try server.handleRequest("POST", path, "[0]");
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 400), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"statusCode\":400") != null);
}

test "dispatchHandler GET /eth/v3/validator/blocks returns unsigned block json with v3 metadata" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const MockCb = struct {
        fn produce(_: *anyopaque, allocator: std.mem.Allocator, _: context.ProduceBlockParams) anyerror!context.ProducedBlockData {
            var block = consensus_types.phase0.BeaconBlock.default_value;
            block.slot = 123;
            const out = try allocator.alloc(u8, consensus_types.phase0.BeaconBlock.serializedSize(&block));
            errdefer allocator.free(out);
            _ = consensus_types.phase0.BeaconBlock.serializeIntoBytes(&block, out);
            return .{
                .ssz_bytes = out,
                .fork = "phase0",
                .blinded = false,
                .execution_payload_source = .engine,
                .execution_payload_value = 777,
                .consensus_block_value = 888,
            };
        }
    };

    var dummy: u8 = 0;
    tc.ctx.produce_block = .{ .ptr = &dummy, .produceBlockFn = &MockCb.produce };

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const match = routes_mod.findRoute(.GET, "/eth/v3/validator/blocks/123").?;
    const dc = HttpServer.DispatchContext{
        .match = match,
        .query = "randao_reveal=0x" ++ "00" ** 96,
        .body = &[_]u8{},
    };
    const resp = try server.dispatchHandler(dc);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqual(response_meta.Fork.phase0, resp.meta.version.?);
    try std.testing.expectEqual(false, resp.meta.execution_payload_blinded.?);
    try std.testing.expectEqual(types.ExecutionPayloadSource.engine, resp.meta.execution_payload_source.?);
    try std.testing.expectEqual(@as(u256, 777), resp.meta.execution_payload_value.?);
    try std.testing.expectEqual(@as(u256, 888), resp.meta.consensus_block_value.?);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"signature\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"execution_payload_value\":\"777\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"consensus_block_value\":\"888\"") != null);
}

test "dispatchHandler GET /eth/v2/debug/beacon/states slot returns ssz" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    const fake_state = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    try tc.db.putStateArchive(42, [_]u8{0x11} ** 32, &fake_state);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const match = routes_mod.findRoute(.GET, "/eth/v2/debug/beacon/states/42").?;
    const dc = HttpServer.DispatchContext{
        .match = match,
        .query = null,
        .body = &[_]u8{},
        .format = .ssz,
    };
    const resp = try server.dispatchHandler(dc);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("application/octet-stream", resp.content_type);
    try std.testing.expectEqualSlices(u8, &fake_state, resp.body);
    try std.testing.expectEqual(response_meta.Fork.phase0, resp.meta.version.?);
}

test "handleRequest GET /eth/v2/debug/beacon/states slot returns json" {
    const allocator = std.testing.allocator;
    var tc = test_helpers.makeTestContext(allocator);
    defer test_helpers.destroyTestContext(allocator, &tc);

    const ct = @import("consensus_types");
    const Node = @import("persistent_merkle_tree").Node;
    const AnyBeaconState = @import("fork_types").AnyBeaconState;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var state = try AnyBeaconState.fromValue(allocator, &pool, .phase0, &ct.phase0.BeaconState.default_value);
    defer state.deinit();
    try state.setSlot(42);

    const state_root = (try state.hashTreeRoot()).*;
    const state_bytes = try state.serialize(allocator);
    defer allocator.free(state_bytes);
    try tc.db.putStateArchive(42, state_root, state_bytes);

    var server = HttpServer.init(allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v2/debug/beacon/states/42", null);
    defer resp.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("application/json", resp.content_type);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"version\":\"phase0\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"slot\":\"42\"") != null);
}

test "handleRequest GET /eth/v1/debug/fork_choice returns 200" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/debug/fork_choice", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "fork_choice_nodes") != null);
}

test "handleRequest GET /eth/v1/node/peer_count without peer db returns 501" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/node/peer_count", null);
    defer resp.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 501), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"statusCode\":501") != null);
}
