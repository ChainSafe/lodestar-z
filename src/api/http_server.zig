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
const http = std.http;
const net = std.Io.net;
const Io = std.Io;
const Allocator = std.mem.Allocator;

const api_mod = @import("root.zig");
const routes_mod = @import("routes.zig");
const response_mod = @import("response.zig");
const handlers = @import("handlers/root.zig");
const context = @import("context.zig");
const ApiContext = context.ApiContext;
const types = @import("types.zig");

const log = std.log.scoped(.http_server);

/// CORS headers applied to every response.
const cors_headers: []const http.Header = &.{
    .{ .name = "Access-Control-Allow-Origin", .value = "*" },
    .{ .name = "Access-Control-Allow-Methods", .value = "GET, POST, OPTIONS" },
    .{ .name = "Access-Control-Allow-Headers", .value = "Content-Type, Accept" },
};

pub const HttpServer = struct {
    allocator: Allocator,
    api_context: *ApiContext,
    address: []const u8,
    port: u16,

    pub fn init(
        allocator: Allocator,
        api_context: *ApiContext,
        address: []const u8,
        port: u16,
    ) HttpServer {
        return .{
            .allocator = allocator,
            .api_context = api_context,
            .address = address,
            .port = port,
        };
    }

    /// Start serving HTTP requests (blocking).
    ///
    /// Listens on the configured address:port, accepts connections, parses
    /// HTTP requests via `std.http.Server`, and dispatches to Beacon API
    /// handlers.
    pub fn serve(self: *HttpServer, io: Io) !void {
        const ip = try parseIpAddress(self.address, self.port);
        var tcp_server = try ip.listen(io, .{ .reuse_address = true });
        defer tcp_server.deinit(io);

        log.info("Beacon API listening on {s}:{d}", .{ self.address, self.port });

        while (true) {
            const stream = tcp_server.accept(io) catch |err| {
                log.err("accept failed: {s}", .{@errorName(err)});
                continue;
            };
            self.handleConnection(io, stream);
        }
    }

    fn handleConnection(self: *HttpServer, io: Io, stream: net.Stream) void {
        defer {
            var copy = stream;
            copy.close(io);
        }

        var send_buf: [8192]u8 = undefined;
        var recv_buf: [8192]u8 = undefined;
        var conn_reader = stream.reader(io, &recv_buf);
        var conn_writer = stream.writer(io, &send_buf);
        var server: http.Server = .init(&conn_reader.interface, &conn_writer.interface);

        // Handle requests on this connection (keep-alive support).
        while (true) {
            var request = server.receiveHead() catch |err| switch (err) {
                error.HttpConnectionClosing => return,
                else => {
                    log.err("receive head failed: {s}", .{@errorName(err)});
                    return;
                },
            };
            self.handleHttpRequest(&request) catch |err| {
                log.err("handle request failed: {s}", .{@errorName(err)});
                return;
            };
        }
    }

    fn handleHttpRequest(self: *HttpServer, request: *http.Server.Request) !void {
        const target = request.head.target;

        // Split target into path and query.
        const path, _ = splitTarget(target);

        // CORS preflight.
        if (request.head.method == .OPTIONS) {
            try request.respond("", .{
                .status = .no_content,
                .extra_headers = cors_headers,
            });
            return;
        }

        // Map std.http.Method to our route method.
        const route_method: routes_mod.HttpMethod = switch (request.head.method) {
            .GET => .GET,
            .POST => .POST,
            else => {
                try respondError(request, .method_not_allowed, "Method not allowed");
                return;
            },
        };

        // Determine Accept header for content negotiation.
        const accept_header = findHeader(request);

        // Route lookup.
        const match = routes_mod.findRoute(route_method, path) orelse {
            try respondError(request, .not_found, "Route not found");
            return;
        };

        // Dispatch to handler and get JSON bytes.
        const result = self.dispatchHandler(match) catch |err| {
            try respondApiError(request, err);
            return;
        };
        defer self.allocator.free(result.body);

        // Content-Type based on accept header and SSZ support.
        const content_type = if (match.route.supports_ssz and
            types.ContentType.fromAcceptHeader(accept_header) == .ssz)
            "application/octet-stream"
        else
            "application/json";

        // Build response headers: content-type + CORS.
        const extra_headers: []const http.Header = &.{
            .{ .name = "Content-Type", .value = content_type },
            .{ .name = "Access-Control-Allow-Origin", .value = "*" },
            .{ .name = "Access-Control-Allow-Methods", .value = "GET, POST, OPTIONS" },
            .{ .name = "Access-Control-Allow-Headers", .value = "Content-Type, Accept" },
        };

        try request.respond(result.body, .{
            .status = statusFromCode(result.status),
            .extra_headers = extra_headers,
        });
    }

    /// Dispatch result from a handler.
    pub const HandlerResult = struct {
        status: u16,
        body: []const u8,
    };

    /// Route to the correct handler and encode the response as JSON.
    fn dispatchHandler(
        self: *HttpServer,
        match: routes_mod.RouteMatch,
    ) !HandlerResult {
        const op = match.route.operation_id;
        const alloc = self.allocator;
        const ctx = self.api_context;

        // Node endpoints.
        if (std.mem.eql(u8, op, "getNodeIdentity")) {
            const resp = handlers.node.getIdentity(ctx);
            const body = try response_mod.encodeJsonResponse(alloc, types.NodeIdentity, resp);
            return .{ .status = 200, .body = body };
        }
        if (std.mem.eql(u8, op, "getNodeVersion")) {
            const resp = handlers.node.getVersion(ctx);
            const body = try response_mod.encodeJsonResponse(alloc, types.NodeVersion, resp);
            return .{ .status = 200, .body = body };
        }
        if (std.mem.eql(u8, op, "getSyncing")) {
            const resp = handlers.node.getSyncing(ctx);
            const body = try response_mod.encodeJsonResponse(alloc, types.SyncingStatus, resp);
            return .{ .status = 200, .body = body };
        }
        if (std.mem.eql(u8, op, "getHealth")) {
            const health = handlers.node.getHealth(ctx);
            const status = @intFromEnum(health);
            // Health endpoint returns just the status code, no body.
            const body = try std.fmt.allocPrint(alloc, "{{\"status\":{d}}}", .{status});
            return .{ .status = status, .body = body };
        }
        if (std.mem.eql(u8, op, "getPeers")) {
            const resp = handlers.node.getPeers(ctx);
            const body = try response_mod.encodeJsonResponse(alloc, []const types.PeerInfo, resp);
            return .{ .status = 200, .body = body };
        }

        // Beacon endpoints.
        if (std.mem.eql(u8, op, "getGenesis")) {
            const resp = handlers.beacon.getGenesis(ctx);
            const body = try response_mod.encodeJsonResponse(alloc, types.GenesisData, resp);
            return .{ .status = 200, .body = body };
        }
        if (std.mem.eql(u8, op, "getBlockHeader")) {
            const block_id_str = match.getParam("block_id") orelse return error.InvalidBlockId;
            const block_id = try types.BlockId.parse(block_id_str);
            const resp = try handlers.beacon.getBlockHeader(ctx, block_id);
            const body = try response_mod.encodeJsonResponse(alloc, types.BlockHeaderData, resp);
            return .{ .status = 200, .body = body };
        }
        if (std.mem.eql(u8, op, "getBlockV2")) {
            const block_id_str = match.getParam("block_id") orelse return error.InvalidBlockId;
            const block_id = try types.BlockId.parse(block_id_str);
            const result = try handlers.beacon.getBlock(ctx, block_id);
            // For simplicity, return SSZ bytes wrapped in a JSON envelope with hex encoding.
            // A full implementation would handle content negotiation here.
            const body = try std.fmt.allocPrint(alloc, "{{\"version\":\"phase0\",\"data\":\"{s}\"}}", .{result.data});
            return .{ .status = 200, .body = body };
        }
        if (std.mem.eql(u8, op, "getStateValidatorV2")) {
            // Requires state_id and validator_id path params.
            const state_id_str = match.getParam("state_id") orelse return error.InvalidStateId;
            const validator_id_str = match.getParam("validator_id") orelse return error.InvalidValidatorId;
            const state_id = try types.StateId.parse(state_id_str);
            const validator_id = try types.ValidatorId.parse(validator_id_str);
            const resp = try handlers.beacon.getValidator(ctx, state_id, validator_id);
            const body = try response_mod.encodeJsonResponse(alloc, types.ValidatorData, resp);
            return .{ .status = 200, .body = body };
        }
        if (std.mem.eql(u8, op, "getStateValidatorsV2")) {
            const state_id_str = match.getParam("state_id") orelse return error.InvalidStateId;
            const state_id = try types.StateId.parse(state_id_str);
            const resp = try handlers.beacon.getValidators(ctx, state_id, .{});
            const body = try response_mod.encodeJsonResponse(alloc, []const types.ValidatorData, resp);
            return .{ .status = 200, .body = body };
        }
        if (std.mem.eql(u8, op, "getStateRoot")) {
            const state_id_str = match.getParam("state_id") orelse return error.InvalidStateId;
            const state_id = try types.StateId.parse(state_id_str);
            const resp = try handlers.beacon.getStateRoot(ctx, state_id);
            const body = try response_mod.encodeJsonResponse(alloc, [32]u8, resp);
            return .{ .status = 200, .body = body };
        }
        if (std.mem.eql(u8, op, "getStateFork")) {
            const state_id_str = match.getParam("state_id") orelse return error.InvalidStateId;
            const state_id = try types.StateId.parse(state_id_str);
            const resp = try handlers.beacon.getStateFork(ctx, state_id);
            const body = try response_mod.encodeJsonResponse(alloc, types.ForkData, resp);
            return .{ .status = 200, .body = body };
        }
        if (std.mem.eql(u8, op, "getFinalityCheckpoints")) {
            const state_id_str = match.getParam("state_id") orelse return error.InvalidStateId;
            const state_id = try types.StateId.parse(state_id_str);
            const resp = try handlers.beacon.getFinalityCheckpoints(ctx, state_id);
            const body = try response_mod.encodeJsonResponse(alloc, types.FinalityCheckpoints, resp);
            return .{ .status = 200, .body = body };
        }
        if (std.mem.eql(u8, op, "publishBlockV2")) {
            // POST endpoint — block publishing is a stub for now.
            return .{
                .status = 200,
                .body = try alloc.dupe(u8, "{\"status\":\"accepted\"}"),
            };
        }

        // Config endpoints.
        if (std.mem.eql(u8, op, "getSpec")) {
            const resp = handlers.config.getSpec(ctx);
            const body = try response_mod.encodeJsonResponse(alloc, handlers.config.SpecData, resp);
            return .{ .status = 200, .body = body };
        }
        if (std.mem.eql(u8, op, "getForkSchedule")) {
            const resp = handlers.config.getForkSchedule(ctx);
            const body = try response_mod.encodeJsonResponse(alloc, []const types.ForkScheduleEntry, resp);
            return .{ .status = 200, .body = body };
        }

        return error.NotImplemented;
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
        _ = body;

        const route_method: routes_mod.HttpMethod = if (std.mem.eql(u8, method, "GET"))
            .GET
        else if (std.mem.eql(u8, method, "POST"))
            .POST
        else
            return .{
                .status = 405,
                .status_text = "Method Not Allowed",
                .content_type = "application/json",
                .body = "{\"message\":\"Method not allowed\"}",
            };

        // OPTIONS (CORS preflight).
        if (std.mem.eql(u8, method, "OPTIONS")) {
            return .{
                .status = 204,
                .status_text = "No Content",
                .content_type = "text/plain",
                .body = "",
            };
        }

        const clean_path, _ = splitTarget(path);

        const match = routes_mod.findRoute(route_method, clean_path) orelse {
            return .{
                .status = 404,
                .status_text = "Not Found",
                .content_type = "application/json",
                .body = "{\"message\":\"Route not found\"}",
            };
        };

        const result = self.dispatchHandler(match) catch |err| {
            return apiErrorResponse(err);
        };

        return .{
            .status = result.status,
            .status_text = "OK",
            .content_type = "application/json",
            .body = result.body,
        };
    }

    pub const HttpResponse = struct {
        status: u16,
        status_text: []const u8,
        content_type: []const u8,
        body: []const u8,
    };
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Split a request target into path and optional query string.
fn splitTarget(target: []const u8) struct { []const u8, ?[]const u8 } {
    if (std.mem.indexOfScalar(u8, target, '?')) |idx| {
        return .{ target[0..idx], target[idx + 1 ..] };
    }
    return .{ target, null };
}

/// Parse an IP address string (IPv4 only for now).
fn parseIpAddress(addr: []const u8, port: u16) !net.IpAddress {
    return .{ .ip4 = net.Ip4Address.parse(addr, port) catch return error.AddressFamilyUnsupported };
}

/// Find the Accept header value from the request.
fn findHeader(request: *http.Server.Request) ?[]const u8 {
    var it = request.iterateHeaders();
    while (it.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "accept")) {
            return header.value;
        }
    }
    return null;
}

/// Map API errors to HTTP error responses.
fn respondError(request: *http.Server.Request, status: http.Status, message: []const u8) !void {
    try request.respond(message, .{
        .status = status,
        .extra_headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "Access-Control-Allow-Origin", .value = "*" },
        },
    });
}

fn respondApiError(request: *http.Server.Request, err: anyerror) !void {
    const status: http.Status, const message: []const u8 = switch (err) {
        error.BlockNotFound, error.StateNotFound, error.ValidatorNotFound, error.SlotNotFound => .{
            .not_found, "{\"message\":\"Resource not found\"}",
        },
        error.InvalidBlockId, error.InvalidStateId, error.InvalidValidatorId => .{
            .bad_request, "{\"message\":\"Invalid identifier\"}",
        },
        error.NotImplemented => .{
            .not_implemented, "{\"message\":\"Not implemented\"}",
        },
        else => .{
            .internal_server_error, "{\"message\":\"Internal server error\"}",
        },
    };
    try respondError(request, status, message);
}

fn apiErrorResponse(err: anyerror) HttpServer.HttpResponse {
    const status: u16, const message: []const u8 = switch (err) {
        error.BlockNotFound, error.StateNotFound, error.ValidatorNotFound, error.SlotNotFound => .{
            404, "{\"message\":\"Resource not found\"}",
        },
        error.InvalidBlockId, error.InvalidStateId, error.InvalidValidatorId => .{
            400, "{\"message\":\"Invalid identifier\"}",
        },
        error.NotImplemented => .{
            501, "{\"message\":\"Not implemented\"}",
        },
        else => .{
            500, "{\"message\":\"Internal server error\"}",
        },
    };
    return .{
        .status = status,
        .status_text = "Error",
        .content_type = "application/json",
        .body = message,
    };
}

fn statusFromCode(code: u16) http.Status {
    return @enumFromInt(code);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_helpers = @import("test_helpers.zig");

test "handleRequest GET /eth/v1/node/version" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/node/version", null);
    defer if (resp.status == 200) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "lodestar-z") != null);
}

test "handleRequest GET /eth/v1/node/identity" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/node/identity", null);
    defer if (resp.status == 200) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "test-peer-id") != null);
}

test "handleRequest GET /eth/v1/node/syncing" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/node/syncing", null);
    defer if (resp.status == 200) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "is_syncing") != null);
}

test "handleRequest GET /eth/v1/node/health" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/node/health", null);
    defer if (resp.status == 200) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
}

test "handleRequest GET /eth/v1/node/peers" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/node/peers", null);
    defer if (resp.status == 200) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
}

test "handleRequest GET /eth/v1/beacon/genesis" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/beacon/genesis", null);
    defer if (resp.status == 200) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "genesis_time") != null);
}

test "handleRequest GET /eth/v1/config/spec" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/config/spec", null);
    defer if (resp.status == 200) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "config_name") != null);
}

test "handleRequest GET /eth/v1/config/fork_schedule" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/config/fork_schedule", null);
    defer if (resp.status == 200) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
}

test "handleRequest unknown route returns 404" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/not/a/route", null);

    try std.testing.expectEqual(@as(u16, 404), resp.status);
}

test "handleRequest wrong method returns 405" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("DELETE", "/eth/v1/node/version", null);

    try std.testing.expectEqual(@as(u16, 405), resp.status);
}

test "handleRequest with query string" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/node/version?foo=bar", null);
    defer if (resp.status == 200) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
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
