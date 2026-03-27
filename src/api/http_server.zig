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
const content_negotiation = @import("content_negotiation.zig");
const response_meta = @import("response_meta.zig");
const error_response = @import("error_response.zig");
const handler_result_mod = @import("handler_result.zig");
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
                try respondApiError(request, .{
                    .code = .method_not_allowed,
                    .message = "Method not allowed",
                });
                return;
            },
        };

        // Route lookup.
        const match = routes_mod.findRoute(route_method, path) orelse {
            try respondApiError(request, .{
                .code = .not_found,
                .message = "Route not found",
            });
            return;
        };

        // Content negotiation.
        const accept = findHeader(request, "accept");
        const format = switch (content_negotiation.parseAcceptHeader(accept)) {
            .absent => content_negotiation.WireFormat.json,
            .format => |f| f,
            .not_acceptable => {
                try respondApiError(request, .{
                    .code = .not_acceptable,
                    .message = "Supported: application/json, application/octet-stream",
                });
                return;
            },
        };

        // For SSZ requests, ensure the route supports SSZ.
        if (format == .ssz and !match.route.supports_ssz) {
            try respondApiError(request, .{
                .code = .not_acceptable,
                .message = "This endpoint does not support SSZ responses",
            });
            return;
        }

        // Dispatch to handler and get response body.
        const result = self.dispatchHandler(match) catch |err| {
            try respondApiError(request, error_response.fromZigError(err));
            return;
        };
        defer self.allocator.free(result.body);

        // Build response headers: content-type + CORS + metadata.
        var extra_hdrs_buf: [16]http.Header = undefined;
        var extra_count: usize = 0;

        extra_hdrs_buf[extra_count] = .{ .name = "Content-Type", .value = result.content_type };
        extra_count += 1;
        extra_hdrs_buf[extra_count] = .{ .name = "Access-Control-Allow-Origin", .value = "*" };
        extra_count += 1;
        extra_hdrs_buf[extra_count] = .{ .name = "Access-Control-Allow-Methods", .value = "GET, POST, OPTIONS" };
        extra_count += 1;
        extra_hdrs_buf[extra_count] = .{ .name = "Access-Control-Allow-Headers", .value = "Content-Type, Accept" };
        extra_count += 1;

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
    }

    /// Dispatch result from a handler.
    pub const HandlerResult = struct {
        status: u16,
        content_type: []const u8,
        body: []const u8,
        meta: response_meta.ResponseMeta = .{},
    };

    /// Write a JSON body for a HandlerResult(T) and return a HandlerResult for the server.
    fn makeJsonResult(
        self: *HttpServer,
        comptime T: type,
        result: handler_result_mod.HandlerResult(T),
    ) !HandlerResult {
        const status = if (result.status != 0) result.status else 200;
        const body = try response_mod.encodeHandlerResultJson(self.allocator, T, result);
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

    /// Route to the correct handler and encode the response.
    fn dispatchHandler(
        self: *HttpServer,
        match: routes_mod.RouteMatch,
    ) !HandlerResult {
        const op = match.route.operation_id;
        const alloc = self.allocator;
        const ctx = self.api_context;

        // Node endpoints.
        if (std.mem.eql(u8, op, "getNodeIdentity")) {
            const result = handlers.node.getIdentity(ctx);
            return self.makeJsonResult(types.NodeIdentity, result);
        }
        if (std.mem.eql(u8, op, "getNodeVersion")) {
            const result = handlers.node.getVersion(ctx);
            return self.makeJsonResult(types.NodeVersion, result);
        }
        if (std.mem.eql(u8, op, "getSyncing")) {
            const result = handlers.node.getSyncing(ctx);
            return self.makeJsonResult(types.SyncingStatus, result);
        }
        if (std.mem.eql(u8, op, "getHealth")) {
            const result = handlers.node.getHealth(ctx);
            // Health returns void with status override: 200/206/503
            return self.makeVoidResult(result);
        }
        if (std.mem.eql(u8, op, "getPeers")) {
            const result = handlers.node.getPeers(ctx);
            return self.makeJsonResult([]const types.PeerInfo, result);
        }
        if (std.mem.eql(u8, op, "getPeerCount")) {
            const result = handlers.node.getPeerCount(ctx);
            return self.makeJsonResult(types.PeerCount, result);
        }

        // Beacon endpoints.
        if (std.mem.eql(u8, op, "getGenesis")) {
            const resp = handlers.beacon.getGenesis(ctx);
            return self.makeJsonResult(types.GenesisData, resp);
        }
        if (std.mem.eql(u8, op, "getBlockHeader")) {
            const block_id_str = match.getParam("block_id") orelse return error.InvalidBlockId;
            const block_id = try types.BlockId.parse(block_id_str);
            const result = try handlers.beacon.getBlockHeader(ctx, block_id);
            return self.makeJsonResult(types.BlockHeaderData, result);
        }
        if (std.mem.eql(u8, op, "getBlockV2")) {
            const block_id_str = match.getParam("block_id") orelse return error.InvalidBlockId;
            const block_id = try types.BlockId.parse(block_id_str);
            const block_result = try handlers.beacon.getBlock(ctx, block_id);
            // SSZ bytes available — wrap them in a HandlerResult for dispatch
            const handler_res = handler_result_mod.HandlerResult([]const u8){
                .data = block_result.data,
                .meta = .{
                    .version = block_result.fork_name,
                    .execution_optimistic = block_result.execution_optimistic,
                    .finalized = block_result.finalized,
                },
                .ssz_bytes = block_result.data, // SSZ bytes already in data
            };
            const body = try response_mod.encodeHandlerResultJson(alloc, []const u8, handler_res);
            return .{
                .status = 200,
                .content_type = "application/json",
                .body = body,
                .meta = handler_res.meta,
            };
        }
        if (std.mem.eql(u8, op, "getStateValidatorV2")) {
            const state_id_str = match.getParam("state_id") orelse return error.InvalidStateId;
            const validator_id_str = match.getParam("validator_id") orelse return error.InvalidValidatorId;
            const state_id = try types.StateId.parse(state_id_str);
            const validator_id = try types.ValidatorId.parse(validator_id_str);
            const result = try handlers.beacon.getValidator(ctx, state_id, validator_id);
            return self.makeJsonResult(types.ValidatorData, result);
        }
        if (std.mem.eql(u8, op, "getStateValidatorsV2")) {
            const state_id_str = match.getParam("state_id") orelse return error.InvalidStateId;
            const state_id = try types.StateId.parse(state_id_str);
            const handler_res = try handlers.beacon.getValidators(ctx, state_id, .{});
            defer alloc.free(handler_res.data);
            return self.makeJsonResult([]const types.ValidatorData, handler_res);
        }
        if (std.mem.eql(u8, op, "getStateRoot")) {
            const state_id_str = match.getParam("state_id") orelse return error.InvalidStateId;
            const state_id = try types.StateId.parse(state_id_str);
            const result = try handlers.beacon.getStateRoot(ctx, state_id);
            return self.makeJsonResult([32]u8, result);
        }
        if (std.mem.eql(u8, op, "getStateFork")) {
            const state_id_str = match.getParam("state_id") orelse return error.InvalidStateId;
            const state_id = try types.StateId.parse(state_id_str);
            const result = try handlers.beacon.getStateFork(ctx, state_id);
            return self.makeJsonResult(types.ForkData, result);
        }
        if (std.mem.eql(u8, op, "getFinalityCheckpoints")) {
            const state_id_str = match.getParam("state_id") orelse return error.InvalidStateId;
            const state_id = try types.StateId.parse(state_id_str);
            const result = try handlers.beacon.getFinalityCheckpoints(ctx, state_id);
            return self.makeJsonResult(types.FinalityCheckpoints, result);
        }
        if (std.mem.eql(u8, op, "publishBlockV2")) {
            // TODO: read request body (JSON or SSZ based on Content-Type)
            const result = try handlers.beacon.submitBlock(ctx, &[_]u8{});
            return self.makeVoidResult(result);
        }

        // Pool GET endpoints.
        if (std.mem.eql(u8, op, "getPoolAttestations")) {
            const result = handlers.beacon.getPoolAttestations(ctx);
            return self.makeJsonResult(types.PoolCounts, result);
        }
        if (std.mem.eql(u8, op, "getPoolVoluntaryExits")) {
            const result = handlers.beacon.getPoolVoluntaryExits(ctx);
            return self.makeJsonResult(usize, result);
        }
        if (std.mem.eql(u8, op, "getPoolProposerSlashings")) {
            const result = handlers.beacon.getPoolProposerSlashings(ctx);
            return self.makeJsonResult(usize, result);
        }
        if (std.mem.eql(u8, op, "getPoolAttesterSlashings")) {
            const result = handlers.beacon.getPoolAttesterSlashings(ctx);
            return self.makeJsonResult(usize, result);
        }
        if (std.mem.eql(u8, op, "getPoolBlsToExecutionChanges")) {
            const result = handlers.beacon.getPoolBlsToExecutionChanges(ctx);
            return self.makeJsonResult(usize, result);
        }

        // Pool POST endpoints (stubs — accept body, return 200).
        if (std.mem.eql(u8, op, "submitPoolAttestations")) {
            const result = try handlers.beacon.submitPoolAttestations(ctx, &[_]u8{});
            return self.makeVoidResult(result);
        }
        if (std.mem.eql(u8, op, "submitPoolVoluntaryExits")) {
            const result = try handlers.beacon.submitPoolVoluntaryExits(ctx, &[_]u8{});
            return self.makeVoidResult(result);
        }
        if (std.mem.eql(u8, op, "submitPoolProposerSlashings")) {
            const result = try handlers.beacon.submitPoolProposerSlashings(ctx, &[_]u8{});
            return self.makeVoidResult(result);
        }
        if (std.mem.eql(u8, op, "submitPoolAttesterSlashings")) {
            const result = try handlers.beacon.submitPoolAttesterSlashings(ctx, &[_]u8{});
            return self.makeVoidResult(result);
        }
        if (std.mem.eql(u8, op, "submitPoolBlsToExecutionChanges")) {
            const result = try handlers.beacon.submitPoolBlsToExecutionChanges(ctx, &[_]u8{});
            return self.makeVoidResult(result);
        }
        if (std.mem.eql(u8, op, "submitPoolSyncCommittees")) {
            const result = try handlers.beacon.submitPoolSyncCommittees(ctx, &[_]u8{});
            return self.makeVoidResult(result);
        }

        // Debug endpoints.
        if (std.mem.eql(u8, op, "getDebugState")) {
            const state_id_str = match.getParam("state_id") orelse return error.InvalidStateId;
            const state_id = try types.StateId.parse(state_id_str);
            const handler_res = try handlers.debug.getState(ctx, state_id);
            defer alloc.free(handler_res.data);
            // Wrap raw SSZ bytes in JSON envelope showing size for now.
            const body = try std.fmt.allocPrint(alloc, "{{\"data\":\"ssz_omitted\",\"size\":{d}}}", .{handler_res.data.len});
            return .{
                .status = 200,
                .content_type = "application/json",
                .body = body,
                .meta = handler_res.meta,
            };
        }
        if (std.mem.eql(u8, op, "getDebugHeads")) {
            const handler_res = try handlers.debug.getHeads(ctx);
            defer alloc.free(handler_res.data);
            var buf = std.ArrayListUnmanaged(u8).empty;
            errdefer buf.deinit(alloc);
            try buf.appendSlice(alloc, "{\"data\":[");
            for (handler_res.data, 0..) |h, i| {
                if (i > 0) try buf.appendSlice(alloc, ",");
                const entry = try std.fmt.allocPrint(alloc, "{{\"slot\":{d},\"root\":\"0x{s}\"}}", .{
                    h.slot,
                    std.fmt.bytesToHex(h.root, .lower),
                });
                defer alloc.free(entry);
                try buf.appendSlice(alloc, entry);
            }
            try buf.appendSlice(alloc, "]}");
            return .{
                .status = 200,
                .content_type = "application/json",
                .body = try buf.toOwnedSlice(alloc),
                .meta = handler_res.meta,
            };
        }

        // Events endpoint (SSE — special path).
        if (std.mem.eql(u8, op, "getEvents")) {
            handlers.events.getEvents(ctx, match.getParam("topics") orelse "") catch |err| {
                return err;
            };
            const body = try alloc.dupe(u8, "{}");
            return .{
                .status = 200,
                .content_type = "application/json",
                .body = body,
            };
        }

        // Validator endpoints.
        if (std.mem.eql(u8, op, "getProposerDuties")) {
            const epoch_str = match.getParam("epoch") orelse return error.InvalidBlockId;
            const epoch = std.fmt.parseInt(u64, epoch_str, 10) catch return error.InvalidBlockId;
            const handler_res = try handlers.validator.getProposerDuties(ctx, epoch);
            defer alloc.free(handler_res.data);
            var buf = std.ArrayListUnmanaged(u8).empty;
            errdefer buf.deinit(alloc);
            try buf.appendSlice(alloc, "{\"data\":[");
            for (handler_res.data, 0..) |d, i| {
                if (i > 0) try buf.appendSlice(alloc, ",");
                const entry = try std.fmt.allocPrint(alloc,
                    "{{\"pubkey\":\"0x{s}\",\"validator_index\":\"{d}\",\"slot\":\"{d}\"}}",
                    .{ std.fmt.bytesToHex(d.pubkey, .lower), d.validator_index, d.slot });
                defer alloc.free(entry);
                try buf.appendSlice(alloc, entry);
            }
            try buf.appendSlice(alloc, "]");
            // Emit metadata (dependent_root, execution_optimistic)
            const meta = handler_res.meta;
            if (meta.dependent_root) |root| {
                const hex = std.fmt.bytesToHex(&root, .lower);
                const dep_root = try std.fmt.allocPrint(alloc, ",\"dependent_root\":\"0x{s}\"", .{hex});
                defer alloc.free(dep_root);
                try buf.appendSlice(alloc, dep_root);
            }
            if (meta.execution_optimistic) |opt| {
                const s = if (opt) ",\"execution_optimistic\":true" else ",\"execution_optimistic\":false";
                try buf.appendSlice(alloc, s);
            }
            try buf.appendSlice(alloc, "}");
            return .{
                .status = 200,
                .content_type = "application/json",
                .body = try buf.toOwnedSlice(alloc),
                .meta = handler_res.meta,
            };
        }
        if (std.mem.eql(u8, op, "getAttesterDuties")) {
            return error.NotImplemented;
        }
        if (std.mem.eql(u8, op, "getSyncDuties")) {
            return error.NotImplemented;
        }

        // Config endpoints.
        if (std.mem.eql(u8, op, "getSpec")) {
            const result = handlers.config.getSpec(ctx);
            return self.makeJsonResult(handlers.config.SpecData, result);
        }
        if (std.mem.eql(u8, op, "getForkSchedule")) {
            const result = handlers.config.getForkSchedule(ctx);
            return self.makeJsonResult([]const types.ForkScheduleEntry, result);
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
                .body = "{\"statusCode\":405,\"message\":\"Method not allowed\"}",
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
                .body = "{\"statusCode\":404,\"message\":\"Route not found\"}",
            };
        };

        const result = self.dispatchHandler(match) catch |err| {
            const api_err = error_response.fromZigError(err);
            var err_buf: [256]u8 = undefined;
            const err_json = api_err.formatJson(&err_buf);
            return .{
                .status = api_err.code.statusCode(),
                .status_text = api_err.code.phrase(),
                .content_type = "application/json",
                .body = err_json,
            };
        };

        return .{
            .status = result.status,
            .status_text = "OK",
            .content_type = result.content_type,
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
fn respondApiError(request: *http.Server.Request, api_err: error_response.ApiError) !void {
    var buf: [512]u8 = undefined;
    const json = api_err.formatJson(&buf);
    try request.respond(json, .{
        .status = statusFromCode(api_err.code.statusCode()),
        .extra_headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "Access-Control-Allow-Origin", .value = "*" },
        },
    });
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

test "handleRequest GET /eth/v1/node/health ready" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    tc.ctx.sync_status.is_syncing = false;
    tc.ctx.sync_status.head_slot = 1000;
    const resp = try server.handleRequest("GET", "/eth/v1/node/health", null);
    defer std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
}

test "handleRequest GET /eth/v1/node/health syncing returns 206" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    tc.ctx.sync_status.is_syncing = true;
    const resp = try server.handleRequest("GET", "/eth/v1/node/health", null);
    defer std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 206), resp.status);
}

test "handleRequest GET /eth/v1/node/health not initialized returns 503" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    tc.ctx.sync_status.is_syncing = false;
    tc.ctx.sync_status.head_slot = 0;
    const resp = try server.handleRequest("GET", "/eth/v1/node/health", null);
    defer std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 503), resp.status);
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

test "handleRequest unknown route returns 404 with statusCode field" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/not/a/route", null);

    try std.testing.expectEqual(@as(u16, 404), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "statusCode") != null);
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

test "handleRequest pool submission POST returns 204" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("POST", "/eth/v1/beacon/pool/attestations", null);
    defer std.testing.allocator.free(resp.body);

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
    try std.testing.expectEqual(@as(u16, 404), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"statusCode\":404") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"message\"") != null);
}
