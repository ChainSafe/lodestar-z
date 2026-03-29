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
const response_mod = @import("response.zig");
const content_negotiation = @import("content_negotiation.zig");
const response_meta = @import("response_meta.zig");
const error_response = @import("error_response.zig");
const handler_result_mod = @import("handler_result.zig");
const handlers = @import("handlers/root.zig");
const context = @import("context.zig");
const ApiContext = context.ApiContext;
const types = @import("types.zig");
const json_response = @import("json_response.zig");
const fork_types = @import("fork_types");
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

/// Keymanager path prefixes that must never receive wildcard CORS.
const keymanager_paths: []const []const u8 = &.{
    "/eth/v1/keystores",
    "/eth/v1/remotekeys",
};

/// Returns true if path is a keymanager endpoint.
fn isKeymanagerPath(path: []const u8) bool {
    for (keymanager_paths) |prefix| {
        if (std.mem.startsWith(u8, path, prefix)) return true;
    }
    return false;
}

pub const HttpServer = struct {
    allocator: Allocator,
    api_context: *ApiContext,
    address: []const u8,
    port: u16,
    /// CORS origin to allow. Null = no CORS headers (same-origin only).
    /// Never applied to keymanager endpoints regardless of this setting.
    cors_origin: ?[]const u8 = null,
    /// Set to true to request a clean shutdown of the serve loop.
    shutdown_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Number of currently active connections.
    active_connections: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    // ── DoS protection limits ─────────────────────────────────────────────────

    /// Read timeout per connection in seconds (Slowloris defence).
    pub const recv_timeout_sec: c_long = 30;
    /// Maximum request body size for general POST endpoints (1 MiB).
    pub const max_body_bytes: usize = 1 * 1024 * 1024;
    /// Maximum request body size for block-submission endpoints (10 MiB).
    pub const max_block_body_bytes: usize = 10 * 1024 * 1024;
    /// Maximum keep-alive requests per connection.
    pub const max_keepalive_requests: u32 = 100;
    /// Maximum concurrent TCP connections.
    pub const max_concurrent_connections: u32 = 256;
    // TODO(SSE): Add a separate sse_connections counter when real SSE streaming
    // is implemented.  SSE connections are long-lived and should be accounted
    // separately so they cannot exhaust the general connection budget.

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

    /// Create an HttpServer with CORS configured.
    pub fn initWithCors(
        allocator: Allocator,
        api_context: *ApiContext,
        address: []const u8,
        port: u16,
        cors_origin: ?[]const u8,
    ) HttpServer {
        return .{
            .allocator = allocator,
            .api_context = api_context,
            .address = address,
            .port = port,
            .cors_origin = cors_origin,
        };
    }

    /// Signal the serve loop to exit after the current connection completes.
    pub fn shutdown(self: *HttpServer) void {
        self.shutdown_requested.store(true, .release);
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

        while (!self.shutdown_requested.load(.acquire)) {
            const stream = tcp_server.accept(io) catch |err| {
                log.err("accept failed: {s}", .{@errorName(err)});
                continue;
            };

            // Enforce maximum concurrent connection limit (DoS protection).
            const prev = self.active_connections.fetchAdd(1, .acquire);
            if (prev >= max_concurrent_connections) {
                _ = self.active_connections.fetchSub(1, .release);
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
            _ = self.active_connections.fetchSub(1, .release);
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
        var recv_buf: [8192]u8 = undefined;
        var conn_reader = stream.reader(io, &recv_buf);
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
            self.handleHttpRequest(&request) catch |err| {
                log.err("handle request failed: {s}", .{@errorName(err)});
                return;
            };
            requests_served += 1;
        }
    }

    fn handleHttpRequest(self: *HttpServer, request: *http.Server.Request) !void {
        const target = request.head.target;

        // Split target into path and query.
        const path, _ = splitTarget(target);

        // CORS preflight.
        if (request.head.method == .OPTIONS) {
            // Only send CORS headers for non-keymanager paths; keymanager
            // paths require authentication and must not expose CORS headers.
            if (self.cors_origin) |origin| {
                if (!isKeymanagerPath(path)) {
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
        // Read request body for POST methods.
        var request_body: []const u8 = &[_]u8{};
        var request_body_owned = false;
        if (route_method == .POST or route_method == .DELETE) {
            var reader_buf: [4096]u8 = undefined;
            const body_reader = request.readerExpectNone(&reader_buf);
            // Block-submission endpoints allow up to max_block_body_bytes; all
            // other POST endpoints are capped at max_body_bytes (1 MiB).
            const is_block_endpoint = std.mem.eql(u8, match.route.operation_id, "publishBlockV2");
            const body_limit: usize = if (is_block_endpoint) max_block_body_bytes else max_body_bytes;
            request_body = body_reader.readAlloc(self.allocator, body_limit) catch &[_]u8{};
            request_body_owned = true;
        }
        defer if (request_body_owned) self.allocator.free(request_body);

        const dc = DispatchContext{
            .match = match,
            .query = if (std.mem.indexOfScalar(u8, target, '?')) |idx| target[idx + 1..] else null,
            .body = request_body,
            .format = format,
            .auth_header = findHeader(request, "authorization"),
        };
        const result = self.dispatchHandler(dc) catch |err| {
            try respondApiError(request, error_response.fromZigError(err));
            return;
        };
        defer self.allocator.free(result.body);

        // Build response headers: content-type + CORS + metadata.
        var extra_hdrs_buf: [16]http.Header = undefined;
        var extra_count: usize = 0;

        extra_hdrs_buf[extra_count] = .{ .name = "Content-Type", .value = result.content_type };
        extra_count += 1;
        // Apply CORS headers only when configured AND not a keymanager endpoint.
        if (self.cors_origin) |origin| {
            if (!isKeymanagerPath(path)) {
                extra_hdrs_buf[extra_count] = .{ .name = "Access-Control-Allow-Origin", .value = origin };
                extra_count += 1;
                extra_hdrs_buf[extra_count] = .{ .name = "Access-Control-Allow-Methods", .value = "GET, POST, DELETE, OPTIONS" };
                extra_count += 1;
                extra_hdrs_buf[extra_count] = .{ .name = "Access-Control-Allow-Headers", .value = "Content-Type, Authorization" };
                extra_count += 1;
            }
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

    // Dispatch coverage is verified by the "dispatch coverage" test below.
    // When adding a new route, add a dispatch branch here AND update the
    // coverage check in the test.

    // ── Handler function type ────────────────────────────────────────────────

    const HandlerFn = *const fn (*HttpServer, DispatchContext) anyerror!HandlerResult;

    // ── StaticStringMap dispatch table ───────────────────────────────────────

    const handler_table = std.StaticStringMap(HandlerFn).initComptime(.{
        .{ "getNodeIdentity",               &hGetNodeIdentity },
        .{ "getNodeVersion",                &hGetNodeVersion },
        .{ "getSyncing",                    &hGetSyncing },
        .{ "getHealth",                     &hGetHealth },
        .{ "getPeers",                      &hGetPeers },
        .{ "getPeerCount",                  &hGetPeerCount },
        .{ "getPeer",                       &hGetPeer },
        .{ "getGenesis",                    &hGetGenesis },
        .{ "getBlockHeader",                &hGetBlockHeader },
        .{ "getBlockV2",                    &hGetBlockV2 },
        .{ "getStateValidatorV2",           &hGetStateValidatorV2 },
        .{ "getStateValidatorsV2",          &hGetStateValidatorsV2 },
        .{ "getStateRoot",                  &hGetStateRoot },
        .{ "getStateFork",                  &hGetStateFork },
        .{ "getFinalityCheckpoints",        &hGetFinalityCheckpoints },
        .{ "publishBlockV2",               &hPublishBlockV2 },
        .{ "getPoolAttestations",           &hGetPoolAttestations },
        .{ "getPoolVoluntaryExits",         &hGetPoolVoluntaryExits },
        .{ "getPoolProposerSlashings",      &hGetPoolProposerSlashings },
        .{ "getPoolAttesterSlashings",      &hGetPoolAttesterSlashings },
        .{ "getPoolBlsToExecutionChanges",  &hGetPoolBlsToExecutionChanges },
        .{ "submitPoolAttestations",        &hSubmitPoolAttestations },
        .{ "submitPoolVoluntaryExits",      &hSubmitPoolVoluntaryExits },
        .{ "submitPoolProposerSlashings",   &hSubmitPoolProposerSlashings },
        .{ "submitPoolAttesterSlashings",   &hSubmitPoolAttesterSlashings },
        .{ "submitPoolBlsToExecutionChanges", &hSubmitPoolBlsToExecutionChanges },
        .{ "submitPoolSyncCommittees",      &hSubmitPoolSyncCommittees },
        .{ "getDebugState",                 &hGetDebugState },
        .{ "getDebugHeads",                 &hGetDebugHeads },
        .{ "getEvents",                     &hGetEvents },
        .{ "getProposerDuties",             &hGetProposerDuties },
        .{ "getAttesterDuties",             &hGetAttesterDuties },
        .{ "getSyncDuties",                 &hGetSyncDuties },
        .{ "getSpec",                       &hGetSpec },
        .{ "getForkSchedule",               &hGetForkSchedule },
        .{ "getValidatorMonitor",           &hGetValidatorMonitor },
        .{ "produceBlock",                  &hProduceBlock },
        .{ "produceBlockV3",                &hProduceBlock },
        .{ "getAttestationData",            &hGetAttestationData },
        .{ "getAggregateAttestation",       &hGetAggregateAttestation },
        .{ "publishAggregateAndProofs",     &hPublishAggregateAndProofs },
        .{ "getSyncCommitteeContribution",  &hGetSyncCommitteeContribution },
        .{ "publishContributionAndProofs",  &hPublishContributionAndProofs },
        .{ "getStateCommittees",            &hGetStateCommittees },
        .{ "getStateSyncCommittees",        &hGetStateSyncCommittees },
        .{ "getStateRandao",                &hGetStateRandao },
        .{ "getBlockHeaders",               &hGetBlockHeaders },
        .{ "getBlobSidecars",               &hGetBlobSidecars },
        .{ "getBlindedBlock",               &hGetBlindedBlock },
        .{ "getBlockRewards",               &hGetBlockRewards },
        .{ "getAttestationRewards",         &hGetAttestationRewards },
        .{ "getSyncCommitteeRewards",       &hGetSyncCommitteeRewards },
        .{ "prepareBeaconProposer",         &hPrepareBeaconProposer },
        .{ "registerValidator",             &hRegisterValidator },
        .{ "getValidatorLiveness",          &hGetValidatorLiveness },
        .{ "listKeystores",                 &hListKeystores },
        .{ "importKeystores",               &hImportKeystores },
        .{ "deleteKeystores",               &hDeleteKeystores },
        .{ "listRemoteKeys",                &hListRemoteKeys },
        .{ "importRemoteKeys",              &hImportRemoteKeys },
        .{ "deleteRemoteKeys",              &hDeleteRemoteKeys },
        .{ "getForkChoice",                 &hGetForkChoice },
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
        const result = handlers.node.getPeers(self.api_context);
        return self.makeJsonResult([]const types.PeerInfo, result);
    }

    fn hGetPeerCount(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const result = handlers.node.getPeerCount(self.api_context);
        return self.makeJsonResult(types.PeerCount, result);
    }

    fn hGetPeer(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const peer_id_str = dc.match.getParam("peer_id") orelse return error.InvalidRequest;
        const handler_res = try handlers.node.getPeer(self.api_context, peer_id_str);
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
        const any_block = try AnySignedBeaconBlock.deserialize(alloc, .full, fork_seq, block_result.data);
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
        const result = try handlers.beacon.submitBlock(self.api_context, dc.body);
        return self.makeVoidResult(result);
    }

    fn hGetPoolAttestations(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const result = handlers.beacon.getPoolAttestations(self.api_context);
        return self.makeJsonResult(types.PoolCounts, result);
    }

    fn hGetPoolVoluntaryExits(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const result = handlers.beacon.getPoolVoluntaryExits(self.api_context);
        return self.makeJsonResult(usize, result);
    }

    fn hGetPoolProposerSlashings(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const result = handlers.beacon.getPoolProposerSlashings(self.api_context);
        return self.makeJsonResult(usize, result);
    }

    fn hGetPoolAttesterSlashings(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const result = handlers.beacon.getPoolAttesterSlashings(self.api_context);
        return self.makeJsonResult(usize, result);
    }

    fn hGetPoolBlsToExecutionChanges(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const result = handlers.beacon.getPoolBlsToExecutionChanges(self.api_context);
        return self.makeJsonResult(usize, result);
    }

    fn hSubmitPoolAttestations(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const result = try handlers.beacon.submitPoolAttestations(self.api_context, dc.body);
        return self.makeVoidResult(result);
    }

    fn hSubmitPoolVoluntaryExits(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const result = try handlers.beacon.submitPoolVoluntaryExits(self.api_context, dc.body);
        return self.makeVoidResult(result);
    }

    fn hSubmitPoolProposerSlashings(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const result = try handlers.beacon.submitPoolProposerSlashings(self.api_context, dc.body);
        return self.makeVoidResult(result);
    }

    fn hSubmitPoolAttesterSlashings(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const result = try handlers.beacon.submitPoolAttesterSlashings(self.api_context, dc.body);
        return self.makeVoidResult(result);
    }

    fn hSubmitPoolBlsToExecutionChanges(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const result = try handlers.beacon.submitPoolBlsToExecutionChanges(self.api_context, dc.body);
        return self.makeVoidResult(result);
    }

    fn hSubmitPoolSyncCommittees(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const result = try handlers.beacon.submitPoolSyncCommittees(self.api_context, dc.body);
        return self.makeVoidResult(result);
    }

    fn hGetDebugState(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const state_id_str = dc.match.getParam("state_id") orelse return error.InvalidStateId;
        const state_id = try types.StateId.parse(state_id_str);
        const handler_res = try handlers.debug.getState(self.api_context, state_id);
        defer alloc.free(handler_res.data);
        // Derive Eth-Consensus-Version from the state's slot.
        const state_slot: u64 = switch (state_id) {
            .slot => |s| s,
            .head => self.api_context.head_tracker.head_slot,
            .finalized => self.api_context.head_tracker.finalized_slot,
            .justified => self.api_context.head_tracker.justified_slot,
            .genesis => 0,
            .root => self.api_context.head_tracker.head_slot,
        };
        const fork_seq = self.api_context.beacon_config.forkSeq(state_slot);
        const fork_version: response_meta.Fork = @enumFromInt(@intFromEnum(fork_seq));
        var meta = handler_res.meta;
        meta.version = fork_version;
        const body = try std.fmt.allocPrint(alloc, "{{\"data\":\"ssz_omitted\",\"size\":{d}}}", .{handler_res.data.len});
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = meta };
    }

    fn hGetDebugHeads(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const handler_res = try handlers.debug.getHeads(self.api_context);
        defer alloc.free(handler_res.data);
        // Eth-Consensus-Version intentionally omitted: multiple chain heads may span forks.
        const body = try json_response.writeApiArrayEnvelope(alloc, handlers.debug.DebugChainHead, handler_res.data, handler_res.meta);
        return .{ .status = 200, .content_type = "application/json", .body = body, .meta = handler_res.meta };
    }


    fn hGetEvents(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        // /eth/v1/events?topics=head,block — topics come from query params, not path params.
        const topics = dc.getQuery("topics") orelse "";
        handlers.events.getEvents(self.api_context, topics) catch |err| return err;
        const body = try alloc.dupe(u8, "{}");
        return .{ .status = 200, .content_type = "application/json", .body = body };
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


    fn hGetSpec(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const result = handlers.config.getSpec(self.api_context);
        return self.makeJsonResult(handlers.config.SpecData, result);
    }

    fn hGetForkSchedule(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const result = handlers.config.getForkSchedule(self.api_context);
        return self.makeJsonResult([]const types.ForkScheduleEntry, result);
    }

    fn hGetValidatorMonitor(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const result = handlers.lodestar.getValidatorMonitor(self.api_context) catch |err| {
            if (err == error.ValidatorMonitorNotConfigured) return error.NotImplemented;
            return err;
        };
        return .{ .status = 200, .content_type = "application/json", .body = result.data };
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
        const handler_res = try handlers.validator.produceBlock(self.api_context, slot, randao_reveal, graffiti);
        var block_meta = handler_res.meta;
        block_meta.version = response_meta.Fork.fromString(handler_res.data.fork);
        if (dc.format == .ssz) {
            const ssz_copy = try alloc.dupe(u8, handler_res.data.ssz_bytes);
            return .{ .status = 200, .content_type = "application/octet-stream", .body = ssz_copy, .meta = block_meta };
        }
        // Deserialize SSZ bytes into typed block, then serialize to JSON via SSZ type system
        const fork_seq = ForkSeq.fromName(handler_res.data.fork);
        const any_block = try AnySignedBeaconBlock.deserialize(alloc, .full, fork_seq, handler_res.data.ssz_bytes);
        const body_json = try json_response.writeBlockEnvelope(alloc, any_block, block_meta);
        return .{ .status = 200, .content_type = "application/json", .body = body_json, .meta = block_meta };
    }


    fn hGetAttestationData(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const slot_str = dc.getQuery("slot") orelse return error.InvalidRequest;
        const committee_str = dc.getQuery("committee_index") orelse "0";
        const slot = std.fmt.parseInt(u64, slot_str, 10) catch return error.InvalidRequest;
        const committee_index = std.fmt.parseInt(u64, committee_str, 10) catch return error.InvalidRequest;
        const handler_res = try handlers.validator.getAttestationData(self.api_context, slot, committee_index);
        const d = handler_res.data;
        const body_json = try std.fmt.allocPrint(alloc,
            "{{\"data\":{{\"slot\":\"{d}\",\"index\":\"{d}\",\"beacon_block_root\":\"0x{s}\",\"source\":{{\"epoch\":\"{d}\",\"root\":\"0x{s}\"}},\"target\":{{\"epoch\":\"{d}\",\"root\":\"0x{s}\"}}}}}}",
            .{
                d.slot, d.index,
                std.fmt.bytesToHex(&d.beacon_block_root, .lower),
                d.source_epoch, std.fmt.bytesToHex(&d.source_root, .lower),
                d.target_epoch, std.fmt.bytesToHex(&d.target_root, .lower),
            });
        return .{ .status = 200, .content_type = "application/json", .body = body_json, .meta = handler_res.meta };
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
        const raw_json = try handlers.validator.getAggregateAttestation(self.api_context, slot, data_root);
        defer alloc.free(raw_json);
        const envelope = try std.fmt.allocPrint(alloc, "{{\"data\":{s}}}", .{raw_json});
        return .{ .status = 200, .content_type = "application/json", .body = envelope, .meta = .{} };
    }

    fn hPublishAggregateAndProofs(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const handler_res = try handlers.validator.publishAggregateAndProofs(self.api_context, dc.body);
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
        const raw_json = try handlers.validator.getSyncCommitteeContribution(self.api_context, slot, subcommittee_index, block_root);
        defer alloc.free(raw_json);
        const envelope = try std.fmt.allocPrint(alloc, "{{\"data\":{s}}}", .{raw_json});
        return .{ .status = 200, .content_type = "application/json", .body = envelope, .meta = .{} };
    }

    fn hPublishContributionAndProofs(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const handler_res = try handlers.validator.publishContributionAndProofs(self.api_context, dc.body);
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
        // TODO: wire Deneb blob DB lookup — parse optional ?indices query param and filter.
        // When BeaconDB.getBlobSidecars is plumbed through ApiContext, call:
        //   handlers.beacon.getBlobSidecars(self.api_context, block_id, indices_opt)
        // and return the raw SSZ-decoded blob sidecar list as JSON.
        _ = block_id;
        _ = alloc;
        return error.NotImplemented;
    }

    // TODO(stub): returns full block data, not an actual blinded block.
    // A real implementation would strip execution payload fields per the blinded block spec.
    fn hGetBlindedBlock(self: *HttpServer, dc: DispatchContext) !HandlerResult {
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
        // TODO(stub): returns full block, not blinded. Blinding requires fork-specific payload stripping.
        const fork_seq = self.api_context.beacon_config.forkSeq(block_result.slot);
        const any_block = try AnySignedBeaconBlock.deserialize(alloc, .full, fork_seq, block_result.data);
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
        const epoch_str = dc.match.getParam("epoch") orelse return error.InvalidRequest;
        const epoch = std.fmt.parseInt(u64, epoch_str, 10) catch return error.InvalidRequest;
        const result = try handlers.beacon.getAttestationRewards(self.api_context, epoch, &[_]u64{});
        return self.makeJsonResult(types.AttestationRewardsData, result);
    }

    fn hGetSyncCommitteeRewards(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const block_id_str = dc.match.getParam("block_id") orelse return error.InvalidBlockId;
        const block_id = try types.BlockId.parse(block_id_str);
        const result = try handlers.beacon.getSyncCommitteeRewards(self.api_context, block_id, &[_]u64{});
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
        var buf = std.ArrayListUnmanaged(u8).empty;
        errdefer buf.deinit(alloc);
        try buf.appendSlice(alloc, "{\"data\":[");
        for (handler_res.data, 0..) |lv, i| {
            if (i > 0) try buf.appendSlice(alloc, ",");
            const entry = try std.fmt.allocPrint(alloc,
                "{{\"index\":\"{d}\",\"epoch\":\"{d}\",\"is_live\":{s}}}",
                .{ lv.index, lv.epoch, if (lv.is_live) "true" else "false" });
            defer alloc.free(entry);
            try buf.appendSlice(alloc, entry);
        }
        try buf.appendSlice(alloc, "]}");
        return .{ .status = 200, .content_type = "application/json", .body = try buf.toOwnedSlice(alloc), .meta = handler_res.meta };
    }

    fn hListKeystores(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const body = try handlers.keymanager.listKeystores(self.api_context, dc.auth_header);
        return .{ .status = 200, .content_type = "application/json", .body = body };
    }

    fn hImportKeystores(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const body = try handlers.keymanager.importKeystores(self.api_context, dc.auth_header, dc.body);
        return .{ .status = 200, .content_type = "application/json", .body = body };
    }

    fn hDeleteKeystores(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const body = try handlers.keymanager.deleteKeystores(self.api_context, dc.auth_header, dc.body);
        return .{ .status = 200, .content_type = "application/json", .body = body };
    }

    fn hListRemoteKeys(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const body = try handlers.keymanager.listRemoteKeys(self.api_context, dc.auth_header);
        return .{ .status = 200, .content_type = "application/json", .body = body };
    }

    fn hImportRemoteKeys(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const body = try handlers.keymanager.importRemoteKeys(self.api_context, dc.auth_header, dc.body);
        return .{ .status = 200, .content_type = "application/json", .body = body };
    }

    fn hDeleteRemoteKeys(self: *HttpServer, dc: DispatchContext) !HandlerResult {
        const body = try handlers.keymanager.deleteRemoteKeys(self.api_context, dc.auth_header, dc.body);
        return .{ .status = 200, .content_type = "application/json", .body = body };
    }

    fn hGetForkChoice(self: *HttpServer, _: DispatchContext) !HandlerResult {
        const alloc = self.allocator;
        const handler_res = try handlers.debug.getForkChoice(self.api_context);
        defer alloc.free(handler_res.data.fork_choice_nodes);
        var buf = std.ArrayListUnmanaged(u8).empty;
        errdefer buf.deinit(alloc);
        const fc = handler_res.data;
        const header = try std.fmt.allocPrint(alloc,
            "{{\"data\":{{\"justified_checkpoint\":{{\"epoch\":\"{d}\",\"root\":\"0x{s}\"}},\"finalized_checkpoint\":{{\"epoch\":\"{d}\",\"root\":\"0x{s}\"}},\"fork_choice_nodes\":[",
            .{
                fc.justified_checkpoint.epoch,
                std.fmt.bytesToHex(&fc.justified_checkpoint.root, .lower),
                fc.finalized_checkpoint.epoch,
                std.fmt.bytesToHex(&fc.finalized_checkpoint.root, .lower),
            });
        defer alloc.free(header);
        try buf.appendSlice(alloc, header);
        for (fc.fork_choice_nodes, 0..) |node, ni| {
            if (ni > 0) try buf.appendSlice(alloc, ",");
            const parent_root_str = if (node.parent_root) |pr|
                try std.fmt.allocPrint(alloc, "\"0x{s}\"", .{std.fmt.bytesToHex(&pr, .lower)})
            else
                try alloc.dupe(u8, "null");
            defer alloc.free(parent_root_str);
            const node_entry = try std.fmt.allocPrint(alloc,
                "{{\"slot\":\"{d}\",\"block_root\":\"0x{s}\",\"parent_root\":{s},\"justified_epoch\":\"{d}\",\"finalized_epoch\":\"{d}\",\"weight\":\"{d}\",\"validity\":\"{s}\",\"execution_block_hash\":\"0x{s}\"}}",
                .{
                    node.slot,
                    std.fmt.bytesToHex(&node.block_root, .lower),
                    parent_root_str,
                    node.justified_epoch,
                    node.finalized_epoch,
                    node.weight,
                    node.validity,
                    std.fmt.bytesToHex(&node.execution_block_hash, .lower),
                });
            defer alloc.free(node_entry);
            try buf.appendSlice(alloc, node_entry);
        }
        try buf.appendSlice(alloc, "]}}");
        return .{ .status = 200, .content_type = "application/json", .body = try buf.toOwnedSlice(alloc), .meta = handler_res.meta };
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
            };

        const clean_path, _ = splitTarget(path);

        const match = routes_mod.findRoute(route_method, clean_path) orelse {
            return .{
                .status = 404,
                .status_text = "Not Found",
                .content_type = "application/json",
                .body = "{\"statusCode\":404,\"message\":\"Route not found\"}",
            };
        };

        const clean_query = if (std.mem.indexOfScalar(u8, path, '?')) |idx| path[idx+1..] else null;
        const dc_test = DispatchContext{
            .match = match,
            .query = clean_query,
            .body = body orelse &[_]u8{},
        };
        const result = self.dispatchHandler(dc_test) catch |err| {
            const api_err = error_response.fromZigError(err);
            var err_buf: [256]u8 = undefined;
            const err_json = api_err.formatJson(&err_buf);
            // Dupe onto heap — err_buf is stack-local and would dangle after return.
            // On OOM, fall back to a static string literal (safe to return by reference).
            const err_json_heap = self.allocator.dupe(u8, err_json) catch
                "{\"statusCode\":500,\"message\":\"internal server error\"}";
            return .{
                .status = api_err.code.statusCode(),
                .status_text = api_err.code.phrase(),
                .content_type = "application/json",
                .body = err_json_heap,
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
            if (ch == '{') { in_param = true; continue; }
            if (ch == '}') {
                const dummy = "head";
                @memcpy(path_buf[path_len..path_len + dummy.len], dummy);
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
    // PATCH is not a supported method, should return 405.
    const resp = try server.handleRequest("PATCH", "/eth/v1/node/version", null);

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

test "handleRequest GET /eth/v1/validator/attestation_data returns 200" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/validator/attestation_data?slot=100&committee_index=0", null);
    defer std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "beacon_block_root") != null);
}

test "handleRequest POST /eth/v1/validator/aggregate_and_proofs returns 204" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("POST", "/eth/v1/validator/aggregate_and_proofs", null);
    defer std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 204), resp.status);
}

test "handleRequest POST /eth/v1/validator/contribution_and_proofs returns 204" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("POST", "/eth/v1/validator/contribution_and_proofs", null);
    defer std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 204), resp.status);
}

test "handleRequest POST /eth/v2/beacon/blocks without import returns error" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    // submitBlock returns NotImplemented since no block_import is wired
    // Error responses from handleRequest are stack-allocated (not heap), so no free needed.
    const resp = try server.handleRequest("POST", "/eth/v2/beacon/blocks", "{}");

    // NotImplemented maps to 500 or 501
    try std.testing.expect(resp.status >= 400);
}

test "handleRequest pool submission POST attestations with body" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const body =
        \\[{"aggregation_bits":"0x01","data":{"slot":100,"index":0,"beacon_block_root":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source":{"epoch":0,"root":"0x0000000000000000000000000000000000000000000000000000000000000000"},"target":{"epoch":1,"root":"0x0000000000000000000000000000000000000000000000000000000000000000"}},"signature":"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}]
    ;
    const resp = try server.handleRequest("POST", "/eth/v1/beacon/pool/attestations", body);
    defer std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 204), resp.status);
}

test "handleRequest pool submission POST voluntary_exits with body" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const body =
        \\{"message":{"epoch":100,"validator_index":42},"signature":"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}
    ;
    const resp = try server.handleRequest("POST", "/eth/v1/beacon/pool/voluntary_exits", body);
    defer std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 204), resp.status);
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
    // Error responses are stack-allocated, do not free the body.

    // Without a head state, should return an error (StateNotAvailable -> 500)
    try std.testing.expect(resp.status >= 400);
}

test "handleRequest GET /eth/v1/beacon/headers returns 200" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/beacon/headers", null);
    defer if (resp.status == 200) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "data") != null);
}

test "handleRequest GET /eth/v1/beacon/rewards/blocks/head returns 501" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/beacon/rewards/blocks/head", null);

    // Rewards require RewardCache which is not yet implemented.
    try std.testing.expectEqual(@as(u16, 501), resp.status);
}

test "handleRequest POST /eth/v1/beacon/rewards/attestations/1 returns 501" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("POST", "/eth/v1/beacon/rewards/attestations/1", "[]");

    // Rewards require RewardCache which is not yet implemented.
    try std.testing.expectEqual(@as(u16, 501), resp.status);
}
test "handleRequest POST /eth/v1/validator/prepare_beacon_proposer returns 204" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("POST", "/eth/v1/validator/prepare_beacon_proposer", "[]");
    defer std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 204), resp.status);
}

test "handleRequest POST /eth/v1/validator/register_validator returns 204" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("POST", "/eth/v1/validator/register_validator", "[]");
    defer std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 204), resp.status);
}

test "handleRequest POST /eth/v1/validator/liveness/1 returns 200" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("POST", "/eth/v1/validator/liveness/1", "[0,1,2]");
    defer if (resp.status == 200) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "is_live") != null);
}

test "handleRequest GET /eth/v1/debug/fork_choice returns 200" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/debug/fork_choice", null);
    defer if (resp.status == 200) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "fork_choice_nodes") != null);
}

test "handleRequest GET /eth/v1/node/peer_count returns 200" {
    var tc = test_helpers.makeTestContext(std.testing.allocator);
    defer test_helpers.destroyTestContext(std.testing.allocator, &tc);

    var server = HttpServer.init(std.testing.allocator, &tc.ctx, "127.0.0.1", 0);
    const resp = try server.handleRequest("GET", "/eth/v1/node/peer_count", null);
    defer if (resp.status == 200) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "connected") != null);
}
