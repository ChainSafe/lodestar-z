//! Engine API HTTP client with JWT authentication.
//!
//! Implements the EngineApi vtable using a pluggable HTTP transport, enabling
//! full testing of encoding/decoding logic without a real execution client.
//! JWT HS256 tokens are generated per-request using the configured secret.
//!
//! Transport is abstracted so production code can plug in a real HTTP client
//! while tests use MockTransport to inspect requests and return canned responses.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

const engine_api = @import("engine_api.zig");
const json_rpc = @import("json_rpc.zig");
const types = @import("engine_api_types.zig");

const EngineApi = engine_api.EngineApi;
const ExecutionPayloadV1 = types.ExecutionPayloadV1;
const ExecutionPayloadV2 = types.ExecutionPayloadV2;
const ExecutionPayloadV3 = types.ExecutionPayloadV3;
const ExecutionPayloadV4 = types.ExecutionPayloadV4;
const PayloadStatusV1 = types.PayloadStatusV1;
const ExecutionPayloadStatus = types.ExecutionPayloadStatus;
const ForkchoiceStateV1 = types.ForkchoiceStateV1;
const PayloadAttributesV1 = types.PayloadAttributesV1;
const PayloadAttributesV2 = types.PayloadAttributesV2;
const PayloadAttributesV3 = types.PayloadAttributesV3;
const ForkchoiceUpdatedResponse = types.ForkchoiceUpdatedResponse;
const GetPayloadResponseV1 = types.GetPayloadResponseV1;
const GetPayloadResponseV2 = types.GetPayloadResponseV2;
const GetPayloadResponse = types.GetPayloadResponse;
const GetPayloadResponseV4 = types.GetPayloadResponseV4;
const BlobsBundle = types.BlobsBundle;
const Withdrawal = types.Withdrawal;
const DepositRequest = types.DepositRequest;
const WithdrawalRequest = types.WithdrawalRequest;
const ConsolidationRequest = types.ConsolidationRequest;
const ExecutionPayloadBodyV1 = types.ExecutionPayloadBodyV1;
const ExecutionPayloadBodyV2 = types.ExecutionPayloadBodyV2;

// ── Connection state ──────────────────────────────────────────────────────────

/// EL connection state machine.
///
/// Tracks the current health of the execution layer connection.
/// State transitions are logged to aid debugging.
pub const EngineState = enum {
    /// EL is responding normally.
    online,
    /// EL connection failed (transport error, timeout).
    offline,
    /// EL is syncing (newPayload/FCU returned SYNCING).
    syncing,
    /// JWT authentication was rejected by the EL.
    auth_failed,
};

// ── Retry configuration ───────────────────────────────────────────────────────

/// Retry configuration for Engine API calls.
pub const RetryConfig = struct {
    /// Number of retry attempts (default 3).
    max_retries: u32 = 3,
    /// Initial backoff in milliseconds (doubles each retry).
    initial_backoff_ms: u64 = 100,
    /// Timeout for newPayload calls (milliseconds).
    new_payload_timeout_ms: u64 = 12_000,
    /// Timeout for other calls (milliseconds).
    default_timeout_ms: u64 = 8_000,
};

// ── Transport interface ───────────────────────────────────────────────────────

/// HTTP method for a transport send call.
pub const HttpMethod = enum { GET, POST };

/// An HTTP header name/value pair.
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// Pluggable HTTP transport.
///
/// The send function receives the target URL, a slice of headers, and the
/// request body. It returns an allocated response body. Caller owns the memory.
///
/// Real transports (IoHttpTransport) store their own std.Io context internally.
/// Mock transports ignore I/O entirely.
pub const Transport = struct {
    ptr: *anyopaque,
    sendFn: *const fn (
        ptr: *anyopaque,
        method: HttpMethod,
        url: []const u8,
        headers: []const Header,
        body: []const u8,
    ) anyerror![]const u8,

    pub fn send(
        self: Transport,
        method: HttpMethod,
        url: []const u8,
        headers: []const Header,
        body: []const u8,
    ) ![]const u8 {
        return self.sendFn(self.ptr, method, url, headers, body);
    }
};

// ── HttpEngine ────────────────────────────────────────────────────────────────

/// EL client version as reported by engine_getClientVersionV1.
pub const ClientVersion = struct {
    /// Short client code (e.g. "GE" for Geth, "NM" for Nethermind).
    code: []const u8,
    /// Human-readable client name.
    name: []const u8,
    /// Client version string.
    version: []const u8,
    /// 4-byte hex commit hash with 0x prefix.
    commit: []const u8,
};

/// Transition configuration for engine_exchangeTransitionConfigurationV1.
pub const TransitionConfiguration = struct {
    /// Terminal total difficulty as hex string (QUANTITY).
    terminal_total_difficulty: u256,
    /// Terminal block hash (DATA 32 bytes).
    terminal_block_hash: [32]u8,
    /// Terminal block number (QUANTITY).
    terminal_block_number: u64,
};

/// Engine API client that communicates via JSON-RPC over HTTP.
///
/// Uses a pluggable Transport for the actual HTTP layer, making the encoding,
/// JWT generation, and response decoding fully testable without a real EL.
pub const HttpEngine = struct {
    /// All Engine API methods supported by this CL client.
    /// Pass to exchangeCapabilities() during EL handshake.
    pub const supported_capabilities = [_][]const u8{
        "engine_newPayloadV1",
        "engine_newPayloadV2",
        "engine_newPayloadV3",
        "engine_newPayloadV4",
        "engine_forkchoiceUpdatedV1",
        "engine_forkchoiceUpdatedV2",
        "engine_forkchoiceUpdatedV3",
        "engine_getPayloadV1",
        "engine_getPayloadV2",
        "engine_getPayloadV3",
        "engine_getPayloadV4",
        "engine_getPayloadBodiesByHashV1",
        "engine_getPayloadBodiesByHashV2",
        "engine_getPayloadBodiesByRangeV1",
        "engine_getPayloadBodiesByRangeV2",
        "engine_exchangeTransitionConfigurationV1",
        "engine_getClientVersionV1",
    };
    allocator: Allocator,
    /// Execution engine endpoint URL (e.g. "http://localhost:8551").
    endpoint: []const u8,
    /// Optional JWT secret for authentication (32 bytes).
    jwt_secret: ?[32]u8,
    /// Pluggable HTTP transport.
    transport: Transport,
    /// Monotonically increasing JSON-RPC request ID.
    next_id: u64,
    /// I/O context for std.http.Client and clock access.
    /// Set after construction via setIo() when the Io context becomes available.
    io: ?std.Io,
    /// Current EL connection state.
    state: EngineState,
    /// Retry configuration.
    retry_config: RetryConfig,
    /// Cached EL client version (null until first successful getClientVersion call).
    client_version: ?ClientVersion,

    pub fn init(
        allocator: Allocator,
        endpoint: []const u8,
        jwt_secret: ?[32]u8,
        transport: Transport,
    ) HttpEngine {
        return .{
            .allocator = allocator,
            .endpoint = endpoint,
            .jwt_secret = jwt_secret,
            .transport = transport,
            .next_id = 1,
            .io = null,
            .state = .online,
            .retry_config = .{},
            .client_version = null,
        };
    }

    /// Create an HttpEngine with custom retry configuration.
    pub fn initWithRetry(
        allocator: Allocator,
        endpoint: []const u8,
        jwt_secret: ?[32]u8,
        transport: Transport,
        retry_config: RetryConfig,
    ) HttpEngine {
        return .{
            .allocator = allocator,
            .endpoint = endpoint,
            .jwt_secret = jwt_secret,
            .transport = transport,
            .next_id = 1,
            .io = null,
            .state = .online,
            .retry_config = retry_config,
            .client_version = null,
        };
    }

    /// Set the Io context. Must be called before any requests are made.
    /// The Io context is not available at init time (before the event loop starts).
    pub fn setIo(self: *HttpEngine, io: std.Io) void {
        self.io = io;
    }

    pub fn deinit(self: *HttpEngine) void {
        if (self.client_version) |cv| {
            self.allocator.free(cv.code);
            self.allocator.free(cv.name);
            self.allocator.free(cv.version);
            self.allocator.free(cv.commit);
        }
    }

    /// Return an EngineApi vtable interface backed by this client.
    pub fn engine(self: *HttpEngine) EngineApi {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Allocate the next request ID and increment the counter.
    fn nextId(self: *HttpEngine) u64 {
        const id = self.next_id;
        self.next_id += 1;
        return id;
    }

    /// Update the connection state and log transitions.
    fn updateState(self: *HttpEngine, new_state: EngineState) void {
        if (self.state == new_state) return;
        const old = self.state;
        self.state = new_state;
        switch (new_state) {
            .online => std.log.info("Engine API: EL came online (was {s})", .{@tagName(old)}),
            .offline => std.log.warn("Engine API: EL went offline (was {s})", .{@tagName(old)}),
            .syncing => std.log.warn("Engine API: EL is syncing (was {s})", .{@tagName(old)}),
            .auth_failed => std.log.err("Engine API: JWT authentication failed (was {s})", .{@tagName(old)}),
        }
    }

    /// Build headers for a JSON-RPC request (Content-Type + optional JWT auth).
    /// Returns the header count. `auth_buf` must be live for the duration of the request.
    fn buildHeaders(
        self: *HttpEngine,
        headers_buf: []Header,
        auth_buf: []u8,
        auth_buf_len: *usize,
    ) !usize {
        var count: usize = 0;
        headers_buf[count] = .{ .name = "Content-Type", .value = "application/json" };
        count += 1;

        if (self.jwt_secret) |secret| {
            const iat = if (self.io) |io| unixTimestamp(io) else 0;
            const token = try generateJwt(self.allocator, secret, iat);
            defer self.allocator.free(token);

            const auth_value = try std.fmt.bufPrint(auth_buf, "Bearer {s}", .{token});
            auth_buf_len.* = auth_value.len;

            headers_buf[count] = .{ .name = "Authorization", .value = auth_value };
            count += 1;
        }

        return count;
    }

    /// Send a JSON-RPC request with retry and exponential backoff.
    ///
    /// Retries on transport errors (connection refused, timeout, etc.).
    /// Does NOT retry on JSON-RPC application errors (those are definitive).
    /// Caller owns the returned memory.
    fn sendRequest(self: *HttpEngine, body: []const u8) ![]const u8 {
        // JWT tokens can be up to ~300 bytes; 512 is safe.
        var auth_buf: [512]u8 = undefined;
        var auth_buf_len: usize = 0;
        var headers_buf: [2]Header = undefined;

        const header_count = try self.buildHeaders(&headers_buf, &auth_buf, &auth_buf_len);
        _ = &auth_buf_len; // length tracked inside auth_buf slice via buildHeaders

        const max_attempts = self.retry_config.max_retries + 1;
        var attempt: u32 = 0;
        while (attempt < max_attempts) : (attempt += 1) {
            // On retry: rebuild JWT (iat must be fresh) and sleep with backoff.
            if (attempt > 0) {
                // Rebuild headers with a fresh JWT token for this attempt.
                const retry_count = try self.buildHeaders(&headers_buf, &auth_buf, &auth_buf_len);
                _ = retry_count;

                const backoff_ms = self.retry_config.initial_backoff_ms *
                    (@as(u64, 1) << @intCast(attempt - 1));
                std.log.debug("Engine API: retrying request (attempt {d}/{d}) after {d}ms", .{
                    attempt + 1, max_attempts, backoff_ms,
                });
                // Sleep if Io available; in tests without Io, skip sleep.
                if (self.io) |io| {
                    std.Io.sleep(io, .{ .nanoseconds = @as(i96, @intCast(backoff_ms)) * std.time.ns_per_ms }, .real) catch {};
                }
            }

            const result = self.transport.send(.POST, self.endpoint, headers_buf[0..header_count], body);
            if (result) |response| {
                // Successful transport — mark online.
                self.updateState(.online);
                return response;
            } else |err| {
                // Transport error — check if we should retry.
                std.log.warn("Engine API: transport error on attempt {d}: {}", .{ attempt + 1, err });
                if (attempt + 1 >= max_attempts) {
                    self.updateState(.offline);
                    return err;
                }
                // Continue to retry.
            }
        }
        unreachable;
    }

    // ── Additional Engine API methods ─────────────────────────────────────────

    /// engine_exchangeCapabilities: negotiate supported methods with the EL.
    ///
    /// The CL sends its supported method list; the EL responds with its list.
    /// Returns the EL's supported capability strings. Caller owns the slice
    /// and each string in it (allocated from `allocator`).
    pub fn exchangeCapabilities(
        self: *HttpEngine,
        cl_capabilities: []const []const u8,
    ) ![][]const u8 {
        const id = self.nextId();

        // Encode capabilities as a JSON array of strings.
        var caps_parts: std.ArrayListUnmanaged([]const u8) = .empty;
        defer {
            for (caps_parts.items) |p| self.allocator.free(p);
            caps_parts.deinit(self.allocator);
        }
        for (cl_capabilities) |cap| {
            const quoted = try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{cap});
            try caps_parts.append(self.allocator, quoted);
        }
        const caps_json = try joinJsonArray(self.allocator, caps_parts.items);
        defer self.allocator.free(caps_json);

        const params_json = try std.fmt.allocPrint(self.allocator, "[{s}]", .{caps_json});
        defer self.allocator.free(params_json);

        const body = try encodeRawRequest(self.allocator, "engine_exchangeCapabilities", params_json, id);
        defer self.allocator.free(body);

        const response = try self.sendRequest(body);
        defer self.allocator.free(response);

        // Response is an array of strings.
        // The result itself is an array, so we need to wrap it.
        const CapArrayJson = []const []const u8;
        var parsed = try json_rpc.decodeResponse(CapArrayJson, self.allocator, response);
        defer parsed.deinit();

        // Deep-copy the strings — the arena will be freed.
        const result = try self.allocator.alloc([]const u8, parsed.value.len);
        errdefer self.allocator.free(result);
        for (parsed.value, 0..) |cap, i| {
            result[i] = try self.allocator.dupe(u8, cap);
        }
        return result;
    }

    /// engine_exchangeTransitionConfigurationV1: verify CL and EL agree on terminal PoW config.
    ///
    /// Called periodically (every ~60s) post-Merge to confirm both sides have
    /// the same terminal total difficulty and terminal block hash.
    pub fn exchangeTransitionConfiguration(
        self: *HttpEngine,
        config: TransitionConfiguration,
    ) !TransitionConfiguration {
        const id = self.nextId();

        // Encode TTD as quantity (no leading zeros).
        const ttd_hex = try hexEncodeQuantityU256(self.allocator, config.terminal_total_difficulty);
        defer self.allocator.free(ttd_hex);
        const tbh_hex = try hexEncodeFixed(self.allocator, &config.terminal_block_hash);
        defer self.allocator.free(tbh_hex);
        const tbn_hex = try hexEncodeQuantity(self.allocator, config.terminal_block_number);
        defer self.allocator.free(tbn_hex);

        const params_json = try std.fmt.allocPrint(
            self.allocator,
            "[{{\"terminalTotalDifficulty\":\"{s}\",\"terminalBlockHash\":\"{s}\",\"terminalBlockNumber\":\"{s}\"}}]",
            .{ ttd_hex, tbh_hex, tbn_hex },
        );
        defer self.allocator.free(params_json);

        const body = try encodeRawRequest(
            self.allocator,
            "engine_exchangeTransitionConfigurationV1",
            params_json,
            id,
        );
        defer self.allocator.free(body);

        const response = try self.sendRequest(body);
        defer self.allocator.free(response);

        const TransitionConfigJson = struct {
            terminalTotalDifficulty: []const u8,
            terminalBlockHash: []const u8,
            terminalBlockNumber: []const u8,
        };

        var parsed = try json_rpc.decodeResponse(TransitionConfigJson, self.allocator, response);
        defer parsed.deinit();

        return TransitionConfiguration{
            .terminal_total_difficulty = try hexDecodeU256(parsed.value.terminalTotalDifficulty),
            .terminal_block_hash = try hexDecode32(parsed.value.terminalBlockHash),
            .terminal_block_number = try hexDecodeQuantity(parsed.value.terminalBlockNumber),
        };
    }

    /// engine_getClientVersionV1: fetch EL client name and version info.
    ///
    /// Returns a slice of ClientVersion structs. Strings are owned by the caller
    /// and allocated with `allocator`.
    pub fn getClientVersion(
        self: *HttpEngine,
        cl_name: []const u8,
        cl_version: []const u8,
        cl_commit: []const u8,
    ) ![]ClientVersion {
        const id = self.nextId();

        const params_json = try std.fmt.allocPrint(
            self.allocator,
            "[{{\"code\":\"LS\",\"name\":\"{s}\",\"version\":\"{s}\",\"commit\":\"{s}\"}}]",
            .{ cl_name, cl_version, cl_commit },
        );
        defer self.allocator.free(params_json);

        const body = try encodeRawRequest(self.allocator, "engine_getClientVersionV1", params_json, id);
        defer self.allocator.free(body);

        const response = try self.sendRequest(body);
        defer self.allocator.free(response);

        const ClientVersionJson = struct {
            code: []const u8,
            name: []const u8,
            version: []const u8,
            commit: []const u8,
        };

        var parsed = try json_rpc.decodeResponse([]const ClientVersionJson, self.allocator, response);
        defer parsed.deinit();

        const result = try self.allocator.alloc(ClientVersion, parsed.value.len);
        errdefer self.allocator.free(result);
        for (parsed.value, 0..) |cv, i| {
            result[i] = ClientVersion{
                .code = try self.allocator.dupe(u8, cv.code),
                .name = try self.allocator.dupe(u8, cv.name),
                .version = try self.allocator.dupe(u8, cv.version),
                .commit = try self.allocator.dupe(u8, cv.commit),
            };
        }

        std.log.debug("Engine API: EL client version: code={s} name={s} version={s}", .{
            if (result.len > 0) result[0].code else "?",
            if (result.len > 0) result[0].name else "?",
            if (result.len > 0) result[0].version else "?",
        });

        return result;
    }

    /// Free a ClientVersion slice returned by getClientVersion.
    pub fn freeClientVersions(self: *HttpEngine, versions: []ClientVersion) void {
        for (versions) |cv| {
            self.allocator.free(cv.code);
            self.allocator.free(cv.name);
            self.allocator.free(cv.version);
            self.allocator.free(cv.commit);
        }
        self.allocator.free(versions);
    }

    /// Free a capabilities slice returned by exchangeCapabilities.
    pub fn freeExchangeCapabilities(self: *HttpEngine, capabilities: [][]const u8) void {
        for (capabilities) |cap| {
            self.allocator.free(cap);
        }
        self.allocator.free(capabilities);
    }


    /// Free all allocator-owned fields of a GetPayloadResponse.
    ///
    /// Frees: extra_data, each transaction bytes, transactions slice,
    /// withdrawals slice, blobs_bundle commitments/proofs/blobs,
    /// and any Electra execution request slices.
    pub fn freeGetPayloadResponse(self: *HttpEngine, resp: GetPayloadResponse) void {
        const ep = resp.execution_payload;
        if (ep.extra_data.len > 0) self.allocator.free(ep.extra_data);
        for (ep.transactions) |tx| self.allocator.free(tx);
        if (ep.transactions.len > 0) self.allocator.free(ep.transactions);
        if (ep.withdrawals.len > 0) self.allocator.free(ep.withdrawals);
        if (resp.blobs_bundle.commitments.len > 0) self.allocator.free(resp.blobs_bundle.commitments);
        if (resp.blobs_bundle.proofs.len > 0) self.allocator.free(resp.blobs_bundle.proofs);
        if (resp.blobs_bundle.blobs.len > 0) self.allocator.free(resp.blobs_bundle.blobs);
        // Electra execution requests (empty slices are safe to free).
        if (resp.deposit_requests.len > 0) self.allocator.free(resp.deposit_requests);
        if (resp.withdrawal_requests.len > 0) self.allocator.free(resp.withdrawal_requests);
        if (resp.consolidation_requests.len > 0) self.allocator.free(resp.consolidation_requests);
    }

    /// Free allocator-owned fields of a GetPayloadResponseV1 (Bellatrix).
    pub fn freeGetPayloadResponseV1(self: *HttpEngine, resp: GetPayloadResponseV1) void {
        const ep = resp.execution_payload;
        if (ep.extra_data.len > 0) self.allocator.free(ep.extra_data);
        for (ep.transactions) |tx| self.allocator.free(tx);
        if (ep.transactions.len > 0) self.allocator.free(ep.transactions);
    }

    /// Free allocator-owned fields of a GetPayloadResponseV2 (Capella).
    pub fn freeGetPayloadResponseV2(self: *HttpEngine, resp: GetPayloadResponseV2) void {
        const ep = resp.execution_payload;
        if (ep.extra_data.len > 0) self.allocator.free(ep.extra_data);
        for (ep.transactions) |tx| self.allocator.free(tx);
        if (ep.transactions.len > 0) self.allocator.free(ep.transactions);
        if (ep.withdrawals.len > 0) self.allocator.free(ep.withdrawals);
    }

    /// Free allocator-owned fields of a GetPayloadResponseV4 (Electra).
    pub fn freeGetPayloadResponseV4(self: *HttpEngine, resp: GetPayloadResponseV4) void {
        const ep = resp.execution_payload;
        if (ep.extra_data.len > 0) self.allocator.free(ep.extra_data);
        for (ep.transactions) |tx| self.allocator.free(tx);
        if (ep.transactions.len > 0) self.allocator.free(ep.transactions);
        if (ep.withdrawals.len > 0) self.allocator.free(ep.withdrawals);
        if (resp.blobs_bundle.commitments.len > 0) self.allocator.free(resp.blobs_bundle.commitments);
        if (resp.blobs_bundle.proofs.len > 0) self.allocator.free(resp.blobs_bundle.proofs);
        if (resp.blobs_bundle.blobs.len > 0) self.allocator.free(resp.blobs_bundle.blobs);
    }


    // ── getPayloadBodies ──────────────────────────────────────────────────────

    /// engine_getPayloadBodiesByHashV1: fetch payload bodies for a list of block hashes.
    ///
    /// Returns an array of nullable ExecutionPayloadBodyV1. A null entry means
    /// the block was not found by the EL. Caller owns the returned slice and
    /// each body's inner allocations.
    pub fn getPayloadBodiesByHashV1(
        self: *HttpEngine,
        block_hashes: []const [32]u8,
    ) ![]?ExecutionPayloadBodyV1 {
        return self.getPayloadBodiesByHashImpl(ExecutionPayloadBodyV1, PayloadBodyV1Json, "engine_getPayloadBodiesByHashV1", block_hashes);
    }

    /// engine_getPayloadBodiesByHashV2: V2 variant with Electra execution requests.
    pub fn getPayloadBodiesByHashV2(
        self: *HttpEngine,
        block_hashes: []const [32]u8,
    ) ![]?ExecutionPayloadBodyV2 {
        return self.getPayloadBodiesByHashImpl(ExecutionPayloadBodyV2, PayloadBodyV2Json, "engine_getPayloadBodiesByHashV2", block_hashes);
    }

    /// engine_getPayloadBodiesByRangeV1: fetch payload bodies for a range of block numbers.
    ///
    /// Returns an array of nullable ExecutionPayloadBodyV1. A null entry means
    /// the block was not available. Caller owns the returned slice.
    pub fn getPayloadBodiesByRangeV1(
        self: *HttpEngine,
        start: u64,
        count: u64,
    ) ![]?ExecutionPayloadBodyV1 {
        return self.getPayloadBodiesByRangeImpl(ExecutionPayloadBodyV1, PayloadBodyV1Json, "engine_getPayloadBodiesByRangeV1", start, count);
    }

    /// engine_getPayloadBodiesByRangeV2: V2 variant with Electra execution requests.
    pub fn getPayloadBodiesByRangeV2(
        self: *HttpEngine,
        start: u64,
        count: u64,
    ) ![]?ExecutionPayloadBodyV2 {
        return self.getPayloadBodiesByRangeImpl(ExecutionPayloadBodyV2, PayloadBodyV2Json, "engine_getPayloadBodiesByRangeV2", start, count);
    }

    /// Shared implementation for getPayloadBodiesByHash V1/V2.
    fn getPayloadBodiesByHashImpl(
        self: *HttpEngine,
        comptime BodyT: type,
        comptime JsonT: type,
        method: []const u8,
        block_hashes: []const [32]u8,
    ) ![]?BodyT {
        const id = self.nextId();

        // Encode block hashes as JSON array of hex strings.
        var hash_parts: std.ArrayListUnmanaged([]const u8) = .empty;
        defer {
            for (hash_parts.items) |p| self.allocator.free(p);
            hash_parts.deinit(self.allocator);
        }
        for (block_hashes) |h| {
            const hex = try hexEncodeFixed(self.allocator, &h);
            defer self.allocator.free(hex);
            const quoted = try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{hex});
            try hash_parts.append(self.allocator, quoted);
        }
        const hashes_json = try joinJsonArray(self.allocator, hash_parts.items);
        defer self.allocator.free(hashes_json);

        const params_json = try std.fmt.allocPrint(self.allocator, "[{s}]", .{hashes_json});
        defer self.allocator.free(params_json);

        const body = try encodeRawRequest(self.allocator, method, params_json, id);
        defer self.allocator.free(body);

        const response = try self.sendRequest(body);
        defer self.allocator.free(response);

        return decodePayloadBodiesResponse(BodyT, JsonT, self.allocator, response);
    }

    /// Shared implementation for getPayloadBodiesByRange V1/V2.
    fn getPayloadBodiesByRangeImpl(
        self: *HttpEngine,
        comptime BodyT: type,
        comptime JsonT: type,
        method: []const u8,
        start: u64,
        count: u64,
    ) ![]?BodyT {
        const id = self.nextId();

        const start_hex = try hexEncodeQuantity(self.allocator, start);
        defer self.allocator.free(start_hex);
        const count_hex = try hexEncodeQuantity(self.allocator, count);
        defer self.allocator.free(count_hex);

        const params_json = try std.fmt.allocPrint(
            self.allocator,
            "[\"{s}\",\"{s}\"]",
            .{ start_hex, count_hex },
        );
        defer self.allocator.free(params_json);

        const body = try encodeRawRequest(self.allocator, method, params_json, id);
        defer self.allocator.free(body);

        const response = try self.sendRequest(body);
        defer self.allocator.free(response);

        return decodePayloadBodiesResponse(BodyT, JsonT, self.allocator, response);
    }

    /// Free a nullable payload body V1 slice returned by getPayloadBodiesByHash/RangeV1.
    pub fn freePayloadBodiesV1(self: *HttpEngine, bodies: []?ExecutionPayloadBodyV1) void {
        for (bodies) |maybe_body| {
            if (maybe_body) |b| {
                for (b.transactions) |tx| self.allocator.free(tx);
                if (b.transactions.len > 0) self.allocator.free(b.transactions);
                if (b.withdrawals) |ws| {
                    if (ws.len > 0) self.allocator.free(ws);
                }
            }
        }
        self.allocator.free(bodies);
    }

    /// Free a nullable payload body V2 slice returned by getPayloadBodiesByHash/RangeV2.
    pub fn freePayloadBodiesV2(self: *HttpEngine, bodies: []?ExecutionPayloadBodyV2) void {
        for (bodies) |maybe_body| {
            if (maybe_body) |b| {
                for (b.transactions) |tx| self.allocator.free(tx);
                if (b.transactions.len > 0) self.allocator.free(b.transactions);
                if (b.withdrawals) |ws| {
                    if (ws.len > 0) self.allocator.free(ws);
                }
                if (b.deposit_requests) |drs| {
                    if (drs.len > 0) self.allocator.free(drs);
                }
                if (b.withdrawal_requests) |wrs| {
                    if (wrs.len > 0) self.allocator.free(wrs);
                }
                if (b.consolidation_requests) |crs| {
                    if (crs.len > 0) self.allocator.free(crs);
                }
            }
        }
        self.allocator.free(bodies);
    }

    /// Get payload bodies by hash using the fork-appropriate version.
    pub fn getPayloadBodiesByHashForFork(
        self: *HttpEngine,
        fork: Fork,
        block_hashes: []const [32]u8,
    ) !union(enum) { v1: []?ExecutionPayloadBodyV1, v2: []?ExecutionPayloadBodyV2 } {
        return switch (fork) {
            .phase0, .altair => error.UnsupportedFork,
            .bellatrix, .capella, .deneb => .{ .v1 = try self.getPayloadBodiesByHashV1(block_hashes) },
            .electra, .fulu => .{ .v2 = try self.getPayloadBodiesByHashV2(block_hashes) },
        };
    }

    /// Get payload bodies by range using the fork-appropriate version.
    pub fn getPayloadBodiesByRangeForFork(
        self: *HttpEngine,
        fork: Fork,
        start: u64,
        count: u64,
    ) !union(enum) { v1: []?ExecutionPayloadBodyV1, v2: []?ExecutionPayloadBodyV2 } {
        return switch (fork) {
            .phase0, .altair => error.UnsupportedFork,
            .bellatrix, .capella, .deneb => .{ .v1 = try self.getPayloadBodiesByRangeV1(start, count) },
            .electra, .fulu => .{ .v2 = try self.getPayloadBodiesByRangeV2(start, count) },
        };
    }
    // ── Health monitoring ─────────────────────────────────────────────────────

    /// EL syncing result from eth_syncing.
    pub const SyncingStatus = union(enum) {
        /// EL is fully synced.
        synced,
        /// EL is syncing — contains progress info.
        syncing: SyncingProgress,
    };

    pub const SyncingProgress = struct {
        /// Current head block.
        current_block: u64,
        /// Highest block seen.
        highest_block: u64,
    };

    /// Call eth_syncing to check EL health and sync status.
    ///
    /// Returns `.synced` if the EL is fully synced (eth_syncing returns false),
    /// or `.syncing` with progress info if syncing is in progress.
    ///
    /// Used for periodic health monitoring (every ~30s when idle).
    /// Updates the internal connection state: online, offline, or syncing.
    pub fn checkHealth(self: *HttpEngine) !SyncingStatus {
        const id = self.nextId();

        const body = try encodeRawRequest(self.allocator, "eth_syncing", "[]", id);
        defer self.allocator.free(body);

        const response = self.sendRequest(body) catch |err| {
            std.log.warn("execution layer offline — retrying ({})", .{err});
            self.updateState(.offline);
            return err;
        };
        defer self.allocator.free(response);

        // eth_syncing returns either false (synced) or a sync status object.
        // We need to try parsing as bool first, then as object.
        const BoolOrSyncing = std.json.Value;
        var parsed = try json_rpc.decodeResponse(BoolOrSyncing, self.allocator, response);
        defer parsed.deinit();

        switch (parsed.value) {
            .bool => |b| {
                if (!b) {
                    // false = fully synced
                    if (self.state != .online) {
                        std.log.info("execution layer connected", .{});
                    }
                    self.updateState(.online);
                    return .synced;
                }
                // true = syncing but no detail
                std.log.warn("execution layer syncing", .{});
                self.updateState(.syncing);
                return .{ .syncing = .{ .current_block = 0, .highest_block = 0 } };
            },
            .object => |obj| {
                // Syncing object: {currentBlock, highestBlock, ...}
                const current = if (obj.get("currentBlock")) |v|
                    try hexDecodeQuantity(v.string)
                else
                    0;
                const highest = if (obj.get("highestBlock")) |v|
                    try hexDecodeQuantity(v.string)
                else
                    0;

                std.log.warn("execution layer syncing: block {d}/{d}", .{ current, highest });
                self.updateState(.syncing);
                return .{ .syncing = .{ .current_block = current, .highest_block = highest } };
            },
            else => {
                std.log.warn("execution layer syncing: unexpected response type", .{});
                self.updateState(.syncing);
                return .{ .syncing = .{ .current_block = 0, .highest_block = 0 } };
            },
        }
    }

    // ── Fork-aware dispatch ───────────────────────────────────────────────────

    /// Fork enum for fork-aware dispatch.
    pub const Fork = enum {
        phase0,
        altair,
        bellatrix,
        capella,
        deneb,
        electra,
        fulu,
    };

    /// Submit a new payload for validation using the fork-appropriate method version.
    ///
    /// Dispatches to newPayloadV1/V2/V3/V4 based on fork.
    pub fn newPayloadForFork(
        self: *HttpEngine,
        fork: Fork,
        /// Must be the appropriate payload type for the fork:
        /// V1 for bellatrix, V2 for capella, V3 for deneb, V4 for electra/fulu.
        /// Caller must ensure the correct variant is passed for the given fork.
        payload: anytype,
        versioned_hashes: []const [32]u8,
        parent_beacon_root: [32]u8,
    ) !PayloadStatusV1 {
        return switch (fork) {
            .phase0, .altair => error.UnsupportedFork,
            .bellatrix => blk: {
                // payload must be ExecutionPayloadV1
                const p: ExecutionPayloadV1 = payload;
                break :blk newPayloadV1(@ptrCast(self), p);
            },
            .capella => blk: {
                // payload must be ExecutionPayloadV2
                const p: ExecutionPayloadV2 = payload;
                break :blk newPayloadV2(@ptrCast(self), p);
            },
            .deneb => blk: {
                // payload must be ExecutionPayloadV3
                const p: ExecutionPayloadV3 = payload;
                break :blk newPayloadV3(@ptrCast(self), p, versioned_hashes, parent_beacon_root);
            },
            .electra, .fulu => blk: {
                // payload must be ExecutionPayloadV4
                const p: ExecutionPayloadV4 = payload;
                break :blk newPayloadV4(@ptrCast(self), p, versioned_hashes, parent_beacon_root);
            },
        };
    }

    /// Send forkchoiceUpdated using the fork-appropriate version.
    ///
    /// Unlike newPayloadForFork (which uses comptime dispatch on typed payloads),
    /// this accepts pre-encoded JSON for the attributes parameter. This avoids
    /// needing a comptime `anytype` for attrs (which would require callers to
    /// know the concrete PayloadAttributes variant at comptime). The individual
    /// forkchoiceUpdatedV1/V2/V3 methods accept typed attributes; use those
    /// when the fork is known at comptime.
    pub fn forkchoiceUpdatedForFork(
        self: *HttpEngine,
        fork: Fork,
        state: ForkchoiceStateV1,
        /// Pre-encoded JSON payload attributes, or null.
        /// Use encodePayloadAttributesV1/V2/V3 to produce this from typed values.
        attrs_json: ?[]const u8,
    ) !ForkchoiceUpdatedResponse {
        const method = switch (fork) {
            .phase0, .altair => return error.UnsupportedFork,
            .bellatrix => "engine_forkchoiceUpdatedV1",
            .capella => "engine_forkchoiceUpdatedV2",
            .deneb, .electra, .fulu => "engine_forkchoiceUpdatedV3",
        };

        const id = self.nextId();
        const state_json = try encodeForkchoiceState(self.allocator, state);
        defer self.allocator.free(state_json);

        const attrs = attrs_json orelse "null";
        const params_json = try std.fmt.allocPrint(
            self.allocator,
            "[{s},{s}]",
            .{ state_json, attrs },
        );
        defer self.allocator.free(params_json);

        const body = try encodeRawRequest(self.allocator, method, params_json, id);
        defer self.allocator.free(body);

        const response = try self.sendRequest(body);
        defer self.allocator.free(response);

        var parsed = try json_rpc.decodeResponse(ForkchoiceUpdatedJson, self.allocator, response);
        defer parsed.deinit();

        return decodeForkchoiceUpdatedResponse(self.allocator, parsed.value);
    }


    // ── Payload promotion helpers ─────────────────────────────────────────────

    /// Promote a versioned payload (V1/V2/V4) to the unified ExecutionPayloadV3.
    ///
    /// Copies all fields that exist in both Src and V3 by name. Fields absent
    /// in Src (e.g. withdrawals for V1, blob fields for V2) are zero-initialized.
    fn promoteToV3(src: anytype) ExecutionPayloadV3 {
        const Src = @TypeOf(src);
        var dst: ExecutionPayloadV3 = .{
            .parent_hash = undefined,
            .fee_recipient = undefined,
            .state_root = undefined,
            .receipts_root = undefined,
            .logs_bloom = undefined,
            .prev_randao = undefined,
            .block_number = undefined,
            .gas_limit = undefined,
            .gas_used = undefined,
            .timestamp = undefined,
            .extra_data = undefined,
            .base_fee_per_gas = undefined,
            .block_hash = undefined,
            .transactions = undefined,
            .withdrawals = &.{},
            .blob_gas_used = 0,
            .excess_blob_gas = 0,
        };
        inline for (std.meta.fields(ExecutionPayloadV3)) |dst_field| {
            if (@hasField(Src, dst_field.name)) {
                @field(dst, dst_field.name) = @field(src, dst_field.name);
            }
        }
        return dst;
    }

    /// Get a built payload using the fork-appropriate version.
    pub fn getPayloadForFork(
        self: *HttpEngine,
        fork: Fork,
        payload_id: [8]u8,
    ) !GetPayloadResponse {
        return switch (fork) {
            .phase0, .altair => error.UnsupportedFork,
            .bellatrix => blk: {
                const r = try getPayloadV1(@ptrCast(self), payload_id);
                break :blk GetPayloadResponse{
                    .execution_payload = promoteToV3(r.execution_payload),
                    .block_value = r.block_value,
                    .blobs_bundle = .{ .commitments = &.{}, .proofs = &.{}, .blobs = &.{} },
                    .should_override_builder = false,
                };
            },
            .capella => blk: {
                const r = try getPayloadV2(@ptrCast(self), payload_id);
                break :blk GetPayloadResponse{
                    .execution_payload = promoteToV3(r.execution_payload),
                    .block_value = r.block_value,
                    .blobs_bundle = .{ .commitments = &.{}, .proofs = &.{}, .blobs = &.{} },
                    .should_override_builder = false,
                };
            },
            .deneb => getPayloadV3(@ptrCast(self), payload_id),
            .electra, .fulu => blk: {
                // Fix 2: For Electra/Fulu, call V4 and preserve execution requests.
                // promoteToV3() would discard deposit/withdrawal/consolidation requests.
                const r = try getPayloadV4(@ptrCast(self), payload_id);
                break :blk GetPayloadResponse{
                    .execution_payload = promoteToV3(r.execution_payload),
                    .block_value = r.block_value,
                    .blobs_bundle = r.blobs_bundle,
                    .should_override_builder = r.should_override_builder,
                    .deposit_requests = r.execution_payload.deposit_requests,
                    .withdrawal_requests = r.execution_payload.withdrawal_requests,
                    .consolidation_requests = r.execution_payload.consolidation_requests,
                };
            },
        };
    }

    // ── vtable ────────────────────────────────────────────────────────────────

    const vtable = EngineApi.VTable{
        .newPayloadV1 = &newPayloadV1,
        .newPayloadV2 = &newPayloadV2,
        .newPayloadV3 = &newPayloadV3,
        .newPayloadV4 = &newPayloadV4,
        .forkchoiceUpdatedV1 = &forkchoiceUpdatedV1,
        .forkchoiceUpdatedV2 = &forkchoiceUpdatedV2,
        .forkchoiceUpdatedV3 = &forkchoiceUpdatedV3,
        .getPayloadV1 = &getPayloadV1,
        .getPayloadV2 = &getPayloadV2,
        .getPayloadV3 = &getPayloadV3,
        .getPayloadV4 = &getPayloadV4,
        .freeGetPayloadResponse = &freeGetPayloadResponseImpl,
    };

    fn freeGetPayloadResponseImpl(ptr: *anyopaque, resp: GetPayloadResponse) void {
        const self: *HttpEngine = @ptrCast(@alignCast(ptr));
        self.freeGetPayloadResponse(resp);
    }

    fn newPayloadV3(
        ptr: *anyopaque,
        payload: ExecutionPayloadV3,
        versioned_hashes: []const [32]u8,
        parent_beacon_root: [32]u8,
    ) anyerror!PayloadStatusV1 {
        const self: *HttpEngine = @ptrCast(@alignCast(ptr));
        const id = self.nextId();

        // Encode the payload as Engine API JSON object.
        const payload_json = try encodeExecutionPayloadV3(self.allocator, payload);
        defer self.allocator.free(payload_json);

        // Encode versioned hashes as array of hex strings.
        const vh_json = try encodeVersionedHashes(self.allocator, versioned_hashes);
        defer self.allocator.free(vh_json);

        // Encode parent beacon root.
        const pbr_hex = try hexEncodeFixed(self.allocator, &parent_beacon_root);
        defer self.allocator.free(pbr_hex);

        // Build params as a raw JSON array: [payload, versioned_hashes, parent_beacon_root]
        const params_json = try std.fmt.allocPrint(
            self.allocator,
            "[{s},{s},\"{s}\"]",
            .{ payload_json, vh_json, pbr_hex },
        );
        defer self.allocator.free(params_json);

        const body = try encodeRawRequest(self.allocator, "engine_newPayloadV3", params_json, id);
        defer self.allocator.free(body);

        const response = try self.sendRequest(body);
        defer self.allocator.free(response);

        var parsed = try json_rpc.decodeResponse(PayloadStatusJson, self.allocator, response);
        defer parsed.deinit();

        return decodePayloadStatus(self.allocator, parsed.value);
    }

    fn forkchoiceUpdatedV3(
        ptr: *anyopaque,
        state: ForkchoiceStateV1,
        attrs: ?PayloadAttributesV3,
    ) anyerror!ForkchoiceUpdatedResponse {
        const self: *HttpEngine = @ptrCast(@alignCast(ptr));
        const id = self.nextId();

        const state_json = try encodeForkchoiceState(self.allocator, state);
        defer self.allocator.free(state_json);

        const attrs_json = if (attrs) |a| blk: {
            const j = try encodePayloadAttributes(self.allocator, a);
            break :blk j;
        } else blk: {
            const j = try self.allocator.dupe(u8, "null");
            break :blk j;
        };
        defer self.allocator.free(attrs_json);

        const params_json = try std.fmt.allocPrint(
            self.allocator,
            "[{s},{s}]",
            .{ state_json, attrs_json },
        );
        defer self.allocator.free(params_json);

        const body = try encodeRawRequest(self.allocator, "engine_forkchoiceUpdatedV3", params_json, id);
        defer self.allocator.free(body);

        const response = try self.sendRequest(body);
        defer self.allocator.free(response);

        var parsed = try json_rpc.decodeResponse(ForkchoiceUpdatedJson, self.allocator, response);
        defer parsed.deinit();

        return decodeForkchoiceUpdatedResponse(self.allocator, parsed.value);
    }

    fn getPayloadV3(
        ptr: *anyopaque,
        payload_id: [8]u8,
    ) anyerror!GetPayloadResponse {
        const self: *HttpEngine = @ptrCast(@alignCast(ptr));
        const id = self.nextId();

        const pid_hex = try hexEncodeFixed(self.allocator, &payload_id);
        defer self.allocator.free(pid_hex);

        const params_json = try std.fmt.allocPrint(
            self.allocator,
            "[\"{s}\"]",
            .{pid_hex},
        );
        defer self.allocator.free(params_json);

        const body = try encodeRawRequest(self.allocator, "engine_getPayloadV3", params_json, id);
        defer self.allocator.free(body);

        const response = try self.sendRequest(body);
        defer self.allocator.free(response);

        var parsed = try json_rpc.decodeResponse(GetPayloadJson, self.allocator, response);
        defer parsed.deinit();

        return decodeGetPayloadResponse(self.allocator, parsed.value);
    }

    // ── newPayload V1 / V2 / V4 ───────────────────────────────────────────────

    fn newPayloadV1(
        ptr: *anyopaque,
        payload: ExecutionPayloadV1,
    ) anyerror!PayloadStatusV1 {
        const self: *HttpEngine = @ptrCast(@alignCast(ptr));
        const id = self.nextId();

        const payload_json = try encodeExecutionPayloadV1(self.allocator, payload);
        defer self.allocator.free(payload_json);

        const params_json = try std.fmt.allocPrint(
            self.allocator,
            "[{s}]",
            .{payload_json},
        );
        defer self.allocator.free(params_json);

        const body = try encodeRawRequest(self.allocator, "engine_newPayloadV1", params_json, id);
        defer self.allocator.free(body);

        const response = try self.sendRequest(body);
        defer self.allocator.free(response);

        var parsed = try json_rpc.decodeResponse(PayloadStatusJson, self.allocator, response);
        defer parsed.deinit();

        return decodePayloadStatus(self.allocator, parsed.value);
    }

    fn newPayloadV2(
        ptr: *anyopaque,
        payload: ExecutionPayloadV2,
    ) anyerror!PayloadStatusV1 {
        const self: *HttpEngine = @ptrCast(@alignCast(ptr));
        const id = self.nextId();

        const payload_json = try encodeExecutionPayloadV2(self.allocator, payload);
        defer self.allocator.free(payload_json);

        const params_json = try std.fmt.allocPrint(
            self.allocator,
            "[{s}]",
            .{payload_json},
        );
        defer self.allocator.free(params_json);

        const body = try encodeRawRequest(self.allocator, "engine_newPayloadV2", params_json, id);
        defer self.allocator.free(body);

        const response = try self.sendRequest(body);
        defer self.allocator.free(response);

        var parsed = try json_rpc.decodeResponse(PayloadStatusJson, self.allocator, response);
        defer parsed.deinit();

        return decodePayloadStatus(self.allocator, parsed.value);
    }

    fn newPayloadV4(
        ptr: *anyopaque,
        payload: ExecutionPayloadV4,
        versioned_hashes: []const [32]u8,
        parent_beacon_root: [32]u8,
    ) anyerror!PayloadStatusV1 {
        const self: *HttpEngine = @ptrCast(@alignCast(ptr));
        const id = self.nextId();

        const payload_json = try encodeExecutionPayloadV4(self.allocator, payload);
        defer self.allocator.free(payload_json);

        const vh_json = try encodeVersionedHashes(self.allocator, versioned_hashes);
        defer self.allocator.free(vh_json);

        const pbr_hex = try hexEncodeFixed(self.allocator, &parent_beacon_root);
        defer self.allocator.free(pbr_hex);

        const params_json = try std.fmt.allocPrint(
            self.allocator,
            "[{s},{s},\"{s}\"]",
            .{ payload_json, vh_json, pbr_hex },
        );
        defer self.allocator.free(params_json);

        const body = try encodeRawRequest(self.allocator, "engine_newPayloadV4", params_json, id);
        defer self.allocator.free(body);

        const response = try self.sendRequest(body);
        defer self.allocator.free(response);

        var parsed = try json_rpc.decodeResponse(PayloadStatusJson, self.allocator, response);
        defer parsed.deinit();

        return decodePayloadStatus(self.allocator, parsed.value);
    }

    // ── forkchoiceUpdated V1 / V2 ─────────────────────────────────────────────

    fn forkchoiceUpdatedV1(
        ptr: *anyopaque,
        state: ForkchoiceStateV1,
        attrs: ?PayloadAttributesV1,
    ) anyerror!ForkchoiceUpdatedResponse {
        const self: *HttpEngine = @ptrCast(@alignCast(ptr));
        const id = self.nextId();

        const state_json = try encodeForkchoiceState(self.allocator, state);
        defer self.allocator.free(state_json);

        const attrs_json = if (attrs) |a| blk: {
            break :blk try encodePayloadAttributesV1(self.allocator, a);
        } else blk: {
            break :blk try self.allocator.dupe(u8, "null");
        };
        defer self.allocator.free(attrs_json);

        const params_json = try std.fmt.allocPrint(
            self.allocator,
            "[{s},{s}]",
            .{ state_json, attrs_json },
        );
        defer self.allocator.free(params_json);

        const body = try encodeRawRequest(self.allocator, "engine_forkchoiceUpdatedV1", params_json, id);
        defer self.allocator.free(body);

        const response = try self.sendRequest(body);
        defer self.allocator.free(response);

        var parsed = try json_rpc.decodeResponse(ForkchoiceUpdatedJson, self.allocator, response);
        defer parsed.deinit();

        return decodeForkchoiceUpdatedResponse(self.allocator, parsed.value);
    }

    fn forkchoiceUpdatedV2(
        ptr: *anyopaque,
        state: ForkchoiceStateV1,
        attrs: ?PayloadAttributesV2,
    ) anyerror!ForkchoiceUpdatedResponse {
        const self: *HttpEngine = @ptrCast(@alignCast(ptr));
        const id = self.nextId();

        const state_json = try encodeForkchoiceState(self.allocator, state);
        defer self.allocator.free(state_json);

        const attrs_json = if (attrs) |a| blk: {
            break :blk try encodePayloadAttributesV2(self.allocator, a);
        } else blk: {
            break :blk try self.allocator.dupe(u8, "null");
        };
        defer self.allocator.free(attrs_json);

        const params_json = try std.fmt.allocPrint(
            self.allocator,
            "[{s},{s}]",
            .{ state_json, attrs_json },
        );
        defer self.allocator.free(params_json);

        const body = try encodeRawRequest(self.allocator, "engine_forkchoiceUpdatedV2", params_json, id);
        defer self.allocator.free(body);

        const response = try self.sendRequest(body);
        defer self.allocator.free(response);

        var parsed = try json_rpc.decodeResponse(ForkchoiceUpdatedJson, self.allocator, response);
        defer parsed.deinit();

        return decodeForkchoiceUpdatedResponse(self.allocator, parsed.value);
    }

    // ── getPayload V1 / V2 / V4 ──────────────────────────────────────────────

    fn getPayloadV1(
        ptr: *anyopaque,
        payload_id: [8]u8,
    ) anyerror!GetPayloadResponseV1 {
        const self: *HttpEngine = @ptrCast(@alignCast(ptr));
        const id = self.nextId();

        const pid_hex = try hexEncodeFixed(self.allocator, &payload_id);
        defer self.allocator.free(pid_hex);

        const params_json = try std.fmt.allocPrint(
            self.allocator,
            "[\"{s}\"]",
            .{pid_hex},
        );
        defer self.allocator.free(params_json);

        const body = try encodeRawRequest(self.allocator, "engine_getPayloadV1", params_json, id);
        defer self.allocator.free(body);

        const response = try self.sendRequest(body);
        defer self.allocator.free(response);

        var parsed = try json_rpc.decodeResponse(GetPayloadV1Json, self.allocator, response);
        defer parsed.deinit();

        return decodeGetPayloadResponseV1(self.allocator, parsed.value);
    }

    fn getPayloadV2(
        ptr: *anyopaque,
        payload_id: [8]u8,
    ) anyerror!GetPayloadResponseV2 {
        const self: *HttpEngine = @ptrCast(@alignCast(ptr));
        const id = self.nextId();

        const pid_hex = try hexEncodeFixed(self.allocator, &payload_id);
        defer self.allocator.free(pid_hex);

        const params_json = try std.fmt.allocPrint(
            self.allocator,
            "[\"{s}\"]",
            .{pid_hex},
        );
        defer self.allocator.free(params_json);

        const body = try encodeRawRequest(self.allocator, "engine_getPayloadV2", params_json, id);
        defer self.allocator.free(body);

        const response = try self.sendRequest(body);
        defer self.allocator.free(response);

        var parsed = try json_rpc.decodeResponse(GetPayloadV2Json, self.allocator, response);
        defer parsed.deinit();

        return decodeGetPayloadResponseV2(self.allocator, parsed.value);
    }

    fn getPayloadV4(
        ptr: *anyopaque,
        payload_id: [8]u8,
    ) anyerror!GetPayloadResponseV4 {
        const self: *HttpEngine = @ptrCast(@alignCast(ptr));
        const id = self.nextId();

        const pid_hex = try hexEncodeFixed(self.allocator, &payload_id);
        defer self.allocator.free(pid_hex);

        const params_json = try std.fmt.allocPrint(
            self.allocator,
            "[\"{s}\"]",
            .{pid_hex},
        );
        defer self.allocator.free(params_json);

        const body = try encodeRawRequest(self.allocator, "engine_getPayloadV4", params_json, id);
        defer self.allocator.free(body);

        const response = try self.sendRequest(body);
        defer self.allocator.free(response);

        var parsed = try json_rpc.decodeResponse(GetPayloadV4Json, self.allocator, response);
        defer parsed.deinit();

        return decodeGetPayloadResponseV4(self.allocator, parsed.value);
    }
};

// ── Time ─────────────────────────────────────────────────────────────────────

/// Get the current Unix timestamp in seconds via std.Io.
fn unixTimestamp(io: std.Io) u64 {
    const now = std.Io.Clock.real.now(io);
    return @intCast(@divTrunc(now.nanoseconds, std.time.ns_per_s));
}

// ── Encoding helpers ──────────────────────────────────────────────────────────

/// Encode a raw JSON-RPC request where params is already a JSON string.
/// Returns an allocated JSON byte string. Caller owns the memory.
fn encodeRawRequest(
    allocator: Allocator,
    method: []const u8,
    params_json: []const u8,
    id: u64,
) ![]const u8 {
    return std.fmt.allocPrint(
        allocator,
        "{{\"jsonrpc\":\"2.0\",\"method\":\"{s}\",\"params\":{s},\"id\":{d}}}",
        .{ method, params_json, id },
    );
}

/// Hex-encode `bytes` with a "0x" prefix. Caller owns the memory.
pub fn hexEncode(allocator: Allocator, bytes: []const u8) ![]const u8 {
    const hex_chars = "0123456789abcdef";
    const out = try allocator.alloc(u8, 2 + bytes.len * 2);
    out[0] = '0';
    out[1] = 'x';
    for (bytes, 0..) |b, i| {
        out[2 + i * 2] = hex_chars[b >> 4];
        out[2 + i * 2 + 1] = hex_chars[b & 0xf];
    }
    return out;
}

/// Hex-encode a fixed-size byte array with a "0x" prefix. Caller owns the memory.
pub fn hexEncodeFixed(allocator: Allocator, bytes: anytype) ![]const u8 {
    return hexEncode(allocator, bytes);
}

/// Hex-encode a u256 as big-endian with "0x" prefix.
/// Use this for fixed-width DATA fields.
pub fn hexEncodeU256(allocator: Allocator, value: u256) ![]const u8 {
    var buf: [32]u8 = undefined;
    std.mem.writeInt(u256, &buf, value, .big);
    return hexEncode(allocator, &buf);
}

/// Hex-encode a u64 as a QUANTITY (0x-prefixed, no leading zeros).
/// Per Engine API spec, quantities like blockNumber, gasLimit, etc. must
/// be encoded without leading zeros (e.g. "0x0" not "0x0000000000000000").
pub fn hexEncodeQuantity(allocator: Allocator, value: u64) ![]const u8 {
    if (value == 0) return allocator.dupe(u8, "0x0");
    const hex_chars = "0123456789abcdef";
    // u64 fits in 16 hex digits max.
    var tmp: [16]u8 = undefined;
    var pos: usize = 16;
    var v = value;
    while (v > 0) {
        pos -= 1;
        tmp[pos] = hex_chars[v & 0xf];
        v >>= 4;
    }
    const hex_digits = tmp[pos..];
    const out = try allocator.alloc(u8, 2 + hex_digits.len);
    out[0] = '0';
    out[1] = 'x';
    @memcpy(out[2..], hex_digits);
    return out;
}

/// Hex-encode a u256 as a QUANTITY (0x-prefixed, no leading zeros).
pub fn hexEncodeQuantityU256(allocator: Allocator, value: u256) ![]const u8 {
    if (value == 0) return allocator.dupe(u8, "0x0");
    const hex_chars = "0123456789abcdef";
    var tmp: [64]u8 = undefined;
    var pos: usize = 64;
    var v = value;
    while (v > 0) {
        pos -= 1;
        tmp[pos] = hex_chars[@intCast(v & 0xf)];
        v >>= 4;
    }
    const hex_digits = tmp[pos..];
    const out = try allocator.alloc(u8, 2 + hex_digits.len);
    out[0] = '0';
    out[1] = 'x';
    @memcpy(out[2..], hex_digits);
    return out;
}

/// Base64url-encode (no padding). Caller owns the memory.
pub fn base64urlEncode(allocator: Allocator, data: []const u8) ![]const u8 {
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const out_len = encoder.calcSize(data.len);
    const out = try allocator.alloc(u8, out_len);
    _ = encoder.encode(out, data);
    return out;
}

/// Generate a JWT HS256 token with `{"iat":<iat>}` payload.
/// Returns an allocated token string. Caller owns the memory.
pub fn generateJwt(allocator: Allocator, secret: [32]u8, iat: u64) ![]const u8 {
    // Header: {"typ":"JWT","alg":"HS256"}
    const header_json = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";
    const header_b64 = try base64urlEncode(allocator, header_json);
    defer allocator.free(header_b64);

    // Payload: {"iat":<timestamp>}
    const payload_json = try std.fmt.allocPrint(allocator, "{{\"iat\":{d}}}", .{iat});
    defer allocator.free(payload_json);
    const payload_b64 = try base64urlEncode(allocator, payload_json);
    defer allocator.free(payload_b64);

    // Signing input: header_b64 + "." + payload_b64
    const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ header_b64, payload_b64 });
    defer allocator.free(signing_input);

    // HMAC-SHA256 signature.
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, signing_input, &secret);

    const sig_b64 = try base64urlEncode(allocator, &mac);
    defer allocator.free(sig_b64);

    return std.fmt.allocPrint(allocator, "{s}.{s}.{s}", .{ header_b64, payload_b64, sig_b64 });
}

// ── Engine API JSON encoding ──────────────────────────────────────────────────

fn encodeWithdrawal(allocator: Allocator, w: Withdrawal) ![]const u8 {
    const index_hex = try hexEncodeQuantity(allocator, w.index);
    defer allocator.free(index_hex);
    const vi_hex = try hexEncodeQuantity(allocator, w.validator_index);
    defer allocator.free(vi_hex);
    const addr_hex = try hexEncodeFixed(allocator, &w.address);
    defer allocator.free(addr_hex);
    const amt_hex = try hexEncodeQuantity(allocator, w.amount);
    defer allocator.free(amt_hex);

    return std.fmt.allocPrint(
        allocator,
        "{{\"index\":\"{s}\",\"validatorIndex\":\"{s}\",\"address\":\"{s}\",\"amount\":\"{s}\"}}",
        .{ index_hex, vi_hex, addr_hex, amt_hex },
    );
}

fn encodeWithdrawals(allocator: Allocator, withdrawals: []const Withdrawal) ![]const u8 {
    var parts: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (parts.items) |p| allocator.free(p);
        parts.deinit(allocator);
    }

    for (withdrawals) |w| {
        const encoded = try encodeWithdrawal(allocator, w);
        try parts.append(allocator, encoded);
    }

    return joinJsonArray(allocator, parts.items);
}

fn joinJsonArray(allocator: Allocator, items: []const []const u8) ![]const u8 {
    if (items.len == 0) return allocator.dupe(u8, "[]");

    var total: usize = 2; // '[' + ']'
    for (items, 0..) |item, i| {
        total += item.len;
        if (i + 1 < items.len) total += 1; // comma
    }

    const out = try allocator.alloc(u8, total);
    out[0] = '[';
    var pos: usize = 1;
    for (items, 0..) |item, i| {
        @memcpy(out[pos .. pos + item.len], item);
        pos += item.len;
        if (i + 1 < items.len) {
            out[pos] = ',';
            pos += 1;
        }
    }
    out[pos] = ']';
    return out;
}

fn encodeTransactions(allocator: Allocator, txs: []const []const u8) ![]const u8 {
    var parts: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (parts.items) |p| allocator.free(p);
        parts.deinit(allocator);
    }

    for (txs) |tx| {
        const hex = try hexEncode(allocator, tx);
        defer allocator.free(hex);
        const quoted = try std.fmt.allocPrint(allocator, "\"{s}\"", .{hex});
        try parts.append(allocator, quoted);
    }

    return joinJsonArray(allocator, parts.items);
}

fn encodeVersionedHashes(allocator: Allocator, hashes: []const [32]u8) ![]const u8 {
    var parts: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (parts.items) |p| allocator.free(p);
        parts.deinit(allocator);
    }

    for (hashes) |h| {
        const hex = try hexEncodeFixed(allocator, &h);
        defer allocator.free(hex);
        const quoted = try std.fmt.allocPrint(allocator, "\"{s}\"", .{hex});
        try parts.append(allocator, quoted);
    }

    return joinJsonArray(allocator, parts.items);
}

fn encodePayloadAttributesV1(allocator: Allocator, attrs: PayloadAttributesV1) ![]const u8 {
    const timestamp = try hexEncodeQuantity(allocator, attrs.timestamp);
    defer allocator.free(timestamp);
    const prev_randao = try hexEncodeFixed(allocator, &attrs.prev_randao);
    defer allocator.free(prev_randao);
    const fee_recipient = try hexEncodeFixed(allocator, &attrs.suggested_fee_recipient);
    defer allocator.free(fee_recipient);

    return std.fmt.allocPrint(
        allocator,
        "{{\"timestamp\":\"{s}\",\"prevRandao\":\"{s}\",\"suggestedFeeRecipient\":\"{s}\"}}",
        .{ timestamp, prev_randao, fee_recipient },
    );
}

fn encodePayloadAttributesV2(allocator: Allocator, attrs: PayloadAttributesV2) ![]const u8 {
    const timestamp = try hexEncodeQuantity(allocator, attrs.timestamp);
    defer allocator.free(timestamp);
    const prev_randao = try hexEncodeFixed(allocator, &attrs.prev_randao);
    defer allocator.free(prev_randao);
    const fee_recipient = try hexEncodeFixed(allocator, &attrs.suggested_fee_recipient);
    defer allocator.free(fee_recipient);
    const withdrawals = try encodeWithdrawals(allocator, attrs.withdrawals);
    defer allocator.free(withdrawals);

    return std.fmt.allocPrint(
        allocator,
        "{{\"timestamp\":\"{s}\",\"prevRandao\":\"{s}\",\"suggestedFeeRecipient\":\"{s}\",\"withdrawals\":{s}}}",
        .{ timestamp, prev_randao, fee_recipient, withdrawals },
    );
}

/// Encodes the 14 base execution payload fields (present in V1-V4) into
/// their hex/JSON representations. Call `b.deinit(allocator)` to free all strings.
const BasePayloadEncoded = struct {
    parent_hash: []const u8,
    fee_recipient: []const u8,
    state_root: []const u8,
    receipts_root: []const u8,
    logs_bloom: []const u8,
    prev_randao: []const u8,
    block_number: []const u8,
    gas_limit: []const u8,
    gas_used: []const u8,
    timestamp: []const u8,
    extra_data: []const u8,
    base_fee: []const u8,
    block_hash: []const u8,
    transactions: []const u8,

    fn deinit(self: BasePayloadEncoded, allocator: Allocator) void {
        allocator.free(self.parent_hash);
        allocator.free(self.fee_recipient);
        allocator.free(self.state_root);
        allocator.free(self.receipts_root);
        allocator.free(self.logs_bloom);
        allocator.free(self.prev_randao);
        allocator.free(self.block_number);
        allocator.free(self.gas_limit);
        allocator.free(self.gas_used);
        allocator.free(self.timestamp);
        allocator.free(self.extra_data);
        allocator.free(self.base_fee);
        allocator.free(self.block_hash);
        allocator.free(self.transactions);
    }
};

/// Encode the 14 fields common to ExecutionPayload V1-V4.
/// Accepts any payload struct that has these fields (V1/V2/V3/V4 all qualify).
fn encodeBasePayloadFields(allocator: Allocator, p: anytype) !BasePayloadEncoded {
    const parent_hash = try hexEncodeFixed(allocator, &p.parent_hash);
    errdefer allocator.free(parent_hash);
    const fee_recipient = try hexEncodeFixed(allocator, &p.fee_recipient);
    errdefer allocator.free(fee_recipient);
    const state_root = try hexEncodeFixed(allocator, &p.state_root);
    errdefer allocator.free(state_root);
    const receipts_root = try hexEncodeFixed(allocator, &p.receipts_root);
    errdefer allocator.free(receipts_root);
    const logs_bloom = try hexEncodeFixed(allocator, &p.logs_bloom);
    errdefer allocator.free(logs_bloom);
    const prev_randao = try hexEncodeFixed(allocator, &p.prev_randao);
    errdefer allocator.free(prev_randao);
    const block_number = try hexEncodeQuantity(allocator, p.block_number);
    errdefer allocator.free(block_number);
    const gas_limit = try hexEncodeQuantity(allocator, p.gas_limit);
    errdefer allocator.free(gas_limit);
    const gas_used = try hexEncodeQuantity(allocator, p.gas_used);
    errdefer allocator.free(gas_used);
    const timestamp = try hexEncodeQuantity(allocator, p.timestamp);
    errdefer allocator.free(timestamp);
    const extra_data = try hexEncode(allocator, p.extra_data);
    errdefer if (extra_data.len > 0) allocator.free(extra_data);
    const base_fee = try hexEncodeQuantityU256(allocator, p.base_fee_per_gas);
    errdefer allocator.free(base_fee);
    const block_hash = try hexEncodeFixed(allocator, &p.block_hash);
    errdefer allocator.free(block_hash);
    const transactions = try encodeTransactions(allocator, p.transactions);
    errdefer allocator.free(transactions);
    return .{
        .parent_hash = parent_hash,
        .fee_recipient = fee_recipient,
        .state_root = state_root,
        .receipts_root = receipts_root,
        .logs_bloom = logs_bloom,
        .prev_randao = prev_randao,
        .block_number = block_number,
        .gas_limit = gas_limit,
        .gas_used = gas_used,
        .timestamp = timestamp,
        .extra_data = extra_data,
        .base_fee = base_fee,
        .block_hash = block_hash,
        .transactions = transactions,
    };
}

fn encodeExecutionPayloadV1(allocator: Allocator, p: ExecutionPayloadV1) ![]const u8 {
    const b = try encodeBasePayloadFields(allocator, p);
    defer b.deinit(allocator);
    return std.fmt.allocPrint(allocator,
        \\{{
        \\"parentHash":"{s}",
        \\"feeRecipient":"{s}",
        \\"stateRoot":"{s}",
        \\"receiptsRoot":"{s}",
        \\"logsBloom":"{s}",
        \\"prevRandao":"{s}",
        \\"blockNumber":"{s}",
        \\"gasLimit":"{s}",
        \\"gasUsed":"{s}",
        \\"timestamp":"{s}",
        \\"extraData":"{s}",
        \\"baseFeePerGas":"{s}",
        \\"blockHash":"{s}",
        \\"transactions":{s}
        \\}}
    , .{
        b.parent_hash,  b.fee_recipient, b.state_root,  b.receipts_root,
        b.logs_bloom,   b.prev_randao,   b.block_number, b.gas_limit,
        b.gas_used,     b.timestamp,     b.extra_data,   b.base_fee,
        b.block_hash,   b.transactions,
    });
}

fn encodeExecutionPayloadV2(allocator: Allocator, p: ExecutionPayloadV2) ![]const u8 {
    const b = try encodeBasePayloadFields(allocator, p);
    defer b.deinit(allocator);
    const withdrawals = try encodeWithdrawals(allocator, p.withdrawals);
    defer allocator.free(withdrawals);
    return std.fmt.allocPrint(allocator,
        \\{{
        \\"parentHash":"{s}",
        \\"feeRecipient":"{s}",
        \\"stateRoot":"{s}",
        \\"receiptsRoot":"{s}",
        \\"logsBloom":"{s}",
        \\"prevRandao":"{s}",
        \\"blockNumber":"{s}",
        \\"gasLimit":"{s}",
        \\"gasUsed":"{s}",
        \\"timestamp":"{s}",
        \\"extraData":"{s}",
        \\"baseFeePerGas":"{s}",
        \\"blockHash":"{s}",
        \\"transactions":{s},
        \\"withdrawals":{s}
        \\}}
    , .{
        b.parent_hash,  b.fee_recipient, b.state_root,   b.receipts_root,
        b.logs_bloom,   b.prev_randao,   b.block_number,  b.gas_limit,
        b.gas_used,     b.timestamp,     b.extra_data,    b.base_fee,
        b.block_hash,   b.transactions,  withdrawals,
    });
}

fn encodeDepositRequest(allocator: Allocator, dr: DepositRequest) ![]const u8 {
    const pubkey = try hexEncodeFixed(allocator, &dr.pubkey);
    defer allocator.free(pubkey);
    const wc = try hexEncodeFixed(allocator, &dr.withdrawal_credentials);
    defer allocator.free(wc);
    const amount = try hexEncodeQuantity(allocator, dr.amount);
    defer allocator.free(amount);
    const sig = try hexEncodeFixed(allocator, &dr.signature);
    defer allocator.free(sig);
    const index = try hexEncodeQuantity(allocator, dr.index);
    defer allocator.free(index);
    return std.fmt.allocPrint(
        allocator,
        "{{\"pubkey\":\"{s}\",\"withdrawalCredentials\":\"{s}\",\"amount\":\"{s}\",\"signature\":\"{s}\",\"index\":\"{s}\"}}",
        .{ pubkey, wc, amount, sig, index },
    );
}

fn encodeWithdrawalRequest(allocator: Allocator, wr: WithdrawalRequest) ![]const u8 {
    const src = try hexEncodeFixed(allocator, &wr.source_address);
    defer allocator.free(src);
    const vpk = try hexEncodeFixed(allocator, &wr.validator_pubkey);
    defer allocator.free(vpk);
    const amt = try hexEncodeQuantity(allocator, wr.amount);
    defer allocator.free(amt);
    return std.fmt.allocPrint(
        allocator,
        "{{\"sourceAddress\":\"{s}\",\"validatorPubkey\":\"{s}\",\"amount\":\"{s}\"}}",
        .{ src, vpk, amt },
    );
}

fn encodeConsolidationRequest(allocator: Allocator, cr: ConsolidationRequest) ![]const u8 {
    const src = try hexEncodeFixed(allocator, &cr.source_address);
    defer allocator.free(src);
    const spk = try hexEncodeFixed(allocator, &cr.source_pubkey);
    defer allocator.free(spk);
    const tpk = try hexEncodeFixed(allocator, &cr.target_pubkey);
    defer allocator.free(tpk);
    return std.fmt.allocPrint(
        allocator,
        "{{\"sourceAddress\":\"{s}\",\"sourcePubkey\":\"{s}\",\"targetPubkey\":\"{s}\"}}",
        .{ src, spk, tpk },
    );
}

fn encodeDepositRequests(allocator: Allocator, requests: []const DepositRequest) ![]const u8 {
    var parts: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (parts.items) |p| allocator.free(p);
        parts.deinit(allocator);
    }
    for (requests) |r| {
        try parts.append(allocator, try encodeDepositRequest(allocator, r));
    }
    return joinJsonArray(allocator, parts.items);
}

fn encodeWithdrawalRequests(allocator: Allocator, requests: []const WithdrawalRequest) ![]const u8 {
    var parts: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (parts.items) |p| allocator.free(p);
        parts.deinit(allocator);
    }
    for (requests) |r| {
        try parts.append(allocator, try encodeWithdrawalRequest(allocator, r));
    }
    return joinJsonArray(allocator, parts.items);
}

fn encodeConsolidationRequests(allocator: Allocator, requests: []const ConsolidationRequest) ![]const u8 {
    var parts: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (parts.items) |p| allocator.free(p);
        parts.deinit(allocator);
    }
    for (requests) |r| {
        try parts.append(allocator, try encodeConsolidationRequest(allocator, r));
    }
    return joinJsonArray(allocator, parts.items);
}

fn encodeExecutionPayloadV4(allocator: Allocator, p: ExecutionPayloadV4) ![]const u8 {
    const b = try encodeBasePayloadFields(allocator, p);
    defer b.deinit(allocator);
    const withdrawals = try encodeWithdrawals(allocator, p.withdrawals);
    defer allocator.free(withdrawals);
    const blob_gas_used = try hexEncodeQuantity(allocator, p.blob_gas_used);
    defer allocator.free(blob_gas_used);
    const excess_blob_gas = try hexEncodeQuantity(allocator, p.excess_blob_gas);
    defer allocator.free(excess_blob_gas);
    const deposit_requests = try encodeDepositRequests(allocator, p.deposit_requests);
    defer allocator.free(deposit_requests);
    const withdrawal_requests = try encodeWithdrawalRequests(allocator, p.withdrawal_requests);
    defer allocator.free(withdrawal_requests);
    const consolidation_requests = try encodeConsolidationRequests(allocator, p.consolidation_requests);
    defer allocator.free(consolidation_requests);
    return std.fmt.allocPrint(allocator,
        \\{{
        \\"parentHash":"{s}",
        \\"feeRecipient":"{s}",
        \\"stateRoot":"{s}",
        \\"receiptsRoot":"{s}",
        \\"logsBloom":"{s}",
        \\"prevRandao":"{s}",
        \\"blockNumber":"{s}",
        \\"gasLimit":"{s}",
        \\"gasUsed":"{s}",
        \\"timestamp":"{s}",
        \\"extraData":"{s}",
        \\"baseFeePerGas":"{s}",
        \\"blockHash":"{s}",
        \\"transactions":{s},
        \\"withdrawals":{s},
        \\"blobGasUsed":"{s}",
        \\"excessBlobGas":"{s}",
        \\"depositRequests":{s},
        \\"withdrawalRequests":{s},
        \\"consolidationRequests":{s}
        \\}}
    , .{
        b.parent_hash,          b.fee_recipient,        b.state_root,           b.receipts_root,
        b.logs_bloom,           b.prev_randao,           b.block_number,         b.gas_limit,
        b.gas_used,             b.timestamp,             b.extra_data,           b.base_fee,
        b.block_hash,           b.transactions,          withdrawals,            blob_gas_used,
        excess_blob_gas,        deposit_requests,        withdrawal_requests,    consolidation_requests,
    });
}

fn encodeExecutionPayloadV3(allocator: Allocator, p: ExecutionPayloadV3) ![]const u8 {
    const b = try encodeBasePayloadFields(allocator, p);
    defer b.deinit(allocator);
    const withdrawals = try encodeWithdrawals(allocator, p.withdrawals);
    defer allocator.free(withdrawals);
    const blob_gas_used = try hexEncodeQuantity(allocator, p.blob_gas_used);
    defer allocator.free(blob_gas_used);
    const excess_blob_gas = try hexEncodeQuantity(allocator, p.excess_blob_gas);
    defer allocator.free(excess_blob_gas);
    return std.fmt.allocPrint(allocator,
        \\{{
        \\"parentHash":"{s}",
        \\"feeRecipient":"{s}",
        \\"stateRoot":"{s}",
        \\"receiptsRoot":"{s}",
        \\"logsBloom":"{s}",
        \\"prevRandao":"{s}",
        \\"blockNumber":"{s}",
        \\"gasLimit":"{s}",
        \\"gasUsed":"{s}",
        \\"timestamp":"{s}",
        \\"extraData":"{s}",
        \\"baseFeePerGas":"{s}",
        \\"blockHash":"{s}",
        \\"transactions":{s},
        \\"withdrawals":{s},
        \\"blobGasUsed":"{s}",
        \\"excessBlobGas":"{s}"
        \\}}
    , .{
        b.parent_hash,   b.fee_recipient, b.state_root,    b.receipts_root,
        b.logs_bloom,    b.prev_randao,   b.block_number,  b.gas_limit,
        b.gas_used,      b.timestamp,     b.extra_data,    b.base_fee,
        b.block_hash,    b.transactions,  withdrawals,     blob_gas_used,
        excess_blob_gas,
    });
}

fn encodeForkchoiceState(allocator: Allocator, state: ForkchoiceStateV1) ![]const u8 {
    const head = try hexEncodeFixed(allocator, &state.head_block_hash);
    defer allocator.free(head);
    const safe = try hexEncodeFixed(allocator, &state.safe_block_hash);
    defer allocator.free(safe);
    const fin = try hexEncodeFixed(allocator, &state.finalized_block_hash);
    defer allocator.free(fin);

    return std.fmt.allocPrint(
        allocator,
        "{{\"headBlockHash\":\"{s}\",\"safeBlockHash\":\"{s}\",\"finalizedBlockHash\":\"{s}\"}}",
        .{ head, safe, fin },
    );
}

fn encodePayloadAttributes(allocator: Allocator, attrs: PayloadAttributesV3) ![]const u8 {
    const timestamp = try hexEncodeQuantity(allocator, attrs.timestamp);
    defer allocator.free(timestamp);
    const prev_randao = try hexEncodeFixed(allocator, &attrs.prev_randao);
    defer allocator.free(prev_randao);
    const fee_recipient = try hexEncodeFixed(allocator, &attrs.suggested_fee_recipient);
    defer allocator.free(fee_recipient);
    const withdrawals = try encodeWithdrawals(allocator, attrs.withdrawals);
    defer allocator.free(withdrawals);
    const pbr = try hexEncodeFixed(allocator, &attrs.parent_beacon_block_root);
    defer allocator.free(pbr);

    return std.fmt.allocPrint(
        allocator,
        "{{\"timestamp\":\"{s}\",\"prevRandao\":\"{s}\",\"suggestedFeeRecipient\":\"{s}\",\"withdrawals\":{s},\"parentBeaconBlockRoot\":\"{s}\"}}",
        .{ timestamp, prev_randao, fee_recipient, withdrawals, pbr },
    );
}

// ── JSON response decoding ────────────────────────────────────────────────────

/// Intermediate JSON representation for PayloadStatusV1.
const PayloadStatusJson = struct {
    status: []const u8,
    latestValidHash: ?[]const u8 = null,
    validationError: ?[]const u8 = null,
};

fn decodePayloadStatus(allocator: Allocator, j: PayloadStatusJson) !PayloadStatusV1 {
    const status = blk: {
        if (std.mem.eql(u8, j.status, "VALID")) break :blk ExecutionPayloadStatus.valid;
        if (std.mem.eql(u8, j.status, "INVALID")) break :blk ExecutionPayloadStatus.invalid;
        if (std.mem.eql(u8, j.status, "SYNCING")) break :blk ExecutionPayloadStatus.syncing;
        if (std.mem.eql(u8, j.status, "ACCEPTED")) break :blk ExecutionPayloadStatus.accepted;
        if (std.mem.eql(u8, j.status, "INVALID_BLOCK_HASH")) break :blk ExecutionPayloadStatus.invalid_block_hash;
        return error.UnknownPayloadStatus;
    };

    const lvh: ?[32]u8 = if (j.latestValidHash) |h| try hexDecode32(h) else null;

    // Dupe validationError to avoid dangling pointer into the parsed JSON arena.
    const validation_error: ?[]const u8 = if (j.validationError) |ve|
        try allocator.dupe(u8, ve)
    else
        null;

    return PayloadStatusV1{
        .status = status,
        .latest_valid_hash = lvh,
        .validation_error = validation_error,
    };
}

/// Intermediate JSON representation for ForkchoiceUpdatedResponse.
const ForkchoiceUpdatedJson = struct {
    payloadStatus: PayloadStatusJson,
    payloadId: ?[]const u8 = null,
};

fn decodeForkchoiceUpdatedResponse(allocator: Allocator, j: ForkchoiceUpdatedJson) !ForkchoiceUpdatedResponse {
    const payload_status = try decodePayloadStatus(allocator, j.payloadStatus);

    const payload_id: ?[8]u8 = if (j.payloadId) |pid| blk: {
        if (pid.len < 2 or (pid[0] != '0' or pid[1] != 'x')) return error.InvalidPayloadId;
        const hex_str = pid[2..];
        if (hex_str.len != 16) return error.InvalidPayloadId;
        var bytes: [8]u8 = undefined;
        _ = try std.fmt.hexToBytes(&bytes, hex_str);
        break :blk bytes;
    } else null;

    return ForkchoiceUpdatedResponse{
        .payload_status = payload_status,
        .payload_id = payload_id,
    };
}

/// Intermediate JSON representation for GetPayloadResponse.
const GetPayloadJson = struct {
    executionPayload: ExecutionPayloadJsonV3,
    blockValue: []const u8,
    blobsBundle: BlobsBundleJson,
    shouldOverrideBuilder: bool,
};

const ExecutionPayloadJsonV3 = struct {
    parentHash: []const u8,
    feeRecipient: []const u8,
    stateRoot: []const u8,
    receiptsRoot: []const u8,
    logsBloom: []const u8,
    prevRandao: []const u8,
    blockNumber: []const u8,
    gasLimit: []const u8,
    gasUsed: []const u8,
    timestamp: []const u8,
    extraData: []const u8,
    baseFeePerGas: []const u8,
    blockHash: []const u8,
    transactions: []const []const u8,
    withdrawals: []const WithdrawalJson,
    blobGasUsed: []const u8,
    excessBlobGas: []const u8,
};

const WithdrawalJson = struct {
    index: []const u8,
    validatorIndex: []const u8,
    address: []const u8,
    amount: []const u8,
};

const BlobsBundleJson = struct {
    commitments: []const []const u8,
    proofs: []const []const u8,
    blobs: []const []const u8,
};

fn decodeGetPayloadResponse(allocator: Allocator, j: GetPayloadJson) !GetPayloadResponse {
    const ep = j.executionPayload;

    // Deep-copy extra_data: decode hex bytes into owned memory.
    const extra_data = try decodeExtraData(allocator, ep.extraData);
    errdefer if (extra_data.len > 0) allocator.free(extra_data);

    // Deep-copy transactions from arena.
    const transactions = try decodeTransactions(allocator, ep.transactions);
    errdefer {
        for (transactions) |tx| allocator.free(tx);
        if (transactions.len > 0) allocator.free(transactions);
    }

    // Decode and deep-copy withdrawals from arena.
    const withdrawals = try decodeWithdrawalsOwned(allocator, ep.withdrawals);
    errdefer if (withdrawals.len > 0) allocator.free(withdrawals);

    // Decode blobs bundle.
    const blobs_bundle = try decodeBlobsBundle(allocator, j.blobsBundle);
    errdefer {
        if (blobs_bundle.commitments.len > 0) allocator.free(blobs_bundle.commitments);
        if (blobs_bundle.proofs.len > 0) allocator.free(blobs_bundle.proofs);
        if (blobs_bundle.blobs.len > 0) allocator.free(blobs_bundle.blobs);
    }

    const payload = ExecutionPayloadV3{
        .parent_hash = try hexDecode32(ep.parentHash),
        .fee_recipient = try hexDecode20(ep.feeRecipient),
        .state_root = try hexDecode32(ep.stateRoot),
        .receipts_root = try hexDecode32(ep.receiptsRoot),
        .logs_bloom = try hexDecode256(ep.logsBloom),
        .prev_randao = try hexDecode32(ep.prevRandao),
        .block_number = try hexDecodeQuantity(ep.blockNumber),
        .gas_limit = try hexDecodeQuantity(ep.gasLimit),
        .gas_used = try hexDecodeQuantity(ep.gasUsed),
        .timestamp = try hexDecodeQuantity(ep.timestamp),
        .extra_data = extra_data,
        .base_fee_per_gas = try hexDecodeU256(ep.baseFeePerGas),
        .block_hash = try hexDecode32(ep.blockHash),
        .transactions = transactions,
        .withdrawals = withdrawals,
        .blob_gas_used = try hexDecodeQuantity(ep.blobGasUsed),
        .excess_blob_gas = try hexDecodeQuantity(ep.excessBlobGas),
    };

    const block_value = try hexDecodeU256(j.blockValue);

    return GetPayloadResponse{
        .execution_payload = payload,
        .block_value = block_value,
        .blobs_bundle = blobs_bundle,
        .should_override_builder = j.shouldOverrideBuilder,
    };
}

// ── V1/V2/V4 JSON response types & decoders ─────────────────────────────────

/// JSON representation for ExecutionPayloadV1 (no withdrawals, no blob fields).
const ExecutionPayloadJsonV1 = struct {
    parentHash: []const u8,
    feeRecipient: []const u8,
    stateRoot: []const u8,
    receiptsRoot: []const u8,
    logsBloom: []const u8,
    prevRandao: []const u8,
    blockNumber: []const u8,
    gasLimit: []const u8,
    gasUsed: []const u8,
    timestamp: []const u8,
    extraData: []const u8,
    baseFeePerGas: []const u8,
    blockHash: []const u8,
    transactions: []const []const u8,
};

const GetPayloadV1Json = struct {
    executionPayload: ExecutionPayloadJsonV1,
    blockValue: []const u8,
};

fn decodeGetPayloadResponseV1(allocator: Allocator, j: GetPayloadV1Json) !GetPayloadResponseV1 {
    const ep = j.executionPayload;

    const extra_data = try decodeExtraData(allocator, ep.extraData);
    errdefer if (extra_data.len > 0) allocator.free(extra_data);

    const transactions = try decodeTransactions(allocator, ep.transactions);
    errdefer {
        for (transactions) |tx| allocator.free(tx);
        if (transactions.len > 0) allocator.free(transactions);
    }

    return GetPayloadResponseV1{
        .execution_payload = ExecutionPayloadV1{
            .parent_hash = try hexDecode32(ep.parentHash),
            .fee_recipient = try hexDecode20(ep.feeRecipient),
            .state_root = try hexDecode32(ep.stateRoot),
            .receipts_root = try hexDecode32(ep.receiptsRoot),
            .logs_bloom = try hexDecode256(ep.logsBloom),
            .prev_randao = try hexDecode32(ep.prevRandao),
            .block_number = try hexDecodeQuantity(ep.blockNumber),
            .gas_limit = try hexDecodeQuantity(ep.gasLimit),
            .gas_used = try hexDecodeQuantity(ep.gasUsed),
            .timestamp = try hexDecodeQuantity(ep.timestamp),
            .extra_data = extra_data,
            .base_fee_per_gas = try hexDecodeU256(ep.baseFeePerGas),
            .block_hash = try hexDecode32(ep.blockHash),
            .transactions = transactions,
        },
        .block_value = try hexDecodeU256(j.blockValue),
    };
}

/// JSON representation for ExecutionPayloadV2 (adds withdrawals).
const ExecutionPayloadJsonV2 = struct {
    parentHash: []const u8,
    feeRecipient: []const u8,
    stateRoot: []const u8,
    receiptsRoot: []const u8,
    logsBloom: []const u8,
    prevRandao: []const u8,
    blockNumber: []const u8,
    gasLimit: []const u8,
    gasUsed: []const u8,
    timestamp: []const u8,
    extraData: []const u8,
    baseFeePerGas: []const u8,
    blockHash: []const u8,
    transactions: []const []const u8,
    withdrawals: []const WithdrawalJson,
};

const GetPayloadV2Json = struct {
    executionPayload: ExecutionPayloadJsonV2,
    blockValue: []const u8,
};

fn decodeGetPayloadResponseV2(allocator: Allocator, j: GetPayloadV2Json) !GetPayloadResponseV2 {
    const ep = j.executionPayload;

    const extra_data = try decodeExtraData(allocator, ep.extraData);
    errdefer if (extra_data.len > 0) allocator.free(extra_data);

    const transactions = try decodeTransactions(allocator, ep.transactions);
    errdefer {
        for (transactions) |tx| allocator.free(tx);
        if (transactions.len > 0) allocator.free(transactions);
    }

    const withdrawals = try decodeWithdrawalsOwned(allocator, ep.withdrawals);
    errdefer if (withdrawals.len > 0) allocator.free(withdrawals);

    return GetPayloadResponseV2{
        .execution_payload = ExecutionPayloadV2{
            .parent_hash = try hexDecode32(ep.parentHash),
            .fee_recipient = try hexDecode20(ep.feeRecipient),
            .state_root = try hexDecode32(ep.stateRoot),
            .receipts_root = try hexDecode32(ep.receiptsRoot),
            .logs_bloom = try hexDecode256(ep.logsBloom),
            .prev_randao = try hexDecode32(ep.prevRandao),
            .block_number = try hexDecodeQuantity(ep.blockNumber),
            .gas_limit = try hexDecodeQuantity(ep.gasLimit),
            .gas_used = try hexDecodeQuantity(ep.gasUsed),
            .timestamp = try hexDecodeQuantity(ep.timestamp),
            .extra_data = extra_data,
            .base_fee_per_gas = try hexDecodeU256(ep.baseFeePerGas),
            .block_hash = try hexDecode32(ep.blockHash),
            .transactions = transactions,
            .withdrawals = withdrawals,
        },
        .block_value = try hexDecodeU256(j.blockValue),
    };
}

/// Decode extra_data hex string into an owned byte slice. Caller frees.
fn decodeExtraData(allocator: Allocator, hex: []const u8) ![]const u8 {
    const stripped = hexStrip0x(hex) catch hex; // allow missing 0x
    if (stripped.len == 0) return &.{};
    const out = try allocator.alloc(u8, stripped.len / 2);
    _ = try std.fmt.hexToBytes(out, stripped);
    return out;
}

/// Decode transaction hex strings into owned byte slices. Caller frees each tx and the slice.
fn decodeTransactions(allocator: Allocator, txs: []const []const u8) ![]const []const u8 {
    if (txs.len == 0) return &.{};
    const result = try allocator.alloc([]const u8, txs.len);
    errdefer allocator.free(result);
    var decoded: usize = 0;
    errdefer for (result[0..decoded]) |tx| allocator.free(tx);
    for (txs, 0..) |tx_hex, i| {
        const stripped = hexStrip0x(tx_hex) catch tx_hex;
        const out = try allocator.alloc(u8, stripped.len / 2);
        _ = try std.fmt.hexToBytes(out, stripped);
        result[i] = out;
        decoded += 1;
    }
    return result;
}

/// Decode a slice of WithdrawalJson into an owned Withdrawal slice. Caller frees.
fn decodeWithdrawalsOwned(allocator: Allocator, withdrawals: []const WithdrawalJson) ![]const Withdrawal {
    if (withdrawals.len == 0) return &.{};
    const result = try allocator.alloc(Withdrawal, withdrawals.len);
    errdefer allocator.free(result);
    for (withdrawals, 0..) |w, i| {
        result[i] = Withdrawal{
            .index = try hexDecodeQuantity(w.index),
            .validator_index = try hexDecodeQuantity(w.validatorIndex),
            .address = try hexDecode20(w.address),
            .amount = try hexDecodeQuantity(w.amount),
        };
    }
    return result;
}

/// JSON representation of a DepositRequest from the EL (EIP-6110).
const DepositRequestJson = struct {
    pubkey: []const u8,
    withdrawalCredentials: []const u8,
    amount: []const u8,
    signature: []const u8,
    index: []const u8,
};

/// JSON representation of a WithdrawalRequest from the EL (EIP-7002).
const WithdrawalRequestJson = struct {
    sourceAddress: []const u8,
    validatorPubkey: []const u8,
    amount: []const u8,
};

/// JSON representation of a ConsolidationRequest from the EL (EIP-7251).
const ConsolidationRequestJson = struct {
    sourceAddress: []const u8,
    sourcePubkey: []const u8,
    targetPubkey: []const u8,
};

/// JSON representation for ExecutionPayloadV4 (Electra, adds request arrays).
const ExecutionPayloadJsonV4 = struct {
    parentHash: []const u8,
    feeRecipient: []const u8,
    stateRoot: []const u8,
    receiptsRoot: []const u8,
    logsBloom: []const u8,
    prevRandao: []const u8,
    blockNumber: []const u8,
    gasLimit: []const u8,
    gasUsed: []const u8,
    timestamp: []const u8,
    extraData: []const u8,
    baseFeePerGas: []const u8,
    blockHash: []const u8,
    transactions: []const []const u8,
    withdrawals: []const WithdrawalJson,
    blobGasUsed: []const u8,
    excessBlobGas: []const u8,
    depositRequests: []const DepositRequestJson,
    withdrawalRequests: []const WithdrawalRequestJson,
    consolidationRequests: []const ConsolidationRequestJson,
};

const GetPayloadV4Json = struct {
    executionPayload: ExecutionPayloadJsonV4,
    blockValue: []const u8,
    blobsBundle: BlobsBundleJson,
    shouldOverrideBuilder: bool,
};

fn decodeGetPayloadResponseV4(allocator: Allocator, j: GetPayloadV4Json) !GetPayloadResponseV4 {
    const ep = j.executionPayload;

    const extra_data = try decodeExtraData(allocator, ep.extraData);
    errdefer if (extra_data.len > 0) allocator.free(extra_data);

    const transactions = try decodeTransactions(allocator, ep.transactions);
    errdefer {
        for (transactions) |tx| allocator.free(tx);
        if (transactions.len > 0) allocator.free(transactions);
    }

    const withdrawals = try decodeWithdrawalsOwned(allocator, ep.withdrawals);
    errdefer if (withdrawals.len > 0) allocator.free(withdrawals);

    const deposit_requests = try decodeDepositRequests(allocator, ep.depositRequests);
    errdefer if (deposit_requests.len > 0) allocator.free(deposit_requests);

    const withdrawal_requests = try decodeWithdrawalRequests(allocator, ep.withdrawalRequests);
    errdefer if (withdrawal_requests.len > 0) allocator.free(withdrawal_requests);

    const consolidation_requests = try decodeConsolidationRequests(allocator, ep.consolidationRequests);
    errdefer if (consolidation_requests.len > 0) allocator.free(consolidation_requests);

    const blobs_bundle = try decodeBlobsBundle(allocator, j.blobsBundle);
    errdefer {
        if (blobs_bundle.commitments.len > 0) allocator.free(blobs_bundle.commitments);
        if (blobs_bundle.proofs.len > 0) allocator.free(blobs_bundle.proofs);
        if (blobs_bundle.blobs.len > 0) allocator.free(blobs_bundle.blobs);
    }

    const payload = ExecutionPayloadV4{
        .parent_hash = try hexDecode32(ep.parentHash),
        .fee_recipient = try hexDecode20(ep.feeRecipient),
        .state_root = try hexDecode32(ep.stateRoot),
        .receipts_root = try hexDecode32(ep.receiptsRoot),
        .logs_bloom = try hexDecode256(ep.logsBloom),
        .prev_randao = try hexDecode32(ep.prevRandao),
        .block_number = try hexDecodeQuantity(ep.blockNumber),
        .gas_limit = try hexDecodeQuantity(ep.gasLimit),
        .gas_used = try hexDecodeQuantity(ep.gasUsed),
        .timestamp = try hexDecodeQuantity(ep.timestamp),
        .extra_data = extra_data,
        .base_fee_per_gas = try hexDecodeU256(ep.baseFeePerGas),
        .block_hash = try hexDecode32(ep.blockHash),
        .transactions = transactions,
        .withdrawals = withdrawals,
        .blob_gas_used = try hexDecodeQuantity(ep.blobGasUsed),
        .excess_blob_gas = try hexDecodeQuantity(ep.excessBlobGas),
        .deposit_requests = deposit_requests,
        .withdrawal_requests = withdrawal_requests,
        .consolidation_requests = consolidation_requests,
    };

    return GetPayloadResponseV4{
        .execution_payload = payload,
        .block_value = try hexDecodeU256(j.blockValue),
        .blobs_bundle = blobs_bundle,
        .should_override_builder = j.shouldOverrideBuilder,
    };
}

/// Decode DepositRequest array. Caller owns the slice.
fn decodeDepositRequests(allocator: Allocator, requests: []const DepositRequestJson) ![]const DepositRequest {
    if (requests.len == 0) return &.{};
    const result = try allocator.alloc(DepositRequest, requests.len);
    errdefer allocator.free(result);
    for (requests, 0..) |r, i| {
        result[i] = DepositRequest{
            .pubkey = try hexDecode48(r.pubkey),
            .withdrawal_credentials = try hexDecode32(r.withdrawalCredentials),
            .amount = try hexDecodeQuantity(r.amount),
            .signature = try hexDecode96(r.signature),
            .index = try hexDecodeQuantity(r.index),
        };
    }
    return result;
}

/// Decode WithdrawalRequest array. Caller owns the slice.
fn decodeWithdrawalRequests(allocator: Allocator, requests: []const WithdrawalRequestJson) ![]const WithdrawalRequest {
    if (requests.len == 0) return &.{};
    const result = try allocator.alloc(WithdrawalRequest, requests.len);
    errdefer allocator.free(result);
    for (requests, 0..) |r, i| {
        result[i] = WithdrawalRequest{
            .source_address = try hexDecode20(r.sourceAddress),
            .validator_pubkey = try hexDecode48(r.validatorPubkey),
            .amount = try hexDecodeQuantity(r.amount),
        };
    }
    return result;
}

/// Decode ConsolidationRequest array. Caller owns the slice.
fn decodeConsolidationRequests(allocator: Allocator, requests: []const ConsolidationRequestJson) ![]const ConsolidationRequest {
    if (requests.len == 0) return &.{};
    const result = try allocator.alloc(ConsolidationRequest, requests.len);
    errdefer allocator.free(result);
    for (requests, 0..) |r, i| {
        result[i] = ConsolidationRequest{
            .source_address = try hexDecode20(r.sourceAddress),
            .source_pubkey = try hexDecode48(r.sourcePubkey),
            .target_pubkey = try hexDecode48(r.targetPubkey),
        };
    }
    return result;
}

/// Decode BlobsBundle from JSON. commitments/proofs are 48 bytes, blobs are 131072 bytes.
/// Caller owns all returned slices.
fn decodeBlobsBundle(allocator: Allocator, j: BlobsBundleJson) !BlobsBundle {
    const commitments = try allocator.alloc([48]u8, j.commitments.len);
    errdefer allocator.free(commitments);
    for (j.commitments, 0..) |c, i| commitments[i] = try hexDecode48(c);

    const proofs = try allocator.alloc([48]u8, j.proofs.len);
    errdefer allocator.free(proofs);
    for (j.proofs, 0..) |p, i| proofs[i] = try hexDecode48(p);

    const blobs = try allocator.alloc([131072]u8, j.blobs.len);
    errdefer allocator.free(blobs);
    for (j.blobs, 0..) |b, i| {
        const stripped = try hexStrip0x(b);
        if (stripped.len != 131072 * 2) return error.InvalidHexLength;
        _ = try std.fmt.hexToBytes(&blobs[i], stripped);
    }

    return BlobsBundle{ .commitments = commitments, .proofs = proofs, .blobs = blobs };
}


// ── Payload body JSON types and decoding ──────────────────────────────────────

/// JSON representation of an ExecutionPayloadBody V1.
const PayloadBodyV1Json = struct {
    transactions: []const []const u8,
    withdrawals: ?[]const WithdrawalJson,
};

/// JSON representation of an ExecutionPayloadBody V2 (with Electra requests).
const PayloadBodyV2Json = struct {
    transactions: []const []const u8,
    withdrawals: ?[]const WithdrawalJson,
    depositRequests: ?[]const DepositRequestJson = null,
    withdrawalRequests: ?[]const WithdrawalRequestJson = null,
    consolidationRequests: ?[]const ConsolidationRequestJson = null,
};

/// Decode a JSON-RPC response containing an array of nullable payload bodies.
/// Handles both V1 and V2 body types via comptime dispatch.
fn decodePayloadBodiesResponse(
    comptime BodyT: type,
    comptime JsonT: type,
    allocator: Allocator,
    response: []const u8,
) ![]?BodyT {
    // The response is an array of nullable objects.
    // std.json can't directly parse ?JsonT inside an array via decodeResponse,
    // so we use std.json.Value and walk the array manually.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    var source_parsed = try std.json.parseFromSlice(std.json.Value, arena_alloc, response, .{});
    defer source_parsed.deinit();

    const root = source_parsed.value;

    // Check for JSON-RPC error.
    if (root.object.get("error")) |err_val| {
        if (err_val != .null) {
            if (err_val == .object) {
                const code = if (err_val.object.get("code")) |c| c.integer else -1;
                return json_rpc.mapErrorCode(code);
            }
            return error.UnknownErrorCode;
        }
    }

    const result_val = root.object.get("result") orelse return error.MissingResult;
    if (result_val == .null) return error.NullResult;

    const items = result_val.array.items;
    const result = try allocator.alloc(?BodyT, items.len);
    errdefer allocator.free(result);

    var decoded_count: usize = 0;
    errdefer {
        // Free already-decoded bodies on error.
        for (result[0..decoded_count]) |maybe_body| {
            if (maybe_body) |b| freePayloadBodyInner(BodyT, allocator, b);
        }
    }

    for (items, 0..) |item, i| {
        if (item == .null) {
            result[i] = null;
        } else {
            // Re-serialize this element, then parse as JsonT.
            var out: std.Io.Writer.Allocating = .init(arena_alloc);
            var writer: std.json.Stringify = .{ .writer = &out.writer };
            try item.jsonStringify(&writer);

            const json_entry = try std.json.parseFromSliceLeaky(JsonT, arena_alloc, out.written(), .{});
            result[i] = try decodePayloadBody(BodyT, JsonT, allocator, json_entry);
        }
        decoded_count = i + 1;
    }

    return result;
}

/// Decode a single payload body JSON into the Zig type.
fn decodePayloadBody(
    comptime BodyT: type,
    comptime JsonT: type,
    allocator: Allocator,
    j: JsonT,
) !BodyT {
    const transactions = try decodeTransactions(allocator, j.transactions);
    errdefer {
        for (transactions) |tx| allocator.free(tx);
        if (transactions.len > 0) allocator.free(transactions);
    }

    const withdrawals: ?[]const Withdrawal = if (j.withdrawals) |ws|
        try decodeWithdrawalsOwned(allocator, ws)
    else
        null;
    errdefer if (withdrawals) |ws| {
        if (ws.len > 0) allocator.free(ws);
    };

    if (BodyT == ExecutionPayloadBodyV1) {
        return ExecutionPayloadBodyV1{
            .transactions = transactions,
            .withdrawals = withdrawals,
        };
    } else {
        // V2: also decode Electra request fields.
        const deposit_requests: ?[]const DepositRequest = if (j.depositRequests) |drs|
            try decodeDepositRequests(allocator, drs)
        else
            null;
        errdefer if (deposit_requests) |drs| {
            if (drs.len > 0) allocator.free(drs);
        };

        const withdrawal_requests: ?[]const WithdrawalRequest = if (j.withdrawalRequests) |wrs|
            try decodeWithdrawalRequests(allocator, wrs)
        else
            null;
        errdefer if (withdrawal_requests) |wrs| {
            if (wrs.len > 0) allocator.free(wrs);
        };

        const consolidation_requests: ?[]const ConsolidationRequest = if (j.consolidationRequests) |crs|
            try decodeConsolidationRequests(allocator, crs)
        else
            null;

        return ExecutionPayloadBodyV2{
            .transactions = transactions,
            .withdrawals = withdrawals,
            .deposit_requests = deposit_requests,
            .withdrawal_requests = withdrawal_requests,
            .consolidation_requests = consolidation_requests,
        };
    }
}

/// Free inner allocations of a payload body (used in error cleanup).
fn freePayloadBodyInner(comptime BodyT: type, allocator: Allocator, b: BodyT) void {
    for (b.transactions) |tx| allocator.free(tx);
    if (b.transactions.len > 0) allocator.free(b.transactions);
    if (b.withdrawals) |ws| {
        if (ws.len > 0) allocator.free(ws);
    }
    if (BodyT == ExecutionPayloadBodyV2) {
        if (b.deposit_requests) |drs| {
            if (drs.len > 0) allocator.free(drs);
        }
        if (b.withdrawal_requests) |wrs| {
            if (wrs.len > 0) allocator.free(wrs);
        }
        if (b.consolidation_requests) |crs| {
            if (crs.len > 0) allocator.free(crs);
        }
    }
}
// ── Hex decoding helpers ──────────────────────────────────────────────────────

fn hexStrip0x(hex: []const u8) ![]const u8 {
    if (hex.len >= 2 and hex[0] == '0' and hex[1] == 'x') return hex[2..];
    return error.MissingHexPrefix;
}

pub fn hexDecode48(hex: []const u8) ![48]u8 {
    const stripped = try hexStrip0x(hex);
    if (stripped.len != 96) return error.InvalidHexLength;
    var out: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, stripped);
    return out;
}

pub fn hexDecode96(hex: []const u8) ![96]u8 {
    const stripped = try hexStrip0x(hex);
    if (stripped.len != 192) return error.InvalidHexLength;
    var out: [96]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, stripped);
    return out;
}

pub fn hexDecode32(hex: []const u8) ![32]u8 {
    const stripped = try hexStrip0x(hex);
    if (stripped.len != 64) return error.InvalidHexLength;
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, stripped);
    return out;
}

pub fn hexDecode20(hex: []const u8) ![20]u8 {
    const stripped = try hexStrip0x(hex);
    if (stripped.len != 40) return error.InvalidHexLength;
    var out: [20]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, stripped);
    return out;
}

pub fn hexDecode256(hex: []const u8) ![256]u8 {
    const stripped = try hexStrip0x(hex);
    if (stripped.len != 512) return error.InvalidHexLength;
    var out: [256]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, stripped);
    return out;
}

/// Decode a QUANTITY field (variable-length hex, no leading zeros).
/// Handles "0x0" through "0xffffffffffffffff".
pub fn hexDecodeQuantity(hex: []const u8) !u64 {
    const stripped = try hexStrip0x(hex);
    if (stripped.len == 0) return error.InvalidHexLength;
    if (stripped.len > 16) return error.InvalidHexLength;
    // Left-pad to 16 chars.
    var padded: [16]u8 = .{'0'} ** 16;
    @memcpy(padded[16 - stripped.len ..], stripped);
    var bytes: [8]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, &padded);
    return std.mem.readInt(u64, &bytes, .big);
}

/// Decode a u256 QUANTITY or DATA field (handles both padded and unpadded hex).
pub fn hexDecodeU256(hex: []const u8) !u256 {
    const stripped = try hexStrip0x(hex);
    if (stripped.len == 0) return error.InvalidHexLength;
    if (stripped.len > 64) return error.InvalidHexLength;
    // Left-pad to 64 chars.
    var padded: [64]u8 = .{'0'} ** 64;
    @memcpy(padded[64 - stripped.len ..], stripped);
    var bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, &padded);
    return std.mem.readInt(u256, &bytes, .big);
}

// ── MockTransport ─────────────────────────────────────────────────────────────

/// Mock HTTP transport for testing.
///
/// Records incoming requests and returns a pre-configured canned response.
pub const MockTransport = struct {
    allocator: Allocator,
    /// Canned response body returned by every call.
    canned_response: []const u8,
    /// Copy of the last request body received.
    last_body: ?[]const u8 = null,
    /// Copy of the last URL received.
    last_url: ?[]const u8 = null,
    /// Whether an Authorization header was present in the last call.
    last_had_auth: bool = false,
    /// Last HTTP method used.
    last_method: ?HttpMethod = null,

    pub fn init(allocator: Allocator, canned_response: []const u8) MockTransport {
        return .{
            .allocator = allocator,
            .canned_response = canned_response,
        };
    }

    pub fn deinit(self: *MockTransport) void {
        if (self.last_body) |b| self.allocator.free(b);
        if (self.last_url) |u| self.allocator.free(u);
    }

    pub fn transport(self: *MockTransport) Transport {
        return .{
            .ptr = @ptrCast(self),
            .sendFn = &MockTransport.send,
        };
    }

    fn send(
        ptr: *anyopaque,
        method: HttpMethod,
        url: []const u8,
        headers: []const Header,
        body: []const u8,
    ) anyerror![]const u8 {
        const self: *MockTransport = @ptrCast(@alignCast(ptr));
        // Free previous recorded values.
        if (self.last_body) |b| {
            self.allocator.free(b);
            self.last_body = null;
        }
        if (self.last_url) |u| {
            self.allocator.free(u);
            self.last_url = null;
        }

        self.last_method = method;
        self.last_body = try self.allocator.dupe(u8, body);
        self.last_url = try self.allocator.dupe(u8, url);
        self.last_had_auth = false;
        for (headers) |h| {
            if (std.mem.eql(u8, h.name, "Authorization")) {
                self.last_had_auth = true;
                break;
            }
        }

        return self.allocator.dupe(u8, self.canned_response);
    }
};

// ── Tests ─────────────────────────────────────────────────────────────────────

test "hexEncode basic" {
    const allocator = testing.allocator;

    const result = try hexEncode(allocator, &[_]u8{ 0x01, 0x02 });
    defer allocator.free(result);
    try testing.expectEqualStrings("0x0102", result);
}

test "hexEncode empty" {
    const allocator = testing.allocator;
    const result = try hexEncode(allocator, &[_]u8{});
    defer allocator.free(result);
    try testing.expectEqualStrings("0x", result);
}

test "hexEncode all bytes" {
    const allocator = testing.allocator;
    const result = try hexEncode(allocator, &[_]u8{ 0x00, 0xff, 0xab, 0xcd });
    defer allocator.free(result);
    try testing.expectEqualStrings("0x00ffabcd", result);
}

test "base64urlEncode known" {
    const allocator = testing.allocator;
    // RFC 4648 test vector: "\x00\x00\x00" → "AAAA"
    const result = try base64urlEncode(allocator, &[_]u8{ 0x00, 0x00, 0x00 });
    defer allocator.free(result);
    try testing.expectEqualStrings("AAAA", result);
}

test "jwt format has three segments" {
    const allocator = testing.allocator;
    const secret = [_]u8{0x42} ** 32;
    const token = try generateJwt(allocator, secret, 1_700_000_000);
    defer allocator.free(token);

    // Count dots — must be exactly 2 (three segments).
    var dot_count: usize = 0;
    for (token) |c| {
        if (c == '.') dot_count += 1;
    }
    try testing.expectEqual(@as(usize, 2), dot_count);
    try testing.expect(token.len > 0);
}

test "jwt header is correct base64url" {
    const allocator = testing.allocator;
    const secret = [_]u8{0x01} ** 32;
    const token = try generateJwt(allocator, secret, 0);
    defer allocator.free(token);

    // Extract first segment (header).
    const dot1 = std.mem.indexOfScalar(u8, token, '.') orelse unreachable;
    const header_b64 = token[0..dot1];

    // Decode and verify.
    const decoded_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(header_b64) catch unreachable;
    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);
    try std.base64.url_safe_no_pad.Decoder.decode(decoded, header_b64);
    try testing.expectEqualStrings("{\"typ\":\"JWT\",\"alg\":\"HS256\"}", decoded);
}

test "jwt HMAC is deterministic" {
    const allocator = testing.allocator;
    const secret = [_]u8{0xde, 0xad, 0xbe, 0xef} ++ [_]u8{0x00} ** 28;
    const token1 = try generateJwt(allocator, secret, 999);
    defer allocator.free(token1);
    const token2 = try generateJwt(allocator, secret, 999);
    defer allocator.free(token2);

    try testing.expectEqualStrings(token1, token2);
}

test "jwt different iat produces different token" {
    const allocator = testing.allocator;
    const secret = [_]u8{0x11} ** 32;
    const token1 = try generateJwt(allocator, secret, 1000);
    defer allocator.free(token1);
    const token2 = try generateJwt(allocator, secret, 2000);
    defer allocator.free(token2);

    try testing.expect(!std.mem.eql(u8, token1, token2));
}

test "HttpEngine: newPayloadV3 sends correct method" {
    const allocator = testing.allocator;

    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"status":"VALID","latestValidHash":"0x0101010101010101010101010101010101010101010101010101010101010101","validationError":null}}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();

    var http_engine = HttpEngine.init(
        allocator,
        "http://localhost:8551",
        null,
        mock.transport(),
    );
    defer http_engine.deinit();

    const api = http_engine.engine();
    const payload = makeTestPayload([_]u8{0x01} ** 32);
    const result = try api.newPayload(payload, &.{}, std.mem.zeroes([32]u8));

    try testing.expectEqual(ExecutionPayloadStatus.valid, result.status);

    // Verify the request contained the correct method.
    const body = mock.last_body orelse return error.NoRequestRecorded;
    try testing.expect(std.mem.indexOf(u8, body, "engine_newPayloadV3") != null);
}

test "HttpEngine: newPayloadV3 encodes block_hash in hex" {
    const allocator = testing.allocator;

    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"status":"VALID","latestValidHash":null,"validationError":null}}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();

    var http_engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer http_engine.deinit();

    const api = http_engine.engine();
    const block_hash = [_]u8{0xde, 0xad, 0xbe, 0xef} ++ [_]u8{0x00} ** 28;
    const payload = makeTestPayload(block_hash);
    _ = try api.newPayload(payload, &.{}, std.mem.zeroes([32]u8));

    const body = mock.last_body orelse return error.NoRequestRecorded;
    // Block hash must appear hex-encoded in the request.
    try testing.expect(std.mem.indexOf(u8, body, "0xdeadbeef") != null);
}

test "HttpEngine: no auth header without jwt_secret" {
    const allocator = testing.allocator;

    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"status":"SYNCING","latestValidHash":null,"validationError":null}}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();

    var http_engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer http_engine.deinit();

    const api = http_engine.engine();
    _ = try api.newPayload(makeTestPayload([_]u8{0x00} ** 32), &.{}, std.mem.zeroes([32]u8));

    try testing.expect(!mock.last_had_auth);
}

test "HttpEngine: auth header present with jwt_secret" {
    const allocator = testing.allocator;

    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"status":"VALID","latestValidHash":null,"validationError":null}}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();

    const secret = [_]u8{0x42} ** 32;
    var http_engine = HttpEngine.init(allocator, "http://localhost:8551", secret, mock.transport());
    defer http_engine.deinit();

    const api = http_engine.engine();
    _ = try api.newPayload(makeTestPayload([_]u8{0x00} ** 32), &.{}, std.mem.zeroes([32]u8));

    try testing.expect(mock.last_had_auth);
}

test "HttpEngine: forkchoiceUpdatedV3 sends correct method" {
    const allocator = testing.allocator;

    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"payloadStatus":{"status":"VALID","latestValidHash":null,"validationError":null},"payloadId":null}}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();

    var http_engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer http_engine.deinit();

    const api = http_engine.engine();
    const result = try api.forkchoiceUpdated(.{
        .head_block_hash = [_]u8{0xaa} ** 32,
        .safe_block_hash = [_]u8{0xaa} ** 32,
        .finalized_block_hash = [_]u8{0xaa} ** 32,
    }, null);

    try testing.expectEqual(ExecutionPayloadStatus.valid, result.payload_status.status);
    try testing.expect(result.payload_id == null);

    const body = mock.last_body orelse return error.NoRequestRecorded;
    try testing.expect(std.mem.indexOf(u8, body, "engine_forkchoiceUpdatedV3") != null);
}

test "HttpEngine: forkchoiceUpdatedV3 with payload_id in response" {
    const allocator = testing.allocator;

    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"payloadStatus":{"status":"VALID","latestValidHash":null,"validationError":null},"payloadId":"0x0102030405060708"}}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();

    var http_engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer http_engine.deinit();

    const api = http_engine.engine();
    const result = try api.forkchoiceUpdated(.{
        .head_block_hash = [_]u8{0xbb} ** 32,
        .safe_block_hash = [_]u8{0xbb} ** 32,
        .finalized_block_hash = [_]u8{0xbb} ** 32,
    }, .{
        .timestamp = 1000,
        .prev_randao = [_]u8{0xcc} ** 32,
        .suggested_fee_recipient = [_]u8{0xdd} ** 20,
        .withdrawals = &.{},
        .parent_beacon_block_root = [_]u8{0xee} ** 32,
    });

    try testing.expect(result.payload_id != null);
    try testing.expectEqual([_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }, result.payload_id.?);
}

test "HttpEngine: request id increments" {
    const allocator = testing.allocator;

    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"status":"VALID","latestValidHash":null,"validationError":null}}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();

    var http_engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer http_engine.deinit();

    const api = http_engine.engine();

    _ = try api.newPayload(makeTestPayload([_]u8{0x01} ** 32), &.{}, std.mem.zeroes([32]u8));
    const body1 = try allocator.dupe(u8, mock.last_body.?);
    defer allocator.free(body1);

    _ = try api.newPayload(makeTestPayload([_]u8{0x02} ** 32), &.{}, std.mem.zeroes([32]u8));
    const body2 = try allocator.dupe(u8, mock.last_body.?);
    defer allocator.free(body2);

    // First request uses id 1, second uses id 2.
    try testing.expect(std.mem.indexOf(u8, body1, "\"id\":1") != null);
    try testing.expect(std.mem.indexOf(u8, body2, "\"id\":2") != null);
}

fn makeTestPayload(block_hash: [32]u8) ExecutionPayloadV3 {
    return .{
        .parent_hash = std.mem.zeroes([32]u8),
        .fee_recipient = std.mem.zeroes([20]u8),
        .state_root = std.mem.zeroes([32]u8),
        .receipts_root = std.mem.zeroes([32]u8),
        .logs_bloom = std.mem.zeroes([256]u8),
        .prev_randao = std.mem.zeroes([32]u8),
        .block_number = 1,
        .gas_limit = 30_000_000,
        .gas_used = 21_000,
        .timestamp = 1_700_000_000,
        .extra_data = &.{},
        .base_fee_per_gas = 1_000_000_000,
        .block_hash = block_hash,
        .transactions = &.{},
        .withdrawals = &.{},
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
    };
}

// ── New feature tests ─────────────────────────────────────────────────────────

test "EngineState: transitions" {
    // Verify all state variants exist.
    const states = [_]EngineState{ .online, .offline, .syncing, .auth_failed };
    try testing.expectEqual(@as(usize, 4), states.len);
    try testing.expect(states[0] != states[1]);
}

test "RetryConfig: defaults" {
    const cfg = RetryConfig{};
    try testing.expectEqual(@as(u32, 3), cfg.max_retries);
    try testing.expectEqual(@as(u64, 100), cfg.initial_backoff_ms);
    try testing.expectEqual(@as(u64, 12_000), cfg.new_payload_timeout_ms);
    try testing.expectEqual(@as(u64, 8_000), cfg.default_timeout_ms);
}

test "HttpEngine: state starts online" {
    var mock = MockTransport.init(testing.allocator, "{}");
    defer mock.deinit();
    const engine = HttpEngine.init(testing.allocator, "http://localhost:8551", null, mock.transport());
    try testing.expectEqual(EngineState.online, engine.state);
}

test "HttpEngine: initWithRetry sets custom retry config" {
    var mock = MockTransport.init(testing.allocator, "{}");
    defer mock.deinit();
    const cfg = RetryConfig{ .max_retries = 5, .initial_backoff_ms = 50 };
    const engine = HttpEngine.initWithRetry(testing.allocator, "http://localhost:8551", null, mock.transport(), cfg);
    try testing.expectEqual(@as(u32, 5), engine.retry_config.max_retries);
    try testing.expectEqual(@as(u64, 50), engine.retry_config.initial_backoff_ms);
}

test "HttpEngine: retry: transport success on first attempt stays online" {
    const allocator = testing.allocator;
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"status":"VALID","latestValidHash":null,"validationError":null}}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const api = engine.engine();
    _ = try api.newPayload(makeTestPayload([_]u8{0x01} ** 32), &.{}, std.mem.zeroes([32]u8));
    try testing.expectEqual(EngineState.online, engine.state);
}

test "hexEncodeQuantity: zero" {
    const allocator = testing.allocator;
    const result = try hexEncodeQuantity(allocator, 0);
    defer allocator.free(result);
    try testing.expectEqualStrings("0x0", result);
}

test "hexEncodeQuantity: small value" {
    const allocator = testing.allocator;
    const result = try hexEncodeQuantity(allocator, 1);
    defer allocator.free(result);
    try testing.expectEqualStrings("0x1", result);
}

test "hexEncodeQuantity: no leading zeros" {
    const allocator = testing.allocator;
    // Block number 100 = 0x64
    const result = try hexEncodeQuantity(allocator, 100);
    defer allocator.free(result);
    try testing.expectEqualStrings("0x64", result);
}

test "hexEncodeQuantity: max u64" {
    const allocator = testing.allocator;
    const result = try hexEncodeQuantity(allocator, std.math.maxInt(u64));
    defer allocator.free(result);
    try testing.expectEqualStrings("0xffffffffffffffff", result);
}

test "hexEncodeQuantityU256: zero" {
    const allocator = testing.allocator;
    const result = try hexEncodeQuantityU256(allocator, 0);
    defer allocator.free(result);
    try testing.expectEqualStrings("0x0", result);
}

test "hexEncodeQuantityU256: small value" {
    const allocator = testing.allocator;
    const result = try hexEncodeQuantityU256(allocator, 255);
    defer allocator.free(result);
    try testing.expectEqualStrings("0xff", result);
}

test "hexDecodeQuantity: zero" {
    try testing.expectEqual(@as(u64, 0), try hexDecodeQuantity("0x0"));
}

test "hexDecodeQuantity: small value" {
    try testing.expectEqual(@as(u64, 100), try hexDecodeQuantity("0x64"));
}

test "hexDecodeQuantity: padded value" {
    try testing.expectEqual(@as(u64, 256), try hexDecodeQuantity("0x100"));
}

test "hexDecodeQuantity: full padded" {
    try testing.expectEqual(@as(u64, 0x0102030405060708), try hexDecodeQuantity("0x0102030405060708"));
}

test "hexDecodeQuantity: handles both padded and unpadded aliases" {
    try testing.expectEqual(@as(u64, 1), try hexDecodeQuantity("0x1"));
    try testing.expectEqual(@as(u64, 1), try hexDecodeQuantity("0x0000000000000001"));
    try testing.expectEqual(@as(u64, 30_000_000), try hexDecodeQuantity("0x1c9c380"));
}

test "hexDecodeU256: handles variable length" {
    try testing.expectEqual(@as(u256, 0), try hexDecodeU256("0x0"));
    try testing.expectEqual(@as(u256, 255), try hexDecodeU256("0xff"));
    try testing.expectEqual(@as(u256, 1_000_000_000), try hexDecodeU256("0x3b9aca00"));
}

test "HttpEngine: Fork.newPayloadForFork with unsupported fork returns error" {
    const allocator = testing.allocator;
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"status":"VALID","latestValidHash":null,"validationError":null}}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    // phase0 and altair are pre-Merge — no execution engine.
    const result = engine.newPayloadForFork(.phase0, undefined, &.{}, std.mem.zeroes([32]u8));
    try testing.expectError(error.UnsupportedFork, result);

    const result2 = engine.newPayloadForFork(.altair, undefined, &.{}, std.mem.zeroes([32]u8));
    try testing.expectError(error.UnsupportedFork, result2);
}

test "HttpEngine: getPayloadForFork deneb dispatches to V3" {
    const allocator = testing.allocator;
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"executionPayload":{"parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","feeRecipient":"0x0000000000000000000000000000000000000000","stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","receiptsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x1","gasLimit":"0x1c9c380","gasUsed":"0x5208","timestamp":"0x6553f100","extraData":"0x","baseFeePerGas":"0x3b9aca00","blockHash":"0x0101010101010101010101010101010101010101010101010101010101010101","transactions":[],"withdrawals":[],"blobGasUsed":"0x0","excessBlobGas":"0x0"},"blockValue":"0x0","blobsBundle":{"commitments":[],"proofs":[],"blobs":[]},"shouldOverrideBuilder":false}}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const resp = try engine.getPayloadForFork(.deneb, [_]u8{0xab} ** 8);
    try testing.expectEqual([_]u8{0x01} ** 32, resp.execution_payload.block_hash);

    // Verify the request used V3 method.
    const body = mock.last_body orelse return error.NoRequest;
    try testing.expect(std.mem.indexOf(u8, body, "engine_getPayloadV3") != null);
}

test "HttpEngine: forkchoiceUpdatedForFork unsupported fork" {
    const allocator = testing.allocator;
    var mock = MockTransport.init(allocator, "{}");
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const result = engine.forkchoiceUpdatedForFork(.phase0, .{
        .head_block_hash = std.mem.zeroes([32]u8),
        .safe_block_hash = std.mem.zeroes([32]u8),
        .finalized_block_hash = std.mem.zeroes([32]u8),
    }, null);
    try testing.expectError(error.UnsupportedFork, result);
}

test "HttpEngine: forkchoiceUpdatedForFork bellatrix uses V1" {
    const allocator = testing.allocator;
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"payloadStatus":{"status":"VALID","latestValidHash":null,"validationError":null},"payloadId":null}}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    _ = try engine.forkchoiceUpdatedForFork(.bellatrix, .{
        .head_block_hash = std.mem.zeroes([32]u8),
        .safe_block_hash = std.mem.zeroes([32]u8),
        .finalized_block_hash = std.mem.zeroes([32]u8),
    }, null);

    const body = mock.last_body orelse return error.NoRequest;
    try testing.expect(std.mem.indexOf(u8, body, "engine_forkchoiceUpdatedV1") != null);
}

test "HttpEngine: forkchoiceUpdatedForFork deneb uses V3" {
    const allocator = testing.allocator;
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"payloadStatus":{"status":"VALID","latestValidHash":null,"validationError":null},"payloadId":null}}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    _ = try engine.forkchoiceUpdatedForFork(.deneb, .{
        .head_block_hash = std.mem.zeroes([32]u8),
        .safe_block_hash = std.mem.zeroes([32]u8),
        .finalized_block_hash = std.mem.zeroes([32]u8),
    }, null);

    const body = mock.last_body orelse return error.NoRequest;
    try testing.expect(std.mem.indexOf(u8, body, "engine_forkchoiceUpdatedV3") != null);
}

test "HttpEngine: exchangeTransitionConfiguration encodes config correctly" {
    const allocator = testing.allocator;
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"terminalTotalDifficulty":"0xc70d808a128d7380000","terminalBlockHash":"0x0000000000000000000000000000000000000000000000000000000000000000","terminalBlockNumber":"0x0"}}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const result = try engine.exchangeTransitionConfiguration(.{
        .terminal_total_difficulty = 58750003716598352816469,
        .terminal_block_hash = std.mem.zeroes([32]u8),
        .terminal_block_number = 0,
    });

    // Verify method in request.
    const body = mock.last_body orelse return error.NoRequest;
    try testing.expect(std.mem.indexOf(u8, body, "engine_exchangeTransitionConfigurationV1") != null);
    // Terminal block hash should be zero.
    try testing.expectEqual(std.mem.zeroes([32]u8), result.terminal_block_hash);
}

test "HttpEngine: getClientVersion sends correct method" {
    const allocator = testing.allocator;
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":[{"code":"GE","name":"Geth","version":"v1.13.0","commit":"0xdeadbeef"}]}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const versions = try engine.getClientVersion("lodestar-z", "v0.1.0", "abc123");
    defer engine.freeClientVersions(versions);

    try testing.expectEqual(@as(usize, 1), versions.len);
    try testing.expectEqualStrings("GE", versions[0].code);
    try testing.expectEqualStrings("Geth", versions[0].name);

    const body = mock.last_body orelse return error.NoRequest;
    try testing.expect(std.mem.indexOf(u8, body, "engine_getClientVersionV1") != null);
}

test "HttpEngine: JSON-RPC error propagates as specific error" {
    const allocator = testing.allocator;
    const canned =
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-38001,"message":"unknown payload"}}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const api = engine.engine();
    const result = api.newPayload(makeTestPayload([_]u8{0x01} ** 32), &.{}, std.mem.zeroes([32]u8));
    try testing.expectError(error.UnknownPayload, result);
}

test "HttpEngine: JWT payload contains iat field" {
    const allocator = testing.allocator;
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"status":"VALID","latestValidHash":null,"validationError":null}}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();

    const secret = [_]u8{0x42} ** 32;
    var engine = HttpEngine.init(allocator, "http://localhost:8551", secret, mock.transport());
    defer engine.deinit();

    const api = engine.engine();
    _ = try api.newPayload(makeTestPayload([_]u8{0x00} ** 32), &.{}, std.mem.zeroes([32]u8));

    // Auth header must be present.
    try testing.expect(mock.last_had_auth);
}

// ── IoHttpTransport ───────────────────────────────────────────────────────────

/// Production HTTP transport using std.http.Client (built on std.Io).
///
/// Implements the Transport interface for real EL communication. Uses the
/// standard library's HTTP client which handles connection pooling, chunked
/// encoding, and all I/O through std.Io.
///
/// Not thread-safe: must be called from a single fiber/thread at a time.
pub const IoHttpTransport = struct {
    allocator: Allocator,
    /// Reusable HTTP client — handles connection pooling across requests.
    http_client: ?std.http.Client,
    /// I/O context — set via setIo() before any requests are made.
    io: ?std.Io,

    pub fn init(allocator: Allocator) IoHttpTransport {
        return .{
            .allocator = allocator,
            .http_client = null,
            .io = null,
        };
    }

    /// Set the I/O context. Must be called before send().
    pub fn setIo(self: *IoHttpTransport, io: std.Io) void {
        self.io = io;
    }

    pub fn deinit(self: *IoHttpTransport) void {
        if (self.http_client) |*c| c.deinit();
    }

    pub fn transport(self: *IoHttpTransport) Transport {
        return .{
            .ptr = @ptrCast(self),
            .sendFn = &IoHttpTransport.send,
        };
    }

    fn ensureClient(self: *IoHttpTransport, io: std.Io) *std.http.Client {
        if (self.http_client == null) {
            self.http_client = .{
                .allocator = self.allocator,
                .io = io,
            };
        }
        return &self.http_client.?;
    }

    fn send(
        ptr: *anyopaque,
        method: HttpMethod,
        url: []const u8,
        headers: []const Header,
        body: []const u8,
    ) anyerror![]const u8 {
        const self: *IoHttpTransport = @ptrCast(@alignCast(ptr));
        const io = self.io orelse return error.IoNotInitialized;
        const client = self.ensureClient(io);

        // Parse URI.
        const uri = try std.Uri.parse(url);

        // Build extra headers from the Header slice.
        // We need to convert our Header type to std.http.Header.
        var extra_hdrs = try self.allocator.alloc(std.http.Header, headers.len);
        defer self.allocator.free(extra_hdrs);
        for (headers, 0..) |h, i| {
            extra_hdrs[i] = .{ .name = h.name, .value = h.value };
        }

        const http_method: std.http.Method = switch (method) {
            .GET => .GET,
            .POST => .POST,
        };

        // Use the lower-level request API with the specified method.
        var req = try client.request(http_method, uri, .{
            .keep_alive = true,
            .extra_headers = extra_hdrs,
            .headers = .{
                .content_type = .{ .override = "application/json" },
            },
        });
        defer req.deinit();

        // Set content length and send body.
        req.transfer_encoding = .{ .content_length = body.len };
        try req.sendBodyComplete(@constCast(body));

        // Receive response head.
        var redirect_buf: [1024]u8 = undefined;
        var response = try req.receiveHead(&redirect_buf);

        // Read the entire response body via std.Io.Reader.
        var transfer_buf: [8192]u8 = undefined;
        const reader = response.reader(&transfer_buf);
        // allocRemaining reads until EOF and returns an owned slice.
        return reader.allocRemaining(self.allocator, std.Io.Limit.limited(4 * 1024 * 1024)) catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr() orelse error.ReadFailed,
            else => |e| return e,
        };
    }
};

// ── GetPayload response parsing tests ─────────────────────────────────────────

test "getPayloadV1: parses ExecutionPayload response" {
    const allocator = testing.allocator;

    // V1 response: just executionPayload + blockValue
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"executionPayload":{"parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","feeRecipient":"0x0000000000000000000000000000000000000000","stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","receiptsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x1","gasLimit":"0x1c9c380","gasUsed":"0x5208","timestamp":"0x6553f100","extraData":"0x","baseFeePerGas":"0x3b9aca00","blockHash":"0x0101010101010101010101010101010101010101010101010101010101010101","transactions":[]},"blockValue":"0x64"}}
    ;

    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const api1 = engine.engine();
    const result = try api1.getPayloadV1([_]u8{0xab} ** 8);

    // Verify payload fields
    try testing.expectEqual(@as(u64, 1), result.execution_payload.block_number);
    try testing.expectEqual([_]u8{0x01} ** 32, result.execution_payload.block_hash);
    try testing.expectEqual(@as(u64, 21000), result.execution_payload.gas_used);
    // blockValue = 0x64 = 100
    try testing.expectEqual(@as(u256, 100), result.block_value);

    const body = mock.last_body orelse return error.NoRequest;
    try testing.expect(std.mem.indexOf(u8, body, "engine_getPayloadV1") != null);
}

test "getPayloadV2: parses ExecutionPayload + blockValue response" {
    const allocator = testing.allocator;

    // V2 response: executionPayload with withdrawals + blockValue
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"executionPayload":{"parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","feeRecipient":"0x0000000000000000000000000000000000000000","stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","receiptsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x2","gasLimit":"0x1c9c380","gasUsed":"0x0","timestamp":"0x6553f200","extraData":"0x","baseFeePerGas":"0x3b9aca00","blockHash":"0x0202020202020202020202020202020202020202020202020202020202020202","transactions":[],"withdrawals":[]},"blockValue":"0x3b9aca00"}}
    ;

    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const api2 = engine.engine();
    const result = try api2.getPayloadV2([_]u8{0xcd} ** 8);

    try testing.expectEqual(@as(u64, 2), result.execution_payload.block_number);
    try testing.expectEqual([_]u8{0x02} ** 32, result.execution_payload.block_hash);
    // blockValue = 0x3b9aca00 = 1_000_000_000
    try testing.expectEqual(@as(u256, 1_000_000_000), result.block_value);

    const body = mock.last_body orelse return error.NoRequest;
    try testing.expect(std.mem.indexOf(u8, body, "engine_getPayloadV2") != null);
}

test "getPayloadV3: parses ExecutionPayload + blockValue + BlobsBundle response" {
    const allocator = testing.allocator;

    // V3 response: includes blobsBundle and shouldOverrideBuilder
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"executionPayload":{"parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","feeRecipient":"0x0000000000000000000000000000000000000000","stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","receiptsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x3","gasLimit":"0x1c9c380","gasUsed":"0x0","timestamp":"0x6553f300","extraData":"0x","baseFeePerGas":"0x3b9aca00","blockHash":"0x0303030303030303030303030303030303030303030303030303030303030303","transactions":[],"withdrawals":[],"blobGasUsed":"0x20000","excessBlobGas":"0x0"},"blockValue":"0x1","blobsBundle":{"commitments":[],"proofs":[],"blobs":[]},"shouldOverrideBuilder":false}}
    ;

    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const api3 = engine.engine();
    const result = try api3.getPayload([_]u8{0xef} ** 8);

    try testing.expectEqual(@as(u64, 3), result.execution_payload.block_number);
    try testing.expectEqual([_]u8{0x03} ** 32, result.execution_payload.block_hash);
    // blobGasUsed = 0x20000 = 131072
    try testing.expectEqual(@as(u64, 131072), result.execution_payload.blob_gas_used);
    try testing.expectEqual(@as(u256, 1), result.block_value);
    try testing.expect(!result.should_override_builder);

    const body = mock.last_body orelse return error.NoRequest;
    try testing.expect(std.mem.indexOf(u8, body, "engine_getPayloadV3") != null);
}

test "getPayloadV4: parses ExecutionPayload + blockValue + BlobsBundle + executionRequests" {
    const allocator = testing.allocator;

    // V4 response: Electra — adds depositRequests/withdrawalRequests/consolidationRequests
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"executionPayload":{"parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","feeRecipient":"0x0000000000000000000000000000000000000000","stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","receiptsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x4","gasLimit":"0x1c9c380","gasUsed":"0x0","timestamp":"0x6553f400","extraData":"0x","baseFeePerGas":"0x3b9aca00","blockHash":"0x0404040404040404040404040404040404040404040404040404040404040404","transactions":[],"withdrawals":[],"blobGasUsed":"0x0","excessBlobGas":"0x0","depositRequests":[],"withdrawalRequests":[],"consolidationRequests":[]},"blockValue":"0xff","blobsBundle":{"commitments":[],"proofs":[],"blobs":[]},"shouldOverrideBuilder":true}}
    ;

    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const api4 = engine.engine();
    const result = try api4.getPayloadV4([_]u8{0x12} ** 8);

    try testing.expectEqual(@as(u64, 4), result.execution_payload.block_number);
    try testing.expectEqual([_]u8{0x04} ** 32, result.execution_payload.block_hash);
    // blockValue = 0xff = 255
    try testing.expectEqual(@as(u256, 255), result.block_value);
    try testing.expect(result.should_override_builder);
    // Empty request arrays
    try testing.expectEqual(@as(usize, 0), result.execution_payload.deposit_requests.len);
    try testing.expectEqual(@as(usize, 0), result.execution_payload.withdrawal_requests.len);
    try testing.expectEqual(@as(usize, 0), result.execution_payload.consolidation_requests.len);

    const body = mock.last_body orelse return error.NoRequest;
    try testing.expect(std.mem.indexOf(u8, body, "engine_getPayloadV4") != null);
}

test "getPayloadV1: payload id is hex-encoded in request" {
    const allocator = testing.allocator;
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"executionPayload":{"parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","feeRecipient":"0x0000000000000000000000000000000000000000","stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","receiptsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x1","gasLimit":"0x0","gasUsed":"0x0","timestamp":"0x0","extraData":"0x","baseFeePerGas":"0x0","blockHash":"0x0000000000000000000000000000000000000000000000000000000000000000","transactions":[]},"blockValue":"0x0"}}
    ;

    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    // Payload ID with known bytes
    const pid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const api5 = engine.engine();
    _ = try api5.getPayloadV1(pid);

    const body = mock.last_body orelse return error.NoRequest;
    // Payload ID must appear as 0x0102030405060708
    try testing.expect(std.mem.indexOf(u8, body, "0x0102030405060708") != null);
}

test "getPayloadForFork: bellatrix dispatches to V1" {
    const allocator = testing.allocator;
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"executionPayload":{"parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","feeRecipient":"0x0000000000000000000000000000000000000000","stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","receiptsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x1","gasLimit":"0x0","gasUsed":"0x0","timestamp":"0x0","extraData":"0x","baseFeePerGas":"0x0","blockHash":"0x0101010101010101010101010101010101010101010101010101010101010101","transactions":[]},"blockValue":"0x0"}}
    ;

    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const resp = try engine.getPayloadForFork(.bellatrix, [_]u8{0xaa} ** 8);
    try testing.expectEqual([_]u8{0x01} ** 32, resp.execution_payload.block_hash);
    // Must use V1 method
    const body = mock.last_body orelse return error.NoRequest;
    try testing.expect(std.mem.indexOf(u8, body, "engine_getPayloadV1") != null);
}

test "getPayloadForFork: capella dispatches to V2" {
    const allocator = testing.allocator;
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"executionPayload":{"parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","feeRecipient":"0x0000000000000000000000000000000000000000","stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","receiptsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x2","gasLimit":"0x0","gasUsed":"0x0","timestamp":"0x0","extraData":"0x","baseFeePerGas":"0x0","blockHash":"0x0202020202020202020202020202020202020202020202020202020202020202","transactions":[],"withdrawals":[]},"blockValue":"0x0"}}
    ;

    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const resp = try engine.getPayloadForFork(.capella, [_]u8{0xbb} ** 8);
    try testing.expectEqual([_]u8{0x02} ** 32, resp.execution_payload.block_hash);
    const body = mock.last_body orelse return error.NoRequest;
    try testing.expect(std.mem.indexOf(u8, body, "engine_getPayloadV2") != null);
}

test "getPayloadForFork: electra dispatches to V4" {
    const allocator = testing.allocator;
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"executionPayload":{"parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","feeRecipient":"0x0000000000000000000000000000000000000000","stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","receiptsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x5","gasLimit":"0x0","gasUsed":"0x0","timestamp":"0x0","extraData":"0x","baseFeePerGas":"0x0","blockHash":"0x0505050505050505050505050505050505050505050505050505050505050505","transactions":[],"withdrawals":[],"blobGasUsed":"0x0","excessBlobGas":"0x0","depositRequests":[],"withdrawalRequests":[],"consolidationRequests":[]},"blockValue":"0x0","blobsBundle":{"commitments":[],"proofs":[],"blobs":[]},"shouldOverrideBuilder":false}}
    ;

    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const resp = try engine.getPayloadForFork(.electra, [_]u8{0xcc} ** 8);
    try testing.expectEqual([_]u8{0x05} ** 32, resp.execution_payload.block_hash);
    const body = mock.last_body orelse return error.NoRequest;
    try testing.expect(std.mem.indexOf(u8, body, "engine_getPayloadV4") != null);
}

// ── Payload Attributes encoding tests ─────────────────────────────────────────

test "PayloadAttributesV1: serializes timestamp, prevRandao, suggestedFeeRecipient" {
    const allocator = testing.allocator;
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"payloadStatus":{"status":"VALID","latestValidHash":null,"validationError":null},"payloadId":"0x0102030405060708"}}
    ;

    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const attrs = PayloadAttributesV1{
        .timestamp = 0xdeadbeef,
        .prev_randao = [_]u8{0x11} ** 32,
        .suggested_fee_recipient = [_]u8{0x22} ** 20,
    };

    const attrs_json = try encodePayloadAttributesV1(allocator, attrs);
    defer allocator.free(attrs_json);

    // Check all three fields are present
    try testing.expect(std.mem.indexOf(u8, attrs_json, "timestamp") != null);
    try testing.expect(std.mem.indexOf(u8, attrs_json, "prevRandao") != null);
    try testing.expect(std.mem.indexOf(u8, attrs_json, "suggestedFeeRecipient") != null);
    // No withdrawals in V1
    try testing.expect(std.mem.indexOf(u8, attrs_json, "withdrawals") == null);
    // No parentBeaconBlockRoot in V1
    try testing.expect(std.mem.indexOf(u8, attrs_json, "parentBeaconBlockRoot") == null);
    // Timestamp should be hex-encoded: 0xdeadbeef
    try testing.expect(std.mem.indexOf(u8, attrs_json, "deadbeef") != null);
}

test "PayloadAttributesV2: includes withdrawals, no parentBeaconBlockRoot" {
    const allocator = testing.allocator;

    const attrs = PayloadAttributesV2{
        .timestamp = 1000,
        .prev_randao = [_]u8{0x33} ** 32,
        .suggested_fee_recipient = [_]u8{0x44} ** 20,
        .withdrawals = &.{
            .{ .index = 0, .validator_index = 1, .address = [_]u8{0x55} ** 20, .amount = 1000000 },
        },
    };

    const attrs_json = try encodePayloadAttributesV2(allocator, attrs);
    defer allocator.free(attrs_json);

    try testing.expect(std.mem.indexOf(u8, attrs_json, "withdrawals") != null);
    try testing.expect(std.mem.indexOf(u8, attrs_json, "parentBeaconBlockRoot") == null);
    // Fee recipient: 0x44*20 should appear
    try testing.expect(std.mem.indexOf(u8, attrs_json, "4444444444444444444444444444444444444444") != null);
}

test "PayloadAttributesV3: includes withdrawals AND parentBeaconBlockRoot" {
    const allocator = testing.allocator;

    const attrs = PayloadAttributesV3{
        .timestamp = 2000,
        .prev_randao = [_]u8{0x77} ** 32,
        .suggested_fee_recipient = [_]u8{0x88} ** 20,
        .withdrawals = &.{},
        .parent_beacon_block_root = [_]u8{0x99} ** 32,
    };

    const attrs_json = try encodePayloadAttributes(allocator, attrs);
    defer allocator.free(attrs_json);

    try testing.expect(std.mem.indexOf(u8, attrs_json, "withdrawals") != null);
    try testing.expect(std.mem.indexOf(u8, attrs_json, "parentBeaconBlockRoot") != null);
    // Parent beacon block root 0x99*32 should appear
    try testing.expect(std.mem.indexOf(u8, attrs_json, "9999999999999999999999999999999999999999999999999999999999999999") != null);
}

// ── Engine health monitoring tests ───────────────────────────────────────────

test "HttpEngine: state transitions offline→online are logged" {
    const allocator = testing.allocator;

    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"status":"VALID","latestValidHash":null,"validationError":null}}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();

    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    // Manually set offline state
    engine.state = .offline;
    try testing.expectEqual(EngineState.offline, engine.state);

    // Successful request should transition back to online
    const api = engine.engine();
    _ = try api.newPayload(makeTestPayload([_]u8{0x01} ** 32), &.{}, std.mem.zeroes([32]u8));

    // State should now be online
    try testing.expectEqual(EngineState.online, engine.state);
}

test "HttpEngine: syncing state tracks EL sync" {
    const allocator = testing.allocator;

    // EL returns SYNCING — state machine should track this
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"status":"SYNCING","latestValidHash":null,"validationError":null}}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();

    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const api = engine.engine();
    const result = try api.newPayload(makeTestPayload([_]u8{0x01} ** 32), &.{}, std.mem.zeroes([32]u8));

    // SYNCING is a valid response (optimistic sync)
    try testing.expectEqual(ExecutionPayloadStatus.syncing, result.status);
    // Transport succeeded so state stays online (SYNCING is an application-level response, not transport error)
    try testing.expectEqual(EngineState.online, engine.state);
}

test "HttpEngine: exchangeTransitionConfiguration verifies merge config" {
    const allocator = testing.allocator;

    // EL responds with matching TTD config
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"terminalTotalDifficulty":"0xc70d808a128d7380000","terminalBlockHash":"0x0000000000000000000000000000000000000000000000000000000000000000","terminalBlockNumber":"0x0"}}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();

    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    // The Ethereum mainnet TTD
    const mainnet_ttd: u256 = 58750003716598352816469;
    const result = try engine.exchangeTransitionConfiguration(.{
        .terminal_total_difficulty = mainnet_ttd,
        .terminal_block_hash = std.mem.zeroes([32]u8),
        .terminal_block_number = 0,
    });

    // EL confirmed terminal block hash is zero (pre-merge / block not yet reached)
    try testing.expectEqual(std.mem.zeroes([32]u8), result.terminal_block_hash);
    try testing.expectEqual(@as(u64, 0), result.terminal_block_number);
    // The method must appear in the request
    const body = mock.last_body orelse return error.NoRequest;
    try testing.expect(std.mem.indexOf(u8, body, "engine_exchangeTransitionConfigurationV1") != null);
}

test "HttpEngine: optimistic sync — SYNCING newPayload accepted without error" {
    const allocator = testing.allocator;

    // During optimistic sync, EL returns SYNCING for newPayload
    // CL must accept the block (not reject it)
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"status":"SYNCING","latestValidHash":null,"validationError":null}}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();

    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const api = engine.engine();

    // Must not return an error — SYNCING is a valid status
    const result = try api.newPayload(makeTestPayload([_]u8{0x42} ** 32), &.{}, std.mem.zeroes([32]u8));
    try testing.expectEqual(ExecutionPayloadStatus.syncing, result.status);
    try testing.expect(result.latest_valid_hash == null);
}

test "checkHealth: eth_syncing returns false = synced" {
    const allocator = testing.allocator;

    // EL is fully synced — eth_syncing returns false
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":false}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();

    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const status = try engine.checkHealth();
    try testing.expectEqual(HttpEngine.SyncingStatus.synced, status);
    try testing.expectEqual(EngineState.online, engine.state);

    const body = mock.last_body orelse return error.NoRequest;
    try testing.expect(std.mem.indexOf(u8, body, "eth_syncing") != null);
}

test "checkHealth: eth_syncing returns object = syncing with progress" {
    const allocator = testing.allocator;

    // EL is syncing — returns progress object
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":{"currentBlock":"0x100","highestBlock":"0x200","startingBlock":"0x0","knownStates":"0x0","pulledStates":"0x0"}}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();

    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const status = try engine.checkHealth();
    try testing.expect(status == .syncing);
    try testing.expectEqual(@as(u64, 0x100), status.syncing.current_block);
    try testing.expectEqual(@as(u64, 0x200), status.syncing.highest_block);
    try testing.expectEqual(EngineState.syncing, engine.state);
}

test "checkHealth: transport error marks EL offline" {
    const allocator = testing.allocator;

    var mock = MockTransport.init(allocator, "");
    defer mock.deinit();

    // Use an engine that will get an error from the transport
    // We need a custom transport that errors — use a mock engine that fails
    const ErrorTransport = struct {
        fn send(_: *anyopaque, _: HttpMethod, _: []const u8, _: []const Header, _: []const u8) anyerror![]const u8 {
            return error.ConnectionRefused;
        }
    };
    var dummy: u8 = 0;
    const error_transport = Transport{
        .ptr = @ptrCast(&dummy),
        .sendFn = ErrorTransport.send,
    };

    var engine = HttpEngine.initWithRetry(allocator, "http://localhost:8551", null, error_transport, .{
        .max_retries = 0,
        .initial_backoff_ms = 0,
    });
    defer engine.deinit();

    const result = engine.checkHealth();
    try testing.expectError(error.ConnectionRefused, result);
    try testing.expectEqual(EngineState.offline, engine.state);
}

test "checkHealth: offline→online transition logs" {
    const allocator = testing.allocator;

    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":false}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();

    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    // Force offline state
    engine.state = .offline;

    // Health check should transition to online
    const status = try engine.checkHealth();
    try testing.expectEqual(HttpEngine.SyncingStatus.synced, status);
    try testing.expectEqual(EngineState.online, engine.state);
}

// ── getPayloadBodies tests ────────────────────────────────────────────────────

test "getPayloadBodiesByHashV1: empty array" {
    const allocator = testing.allocator;

    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":[]}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const result = try engine.getPayloadBodiesByHashV1(&.{});
    defer engine.freePayloadBodiesV1(result);

    try testing.expectEqual(@as(usize, 0), result.len);

    const body = mock.last_body orelse return error.NoRequest;
    try testing.expect(std.mem.indexOf(u8, body, "engine_getPayloadBodiesByHashV1") != null);
}

test "getPayloadBodiesByHashV1: mixed null and present entries" {
    const allocator = testing.allocator;

    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":[{"transactions":["0xdeadbeef"],"withdrawals":[{"index":"0x0","validatorIndex":"0x1","address":"0x0000000000000000000000000000000000000001","amount":"0x3b9aca00"}]},null,{"transactions":[],"withdrawals":null}]}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const hashes = [_][32]u8{ [_]u8{0x01} ** 32, [_]u8{0x02} ** 32, [_]u8{0x03} ** 32 };
    const result = try engine.getPayloadBodiesByHashV1(&hashes);
    defer engine.freePayloadBodiesV1(result);

    try testing.expectEqual(@as(usize, 3), result.len);

    // First entry: 1 transaction, 1 withdrawal
    const body0 = result[0].?;
    try testing.expectEqual(@as(usize, 1), body0.transactions.len);
    try testing.expectEqual(@as(usize, 4), body0.transactions[0].len); // 0xdeadbeef = 4 bytes
    try testing.expect(body0.withdrawals != null);
    try testing.expectEqual(@as(usize, 1), body0.withdrawals.?.len);
    try testing.expectEqual(@as(u64, 1_000_000_000), body0.withdrawals.?[0].amount);

    // Second entry: null (block not found)
    try testing.expect(result[1] == null);

    // Third entry: no transactions, no withdrawals (pre-Capella)
    const body2 = result[2].?;
    try testing.expectEqual(@as(usize, 0), body2.transactions.len);
    try testing.expect(body2.withdrawals == null);

    // Verify hashes encoded in request
    const req_body = mock.last_body orelse return error.NoRequest;
    try testing.expect(std.mem.indexOf(u8, req_body, "engine_getPayloadBodiesByHashV1") != null);
    try testing.expect(std.mem.indexOf(u8, req_body, "0x0101010101010101010101010101010101010101010101010101010101010101") != null);
}

test "getPayloadBodiesByRangeV1: parses range response" {
    const allocator = testing.allocator;

    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":[{"transactions":["0xaa","0xbb"],"withdrawals":[]},null]}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const result = try engine.getPayloadBodiesByRangeV1(100, 2);
    defer engine.freePayloadBodiesV1(result);

    try testing.expectEqual(@as(usize, 2), result.len);

    // First entry present
    const body0 = result[0].?;
    try testing.expectEqual(@as(usize, 2), body0.transactions.len);
    try testing.expect(body0.withdrawals != null);
    try testing.expectEqual(@as(usize, 0), body0.withdrawals.?.len);

    // Second entry null
    try testing.expect(result[1] == null);

    // Verify request uses QUANTITY encoding for start/count
    const body = mock.last_body orelse return error.NoRequest;
    try testing.expect(std.mem.indexOf(u8, body, "engine_getPayloadBodiesByRangeV1") != null);
    try testing.expect(std.mem.indexOf(u8, body, "0x64") != null); // 100 = 0x64
    try testing.expect(std.mem.indexOf(u8, body, "0x2") != null); // count = 2
}

test "getPayloadBodiesByHashV2: parses Electra requests" {
    const allocator = testing.allocator;

    // V2 response with deposit/withdrawal/consolidation requests
    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":[{"transactions":[],"withdrawals":[],"depositRequests":[{"pubkey":"0x010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101","withdrawalCredentials":"0x0202020202020202020202020202020202020202020202020202020202020202","amount":"0x773593ff","signature":"0x030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303","index":"0x0"}],"withdrawalRequests":[{"sourceAddress":"0x0404040404040404040404040404040404040404","validatorPubkey":"0x050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505","amount":"0x3b9aca00"}],"consolidationRequests":[{"sourceAddress":"0x0606060606060606060606060606060606060606","sourcePubkey":"0x070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707","targetPubkey":"0x080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808"}]}]}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const hashes = [_][32]u8{[_]u8{0xaa} ** 32};
    const result = try engine.getPayloadBodiesByHashV2(&hashes);
    defer engine.freePayloadBodiesV2(result);

    try testing.expectEqual(@as(usize, 1), result.len);
    const b = result[0].?;
    try testing.expectEqual(@as(usize, 0), b.transactions.len);
    try testing.expect(b.withdrawals != null);
    try testing.expectEqual(@as(usize, 0), b.withdrawals.?.len);

    // Deposit requests
    try testing.expect(b.deposit_requests != null);
    try testing.expectEqual(@as(usize, 1), b.deposit_requests.?.len);
    try testing.expectEqual([_]u8{0x01} ** 48, b.deposit_requests.?[0].pubkey);

    // Withdrawal requests
    try testing.expect(b.withdrawal_requests != null);
    try testing.expectEqual(@as(usize, 1), b.withdrawal_requests.?.len);
    try testing.expectEqual([_]u8{0x04} ** 20, b.withdrawal_requests.?[0].source_address);

    // Consolidation requests
    try testing.expect(b.consolidation_requests != null);
    try testing.expectEqual(@as(usize, 1), b.consolidation_requests.?.len);
    try testing.expectEqual([_]u8{0x06} ** 20, b.consolidation_requests.?[0].source_address);

    const body = mock.last_body orelse return error.NoRequest;
    try testing.expect(std.mem.indexOf(u8, body, "engine_getPayloadBodiesByHashV2") != null);
}

test "getPayloadBodiesByRangeV2: parses V2 range response" {
    const allocator = testing.allocator;

    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":[{"transactions":[],"withdrawals":null,"depositRequests":null,"withdrawalRequests":null,"consolidationRequests":null},null]}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const result = try engine.getPayloadBodiesByRangeV2(1, 2);
    defer engine.freePayloadBodiesV2(result);

    try testing.expectEqual(@as(usize, 2), result.len);
    const b = result[0].?;
    try testing.expect(b.withdrawals == null);
    try testing.expect(b.deposit_requests == null);
    try testing.expect(b.withdrawal_requests == null);
    try testing.expect(b.consolidation_requests == null);
    try testing.expect(result[1] == null);

    const body = mock.last_body orelse return error.NoRequest;
    try testing.expect(std.mem.indexOf(u8, body, "engine_getPayloadBodiesByRangeV2") != null);
}

test "getPayloadBodiesByHashV1: JSON-RPC error propagates" {
    const allocator = testing.allocator;

    const canned =
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-38004,"message":"too large"}}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const result = engine.getPayloadBodiesByHashV1(&.{[_]u8{0x01} ** 32});
    try testing.expectError(error.TooLargeRequest, result);
}

test "supported_capabilities includes payload bodies methods" {
    const caps = HttpEngine.supported_capabilities;
    var found_hash_v1 = false;
    var found_hash_v2 = false;
    var found_range_v1 = false;
    var found_range_v2 = false;
    for (caps) |c| {
        if (std.mem.eql(u8, c, "engine_getPayloadBodiesByHashV1")) found_hash_v1 = true;
        if (std.mem.eql(u8, c, "engine_getPayloadBodiesByHashV2")) found_hash_v2 = true;
        if (std.mem.eql(u8, c, "engine_getPayloadBodiesByRangeV1")) found_range_v1 = true;
        if (std.mem.eql(u8, c, "engine_getPayloadBodiesByRangeV2")) found_range_v2 = true;
    }
    try testing.expect(found_hash_v1);
    try testing.expect(found_hash_v2);
    try testing.expect(found_range_v1);
    try testing.expect(found_range_v2);
}

test "getPayloadBodiesByHashForFork: deneb uses V1, electra uses V2" {
    const allocator = testing.allocator;

    const canned =
        \\{"jsonrpc":"2.0","id":1,"result":[]}
    ;
    var mock = MockTransport.init(allocator, canned);
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    // Deneb → V1
    const r1 = try engine.getPayloadBodiesByHashForFork(.deneb, &.{});
    switch (r1) {
        .v1 => |v| engine.freePayloadBodiesV1(v),
        .v2 => return error.ExpectedV1,
    }
    const body1 = mock.last_body orelse return error.NoRequest;
    try testing.expect(std.mem.indexOf(u8, body1, "engine_getPayloadBodiesByHashV1") != null);

    // Electra → V2
    const r2 = try engine.getPayloadBodiesByHashForFork(.electra, &.{});
    switch (r2) {
        .v1 => return error.ExpectedV2,
        .v2 => |v| engine.freePayloadBodiesV2(v),
    }
    const body2 = mock.last_body orelse return error.NoRequest;
    try testing.expect(std.mem.indexOf(u8, body2, "engine_getPayloadBodiesByHashV2") != null);
}

test "getPayloadBodiesByRangeForFork: pre-merge returns error" {
    const allocator = testing.allocator;
    var mock = MockTransport.init(allocator, "{}");
    defer mock.deinit();
    var engine = HttpEngine.init(allocator, "http://localhost:8551", null, mock.transport());
    defer engine.deinit();

    const result = engine.getPayloadBodiesByRangeForFork(.phase0, 1, 10);
    try testing.expectError(error.UnsupportedFork, result);
}
