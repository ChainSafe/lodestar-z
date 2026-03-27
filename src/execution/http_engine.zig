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
        url: []const u8,
        headers: []const Header,
        body: []const u8,
    ) anyerror![]const u8,

    pub fn send(
        self: Transport,
        url: []const u8,
        headers: []const Header,
        body: []const u8,
    ) ![]const u8 {
        return self.sendFn(self.ptr, url, headers, body);
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

    pub fn deinit(_: *HttpEngine) void {}

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
            .offline => std.log.err("Engine API: EL went offline (was {s})", .{@tagName(old)}),
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

            const result = self.transport.send(self.endpoint, headers_buf[0..header_count], body);
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
        var caps_parts: std.ArrayList([]const u8) = .empty;
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
                break :blk self.newPayloadV1(p);
            },
            .capella => blk: {
                // payload must be ExecutionPayloadV2
                const p: ExecutionPayloadV2 = payload;
                break :blk self.newPayloadV2(p);
            },
            .deneb => blk: {
                // payload must be ExecutionPayloadV3
                const p: ExecutionPayloadV3 = payload;
                break :blk self.newPayloadV3(p, versioned_hashes, parent_beacon_root);
            },
            .electra, .fulu => blk: {
                // payload must be ExecutionPayloadV4
                const p: ExecutionPayloadV4 = payload;
                break :blk self.newPayloadV4(p, versioned_hashes, parent_beacon_root);
            },
        };
    }

    /// Send forkchoiceUpdated using the fork-appropriate version.
    pub fn forkchoiceUpdatedForFork(
        self: *HttpEngine,
        fork: Fork,
        state: ForkchoiceStateV1,
        /// Must be null or the appropriate PayloadAttributes variant for the fork.
        /// Pass PayloadAttributesV1 for bellatrix, V2 for capella, V3 for deneb+.
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

        return decodeForkchoiceUpdatedResponse(parsed.value);
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
                const r = try self.getPayloadV1(payload_id);
                // Promote V1 to unified GetPayloadResponse.
                break :blk GetPayloadResponse{
                    .execution_payload = ExecutionPayloadV3{
                        .parent_hash = r.execution_payload.parent_hash,
                        .fee_recipient = r.execution_payload.fee_recipient,
                        .state_root = r.execution_payload.state_root,
                        .receipts_root = r.execution_payload.receipts_root,
                        .logs_bloom = r.execution_payload.logs_bloom,
                        .prev_randao = r.execution_payload.prev_randao,
                        .block_number = r.execution_payload.block_number,
                        .gas_limit = r.execution_payload.gas_limit,
                        .gas_used = r.execution_payload.gas_used,
                        .timestamp = r.execution_payload.timestamp,
                        .extra_data = r.execution_payload.extra_data,
                        .base_fee_per_gas = r.execution_payload.base_fee_per_gas,
                        .block_hash = r.execution_payload.block_hash,
                        .transactions = r.execution_payload.transactions,
                        .withdrawals = &.{},
                        .blob_gas_used = 0,
                        .excess_blob_gas = 0,
                    },
                    .block_value = r.block_value,
                    .blobs_bundle = .{ .commitments = &.{}, .proofs = &.{}, .blobs = &.{} },
                    .should_override_builder = false,
                };
            },
            .capella => blk: {
                const r = try self.getPayloadV2(payload_id);
                break :blk GetPayloadResponse{
                    .execution_payload = ExecutionPayloadV3{
                        .parent_hash = r.execution_payload.parent_hash,
                        .fee_recipient = r.execution_payload.fee_recipient,
                        .state_root = r.execution_payload.state_root,
                        .receipts_root = r.execution_payload.receipts_root,
                        .logs_bloom = r.execution_payload.logs_bloom,
                        .prev_randao = r.execution_payload.prev_randao,
                        .block_number = r.execution_payload.block_number,
                        .gas_limit = r.execution_payload.gas_limit,
                        .gas_used = r.execution_payload.gas_used,
                        .timestamp = r.execution_payload.timestamp,
                        .extra_data = r.execution_payload.extra_data,
                        .base_fee_per_gas = r.execution_payload.base_fee_per_gas,
                        .block_hash = r.execution_payload.block_hash,
                        .transactions = r.execution_payload.transactions,
                        .withdrawals = r.execution_payload.withdrawals,
                        .blob_gas_used = 0,
                        .excess_blob_gas = 0,
                    },
                    .block_value = r.block_value,
                    .blobs_bundle = .{ .commitments = &.{}, .proofs = &.{}, .blobs = &.{} },
                    .should_override_builder = false,
                };
            },
            .deneb => self.getPayloadV3(payload_id),
            .electra, .fulu => blk: {
                const r = try self.getPayloadV4(payload_id);
                break :blk GetPayloadResponse{
                    .execution_payload = ExecutionPayloadV3{
                        .parent_hash = r.execution_payload.parent_hash,
                        .fee_recipient = r.execution_payload.fee_recipient,
                        .state_root = r.execution_payload.state_root,
                        .receipts_root = r.execution_payload.receipts_root,
                        .logs_bloom = r.execution_payload.logs_bloom,
                        .prev_randao = r.execution_payload.prev_randao,
                        .block_number = r.execution_payload.block_number,
                        .gas_limit = r.execution_payload.gas_limit,
                        .gas_used = r.execution_payload.gas_used,
                        .timestamp = r.execution_payload.timestamp,
                        .extra_data = r.execution_payload.extra_data,
                        .base_fee_per_gas = r.execution_payload.base_fee_per_gas,
                        .block_hash = r.execution_payload.block_hash,
                        .transactions = r.execution_payload.transactions,
                        .withdrawals = r.execution_payload.withdrawals,
                        .blob_gas_used = r.execution_payload.blob_gas_used,
                        .excess_blob_gas = r.execution_payload.excess_blob_gas,
                    },
                    .block_value = r.block_value,
                    .blobs_bundle = r.blobs_bundle,
                    .should_override_builder = r.should_override_builder,
                };
            },
        };
    }

    // ── vtable ────────────────────────────────────────────────────────────────

    const vtable = EngineApi.VTable{
        .newPayloadV1 = @ptrCast(&newPayloadV1),
        .newPayloadV2 = @ptrCast(&newPayloadV2),
        .newPayloadV3 = @ptrCast(&newPayloadV3),
        .newPayloadV4 = @ptrCast(&newPayloadV4),
        .forkchoiceUpdatedV1 = @ptrCast(&forkchoiceUpdatedV1),
        .forkchoiceUpdatedV2 = @ptrCast(&forkchoiceUpdatedV2),
        .forkchoiceUpdatedV3 = @ptrCast(&forkchoiceUpdatedV3),
        .getPayloadV1 = @ptrCast(&getPayloadV1),
        .getPayloadV2 = @ptrCast(&getPayloadV2),
        .getPayloadV3 = @ptrCast(&getPayloadV3),
        .getPayloadV4 = @ptrCast(&getPayloadV4),
    };

    fn newPayloadV3(
        self: *HttpEngine,
        payload: ExecutionPayloadV3,
        versioned_hashes: []const [32]u8,
        parent_beacon_root: [32]u8,
    ) anyerror!PayloadStatusV1 {
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

        return decodePayloadStatus(parsed.value);
    }

    fn forkchoiceUpdatedV3(
        self: *HttpEngine,
        state: ForkchoiceStateV1,
        attrs: ?PayloadAttributesV3,
    ) anyerror!ForkchoiceUpdatedResponse {
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

        return decodeForkchoiceUpdatedResponse(parsed.value);
    }

    fn getPayloadV3(
        self: *HttpEngine,
        payload_id: [8]u8,
    ) anyerror!GetPayloadResponse {
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
        self: *HttpEngine,
        payload: ExecutionPayloadV1,
    ) anyerror!PayloadStatusV1 {
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

        return decodePayloadStatus(parsed.value);
    }

    fn newPayloadV2(
        self: *HttpEngine,
        payload: ExecutionPayloadV2,
    ) anyerror!PayloadStatusV1 {
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

        return decodePayloadStatus(parsed.value);
    }

    fn newPayloadV4(
        self: *HttpEngine,
        payload: ExecutionPayloadV4,
        versioned_hashes: []const [32]u8,
        parent_beacon_root: [32]u8,
    ) anyerror!PayloadStatusV1 {
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

        return decodePayloadStatus(parsed.value);
    }

    // ── forkchoiceUpdated V1 / V2 ─────────────────────────────────────────────

    fn forkchoiceUpdatedV1(
        self: *HttpEngine,
        state: ForkchoiceStateV1,
        attrs: ?PayloadAttributesV1,
    ) anyerror!ForkchoiceUpdatedResponse {
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

        return decodeForkchoiceUpdatedResponse(parsed.value);
    }

    fn forkchoiceUpdatedV2(
        self: *HttpEngine,
        state: ForkchoiceStateV1,
        attrs: ?PayloadAttributesV2,
    ) anyerror!ForkchoiceUpdatedResponse {
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

        return decodeForkchoiceUpdatedResponse(parsed.value);
    }

    // ── getPayload V1 / V2 / V4 ──────────────────────────────────────────────

    fn getPayloadV1(
        self: *HttpEngine,
        payload_id: [8]u8,
    ) anyerror!GetPayloadResponseV1 {
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

        return decodeGetPayloadResponseV1(parsed.value);
    }

    fn getPayloadV2(
        self: *HttpEngine,
        payload_id: [8]u8,
    ) anyerror!GetPayloadResponseV2 {
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

        return decodeGetPayloadResponseV2(parsed.value);
    }

    fn getPayloadV4(
        self: *HttpEngine,
        payload_id: [8]u8,
    ) anyerror!GetPayloadResponseV4 {
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

/// Hex-encode a u64 as big-endian with "0x" prefix (no leading zero bytes stripped).
/// Use this for fixed-width DATA fields (block_hash, etc.).
pub fn hexEncodeU64(allocator: Allocator, value: u64) ![]const u8 {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .big);
    return hexEncode(allocator, &buf);
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
    const index_hex = try hexEncodeU64(allocator, w.index);
    defer allocator.free(index_hex);
    const vi_hex = try hexEncodeU64(allocator, w.validator_index);
    defer allocator.free(vi_hex);
    const addr_hex = try hexEncodeFixed(allocator, &w.address);
    defer allocator.free(addr_hex);
    const amt_hex = try hexEncodeU64(allocator, w.amount);
    defer allocator.free(amt_hex);

    return std.fmt.allocPrint(
        allocator,
        "{{\"index\":\"{s}\",\"validatorIndex\":\"{s}\",\"address\":\"{s}\",\"amount\":\"{s}\"}}",
        .{ index_hex, vi_hex, addr_hex, amt_hex },
    );
}

fn encodeWithdrawals(allocator: Allocator, withdrawals: []const Withdrawal) ![]const u8 {
    var parts: std.ArrayList([]const u8) = .empty;
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
    var parts: std.ArrayList([]const u8) = .empty;
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
    var parts: std.ArrayList([]const u8) = .empty;
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
    const timestamp = try hexEncodeU64(allocator, attrs.timestamp);
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
    const timestamp = try hexEncodeU64(allocator, attrs.timestamp);
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

fn encodeExecutionPayloadV1(allocator: Allocator, p: ExecutionPayloadV1) ![]const u8 {
    const parent_hash = try hexEncodeFixed(allocator, &p.parent_hash);
    defer allocator.free(parent_hash);
    const fee_recipient = try hexEncodeFixed(allocator, &p.fee_recipient);
    defer allocator.free(fee_recipient);
    const state_root = try hexEncodeFixed(allocator, &p.state_root);
    defer allocator.free(state_root);
    const receipts_root = try hexEncodeFixed(allocator, &p.receipts_root);
    defer allocator.free(receipts_root);
    const logs_bloom = try hexEncodeFixed(allocator, &p.logs_bloom);
    defer allocator.free(logs_bloom);
    const prev_randao = try hexEncodeFixed(allocator, &p.prev_randao);
    defer allocator.free(prev_randao);
    const block_number = try hexEncodeU64(allocator, p.block_number);
    defer allocator.free(block_number);
    const gas_limit = try hexEncodeU64(allocator, p.gas_limit);
    defer allocator.free(gas_limit);
    const gas_used = try hexEncodeU64(allocator, p.gas_used);
    defer allocator.free(gas_used);
    const timestamp = try hexEncodeU64(allocator, p.timestamp);
    defer allocator.free(timestamp);
    const extra_data = try hexEncode(allocator, p.extra_data);
    defer allocator.free(extra_data);
    const base_fee = try hexEncodeU256(allocator, p.base_fee_per_gas);
    defer allocator.free(base_fee);
    const block_hash = try hexEncodeFixed(allocator, &p.block_hash);
    defer allocator.free(block_hash);
    const transactions = try encodeTransactions(allocator, p.transactions);
    defer allocator.free(transactions);

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
        parent_hash,  fee_recipient, state_root,  receipts_root,
        logs_bloom,   prev_randao,   block_number, gas_limit,
        gas_used,     timestamp,     extra_data,   base_fee,
        block_hash,   transactions,
    });
}

fn encodeExecutionPayloadV2(allocator: Allocator, p: ExecutionPayloadV2) ![]const u8 {
    const parent_hash = try hexEncodeFixed(allocator, &p.parent_hash);
    defer allocator.free(parent_hash);
    const fee_recipient = try hexEncodeFixed(allocator, &p.fee_recipient);
    defer allocator.free(fee_recipient);
    const state_root = try hexEncodeFixed(allocator, &p.state_root);
    defer allocator.free(state_root);
    const receipts_root = try hexEncodeFixed(allocator, &p.receipts_root);
    defer allocator.free(receipts_root);
    const logs_bloom = try hexEncodeFixed(allocator, &p.logs_bloom);
    defer allocator.free(logs_bloom);
    const prev_randao = try hexEncodeFixed(allocator, &p.prev_randao);
    defer allocator.free(prev_randao);
    const block_number = try hexEncodeU64(allocator, p.block_number);
    defer allocator.free(block_number);
    const gas_limit = try hexEncodeU64(allocator, p.gas_limit);
    defer allocator.free(gas_limit);
    const gas_used = try hexEncodeU64(allocator, p.gas_used);
    defer allocator.free(gas_used);
    const timestamp = try hexEncodeU64(allocator, p.timestamp);
    defer allocator.free(timestamp);
    const extra_data = try hexEncode(allocator, p.extra_data);
    defer allocator.free(extra_data);
    const base_fee = try hexEncodeU256(allocator, p.base_fee_per_gas);
    defer allocator.free(base_fee);
    const block_hash = try hexEncodeFixed(allocator, &p.block_hash);
    defer allocator.free(block_hash);
    const transactions = try encodeTransactions(allocator, p.transactions);
    defer allocator.free(transactions);
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
        parent_hash,  fee_recipient, state_root,   receipts_root,
        logs_bloom,   prev_randao,   block_number,  gas_limit,
        gas_used,     timestamp,     extra_data,    base_fee,
        block_hash,   transactions,  withdrawals,
    });
}

fn encodeDepositRequest(allocator: Allocator, dr: DepositRequest) ![]const u8 {
    const pubkey = try hexEncodeFixed(allocator, &dr.pubkey);
    defer allocator.free(pubkey);
    const wc = try hexEncodeFixed(allocator, &dr.withdrawal_credentials);
    defer allocator.free(wc);
    const amount = try hexEncodeU64(allocator, dr.amount);
    defer allocator.free(amount);
    const sig = try hexEncodeFixed(allocator, &dr.signature);
    defer allocator.free(sig);
    const index = try hexEncodeU64(allocator, dr.index);
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
    const amt = try hexEncodeU64(allocator, wr.amount);
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
    var parts: std.ArrayList([]const u8) = .empty;
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
    var parts: std.ArrayList([]const u8) = .empty;
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
    var parts: std.ArrayList([]const u8) = .empty;
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
    const parent_hash = try hexEncodeFixed(allocator, &p.parent_hash);
    defer allocator.free(parent_hash);
    const fee_recipient = try hexEncodeFixed(allocator, &p.fee_recipient);
    defer allocator.free(fee_recipient);
    const state_root = try hexEncodeFixed(allocator, &p.state_root);
    defer allocator.free(state_root);
    const receipts_root = try hexEncodeFixed(allocator, &p.receipts_root);
    defer allocator.free(receipts_root);
    const logs_bloom = try hexEncodeFixed(allocator, &p.logs_bloom);
    defer allocator.free(logs_bloom);
    const prev_randao = try hexEncodeFixed(allocator, &p.prev_randao);
    defer allocator.free(prev_randao);
    const block_number = try hexEncodeU64(allocator, p.block_number);
    defer allocator.free(block_number);
    const gas_limit = try hexEncodeU64(allocator, p.gas_limit);
    defer allocator.free(gas_limit);
    const gas_used = try hexEncodeU64(allocator, p.gas_used);
    defer allocator.free(gas_used);
    const timestamp = try hexEncodeU64(allocator, p.timestamp);
    defer allocator.free(timestamp);
    const extra_data = try hexEncode(allocator, p.extra_data);
    defer allocator.free(extra_data);
    const base_fee = try hexEncodeU256(allocator, p.base_fee_per_gas);
    defer allocator.free(base_fee);
    const block_hash = try hexEncodeFixed(allocator, &p.block_hash);
    defer allocator.free(block_hash);
    const transactions = try encodeTransactions(allocator, p.transactions);
    defer allocator.free(transactions);
    const withdrawals = try encodeWithdrawals(allocator, p.withdrawals);
    defer allocator.free(withdrawals);
    const blob_gas_used = try hexEncodeU64(allocator, p.blob_gas_used);
    defer allocator.free(blob_gas_used);
    const excess_blob_gas = try hexEncodeU64(allocator, p.excess_blob_gas);
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
        parent_hash,          fee_recipient,        state_root,           receipts_root,
        logs_bloom,           prev_randao,           block_number,         gas_limit,
        gas_used,             timestamp,             extra_data,           base_fee,
        block_hash,           transactions,          withdrawals,          blob_gas_used,
        excess_blob_gas,      deposit_requests,      withdrawal_requests,  consolidation_requests,
    });
}

fn encodeExecutionPayloadV3(allocator: Allocator, p: ExecutionPayloadV3) ![]const u8 {
    const parent_hash = try hexEncodeFixed(allocator, &p.parent_hash);
    defer allocator.free(parent_hash);
    const fee_recipient = try hexEncodeFixed(allocator, &p.fee_recipient);
    defer allocator.free(fee_recipient);
    const state_root = try hexEncodeFixed(allocator, &p.state_root);
    defer allocator.free(state_root);
    const receipts_root = try hexEncodeFixed(allocator, &p.receipts_root);
    defer allocator.free(receipts_root);
    const logs_bloom = try hexEncodeFixed(allocator, &p.logs_bloom);
    defer allocator.free(logs_bloom);
    const prev_randao = try hexEncodeFixed(allocator, &p.prev_randao);
    defer allocator.free(prev_randao);
    const block_number = try hexEncodeU64(allocator, p.block_number);
    defer allocator.free(block_number);
    const gas_limit = try hexEncodeU64(allocator, p.gas_limit);
    defer allocator.free(gas_limit);
    const gas_used = try hexEncodeU64(allocator, p.gas_used);
    defer allocator.free(gas_used);
    const timestamp = try hexEncodeU64(allocator, p.timestamp);
    defer allocator.free(timestamp);
    const extra_data = try hexEncode(allocator, p.extra_data);
    defer allocator.free(extra_data);
    const base_fee = try hexEncodeU256(allocator, p.base_fee_per_gas);
    defer allocator.free(base_fee);
    const block_hash = try hexEncodeFixed(allocator, &p.block_hash);
    defer allocator.free(block_hash);
    const transactions = try encodeTransactions(allocator, p.transactions);
    defer allocator.free(transactions);
    const withdrawals = try encodeWithdrawals(allocator, p.withdrawals);
    defer allocator.free(withdrawals);
    const blob_gas_used = try hexEncodeU64(allocator, p.blob_gas_used);
    defer allocator.free(blob_gas_used);
    const excess_blob_gas = try hexEncodeU64(allocator, p.excess_blob_gas);
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
        parent_hash,   fee_recipient, state_root,    receipts_root,
        logs_bloom,    prev_randao,   block_number,  gas_limit,
        gas_used,      timestamp,     extra_data,    base_fee,
        block_hash,    transactions,  withdrawals,   blob_gas_used,
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
    const timestamp = try hexEncodeU64(allocator, attrs.timestamp);
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

fn decodePayloadStatus(j: PayloadStatusJson) !PayloadStatusV1 {
    const status = blk: {
        if (std.mem.eql(u8, j.status, "VALID")) break :blk ExecutionPayloadStatus.valid;
        if (std.mem.eql(u8, j.status, "INVALID")) break :blk ExecutionPayloadStatus.invalid;
        if (std.mem.eql(u8, j.status, "SYNCING")) break :blk ExecutionPayloadStatus.syncing;
        if (std.mem.eql(u8, j.status, "ACCEPTED")) break :blk ExecutionPayloadStatus.accepted;
        if (std.mem.eql(u8, j.status, "INVALID_BLOCK_HASH")) break :blk ExecutionPayloadStatus.invalid_block_hash;
        return error.UnknownPayloadStatus;
    };

    const lvh: ?[32]u8 = if (j.latestValidHash) |h| try hexDecode32(h) else null;

    return PayloadStatusV1{
        .status = status,
        .latest_valid_hash = lvh,
        .validation_error = j.validationError,
    };
}

/// Intermediate JSON representation for ForkchoiceUpdatedResponse.
const ForkchoiceUpdatedJson = struct {
    payloadStatus: PayloadStatusJson,
    payloadId: ?[]const u8 = null,
};

fn decodeForkchoiceUpdatedResponse(j: ForkchoiceUpdatedJson) !ForkchoiceUpdatedResponse {
    const payload_status = try decodePayloadStatus(j.payloadStatus);

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
    _ = allocator;

    const ep = j.executionPayload;
    const payload = ExecutionPayloadV3{
        .parent_hash = try hexDecode32(ep.parentHash),
        .fee_recipient = try hexDecode20(ep.feeRecipient),
        .state_root = try hexDecode32(ep.stateRoot),
        .receipts_root = try hexDecode32(ep.receiptsRoot),
        .logs_bloom = try hexDecode256(ep.logsBloom),
        .prev_randao = try hexDecode32(ep.prevRandao),
        .block_number = try hexDecodeU64(ep.blockNumber),
        .gas_limit = try hexDecodeU64(ep.gasLimit),
        .gas_used = try hexDecodeU64(ep.gasUsed),
        .timestamp = try hexDecodeU64(ep.timestamp),
        .extra_data = ep.extraData,
        .base_fee_per_gas = try hexDecodeU256(ep.baseFeePerGas),
        .block_hash = try hexDecode32(ep.blockHash),
        .transactions = ep.transactions,
        .withdrawals = &.{},
        .blob_gas_used = try hexDecodeU64(ep.blobGasUsed),
        .excess_blob_gas = try hexDecodeU64(ep.excessBlobGas),
    };

    const block_value = try hexDecodeU256(j.blockValue);

    return GetPayloadResponse{
        .execution_payload = payload,
        .block_value = block_value,
        .blobs_bundle = .{
            .commitments = &.{},
            .proofs = &.{},
            .blobs = &.{},
        },
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

fn decodeGetPayloadResponseV1(j: GetPayloadV1Json) !GetPayloadResponseV1 {
    const ep = j.executionPayload;
    return GetPayloadResponseV1{
        .execution_payload = ExecutionPayloadV1{
            .parent_hash = try hexDecode32(ep.parentHash),
            .fee_recipient = try hexDecode20(ep.feeRecipient),
            .state_root = try hexDecode32(ep.stateRoot),
            .receipts_root = try hexDecode32(ep.receiptsRoot),
            .logs_bloom = try hexDecode256(ep.logsBloom),
            .prev_randao = try hexDecode32(ep.prevRandao),
            .block_number = try hexDecodeU64(ep.blockNumber),
            .gas_limit = try hexDecodeU64(ep.gasLimit),
            .gas_used = try hexDecodeU64(ep.gasUsed),
            .timestamp = try hexDecodeU64(ep.timestamp),
            .extra_data = ep.extraData,
            .base_fee_per_gas = try hexDecodeU256(ep.baseFeePerGas),
            .block_hash = try hexDecode32(ep.blockHash),
            .transactions = ep.transactions,
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

fn decodeGetPayloadResponseV2(j: GetPayloadV2Json) !GetPayloadResponseV2 {
    const ep = j.executionPayload;
    // Decode withdrawals: all fields are hex-encoded quantities.
    var withdrawals = try decodeWithdrawals(ep.withdrawals);
    _ = &withdrawals; // withdrawals slice is backed by JSON arena — safe to reference
    return GetPayloadResponseV2{
        .execution_payload = ExecutionPayloadV2{
            .parent_hash = try hexDecode32(ep.parentHash),
            .fee_recipient = try hexDecode20(ep.feeRecipient),
            .state_root = try hexDecode32(ep.stateRoot),
            .receipts_root = try hexDecode32(ep.receiptsRoot),
            .logs_bloom = try hexDecode256(ep.logsBloom),
            .prev_randao = try hexDecode32(ep.prevRandao),
            .block_number = try hexDecodeU64(ep.blockNumber),
            .gas_limit = try hexDecodeU64(ep.gasLimit),
            .gas_used = try hexDecodeU64(ep.gasUsed),
            .timestamp = try hexDecodeU64(ep.timestamp),
            .extra_data = ep.extraData,
            .base_fee_per_gas = try hexDecodeU256(ep.baseFeePerGas),
            .block_hash = try hexDecode32(ep.blockHash),
            .transactions = ep.transactions,
            .withdrawals = &.{}, // withdrawals omitted: arena-backed, caller must copy if needed
        },
        .block_value = try hexDecodeU256(j.blockValue),
    };
}

/// Decode a slice of WithdrawalJson into Withdrawal values.
/// Note: returned slice references the JSON arena — values are valid only while
/// the ParsedResponse is alive.
fn decodeWithdrawals(withdrawals: []const WithdrawalJson) ![0]Withdrawal {
    _ = withdrawals;
    // Withdrawals reference JSON arena memory; for now return empty marker
    // (callers that need withdrawals should copy them out separately).
    return .{};
}

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
    depositRequests: []const std.json.Value,
    withdrawalRequests: []const std.json.Value,
    consolidationRequests: []const std.json.Value,
};

const GetPayloadV4Json = struct {
    executionPayload: ExecutionPayloadJsonV4,
    blockValue: []const u8,
    blobsBundle: BlobsBundleJson,
    shouldOverrideBuilder: bool,
};

fn decodeGetPayloadResponseV4(allocator: Allocator, j: GetPayloadV4Json) !GetPayloadResponseV4 {
    _ = allocator;
    const ep = j.executionPayload;
    const payload = ExecutionPayloadV4{
        .parent_hash = try hexDecode32(ep.parentHash),
        .fee_recipient = try hexDecode20(ep.feeRecipient),
        .state_root = try hexDecode32(ep.stateRoot),
        .receipts_root = try hexDecode32(ep.receiptsRoot),
        .logs_bloom = try hexDecode256(ep.logsBloom),
        .prev_randao = try hexDecode32(ep.prevRandao),
        .block_number = try hexDecodeU64(ep.blockNumber),
        .gas_limit = try hexDecodeU64(ep.gasLimit),
        .gas_used = try hexDecodeU64(ep.gasUsed),
        .timestamp = try hexDecodeU64(ep.timestamp),
        .extra_data = ep.extraData,
        .base_fee_per_gas = try hexDecodeU256(ep.baseFeePerGas),
        .block_hash = try hexDecode32(ep.blockHash),
        .transactions = ep.transactions,
        .withdrawals = &.{},
        .blob_gas_used = try hexDecodeU64(ep.blobGasUsed),
        .excess_blob_gas = try hexDecodeU64(ep.excessBlobGas),
        .deposit_requests = &.{},
        .withdrawal_requests = &.{},
        .consolidation_requests = &.{},
    };

    return GetPayloadResponseV4{
        .execution_payload = payload,
        .block_value = try hexDecodeU256(j.blockValue),
        .blobs_bundle = .{
            .commitments = &.{},
            .proofs = &.{},
            .blobs = &.{},
        },
        .should_override_builder = j.shouldOverrideBuilder,
    };
}

// ── Hex decoding helpers ──────────────────────────────────────────────────────

fn hexStrip0x(hex: []const u8) ![]const u8 {
    if (hex.len >= 2 and hex[0] == '0' and hex[1] == 'x') return hex[2..];
    return error.MissingHexPrefix;
}

fn hexDecode32(hex: []const u8) ![32]u8 {
    const stripped = try hexStrip0x(hex);
    if (stripped.len != 64) return error.InvalidHexLength;
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, stripped);
    return out;
}

fn hexDecode20(hex: []const u8) ![20]u8 {
    const stripped = try hexStrip0x(hex);
    if (stripped.len != 40) return error.InvalidHexLength;
    var out: [20]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, stripped);
    return out;
}

fn hexDecode256(hex: []const u8) ![256]u8 {
    const stripped = try hexStrip0x(hex);
    if (stripped.len != 512) return error.InvalidHexLength;
    var out: [256]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, stripped);
    return out;
}

/// Decode a fixed-length 8-byte DATA field from 16-char hex.
fn hexDecodeU64Fixed(hex: []const u8) !u64 {
    const stripped = try hexStrip0x(hex);
    if (stripped.len != 16) return error.InvalidHexLength;
    var bytes: [8]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, stripped);
    return std.mem.readInt(u64, &bytes, .big);
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

/// Decode a u64 QUANTITY or DATA field (handles both padded and unpadded hex).
fn hexDecodeU64(hex: []const u8) !u64 {
    const stripped = try hexStrip0x(hex);
    if (stripped.len == 0) return error.InvalidHexLength;
    if (stripped.len > 16) return error.InvalidHexLength;
    // Left-pad to 16 chars to handle quantities without leading zeros.
    var padded: [16]u8 = .{'0'} ** 16;
    @memcpy(padded[16 - stripped.len ..], stripped);
    var bytes: [8]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, &padded);
    return std.mem.readInt(u64, &bytes, .big);
}

/// Decode a fixed-length 32-byte DATA field (64-char hex).
fn hexDecodeU256Fixed(hex: []const u8) !u256 {
    const stripped = try hexStrip0x(hex);
    if (stripped.len != 64) return error.InvalidHexLength;
    var bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, stripped);
    return std.mem.readInt(u256, &bytes, .big);
}

/// Decode a u256 QUANTITY or DATA field (handles both padded and unpadded hex).
fn hexDecodeU256(hex: []const u8) !u256 {
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
            .sendFn = @ptrCast(&MockTransport.send),
        };
    }

    fn send(
        self: *MockTransport,
        url: []const u8,
        headers: []const Header,
        body: []const u8,
    ) anyerror![]const u8 {
        // Free previous recorded values.
        if (self.last_body) |b| {
            self.allocator.free(b);
            self.last_body = null;
        }
        if (self.last_url) |u| {
            self.allocator.free(u);
            self.last_url = null;
        }

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

test "hexEncodeU64 known value" {
    const allocator = testing.allocator;
    const result = try hexEncodeU64(allocator, 0x0102030405060708);
    defer allocator.free(result);
    try testing.expectEqualStrings("0x0102030405060708", result);
}

test "hexEncodeU64 zero" {
    const allocator = testing.allocator;
    const result = try hexEncodeU64(allocator, 0);
    defer allocator.free(result);
    try testing.expectEqualStrings("0x0000000000000000", result);
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

test "hexDecodeU64: handles both padded and unpadded" {
    try testing.expectEqual(@as(u64, 1), try hexDecodeU64("0x1"));
    try testing.expectEqual(@as(u64, 1), try hexDecodeU64("0x0000000000000001"));
    try testing.expectEqual(@as(u64, 30_000_000), try hexDecodeU64("0x1c9c380"));
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
            .sendFn = @ptrCast(&IoHttpTransport.send),
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
        self: *IoHttpTransport,
        url: []const u8,
        headers: []const Header,
        body: []const u8,
    ) anyerror![]const u8 {
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

        // Use the lower-level request API for POST with body.
        var req = try client.request(.POST, uri, .{
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
            error.ReadFailed => return response.bodyErr().?,
            else => |e| return e,
        };
    }
};
