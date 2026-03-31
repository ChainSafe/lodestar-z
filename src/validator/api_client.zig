//! Beacon API HTTP client for the Validator Client.
//!
//! Wraps HTTP calls to the Beacon Node REST API endpoints consumed by
//! validator clients (duties, block production, attestation, sync committee).
//!
//! TS equivalent: @lodestar/api ApiClient (packages/api/src/client/)
//!
//! Design (Zig 0.16):
//!   - Uses std.http.Client with std.Io for HTTP/1.1 requests.
//!   - GET requests use sendBodiless(); POST uses transfer_encoding + sendBodyComplete().
//!   - SSE stream for events uses a chunked reader over a persistent TCP connection.
//!   - JSON parsing uses std.json.parseFromSlice with ArenaAllocator.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const types = @import("types.zig");
const ProposerDuty = types.ProposerDuty;
const AttesterDuty = types.AttesterDuty;
const SyncCommitteeDuty = types.SyncCommitteeDuty;
const time = @import("time.zig");

const log = std.log.scoped(.vc_api);

/// Maximum response body size: 16 MiB.
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
/// SSE line buffer size.
const SSE_LINE_BUF = 4096;

// ---------------------------------------------------------------------------
// SSE event (raw)
// ---------------------------------------------------------------------------

/// A single Server-Sent Event received from the BN.
pub const SseEvent = struct {
    /// Event type string (e.g., "head", "block", "finalized_checkpoint").
    event_type: []const u8,
    /// Raw JSON data payload.
    data: []const u8,
};

/// Callback type for SSE events.
pub const SseCallback = struct {
    ctx: *anyopaque,
    fn_ptr: *const fn (ctx: *anyopaque, event: SseEvent) void,

    pub fn call(self: SseCallback, event: SseEvent) void {
        self.fn_ptr(self.ctx, event);
    }
};

// ---------------------------------------------------------------------------
// BeaconApiClient
// ---------------------------------------------------------------------------

/// Maximum consecutive failures before logging "beacon node unreachable".
const BN_UNREACHABLE_THRESHOLD: u64 = 3;

/// HTTP client for the Beacon Node REST API (validator-facing endpoints).
///
/// Supports multiple beacon node URLs with primary-with-fallback strategy.
/// Tracks consecutive failures and logs when BN becomes unreachable/reconnects.
pub const BeaconApiClient = struct {
    allocator: Allocator,
    /// Primary beacon node URL (first in urls list, or beacon_node_url).
    base_url: []const u8,
    /// Additional fallback beacon node URLs (may be empty).
    /// Tried in order when the primary fails.
    fallback_urls: []const []const u8,
    /// Index of the currently active URL (0 = primary).
    active_url_idx: usize,
    /// Consecutive HTTP/transport failures on the current URL.
    consecutive_failures: u64,
    /// Whether the BN was considered unreachable at the last check.
    was_unreachable: bool,
    /// Monotonic ns timestamp when BN first became unreachable.
    unreachable_since_ns: u64,

    pub fn init(allocator: Allocator, base_url: []const u8) BeaconApiClient {
        return .{
            .allocator = allocator,
            .base_url = base_url,
            .fallback_urls = &.{},
            .active_url_idx = 0,
            .consecutive_failures = 0,
            .was_unreachable = false,
            .unreachable_since_ns = 0,
        };
    }

    /// Create a client with multiple beacon node URLs (fallback support).
    ///
    /// `urls` must have at least one entry. The first is the primary.
    /// TS: BeaconNodeOpts.urls (array of BN endpoints)
    pub fn initMulti(allocator: Allocator, urls: []const []const u8) BeaconApiClient {
        if (urls.len == 0) @panic("BeaconApiClient.initMulti: urls must not be empty");
        return .{
            .allocator = allocator,
            .base_url = urls[0],
            .fallback_urls = urls[1..],
            .active_url_idx = 0,
            .consecutive_failures = 0,
            .was_unreachable = false,
            .unreachable_since_ns = 0,
        };
    }

    pub fn deinit(self: *BeaconApiClient) void {
        _ = self;
    }

    /// Return the currently active beacon node URL.
    fn activeUrl(self: *const BeaconApiClient) []const u8 {
        if (self.active_url_idx == 0) return self.base_url;
        const idx = self.active_url_idx - 1;
        if (idx < self.fallback_urls.len) return self.fallback_urls[idx];
        return self.base_url;
    }

    /// Record a transport/HTTP failure. Rotates to next BN URL after threshold.
    fn recordFailure(self: *BeaconApiClient) void {
        self.consecutive_failures += 1;
        const total_urls = 1 + self.fallback_urls.len;
        if (self.consecutive_failures >= BN_UNREACHABLE_THRESHOLD) {
            if (!self.was_unreachable) {
                self.was_unreachable = true;
                self.unreachable_since_ns = time.realtimeNs();
                log.warn("beacon node unreachable url={s} (consecutive_failures={d})", .{
                    self.activeUrl(), self.consecutive_failures,
                });
            } else {
                const now_ns = time.realtimeNs();
                const secs = (now_ns -| self.unreachable_since_ns) / std.time.ns_per_s;
                log.warn("beacon node unreachable for {d}s url={s}", .{ secs, self.activeUrl() });
            }
            // Rotate to next URL.
            if (total_urls > 1) {
                self.active_url_idx = (self.active_url_idx + 1) % total_urls;
                self.consecutive_failures = 0;
                log.info("rotating to beacon node url={s}", .{self.activeUrl()});
            }
        }
    }

    /// Record a successful HTTP call. Clears failure state.
    fn recordSuccess(self: *BeaconApiClient) void {
        if (self.was_unreachable) {
            log.info("beacon node reconnected url={s}", .{self.activeUrl()});
            self.was_unreachable = false;
            self.unreachable_since_ns = 0;
        }
        self.consecutive_failures = 0;
    }

    // -----------------------------------------------------------------------
    // Internal HTTP helpers
    // -----------------------------------------------------------------------

    /// Perform a GET request and return the response body (caller frees).
    ///
    /// COH-4: A new std.http.Client is created per request instead of reusing a
    /// persistent connection. This avoids connection-state bugs in the current Zig 0.14
    /// std.http.Client (no idle-connection pool, and keep_alive requires manual drain).
    /// TODO: Add an `http_client: std.http.Client` field to BeaconApiClient and reuse
    ///       it once std.http.Client supports connection pooling with Zig 0.16 evented I/O.
    fn get(self: *BeaconApiClient, io: Io, path: []const u8) ![]const u8 {
        const url = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ self.activeUrl(), path });
        defer self.allocator.free(url);

        var client: std.http.Client = .{ .allocator = self.allocator, .io = io };
        defer client.deinit();

        const uri = try std.Uri.parse(url);
        var req = client.request(.GET, uri, .{
            .keep_alive = false,
            .extra_headers = &.{
                .{ .name = "Accept", .value = "application/json" },
            },
        }) catch |err| {
            self.recordFailure();
            return err;
        };
        defer req.deinit();

        req.sendBodiless() catch |err| {
            self.recordFailure();
            return err;
        };

        var redirect_buf: [1024]u8 = undefined;
        var response = req.receiveHead(&redirect_buf) catch |err| {
            self.recordFailure();
            return err;
        };

        if (response.head.status != .ok) {
            log.warn("GET {s} → HTTP {d}", .{ path, @intFromEnum(response.head.status) });
            self.recordFailure();
            return error.HttpError;
        }

        self.recordSuccess();
        var transfer_buf: [8192]u8 = undefined;
        const reader = response.reader(&transfer_buf);
        return reader.allocRemaining(self.allocator, Io.Limit.limited(MAX_RESPONSE_BYTES)) catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr().?,
            else => |e| return e,
        };
    }

    /// Perform a GET request with Accept: application/octet-stream.
    /// Returns the raw SSZ bytes and parsed response headers.
    /// Caller must free the returned SszGetResponse.body.
    fn getSsz(self: *BeaconApiClient, io: Io, path: []const u8) !SszGetResponse {
        const url = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ self.activeUrl(), path });
        defer self.allocator.free(url);

        var client: std.http.Client = .{ .allocator = self.allocator, .io = io };
        defer client.deinit();

        const uri = try std.Uri.parse(url);
        var req = client.request(.GET, uri, .{
            .keep_alive = false,
            .extra_headers = &.{
                .{ .name = "Accept", .value = "application/octet-stream" },
            },
        }) catch |err| {
            self.recordFailure();
            return err;
        };
        defer req.deinit();

        req.sendBodiless() catch |err| {
            self.recordFailure();
            return err;
        };

        var redirect_buf: [1024]u8 = undefined;
        var response = req.receiveHead(&redirect_buf) catch |err| {
            self.recordFailure();
            return err;
        };

        if (response.head.status != .ok) {
            log.warn("GET(ssz) {s} → HTTP {d}", .{ path, @intFromEnum(response.head.status) });
            self.recordFailure();
            return error.HttpError;
        }

        self.recordSuccess();

        // Extract Eth-Consensus-Version header before reading body
        // (response.reader() invalidates head string pointers).
        var fork_name_buf: [32]u8 = [_]u8{0} ** 32;
        var fork_name_len: u8 = 0;
        var is_blinded = false;
        {
            var it = response.head.iterateHeaders();
            while (it.next()) |hdr| {
                if (std.ascii.eqlIgnoreCase(hdr.name, "Eth-Consensus-Version")) {
                    const len: u8 = @intCast(@min(hdr.value.len, fork_name_buf.len));
                    @memcpy(fork_name_buf[0..len], hdr.value[0..len]);
                    fork_name_len = len;
                } else if (std.ascii.eqlIgnoreCase(hdr.name, "Eth-Execution-Payload-Blinded")) {
                    is_blinded = std.mem.eql(u8, hdr.value, "true");
                }
            }
        }

        var transfer_buf: [8192]u8 = undefined;
        const reader = response.reader(&transfer_buf);
        const ssz_body = reader.allocRemaining(self.allocator, Io.Limit.limited(MAX_RESPONSE_BYTES)) catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr().?,
            else => |e| return e,
        };

        return .{
            .body = ssz_body,
            .fork_name = fork_name_buf,
            .fork_name_len = fork_name_len,
            .is_blinded = is_blinded,
        };
    }

    const SszGetResponse = struct {
        body: []const u8,
        fork_name: [32]u8,
        fork_name_len: u8,
        is_blinded: bool,
    };

    /// Perform a POST request with JSON body and return the response body (caller frees).
    ///
    /// Pass an empty body (`""`) for POST endpoints that don't require a body.
    ///
    /// COH-4: See get() — per-request clients are intentional for now; same TODO applies.
    fn post(self: *BeaconApiClient, io: Io, path: []const u8, body: []const u8) ![]const u8 {
        const url = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ self.activeUrl(), path });
        defer self.allocator.free(url);

        var client: std.http.Client = .{ .allocator = self.allocator, .io = io };
        defer client.deinit();

        const uri = try std.Uri.parse(url);
        var req = client.request(.POST, uri, .{
            .keep_alive = false,
            .extra_headers = &.{
                .{ .name = "Accept", .value = "application/json" },
            },
            .headers = .{
                .content_type = .{ .override = "application/json" },
            },
        }) catch |err| {
            self.recordFailure();
            return err;
        };
        defer req.deinit();

        req.transfer_encoding = .{ .content_length = body.len };
        req.sendBodyComplete(@constCast(body)) catch |err| {
            self.recordFailure();
            return err;
        };

        var redirect_buf: [1024]u8 = undefined;
        var response = req.receiveHead(&redirect_buf) catch |err| {
            self.recordFailure();
            return err;
        };

        const status = response.head.status;
        // 2xx codes are all success; 204 has no body.
        if (@intFromEnum(status) < 200 or @intFromEnum(status) >= 300) {
            log.warn("POST {s} → HTTP {d}", .{ path, @intFromEnum(status) });
            self.recordFailure();
            return error.HttpError;
        }

        self.recordSuccess();
        if (status == .no_content) {
            // 204 No Content — return empty slice.
            return try self.allocator.dupe(u8, "");
        }

        var transfer_buf: [8192]u8 = undefined;
        const reader = response.reader(&transfer_buf);
        return reader.allocRemaining(self.allocator, Io.Limit.limited(MAX_RESPONSE_BYTES)) catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr().?,
            else => |e| return e,
        };
    }

    /// Perform a POST with no response body required (fire-and-forget).
    fn postNoResponse(self: *BeaconApiClient, io: Io, path: []const u8, body: []const u8) !void {
        const resp = try self.post(io, path, body);
        self.allocator.free(resp);
    }

    /// Perform a POST request with SSZ body (Content-Type: application/octet-stream).
    /// The Eth-Consensus-Version header is included for fork context.
    /// Returns void on success; errors on non-2xx status.
    fn postSsz(self: *BeaconApiClient, io: Io, path: []const u8, body: []const u8, fork_name: []const u8) !void {
        const url = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ self.activeUrl(), path });
        defer self.allocator.free(url);

        var client: std.http.Client = .{ .allocator = self.allocator, .io = io };
        defer client.deinit();

        const uri = try std.Uri.parse(url);
        var req = client.request(.POST, uri, .{
            .keep_alive = false,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/octet-stream" },
                .{ .name = "Eth-Consensus-Version", .value = fork_name },
            },
        }) catch |err| {
            self.recordFailure();
            return err;
        };
        defer req.deinit();

        req.transfer_encoding = .{ .content_length = body.len };
        req.sendBodyComplete(@constCast(body)) catch |err| {
            self.recordFailure();
            return err;
        };

        var redirect_buf: [1024]u8 = undefined;
        const response = req.receiveHead(&redirect_buf) catch |err| {
            self.recordFailure();
            return err;
        };

        const status = response.head.status;
        if (@intFromEnum(status) < 200 or @intFromEnum(status) >= 300) {
            log.warn("POST(ssz) {s} → HTTP {d}", .{ path, @intFromEnum(status) });
            self.recordFailure();
            return error.HttpError;
        }

        self.recordSuccess();
    }

    // -----------------------------------------------------------------------
    // Genesis
    // -----------------------------------------------------------------------

    /// GET /eth/v1/beacon/genesis
    pub fn getGenesis(self: *BeaconApiClient, io: Io) !GenesisResponse {
        const body = try self.get(io, "/eth/v1/beacon/genesis");
        defer self.allocator.free(body);

        const Parsed = struct {
            data: struct {
                genesis_time: []const u8,
                genesis_validators_root: []const u8,
                genesis_fork_version: []const u8,
            },
        };

        var parsed = try std.json.parseFromSlice(Parsed, self.allocator, body, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        const d = parsed.value.data;
        const genesis_time = try std.fmt.parseInt(u64, d.genesis_time, 10);

        var genesis_validators_root: [32]u8 = [_]u8{0} ** 32;
        const gvr_hex = if (std.mem.startsWith(u8, d.genesis_validators_root, "0x")) d.genesis_validators_root[2..] else d.genesis_validators_root;
        _ = std.fmt.hexToBytes(&genesis_validators_root, gvr_hex) catch {};

        var genesis_fork_version: [4]u8 = [_]u8{0} ** 4;
        const gfv_hex = if (std.mem.startsWith(u8, d.genesis_fork_version, "0x")) d.genesis_fork_version[2..] else d.genesis_fork_version;
        _ = std.fmt.hexToBytes(&genesis_fork_version, gfv_hex) catch {};

        return .{
            .genesis_time = genesis_time,
            .genesis_validators_root = genesis_validators_root,
            .genesis_fork_version = genesis_fork_version,
        };
    }

    // -----------------------------------------------------------------------
    // Duties
    // -----------------------------------------------------------------------

    /// GET /eth/v1/validator/duties/proposer/{epoch}
    pub fn getProposerDuties(
        self: *BeaconApiClient,
        io: Io,
        epoch: u64,
    ) ![]ProposerDuty {
        const path = try std.fmt.allocPrint(self.allocator, "/eth/v1/validator/duties/proposer/{d}", .{epoch});
        defer self.allocator.free(path);

        const body = try self.get(io, path);
        defer self.allocator.free(body);

        const ProposerDutyJson = struct {
            pubkey: []const u8,
            validator_index: []const u8,
            slot: []const u8,
        };
        const Parsed = struct {
            data: []const ProposerDutyJson,
        };

        var parsed = try std.json.parseFromSlice(Parsed, self.allocator, body, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        const duties = try self.allocator.alloc(ProposerDuty, parsed.value.data.len);
        for (parsed.value.data, duties) |src, *dst| {
            dst.validator_index = try std.fmt.parseInt(u64, src.validator_index, 10);
            dst.slot = try std.fmt.parseInt(u64, src.slot, 10);
            const pk_hex = if (std.mem.startsWith(u8, src.pubkey, "0x")) src.pubkey[2..] else src.pubkey;
            _ = std.fmt.hexToBytes(&dst.pubkey, pk_hex) catch {};
        }
        return duties;
    }

    /// POST /eth/v1/validator/duties/attester/{epoch}
    pub fn getAttesterDuties(
        self: *BeaconApiClient,
        io: Io,
        epoch: u64,
        indices: []const u64,
    ) ![]AttesterDuty {
        const path = try std.fmt.allocPrint(self.allocator, "/eth/v1/validator/duties/attester/{d}", .{epoch});
        defer self.allocator.free(path);

        // Serialize indices as JSON array of strings: ["0","1",...]
        var body_buf: std.Io.Writer.Allocating = .init(self.allocator);
        defer body_buf.deinit();
        try body_buf.writer.writeByte('[');
        for (indices, 0..) |idx, i| {
            if (i > 0) try body_buf.writer.writeByte(',');
            try body_buf.writer.print("\"{d}\"", .{idx});
        }
        try body_buf.writer.writeByte(']');

        const resp = try self.post(io, path, body_buf.written());
        defer self.allocator.free(resp);

        const AttesterDutyJson = struct {
            pubkey: []const u8,
            validator_index: []const u8,
            committee_index: []const u8,
            committee_length: []const u8,
            committees_at_slot: []const u8,
            validator_committee_index: []const u8,
            slot: []const u8,
        };
        const Parsed = struct {
            data: []const AttesterDutyJson,
        };

        var parsed = try std.json.parseFromSlice(Parsed, self.allocator, resp, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        const duties = try self.allocator.alloc(AttesterDuty, parsed.value.data.len);
        for (parsed.value.data, duties) |src, *dst| {
            dst.validator_index = try std.fmt.parseInt(u64, src.validator_index, 10);
            dst.committee_index = try std.fmt.parseInt(u64, src.committee_index, 10);
            dst.committee_length = try std.fmt.parseInt(u64, src.committee_length, 10);
            dst.committees_at_slot = try std.fmt.parseInt(u64, src.committees_at_slot, 10);
            dst.validator_committee_index = try std.fmt.parseInt(u64, src.validator_committee_index, 10);
            dst.slot = try std.fmt.parseInt(u64, src.slot, 10);
            const pk_hex = if (std.mem.startsWith(u8, src.pubkey, "0x")) src.pubkey[2..] else src.pubkey;
            _ = std.fmt.hexToBytes(&dst.pubkey, pk_hex) catch {};
        }
        return duties;
    }

    /// POST /eth/v1/validator/duties/sync/{epoch}
    pub fn getSyncCommitteeDuties(
        self: *BeaconApiClient,
        io: Io,
        epoch: u64,
        indices: []const u64,
    ) ![]SyncCommitteeDuty {
        const path = try std.fmt.allocPrint(self.allocator, "/eth/v1/validator/duties/sync/{d}", .{epoch});
        defer self.allocator.free(path);

        var body_buf: std.Io.Writer.Allocating = .init(self.allocator);
        defer body_buf.deinit();
        try body_buf.writer.writeByte('[');
        for (indices, 0..) |idx, i| {
            if (i > 0) try body_buf.writer.writeByte(',');
            try body_buf.writer.print("\"{d}\"", .{idx});
        }
        try body_buf.writer.writeByte(']');

        const resp = try self.post(io, path, body_buf.written());
        defer self.allocator.free(resp);

        const SyncDutyJson = struct {
            pubkey: []const u8,
            validator_index: []const u8,
            validator_sync_committee_indices: []const []const u8,
        };
        const Parsed = struct {
            data: []const SyncDutyJson,
        };

        var parsed = try std.json.parseFromSlice(Parsed, self.allocator, resp, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        const duties = try self.allocator.alloc(SyncCommitteeDuty, parsed.value.data.len);
        errdefer self.allocator.free(duties);

        for (parsed.value.data, duties) |src, *dst| {
            dst.validator_index = try std.fmt.parseInt(u64, src.validator_index, 10);
            const pk_hex = if (std.mem.startsWith(u8, src.pubkey, "0x")) src.pubkey[2..] else src.pubkey;
            _ = std.fmt.hexToBytes(&dst.pubkey, pk_hex) catch {};

            const sc_indices = try self.allocator.alloc(u64, src.validator_sync_committee_indices.len);
            for (src.validator_sync_committee_indices, sc_indices) |str, *out_idx| {
                out_idx.* = try std.fmt.parseInt(u64, str, 10);
            }
            dst.validator_sync_committee_indices = sc_indices;
        }
        return duties;
    }

    // -----------------------------------------------------------------------
    // Validator indices
    // -----------------------------------------------------------------------

    /// POST /eth/v1/beacon/states/head/validators
    pub fn getValidatorIndices(
        self: *BeaconApiClient,
        io: Io,
        pubkeys: []const [48]u8,
    ) ![]ValidatorIndexAndStatus {
        // Build JSON array of hex pubkeys.
        var body_buf: std.Io.Writer.Allocating = .init(self.allocator);
        defer body_buf.deinit();
        try body_buf.writer.writeByte('[');
        for (pubkeys, 0..) |pk, i| {
            if (i > 0) try body_buf.writer.writeByte(',');
            try body_buf.writer.print("\"0x{x}\"", .{pk});
        }
        try body_buf.writer.writeByte(']');

        const resp = try self.post(io, "/eth/v1/beacon/states/head/validators", body_buf.written());
        defer self.allocator.free(resp);

        const ValidatorJson = struct {
            index: []const u8,
            validator: struct {
                pubkey: []const u8,
            },
            status: []const u8,
        };
        const Parsed = struct {
            data: []const ValidatorJson,
        };

        var parsed = try std.json.parseFromSlice(Parsed, self.allocator, resp, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        const result = try self.allocator.alloc(ValidatorIndexAndStatus, parsed.value.data.len);
        for (parsed.value.data, result) |src, *dst| {
            dst.index = try std.fmt.parseInt(u64, src.index, 10);
            const pk_hex = if (std.mem.startsWith(u8, src.validator.pubkey, "0x")) src.validator.pubkey[2..] else src.validator.pubkey;
            _ = std.fmt.hexToBytes(&dst.pubkey, pk_hex) catch {};
            // COH-3 Fix: copy status string into owned fixed-size buffer
            // to avoid dangling pointer into the freed JSON arena.
            {
                const s = src.status;
                const copy_len: u8 = @intCast(@min(s.len, dst.status.len));
                @memcpy(dst.status[0..copy_len], s[0..copy_len]);
                dst.status_len = copy_len;
            }
        }
        return result;
    }

    // -----------------------------------------------------------------------
    // Block production
    // -----------------------------------------------------------------------

    /// GET /eth/v3/validator/blocks/{slot}?randao_reveal=...&graffiti=...
    pub fn produceBlock(
        self: *BeaconApiClient,
        io: Io,
        slot: u64,
        randao_reveal: [96]u8,
        graffiti: [32]u8,
    ) !ProduceBlockResponse {
        const randao_hex = std.fmt.bytesToHex(&randao_reveal, .lower);
        const graffiti_hex = std.fmt.bytesToHex(&graffiti, .lower);
        const path = try std.fmt.allocPrint(
            self.allocator,
            "/eth/v3/validator/blocks/{d}?randao_reveal=0x{s}&graffiti=0x{s}",
            .{ slot, randao_hex, graffiti_hex },
        );
        defer self.allocator.free(path);

        const body = try self.get(io, path);
        // Return the raw JSON body — callers parse what they need.
        return .{ .block_ssz = body, .blinded = false };
    }

    /// POST /eth/v2/beacon/blocks
    pub fn publishBlock(
        self: *BeaconApiClient,
        io: Io,
        signed_block_ssz: []const u8,
    ) !void {
        try self.postNoResponse(io, "/eth/v2/beacon/blocks", signed_block_ssz);
    }

    /// GET /eth/v3/validator/blocks/{slot} with SSZ response.
    ///
    /// Requests the unsigned BeaconBlock as SSZ (Accept: application/octet-stream).
    /// The fork is determined from the Eth-Consensus-Version response header.
    /// Returns raw SSZ bytes of the unsigned BeaconBlock + fork metadata.
    pub fn produceBlockSsz(
        self: *BeaconApiClient,
        io: Io,
        slot: u64,
        randao_reveal: [96]u8,
        graffiti: [32]u8,
    ) !ProduceBlockSszResponse {
        const randao_hex = std.fmt.bytesToHex(&randao_reveal, .lower);
        const graffiti_hex = std.fmt.bytesToHex(&graffiti, .lower);
        const path = try std.fmt.allocPrint(
            self.allocator,
            "/eth/v3/validator/blocks/{d}?randao_reveal=0x{s}&graffiti=0x{s}",
            .{ slot, randao_hex, graffiti_hex },
        );
        defer self.allocator.free(path);

        const resp = try self.getSsz(io, path);
        return .{
            .block_ssz = resp.body,
            .fork_name = resp.fork_name,
            .fork_name_len = resp.fork_name_len,
            .blinded = resp.is_blinded,
        };
    }

    /// POST /eth/v2/beacon/blocks with SSZ body.
    ///
    /// Publishes a SignedBeaconBlock as SSZ (Content-Type: application/octet-stream).
    /// The Eth-Consensus-Version header is set to the fork name.
    pub fn publishBlockSsz(
        self: *BeaconApiClient,
        io: Io,
        signed_block_ssz: []const u8,
        fork_name: []const u8,
    ) !void {
        try self.postSsz(io, "/eth/v2/beacon/blocks", signed_block_ssz, fork_name);
    }

    // -----------------------------------------------------------------------
    // Attestation
    // -----------------------------------------------------------------------

    /// GET /eth/v1/validator/attestation_data?slot=...&committee_index=...
    pub fn produceAttestationData(
        self: *BeaconApiClient,
        io: Io,
        slot: u64,
        committee_index: u64,
    ) !AttestationDataResponse {
        const path = try std.fmt.allocPrint(
            self.allocator,
            "/eth/v1/validator/attestation_data?slot={d}&committee_index={d}",
            .{ slot, committee_index },
        );
        defer self.allocator.free(path);

        const body = try self.get(io, path);
        defer self.allocator.free(body);

        const AttDataJson = struct {
            slot: []const u8,
            index: []const u8,
            beacon_block_root: []const u8,
            source: struct { epoch: []const u8, root: []const u8 },
            target: struct { epoch: []const u8, root: []const u8 },
        };
        const Parsed = struct {
            data: AttDataJson,
        };

        var parsed = try std.json.parseFromSlice(Parsed, self.allocator, body, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        const d = parsed.value.data;

        var beacon_block_root: [32]u8 = [_]u8{0} ** 32;
        var source_root: [32]u8 = [_]u8{0} ** 32;
        var target_root: [32]u8 = [_]u8{0} ** 32;

        const bbr_hex = if (std.mem.startsWith(u8, d.beacon_block_root, "0x")) d.beacon_block_root[2..] else d.beacon_block_root;
        _ = std.fmt.hexToBytes(&beacon_block_root, bbr_hex) catch {};
        const sr_hex = if (std.mem.startsWith(u8, d.source.root, "0x")) d.source.root[2..] else d.source.root;
        _ = std.fmt.hexToBytes(&source_root, sr_hex) catch {};
        const tr_hex = if (std.mem.startsWith(u8, d.target.root, "0x")) d.target.root[2..] else d.target.root;
        _ = std.fmt.hexToBytes(&target_root, tr_hex) catch {};

        return .{
            .slot = try std.fmt.parseInt(u64, d.slot, 10),
            .index = try std.fmt.parseInt(u64, d.index, 10),
            .beacon_block_root = beacon_block_root,
            .source_epoch = try std.fmt.parseInt(u64, d.source.epoch, 10),
            .source_root = source_root,
            .target_epoch = try std.fmt.parseInt(u64, d.target.epoch, 10),
            .target_root = target_root,
        };
    }

    /// POST /eth/v2/beacon/pool/attestations
    pub fn publishAttestations(
        self: *BeaconApiClient,
        io: Io,
        attestations_json: []const u8,
    ) !void {
        try self.postNoResponse(io, "/eth/v2/beacon/pool/attestations", attestations_json);
    }

    /// POST /eth/v1/beacon/pool/voluntary_exits
    pub fn publishVoluntaryExit(
        self: *BeaconApiClient,
        io: Io,
        signed_exit_json: []const u8,
    ) !void {
        try self.postNoResponse(io, "/eth/v1/beacon/pool/voluntary_exits", signed_exit_json);
    }

    /// GET /eth/v1/validator/aggregate_attestation?slot=...&attestation_data_root=...
    pub fn getAggregatedAttestation(
        self: *BeaconApiClient,
        io: Io,
        slot: u64,
        attestation_data_root: [32]u8,
    ) !AggregatedAttestationResponse {
        const root_hex = std.fmt.bytesToHex(&attestation_data_root, .lower);
        const path = try std.fmt.allocPrint(
            self.allocator,
            "/eth/v1/validator/aggregate_attestation?slot={d}&attestation_data_root=0x{s}",
            .{ slot, root_hex },
        );
        defer self.allocator.free(path);

        const body = try self.get(io, path);
        return .{ .attestation_json = body };
    }

    /// POST /eth/v2/validator/aggregate_and_proofs
    pub fn publishAggregateAndProofs(
        self: *BeaconApiClient,
        io: Io,
        proofs_json: []const u8,
    ) !void {
        try self.postNoResponse(io, "/eth/v2/validator/aggregate_and_proofs", proofs_json);
    }

    // -----------------------------------------------------------------------
    // Sync committee
    // -----------------------------------------------------------------------

    /// POST /eth/v1/beacon/pool/sync_committees
    pub fn publishSyncCommitteeMessages(
        self: *BeaconApiClient,
        io: Io,
        messages_json: []const u8,
    ) !void {
        try self.postNoResponse(io, "/eth/v1/beacon/pool/sync_committees", messages_json);
    }

    /// POST /eth/v1/validator/contribution_and_proofs
    pub fn publishContributionAndProofs(
        self: *BeaconApiClient,
        io: Io,
        contributions_json: []const u8,
    ) !void {
        try self.postNoResponse(io, "/eth/v1/validator/contribution_and_proofs", contributions_json);
    }

    /// GET /eth/v1/validator/sync_committee_contribution?slot=...&subcommittee_index=...&beacon_block_root=...
    pub fn produceSyncCommitteeContribution(
        self: *BeaconApiClient,
        io: Io,
        slot: u64,
        subcommittee_index: u64,
        beacon_block_root: [32]u8,
    ) !SyncCommitteeContributionResponse {
        const root_hex = std.fmt.bytesToHex(&beacon_block_root, .lower);
        const path = try std.fmt.allocPrint(
            self.allocator,
            "/eth/v1/validator/sync_committee_contribution?slot={d}&subcommittee_index={d}&beacon_block_root=0x{s}",
            .{ slot, subcommittee_index, root_hex },
        );
        defer self.allocator.free(path);

        const body = try self.get(io, path);
        defer self.allocator.free(body);

        const ContribJson = struct {
            slot: []const u8,
            beacon_block_root: []const u8,
            subcommittee_index: []const u8,
            aggregation_bits: []const u8,
            signature: []const u8,
        };
        const Parsed = struct {
            data: ContribJson,
        };

        var parsed = try std.json.parseFromSlice(Parsed, self.allocator, body, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        const d = parsed.value.data;

        var block_root: [32]u8 = [_]u8{0} ** 32;
        const br_hex = if (std.mem.startsWith(u8, d.beacon_block_root, "0x")) d.beacon_block_root[2..] else d.beacon_block_root;
        _ = std.fmt.hexToBytes(&block_root, br_hex) catch {};

        var sig: [96]u8 = [_]u8{0} ** 96;
        const sig_hex = if (std.mem.startsWith(u8, d.signature, "0x")) d.signature[2..] else d.signature;
        _ = std.fmt.hexToBytes(&sig, sig_hex) catch {};

        // aggregation_bits is returned as hex in the API.
        const agg_hex = if (std.mem.startsWith(u8, d.aggregation_bits, "0x")) d.aggregation_bits[2..] else d.aggregation_bits;
        const agg_bits = try self.allocator.alloc(u8, agg_hex.len / 2);
        _ = std.fmt.hexToBytes(agg_bits, agg_hex) catch {};

        return .{
            .slot = try std.fmt.parseInt(u64, d.slot, 10),
            .beacon_block_root = block_root,
            .subcommittee_index = try std.fmt.parseInt(u64, d.subcommittee_index, 10),
            .aggregation_bits = agg_bits,
            .signature = sig,
        };
    }

    // -----------------------------------------------------------------------
    // Proposer preparation
    // -----------------------------------------------------------------------

    /// POST /eth/v1/validator/prepare_beacon_proposer
    pub fn prepareBeaconProposer(
        self: *BeaconApiClient,
        io: Io,
        registrations_json: []const u8,
    ) !void {
        try self.postNoResponse(io, "/eth/v1/validator/prepare_beacon_proposer", registrations_json);
    }

    // -----------------------------------------------------------------------
    // Builder API (forwarded through BN)
    // -----------------------------------------------------------------------

    /// POST /eth/v1/validator/register_validator
    ///
    /// Sends signed validator registrations to the BN, which forwards them
    /// to the configured MEV-boost relay.
    pub fn registerValidators(
        self: *BeaconApiClient,
        io: Io,
        registrations_json: []const u8,
    ) !void {
        try self.postNoResponse(io, "/eth/v1/validator/register_validator", registrations_json);
    }

    /// POST /eth/v2/beacon/blinded_blocks with SSZ body.
    ///
    /// Publishes a SignedBlindedBeaconBlock as SSZ.
    /// The builder relay will unblind the block and broadcast it.
    pub fn publishBlindedBlockSsz(
        self: *BeaconApiClient,
        io: Io,
        signed_block_ssz: []const u8,
        fork_name: []const u8,
    ) !void {
        try self.postSsz(io, "/eth/v2/beacon/blinded_blocks", signed_block_ssz, fork_name);
    }

    // -----------------------------------------------------------------------
    // SSE event stream
    // -----------------------------------------------------------------------

    /// GET /eth/v1/events?topics=head,block,...
    ///
    /// Subscribes to beacon node SSE events and calls `callback` for each.
    /// Runs until stream ends or error.
    ///
    /// SSE format (per https://html.spec.whatwg.org/multipage/server-sent-events.html):
    ///   event: head\n
    ///   data: {...}\n
    ///   \n
    pub fn subscribeToEvents(
        self: *BeaconApiClient,
        io: Io,
        topics: []const []const u8,
        callback: SseCallback,
    ) !void {
        // Build topics query string.
        var topics_buf = std.array_list.Managed(u8).init(self.allocator);
        defer topics_buf.deinit();
        for (topics, 0..) |topic, i| {
            if (i > 0) try topics_buf.append(',');
            try topics_buf.appendSlice(topic);
        }

        const path = try std.fmt.allocPrint(
            self.allocator,
            "/eth/v1/events?topics={s}",
            .{topics_buf.items},
        );
        defer self.allocator.free(path);

        const url = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ self.base_url, path });
        defer self.allocator.free(url);

        log.info("subscribing to SSE events: {s}", .{topics_buf.items});

        var client: std.http.Client = .{ .allocator = self.allocator, .io = io };
        defer client.deinit();

        const uri = try std.Uri.parse(url);
        var req = try client.request(.GET, uri, .{
            .keep_alive = true,
            .extra_headers = &.{
                .{ .name = "Accept", .value = "text/event-stream" },
                .{ .name = "Cache-Control", .value = "no-cache" },
            },
        });
        defer req.deinit();

        try req.sendBodiless();

        var redirect_buf: [1024]u8 = undefined;
        var response = try req.receiveHead(&redirect_buf);

        if (response.head.status != .ok) {
            log.err("SSE subscription failed: HTTP {d}", .{@intFromEnum(response.head.status)});
            return error.HttpError;
        }

        // Parse SSE stream line by line.
        var event_type_buf: [128]u8 = undefined;
        var event_type: []const u8 = "";
        var data_buf: [SSE_LINE_BUF]u8 = undefined;
        var data_len: usize = 0;

        var transfer_buf: [SSE_LINE_BUF]u8 = undefined;
        const reader = response.reader(&transfer_buf);

        while (true) {
            // Read one line at a time.
            const line = reader.*.takeDelimiterExclusive('\n') catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };

            // Strip trailing \r if present.
            const trimmed = if (line.len > 0 and line[line.len - 1] == '\r') line[0 .. line.len - 1] else line;

            if (trimmed.len == 0) {
                // Empty line = dispatch event (if we have data).
                if (data_len > 0 and event_type.len > 0) {
                    callback.call(.{
                        .event_type = event_type,
                        .data = data_buf[0..data_len],
                    });
                }
                // Reset for next event.
                event_type = "";
                data_len = 0;
                continue;
            }

            if (std.mem.startsWith(u8, trimmed, "event:")) {
                const ev = std.mem.trimStart(u8, trimmed[6..], " ");
                const copy_len = @min(ev.len, event_type_buf.len);
                @memcpy(event_type_buf[0..copy_len], ev[0..copy_len]);
                event_type = event_type_buf[0..copy_len];
            } else if (std.mem.startsWith(u8, trimmed, "data:")) {
                const d = std.mem.trimStart(u8, trimmed[5..], " ");
                const copy_len = @min(d.len, data_buf.len - data_len);
                @memcpy(data_buf[data_len .. data_len + copy_len], d[0..copy_len]);
                data_len += copy_len;
            }
            // Ignore "id:", "retry:", and comments (":").
        }

        log.info("SSE stream ended", .{});
    }

    // -----------------------------------------------------------------------
    // Liveness (doppelganger)
    // -----------------------------------------------------------------------

    /// POST /eth/v1/validator/liveness/{epoch}
    /// GET /eth/v1/node/syncing
    ///
    /// Returns sync status of the beacon node.
    /// TS: Api.node.getSyncingStatus()
    pub fn getNodeSyncing(self: *BeaconApiClient, io: Io) !NodeSyncingResponse {
        const body = try self.get(io, "/eth/v1/node/syncing");
        defer self.allocator.free(body);

        const Parsed = struct {
            data: struct {
                head_slot: []const u8,
                sync_distance: []const u8,
                is_syncing: bool,
                is_optimistic: bool = false,
            },
        };

        var parsed = try std.json.parseFromSlice(Parsed, self.allocator, body, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        const d = parsed.value.data;
        return .{
            .head_slot = try std.fmt.parseInt(u64, d.head_slot, 10),
            .sync_distance = try std.fmt.parseInt(u64, d.sync_distance, 10),
            .is_syncing = d.is_syncing,
            .is_optimistic = d.is_optimistic,
        };
    }

    pub fn getLiveness(
        self: *BeaconApiClient,
        io: Io,
        epoch: u64,
        indices: []const u64,
    ) ![]ValidatorLiveness {
        const path = try std.fmt.allocPrint(self.allocator, "/eth/v1/validator/liveness/{d}", .{epoch});
        defer self.allocator.free(path);

        var body_buf: std.Io.Writer.Allocating = .init(self.allocator);
        defer body_buf.deinit();
        try body_buf.writer.writeByte('[');
        for (indices, 0..) |idx, i| {
            if (i > 0) try body_buf.writer.writeByte(',');
            try body_buf.writer.print("\"{d}\"", .{idx});
        }
        try body_buf.writer.writeByte(']');

        const resp = try self.post(io, path, body_buf.written());
        defer self.allocator.free(resp);

        const LivenessJson = struct {
            index: []const u8,
            is_live: bool,
        };
        const Parsed = struct {
            data: []const LivenessJson,
        };

        var parsed = try std.json.parseFromSlice(Parsed, self.allocator, resp, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        const result = try self.allocator.alloc(ValidatorLiveness, parsed.value.data.len);
        for (parsed.value.data, result) |src, *dst| {
            dst.index = try std.fmt.parseInt(u64, src.index, 10);
            dst.is_live = src.is_live;
        }
        return result;
    }
};

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

pub const GenesisResponse = struct {
    genesis_time: u64,
    genesis_validators_root: [32]u8,
    genesis_fork_version: [4]u8,
};

pub const ValidatorIndexAndStatus = struct {
    pubkey: [48]u8,
    index: u64,
    /// Validator status string (e.g. "active_ongoing", "withdrawal_possible").
    /// COH-3 Fix: stored as fixed-size buffer to avoid dangling pointer into freed arena.
    /// Max known status len is 20 bytes ("withdrawal_possible"); 32 is safe margin.
    status: [32]u8,
    status_len: u8,

    /// Return the status string slice.
    pub fn statusStr(self: *const ValidatorIndexAndStatus) []const u8 {
        return self.status[0..self.status_len];
    }
};

pub const ProduceBlockResponse = struct {
    /// Raw JSON body of the block response (caller must free).
    block_ssz: []const u8,
    /// Whether the block is blinded (MEV relay path).
    blinded: bool,
};

pub const ProduceBlockSszResponse = struct {
    /// Raw SSZ bytes of the unsigned BeaconBlock (caller must free).
    block_ssz: []const u8,
    /// Fork name from Eth-Consensus-Version header (e.g. "electra").
    /// Stored in fixed buffer — does not require freeing.
    fork_name: [32]u8,
    fork_name_len: u8,
    /// Whether the block is blinded (from response headers).
    blinded: bool,

    pub fn forkNameStr(self: *const ProduceBlockSszResponse) []const u8 {
        return self.fork_name[0..self.fork_name_len];
    }
};

pub const AttestationDataResponse = struct {
    slot: u64,
    index: u64,
    beacon_block_root: [32]u8,
    source_epoch: u64,
    source_root: [32]u8,
    target_epoch: u64,
    target_root: [32]u8,
};

pub const AggregatedAttestationResponse = struct {
    /// Raw JSON body of the aggregated attestation (caller must free).
    attestation_json: []const u8,
};

pub const SyncCommitteeContributionResponse = struct {
    slot: u64,
    beacon_block_root: [32]u8,
    subcommittee_index: u64,
    /// Aggregation bits (caller must free).
    aggregation_bits: []const u8,
    /// Aggregate BLS signature.
    signature: [96]u8,
};

pub const ValidatorLiveness = struct {
    index: u64,
    is_live: bool,
};

pub const NodeSyncingResponse = struct {
    head_slot: u64,
    sync_distance: u64,
    is_syncing: bool,
    is_optimistic: bool,
};
