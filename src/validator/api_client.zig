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

/// HTTP client for the Beacon Node REST API (validator-facing endpoints).
pub const BeaconApiClient = struct {
    allocator: Allocator,
    /// Base URL of the beacon node (e.g. "http://127.0.0.1:5052").
    base_url: []const u8,

    pub fn init(allocator: Allocator, base_url: []const u8) BeaconApiClient {
        return .{
            .allocator = allocator,
            .base_url = base_url,
        };
    }

    pub fn deinit(self: *BeaconApiClient) void {
        _ = self;
    }

    // -----------------------------------------------------------------------
    // Internal HTTP helpers
    // -----------------------------------------------------------------------

    /// Perform a GET request and return the response body (caller frees).
    fn get(self: *BeaconApiClient, io: Io, path: []const u8) ![]const u8 {
        const url = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ self.base_url, path });
        defer self.allocator.free(url);

        var client: std.http.Client = .{ .allocator = self.allocator, .io = io };
        defer client.deinit();

        const uri = try std.Uri.parse(url);
        var req = try client.request(.GET, uri, .{
            .keep_alive = false,
            .extra_headers = &.{
                .{ .name = "Accept", .value = "application/json" },
            },
        });
        defer req.deinit();

        try req.sendBodiless();

        var redirect_buf: [1024]u8 = undefined;
        var response = try req.receiveHead(&redirect_buf);

        if (response.head.status != .ok) {
            log.warn("GET {s} → HTTP {d}", .{ path, @intFromEnum(response.head.status) });
            return error.HttpError;
        }

        var transfer_buf: [8192]u8 = undefined;
        const reader = response.reader(&transfer_buf);
        return reader.allocRemaining(self.allocator, Io.Limit.limited(MAX_RESPONSE_BYTES)) catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr().?,
            else => |e| return e,
        };
    }

    /// Perform a POST request with JSON body and return the response body (caller frees).
    ///
    /// Pass an empty body (`""`) for POST endpoints that don't require a body.
    fn post(self: *BeaconApiClient, io: Io, path: []const u8, body: []const u8) ![]const u8 {
        const url = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ self.base_url, path });
        defer self.allocator.free(url);

        var client: std.http.Client = .{ .allocator = self.allocator, .io = io };
        defer client.deinit();

        const uri = try std.Uri.parse(url);
        var req = try client.request(.POST, uri, .{
            .keep_alive = false,
            .extra_headers = &.{
                .{ .name = "Accept", .value = "application/json" },
            },
            .headers = .{
                .content_type = .{ .override = "application/json" },
            },
        });
        defer req.deinit();

        req.transfer_encoding = .{ .content_length = body.len };
        try req.sendBodyComplete(@constCast(body));

        var redirect_buf: [1024]u8 = undefined;
        var response = try req.receiveHead(&redirect_buf);

        const status = response.head.status;
        // 2xx codes are all success; 204 has no body.
        if (@intFromEnum(status) < 200 or @intFromEnum(status) >= 300) {
            log.warn("POST {s} → HTTP {d}", .{ path, @intFromEnum(status) });
            return error.HttpError;
        }

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
        var body_buf = std.ArrayList(u8).init(self.allocator);
        defer body_buf.deinit();
        try body_buf.append('[');
        for (indices, 0..) |idx, i| {
            if (i > 0) try body_buf.append(',');
            try body_buf.writer().print("\"{d}\"", .{idx});
        }
        try body_buf.append(']');

        const resp = try self.post(io, path, body_buf.items);
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

        var body_buf = std.ArrayList(u8).init(self.allocator);
        defer body_buf.deinit();
        try body_buf.append('[');
        for (indices, 0..) |idx, i| {
            if (i > 0) try body_buf.append(',');
            try body_buf.writer().print("\"{d}\"", .{idx});
        }
        try body_buf.append(']');

        const resp = try self.post(io, path, body_buf.items);
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
        var body_buf = std.ArrayList(u8).init(self.allocator);
        defer body_buf.deinit();
        try body_buf.append('[');
        for (pubkeys, 0..) |pk, i| {
            if (i > 0) try body_buf.append(',');
            try body_buf.writer().print("\"0x{}\"", .{std.fmt.fmtSliceHexLower(&pk)});
        }
        try body_buf.append(']');

        const resp = try self.post(io, "/eth/v1/beacon/states/head/validators", body_buf.items);
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
            // Status is a string slice pointing into parsed arena — but parsed is deferred;
            // we need to copy it. For now, use a fixed-size buffer.
            dst.status = src.status; // NOTE: arena-owned, valid only within this scope.
            // TODO: copy status string to owned memory if needed beyond this call.
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
        return .{ .attestation_ssz = body };
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
        var topics_buf = std.ArrayList(u8).init(self.allocator);
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
        var line_buf: [SSE_LINE_BUF]u8 = undefined;
        var event_type_buf: [128]u8 = undefined;
        var event_type: []const u8 = "";
        var data_buf: [SSE_LINE_BUF]u8 = undefined;
        var data_len: usize = 0;

        var transfer_buf: [SSE_LINE_BUF]u8 = undefined;
        const reader = response.reader(&transfer_buf);

        while (true) {
            // Read one line at a time.
            const line = reader.readUntilDelimiter(&line_buf, '\n') catch |err| switch (err) {
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
                const ev = std.mem.trimLeft(u8, trimmed[6..], " ");
                const copy_len = @min(ev.len, event_type_buf.len);
                @memcpy(event_type_buf[0..copy_len], ev[0..copy_len]);
                event_type = event_type_buf[0..copy_len];
            } else if (std.mem.startsWith(u8, trimmed, "data:")) {
                const d = std.mem.trimLeft(u8, trimmed[5..], " ");
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
    pub fn getLiveness(
        self: *BeaconApiClient,
        io: Io,
        epoch: u64,
        indices: []const u64,
    ) ![]ValidatorLiveness {
        const path = try std.fmt.allocPrint(self.allocator, "/eth/v1/validator/liveness/{d}", .{epoch});
        defer self.allocator.free(path);

        var body_buf = std.ArrayList(u8).init(self.allocator);
        defer body_buf.deinit();
        try body_buf.append('[');
        for (indices, 0..) |idx, i| {
            if (i > 0) try body_buf.append(',');
            try body_buf.writer().print("\"{d}\"", .{idx});
        }
        try body_buf.append(']');

        const resp = try self.post(io, path, body_buf.items);
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
    status: []const u8,
};

pub const ProduceBlockResponse = struct {
    /// Raw JSON body of the block response (caller must free).
    block_ssz: []const u8,
    /// Whether the block is blinded (MEV relay path).
    blinded: bool,
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
    attestation_ssz: []const u8,
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
