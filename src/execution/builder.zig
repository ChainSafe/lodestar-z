//! MEV-boost builder API — HTTP client implementation.
//!
//! Implements the builder relay REST API as defined in:
//! https://github.com/ethereum/builder-specs
//!
//! The builder relay is a separate service from the execution engine (no JWT).
//! It speaks a REST/JSON API, not JSON-RPC.
//!
//! Flow:
//!   1. Each epoch: registerValidators() — tell relay our validator registrations
//!   2. Per block: getHeader() — ask relay for a blinded bid (or 204 = no bid)
//!   3. If bid > local threshold: sign blinded block, submitBlindedBlock() → full payload
//!   4. On any error: fall back to local execution engine

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

const types = @import("engine_api_types.zig");
const http_engine = @import("http_engine.zig");
const Transport = http_engine.Transport;
const Header = http_engine.Header;

// ── Builder API types ─────────────────────────────────────────────────────────

/// Validator registration for the builder API.
/// Sent once per epoch to builder relays.
pub const ValidatorRegistration = struct {
    /// Validator fee recipient address.
    fee_recipient: [20]u8,
    /// Maximum gas limit the validator will accept.
    gas_limit: u64,
    /// Registration timestamp.
    timestamp: u64,
    /// Validator BLS public key.
    pubkey: [48]u8,
};

/// Signed validator registration with BLS signature.
pub const SignedValidatorRegistration = struct {
    message: ValidatorRegistration,
    signature: [96]u8,
};

/// Execution payload header (blinded payload — without transactions).
pub const ExecutionPayloadHeader = struct {
    parent_hash: [32]u8,
    fee_recipient: [20]u8,
    state_root: [32]u8,
    receipts_root: [32]u8,
    logs_bloom: [256]u8,
    prev_randao: [32]u8,
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: []const u8,
    base_fee_per_gas: u256,
    block_hash: [32]u8,
    /// Merkle root of the transactions list (not the transactions themselves).
    transactions_root: [32]u8,
    /// Merkle root of the withdrawals list (Capella+).
    withdrawals_root: ?[32]u8 = null,
    /// Blob gas used (Deneb+).
    blob_gas_used: ?u64 = null,
    /// Excess blob gas (Deneb+).
    excess_blob_gas: ?u64 = null,
};

/// Builder bid returned by getHeader — the blinded block with block value.
pub const BuilderBid = struct {
    /// The blinded execution payload header.
    header: ExecutionPayloadHeader,
    /// Blob KZG commitments (Deneb+).
    blob_kzg_commitments: []const [48]u8,
    /// MEV reward value in wei.
    value: u256,
    /// Builder BLS public key.
    pubkey: [48]u8,
};

/// Signed builder bid.
pub const SignedBuilderBid = struct {
    message: BuilderBid,
    signature: [96]u8,
};

/// Blinded beacon block body (contains header instead of full payload).
pub const BlindedBeaconBlockBody = struct {
    /// The blinded execution payload header.
    execution_payload_header: ExecutionPayloadHeader,
    // Other beacon block body fields would go here.
};

/// Signed blinded beacon block submitted to the builder relay.
pub const SignedBlindedBeaconBlock = struct {
    message: BlindedBeaconBlockBody,
    signature: [96]u8,
};

// ── Builder status ────────────────────────────────────────────────────────────

pub const BuilderStatus = enum {
    /// Builder is available and responding.
    available,
    /// Builder is unavailable (offline, error response).
    unavailable,
    /// Circuit breaker: chain health issues detected, must use local execution.
    circuit_breaker,
};

// ── Builder API interface ─────────────────────────────────────────────────────

/// Builder API vtable interface.
///
/// Abstracts over MEV-boost relay communication. Concrete implementations
/// handle the actual HTTP relay API.
pub const BuilderApi = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Register validators with the builder relay.
        /// Called once per epoch for all active validators.
        registerValidators: *const fn (
            ptr: *anyopaque,
            registrations: []const SignedValidatorRegistration,
        ) anyerror!void,

        /// Get a blinded execution payload header from the builder relay.
        /// Called during block production to check if builder has a better block.
        /// Returns null if no bid is available (204 No Content from relay).
        getHeader: *const fn (
            ptr: *anyopaque,
            slot: u64,
            parent_hash: [32]u8,
            pubkey: [48]u8,
        ) anyerror!?SignedBuilderBid,

        /// Submit a signed blinded beacon block to unblind and broadcast.
        /// Called after the proposer signs the blinded block.
        submitBlindedBlock: *const fn (
            ptr: *anyopaque,
            block: SignedBlindedBeaconBlock,
        ) anyerror!types.ExecutionPayloadV3,

        /// Check builder relay status.
        /// Returns null if the builder is available, error if not.
        status: *const fn (ptr: *anyopaque) anyerror!BuilderStatus,
    };

    /// Register validators with the builder relay.
    pub fn registerValidators(
        self: BuilderApi,
        registrations: []const SignedValidatorRegistration,
    ) !void {
        return self.vtable.registerValidators(self.ptr, registrations);
    }

    /// Get a blinded execution payload header.
    /// Returns null if the relay has no bid available (204 No Content).
    pub fn getHeader(
        self: BuilderApi,
        slot: u64,
        parent_hash: [32]u8,
        pubkey: [48]u8,
    ) !?SignedBuilderBid {
        return self.vtable.getHeader(self.ptr, slot, parent_hash, pubkey);
    }

    /// Submit a blinded beacon block and receive the full execution payload.
    pub fn submitBlindedBlock(
        self: BuilderApi,
        block: SignedBlindedBeaconBlock,
    ) !types.ExecutionPayloadV3 {
        return self.vtable.submitBlindedBlock(self.ptr, block);
    }

    /// Check builder relay status.
    pub fn status(self: BuilderApi) !BuilderStatus {
        return self.vtable.status(self.ptr);
    }
};

// ── HttpBuilder ───────────────────────────────────────────────────────────────

/// REST HTTP client for MEV-boost builder relay API.
///
/// Communicates with the builder relay using JSON REST (not JSON-RPC).
/// No JWT auth — builder is a separate service from the execution engine.
///
/// Key differences from HttpEngine:
/// - REST endpoints, not JSON-RPC
/// - 204 No Content = no bid available (not an error)
/// - No JWT authentication
/// - Shorter timeouts (builder must respond quickly for block production)
pub const HttpBuilder = struct {
    allocator: Allocator,
    /// Builder relay base URL (e.g. "http://localhost:18550").
    endpoint: []const u8,
    /// Pluggable HTTP transport (same interface as HttpEngine).
    transport: Transport,
    /// Current builder status.
    current_status: BuilderStatus,
    /// Timeout for getHeader in milliseconds (builder must respond within 1s).
    header_timeout_ms: u64,

    pub fn init(
        allocator: Allocator,
        endpoint: []const u8,
        transport: Transport,
    ) HttpBuilder {
        return .{
            .allocator = allocator,
            .endpoint = endpoint,
            .transport = transport,
            .current_status = .unavailable,
            .header_timeout_ms = 1_000,
        };
    }

    pub fn deinit(_: *HttpBuilder) void {}

    /// Return a BuilderApi vtable interface backed by this client.
    pub fn builder(self: *HttpBuilder) BuilderApi {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────────

    /// Build common headers for builder REST requests.
    fn buildHeaders(headers_buf: []Header) usize {
        var count: usize = 0;
        headers_buf[count] = .{ .name = "Content-Type", .value = "application/json" };
        count += 1;
        headers_buf[count] = .{ .name = "Accept", .value = "application/json" };
        count += 1;
        return count;
    }

    /// Build a full URL from the base endpoint and a path.
    fn buildUrl(self: *HttpBuilder, path: []const u8) ![]const u8 {
        return std.fmt.allocPrint(self.allocator, "{s}{s}", .{ self.endpoint, path });
    }

    // ── REST method implementations ───────────────────────────────────────────

    fn statusImpl(self: *HttpBuilder) anyerror!BuilderStatus {
        const url = try self.buildUrl("/eth/v1/builder/status");
        defer self.allocator.free(url);

        var headers_buf: [2]Header = undefined;
        const header_count = buildHeaders(&headers_buf);

        // GET with empty body
        const response = self.transport.send(url, headers_buf[0..header_count], "") catch |err| {
            std.log.warn("Builder: status check failed: {}", .{err});
            self.current_status = .unavailable;
            return .unavailable;
        };
        defer self.allocator.free(response);

        // 200 OK = available
        self.current_status = .available;
        std.log.info("Builder: relay is available at {s}", .{self.endpoint});
        return .available;
    }

    fn registerValidatorsImpl(
        self: *HttpBuilder,
        registrations: []const SignedValidatorRegistration,
    ) anyerror!void {
        if (registrations.len == 0) return;

        const url = try self.buildUrl("/eth/v1/builder/validators");
        defer self.allocator.free(url);

        // Encode registrations as JSON array
        const body = try encodeRegistrations(self.allocator, registrations);
        defer self.allocator.free(body);

        var headers_buf: [2]Header = undefined;
        const header_count = buildHeaders(&headers_buf);

        const response = self.transport.send(url, headers_buf[0..header_count], body) catch |err| {
            std.log.warn("Builder: registerValidators failed: {}", .{err});
            return err;
        };
        defer self.allocator.free(response);

        std.log.info("Builder: registered {d} validator(s) with relay", .{registrations.len});
    }

    fn getHeaderImpl(
        self: *HttpBuilder,
        slot: u64,
        parent_hash: [32]u8,
        pubkey: [48]u8,
    ) anyerror!?SignedBuilderBid {
        // Build path: /eth/v1/builder/header/{slot}/{parent_hash}/{pubkey}
        const parent_hash_hex = try http_engine.hexEncodeFixed(self.allocator, &parent_hash);
        defer self.allocator.free(parent_hash_hex);
        const pubkey_hex = try http_engine.hexEncodeFixed(self.allocator, &pubkey);
        defer self.allocator.free(pubkey_hex);

        const path = try std.fmt.allocPrint(
            self.allocator,
            "/eth/v1/builder/header/{d}/{s}/{s}",
            .{ slot, parent_hash_hex, pubkey_hex },
        );
        defer self.allocator.free(path);

        const url = try self.buildUrl(path);
        defer self.allocator.free(url);

        var headers_buf: [2]Header = undefined;
        const header_count = buildHeaders(&headers_buf);

        const response = self.transport.send(url, headers_buf[0..header_count], "") catch |err| {
            std.log.warn("Builder: getHeader failed (slot={d}): {} — falling back to local execution", .{ slot, err });
            return null;
        };
        defer self.allocator.free(response);

        // Empty response = 204 No Content = no bid available
        if (response.len == 0) {
            std.log.debug("Builder: no bid available for slot {d}", .{slot});
            return null;
        }

        // Parse the JSON response
        const bid = parseSignedBuilderBid(self.allocator, response) catch |err| {
            std.log.warn("Builder: failed to parse bid response: {} — falling back", .{err});
            return null;
        };

        std.log.info("Builder: received bid for slot {d}, value={d}", .{ slot, bid.message.value });
        return bid;
    }

    fn submitBlindedBlockImpl(
        self: *HttpBuilder,
        block: SignedBlindedBeaconBlock,
    ) anyerror!types.ExecutionPayloadV3 {
        const url = try self.buildUrl("/eth/v1/builder/blinded_blocks");
        defer self.allocator.free(url);

        const body = try encodeSignedBlindedBlock(self.allocator, block);
        defer self.allocator.free(body);

        var headers_buf: [2]Header = undefined;
        const header_count = buildHeaders(&headers_buf);

        const response = self.transport.send(url, headers_buf[0..header_count], body) catch |err| {
            std.log.err("Builder: submitBlindedBlock failed: {}", .{err});
            return err;
        };
        defer self.allocator.free(response);

        // Parse the full execution payload from response
        const payload = try parseExecutionPayload(self.allocator, response);
        std.log.info("Builder: successfully unblinded block, block_hash={x}", .{
            payload.block_hash[0..4],
        });
        return payload;
    }

    // ── vtable ────────────────────────────────────────────────────────────────

    const vtable = BuilderApi.VTable{
        .registerValidators = @ptrCast(&registerValidatorsImpl),
        .getHeader = @ptrCast(&getHeaderImpl),
        .submitBlindedBlock = @ptrCast(&submitBlindedBlockImpl),
        .status = @ptrCast(&statusImpl),
    };
};

// ── JSON encoding ─────────────────────────────────────────────────────────────

fn hexEncodeBytes(allocator: Allocator, bytes: []const u8) ![]const u8 {
    return http_engine.hexEncode(allocator, bytes);
}

fn encodeRegistrations(
    allocator: Allocator,
    registrations: []const SignedValidatorRegistration,
) ![]const u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    defer {
        for (parts.items) |p| allocator.free(p);
        parts.deinit(allocator);
    }

    for (registrations) |reg| {
        const fee_hex = try http_engine.hexEncodeFixed(allocator, &reg.message.fee_recipient);
        defer allocator.free(fee_hex);
        const pubkey_hex = try http_engine.hexEncodeFixed(allocator, &reg.message.pubkey);
        defer allocator.free(pubkey_hex);
        const sig_hex = try http_engine.hexEncodeFixed(allocator, &reg.signature);
        defer allocator.free(sig_hex);

        const entry = try std.fmt.allocPrint(allocator,
            \\{{"message":{{"fee_recipient":"{s}","gas_limit":"{d}","timestamp":"{d}","pubkey":"{s}"}},"signature":"{s}"}}
        , .{
            fee_hex,
            reg.message.gas_limit,
            reg.message.timestamp,
            pubkey_hex,
            sig_hex,
        });
        try parts.append(allocator, entry);
    }

    // Join into array
    if (parts.items.len == 0) return allocator.dupe(u8, "[]");
    var total: usize = 2;
    for (parts.items, 0..) |p, i| {
        total += p.len;
        if (i + 1 < parts.items.len) total += 1;
    }
    const out = try allocator.alloc(u8, total);
    out[0] = '[';
    var pos: usize = 1;
    for (parts.items, 0..) |p, i| {
        @memcpy(out[pos .. pos + p.len], p);
        pos += p.len;
        if (i + 1 < parts.items.len) {
            out[pos] = ',';
            pos += 1;
        }
    }
    out[pos] = ']';
    return out;
}

fn encodeExecutionPayloadHeader(allocator: Allocator, h: ExecutionPayloadHeader) ![]const u8 {
    const parent_hash = try http_engine.hexEncodeFixed(allocator, &h.parent_hash);
    defer allocator.free(parent_hash);
    const fee_recipient = try http_engine.hexEncodeFixed(allocator, &h.fee_recipient);
    defer allocator.free(fee_recipient);
    const state_root = try http_engine.hexEncodeFixed(allocator, &h.state_root);
    defer allocator.free(state_root);
    const receipts_root = try http_engine.hexEncodeFixed(allocator, &h.receipts_root);
    defer allocator.free(receipts_root);
    const logs_bloom = try http_engine.hexEncodeFixed(allocator, &h.logs_bloom);
    defer allocator.free(logs_bloom);
    const prev_randao = try http_engine.hexEncodeFixed(allocator, &h.prev_randao);
    defer allocator.free(prev_randao);
    const block_number = try http_engine.hexEncodeQuantity(allocator, h.block_number);
    defer allocator.free(block_number);
    const gas_limit = try http_engine.hexEncodeQuantity(allocator, h.gas_limit);
    defer allocator.free(gas_limit);
    const gas_used = try http_engine.hexEncodeQuantity(allocator, h.gas_used);
    defer allocator.free(gas_used);
    const timestamp = try http_engine.hexEncodeQuantity(allocator, h.timestamp);
    defer allocator.free(timestamp);
    const extra_data = try http_engine.hexEncode(allocator, h.extra_data);
    defer allocator.free(extra_data);
    const base_fee = try http_engine.hexEncodeQuantityU256(allocator, h.base_fee_per_gas);
    defer allocator.free(base_fee);
    const block_hash = try http_engine.hexEncodeFixed(allocator, &h.block_hash);
    defer allocator.free(block_hash);
    const tx_root = try http_engine.hexEncodeFixed(allocator, &h.transactions_root);
    defer allocator.free(tx_root);


    // Fix 3: conditionally include Deneb+ fields when present.
    if (h.withdrawals_root != null or h.blob_gas_used != null or h.excess_blob_gas != null) {
        const wr_hex = if (h.withdrawals_root) |wr|
            try http_engine.hexEncodeFixed(allocator, &wr)
        else
            try allocator.dupe(u8, "0x0000000000000000000000000000000000000000000000000000000000000000");
        defer allocator.free(wr_hex);

        const bgu_hex = try http_engine.hexEncodeQuantity(allocator, h.blob_gas_used orelse 0);
        defer allocator.free(bgu_hex);

        const ebg_hex = try http_engine.hexEncodeQuantity(allocator, h.excess_blob_gas orelse 0);
        defer allocator.free(ebg_hex);

        return std.fmt.allocPrint(allocator,
            \\{{"parent_hash":"{s}","fee_recipient":"{s}","state_root":"{s}","receipts_root":"{s}","logs_bloom":"{s}","prev_randao":"{s}","block_number":"{s}","gas_limit":"{s}","gas_used":"{s}","timestamp":"{s}","extra_data":"{s}","base_fee_per_gas":"{s}","block_hash":"{s}","transactions_root":"{s}","withdrawals_root":"{s}","blob_gas_used":"{s}","excess_blob_gas":"{s}"}}
        , .{
            parent_hash, fee_recipient, state_root,  receipts_root,
            logs_bloom,  prev_randao,   block_number, gas_limit,
            gas_used,    timestamp,     extra_data,   base_fee,
            block_hash,  tx_root,       wr_hex,       bgu_hex,
            ebg_hex,
        });
    }

    return std.fmt.allocPrint(allocator,
        \\{{"parent_hash":"{s}","fee_recipient":"{s}","state_root":"{s}","receipts_root":"{s}","logs_bloom":"{s}","prev_randao":"{s}","block_number":"{s}","gas_limit":"{s}","gas_used":"{s}","timestamp":"{s}","extra_data":"{s}","base_fee_per_gas":"{s}","block_hash":"{s}","transactions_root":"{s}"}}
    , .{
        parent_hash, fee_recipient, state_root,  receipts_root,
        logs_bloom,  prev_randao,   block_number, gas_limit,
        gas_used,    timestamp,     extra_data,   base_fee,
        block_hash,  tx_root,
    });
}

fn encodeSignedBlindedBlock(allocator: Allocator, block: SignedBlindedBeaconBlock) ![]const u8 {
    const header_json = try encodeExecutionPayloadHeader(
        allocator,
        block.message.execution_payload_header,
    );
    defer allocator.free(header_json);

    const sig_hex = try http_engine.hexEncodeFixed(allocator, &block.signature);
    defer allocator.free(sig_hex);

    return std.fmt.allocPrint(allocator,
        \\{{"message":{{"body":{{"execution_payload_header":{s}}}}},"signature":"{s}"}}
    , .{ header_json, sig_hex });
}

// ── JSON parsing ──────────────────────────────────────────────────────────────

// ── Local hex parse aliases (delegate to http_engine) ─────────────────────────
//
// Fix 6: Remove duplicates — use http_engine's pub decode functions directly.

const parseHex32 = http_engine.hexDecode32;
const parseHex20 = http_engine.hexDecode20;
const parseHex48 = http_engine.hexDecode48;
const parseHex96 = http_engine.hexDecode96;
const parseHex256 = http_engine.hexDecode256;
const parseQuantityU64 = http_engine.hexDecodeQuantity;
const parseQuantityU256 = http_engine.hexDecodeU256;

/// Parse a SignedBuilderBid from the relay's JSON response.
///
/// Expected shape (simplified):
/// {
///   "version": "bellatrix",
///   "data": {
///     "message": {
///       "header": { ... execution payload header fields ... },
///       "value": "0x...",
///       "pubkey": "0x..."
///     },
///     "signature": "0x..."
///   }
/// }
fn parseSignedBuilderBid(allocator: Allocator, json_bytes: []const u8) !SignedBuilderBid {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{});
    defer parsed.deinit();

    const root = parsed.value.object;

    // Navigate to data.message and data.signature
    const data = root.get("data") orelse return error.MissingField;
    const data_obj = data.object;
    const message = data_obj.get("message") orelse return error.MissingField;
    const message_obj = message.object;
    const sig_val = data_obj.get("signature") orelse return error.MissingField;

    const signature = try parseHex96(sig_val.string);
    const value = try parseQuantityU256((message_obj.get("value") orelse return error.MissingField).string);
    const pubkey = try parseHex48((message_obj.get("pubkey") orelse return error.MissingField).string);

    // Parse header
    const header_val = message_obj.get("header") orelse return error.MissingField;
    const header_obj = header_val.object;

    const header = ExecutionPayloadHeader{
        .parent_hash = try parseHex32((header_obj.get("parent_hash") orelse return error.MissingField).string),
        .fee_recipient = try parseHex20((header_obj.get("fee_recipient") orelse return error.MissingField).string),
        .state_root = try parseHex32((header_obj.get("state_root") orelse return error.MissingField).string),
        .receipts_root = try parseHex32((header_obj.get("receipts_root") orelse return error.MissingField).string),
        .logs_bloom = try parseHex256((header_obj.get("logs_bloom") orelse return error.MissingField).string),
        .prev_randao = try parseHex32((header_obj.get("prev_randao") orelse return error.MissingField).string),
        .block_number = try parseQuantityU64((header_obj.get("block_number") orelse return error.MissingField).string),
        .gas_limit = try parseQuantityU64((header_obj.get("gas_limit") orelse return error.MissingField).string),
        .gas_used = try parseQuantityU64((header_obj.get("gas_used") orelse return error.MissingField).string),
        .timestamp = try parseQuantityU64((header_obj.get("timestamp") orelse return error.MissingField).string),
        .extra_data = blk: {
            // Fix 1: decode extra_data into owned memory before arena is freed.
            const extra_data_hex = (header_obj.get("extra_data") orelse return error.MissingField).string;
            const stripped = if (std.mem.startsWith(u8, extra_data_hex, "0x")) extra_data_hex[2..] else extra_data_hex;
            const owned = try allocator.alloc(u8, if (stripped.len == 0) 0 else stripped.len / 2);
            errdefer allocator.free(owned);
            if (owned.len > 0) _ = std.fmt.hexToBytes(owned, stripped) catch return error.InvalidHex;
            break :blk owned;
        },
        .base_fee_per_gas = try parseQuantityU256((header_obj.get("base_fee_per_gas") orelse return error.MissingField).string),
        .block_hash = try parseHex32((header_obj.get("block_hash") orelse return error.MissingField).string),
        .transactions_root = try parseHex32((header_obj.get("transactions_root") orelse return error.MissingField).string),
        .withdrawals_root = if (header_obj.get("withdrawals_root")) |v| try parseHex32(v.string) else null,
        .blob_gas_used = if (header_obj.get("blob_gas_used")) |v| try parseQuantityU64(v.string) else null,
        .excess_blob_gas = if (header_obj.get("excess_blob_gas")) |v| try parseQuantityU64(v.string) else null,
    };

    return SignedBuilderBid{
        .message = BuilderBid{
            .header = header,
            .blob_kzg_commitments = blk: {
                // Fix 5: parse blob_kzg_commitments array from JSON.
                const kzg_val = message_obj.get("blob_kzg_commitments") orelse break :blk &([_][48]u8{});
                const kzg_arr = kzg_val.array.items;
                if (kzg_arr.len == 0) break :blk &([_][48]u8{});
                const commitments = try allocator.alloc([48]u8, kzg_arr.len);
                errdefer allocator.free(commitments);
                for (kzg_arr, 0..) |item, i| {
                    commitments[i] = try parseHex48(item.string);
                }
                break :blk commitments;
            },
            .value = value,
            .pubkey = pubkey,
        },
        .signature = signature,
    };
}

/// Parse an ExecutionPayload from submitBlindedBlock response.
///
/// The builder returns the full unblinded payload in the "data" field.
/// Transactions are the whole point of unblinding — decode them from hex.
fn parseExecutionPayload(allocator: Allocator, json_bytes: []const u8) !types.ExecutionPayloadV3 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{});
    defer parsed.deinit();

    const root = parsed.value.object;
    const data = (root.get("data") orelse return error.MissingField).object;

    // Decode extra_data hex into owned bytes.
    const extra_data_hex = (data.get("extra_data") orelse return error.MissingField).string;
    const extra_data_stripped = extra_data_hex[if (std.mem.startsWith(u8, extra_data_hex, "0x")) 2 else 0..];
    const extra_data = try allocator.alloc(u8, if (extra_data_stripped.len == 0) 0 else extra_data_stripped.len / 2);
    errdefer allocator.free(extra_data);
    if (extra_data.len > 0) _ = try std.fmt.hexToBytes(extra_data, extra_data_stripped);

    // Decode transactions: each is an opaque hex-encoded RLP transaction.
    const tx_array = if (data.get("transactions")) |v| v.array.items else &[_]std.json.Value{};
    const transactions = try allocator.alloc([]const u8, tx_array.len);
    errdefer allocator.free(transactions);
    var n_decoded: usize = 0;
    errdefer for (transactions[0..n_decoded]) |tx| allocator.free(tx);
    for (tx_array, 0..) |tx_val, i| {
        const tx_hex = tx_val.string;
        const stripped = tx_hex[if (std.mem.startsWith(u8, tx_hex, "0x")) 2 else 0..];
        const tx_bytes = try allocator.alloc(u8, stripped.len / 2);
        _ = try std.fmt.hexToBytes(tx_bytes, stripped);
        transactions[i] = tx_bytes;
        n_decoded += 1;
    }

    // Decode withdrawals if present.
    const wd_array = if (data.get("withdrawals")) |v| v.array.items else &[_]std.json.Value{};
    const withdrawals = try allocator.alloc(types.Withdrawal, wd_array.len);
    errdefer allocator.free(withdrawals);
    for (wd_array, 0..) |wd_val, i| {
        const wd = wd_val.object;
        withdrawals[i] = types.Withdrawal{
            .index = try parseQuantityU64(wd.get("index").?.string),
            .validator_index = try parseQuantityU64(wd.get("validator_index").?.string),
            .address = try parseHex20(wd.get("address").?.string),
            .amount = try parseQuantityU64(wd.get("amount").?.string),
        };
    }

    return types.ExecutionPayloadV3{
        .parent_hash = try parseHex32((data.get("parent_hash") orelse return error.MissingField).string),
        .fee_recipient = try parseHex20((data.get("fee_recipient") orelse return error.MissingField).string),
        .state_root = try parseHex32((data.get("state_root") orelse return error.MissingField).string),
        .receipts_root = try parseHex32((data.get("receipts_root") orelse return error.MissingField).string),
        .logs_bloom = try parseHex256((data.get("logs_bloom") orelse return error.MissingField).string),
        .prev_randao = try parseHex32((data.get("prev_randao") orelse return error.MissingField).string),
        .block_number = try parseQuantityU64((data.get("block_number") orelse return error.MissingField).string),
        .gas_limit = try parseQuantityU64((data.get("gas_limit") orelse return error.MissingField).string),
        .gas_used = try parseQuantityU64((data.get("gas_used") orelse return error.MissingField).string),
        .timestamp = try parseQuantityU64((data.get("timestamp") orelse return error.MissingField).string),
        .extra_data = extra_data,
        .base_fee_per_gas = try parseQuantityU256((data.get("base_fee_per_gas") orelse return error.MissingField).string),
        .block_hash = try parseHex32((data.get("block_hash") orelse return error.MissingField).string),
        .transactions = transactions,
        .withdrawals = withdrawals,
        .blob_gas_used = if (data.get("blob_gas_used")) |v| try parseQuantityU64(v.string) else 0,
        .excess_blob_gas = if (data.get("excess_blob_gas")) |v| try parseQuantityU64(v.string) else 0,
    };
}

// ── MockBuilderTransport ──────────────────────────────────────────────────────

/// Mock HTTP transport for testing the builder client.
///
/// Supports per-path response injection to simulate different relay scenarios:
/// - GET /eth/v1/builder/status → 200 (available)
/// - GET /eth/v1/builder/header/... → bid JSON or empty (204 no bid)
/// - POST /eth/v1/builder/validators → 200 OK
/// - POST /eth/v1/builder/blinded_blocks → full payload JSON
pub const MockBuilderTransport = struct {
    allocator: Allocator,
    /// Response to return for the next send() call.
    /// Empty string simulates 204 No Content.
    canned_response: []const u8,
    /// If set, send() returns this error instead.
    force_error: ?anyerror = null,
    /// Last URL called.
    last_url: ?[]const u8 = null,
    /// Last body sent.
    last_body: ?[]const u8 = null,
    /// Last method used (GET/POST).
    last_method: ?[]const u8 = null,

    pub fn init(allocator: Allocator, canned_response: []const u8) MockBuilderTransport {
        return .{
            .allocator = allocator,
            .canned_response = canned_response,
        };
    }

    pub fn deinit(self: *MockBuilderTransport) void {
        if (self.last_url) |u| self.allocator.free(u);
        if (self.last_body) |b| self.allocator.free(b);
    }

    pub fn transport(self: *MockBuilderTransport) Transport {
        return .{
            .ptr = @ptrCast(self),
            .sendFn = @ptrCast(&MockBuilderTransport.send),
        };
    }

    fn send(
        self: *MockBuilderTransport,
        url: []const u8,
        _: []const Header,
        body: []const u8,
    ) anyerror![]const u8 {
        if (self.last_url) |u| self.allocator.free(u);
        if (self.last_body) |b| self.allocator.free(b);
        self.last_url = try self.allocator.dupe(u8, url);
        self.last_body = try self.allocator.dupe(u8, body);

        if (self.force_error) |err| return err;

        return self.allocator.dupe(u8, self.canned_response);
    }
};

// ── Stub implementation ───────────────────────────────────────────────────────

/// Stub builder implementation — returns error.NotImplemented for all methods.
///
/// Use as a placeholder when no builder relay is configured.
pub const StubBuilder = struct {
    pub fn init() StubBuilder {
        return .{};
    }

    pub fn deinit(_: *StubBuilder) void {}

    /// Return a BuilderApi backed by this stub.
    pub fn builder(self: *StubBuilder) BuilderApi {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = BuilderApi.VTable{
        .registerValidators = @ptrCast(&registerValidatorsImpl),
        .getHeader = @ptrCast(&getHeaderImpl),
        .submitBlindedBlock = @ptrCast(&submitBlindedBlockImpl),
        .status = @ptrCast(&statusImpl),
    };

    fn registerValidatorsImpl(
        _: *StubBuilder,
        _: []const SignedValidatorRegistration,
    ) anyerror!void {
        return error.NotImplemented;
    }

    fn getHeaderImpl(
        _: *StubBuilder,
        _: u64,
        _: [32]u8,
        _: [48]u8,
    ) anyerror!?SignedBuilderBid {
        return error.NotImplemented;
    }

    fn submitBlindedBlockImpl(
        _: *StubBuilder,
        _: SignedBlindedBeaconBlock,
    ) anyerror!types.ExecutionPayloadV3 {
        return error.NotImplemented;
    }

    fn statusImpl(_: *StubBuilder) anyerror!BuilderStatus {
        return .unavailable;
    }
};

// ── Tests ─────────────────────────────────────────────────────────────────────

test "StubBuilder: registerValidators returns NotImplemented" {
    var stub = StubBuilder.init();
    defer stub.deinit();

    const api = stub.builder();
    const result = api.registerValidators(&.{});
    try testing.expectError(error.NotImplemented, result);
}

test "StubBuilder: getHeader returns NotImplemented" {
    var stub = StubBuilder.init();
    defer stub.deinit();

    const api = stub.builder();
    const result = api.getHeader(1, std.mem.zeroes([32]u8), std.mem.zeroes([48]u8));
    try testing.expectError(error.NotImplemented, result);
}

test "StubBuilder: submitBlindedBlock returns NotImplemented" {
    var stub = StubBuilder.init();
    defer stub.deinit();

    const api = stub.builder();
    const result = api.submitBlindedBlock(.{
        .message = .{
            .execution_payload_header = .{
                .parent_hash = std.mem.zeroes([32]u8),
                .fee_recipient = std.mem.zeroes([20]u8),
                .state_root = std.mem.zeroes([32]u8),
                .receipts_root = std.mem.zeroes([32]u8),
                .logs_bloom = std.mem.zeroes([256]u8),
                .prev_randao = std.mem.zeroes([32]u8),
                .block_number = 0,
                .gas_limit = 0,
                .gas_used = 0,
                .timestamp = 0,
                .extra_data = &.{},
                .base_fee_per_gas = 0,
                .block_hash = std.mem.zeroes([32]u8),
                .transactions_root = std.mem.zeroes([32]u8),
            },
        },
        .signature = std.mem.zeroes([96]u8),
    });
    try testing.expectError(error.NotImplemented, result);
}

test "StubBuilder: status returns unavailable" {
    var stub = StubBuilder.init();
    defer stub.deinit();
    const api = stub.builder();
    const s = try api.status();
    try testing.expectEqual(BuilderStatus.unavailable, s);
}

test "BuilderApi vtable struct layout" {
    const info = @typeInfo(BuilderApi.VTable);
    try testing.expectEqual(@as(usize, 4), info.@"struct".fields.len);
}

test "BuilderApi methods exist" {
    try testing.expect(@hasDecl(BuilderApi, "registerValidators"));
    try testing.expect(@hasDecl(BuilderApi, "getHeader"));
    try testing.expect(@hasDecl(BuilderApi, "submitBlindedBlock"));
    try testing.expect(@hasDecl(BuilderApi, "status"));
}

test "HttpBuilder: status check — builder available" {
    const allocator = testing.allocator;
    // Non-empty response = 200 OK
    var mock = MockBuilderTransport.init(allocator, "{}");
    defer mock.deinit();

    var b = HttpBuilder.init(allocator, "http://localhost:18550", mock.transport());
    defer b.deinit();

    const api = b.builder();
    const s = try api.status();
    try testing.expectEqual(BuilderStatus.available, s);
    try testing.expect(std.mem.indexOf(u8, mock.last_url.?, "/eth/v1/builder/status") != null);
}

test "HttpBuilder: status check — builder offline" {
    const allocator = testing.allocator;
    var mock = MockBuilderTransport.init(allocator, "");
    mock.force_error = error.ConnectionRefused;
    defer mock.deinit();

    var b = HttpBuilder.init(allocator, "http://localhost:18550", mock.transport());
    defer b.deinit();

    const api = b.builder();
    const s = try api.status();
    try testing.expectEqual(BuilderStatus.unavailable, s);
}

test "HttpBuilder: registerValidators encodes correctly" {
    const allocator = testing.allocator;
    var mock = MockBuilderTransport.init(allocator, "{}");
    defer mock.deinit();

    var b = HttpBuilder.init(allocator, "http://localhost:18550", mock.transport());
    defer b.deinit();

    const reg = SignedValidatorRegistration{
        .message = .{
            .fee_recipient = [_]u8{0xab} ** 20,
            .gas_limit = 30_000_000,
            .timestamp = 1_700_000_000,
            .pubkey = [_]u8{0xcd} ** 48,
        },
        .signature = [_]u8{0xef} ** 96,
    };

    const api = b.builder();
    try api.registerValidators(&[_]SignedValidatorRegistration{reg});

    // URL must contain the validators endpoint
    try testing.expect(std.mem.indexOf(u8, mock.last_url.?, "/eth/v1/builder/validators") != null);
    // Body must be a JSON array
    try testing.expect(mock.last_body.?[0] == '[');
    // Fee recipient must appear hex-encoded
    try testing.expect(std.mem.indexOf(u8, mock.last_body.?, "abababababababababababababababababababab") != null);
}

test "HttpBuilder: registerValidators empty list is no-op" {
    const allocator = testing.allocator;
    var mock = MockBuilderTransport.init(allocator, "");
    defer mock.deinit();

    var b = HttpBuilder.init(allocator, "http://localhost:18550", mock.transport());
    defer b.deinit();

    const api = b.builder();
    // Should not call transport for empty list
    try api.registerValidators(&.{});
    try testing.expect(mock.last_url == null);
}

test "HttpBuilder: getHeader — builds correct URL" {
    const allocator = testing.allocator;
    // No bid available (empty = 204)
    var mock = MockBuilderTransport.init(allocator, "");
    defer mock.deinit();

    var b = HttpBuilder.init(allocator, "http://localhost:18550", mock.transport());
    defer b.deinit();

    const api = b.builder();
    const result = try api.getHeader(
        100,
        [_]u8{0x11} ** 32,
        [_]u8{0x22} ** 48,
    );
    // Empty response = no bid = null
    try testing.expect(result == null);
    // URL must contain slot
    try testing.expect(std.mem.indexOf(u8, mock.last_url.?, "/eth/v1/builder/header/100/") != null);
}

test "HttpBuilder: getHeader — 204 No Content returns null" {
    const allocator = testing.allocator;
    var mock = MockBuilderTransport.init(allocator, "");
    defer mock.deinit();

    var b = HttpBuilder.init(allocator, "http://localhost:18550", mock.transport());
    defer b.deinit();

    const api = b.builder();
    const result = try api.getHeader(42, std.mem.zeroes([32]u8), std.mem.zeroes([48]u8));
    try testing.expect(result == null);
}

test "HttpBuilder: getHeader — builder offline returns null (fallback)" {
    const allocator = testing.allocator;
    var mock = MockBuilderTransport.init(allocator, "");
    mock.force_error = error.ConnectionRefused;
    defer mock.deinit();

    var b = HttpBuilder.init(allocator, "http://localhost:18550", mock.transport());
    defer b.deinit();

    const api = b.builder();
    // On error, getHeader returns null (not an error) — allow fallback to local execution
    const result = try api.getHeader(1, std.mem.zeroes([32]u8), std.mem.zeroes([48]u8));
    try testing.expect(result == null);
}

test "HttpBuilder: getHeader — parses valid bid response" {
    const allocator = testing.allocator;

    // Hardcoded JSON for a relay bid. Values:
    //   parent_hash, state_root, etc. = 0x00*32
    //   fee_recipient = 0xaa*20
    //   block_hash = 0x01*32
    //   pubkey = 0xbb*48
    //   signature = 0xcc*96
    //   value = 0xde0b6b3a7640000 (1 ETH)
    const bid_json: []const u8 = "{\"version\":\"bellatrix\",\"data\":{\"message\":{\"header\":{\"parent_hash\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"fee_recipient\":\"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"state_root\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"receipts_root\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"logs_bloom\":\"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"prev_randao\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"block_number\":\"0x1\",\"gas_limit\":\"0x1c9c380\",\"gas_used\":\"0x5208\",\"timestamp\":\"0x6553f100\",\"extra_data\":\"0x\",\"base_fee_per_gas\":\"0x3b9aca00\",\"block_hash\":\"0x0101010101010101010101010101010101010101010101010101010101010101\",\"transactions_root\":\"0x0000000000000000000000000000000000000000000000000000000000000000\"},\"value\":\"0xde0b6b3a7640000\",\"pubkey\":\"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"},\"signature\":\"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"}}";

    var mock = MockBuilderTransport.init(allocator, bid_json);
    defer mock.deinit();

    var b = HttpBuilder.init(allocator, "http://localhost:18550", mock.transport());
    defer b.deinit();

    const api = b.builder();
    const result = try api.getHeader(1, std.mem.zeroes([32]u8), std.mem.zeroes([48]u8));

    try testing.expect(result != null);
    const bid = result.?;
    // Value = 0xde0b6b3a7640000 = 1_000_000_000_000_000_000 (1 ETH)
    try testing.expectEqual(@as(u256, 1_000_000_000_000_000_000), bid.message.value);
    try testing.expectEqual([_]u8{0x01} ** 32, bid.message.header.block_hash);
    try testing.expectEqual([_]u8{0xbb} ** 48, bid.message.pubkey);
    try testing.expectEqual([_]u8{0xcc} ** 96, bid.signature);
}


test "HttpBuilder: submitBlindedBlock — calls correct endpoint" {
    const allocator = testing.allocator;

    // Minimal payload response with block_hash = 0xde*32
    const response_json: []const u8 = "{\"version\":\"bellatrix\",\"data\":{\"parent_hash\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"fee_recipient\":\"0x0000000000000000000000000000000000000000\",\"state_root\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"receipts_root\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"logs_bloom\":\"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"prev_randao\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"block_number\":\"0x1\",\"gas_limit\":\"0x1c9c380\",\"gas_used\":\"0x0\",\"timestamp\":\"0x6553f100\",\"extra_data\":\"0x\",\"base_fee_per_gas\":\"0x3b9aca00\",\"block_hash\":\"0xdededededededededededededededededededededededededededededededede\",\"transactions\":[],\"withdrawals\":[]}}";

    var mock = MockBuilderTransport.init(allocator, response_json);
    defer mock.deinit();

    var b = HttpBuilder.init(allocator, "http://localhost:18550", mock.transport());
    defer b.deinit();

    const blinded_block = SignedBlindedBeaconBlock{
        .message = .{
            .execution_payload_header = .{
                .parent_hash = std.mem.zeroes([32]u8),
                .fee_recipient = std.mem.zeroes([20]u8),
                .state_root = std.mem.zeroes([32]u8),
                .receipts_root = std.mem.zeroes([32]u8),
                .logs_bloom = std.mem.zeroes([256]u8),
                .prev_randao = std.mem.zeroes([32]u8),
                .block_number = 1,
                .gas_limit = 30_000_000,
                .gas_used = 0,
                .timestamp = 1_700_000_000,
                .extra_data = &.{},
                .base_fee_per_gas = 1_000_000_000,
                .block_hash = [_]u8{0xde} ** 32,
                .transactions_root = std.mem.zeroes([32]u8),
            },
        },
        .signature = [_]u8{0x11} ** 96,
    };

    const api = b.builder();
    const payload = try api.submitBlindedBlock(blinded_block);

    try testing.expect(std.mem.indexOf(u8, mock.last_url.?, "/eth/v1/builder/blinded_blocks") != null);
    try testing.expectEqual([_]u8{0xde} ** 32, payload.block_hash);
}


test "encodeRegistrations: empty returns []" {
    const allocator = testing.allocator;
    const result = try encodeRegistrations(allocator, &.{});
    defer allocator.free(result);
    try testing.expectEqualStrings("[]", result);
}

test "encodeRegistrations: single entry" {
    const allocator = testing.allocator;
    const reg = SignedValidatorRegistration{
        .message = .{
            .fee_recipient = [_]u8{0x00} ** 20,
            .gas_limit = 30_000_000,
            .timestamp = 1_000_000,
            .pubkey = [_]u8{0x00} ** 48,
        },
        .signature = [_]u8{0x00} ** 96,
    };
    const result = try encodeRegistrations(allocator, &[_]SignedValidatorRegistration{reg});
    defer allocator.free(result);
    try testing.expect(result[0] == '[');
    try testing.expect(result[result.len - 1] == ']');
    try testing.expect(std.mem.indexOf(u8, result, "fee_recipient") != null);
    try testing.expect(std.mem.indexOf(u8, result, "gas_limit") != null);
}
