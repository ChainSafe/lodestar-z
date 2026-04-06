//! Keymanager API (EIP-3042) handlers.
//!
//! Implements the REST API for runtime validator key management.
//! Requires bearer token authentication on every request.
//!
//! Endpoints:
//!   GET    /eth/v1/keystores        — list local keys
//!   POST   /eth/v1/keystores        — import keystores
//!   DELETE /eth/v1/keystores        — delete keys + export slashing protection
//!   GET    /eth/v1/remotekeys       — list remote signer keys
//!   POST   /eth/v1/remotekeys       — import remote signer keys
//!   DELETE /eth/v1/remotekeys       — delete remote signer keys
//!   GET    /eth/v1/validator/{pubkey}/feerecipient
//!   POST   /eth/v1/validator/{pubkey}/feerecipient
//!   DELETE /eth/v1/validator/{pubkey}/feerecipient
//!   GET    /eth/v1/validator/{pubkey}/graffiti
//!   POST   /eth/v1/validator/{pubkey}/graffiti
//!   DELETE /eth/v1/validator/{pubkey}/graffiti
//!   GET    /eth/v1/validator/{pubkey}/gas_limit
//!   POST   /eth/v1/validator/{pubkey}/gas_limit
//!   DELETE /eth/v1/validator/{pubkey}/gas_limit
//!   GET    /eth/v1/validator/{pubkey}/builder_boost_factor
//!   POST   /eth/v1/validator/{pubkey}/builder_boost_factor
//!   DELETE /eth/v1/validator/{pubkey}/builder_boost_factor
//!   GET    /eth/v0/validator/{pubkey}/proposer_config
//!   POST   /eth/v1/validator/{pubkey}/voluntary_exit
//!
//! References:
//!   https://ethereum.github.io/keymanager-APIs/
//!
//! TS equivalent: packages/validator/src/api/impl/keymanager/

const std = @import("std");
const context = @import("../context.zig");
const handler_result = @import("../handler_result.zig");
const api_types = @import("../types.zig");
const consensus_types = @import("consensus_types");
const ApiContext = context.ApiContext;
const HandlerResult = handler_result.HandlerResult;
const RemoteKeyInfo = context.RemoteKeyInfo;

/// Validate the bearer token from an auth header.
/// Returns error.Unauthorized if the Keymanager API is disabled or token invalid.
pub fn validateAuth(ctx: *ApiContext, auth_header: ?[]const u8) !void {
    const km = ctx.keymanager orelse return error.KeymanagerDisabled;
    return km.validateTokenFn(km.ptr, auth_header);
}

// ---------------------------------------------------------------------------
// GET /eth/v1/keystores
// ---------------------------------------------------------------------------

/// Import request body.
pub const ImportKeystoresRequest = struct {
    keystores: []const []const u8,
    passwords: []const []const u8,
    slashing_protection: ?api_types.KeymanagerInterchangeFormat = null,
};

pub const DeleteKeysRequest = struct {
    pubkeys: []const []const u8,
};

pub const RemoteKeyRequest = struct {
    pubkey: ?[]const u8 = null,
    url: ?[]const u8 = null,
};

pub const ImportRemoteKeysRequest = struct {
    remote_keys: []const RemoteKeyRequest,
};

pub const FeeRecipientRequest = struct {
    ethaddress: []const u8,
};

pub const GraffitiRequest = struct {
    graffiti: []const u8,
};

const JsonU64 = struct {
    value: u64,

    pub fn jsonParseFromValue(
        allocator: std.mem.Allocator,
        source: std.json.Value,
        options: std.json.ParseOptions,
    ) !@This() {
        _ = allocator;
        _ = options;
        return .{ .value = switch (source) {
            .integer => |n| std.math.cast(u64, n) orelse return error.InvalidRequestBody,
            .number_string => |s| std.fmt.parseInt(u64, s, 10) catch return error.InvalidRequestBody,
            .string => |s| std.fmt.parseInt(u64, s, 10) catch return error.InvalidRequestBody,
            else => return error.InvalidRequestBody,
        } };
    }
};

pub const GasLimitRequest = struct {
    gas_limit: JsonU64,
};

pub const BuilderBoostFactorRequest = struct {
    builder_boost_factor: JsonU64,
};

/// List all loaded local validator keys.
///
/// TS: keymanager.listKeys()
pub fn listKeystores(ctx: *ApiContext, auth_header: ?[]const u8) !HandlerResult([]const api_types.KeymanagerKeystore) {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;

    const keys = try km.listKeysFn(km.ptr, ctx.allocator);
    defer ctx.allocator.free(keys);

    const result = try ctx.allocator.alloc(api_types.KeymanagerKeystore, keys.len);
    for (keys, result) |k, *out| {
        out.* = .{
            .validating_pubkey = k.pubkey,
            .derivation_path = k.derivation_path,
            .readonly = k.readonly,
        };
    }

    return .{ .data = result };
}

/// Import new keystores at runtime.
///
/// For each keystore: decrypt -> add to validator store -> import slashing protection.
///
/// TS: keymanager.importKeystores()
pub fn importKeystores(ctx: *ApiContext, auth_header: ?[]const u8, body: []const u8) !HandlerResult([]const api_types.KeymanagerOperationResult) {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSlice(ImportKeystoresRequest, arena.allocator(), body, .{ .ignore_unknown_fields = true });
    const req = parsed.value;
    if (req.keystores.len != req.passwords.len) return error.MismatchedCounts;

    const results = try ctx.allocator.alloc(api_types.KeymanagerOperationResult, req.keystores.len);
    for (req.keystores, req.passwords, results) |keystore_json, password, *out| {
        const status = km.importKeyFn(km.ptr, keystore_json, password, req.slashing_protection) catch |err| {
            out.* = statusError(@errorName(err));
            continue;
        };
        out.* = .{ .status = status };
    }

    return .{ .data = results };
}

// ---------------------------------------------------------------------------
// DELETE /eth/v1/keystores
// ---------------------------------------------------------------------------

/// Delete keys and export slashing protection for them.
///
/// TS: keymanager.deleteKeystores()
pub fn deleteKeystores(ctx: *ApiContext, auth_header: ?[]const u8, body: []const u8) !HandlerResult(api_types.KeymanagerDeleteKeystoresResponse) {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSlice(DeleteKeysRequest, arena.allocator(), body, .{ .ignore_unknown_fields = true });
    const req = parsed.value;

    const statuses = try ctx.allocator.alloc(api_types.KeymanagerOperationResult, req.pubkeys.len);

    var sp_entries = std.ArrayListUnmanaged(api_types.KeymanagerInterchangeFormat).empty;
    defer {
        for (sp_entries.items) |entry| deinitInterchangeFormat(ctx.allocator, entry);
        sp_entries.deinit(ctx.allocator);
    }

    for (req.pubkeys, statuses) |pk_hex, *out| {
        const pubkey = parseValidatorPubkeyHex(pk_hex) catch |err| {
            out.* = statusError(switch (err) {
                error.InvalidPubkeyLength => "invalid pubkey length",
                error.InvalidPubkeyHex => "invalid pubkey hex",
            });
            continue;
        };

        const result = km.deleteKeyFn(km.ptr, ctx.allocator, pubkey) catch |err| {
            out.* = statusError(@errorName(err));
            continue;
        };
        out.* = .{ .status = result.status };

        if (result.slashing_protection) |slashing_protection| {
            try sp_entries.append(ctx.allocator, slashing_protection);
        }
    }

    const slashing_protection = try buildCombinedSlashingProtection(ctx.allocator, sp_entries.items);

    return .{ .data = .{
        .data = statuses,
        .slashing_protection = slashing_protection,
    } };
}

pub fn deinitDeleteKeystoresResponse(allocator: std.mem.Allocator, data: api_types.KeymanagerDeleteKeystoresResponse) void {
    allocator.free(data.data);
    if (data.slashing_protection) |slashing_protection| {
        deinitInterchangeFormat(allocator, slashing_protection);
    }
}

// ---------------------------------------------------------------------------
// GET /eth/v1/remotekeys
// ---------------------------------------------------------------------------

/// List remote signer keys.
///
/// TS: keymanager.listRemoteKeys()
pub fn listRemoteKeys(ctx: *ApiContext, auth_header: ?[]const u8) !HandlerResult([]const RemoteKeyInfo) {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;

    return .{ .data = try km.listRemoteKeysFn(km.ptr, ctx.allocator) };
}

// ---------------------------------------------------------------------------
// POST /eth/v1/remotekeys
// ---------------------------------------------------------------------------

/// Import remote signer keys.
///
/// TS: keymanager.importRemoteKeys()
pub fn importRemoteKeys(ctx: *ApiContext, auth_header: ?[]const u8, body: []const u8) !HandlerResult([]const api_types.KeymanagerOperationResult) {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSlice(ImportRemoteKeysRequest, arena.allocator(), body, .{ .ignore_unknown_fields = true });
    const req = parsed.value;

    const results = try ctx.allocator.alloc(api_types.KeymanagerOperationResult, req.remote_keys.len);
    for (req.remote_keys, results) |remote_key, *out| {
        const pk_hex = remote_key.pubkey orelse {
            out.* = statusError("missing pubkey");
            continue;
        };
        const url = remote_key.url orelse {
            out.* = statusError("missing url");
            continue;
        };

        const pubkey = parseValidatorPubkeyHex(pk_hex) catch |err| {
            out.* = statusError(switch (err) {
                error.InvalidPubkeyLength => "invalid pubkey",
                error.InvalidPubkeyHex => "invalid pubkey hex",
            });
            continue;
        };

        const status = km.importRemoteKeyFn(km.ptr, pubkey, url) catch |err| {
            out.* = statusError(@errorName(err));
            continue;
        };
        out.* = .{ .status = status };
    }

    return .{ .data = results };
}

// ---------------------------------------------------------------------------
// DELETE /eth/v1/remotekeys
// ---------------------------------------------------------------------------

/// Delete remote signer keys.
///
/// TS: keymanager.deleteRemoteKeys()
pub fn deleteRemoteKeys(ctx: *ApiContext, auth_header: ?[]const u8, body: []const u8) !HandlerResult([]const api_types.KeymanagerOperationResult) {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSlice(DeleteKeysRequest, arena.allocator(), body, .{ .ignore_unknown_fields = true });
    const req = parsed.value;

    const results = try ctx.allocator.alloc(api_types.KeymanagerOperationResult, req.pubkeys.len);
    for (req.pubkeys, results) |pk_hex, *out| {
        const pubkey = parseValidatorPubkeyHex(pk_hex) catch |err| {
            out.* = statusError(switch (err) {
                error.InvalidPubkeyLength => "invalid pubkey length",
                error.InvalidPubkeyHex => "invalid pubkey hex",
            });
            continue;
        };

        const status = km.deleteRemoteKeyFn(km.ptr, pubkey) catch |err| {
            out.* = statusError(@errorName(err));
            continue;
        };
        out.* = .{ .status = status };
    }

    return .{ .data = results };
}

// ---------------------------------------------------------------------------
// GET/POST/DELETE /eth/v1/validator/{pubkey}/feerecipient
// ---------------------------------------------------------------------------

pub fn listFeeRecipient(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8) !HandlerResult(api_types.KeymanagerFeeRecipientData) {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;
    return .{ .data = .{
        .pubkey = pubkey,
        .ethaddress = try km.getFeeRecipientFn(km.ptr, pubkey),
    } };
}

pub fn setFeeRecipient(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8, body: []const u8) !void {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSlice(FeeRecipientRequest, arena.allocator(), body, .{ .ignore_unknown_fields = true });
    try km.setFeeRecipientFn(km.ptr, pubkey, try parseFeeRecipientHex(parsed.value.ethaddress));
}

pub fn deleteFeeRecipient(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8) !void {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;
    try km.deleteFeeRecipientFn(km.ptr, pubkey);
}

// ---------------------------------------------------------------------------
// GET/POST/DELETE /eth/v1/validator/{pubkey}/graffiti
// ---------------------------------------------------------------------------

pub fn getGraffiti(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8) !HandlerResult(api_types.KeymanagerGraffitiData) {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;
    const graffiti = try km.getGraffitiFn(km.ptr, pubkey);
    const graffiti_hex = try formatGraffitiHex(ctx.allocator, graffiti);
    return .{ .data = .{
        .pubkey = pubkey,
        .graffiti = graffiti_hex,
    } };
}

pub fn setGraffiti(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8, body: []const u8) !void {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSlice(GraffitiRequest, arena.allocator(), body, .{ .ignore_unknown_fields = true });
    try km.setGraffitiFn(km.ptr, pubkey, try parseGraffitiHex(parsed.value.graffiti));
}

pub fn deleteGraffiti(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8) !void {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;
    try km.deleteGraffitiFn(km.ptr, pubkey);
}

// ---------------------------------------------------------------------------
// GET/POST/DELETE /eth/v1/validator/{pubkey}/gas_limit
// ---------------------------------------------------------------------------

pub fn getGasLimit(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8) !HandlerResult(api_types.KeymanagerGasLimitData) {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;
    return .{ .data = .{
        .pubkey = pubkey,
        .gas_limit = try km.getGasLimitFn(km.ptr, pubkey),
    } };
}

pub fn setGasLimit(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8, body: []const u8) !void {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSlice(GasLimitRequest, arena.allocator(), body, .{ .ignore_unknown_fields = true });
    try km.setGasLimitFn(km.ptr, pubkey, parsed.value.gas_limit.value);
}

pub fn deleteGasLimit(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8) !void {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;
    try km.deleteGasLimitFn(km.ptr, pubkey);
}

// ---------------------------------------------------------------------------
// GET/POST/DELETE /eth/v1/validator/{pubkey}/builder_boost_factor
// ---------------------------------------------------------------------------

pub fn getBuilderBoostFactor(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8) !HandlerResult(api_types.KeymanagerBuilderBoostFactorData) {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;
    return .{ .data = .{
        .pubkey = pubkey,
        .builder_boost_factor = try km.getBuilderBoostFactorFn(km.ptr, pubkey),
    } };
}

pub fn setBuilderBoostFactor(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8, body: []const u8) !void {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSlice(BuilderBoostFactorRequest, arena.allocator(), body, .{ .ignore_unknown_fields = true });
    try km.setBuilderBoostFactorFn(km.ptr, pubkey, parsed.value.builder_boost_factor.value);
}

pub fn deleteBuilderBoostFactor(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8) !void {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;
    try km.deleteBuilderBoostFactorFn(km.ptr, pubkey);
}

// ---------------------------------------------------------------------------
// GET /eth/v0/validator/{pubkey}/proposer_config
// ---------------------------------------------------------------------------

pub fn getProposerConfig(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8) !HandlerResult(?api_types.KeymanagerProposerConfigData) {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;
    return .{ .data = try km.getProposerConfigFn(km.ptr, ctx.allocator, pubkey) };
}

pub fn deinitProposerConfigData(allocator: std.mem.Allocator, data: ?api_types.KeymanagerProposerConfigData) void {
    if (data) |config| {
        if (config.graffiti) |graffiti| allocator.free(graffiti);
    }
}

// ---------------------------------------------------------------------------
// POST /eth/v1/validator/{pubkey}/voluntary_exit
// ---------------------------------------------------------------------------

pub fn signVoluntaryExit(
    ctx: *ApiContext,
    auth_header: ?[]const u8,
    pubkey: [48]u8,
    epoch: ?u64,
) !HandlerResult(consensus_types.phase0.SignedVoluntaryExit.Type) {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;
    return .{ .data = try km.signVoluntaryExitFn(km.ptr, pubkey, epoch) };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn statusError(message: []const u8) api_types.KeymanagerOperationResult {
    return .{ .status = .@"error", .message = message };
}

const ParseValidatorPubkeyError = error{ InvalidPubkeyLength, InvalidPubkeyHex };

fn parseValidatorPubkeyHex(input: []const u8) ParseValidatorPubkeyError![48]u8 {
    const hex = if (std.mem.startsWith(u8, input, "0x")) input[2..] else input;
    if (hex.len != 96) return error.InvalidPubkeyLength;

    var pubkey: [48]u8 = undefined;
    _ = std.fmt.hexToBytes(&pubkey, hex) catch return error.InvalidPubkeyHex;
    return pubkey;
}

fn parseFeeRecipientHex(input: []const u8) ![20]u8 {
    const hex = if (std.mem.startsWith(u8, input, "0x")) input[2..] else input;
    if (hex.len != 40) return error.InvalidRequestBody;

    var fee_recipient: [20]u8 = undefined;
    _ = std.fmt.hexToBytes(&fee_recipient, hex) catch return error.InvalidRequestBody;
    return fee_recipient;
}

fn parseGraffitiHex(input: []const u8) ![32]u8 {
    const hex = if (std.mem.startsWith(u8, input, "0x")) input[2..] else input;
    if (hex.len > 64 or hex.len % 2 != 0) return error.InvalidRequestBody;

    var graffiti: [32]u8 = [_]u8{0} ** 32;
    const decoded_len = hex.len / 2;
    _ = std.fmt.hexToBytes(graffiti[0..decoded_len], hex) catch return error.InvalidRequestBody;
    if (!std.unicode.utf8ValidateSlice(graffiti[0..decoded_len])) return error.InvalidRequestBody;
    return graffiti;
}

fn formatGraffitiHex(allocator: std.mem.Allocator, graffiti: [32]u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{x}", .{graffiti});
}

fn textToGraffiti(text: []const u8) [32]u8 {
    var graffiti: [32]u8 = [_]u8{0} ** 32;
    const copy_len = @min(text.len, graffiti.len);
    @memcpy(graffiti[0..copy_len], text[0..copy_len]);
    return graffiti;
}

fn buildCombinedSlashingProtection(allocator: std.mem.Allocator, sp_exports: []const api_types.KeymanagerInterchangeFormat) !?api_types.KeymanagerInterchangeFormat {
    var metadata: ?api_types.KeymanagerInterchangeMetadata = null;
    var merged_items = std.ArrayListUnmanaged(api_types.KeymanagerInterchangeData).empty;
    errdefer {
        if (metadata) |value| {
            allocator.free(value.interchange_format_version);
            allocator.free(value.genesis_validators_root);
        }
        deinitInterchangeDataSlice(allocator, merged_items.items);
        merged_items.deinit(allocator);
    }

    for (sp_exports) |parsed| {
        if (metadata) |expected_metadata| {
            if (!std.mem.eql(u8, expected_metadata.interchange_format_version, parsed.metadata.interchange_format_version)) {
                return error.InvalidInterchangeJson;
            }
            if (!std.mem.eql(u8, expected_metadata.genesis_validators_root, parsed.metadata.genesis_validators_root)) {
                return error.GenesisValidatorsRootMismatch;
            }
        } else {
            metadata = .{
                .interchange_format_version = try allocator.dupe(u8, parsed.metadata.interchange_format_version),
                .genesis_validators_root = try allocator.dupe(u8, parsed.metadata.genesis_validators_root),
            };
        }

        for (parsed.data) |item| {
            try merged_items.append(allocator, try cloneInterchangeData(allocator, item));
        }
    }

    if (metadata == null) return null;
    return .{
        .metadata = metadata.?,
        .data = try merged_items.toOwnedSlice(allocator),
    };
}

fn cloneInterchangeFormat(allocator: std.mem.Allocator, value: api_types.KeymanagerInterchangeFormat) !api_types.KeymanagerInterchangeFormat {
    const out_data = try allocator.alloc(api_types.KeymanagerInterchangeData, value.data.len);
    errdefer allocator.free(out_data);
    var copied: usize = 0;
    errdefer {
        deinitInterchangeDataSlice(allocator, out_data[0..copied]);
    }

    for (value.data, 0..) |item, i| {
        out_data[i] = try cloneInterchangeData(allocator, item);
        copied += 1;
    }

    return .{
        .metadata = .{
            .interchange_format_version = try allocator.dupe(u8, value.metadata.interchange_format_version),
            .genesis_validators_root = try allocator.dupe(u8, value.metadata.genesis_validators_root),
        },
        .data = out_data,
    };
}

fn cloneInterchangeData(allocator: std.mem.Allocator, value: api_types.KeymanagerInterchangeData) !api_types.KeymanagerInterchangeData {
    const signed_blocks = try allocator.alloc(api_types.KeymanagerInterchangeSignedBlock, value.signed_blocks.len);
    errdefer allocator.free(signed_blocks);
    var blocks_copied: usize = 0;
    errdefer {
        for (signed_blocks[0..blocks_copied]) |signed_block| {
            allocator.free(signed_block.slot);
            if (signed_block.signing_root) |signing_root| allocator.free(signing_root);
        }
    }
    for (value.signed_blocks, 0..) |signed_block, i| {
        signed_blocks[i] = .{
            .slot = try allocator.dupe(u8, signed_block.slot),
            .signing_root = if (signed_block.signing_root) |signing_root| try allocator.dupe(u8, signing_root) else null,
        };
        blocks_copied += 1;
    }

    const signed_attestations = try allocator.alloc(api_types.KeymanagerInterchangeSignedAttestation, value.signed_attestations.len);
    errdefer allocator.free(signed_attestations);
    var attestations_copied: usize = 0;
    errdefer {
        for (signed_attestations[0..attestations_copied]) |signed_attestation| {
            allocator.free(signed_attestation.source_epoch);
            allocator.free(signed_attestation.target_epoch);
            if (signed_attestation.signing_root) |signing_root| allocator.free(signing_root);
        }
    }
    for (value.signed_attestations, 0..) |signed_attestation, i| {
        signed_attestations[i] = .{
            .source_epoch = try allocator.dupe(u8, signed_attestation.source_epoch),
            .target_epoch = try allocator.dupe(u8, signed_attestation.target_epoch),
            .signing_root = if (signed_attestation.signing_root) |signing_root| try allocator.dupe(u8, signing_root) else null,
        };
        attestations_copied += 1;
    }

    return .{
        .pubkey = try allocator.dupe(u8, value.pubkey),
        .signed_blocks = signed_blocks,
        .signed_attestations = signed_attestations,
    };
}

fn deinitInterchangeFormat(allocator: std.mem.Allocator, value: api_types.KeymanagerInterchangeFormat) void {
    allocator.free(value.metadata.interchange_format_version);
    allocator.free(value.metadata.genesis_validators_root);
    deinitInterchangeDataSlice(allocator, value.data);
    allocator.free(value.data);
}

fn deinitInterchangeDataSlice(allocator: std.mem.Allocator, items: []const api_types.KeymanagerInterchangeData) void {
    for (items) |item| {
        allocator.free(item.pubkey);
        for (item.signed_blocks) |signed_block| {
            allocator.free(signed_block.slot);
            if (signed_block.signing_root) |signing_root| allocator.free(signing_root);
        }
        allocator.free(item.signed_blocks);
        for (item.signed_attestations) |signed_attestation| {
            allocator.free(signed_attestation.source_epoch);
            allocator.free(signed_attestation.target_epoch);
            if (signed_attestation.signing_root) |signing_root| allocator.free(signing_root);
        }
        allocator.free(item.signed_attestations);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

// Mock KeymanagerCallback for tests.
const RemoteEntry = struct { pubkey: [48]u8, url: []const u8 };

const TestKeyState = struct {
    allocator: std.mem.Allocator,
    token: []const u8,
    local_keys: std.ArrayListUnmanaged([48]u8),
    remote_keys: std.ArrayListUnmanaged(RemoteEntry),
    fee_recipients: std.AutoHashMapUnmanaged([48]u8, [20]u8),
    graffitis: std.AutoHashMapUnmanaged([48]u8, [32]u8),
    gas_limits: std.AutoHashMapUnmanaged([48]u8, u64),
    builder_boost_factors: std.AutoHashMapUnmanaged([48]u8, u64),
    delete_key_slashing_exports: std.AutoHashMapUnmanaged([48]u8, api_types.KeymanagerInterchangeFormat),
    last_import_slashing_protection: ?api_types.KeymanagerInterchangeFormat,

    fn init(allocator: std.mem.Allocator, token: []const u8) !*TestKeyState {
        const self = try allocator.create(TestKeyState);
        self.allocator = allocator;
        self.token = token;
        self.local_keys = .empty;
        self.remote_keys = .empty;
        self.fee_recipients = .empty;
        self.graffitis = .empty;
        self.gas_limits = .empty;
        self.builder_boost_factors = .empty;
        self.delete_key_slashing_exports = .empty;
        self.last_import_slashing_protection = null;
        return self;
    }

    fn deinit(self: *TestKeyState) void {
        self.local_keys.deinit(self.allocator);
        for (self.remote_keys.items) |rk| self.allocator.free(rk.url);
        self.remote_keys.deinit(self.allocator);
        self.fee_recipients.deinit(self.allocator);
        self.graffitis.deinit(self.allocator);
        self.gas_limits.deinit(self.allocator);
        self.builder_boost_factors.deinit(self.allocator);
        var slashing_export_it = self.delete_key_slashing_exports.valueIterator();
        while (slashing_export_it.next()) |value| deinitInterchangeFormat(self.allocator, value.*);
        self.delete_key_slashing_exports.deinit(self.allocator);
        if (self.last_import_slashing_protection) |value| deinitInterchangeFormat(self.allocator, value);
        self.allocator.destroy(self);
    }

    fn callback(self: *TestKeyState) context.KeymanagerCallback {
        return .{
            .ptr = @ptrCast(self),
            .validateTokenFn = TestKeyState.validateToken,
            .listKeysFn = TestKeyState.listKeys,
            .importKeyFn = TestKeyState.importKey,
            .deleteKeyFn = TestKeyState.deleteKey,
            .listRemoteKeysFn = TestKeyState.listRemoteKeys2,
            .importRemoteKeyFn = TestKeyState.importRemoteKey,
            .deleteRemoteKeyFn = TestKeyState.deleteRemoteKey,
            .getFeeRecipientFn = TestKeyState.getFeeRecipient,
            .setFeeRecipientFn = TestKeyState.setFeeRecipient,
            .deleteFeeRecipientFn = TestKeyState.deleteFeeRecipient,
            .getGraffitiFn = TestKeyState.getGraffiti,
            .setGraffitiFn = TestKeyState.setGraffiti,
            .deleteGraffitiFn = TestKeyState.deleteGraffiti,
            .getGasLimitFn = TestKeyState.getGasLimit,
            .setGasLimitFn = TestKeyState.setGasLimit,
            .deleteGasLimitFn = TestKeyState.deleteGasLimit,
            .getBuilderBoostFactorFn = TestKeyState.getBuilderBoostFactor,
            .setBuilderBoostFactorFn = TestKeyState.setBuilderBoostFactor,
            .deleteBuilderBoostFactorFn = TestKeyState.deleteBuilderBoostFactor,
            .getProposerConfigFn = TestKeyState.getProposerConfig,
            .signVoluntaryExitFn = TestKeyState.signVoluntaryExit,
        };
    }

    fn validateToken(ptr: *anyopaque, auth_header: ?[]const u8) anyerror!void {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        const header = auth_header orelse return error.Unauthorized;
        const prefix = "Bearer ";
        if (!std.mem.startsWith(u8, header, prefix)) return error.Unauthorized;
        if (!std.mem.eql(u8, header[prefix.len..], self.token)) return error.Unauthorized;
    }

    fn listKeys(ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]context.ValidatorKeyInfo {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        const result = try allocator.alloc(context.ValidatorKeyInfo, self.local_keys.items.len);
        for (self.local_keys.items, result) |k, *out| {
            out.* = .{ .pubkey = k, .derivation_path = "", .readonly = false };
        }
        return result;
    }

    fn importKey(ptr: *anyopaque, keystore_json: []const u8, password: []const u8, slashing_protection: ?api_types.KeymanagerInterchangeFormat) anyerror!api_types.KeymanagerOperationStatus {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        _ = password;
        _ = keystore_json;
        if (self.last_import_slashing_protection) |value| deinitInterchangeFormat(self.allocator, value);
        self.last_import_slashing_protection = if (slashing_protection) |value|
            try cloneInterchangeFormat(self.allocator, value)
        else
            null;
        const dummy_pubkey = [_]u8{0xaa} ** 48;
        for (self.local_keys.items) |k| {
            if (std.mem.eql(u8, &k, &dummy_pubkey)) return .duplicate;
        }
        try self.local_keys.append(self.allocator, dummy_pubkey);
        return .imported;
    }

    fn deleteKey(ptr: *anyopaque, allocator: std.mem.Allocator, pubkey: [48]u8) anyerror!context.DeleteKeyResult {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        for (self.local_keys.items, 0..) |k, idx| {
            if (std.mem.eql(u8, &k, &pubkey)) {
                _ = self.local_keys.swapRemove(idx);
                return .{
                    .status = .deleted,
                    .slashing_protection = if (self.delete_key_slashing_exports.get(pubkey)) |value|
                        try cloneInterchangeFormat(allocator, value)
                    else
                        null,
                };
            }
        }
        return .{
            .status = .not_found,
            .slashing_protection = null,
        };
    }

    fn listRemoteKeys2(ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]context.RemoteKeyInfo {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        const result = try allocator.alloc(context.RemoteKeyInfo, self.remote_keys.items.len);
        for (self.remote_keys.items, result) |rk, *out| {
            out.* = .{ .pubkey = rk.pubkey, .url = rk.url, .readonly = false };
        }
        return result;
    }

    fn importRemoteKey(ptr: *anyopaque, pubkey: [48]u8, url: []const u8) anyerror!api_types.KeymanagerOperationStatus {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        for (self.remote_keys.items) |rk| {
            if (std.mem.eql(u8, &rk.pubkey, &pubkey)) return .duplicate;
        }
        const url_copy = try self.allocator.dupe(u8, url);
        try self.remote_keys.append(self.allocator, RemoteEntry{ .pubkey = pubkey, .url = url_copy });
        return .imported;
    }

    fn deleteRemoteKey(ptr: *anyopaque, pubkey: [48]u8) anyerror!api_types.KeymanagerOperationStatus {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        for (self.remote_keys.items, 0..) |rk, idx| {
            if (std.mem.eql(u8, &rk.pubkey, &pubkey)) {
                const url = self.remote_keys.items[idx].url;
                self.allocator.free(url);
                _ = self.remote_keys.swapRemove(idx);
                return .deleted;
            }
        }
        return .not_found;
    }

    fn getFeeRecipient(ptr: *anyopaque, pubkey: [48]u8) anyerror![20]u8 {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        try self.ensureKnownPubkey(pubkey);
        return self.fee_recipients.get(pubkey) orelse [_]u8{0x11} ** 20;
    }

    fn setFeeRecipient(ptr: *anyopaque, pubkey: [48]u8, fee_recipient: [20]u8) anyerror!void {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        try self.ensureKnownPubkey(pubkey);
        try self.fee_recipients.put(self.allocator, pubkey, fee_recipient);
    }

    fn deleteFeeRecipient(ptr: *anyopaque, pubkey: [48]u8) anyerror!void {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        try self.ensureKnownPubkey(pubkey);
        _ = self.fee_recipients.remove(pubkey);
    }

    fn getGraffiti(ptr: *anyopaque, pubkey: [48]u8) anyerror![32]u8 {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        try self.ensureKnownPubkey(pubkey);
        return self.graffitis.get(pubkey) orelse textToGraffiti("test-graffiti");
    }

    fn setGraffiti(ptr: *anyopaque, pubkey: [48]u8, graffiti: [32]u8) anyerror!void {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        try self.ensureKnownPubkey(pubkey);
        try self.graffitis.put(self.allocator, pubkey, graffiti);
    }

    fn deleteGraffiti(ptr: *anyopaque, pubkey: [48]u8) anyerror!void {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        try self.ensureKnownPubkey(pubkey);
        _ = self.graffitis.remove(pubkey);
    }

    fn getGasLimit(ptr: *anyopaque, pubkey: [48]u8) anyerror!u64 {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        try self.ensureKnownPubkey(pubkey);
        return self.gas_limits.get(pubkey) orelse 60_000_000;
    }

    fn setGasLimit(ptr: *anyopaque, pubkey: [48]u8, gas_limit: u64) anyerror!void {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        try self.ensureKnownPubkey(pubkey);
        try self.gas_limits.put(self.allocator, pubkey, gas_limit);
    }

    fn deleteGasLimit(ptr: *anyopaque, pubkey: [48]u8) anyerror!void {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        try self.ensureKnownPubkey(pubkey);
        _ = self.gas_limits.remove(pubkey);
    }

    fn getBuilderBoostFactor(ptr: *anyopaque, pubkey: [48]u8) anyerror!u64 {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        try self.ensureKnownPubkey(pubkey);
        return self.builder_boost_factors.get(pubkey) orelse 100;
    }

    fn setBuilderBoostFactor(ptr: *anyopaque, pubkey: [48]u8, builder_boost_factor: u64) anyerror!void {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        try self.ensureKnownPubkey(pubkey);
        try self.builder_boost_factors.put(self.allocator, pubkey, builder_boost_factor);
    }

    fn deleteBuilderBoostFactor(ptr: *anyopaque, pubkey: [48]u8) anyerror!void {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        try self.ensureKnownPubkey(pubkey);
        _ = self.builder_boost_factors.remove(pubkey);
    }

    fn getProposerConfig(ptr: *anyopaque, allocator: std.mem.Allocator, pubkey: [48]u8) anyerror!?api_types.KeymanagerProposerConfigData {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        try self.ensureKnownPubkey(pubkey);

        _ = allocator;
        if (self.fee_recipients.get(pubkey)) |fee_recipient| {
            return .{ .feeRecipient = fee_recipient };
        }

        return null;
    }

    fn signVoluntaryExit(
        ptr: *anyopaque,
        pubkey: [48]u8,
        epoch: ?u64,
    ) anyerror!consensus_types.phase0.SignedVoluntaryExit.Type {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        try self.ensureKnownPubkey(pubkey);
        return .{
            .message = .{ .epoch = epoch orelse 0, .validator_index = 1 },
            .signature = [_]u8{0xaa} ** 96,
        };
    }

    fn ensureKnownPubkey(self: *const TestKeyState, pubkey: [48]u8) !void {
        for (self.local_keys.items) |key| {
            if (std.mem.eql(u8, &key, &pubkey)) return;
        }
        for (self.remote_keys.items) |remote_key| {
            if (std.mem.eql(u8, &remote_key.pubkey, &pubkey)) return;
        }
        return error.ValidatorNotFound;
    }
};

fn makeTestCtx(allocator: std.mem.Allocator, state: *TestKeyState) !context.ApiContext {
    const test_helpers = @import("../test_helpers.zig");
    var tc = test_helpers.makeTestContext(allocator);
    const km = state.callback();
    tc.ctx.keymanager = km;
    return tc.ctx;
}

test "listKeystores: returns empty list" {
    var state = try TestKeyState.init(testing.allocator, "mytoken");
    defer state.deinit();

    const test_helpers = @import("../test_helpers.zig");
    var tc = test_helpers.makeTestContext(testing.allocator);
    defer test_helpers.destroyTestContext(testing.allocator, &tc);
    const km = state.callback();
    tc.ctx.keymanager = km;

    const resp = try listKeystores(&tc.ctx, "Bearer mytoken");
    defer testing.allocator.free(resp.data);
    try testing.expectEqual(@as(usize, 0), resp.data.len);
}

test "listKeystores: unauthorized without token" {
    var state = try TestKeyState.init(testing.allocator, "mytoken");
    defer state.deinit();

    const test_helpers = @import("../test_helpers.zig");
    var tc = test_helpers.makeTestContext(testing.allocator);
    defer test_helpers.destroyTestContext(testing.allocator, &tc);
    const km = state.callback();
    tc.ctx.keymanager = km;

    try testing.expectError(error.Unauthorized, listKeystores(&tc.ctx, null));
}

test "importKeystores: forwards typed slashing protection object" {
    var state = try TestKeyState.init(testing.allocator, "token");
    defer state.deinit();

    const test_helpers = @import("../test_helpers.zig");
    var tc = test_helpers.makeTestContext(testing.allocator);
    defer test_helpers.destroyTestContext(testing.allocator, &tc);
    tc.ctx.keymanager = state.callback();

    const body =
        \\{"keystores":["{}"],"passwords":["pass"],"slashing_protection":{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x1111111111111111111111111111111111111111111111111111111111111111"},"data":[]}}
    ;
    const resp = try importKeystores(&tc.ctx, "Bearer token", body);
    defer testing.allocator.free(resp.data);

    try testing.expectEqual(api_types.KeymanagerOperationStatus.imported, resp.data[0].status);
    try testing.expect(state.last_import_slashing_protection != null);
    const slashing_protection = state.last_import_slashing_protection.?;
    try testing.expectEqualStrings("5", slashing_protection.metadata.interchange_format_version);
    try testing.expectEqualStrings("0x1111111111111111111111111111111111111111111111111111111111111111", slashing_protection.metadata.genesis_validators_root);
    try testing.expectEqual(@as(usize, 0), slashing_protection.data.len);
}

test "importKeystores: imports and returns status" {
    var state = try TestKeyState.init(testing.allocator, "token");
    defer state.deinit();

    const test_helpers = @import("../test_helpers.zig");
    var tc = test_helpers.makeTestContext(testing.allocator);
    defer test_helpers.destroyTestContext(testing.allocator, &tc);
    const km = state.callback();
    tc.ctx.keymanager = km;

    const body =
        \\{"keystores":["{}"],"passwords":["pass"]}
    ;
    const resp = try importKeystores(&tc.ctx, "Bearer token", body);
    defer testing.allocator.free(resp.data);
    try testing.expectEqual(api_types.KeymanagerOperationStatus.imported, resp.data[0].status);
}

test "deleteKeystores: deletes known key" {
    var state = try TestKeyState.init(testing.allocator, "token");
    defer state.deinit();

    const dummy_pubkey = [_]u8{0xaa} ** 48;
    try state.local_keys.append(testing.allocator, dummy_pubkey);

    const test_helpers = @import("../test_helpers.zig");
    var tc = test_helpers.makeTestContext(testing.allocator);
    defer test_helpers.destroyTestContext(testing.allocator, &tc);
    const km = state.callback();
    tc.ctx.keymanager = km;

    const body = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"pubkeys\":[\"0x{s}\"]}}",
        .{std.fmt.bytesToHex(dummy_pubkey, .lower)},
    );
    defer testing.allocator.free(body);

    const resp = try deleteKeystores(&tc.ctx, "Bearer token", body);
    defer deinitDeleteKeystoresResponse(testing.allocator, resp.data);
    try testing.expectEqual(@as(usize, 1), resp.data.data.len);
    try testing.expectEqual(api_types.KeymanagerOperationStatus.deleted, resp.data.data[0].status);
    try testing.expect(resp.data.slashing_protection == null);
}

test "deleteKeystores: merges slashing protection exports across keys" {
    var state = try TestKeyState.init(testing.allocator, "token");
    defer state.deinit();

    const pubkey_a = [_]u8{0xa1} ** 48;
    const pubkey_b = [_]u8{0xb2} ** 48;
    try state.local_keys.append(testing.allocator, pubkey_a);
    try state.local_keys.append(testing.allocator, pubkey_b);

    const export_a = try cloneInterchangeFormat(testing.allocator, .{
        .metadata = .{
            .interchange_format_version = "5",
            .genesis_validators_root = "0x1111111111111111111111111111111111111111111111111111111111111111",
        },
        .data = &.{.{
            .pubkey = "0x" ++ "a1" ** 48,
            .signed_blocks = &.{.{ .slot = "12", .signing_root = null }},
            .signed_attestations = &.{.{ .source_epoch = "3", .target_epoch = "5", .signing_root = null }},
        }},
    });
    try state.delete_key_slashing_exports.put(testing.allocator, pubkey_a, export_a);

    const export_b = try cloneInterchangeFormat(testing.allocator, .{
        .metadata = .{
            .interchange_format_version = "5",
            .genesis_validators_root = "0x1111111111111111111111111111111111111111111111111111111111111111",
        },
        .data = &.{.{
            .pubkey = "0x" ++ "b2" ** 48,
            .signed_blocks = &.{.{ .slot = "19", .signing_root = null }},
            .signed_attestations = &.{.{ .source_epoch = "7", .target_epoch = "9", .signing_root = null }},
        }},
    });
    try state.delete_key_slashing_exports.put(testing.allocator, pubkey_b, export_b);

    const test_helpers = @import("../test_helpers.zig");
    var tc = test_helpers.makeTestContext(testing.allocator);
    defer test_helpers.destroyTestContext(testing.allocator, &tc);
    tc.ctx.keymanager = state.callback();

    const body = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"pubkeys\":[\"0x{s}\",\"0x{s}\"]}}",
        .{ std.fmt.bytesToHex(pubkey_a, .lower), std.fmt.bytesToHex(pubkey_b, .lower) },
    );
    defer testing.allocator.free(body);

    const resp = try deleteKeystores(&tc.ctx, "Bearer token", body);
    defer deinitDeleteKeystoresResponse(testing.allocator, resp.data);

    try testing.expect(resp.data.slashing_protection != null);
    const slashing_protection = resp.data.slashing_protection.?;
    try testing.expectEqual(@as(usize, 2), slashing_protection.data.len);
    try testing.expectEqualStrings("5", slashing_protection.metadata.interchange_format_version);
    try testing.expectEqualStrings("0x1111111111111111111111111111111111111111111111111111111111111111", slashing_protection.metadata.genesis_validators_root);
    try testing.expectEqualStrings("0x" ++ "a1" ** 48, slashing_protection.data[0].pubkey);
    try testing.expectEqualStrings("12", slashing_protection.data[0].signed_blocks[0].slot);
    try testing.expectEqualStrings("0x" ++ "b2" ** 48, slashing_protection.data[1].pubkey);
    try testing.expectEqualStrings("19", slashing_protection.data[1].signed_blocks[0].slot);
}

test "listRemoteKeys: returns empty list" {
    var state = try TestKeyState.init(testing.allocator, "token");
    defer state.deinit();

    const test_helpers = @import("../test_helpers.zig");
    var tc = test_helpers.makeTestContext(testing.allocator);
    defer test_helpers.destroyTestContext(testing.allocator, &tc);
    const km = state.callback();
    tc.ctx.keymanager = km;

    const resp = try listRemoteKeys(&tc.ctx, "Bearer token");
    defer testing.allocator.free(resp.data);
    try testing.expectEqual(@as(usize, 0), resp.data.len);
}

test "importRemoteKeys: imports a remote key" {
    var state = try TestKeyState.init(testing.allocator, "token");
    defer state.deinit();

    const test_helpers = @import("../test_helpers.zig");
    var tc = test_helpers.makeTestContext(testing.allocator);
    defer test_helpers.destroyTestContext(testing.allocator, &tc);
    const km = state.callback();
    tc.ctx.keymanager = km;

    const pubkey_hex = "0x" ++ "cd" ** 48;
    const body = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"remote_keys\":[{{\"pubkey\":\"{s}\",\"url\":\"http://signer:9000\"}}]}}",
        .{pubkey_hex},
    );
    defer testing.allocator.free(body);

    const resp = try importRemoteKeys(&tc.ctx, "Bearer token", body);
    defer testing.allocator.free(resp.data);
    try testing.expectEqual(api_types.KeymanagerOperationStatus.imported, resp.data[0].status);
}

test "getGasLimit: returns typed data" {
    var state = try TestKeyState.init(testing.allocator, "token");
    defer state.deinit();

    const dummy_pubkey = [_]u8{0xaa} ** 48;
    try state.local_keys.append(testing.allocator, dummy_pubkey);
    try state.gas_limits.put(testing.allocator, dummy_pubkey, 42_000_000);

    const test_helpers = @import("../test_helpers.zig");
    var tc = test_helpers.makeTestContext(testing.allocator);
    defer test_helpers.destroyTestContext(testing.allocator, &tc);
    tc.ctx.keymanager = state.callback();

    const resp = try getGasLimit(&tc.ctx, "Bearer token", dummy_pubkey);
    try testing.expectEqual(dummy_pubkey, resp.data.pubkey);
    try testing.expectEqual(@as(u64, 42_000_000), resp.data.gas_limit);
}

test "getBuilderBoostFactor: returns typed data" {
    var state = try TestKeyState.init(testing.allocator, "token");
    defer state.deinit();

    const dummy_pubkey = [_]u8{0xbb} ** 48;
    try state.local_keys.append(testing.allocator, dummy_pubkey);
    try state.builder_boost_factors.put(testing.allocator, dummy_pubkey, 175);

    const test_helpers = @import("../test_helpers.zig");
    var tc = test_helpers.makeTestContext(testing.allocator);
    defer test_helpers.destroyTestContext(testing.allocator, &tc);
    tc.ctx.keymanager = state.callback();

    const resp = try getBuilderBoostFactor(&tc.ctx, "Bearer token", dummy_pubkey);
    try testing.expectEqual(dummy_pubkey, resp.data.pubkey);
    try testing.expectEqual(@as(u64, 175), resp.data.builder_boost_factor);
}

test "getProposerConfig: returns typed sparse config" {
    var state = try TestKeyState.init(testing.allocator, "token");
    defer state.deinit();

    const dummy_pubkey = [_]u8{0xcc} ** 48;
    try state.local_keys.append(testing.allocator, dummy_pubkey);
    try state.fee_recipients.put(testing.allocator, dummy_pubkey, [_]u8{0x22} ** 20);

    const test_helpers = @import("../test_helpers.zig");
    var tc = test_helpers.makeTestContext(testing.allocator);
    defer test_helpers.destroyTestContext(testing.allocator, &tc);
    tc.ctx.keymanager = state.callback();

    const resp = try getProposerConfig(&tc.ctx, "Bearer token", dummy_pubkey);
    defer deinitProposerConfigData(testing.allocator, resp.data);
    try testing.expect(resp.data != null);
    try testing.expectEqual(([_]u8{0x22} ** 20), resp.data.?.feeRecipient.?);
    try testing.expectEqual(@as(?api_types.KeymanagerProposerConfigBuilderData, null), resp.data.?.builder);
}
