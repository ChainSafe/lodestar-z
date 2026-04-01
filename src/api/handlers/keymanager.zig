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
const ApiContext = context.ApiContext;
const KeymanagerCallback = context.KeymanagerCallback;
const ValidatorKeyInfo = context.ValidatorKeyInfo;
const RemoteKeyInfo = context.RemoteKeyInfo;

const log = std.log.scoped(.keymanager_api);

/// Validate the bearer token from an auth header.
/// Returns error.Unauthorized if the Keymanager API is disabled or token invalid.
pub fn validateAuth(ctx: *ApiContext, auth_header: ?[]const u8) !void {
    const km = ctx.keymanager orelse return error.KeymanagerDisabled;
    return km.validateTokenFn(km.ptr, auth_header);
}

// ---------------------------------------------------------------------------
// GET /eth/v1/keystores
// ---------------------------------------------------------------------------

/// Response item for a single local key.
pub const KeystoreItem = struct {
    validating_pubkey: []const u8,
    derivation_path: []const u8,
    readonly: bool,
};

/// List all loaded local validator keys.
///
/// TS: keymanager.listKeys()
pub fn listKeystores(ctx: *ApiContext, auth_header: ?[]const u8) ![]u8 {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;

    const keys = try km.listKeysFn(km.ptr, ctx.allocator);
    defer {
        for (keys) |k| {
            _ = k; // ValidatorKeyInfo fields are not owned by the slice
        }
        ctx.allocator.free(keys);
    }

    var buf = std.ArrayListUnmanaged(u8).empty;
    errdefer buf.deinit(ctx.allocator);

    try buf.appendSlice(ctx.allocator, "{\"data\":[");
    for (keys, 0..) |k, i| {
        if (i > 0) try buf.appendSlice(ctx.allocator, ",");
        const entry = try std.fmt.allocPrint(ctx.allocator,
            "{{\"validating_pubkey\":\"0x{s}\",\"derivation_path\":\"{s}\",\"readonly\":{s}}}",
            .{
                std.fmt.bytesToHex(k.pubkey, .lower),
                k.derivation_path,
                if (k.readonly) "true" else "false",
            },
        );
        defer ctx.allocator.free(entry);
        try buf.appendSlice(ctx.allocator, entry);
    }
    try buf.appendSlice(ctx.allocator, "]}");

    return buf.toOwnedSlice(ctx.allocator);
}

// ---------------------------------------------------------------------------
// POST /eth/v1/keystores
// ---------------------------------------------------------------------------

/// Import request body.
pub const ImportKeystoresRequest = struct {
    keystores: []const []const u8,
    passwords: []const []const u8,
    slashing_protection: ?[]const u8,
};

/// Import new keystores at runtime.
///
/// For each keystore: decrypt → add to validator store → import slashing protection.
/// Returns status per keystore: "imported", "duplicate", or "error".
///
/// TS: keymanager.importKeystores()
pub fn importKeystores(ctx: *ApiContext, auth_header: ?[]const u8, body: []const u8) ![]u8 {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;

    // Parse request body.
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = try std.json.parseFromSlice(std.json.Value, a, body, .{});
    const root_obj = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.InvalidRequestBody,
    };

    const keystores_val = root_obj.get("keystores") orelse return error.MissingField;
    const keystores_arr = switch (keystores_val) {
        .array => |arr| arr,
        else => return error.InvalidRequestBody,
    };

    const passwords_val = root_obj.get("passwords") orelse return error.MissingField;
    const passwords_arr = switch (passwords_val) {
        .array => |arr| arr,
        else => return error.InvalidRequestBody,
    };

    if (keystores_arr.items.len != passwords_arr.items.len) return error.MismatchedCounts;

    const slashing_protection: ?[]const u8 = blk: {
        const sp_val = root_obj.get("slashing_protection") orelse break :blk null;
        break :blk switch (sp_val) {
            .string => |s| s,
            else => null,
        };
    };

    var buf = std.ArrayListUnmanaged(u8).empty;
    errdefer buf.deinit(ctx.allocator);
    try buf.appendSlice(ctx.allocator, "{\"data\":[");

    for (keystores_arr.items, passwords_arr.items, 0..) |ks_val, pw_val, i| {
        if (i > 0) try buf.appendSlice(ctx.allocator, ",");

        const ks_json = switch (ks_val) {
            .string => |s| s,
            else => {
                try buf.appendSlice(ctx.allocator, "{\"status\":\"error\",\"message\":\"keystore must be a JSON string\"}");
                continue;
            },
        };
        const password = switch (pw_val) {
            .string => |s| s,
            else => {
                try buf.appendSlice(ctx.allocator, "{\"status\":\"error\",\"message\":\"password must be a string\"}");
                continue;
            },
        };

        const status = km.importKeyFn(km.ptr, ctx.allocator, ks_json, password, slashing_protection) catch |err| {
            const msg = try std.fmt.allocPrint(ctx.allocator, "{{\"status\":\"error\",\"message\":\"{s}\"}}", .{@errorName(err)});
            defer ctx.allocator.free(msg);
            try buf.appendSlice(ctx.allocator, msg);
            continue;
        };
        defer ctx.allocator.free(status);

        const entry = try std.fmt.allocPrint(ctx.allocator, "{{\"status\":\"{s}\",\"message\":\"\"}}", .{status});
        defer ctx.allocator.free(entry);
        try buf.appendSlice(ctx.allocator, entry);
    }

    try buf.appendSlice(ctx.allocator, "]}");
    return buf.toOwnedSlice(ctx.allocator);
}

// ---------------------------------------------------------------------------
// DELETE /eth/v1/keystores
// ---------------------------------------------------------------------------

/// Delete keys and export slashing protection for them.
///
/// TS: keymanager.deleteKeystores()
pub fn deleteKeystores(ctx: *ApiContext, auth_header: ?[]const u8, body: []const u8) ![]u8 {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = try std.json.parseFromSlice(std.json.Value, a, body, .{});
    const root_obj = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.InvalidRequestBody,
    };

    const pubkeys_val = root_obj.get("pubkeys") orelse return error.MissingField;
    const pubkeys_arr = switch (pubkeys_val) {
        .array => |arr| arr,
        else => return error.InvalidRequestBody,
    };

    var statuses = std.ArrayListUnmanaged(u8).empty;
    errdefer statuses.deinit(ctx.allocator);
    try statuses.appendSlice(ctx.allocator, "[");

    // Collect all slashing protection data for export.
    var sp_entries = std.ArrayListUnmanaged([]const u8).empty;
    defer {
        for (sp_entries.items) |e| ctx.allocator.free(e);
        sp_entries.deinit(ctx.allocator);
    }

    for (pubkeys_arr.items, 0..) |pk_val, i| {
        if (i > 0) try statuses.appendSlice(ctx.allocator, ",");

        const pk_hex = switch (pk_val) {
            .string => |s| s,
            else => {
                try statuses.appendSlice(ctx.allocator, "{\"status\":\"error\",\"message\":\"pubkey must be a string\"}");
                continue;
            },
        };

        // Decode pubkey hex (strip "0x" prefix if present).
        const hex = if (std.mem.startsWith(u8, pk_hex, "0x")) pk_hex[2..] else pk_hex;
        if (hex.len != 96) {
            try statuses.appendSlice(ctx.allocator, "{\"status\":\"error\",\"message\":\"invalid pubkey length\"}");
            continue;
        }
        var pubkey: [48]u8 = undefined;
        _ = std.fmt.hexToBytes(&pubkey, hex) catch {
            try statuses.appendSlice(ctx.allocator, "{\"status\":\"error\",\"message\":\"invalid pubkey hex\"}");
            continue;
        };

        const result = km.deleteKeyFn(km.ptr, ctx.allocator, pubkey) catch |err| {
            const msg = try std.fmt.allocPrint(ctx.allocator, "{{\"status\":\"error\",\"message\":\"{s}\"}}", .{@errorName(err)});
            defer ctx.allocator.free(msg);
            try statuses.appendSlice(ctx.allocator, msg);
            continue;
        };
        defer ctx.allocator.free(result.slashing_protection);
        defer ctx.allocator.free(result.status);

        const entry = try std.fmt.allocPrint(ctx.allocator, "{{\"status\":\"{s}\",\"message\":\"\"}}", .{result.status});
        defer ctx.allocator.free(entry);
        try statuses.appendSlice(ctx.allocator, entry);

        if (result.slashing_protection.len > 0) {
            const sp_copy = try ctx.allocator.dupe(u8, result.slashing_protection);
            try sp_entries.append(ctx.allocator, sp_copy);
        }
    }
    try statuses.appendSlice(ctx.allocator, "]");

    // Build combined slashing protection interchange.
    // For simplicity, emit a minimal valid interchange wrapping the per-key data.
    const sp_json = if (sp_entries.items.len > 0)
        try buildCombinedSlashingProtection(ctx.allocator, sp_entries.items)
    else
        try ctx.allocator.dupe(u8, "{}");
    defer ctx.allocator.free(sp_json);

    const statuses_slice = try statuses.toOwnedSlice(ctx.allocator);
    defer ctx.allocator.free(statuses_slice);

    // Escape the slashing protection JSON as a JSON string value.
    const sp_escaped = try jsonEscapeString(ctx.allocator, sp_json);
    defer ctx.allocator.free(sp_escaped);

    return std.fmt.allocPrint(ctx.allocator,
        "{{\"data\":{s},\"slashing_protection\":\"{s}\"}}",
        .{ statuses_slice, sp_escaped },
    );
}

// ---------------------------------------------------------------------------
// GET /eth/v1/remotekeys
// ---------------------------------------------------------------------------

/// List remote signer keys.
///
/// TS: keymanager.listRemoteKeys()
pub fn listRemoteKeys(ctx: *ApiContext, auth_header: ?[]const u8) ![]u8 {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;

    const keys = try km.listRemoteKeysFn(km.ptr, ctx.allocator);
    defer ctx.allocator.free(keys);

    var buf = std.ArrayListUnmanaged(u8).empty;
    errdefer buf.deinit(ctx.allocator);

    try buf.appendSlice(ctx.allocator, "{\"data\":[");
    for (keys, 0..) |k, i| {
        if (i > 0) try buf.appendSlice(ctx.allocator, ",");
        const entry = try std.fmt.allocPrint(ctx.allocator,
            "{{\"pubkey\":\"0x{s}\",\"url\":\"{s}\",\"readonly\":{s}}}",
            .{
                std.fmt.bytesToHex(k.pubkey, .lower),
                k.url,
                if (k.readonly) "true" else "false",
            },
        );
        defer ctx.allocator.free(entry);
        try buf.appendSlice(ctx.allocator, entry);
    }
    try buf.appendSlice(ctx.allocator, "]}");

    return buf.toOwnedSlice(ctx.allocator);
}

// ---------------------------------------------------------------------------
// POST /eth/v1/remotekeys
// ---------------------------------------------------------------------------

/// Import remote signer keys.
///
/// TS: keymanager.importRemoteKeys()
pub fn importRemoteKeys(ctx: *ApiContext, auth_header: ?[]const u8, body: []const u8) ![]u8 {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = try std.json.parseFromSlice(std.json.Value, a, body, .{});
    const root_obj = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.InvalidRequestBody,
    };

    const rkeys_val = root_obj.get("remote_keys") orelse return error.MissingField;
    const rkeys_arr = switch (rkeys_val) {
        .array => |arr| arr,
        else => return error.InvalidRequestBody,
    };

    var buf = std.ArrayListUnmanaged(u8).empty;
    errdefer buf.deinit(ctx.allocator);
    try buf.appendSlice(ctx.allocator, "{\"data\":[");

    for (rkeys_arr.items, 0..) |rk_val, i| {
        if (i > 0) try buf.appendSlice(ctx.allocator, ",");

        const rk_obj = switch (rk_val) {
            .object => |obj| obj,
            else => {
                try buf.appendSlice(ctx.allocator, "{\"status\":\"error\",\"message\":\"expected object\"}");
                continue;
            },
        };

        const pk_val = rk_obj.get("pubkey") orelse {
            try buf.appendSlice(ctx.allocator, "{\"status\":\"error\",\"message\":\"missing pubkey\"}");
            continue;
        };
        const url_val = rk_obj.get("url") orelse {
            try buf.appendSlice(ctx.allocator, "{\"status\":\"error\",\"message\":\"missing url\"}");
            continue;
        };

        const pk_hex = switch (pk_val) { .string => |s| s, else => "" };
        const url = switch (url_val) { .string => |s| s, else => "" };

        const hex = if (std.mem.startsWith(u8, pk_hex, "0x")) pk_hex[2..] else pk_hex;
        if (hex.len != 96) {
            try buf.appendSlice(ctx.allocator, "{\"status\":\"error\",\"message\":\"invalid pubkey\"}");
            continue;
        }
        var pubkey: [48]u8 = undefined;
        _ = std.fmt.hexToBytes(&pubkey, hex) catch {
            try buf.appendSlice(ctx.allocator, "{\"status\":\"error\",\"message\":\"invalid pubkey hex\"}");
            continue;
        };

        const status = km.importRemoteKeyFn(km.ptr, ctx.allocator, pubkey, url) catch |err| {
            const msg = try std.fmt.allocPrint(ctx.allocator, "{{\"status\":\"error\",\"message\":\"{s}\"}}", .{@errorName(err)});
            defer ctx.allocator.free(msg);
            try buf.appendSlice(ctx.allocator, msg);
            continue;
        };
        defer ctx.allocator.free(status);

        const entry = try std.fmt.allocPrint(ctx.allocator, "{{\"status\":\"{s}\",\"message\":\"\"}}", .{status});
        defer ctx.allocator.free(entry);
        try buf.appendSlice(ctx.allocator, entry);
    }

    try buf.appendSlice(ctx.allocator, "]}");
    return buf.toOwnedSlice(ctx.allocator);
}

// ---------------------------------------------------------------------------
// DELETE /eth/v1/remotekeys
// ---------------------------------------------------------------------------

/// Delete remote signer keys.
///
/// TS: keymanager.deleteRemoteKeys()
pub fn deleteRemoteKeys(ctx: *ApiContext, auth_header: ?[]const u8, body: []const u8) ![]u8 {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = try std.json.parseFromSlice(std.json.Value, a, body, .{});
    const root_obj = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.InvalidRequestBody,
    };

    const pubkeys_val = root_obj.get("pubkeys") orelse return error.MissingField;
    const pubkeys_arr = switch (pubkeys_val) {
        .array => |arr| arr,
        else => return error.InvalidRequestBody,
    };

    var buf = std.ArrayListUnmanaged(u8).empty;
    errdefer buf.deinit(ctx.allocator);
    try buf.appendSlice(ctx.allocator, "{\"data\":[");

    for (pubkeys_arr.items, 0..) |pk_val, i| {
        if (i > 0) try buf.appendSlice(ctx.allocator, ",");

        const pk_hex = switch (pk_val) {
            .string => |s| s,
            else => {
                try buf.appendSlice(ctx.allocator, "{\"status\":\"error\",\"message\":\"pubkey must be a string\"}");
                continue;
            },
        };

        const hex = if (std.mem.startsWith(u8, pk_hex, "0x")) pk_hex[2..] else pk_hex;
        if (hex.len != 96) {
            try buf.appendSlice(ctx.allocator, "{\"status\":\"error\",\"message\":\"invalid pubkey length\"}");
            continue;
        }
        var pubkey: [48]u8 = undefined;
        _ = std.fmt.hexToBytes(&pubkey, hex) catch {
            try buf.appendSlice(ctx.allocator, "{\"status\":\"error\",\"message\":\"invalid pubkey hex\"}");
            continue;
        };

        const status = km.deleteRemoteKeyFn(km.ptr, ctx.allocator, pubkey) catch |err| {
            const msg = try std.fmt.allocPrint(ctx.allocator, "{{\"status\":\"error\",\"message\":\"{s}\"}}", .{@errorName(err)});
            defer ctx.allocator.free(msg);
            try buf.appendSlice(ctx.allocator, msg);
            continue;
        };
        defer ctx.allocator.free(status);

        const entry = try std.fmt.allocPrint(ctx.allocator, "{{\"status\":\"{s}\",\"message\":\"\"}}", .{status});
        defer ctx.allocator.free(entry);
        try buf.appendSlice(ctx.allocator, entry);
    }

    try buf.appendSlice(ctx.allocator, "]}");
    return buf.toOwnedSlice(ctx.allocator);
}

// ---------------------------------------------------------------------------
// GET/POST/DELETE /eth/v1/validator/{pubkey}/feerecipient
// ---------------------------------------------------------------------------

pub fn listFeeRecipient(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8) ![]u8 {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;
    const fee_recipient = try km.getFeeRecipientFn(km.ptr, pubkey);

    return std.fmt.allocPrint(
        ctx.allocator,
        "{{\"data\":{{\"pubkey\":\"0x{s}\",\"ethaddress\":\"0x{s}\"}}}}",
        .{
            std.fmt.bytesToHex(pubkey, .lower),
            std.fmt.bytesToHex(fee_recipient, .lower),
        },
    );
}

pub fn setFeeRecipient(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8, body: []const u8) !void {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSlice(std.json.Value, arena.allocator(), body, .{});
    const root_obj = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.InvalidRequestBody,
    };
    const fee_value = root_obj.get("ethaddress") orelse return error.MissingField;
    const fee_text = switch (fee_value) {
        .string => |value| value,
        else => return error.InvalidRequestBody,
    };

    try km.setFeeRecipientFn(km.ptr, pubkey, try parseFeeRecipientHex(fee_text));
}

pub fn deleteFeeRecipient(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8) !void {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;
    try km.deleteFeeRecipientFn(km.ptr, pubkey);
}

// ---------------------------------------------------------------------------
// GET/POST/DELETE /eth/v1/validator/{pubkey}/graffiti
// ---------------------------------------------------------------------------

pub fn getGraffiti(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8) ![]u8 {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;
    const graffiti = try km.getGraffitiFn(km.ptr, pubkey);
    const graffiti_hex = try formatGraffitiHex(ctx.allocator, graffiti);
    defer ctx.allocator.free(graffiti_hex);

    return std.fmt.allocPrint(
        ctx.allocator,
        "{{\"data\":{{\"pubkey\":\"0x{s}\",\"graffiti\":\"{s}\"}}}}",
        .{
            std.fmt.bytesToHex(pubkey, .lower),
            graffiti_hex,
        },
    );
}

pub fn setGraffiti(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8, body: []const u8) !void {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSlice(std.json.Value, arena.allocator(), body, .{});
    const root_obj = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.InvalidRequestBody,
    };
    const graffiti_value = root_obj.get("graffiti") orelse return error.MissingField;
    const graffiti_text = switch (graffiti_value) {
        .string => |value| value,
        else => return error.InvalidRequestBody,
    };

    try km.setGraffitiFn(km.ptr, pubkey, try parseGraffitiHex(graffiti_text));
}

pub fn deleteGraffiti(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8) !void {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;
    try km.deleteGraffitiFn(km.ptr, pubkey);
}

// ---------------------------------------------------------------------------
// GET/POST/DELETE /eth/v1/validator/{pubkey}/gas_limit
// ---------------------------------------------------------------------------

pub fn getGasLimit(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8) ![]u8 {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;
    const gas_limit = try km.getGasLimitFn(km.ptr, pubkey);

    return std.fmt.allocPrint(
        ctx.allocator,
        "{{\"data\":{{\"pubkey\":\"0x{s}\",\"gas_limit\":{d}}}}}",
        .{ std.fmt.bytesToHex(pubkey, .lower), gas_limit },
    );
}

pub fn setGasLimit(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8, body: []const u8) !void {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSlice(std.json.Value, arena.allocator(), body, .{});
    const root_obj = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.InvalidRequestBody,
    };
    const gas_limit_value = root_obj.get("gas_limit") orelse return error.MissingField;
    try km.setGasLimitFn(km.ptr, pubkey, try parseU64Json(gas_limit_value));
}

pub fn deleteGasLimit(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8) !void {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;
    try km.deleteGasLimitFn(km.ptr, pubkey);
}

// ---------------------------------------------------------------------------
// GET/POST/DELETE /eth/v1/validator/{pubkey}/builder_boost_factor
// ---------------------------------------------------------------------------

pub fn getBuilderBoostFactor(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8) ![]u8 {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;
    const builder_boost_factor = try km.getBuilderBoostFactorFn(km.ptr, pubkey);

    return std.fmt.allocPrint(
        ctx.allocator,
        "{{\"data\":{{\"pubkey\":\"0x{s}\",\"builder_boost_factor\":\"{d}\"}}}}",
        .{ std.fmt.bytesToHex(pubkey, .lower), builder_boost_factor },
    );
}

pub fn setBuilderBoostFactor(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8, body: []const u8) !void {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSlice(std.json.Value, arena.allocator(), body, .{});
    const root_obj = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.InvalidRequestBody,
    };
    const boost_value = root_obj.get("builder_boost_factor") orelse return error.MissingField;
    try km.setBuilderBoostFactorFn(km.ptr, pubkey, try parseU64Json(boost_value));
}

pub fn deleteBuilderBoostFactor(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8) !void {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;
    try km.deleteBuilderBoostFactorFn(km.ptr, pubkey);
}

// ---------------------------------------------------------------------------
// GET /eth/v0/validator/{pubkey}/proposer_config
// ---------------------------------------------------------------------------

pub fn getProposerConfig(ctx: *ApiContext, auth_header: ?[]const u8, pubkey: [48]u8) ![]u8 {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;
    const config_json = try km.getProposerConfigFn(km.ptr, ctx.allocator, pubkey);
    defer ctx.allocator.free(config_json);
    return std.fmt.allocPrint(ctx.allocator, "{{\"data\":{s}}}", .{config_json});
}

// ---------------------------------------------------------------------------
// POST /eth/v1/validator/{pubkey}/voluntary_exit
// ---------------------------------------------------------------------------

pub fn signVoluntaryExit(
    ctx: *ApiContext,
    auth_header: ?[]const u8,
    pubkey: [48]u8,
    epoch: ?u64,
) ![]u8 {
    try validateAuth(ctx, auth_header);
    const km = ctx.keymanager.?;
    const signed_exit_json = try km.signVoluntaryExitFn(km.ptr, ctx.allocator, pubkey, epoch);
    defer ctx.allocator.free(signed_exit_json);
    return std.fmt.allocPrint(ctx.allocator, "{{\"data\":{s}}}", .{signed_exit_json});
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

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

fn parseU64Json(value: std.json.Value) !u64 {
    return switch (value) {
        .integer => |n| std.math.cast(u64, n) orelse error.InvalidRequestBody,
        .number_string => |s| std.fmt.parseInt(u64, s, 10) catch error.InvalidRequestBody,
        .string => |s| std.fmt.parseInt(u64, s, 10) catch error.InvalidRequestBody,
        else => error.InvalidRequestBody,
    };
}

fn buildCombinedSlashingProtection(allocator: std.mem.Allocator, sp_jsons: []const []const u8) ![]const u8 {
    // For now, return the first non-empty one. A full implementation would
    // merge the data arrays from multiple interchange objects.
    for (sp_jsons) |sp| {
        if (sp.len > 2) return allocator.dupe(u8, sp); // not just "{}"
    }
    return allocator.dupe(u8, "{}");
}

/// Escape a string for inclusion as a JSON string value.
/// Escapes backslash and double-quote characters.
fn jsonEscapeString(allocator: std.mem.Allocator, s: []const u8) ![]const u8 {
    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);
    for (s) |c| {
        switch (c) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => try out.append(allocator, c),
        }
    }
    return out.toOwnedSlice(allocator);
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

    fn importKey(ptr: *anyopaque, allocator: std.mem.Allocator, keystore_json: []const u8, password: []const u8, _: ?[]const u8) anyerror![]const u8 {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        _ = password;
        // Fake: extract pubkey from JSON, just add a dummy pubkey.
        _ = keystore_json;
        const dummy_pubkey = [_]u8{0xaa} ** 48;
        // Check for duplicate.
        for (self.local_keys.items) |k| {
            if (std.mem.eql(u8, &k, &dummy_pubkey)) return allocator.dupe(u8, "duplicate");
        }
        try self.local_keys.append(self.allocator, dummy_pubkey);
        return allocator.dupe(u8, "imported");
    }

    fn deleteKey(ptr: *anyopaque, allocator: std.mem.Allocator, pubkey: [48]u8) anyerror!context.DeleteKeyResult {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        for (self.local_keys.items, 0..) |k, idx| {
            if (std.mem.eql(u8, &k, &pubkey)) {
                _ = self.local_keys.swapRemove(idx);
                return .{
                    .status = try allocator.dupe(u8, "deleted"),
                    .slashing_protection = try allocator.dupe(u8, "{}"),
                };
            }
        }
        return .{
            .status = try allocator.dupe(u8, "not_found"),
            .slashing_protection = try allocator.dupe(u8, ""),
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

    fn importRemoteKey(ptr: *anyopaque, allocator: std.mem.Allocator, pubkey: [48]u8, url: []const u8) anyerror![]const u8 {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        for (self.remote_keys.items) |rk| {
            if (std.mem.eql(u8, &rk.pubkey, &pubkey)) return allocator.dupe(u8, "duplicate");
        }
        const url_copy = try self.allocator.dupe(u8, url);
        try self.remote_keys.append(self.allocator, RemoteEntry{ .pubkey = pubkey, .url = url_copy });
        return allocator.dupe(u8, "imported");
    }

    fn deleteRemoteKey(ptr: *anyopaque, allocator: std.mem.Allocator, pubkey: [48]u8) anyerror![]const u8 {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        for (self.remote_keys.items, 0..) |rk, idx| {
            if (std.mem.eql(u8, &rk.pubkey, &pubkey)) {
                const url = self.remote_keys.items[idx].url;
                self.allocator.free(url);
                _ = self.remote_keys.swapRemove(idx);
                return allocator.dupe(u8, "deleted");
            }
        }
        return allocator.dupe(u8, "not_found");
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

    fn getProposerConfig(ptr: *anyopaque, allocator: std.mem.Allocator, pubkey: [48]u8) anyerror![]const u8 {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        try self.ensureKnownPubkey(pubkey);

        if (self.fee_recipients.get(pubkey)) |fee_recipient| {
            return std.fmt.allocPrint(
                allocator,
                "{{\"feeRecipient\":\"0x{s}\"}}",
                .{std.fmt.bytesToHex(fee_recipient, .lower)},
            );
        }

        return allocator.dupe(u8, "null");
    }

    fn signVoluntaryExit(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        pubkey: [48]u8,
        epoch: ?u64,
    ) anyerror![]const u8 {
        const self: *TestKeyState = @ptrCast(@alignCast(ptr));
        try self.ensureKnownPubkey(pubkey);
        return std.fmt.allocPrint(
            allocator,
            "{{\"message\":{{\"epoch\":\"{d}\",\"validator_index\":\"1\"}},\"signature\":\"0x{s}\"}}",
            .{ epoch orelse 0, "aa" ** 96 },
        );
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

    const body = try listKeystores(&tc.ctx, "Bearer mytoken");
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("{\"data\":[]}", body);
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
    defer testing.allocator.free(resp);
    try testing.expect(std.mem.indexOf(u8, resp, "imported") != null);
}

test "deleteKeystores: deletes known key" {
    var state = try TestKeyState.init(testing.allocator, "token");
    defer state.deinit();

    // Pre-populate a key.
    const dummy_pubkey = [_]u8{0xaa} ** 48;
    try state.local_keys.append(testing.allocator, dummy_pubkey);

    const test_helpers = @import("../test_helpers.zig");
    var tc = test_helpers.makeTestContext(testing.allocator);
    defer test_helpers.destroyTestContext(testing.allocator, &tc);
    const km = state.callback();
    tc.ctx.keymanager = km;

    const body = try std.fmt.allocPrint(testing.allocator,
        "{{\"pubkeys\":[\"0x{s}\"]}}",
        .{std.fmt.bytesToHex(dummy_pubkey, .lower)},
    );
    defer testing.allocator.free(body);

    const resp = try deleteKeystores(&tc.ctx, "Bearer token", body);
    defer testing.allocator.free(resp);
    try testing.expect(std.mem.indexOf(u8, resp, "deleted") != null);
}

test "listRemoteKeys: returns empty list" {
    var state = try TestKeyState.init(testing.allocator, "token");
    defer state.deinit();

    const test_helpers = @import("../test_helpers.zig");
    var tc = test_helpers.makeTestContext(testing.allocator);
    defer test_helpers.destroyTestContext(testing.allocator, &tc);
    const km = state.callback();
    tc.ctx.keymanager = km;

    const body = try listRemoteKeys(&tc.ctx, "Bearer token");
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("{\"data\":[]}", body);
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
    const body = try std.fmt.allocPrint(testing.allocator,
        "{{\"remote_keys\":[{{\"pubkey\":\"{s}\",\"url\":\"http://signer:9000\"}}]}}",
        .{pubkey_hex},
    );
    defer testing.allocator.free(body);

    const resp = try importRemoteKeys(&tc.ctx, "Bearer token", body);
    defer testing.allocator.free(resp);
    try testing.expect(std.mem.indexOf(u8, resp, "imported") != null);
}
