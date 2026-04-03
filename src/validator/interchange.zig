//! EIP-3076 slashing protection interchange format for the Validator Client.
//!
//! Parse and emit the standard interchange format that allows importing/exporting
//! slashing protection data between different validator clients.
//!
//! References:
//!   https://eips.ethereum.org/EIPS/eip-3076
//!   https://github.com/ChainSafe/lodestar/blob/unstable/packages/validator/src/slashingProtection/interchange/
//!
//! TS equivalent: packages/validator/src/slashingProtection/interchange/

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("types.zig");
const UNKNOWN_SIGNING_ROOT = types.UNKNOWN_SIGNING_ROOT;
const SignedBlock = types.SlashingProtectionBlockRecord;
const SignedAttestation = types.SlashingProtectionAttestationRecord;
const InterchangeData = types.SlashingProtectionHistory;

const log = std.log.scoped(.interchange);

/// EIP-3076 interchange format version.
pub const INTERCHANGE_FORMAT_VERSION = "5";

// ---------------------------------------------------------------------------
// Interchange JSON types
// ---------------------------------------------------------------------------

/// Top-level EIP-3076 interchange format.
pub const InterchangeFormat = struct {
    /// Interchange metadata.
    metadata: InterchangeMetadata,
    /// Per-validator data.
    data: []const InterchangeData,
};

/// Interchange metadata section.
pub const InterchangeMetadata = struct {
    /// Interchange format version (should be "5").
    interchange_format_version: []const u8,
    /// Genesis validators root (hex) — ties this data to a specific chain.
    genesis_validators_root: [32]u8,
};

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

pub fn deinitInterchangeData(allocator: Allocator, records: []const InterchangeData) void {
    for (records) |record| {
        allocator.free(record.signed_blocks);
        allocator.free(record.signed_attestations);
    }
    allocator.free(records);
}

/// Import EIP-3076 interchange JSON into a list of per-validator histories.
///
/// The returned slice and all inner slices are allocated from `allocator`.
/// Caller must free: `allocator.free(records)` (inner fields are not allocated
/// separately — see docs below).
///
/// ⚠️ WARNING: This function skips genesis_validators_root (GVR) verification.
/// Importing interchange data without GVR verification risks loading protection
/// records from a different chain (e.g., mainnet data into a testnet validator),
/// which can lead to missed slashing protection or false double-sign blocks.
///
/// **Production code should always use `importInterchangeVerified` instead.**
///
/// This unverified variant exists only for testing and tools that handle
/// GVR verification externally.
///
/// TS: SlashingProtection.importInterchange() / parseInterchangeV5()
pub fn importInterchange(allocator: Allocator, json: []const u8) ![]InterchangeData {
    return importInterchangeVerified(allocator, json, null);
}

/// Import EIP-3076 interchange with optional genesis validators root verification.
///
/// If expected_genesis_validators_root is non-null, the interchange metadata is
/// checked against the provided root and error.GenesisValidatorsRootMismatch is
/// returned if they don't match. This prevents accidentally importing protection
/// data from a different chain (e.g. mainnet data into a testnet validator).
///
/// TS: SlashingProtection.importInterchange() — always verifies GVR.
pub fn importInterchangeVerified(
    allocator: Allocator,
    json: []const u8,
    expected_genesis_validators_root: ?[32]u8,
) ![]InterchangeData {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = try std.json.parseFromSlice(std.json.Value, a, json, .{});
    const root_obj = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.InvalidInterchangeJson,
    };

    // Validate metadata.
    const metadata_val = root_obj.get("metadata") orelse return error.MissingInterchangeField;
    const metadata_obj = switch (metadata_val) {
        .object => |obj| obj,
        else => return error.InvalidInterchangeJson,
    };

    const version_val = metadata_obj.get("interchange_format_version") orelse return error.MissingInterchangeField;
    const version_str = switch (version_val) {
        .string => |s| s,
        else => return error.InvalidInterchangeJson,
    };
    if (!std.mem.eql(u8, version_str, INTERCHANGE_FORMAT_VERSION)) {
        log.warn("interchange format version {s} not supported (expected {s})", .{ version_str, INTERCHANGE_FORMAT_VERSION });
        return error.UnsupportedInterchangeVersion;
    }

    // Parse genesis_validators_root.
    const gvr_val = metadata_obj.get("genesis_validators_root") orelse return error.MissingInterchangeField;
    const gvr_str = switch (gvr_val) {
        .string => |s| s,
        else => return error.InvalidInterchangeJson,
    };
    var genesis_validators_root: [32]u8 = [_]u8{0} ** 32;
    const gvr_hex = if (std.mem.startsWith(u8, gvr_str, "0x")) gvr_str[2..] else gvr_str;
    _ = std.fmt.hexToBytes(&genesis_validators_root, gvr_hex) catch {
        log.err("interchange: invalid genesis_validators_root hex: {s}", .{gvr_str});
        return error.InvalidInterchangeJson;
    };

    // Verify genesis_validators_root matches our chain before importing.
    // This is a critical safety check: importing slashing protection data from
    // a different chain (e.g. mainnet into a testnet VC) would leave the validator
    // unprotected against signing on the target chain.
    //
    // TS: SlashingProtectionInterchange.importInterchange always verifies GVR.
    if (expected_genesis_validators_root) |expected_gvr| {
        if (!std.mem.eql(u8, &genesis_validators_root, &expected_gvr)) {
            const file_gvr_hex = std.fmt.bytesToHex(&genesis_validators_root, .lower);
            const expected_gvr_hex = std.fmt.bytesToHex(&expected_gvr, .lower);
            log.err(
                "interchange genesis_validators_root mismatch: file=0x{s} expected=0x{s}",
                .{ file_gvr_hex, expected_gvr_hex },
            );
            return error.GenesisValidatorsRootMismatch;
        }
        log.debug("interchange genesis_validators_root verified OK", .{});
    }

    // Parse data array.
    const data_val = root_obj.get("data") orelse return error.MissingInterchangeField;
    const data_arr = switch (data_val) {
        .array => |arr| arr,
        else => return error.InvalidInterchangeJson,
    };

    const records = try allocator.alloc(InterchangeData, data_arr.items.len);
    errdefer {
        for (records[0..data_arr.items.len]) |record| {
            allocator.free(record.signed_blocks);
            allocator.free(record.signed_attestations);
        }
        allocator.free(records);
    }

    for (records) |*record| {
        record.* = .{
            .pubkey = std.mem.zeroes([48]u8),
            .signed_blocks = &.{},
            .signed_attestations = &.{},
        };
    }

    for (data_arr.items, records) |item, *record| {
        const item_obj = switch (item) {
            .object => |obj| obj,
            else => return error.InvalidInterchangeJson,
        };

        // Pubkey.
        const pk_val = item_obj.get("pubkey") orelse return error.MissingInterchangeField;
        const pk_str = switch (pk_val) {
            .string => |s| s,
            else => return error.InvalidInterchangeJson,
        };
        var pubkey: [48]u8 = [_]u8{0} ** 48;
        const pk_hex = if (std.mem.startsWith(u8, pk_str, "0x")) pk_str[2..] else pk_str;
        _ = std.fmt.hexToBytes(&pubkey, pk_hex) catch return error.InvalidInterchangeJson;

        record.pubkey = pubkey;
        record.signed_blocks = try parseSignedBlocks(allocator, item_obj.get("signed_blocks"));
        errdefer allocator.free(record.signed_blocks);
        record.signed_attestations = try parseSignedAttestations(allocator, item_obj.get("signed_attestations"));
        errdefer allocator.free(record.signed_attestations);
    }

    log.info("imported interchange: {d} validators", .{records.len});
    return records;
}

fn parseSignedBlocks(allocator: Allocator, blocks_val: ?std.json.Value) ![]SignedBlock {
    const blocks = switch (blocks_val orelse .null) {
        .null => return allocator.alloc(SignedBlock, 0),
        .array => |arr| arr,
        else => return error.InvalidInterchangeJson,
    };

    var out = std.array_list.Managed(SignedBlock).init(allocator);
    errdefer out.deinit();

    for (blocks.items) |block_item| {
        const block_obj = switch (block_item) {
            .object => |obj| obj,
            else => return error.InvalidInterchangeJson,
        };
        const slot_val = block_obj.get("slot") orelse return error.MissingInterchangeField;
        const slot = try parseDecimalU64(slot_val);
        const signing_root = try parseOptionalSigningRoot(block_obj.get("signing_root"));
        try out.append(.{
            .slot = slot,
            .signing_root = signing_root,
        });
    }

    return out.toOwnedSlice();
}

fn parseSignedAttestations(allocator: Allocator, atts_val: ?std.json.Value) ![]SignedAttestation {
    const attestations = switch (atts_val orelse .null) {
        .null => return allocator.alloc(SignedAttestation, 0),
        .array => |arr| arr,
        else => return error.InvalidInterchangeJson,
    };

    var out = std.array_list.Managed(SignedAttestation).init(allocator);
    errdefer out.deinit();

    for (attestations.items) |att_item| {
        const att_obj = switch (att_item) {
            .object => |obj| obj,
            else => return error.InvalidInterchangeJson,
        };
        const source_epoch = try parseDecimalU64(att_obj.get("source_epoch") orelse return error.MissingInterchangeField);
        const target_epoch = try parseDecimalU64(att_obj.get("target_epoch") orelse return error.MissingInterchangeField);
        const signing_root = try parseOptionalSigningRoot(att_obj.get("signing_root"));
        try out.append(.{
            .source_epoch = source_epoch,
            .target_epoch = target_epoch,
            .signing_root = signing_root,
        });
    }

    return out.toOwnedSlice();
}

fn parseDecimalU64(value: std.json.Value) !u64 {
    return switch (value) {
        .integer => |n| @intCast(n),
        .string => |s| std.fmt.parseInt(u64, s, 10),
        .number_string => |s| std.fmt.parseInt(u64, s, 10),
        else => error.InvalidInterchangeJson,
    };
}

fn parseOptionalSigningRoot(value: ?std.json.Value) ![32]u8 {
    const root_val = value orelse return UNKNOWN_SIGNING_ROOT;
    return switch (root_val) {
        .null => UNKNOWN_SIGNING_ROOT,
        .string => |s| blk: {
            var signing_root = UNKNOWN_SIGNING_ROOT;
            const root_hex = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
            if (root_hex.len == 0) break :blk UNKNOWN_SIGNING_ROOT;
            _ = std.fmt.hexToBytes(&signing_root, root_hex) catch return error.InvalidInterchangeJson;
            break :blk signing_root;
        },
        else => error.InvalidInterchangeJson,
    };
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

/// Export full slashing-protection history to EIP-3076 interchange JSON.
///
/// genesis_validators_root ties the export to a specific chain.
///
/// The returned bytes are allocated from `allocator` — caller must free.
///
/// TS: SlashingProtectionInterchange.exportInterchange(pubkeys, genesis_validators_root)
pub fn exportInterchange(
    allocator: Allocator,
    records: []const InterchangeData,
    genesis_validators_root: [32]u8,
) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();

    const writer = &out.writer;

    const gvr_hex = std.fmt.bytesToHex(&genesis_validators_root, .lower);

    try writer.writeAll("{\"metadata\":{\"interchange_format_version\":\"" ++ INTERCHANGE_FORMAT_VERSION ++ "\",\"genesis_validators_root\":\"0x");
    try writer.writeAll(&gvr_hex);
    try writer.writeAll("\"},\"data\":[");

    for (records, 0..) |rec, ri| {
        if (ri > 0) try writer.writeByte(',');

        const pk_hex = std.fmt.bytesToHex(&rec.pubkey, .lower);
        try writer.print("{{\"pubkey\":\"0x{s}\",\"signed_blocks\":[", .{pk_hex});

        for (rec.signed_blocks, 0..) |block, bi| {
            if (bi > 0) try writer.writeByte(',');
            try writer.print("{{\"slot\":\"{d}\"", .{block.slot});
            if (!std.mem.eql(u8, &block.signing_root, &UNKNOWN_SIGNING_ROOT)) {
                const root_hex = std.fmt.bytesToHex(&block.signing_root, .lower);
                try writer.print(",\"signing_root\":\"0x{s}\"", .{root_hex});
            }
            try writer.writeByte('}');
        }

        try writer.writeAll("],\"signed_attestations\":[");
        for (rec.signed_attestations, 0..) |attestation, ai| {
            if (ai > 0) try writer.writeByte(',');
            try writer.print(
                "{{\"source_epoch\":\"{d}\",\"target_epoch\":\"{d}\"",
                .{ attestation.source_epoch, attestation.target_epoch },
            );
            if (!std.mem.eql(u8, &attestation.signing_root, &UNKNOWN_SIGNING_ROOT)) {
                const root_hex = std.fmt.bytesToHex(&attestation.signing_root, .lower);
                try writer.print(",\"signing_root\":\"0x{s}\"", .{root_hex});
            }
            try writer.writeByte('}');
        }

        try writer.writeAll("]}");
    }

    try writer.writeAll("]}");

    log.info("exported interchange: {d} validators", .{records.len});
    return out.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "exportInterchange: empty records" {
    const gvr = [_]u8{0} ** 32;
    const json = try exportInterchange(testing.allocator, &.{}, gvr);
    defer testing.allocator.free(json);
    try testing.expect(std.mem.indexOf(u8, json, "\"data\":[]") != null);
    try testing.expect(std.mem.indexOf(u8, json, INTERCHANGE_FORMAT_VERSION) != null);
}

test "exportInterchange: single validator" {
    const gvr = [_]u8{0xab} ** 32;
    const records = [_]InterchangeData{.{
        .pubkey = [_]u8{0x01} ** 48,
        .signed_blocks = &.{.{ .slot = 100 }},
        .signed_attestations = &.{.{ .source_epoch = 5, .target_epoch = 10 }},
    }};
    const json = try exportInterchange(testing.allocator, &records, gvr);
    defer testing.allocator.free(json);
    try testing.expect(std.mem.indexOf(u8, json, "\"slot\":\"100\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"source_epoch\":\"5\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"target_epoch\":\"10\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"signing_root\":null") == null);
}

test "importInterchange: unsupported version" {
    const json =
        \\{"metadata":{"interchange_format_version":"4","genesis_validators_root":"0x0000000000000000000000000000000000000000000000000000000000000000"},"data":[]}
    ;
    try testing.expectError(error.UnsupportedInterchangeVersion, importInterchange(testing.allocator, json));
}

test "importInterchange: empty data" {
    const json =
        \\{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x0000000000000000000000000000000000000000000000000000000000000000"},"data":[]}
    ;
    const records = try importInterchange(testing.allocator, json);
    defer deinitInterchangeData(testing.allocator, records);
    try testing.expectEqual(@as(usize, 0), records.len);
}

test "importInterchange: single validator round-trip" {
    const json =
        \\{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x0000000000000000000000000000000000000000000000000000000000000000"},"data":[{"pubkey":"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001","signed_blocks":[{"slot":"42","signing_root":"0x1111111111111111111111111111111111111111111111111111111111111111"}],"signed_attestations":[{"source_epoch":"3","target_epoch":"7","signing_root":"0x2222222222222222222222222222222222222222222222222222222222222222"}]}]}
    ;
    const records = try importInterchange(testing.allocator, json);
    defer deinitInterchangeData(testing.allocator, records);
    try testing.expectEqual(@as(usize, 1), records.len);
    try testing.expectEqual(@as(usize, 1), records[0].signed_blocks.len);
    try testing.expectEqual(@as(u64, 42), records[0].signed_blocks[0].slot);
    try testing.expectEqual(@as(usize, 1), records[0].signed_attestations.len);
    try testing.expectEqual(@as(u64, 3), records[0].signed_attestations[0].source_epoch);
    try testing.expectEqual(@as(u64, 7), records[0].signed_attestations[0].target_epoch);
    try testing.expectEqualSlices(u8, &([_]u8{0x11} ** 32), &records[0].signed_blocks[0].signing_root);
    try testing.expectEqualSlices(u8, &([_]u8{0x22} ** 32), &records[0].signed_attestations[0].signing_root);
}

test "importInterchangeVerified: rejects mismatched genesis_validators_root" {
    const json =
        \\{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0xabababababababababababababababababababababababababababababababababab"},"data":[]}
    ;
    // Expected root is all zeros — should not match 0xabab...
    const expected_gvr = [_]u8{0x00} ** 32;
    try testing.expectError(
        error.GenesisValidatorsRootMismatch,
        importInterchangeVerified(testing.allocator, json, expected_gvr),
    );
}

test "importInterchangeVerified: accepts matching genesis_validators_root" {
    const json =
        \\{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x0000000000000000000000000000000000000000000000000000000000000000"},"data":[]}
    ;
    const expected_gvr = [_]u8{0x00} ** 32;
    const records = try importInterchangeVerified(testing.allocator, json, expected_gvr);
    defer deinitInterchangeData(testing.allocator, records);
    try testing.expectEqual(@as(usize, 0), records.len);
}

test "importInterchangeVerified: skips verification when expected is null" {
    const json =
        \\{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0xabababababababababababababababababababababababababababababababababab"},"data":[]}
    ;
    // null → no verification, any GVR accepted
    const records = try importInterchangeVerified(testing.allocator, json, null);
    defer deinitInterchangeData(testing.allocator, records);
    try testing.expectEqual(@as(usize, 0), records.len);
}
