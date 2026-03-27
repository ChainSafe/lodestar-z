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
const SlashingProtectionRecord = types.SlashingProtectionRecord;

const log = std.log.scoped(.interchange);

/// EIP-3076 interchange format version.
pub const INTERCHANGE_FORMAT_VERSION = "5";

// ---------------------------------------------------------------------------
// Interchange JSON types
// ---------------------------------------------------------------------------

/// A signed block record within an interchange entry.
/// Represents a block that was signed at a given slot.
pub const SignedBlock = struct {
    /// Slot at which the block was signed (decimal string in JSON).
    slot: u64,
    /// Block signing root (hex, optional — some clients omit).
    signing_root: ?[32]u8,
};

/// A signed attestation record within an interchange entry.
/// Represents an attestation that was signed for source/target epochs.
pub const SignedAttestation = struct {
    /// Source epoch (decimal string in JSON).
    source_epoch: u64,
    /// Target epoch (decimal string in JSON).
    target_epoch: u64,
    /// Attestation signing root (hex, optional).
    signing_root: ?[32]u8,
};

/// Per-validator interchange entry.
pub const InterchangeData = struct {
    /// BLS pubkey (hex, "0x"-prefixed).
    pubkey: [48]u8,
    /// All signed blocks recorded for this validator.
    signed_blocks: []const SignedBlock,
    /// All signed attestations recorded for this validator.
    signed_attestations: []const SignedAttestation,
};

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

/// Import EIP-3076 interchange JSON into a list of SlashingProtectionRecords.
///
/// The returned slice and all inner slices are allocated from `allocator`.
/// Caller must free: `allocator.free(records)` (inner fields are not allocated
/// separately — see docs below).
///
/// Note: We produce one SlashingProtectionRecord per validator, tracking
/// only the *highest* signed slot/epoch from the interchange (conservative
/// protection — same as what TS lodestar does for fast import).
///
/// TS: SlashingProtectionInterchange.importInterchange(interchange)
pub fn importInterchange(allocator: Allocator, json: []const u8) ![]SlashingProtectionRecord {
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
    _ = std.fmt.hexToBytes(&genesis_validators_root, gvr_hex) catch {};
    // TODO: verify genesis_validators_root matches our chain before importing.
    // For now, we accept any GVR (permissive import).

    // Parse data array.
    const data_val = root_obj.get("data") orelse return error.MissingInterchangeField;
    const data_arr = switch (data_val) {
        .array => |arr| arr,
        else => return error.InvalidInterchangeJson,
    };

    const records = try allocator.alloc(SlashingProtectionRecord, data_arr.items.len);
    errdefer allocator.free(records);

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
        _ = std.fmt.hexToBytes(&pubkey, pk_hex) catch {};

        record.pubkey = pubkey;
        record.last_signed_block_slot = null;
        record.last_signed_attestation_source_epoch = null;
        record.last_signed_attestation_target_epoch = null;

        // Signed blocks — track maximum slot.
        const blocks_val = item_obj.get("signed_blocks") orelse continue;
        const blocks_arr = switch (blocks_val) {
            .array => |arr| arr,
            else => continue,
        };
        for (blocks_arr.items) |block_item| {
            const block_obj = switch (block_item) {
                .object => |obj| obj,
                else => continue,
            };
            const slot_val = block_obj.get("slot") orelse continue;
            const slot: u64 = switch (slot_val) {
                .integer => |n| @intCast(n),
                .string => |s| std.fmt.parseInt(u64, s, 10) catch continue,
                .number_string => |s| std.fmt.parseInt(u64, s, 10) catch continue,
                else => continue,
            };
            if (record.last_signed_block_slot == null or slot > record.last_signed_block_slot.?) {
                record.last_signed_block_slot = slot;
            }
        }

        // Signed attestations — track maximum target epoch (and matching source).
        const atts_val = item_obj.get("signed_attestations") orelse continue;
        const atts_arr = switch (atts_val) {
            .array => |arr| arr,
            else => continue,
        };
        for (atts_arr.items) |att_item| {
            const att_obj = switch (att_item) {
                .object => |obj| obj,
                else => continue,
            };
            const src_val = att_obj.get("source_epoch") orelse continue;
            const tgt_val = att_obj.get("target_epoch") orelse continue;
            const src: u64 = switch (src_val) {
                .integer => |n| @intCast(n),
                .string => |s| std.fmt.parseInt(u64, s, 10) catch continue,
                .number_string => |s| std.fmt.parseInt(u64, s, 10) catch continue,
                else => continue,
            };
            const tgt: u64 = switch (tgt_val) {
                .integer => |n| @intCast(n),
                .string => |s| std.fmt.parseInt(u64, s, 10) catch continue,
                .number_string => |s| std.fmt.parseInt(u64, s, 10) catch continue,
                else => continue,
            };
            // Use maximum target epoch (most conservative).
            if (record.last_signed_attestation_target_epoch == null or tgt > record.last_signed_attestation_target_epoch.?) {
                record.last_signed_attestation_target_epoch = tgt;
                record.last_signed_attestation_source_epoch = src;
            }
        }
    }

    log.info("imported interchange: {d} validators", .{records.len});
    return records;
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

/// Export SlashingProtectionRecords to EIP-3076 interchange JSON.
///
/// genesis_validators_root ties the export to a specific chain.
///
/// The returned bytes are allocated from `allocator` — caller must free.
///
/// TS: SlashingProtectionInterchange.exportInterchange(pubkeys, genesis_validators_root)
pub fn exportInterchange(
    allocator: Allocator,
    records: []const SlashingProtectionRecord,
    genesis_validators_root: [32]u8,
) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    const writer = out.writer();

    const gvr_hex = std.fmt.bytesToHex(&genesis_validators_root, .lower);

    try writer.writeAll("{\"metadata\":{\"interchange_format_version\":\"" ++ INTERCHANGE_FORMAT_VERSION ++ "\",\"genesis_validators_root\":\"0x");
    try writer.writeAll(&gvr_hex);
    try writer.writeAll("\"},\"data\":[");

    for (records, 0..) |rec, ri| {
        if (ri > 0) try writer.writeByte(',');

        const pk_hex = std.fmt.bytesToHex(&rec.pubkey, .lower);
        try writer.print("{{\"pubkey\":\"0x{s}\",\"signed_blocks\":[", .{pk_hex});

        // Emit last signed block slot as a single entry (if any).
        if (rec.last_signed_block_slot) |slot| {
            try writer.print("{{\"slot\":\"{d}\",\"signing_root\":null}}", .{slot});
        }

        try writer.writeAll("],\"signed_attestations\":[");

        // Emit last signed attestation as a single entry (if any).
        if (rec.last_signed_attestation_target_epoch) |target| {
            const source = rec.last_signed_attestation_source_epoch orelse 0;
            try writer.print(
                "{{\"source_epoch\":\"{d}\",\"target_epoch\":\"{d}\",\"signing_root\":null}}",
                .{ source, target },
            );
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
    const records = [_]SlashingProtectionRecord{.{
        .pubkey = [_]u8{0x01} ** 48,
        .last_signed_block_slot = 100,
        .last_signed_attestation_source_epoch = 5,
        .last_signed_attestation_target_epoch = 10,
    }};
    const json = try exportInterchange(testing.allocator, &records, gvr);
    defer testing.allocator.free(json);
    try testing.expect(std.mem.indexOf(u8, json, "\"slot\":\"100\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"source_epoch\":\"5\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"target_epoch\":\"10\"") != null);
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
    defer testing.allocator.free(records);
    try testing.expectEqual(@as(usize, 0), records.len);
}

test "importInterchange: single validator round-trip" {
    const json =
        \\{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x0000000000000000000000000000000000000000000000000000000000000000"},"data":[{"pubkey":"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001","signed_blocks":[{"slot":"42"}],"signed_attestations":[{"source_epoch":"3","target_epoch":"7"}]}]}
    ;
    const records = try importInterchange(testing.allocator, json);
    defer testing.allocator.free(records);
    try testing.expectEqual(@as(usize, 1), records.len);
    try testing.expectEqual(@as(?u64, 42), records[0].last_signed_block_slot);
    try testing.expectEqual(@as(?u64, 7), records[0].last_signed_attestation_target_epoch);
    try testing.expectEqual(@as(?u64, 3), records[0].last_signed_attestation_source_epoch);
}
