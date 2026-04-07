//! Load a ChainConfig from a YAML file (e.g. Kurtosis devnet config.yaml).
//!
//! The YAML format is the flat key-value format used by the Ethereum consensus
//! spec configuration files:
//!
//!   PRESET_BASE: 'mainnet'
//!   GENESIS_FORK_VERSION: 0x00000000
//!   ALTAIR_FORK_EPOCH: 74240
//!   ...
//!
//! Unknown fields are silently ignored. Missing fields fall back to the
//! corresponding field in the `base` ChainConfig (the built-in mainnet config
//! by default).

const std = @import("std");
const Allocator = std.mem.Allocator;

const yaml = @import("yaml");
const Yaml = yaml.Yaml;

const ChainConfig = @import("./ChainConfig.zig");
const Preset = @import("preset").Preset;

/// Parse a ChainConfig from YAML bytes.
///
/// Fields present in the YAML override the corresponding field in `base`.
/// Fields absent in the YAML are left unchanged from `base`.
/// The returned `ChainConfig` is fully owned by the caller; `BLOB_SCHEDULE`
/// is allocated into `arena`.
pub fn loadConfigFromYaml(
    arena: Allocator,
    yaml_bytes: []const u8,
    base: *const ChainConfig,
) !ChainConfig {
    // Pre-filter YAML to remove lines with complex values (e.g. BLOB_SCHEDULE).
    // The spec config format is flat key: scalar, but some fields like BLOB_SCHEDULE
    // contain array-of-object values that our YAML parser cannot handle.
    // Since we don't parse these fields anyway, we simply drop them.
    const filtered_bytes = try filterComplexYamlValues(arena, yaml_bytes);

    var doc = Yaml{ .source = filtered_bytes };
    try doc.load(arena);
    defer doc.deinit(arena);

    if (doc.docs.items.len == 0) return error.EmptyYaml;

    const map = try doc.docs.items[0].asMap();

    var result = base.*;

    // Parse BLOB_SCHEDULE from raw YAML before the complex-value filter strips it.
    // Format:  BLOB_SCHEDULE:\n  - EPOCH: <n>\n    MAX_BLOBS_PER_BLOCK: <n>
    {
        var blob_entries: std.ArrayListUnmanaged(ChainConfig.BlobScheduleEntry) = .empty;
        var line_iter = std.mem.splitSequence(u8, yaml_bytes, "\n");
        var in_blob_schedule = false;
        var current_epoch: ?u64 = null;
        while (line_iter.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (std.mem.startsWith(u8, trimmed, "BLOB_SCHEDULE:")) {
                in_blob_schedule = true;
                continue;
            }
            if (in_blob_schedule) {
                if (trimmed.len == 0 or (!std.mem.startsWith(u8, trimmed, "-") and !std.mem.startsWith(u8, trimmed, "EPOCH") and !std.mem.startsWith(u8, trimmed, "MAX_BLOBS"))) {
                    // End of BLOB_SCHEDULE section
                    in_blob_schedule = false;
                    continue;
                }
                // Parse "- EPOCH: <n>" or "EPOCH: <n>"
                if (std.mem.indexOf(u8, trimmed, "EPOCH:")) |pos| {
                    if (std.mem.indexOf(u8, trimmed, "MAX_BLOBS") == null) {
                        const val_str = std.mem.trim(u8, trimmed[pos + 6 ..], " \t\r\'\"");
                        current_epoch = std.fmt.parseInt(u64, val_str, 10) catch null;
                    }
                }
                // Parse "MAX_BLOBS_PER_BLOCK: <n>"
                if (std.mem.indexOf(u8, trimmed, "MAX_BLOBS_PER_BLOCK:")) |pos| {
                    const val_str = std.mem.trim(u8, trimmed[pos + 20 ..], " \t\r\'\"");
                    const max_blobs = std.fmt.parseInt(u64, val_str, 10) catch continue;
                    if (current_epoch) |ep| {
                        try blob_entries.append(arena, .{ .EPOCH = ep, .MAX_BLOBS_PER_BLOCK = max_blobs });
                        current_epoch = null;
                    }
                }
            }
        }
        if (blob_entries.items.len > 0) {
            result.BLOB_SCHEDULE = try blob_entries.toOwnedSlice(arena);
        }
    }

    // Helper: get scalar string from map, or null if absent.
    // We'll inline the field lookups directly.

    // PRESET_BASE
    if (map.get("PRESET_BASE")) |v| {
        const s = try v.asScalar();
        const trimmed = std.mem.trim(u8, s, " \t\r\n'\"");
        if (std.mem.eql(u8, trimmed, "minimal")) {
            result.PRESET_BASE = Preset.minimal;
        } else {
            result.PRESET_BASE = Preset.mainnet;
        }
    }

    // CONFIG_NAME (optional — use PRESET_BASE as default)
    if (map.get("CONFIG_NAME")) |v| {
        result.CONFIG_NAME = try arena.dupe(u8, std.mem.trim(u8, try v.asScalar(), " \t\r\n'\""));
    }

    // Genesis
    if (map.get("MIN_GENESIS_ACTIVE_VALIDATOR_COUNT")) |v| {
        result.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT = try parseU64(v);
    }
    if (map.get("MIN_GENESIS_TIME")) |v| {
        result.MIN_GENESIS_TIME = try parseU64(v);
    }
    if (map.get("GENESIS_FORK_VERSION")) |v| {
        result.GENESIS_FORK_VERSION = try parseForkVersion(v);
    }
    if (map.get("GENESIS_DELAY")) |v| {
        result.GENESIS_DELAY = try parseU64(v);
    }

    // Altair
    if (map.get("ALTAIR_FORK_VERSION")) |v| {
        result.ALTAIR_FORK_VERSION = try parseForkVersion(v);
    }
    if (map.get("ALTAIR_FORK_EPOCH")) |v| {
        result.ALTAIR_FORK_EPOCH = try parseU64(v);
    }

    // Bellatrix
    if (map.get("BELLATRIX_FORK_VERSION")) |v| {
        result.BELLATRIX_FORK_VERSION = try parseForkVersion(v);
    }
    if (map.get("BELLATRIX_FORK_EPOCH")) |v| {
        result.BELLATRIX_FORK_EPOCH = try parseU64(v);
    }

    // Capella
    if (map.get("CAPELLA_FORK_VERSION")) |v| {
        result.CAPELLA_FORK_VERSION = try parseForkVersion(v);
    }
    if (map.get("CAPELLA_FORK_EPOCH")) |v| {
        result.CAPELLA_FORK_EPOCH = try parseU64(v);
    }

    // Deneb
    if (map.get("DENEB_FORK_VERSION")) |v| {
        result.DENEB_FORK_VERSION = try parseForkVersion(v);
    }
    if (map.get("DENEB_FORK_EPOCH")) |v| {
        result.DENEB_FORK_EPOCH = try parseU64(v);
    }

    // Electra
    if (map.get("ELECTRA_FORK_VERSION")) |v| {
        result.ELECTRA_FORK_VERSION = try parseForkVersion(v);
    }
    if (map.get("ELECTRA_FORK_EPOCH")) |v| {
        result.ELECTRA_FORK_EPOCH = try parseU64(v);
    }

    // Fulu / Gloas
    if (map.get("FULU_FORK_VERSION")) |v| {
        result.FULU_FORK_VERSION = try parseForkVersion(v);
    }
    if (map.get("FULU_FORK_EPOCH")) |v| {
        result.FULU_FORK_EPOCH = try parseU64(v);
    }

    // Time parameters
    if (map.get("SECONDS_PER_SLOT")) |v| {
        result.SECONDS_PER_SLOT = try parseU64(v);
    }
    if (map.get("SECONDS_PER_ETH1_BLOCK")) |v| {
        result.SECONDS_PER_ETH1_BLOCK = try parseU64(v);
    }
    if (map.get("MIN_VALIDATOR_WITHDRAWABILITY_DELAY")) |v| {
        result.MIN_VALIDATOR_WITHDRAWABILITY_DELAY = try parseU64(v);
    }
    if (map.get("SHARD_COMMITTEE_PERIOD")) |v| {
        result.SHARD_COMMITTEE_PERIOD = try parseU64(v);
    }
    if (map.get("ETH1_FOLLOW_DISTANCE")) |v| {
        result.ETH1_FOLLOW_DISTANCE = try parseU64(v);
    }

    // Validator cycle
    if (map.get("INACTIVITY_SCORE_BIAS")) |v| {
        result.INACTIVITY_SCORE_BIAS = try parseU64(v);
    }
    if (map.get("INACTIVITY_SCORE_RECOVERY_RATE")) |v| {
        result.INACTIVITY_SCORE_RECOVERY_RATE = try parseU64(v);
    }
    if (map.get("EJECTION_BALANCE")) |v| {
        result.EJECTION_BALANCE = try parseU64(v);
    }
    if (map.get("MIN_PER_EPOCH_CHURN_LIMIT")) |v| {
        result.MIN_PER_EPOCH_CHURN_LIMIT = try parseU64(v);
    }
    if (map.get("MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT")) |v| {
        result.MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT = try parseU64(v);
    }
    if (map.get("CHURN_LIMIT_QUOTIENT")) |v| {
        result.CHURN_LIMIT_QUOTIENT = try parseU64(v);
    }
    if (map.get("MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT")) |v| {
        result.MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT = try parseU64(v);
    }
    if (map.get("MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA")) |v| {
        result.MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA = try parseU64(v);
    }

    // Fork choice
    if (map.get("PROPOSER_SCORE_BOOST")) |v| {
        result.PROPOSER_SCORE_BOOST = try parseU64(v);
    }
    if (map.get("REORG_HEAD_WEIGHT_THRESHOLD")) |v| {
        result.REORG_HEAD_WEIGHT_THRESHOLD = try parseU64(v);
    }
    if (map.get("REORG_PARENT_WEIGHT_THRESHOLD")) |v| {
        result.REORG_PARENT_WEIGHT_THRESHOLD = try parseU64(v);
    }
    if (map.get("REORG_MAX_EPOCHS_SINCE_FINALIZATION")) |v| {
        result.REORG_MAX_EPOCHS_SINCE_FINALIZATION = try parseU64(v);
    }

    // Deposit contract
    if (map.get("DEPOSIT_CHAIN_ID")) |v| {
        result.DEPOSIT_CHAIN_ID = try parseU64(v);
    }
    if (map.get("DEPOSIT_NETWORK_ID")) |v| {
        result.DEPOSIT_NETWORK_ID = try parseU64(v);
    }

    // Networking
    if (map.get("MIN_EPOCHS_FOR_BLOCK_REQUESTS")) |v| {
        result.MIN_EPOCHS_FOR_BLOCK_REQUESTS = try parseU64(v);
    }
    if (map.get("MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS")) |v| {
        result.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS = try parseU64(v);
    }
    if (map.get("MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS")) |v| {
        result.MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS = try parseU64(v);
    }
    if (map.get("BLOB_SIDECAR_SUBNET_COUNT")) |v| {
        result.BLOB_SIDECAR_SUBNET_COUNT = try parseU64(v);
    }
    if (map.get("MAX_BLOBS_PER_BLOCK")) |v| {
        result.MAX_BLOBS_PER_BLOCK = try parseU64(v);
    }
    if (map.get("MAX_REQUEST_BLOB_SIDECARS")) |v| {
        result.MAX_REQUEST_BLOB_SIDECARS = try parseU64(v);
    }
    if (map.get("BLOB_SIDECAR_SUBNET_COUNT_ELECTRA")) |v| {
        result.BLOB_SIDECAR_SUBNET_COUNT_ELECTRA = try parseU64(v);
    }
    if (map.get("MAX_BLOBS_PER_BLOCK_ELECTRA")) |v| {
        result.MAX_BLOBS_PER_BLOCK_ELECTRA = try parseU64(v);
    }
    if (map.get("MAX_REQUEST_BLOB_SIDECARS_ELECTRA")) |v| {
        result.MAX_REQUEST_BLOB_SIDECARS_ELECTRA = try parseU64(v);
    }

    // Fulu DAS
    if (map.get("SAMPLES_PER_SLOT")) |v| {
        result.SAMPLES_PER_SLOT = try parseU64(v);
    }
    if (map.get("CUSTODY_REQUIREMENT")) |v| {
        result.CUSTODY_REQUIREMENT = try parseU64(v);
    }
    if (map.get("NODE_CUSTODY_REQUIREMENT")) |v| {
        result.NODE_CUSTODY_REQUIREMENT = try parseU64(v);
    }
    if (map.get("VALIDATOR_CUSTODY_REQUIREMENT")) |v| {
        result.VALIDATOR_CUSTODY_REQUIREMENT = try parseU64(v);
    }
    if (map.get("BALANCE_PER_ADDITIONAL_CUSTODY_GROUP")) |v| {
        result.BALANCE_PER_ADDITIONAL_CUSTODY_GROUP = try parseU64(v);
    }

    // Terminal block hash / difficulty (optional, large integers)
    if (map.get("TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH")) |v| {
        result.TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH = try parseU64(v);
    }

    return result;
}


// ---------------------------------------------------------------------------
// YAML pre-filtering
// ---------------------------------------------------------------------------

/// Remove lines from YAML bytes where the value (after the first ':') starts
/// with '[' — these are complex list/object values our parser cannot handle.
/// Returns a newly-allocated slice with the offending lines removed.
fn filterComplexYamlValues(alloc: Allocator, yaml_bytes: []const u8) ![]const u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    var lines = std.mem.splitScalar(u8, yaml_bytes, '\n');
    var first = true;
    while (lines.next()) |line| {
        // Check if the value part (after first ':') starts with '[' after trimming.
        const skip = blk: {
            if (std.mem.indexOfScalar(u8, line, ':')) |colon_idx| {
                const after_colon = line[colon_idx + 1 ..];
                var val_start: usize = 0;
                while (val_start < after_colon.len and (after_colon[val_start] == ' ' or after_colon[val_start] == '\t')) {
                    val_start += 1;
                }
                if (val_start < after_colon.len and after_colon[val_start] == '[') break :blk true;
            }
            break :blk false;
        };
        if (skip) continue;
        if (!first) try out.append(alloc, '\n');
        try out.appendSlice(alloc, line);
        first = false;
    }
    return out.items;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parseU64(value: yaml.Yaml.Value) !u64 {
    const s = try value.asScalar();
    const trimmed = std.mem.trim(u8, s, " \t\r\n'\"");
    return std.fmt.parseInt(u64, trimmed, 0);
}

/// Parse a fork version from a YAML scalar.
///
/// Accepted formats:
///   - `0x10000038`  → 4-byte hex (with or without 0x prefix, 8 hex digits)
///   - `16777272`    → decimal (interpreted as big-endian u32 → [4]u8)
fn parseForkVersion(value: yaml.Yaml.Value) ![4]u8 {
    const s = try value.asScalar();
    const trimmed = std.mem.trim(u8, s, " \t\r\n'\"");

    if (std.mem.startsWith(u8, trimmed, "0x") or std.mem.startsWith(u8, trimmed, "0X")) {
        const hex = trimmed[2..];
        if (hex.len != 8) return error.InvalidForkVersion;
        var result: [4]u8 = undefined;
        _ = try std.fmt.hexToBytes(&result, hex);
        return result;
    } else {
        // Decimal: parse as u32, store big-endian.
        const n = try std.fmt.parseInt(u32, trimmed, 10);
        return std.mem.toBytes(std.mem.nativeToBig(u32, n));
    }
}

test "parseForkVersion hex" {
    const testing = std.testing;
    const v = yaml.Yaml.Value{ .scalar = "0x10000038" };
    const result = try parseForkVersion(v);
    try testing.expectEqual([4]u8{ 0x10, 0x00, 0x00, 0x38 }, result);
}

test "parseForkVersion decimal" {
    const testing = std.testing;
    const v = yaml.Yaml.Value{ .scalar = "16777272" };
    const result = try parseForkVersion(v);
    // 16777272 = 0x01000038
    try testing.expectEqual([4]u8{ 0x01, 0x00, 0x00, 0x38 }, result);
}

test "loadConfigFromYaml kurtosis" {
    const testing = std.testing;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const yaml_bytes =
        \\PRESET_BASE: 'mainnet'
        \\MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: 64
        \\MIN_GENESIS_TIME: 1774389712
        \\GENESIS_FORK_VERSION: 0x10000038
        \\ALTAIR_FORK_VERSION: 0x20000038
        \\ALTAIR_FORK_EPOCH: 0
        \\BELLATRIX_FORK_VERSION: 0x30000038
        \\BELLATRIX_FORK_EPOCH: 0
        \\CAPELLA_FORK_VERSION: 0x40000038
        \\CAPELLA_FORK_EPOCH: 0
        \\DENEB_FORK_VERSION: 0x50000038
        \\DENEB_FORK_EPOCH: 0
        \\ELECTRA_FORK_VERSION: 0x60000038
        \\ELECTRA_FORK_EPOCH: 0
        \\FULU_FORK_VERSION: 0x70000038
        \\FULU_FORK_EPOCH: 0
        \\SECONDS_PER_SLOT: 6
    ;

    const base = &@import("./networks/mainnet.zig").chain_config;
    const result = try loadConfigFromYaml(allocator, yaml_bytes, base);

    try testing.expectEqual(Preset.mainnet, result.PRESET_BASE);
    try testing.expectEqual(@as(u64, 64), result.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT);
    try testing.expectEqual(@as(u64, 1774389712), result.MIN_GENESIS_TIME);
    try testing.expectEqual([4]u8{ 0x10, 0x00, 0x00, 0x38 }, result.GENESIS_FORK_VERSION);
    try testing.expectEqual([4]u8{ 0x20, 0x00, 0x00, 0x38 }, result.ALTAIR_FORK_VERSION);
    try testing.expectEqual(@as(u64, 0), result.ALTAIR_FORK_EPOCH);
    try testing.expectEqual(@as(u64, 6), result.SECONDS_PER_SLOT);
    // Fields not in YAML preserve the base config value.
    try testing.expectEqual(base.DEPOSIT_CHAIN_ID, result.DEPOSIT_CHAIN_ID);
}
