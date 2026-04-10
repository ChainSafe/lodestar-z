//! PeerDAS custody column computation.
//!
//! Implements `get_custody_columns(node_id, custody_subnet_count)` from the
//! consensus spec for the fulu/PeerDAS fork.
//!
//! Each node custodies a deterministic subset of custody groups derived from
//! its node ID (the ENR node ID, 32 bytes). Those groups are then expanded
//! into column indices per the Fulu PeerDAS spec.
//!
//! Reference:
//!   https://github.com/ethereum/consensus-specs/blob/dev/specs/fulu/das-core.md
//!   get_custody_groups(node_id, custody_group_count) -> Sequence[CustodyIndex]
//!   compute_columns_for_custody_group(custody_index) -> Sequence[ColumnIndex]

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Total number of data column subnets (= NUMBER_OF_COLUMNS on mainnet).
pub const DATA_COLUMN_SIDECAR_SUBNET_COUNT: u64 = 128;

/// Total number of data columns per blob (= NUMBER_OF_COLUMNS).
pub const NUMBER_OF_COLUMNS: u64 = 128;

/// Total number of custody groups.
pub const NUMBER_OF_CUSTODY_GROUPS: u64 = 128;

/// Default custody requirement: how many column subnets a node custodies by default.
pub const CUSTODY_REQUIREMENT: u64 = 4;

/// Maximum custody subnet count (full node custodies all custody groups).
pub const MAX_CUSTODY_SUBNET_COUNT: u64 = NUMBER_OF_CUSTODY_GROUPS;

// ─── Core algorithm ──────────────────────────────────────────────────────────

/// Compute the set of custody groups this node must custody.
///
/// Matches Lodestar/spec `get_custody_groups(node_id, custody_group_count)`:
///
/// 1. Interpret `node_id` as a big-endian uint256.
/// 2. Serialize that counter as SSZ uint256 (little-endian 32 bytes).
/// 3. Hash the serialized bytes with SHA256 and take the first 8 bytes as a
///    little-endian uint64.
/// 4. Modulo by `NUMBER_OF_CUSTODY_GROUPS`.
/// 5. Keep unique groups, incrementing the uint256 counter with wraparound
///    until `custody_group_count` groups are selected.
///
/// Returns a sorted slice of custody group IDs. Caller owns the returned memory.
///
/// Preconditions:
/// - `custody_group_count <= NUMBER_OF_CUSTODY_GROUPS`
/// - `node_id` is the 32-byte ENR node ID
pub fn getCustodyColumnSubnets(
    allocator: Allocator,
    node_id: [32]u8,
    custody_group_count: u64,
) ![]u64 {
    const count = @min(custody_group_count, NUMBER_OF_CUSTODY_GROUPS);
    if (count == 0) return allocator.alloc(u64, 0);

    if (count == NUMBER_OF_CUSTODY_GROUPS) {
        const all_groups = try allocator.alloc(u64, NUMBER_OF_CUSTODY_GROUPS);
        for (0..NUMBER_OF_CUSTODY_GROUPS) |i| all_groups[i] = i;
        return all_groups;
    }

    var groups = try allocator.alloc(u64, count);
    errdefer allocator.free(groups);

    var selected = std.StaticBitSet(NUMBER_OF_CUSTODY_GROUPS).initEmpty();
    var current = nodeIdToSszUint256(node_id);
    var found: usize = 0;
    while (found < count) {
        var hash_out: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&current, &hash_out, .{});
        const custody_group = std.mem.readInt(u64, hash_out[0..8], .little) % NUMBER_OF_CUSTODY_GROUPS;
        if (!selected.isSet(@intCast(custody_group))) {
            selected.set(@intCast(custody_group));
            groups[found] = custody_group;
            found += 1;
        }
        incrementSszUint256(&current);
    }

    std.sort.pdq(u64, groups, {}, std.sort.asc(u64));
    return groups;
}

/// Compute which data columns this node must custody.
///
/// Expands custody groups into columns using
/// `column = NUMBER_OF_CUSTODY_GROUPS * i + custody_group`.
///
/// Returns a sorted slice of column indices. Caller owns the returned memory.
pub fn getCustodyColumns(
    allocator: Allocator,
    node_id: [32]u8,
    custody_group_count: u64,
) ![]u64 {
    const groups = try getCustodyColumnSubnets(allocator, node_id, custody_group_count);
    defer allocator.free(groups);

    const columns_per_group = NUMBER_OF_COLUMNS / NUMBER_OF_CUSTODY_GROUPS;
    const result = try allocator.alloc(u64, groups.len * columns_per_group);
    errdefer allocator.free(result);

    var out_i: usize = 0;
    for (groups) |group| {
        for (0..columns_per_group) |column_i| {
            result[out_i] = NUMBER_OF_CUSTODY_GROUPS * column_i + group;
            out_i += 1;
        }
    }

    std.sort.pdq(u64, result, {}, std.sort.asc(u64));
    return result;
}

/// Check whether a specific column index is within the given custody set.
pub fn isCustodied(column_index: u64, custody_columns: []const u64) bool {
    // custody_columns is sorted (from getCustodyColumns), so binary search is correct.
    return std.sort.binarySearch(u64, custody_columns, column_index, struct {
        fn order(key: u64, item: u64) std.math.Order {
            return std.math.order(key, item);
        }
    }.order) != null;
}

/// Check whether a specific column subnet is within the custody set.
///
/// Equivalent to `isCustodied` when subnet count == column count.
pub fn isCustodiedSubnet(subnet_id: u64, custody_subnets: []const u64) bool {
    return isCustodied(subnet_id, custody_subnets);
}

fn nodeIdToSszUint256(node_id: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    for (0..32) |i| out[i] = node_id[31 - i];
    return out;
}

fn incrementSszUint256(value: *[32]u8) void {
    for (value) |*byte| {
        if (byte.* == std.math.maxInt(u8)) {
            byte.* = 0;
            continue;
        }
        byte.* += 1;
        return;
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

test "getCustodyColumns: deterministic output for fixed node_id" {
    const allocator = testing.allocator;

    const node_id: [32]u8 = [_]u8{0x01} ** 32;
    const cols = try getCustodyColumns(allocator, node_id, CUSTODY_REQUIREMENT);
    defer allocator.free(cols);

    // Should return exactly CUSTODY_REQUIREMENT columns.
    try testing.expectEqual(CUSTODY_REQUIREMENT, cols.len);

    // Calling again with same inputs must return same result.
    const cols2 = try getCustodyColumns(allocator, node_id, CUSTODY_REQUIREMENT);
    defer allocator.free(cols2);

    try testing.expectEqualSlices(u64, cols, cols2);
}

test "getCustodyColumns: matches Lodestar/spec golden vector" {
    const allocator = testing.allocator;

    const node_id: [32]u8 = [_]u8{0x01} ** 32;
    const cols = try getCustodyColumns(allocator, node_id, CUSTODY_REQUIREMENT);
    defer allocator.free(cols);

    try testing.expectEqualSlices(u64, &[_]u64{ 36, 80, 92, 114 }, cols);
}

test "getCustodyColumns: different node_ids produce different custody sets" {
    const allocator = testing.allocator;

    const node_a: [32]u8 = [_]u8{0xAA} ** 32;
    const node_b: [32]u8 = [_]u8{0xBB} ** 32;

    const cols_a = try getCustodyColumns(allocator, node_a, CUSTODY_REQUIREMENT);
    defer allocator.free(cols_a);

    const cols_b = try getCustodyColumns(allocator, node_b, CUSTODY_REQUIREMENT);
    defer allocator.free(cols_b);

    // With high probability, different node IDs produce different custody sets.
    // (not guaranteed for all inputs, but 0xAA vs 0xBB should differ)
    try testing.expect(!std.mem.eql(u64, cols_a, cols_b));
}

test "getCustodyColumns: result is sorted and within range" {
    const allocator = testing.allocator;

    const node_id: [32]u8 = [_]u8{0x42} ** 32;
    const cols = try getCustodyColumns(allocator, node_id, 8);
    defer allocator.free(cols);

    try testing.expectEqual(@as(usize, 8), cols.len);

    // All columns must be in [0, NUMBER_OF_COLUMNS).
    for (cols) |col| {
        try testing.expect(col < NUMBER_OF_COLUMNS);
    }

    // Must be sorted (ascending).
    for (1..cols.len) |i| {
        try testing.expect(cols[i] > cols[i - 1]);
    }

    // No duplicates (follows from sorted + unique).
    for (1..cols.len) |i| {
        try testing.expect(cols[i] != cols[i - 1]);
    }
}

test "getCustodyColumns: full custody (all columns)" {
    const allocator = testing.allocator;

    const node_id: [32]u8 = [_]u8{0xFF} ** 32;
    const cols = try getCustodyColumns(allocator, node_id, NUMBER_OF_CUSTODY_GROUPS);
    defer allocator.free(cols);

    // Full custody returns all 128 columns.
    try testing.expectEqual(@as(usize, NUMBER_OF_COLUMNS), cols.len);

    // Every column index 0..128 must be present exactly once.
    var seen = [_]bool{false} ** NUMBER_OF_COLUMNS;
    for (cols) |col| {
        try testing.expect(col < NUMBER_OF_COLUMNS);
        try testing.expect(!seen[col]);
        seen[col] = true;
    }
}

test "getCustodyColumns: clamps to max when count exceeds max" {
    const allocator = testing.allocator;

    const node_id: [32]u8 = [_]u8{0x00} ** 32;
    const cols = try getCustodyColumns(allocator, node_id, NUMBER_OF_CUSTODY_GROUPS + 100);
    defer allocator.free(cols);

    // Should be clamped to full custody.
    try testing.expectEqual(@as(usize, NUMBER_OF_COLUMNS), cols.len);
}

test "isCustodied: finds custodied column" {
    const allocator = testing.allocator;

    const node_id: [32]u8 = [_]u8{0x01} ** 32;
    const cols = try getCustodyColumns(allocator, node_id, CUSTODY_REQUIREMENT);
    defer allocator.free(cols);

    // Each column in the custody set should be found.
    for (cols) |col| {
        try testing.expect(isCustodied(col, cols));
    }
}

test "isCustodied: non-custodied column returns false" {
    // Create a known custody set and verify non-members.
    const custody = [_]u64{ 10, 20, 30, 40 };

    try testing.expect(!isCustodied(0, &custody));
    try testing.expect(!isCustodied(15, &custody));
    try testing.expect(!isCustodied(127, &custody));

    try testing.expect(isCustodied(10, &custody));
    try testing.expect(isCustodied(40, &custody));
}

test "getCustodyColumnSubnets: returns sorted unique custody groups" {
    const allocator = testing.allocator;

    const node_id: [32]u8 = [_]u8{0x55} ** 32;
    const subnets = try getCustodyColumnSubnets(allocator, node_id, CUSTODY_REQUIREMENT);
    defer allocator.free(subnets);

    try testing.expectEqual(@as(usize, CUSTODY_REQUIREMENT), subnets.len);

    // All subnets must be in valid range.
    for (subnets) |s| {
        try testing.expect(s < NUMBER_OF_CUSTODY_GROUPS);
    }

    for (1..subnets.len) |i| {
        try testing.expect(subnets[i] > subnets[i - 1]);
    }
}
