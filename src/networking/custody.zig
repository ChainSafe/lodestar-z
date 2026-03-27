//! PeerDAS custody column computation.
//!
//! Implements `get_custody_columns(node_id, custody_subnet_count)` from the
//! consensus spec for the fulu/PeerDAS fork.
//!
//! Each node custodies a deterministic subset of data column subnets derived
//! from its node ID (the ENR node ID, 32 bytes). The custody columns are spread
//! evenly across the available column subnets using a shuffled index approach.
//!
//! Reference:
//!   https://github.com/ethereum/consensus-specs/blob/dev/specs/fulu/p2p-interface.md
//!   get_custody_columns(node_id, custody_subnet_count) -> Sequence[ColumnIndex]

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.custody);

// ─── Constants ────────────────────────────────────────────────────────────────

/// Total number of data column subnets (= NUMBER_OF_COLUMNS on mainnet).
pub const DATA_COLUMN_SIDECAR_SUBNET_COUNT: u64 = 128;

/// Total number of data columns per blob (= NUMBER_OF_COLUMNS).
pub const NUMBER_OF_COLUMNS: u64 = 128;

/// Default custody requirement: how many column subnets a node custodies by default.
pub const CUSTODY_REQUIREMENT: u64 = 4;

/// Maximum custody subnet count (full node custodies all columns).
pub const MAX_CUSTODY_SUBNET_COUNT: u64 = DATA_COLUMN_SIDECAR_SUBNET_COUNT;

// ─── Core algorithm ──────────────────────────────────────────────────────────

/// Compute the set of data column subnets this node must custody.
///
/// Based on the consensus spec `get_custody_columns(node_id, custody_subnet_count)`:
///
/// 1. For each candidate subnet index (0..DATA_COLUMN_SIDECAR_SUBNET_COUNT), compute:
///    `hash(node_id || subnet_index_bytes)` and derive a sort key
/// 2. Sort candidates by their hash keys
/// 3. Take the first `custody_subnet_count` subnets
///
/// Returns a slice of column subnet IDs. Caller owns the returned memory.
///
/// Preconditions:
/// - `custody_subnet_count <= DATA_COLUMN_SIDECAR_SUBNET_COUNT`
/// - `node_id` is the 32-byte ENR node ID
pub fn getCustodyColumnSubnets(
    allocator: Allocator,
    node_id: [32]u8,
    custody_subnet_count: u64,
) ![]u64 {
    const count = @min(custody_subnet_count, DATA_COLUMN_SIDECAR_SUBNET_COUNT);

    // Generate (hash, subnet_id) pairs for all subnets.
    // hash = SHA256(node_id || subnet_id_as_uint64_little_endian)
    const Entry = struct { hash: [32]u8, subnet_id: u64 };
    const entries = try allocator.alloc(Entry, DATA_COLUMN_SIDECAR_SUBNET_COUNT);
    defer allocator.free(entries);

    var input_buf: [32 + 8]u8 = undefined;
    @memcpy(input_buf[0..32], &node_id);

    for (0..DATA_COLUMN_SIDECAR_SUBNET_COUNT) |i| {
        std.mem.writeInt(u64, input_buf[32..40], @intCast(i), .little);
        var hash_out: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&input_buf, &hash_out, .{});
        entries[i] = .{ .hash = hash_out, .subnet_id = @intCast(i) };
    }

    // Sort by hash value (lexicographic on bytes — deterministic across platforms).
    std.sort.pdq(Entry, entries, {}, struct {
        fn lessThan(_: void, a: Entry, b: Entry) bool {
            return std.mem.lessThan(u8, &a.hash, &b.hash);
        }
    }.lessThan);

    // Take the first `count` subnet IDs.
    const result = try allocator.alloc(u64, count);
    for (0..count) |i| {
        result[i] = entries[i].subnet_id;
    }

    return result;
}

/// Compute which data columns this node must custody.
///
/// For PeerDAS where DATA_COLUMN_SIDECAR_SUBNET_COUNT == NUMBER_OF_COLUMNS,
/// custody subnets == custody columns (1:1 mapping).
///
/// Returns a sorted slice of column indices. Caller owns the returned memory.
pub fn getCustodyColumns(
    allocator: Allocator,
    node_id: [32]u8,
    custody_subnet_count: u64,
) ![]u64 {
    const subnets = try getCustodyColumnSubnets(allocator, node_id, custody_subnet_count);
    errdefer allocator.free(subnets);

    // When subnet count == column count (the Fulu mainnet config), subnet IDs
    // are column indices directly. Sort for stable iteration order.
    std.sort.pdq(u64, subnets, {}, std.sort.asc(u64));
    return subnets;
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
    const cols = try getCustodyColumns(allocator, node_id, DATA_COLUMN_SIDECAR_SUBNET_COUNT);
    defer allocator.free(cols);

    // Full custody returns all 128 columns.
    try testing.expectEqual(@as(usize, DATA_COLUMN_SIDECAR_SUBNET_COUNT), cols.len);

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
    const cols = try getCustodyColumns(allocator, node_id, DATA_COLUMN_SIDECAR_SUBNET_COUNT + 100);
    defer allocator.free(cols);

    // Should be clamped to DATA_COLUMN_SIDECAR_SUBNET_COUNT.
    try testing.expectEqual(@as(usize, DATA_COLUMN_SIDECAR_SUBNET_COUNT), cols.len);
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

test "getCustodyColumnSubnets: returns unsorted subnet IDs" {
    const allocator = testing.allocator;

    const node_id: [32]u8 = [_]u8{0x55} ** 32;
    const subnets = try getCustodyColumnSubnets(allocator, node_id, CUSTODY_REQUIREMENT);
    defer allocator.free(subnets);

    try testing.expectEqual(@as(usize, CUSTODY_REQUIREMENT), subnets.len);

    // All subnets must be in valid range.
    for (subnets) |s| {
        try testing.expect(s < DATA_COLUMN_SIDECAR_SUBNET_COUNT);
    }
}
