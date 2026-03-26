//! Bucket prefixes for key namespacing in the beacon chain database.
//!
//! Mirrors Lodestar's `packages/beacon-node/src/db/buckets.ts`.
//! Each bucket uses a single-byte prefix to partition the keyspace.
//!
//! Key format: [1-byte bucket] ++ [key_bytes...]

const std = @import("std");

pub const Bucket = enum(u8) {
    // ---- Beacon chain core ----

    /// Finalized states: Root -> SSZ BeaconState
    all_forks_state_archive = 0,
    /// Unfinalized blocks: Root -> SSZ SignedBeaconBlock
    all_forks_block = 1,
    /// Finalized blocks: Slot (8 bytes LE) -> SSZ SignedBeaconBlock
    all_forks_block_archive = 2,

    // ---- Block archive indices ----

    /// Parent root -> Slot (finalized blocks)
    index_block_archive_parent_root = 3,
    /// Root -> Slot (finalized blocks)
    index_block_archive_root = 4,
    /// Slot -> Root (main chain mapping)
    index_main_chain = 6,
    /// Mixed metadata: justified/finalized roots, etc.
    index_chain_info = 7,

    // ---- Op pool ----

    /// ValidatorIndex -> VoluntaryExit
    phase0_exit = 13,
    /// ValidatorIndex -> ProposerSlashing
    phase0_proposer_slashing = 14,
    /// Root -> AttesterSlashing
    all_forks_attester_slashing = 15,
    /// ValidatorIndex -> SignedBLSToExecutionChange
    capella_bls_to_execution_change = 16,

    // ---- Checkpoint states ----

    /// Root -> SSZ BeaconState (checkpoint boundary)
    all_forks_checkpoint_state = 17,

    // ---- State archive index ----

    /// State Root -> Slot
    index_state_archive_root = 26,

    // ---- Blob sidecars ----

    /// Root -> SSZ BlobSidecars (hot)
    deneb_blob_sidecars = 27,
    /// Slot -> SSZ BlobSidecars (archive)
    deneb_blob_sidecars_archive = 28,

    // ---- Backfill ----

    /// From -> To (inclusive range)
    backfilled_ranges = 42,

    // ---- Light client ----

    /// BlockRoot -> SyncCommitteeWitness
    light_client_sync_committee_witness = 51,
    /// Root(SyncCommittee) -> SyncCommittee
    light_client_sync_committee = 52,
    /// BlockRoot -> BeaconBlockHeader
    light_client_checkpoint_header = 53,
    /// SyncPeriod -> [Slot, LightClientUpdate]
    light_client_best_update = 56,

    // ---- Data columns (PeerDAS / Fulu) ----

    /// Root -> DataColumnSidecars (hot)
    fulu_data_column_sidecars = 57,
    /// Slot -> DataColumnSidecars (archive)
    fulu_data_column_sidecars_archive = 58,
    /// Root(32) ++ ColumnIndex(8 LE) -> single DataColumnSidecar (hot, per-column)
    fulu_data_column_sidecar = 61,

    // ---- ePBS (Gloas) ----

    /// Root -> SignedExecutionPayloadEnvelope (hot)
    gloas_execution_payload_envelope = 59,
    /// Slot -> SignedExecutionPayloadEnvelope (archive)
    gloas_execution_payload_envelope_archive = 60,

    // ---- Internal / custom ----

    /// For fork choice persistence
    fork_choice = 240,
    /// For validator pubkey -> index mapping
    validator_index = 241,
};

/// Construct a bucket-prefixed key: [bucket_byte] ++ key_bytes.
/// Caller owns the returned slice.
pub fn bucketKey(allocator: std.mem.Allocator, bucket: Bucket, key_bytes: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, 1 + key_bytes.len);
    result[0] = @intFromEnum(bucket);
    @memcpy(result[1..], key_bytes);
    return result;
}

/// Construct a bucket-prefixed key for a 32-byte root.
/// Returns a 33-byte owned slice.
pub fn bucketRootKey(allocator: std.mem.Allocator, bucket: Bucket, root: [32]u8) ![]u8 {
    const result = try allocator.alloc(u8, 33);
    result[0] = @intFromEnum(bucket);
    @memcpy(result[1..33], &root);
    return result;
}

/// Construct a bucket-prefixed key for a u64 slot (little-endian).
/// Returns a 9-byte owned slice.
pub fn bucketSlotKey(allocator: std.mem.Allocator, bucket: Bucket, slot: u64) ![]u8 {
    const result = try allocator.alloc(u8, 9);
    result[0] = @intFromEnum(bucket);
    @memcpy(result[1..9], &std.mem.toBytes(slot));
    return result;
}

/// Single-byte prefix for a bucket, usable for prefix scans.
pub fn bucketPrefix(bucket: Bucket) [1]u8 {
    return .{@intFromEnum(bucket)};
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "bucketKey: constructs correct prefix" {
    const allocator = std.testing.allocator;
    const key = try bucketKey(allocator, .all_forks_block, &[_]u8{ 0xab, 0xcd });
    defer allocator.free(key);

    try std.testing.expectEqual(@as(usize, 3), key.len);
    try std.testing.expectEqual(@as(u8, 1), key[0]); // all_forks_block = 1
    try std.testing.expectEqual(@as(u8, 0xab), key[1]);
    try std.testing.expectEqual(@as(u8, 0xcd), key[2]);
}

test "bucketRootKey: 33-byte key" {
    const allocator = std.testing.allocator;
    const root = [_]u8{0xff} ** 32;
    const key = try bucketRootKey(allocator, .all_forks_state_archive, root);
    defer allocator.free(key);

    try std.testing.expectEqual(@as(usize, 33), key.len);
    try std.testing.expectEqual(@as(u8, 0), key[0]); // all_forks_state_archive = 0
    try std.testing.expectEqualSlices(u8, &root, key[1..33]);
}

test "bucketSlotKey: 9-byte key with LE slot" {
    const allocator = std.testing.allocator;
    const key = try bucketSlotKey(allocator, .all_forks_block_archive, 0x1234);
    defer allocator.free(key);

    try std.testing.expectEqual(@as(usize, 9), key.len);
    try std.testing.expectEqual(@as(u8, 2), key[0]); // all_forks_block_archive = 2
    // Little-endian 0x1234
    try std.testing.expectEqual(@as(u8, 0x34), key[1]);
    try std.testing.expectEqual(@as(u8, 0x12), key[2]);
}

test "bucketPrefix: single byte" {
    const prefix = bucketPrefix(.deneb_blob_sidecars);
    try std.testing.expectEqual(@as(u8, 27), prefix[0]);
}

test "Bucket: enum values match Lodestar" {
    // Verify critical bucket values match TS Lodestar
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(Bucket.all_forks_state_archive));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(Bucket.all_forks_block));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(Bucket.all_forks_block_archive));
    try std.testing.expectEqual(@as(u8, 4), @intFromEnum(Bucket.index_block_archive_root));
    try std.testing.expectEqual(@as(u8, 6), @intFromEnum(Bucket.index_main_chain));
    try std.testing.expectEqual(@as(u8, 27), @intFromEnum(Bucket.deneb_blob_sidecars));
    try std.testing.expectEqual(@as(u8, 28), @intFromEnum(Bucket.deneb_blob_sidecars_archive));
}
