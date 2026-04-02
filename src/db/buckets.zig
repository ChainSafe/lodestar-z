//! Database identifiers for the beacon chain database.
//!
//! Each DatabaseId maps to a named LMDB database (DBI), providing native
//! namespace isolation without key prefixes. This replaces the old bucket
//! prefix scheme inherited from TS Lodestar.
//!
//! See DESIGN.md for the full schema.

const std = @import("std");

/// Identifies a named database within the LMDB environment.
/// Each variant maps to a DBI name string used with mdb_dbi_open().
pub const DatabaseId = enum {
    // ---- Beacon chain core ----

    /// Finalized states: Slot (8B BE) -> SSZ BeaconState
    state_archive,
    /// Unfinalized blocks: Root (32B) -> SSZ SignedBeaconBlock
    block,
    /// Finalized blocks: Slot (8B BE) -> SSZ SignedBeaconBlock
    block_archive,

    // ---- Block archive indices ----

    /// Parent Root (32B) -> Slot (8B BE)
    idx_block_parent_root,
    /// Root (32B) -> Slot (8B BE)
    idx_block_root,
    /// Slot (8B BE) -> Root (32B)
    idx_main_chain,
    /// Mixed metadata: short string keys -> variable values
    chain_info,

    // ---- Op pool ----

    /// ValidatorIndex (8B BE) -> SSZ VoluntaryExit
    exit,
    /// ValidatorIndex (8B BE) -> SSZ ProposerSlashing
    proposer_slashing,
    /// Root (32B) -> SSZ AttesterSlashing
    attester_slashing,
    /// ValidatorIndex (8B BE) -> SSZ SignedBLSToExecutionChange
    bls_change,

    // ---- Checkpoint states ----

    /// Root (32B) -> SSZ BeaconState
    checkpoint_state,

    // ---- State archive index ----

    /// State Root (32B) -> Slot (8B BE)
    idx_state_root,

    // ---- Blob sidecars ----

    /// Root (32B) -> SSZ BlobSidecars (hot)
    blob_sidecar,
    /// Slot (8B BE) -> SSZ BlobSidecars (archive)
    blob_sidecar_archive,

    // ---- Backfill ----

    /// From (8B BE) -> To (8B BE)
    backfill_ranges,

    // ---- Light client ----

    /// BlockRoot (32B) -> SyncCommitteeWitness
    lc_sync_witness,
    /// Root(SyncCommittee) (32B) -> SSZ SyncCommittee
    lc_sync_committee,
    /// BlockRoot (32B) -> SSZ BeaconBlockHeader
    lc_checkpoint_header,
    /// SyncPeriod (8B BE) -> [Slot, LightClientUpdate]
    lc_best_update,

    // ---- Data columns (PeerDAS / Fulu) ----

    /// Root (32B) -> SSZ DataColumnSidecars (hot)
    data_column,
    /// Slot (8B BE) -> SSZ DataColumnSidecars (archive)
    data_column_archive,
    /// Root(32B) ++ ColumnIndex(8B BE) -> single DataColumnSidecar (hot)
    data_column_single,
    /// Slot(8B BE) ++ ColumnIndex(8B BE) -> single DataColumnSidecar (archive)
    data_column_single_archive,

    // ---- ePBS (Gloas) ----

    /// Root (32B) -> SSZ SignedExecutionPayloadEnvelope (hot)
    epbs_payload,
    /// Slot (8B BE) -> SSZ SignedExecutionPayloadEnvelope (archive)
    epbs_payload_archive,

    // ---- Internal ----

    /// Fork choice persistence: short string -> serialized data
    fork_choice,
    /// Pubkey (48B) -> ValidatorIndex (8B BE)
    validator_index,

    /// Get the DBI name string for mdb_dbi_open().
    pub fn name(self: DatabaseId) [:0]const u8 {
        return switch (self) {
            .state_archive => "state_archive",
            .block => "block",
            .block_archive => "block_archive",
            .idx_block_parent_root => "idx_block_parent_root",
            .idx_block_root => "idx_block_root",
            .idx_main_chain => "idx_main_chain",
            .chain_info => "chain_info",
            .exit => "exit",
            .proposer_slashing => "proposer_slashing",
            .attester_slashing => "attester_slashing",
            .bls_change => "bls_change",
            .checkpoint_state => "checkpoint_state",
            .idx_state_root => "idx_state_root",
            .blob_sidecar => "blob_sidecar",
            .blob_sidecar_archive => "blob_sidecar_archive",
            .backfill_ranges => "backfill_ranges",
            .lc_sync_witness => "lc_sync_witness",
            .lc_sync_committee => "lc_sync_committee",
            .lc_checkpoint_header => "lc_checkpoint_header",
            .lc_best_update => "lc_best_update",
            .data_column => "data_column",
            .data_column_archive => "data_column_archive",
            .data_column_single => "data_column_single",
            .data_column_single_archive => "data_column_single_archive",
            .epbs_payload => "epbs_payload",
            .epbs_payload_archive => "epbs_payload_archive",
            .fork_choice => "fork_choice",
            .validator_index => "validator_index",
        };
    }

    /// All database IDs in order, for iteration during init.
    pub const all = std.enums.values(DatabaseId);

    /// Number of named databases.
    pub const count = all.len;
};

/// Encode a u64 as 8 bytes big-endian. Returns a stack-allocated array.
///
/// Big-endian (network byte order) is used explicitly to:
/// 1. Ensure portability across architectures (no implicit native-endian dependency)
/// 2. Preserve LMDB's lexicographic sort order as slot ascending (BE integers sort
///    correctly by value under bytewise comparison)
pub fn slotKey(slot: u64) [8]u8 {
    return encodeU64BE(slot);
}

/// Generic big-endian u64 encoder. Use this for non-slot values (e.g., validator indices).
/// `slotKey` is an alias kept for readability at slot-keyed call sites.
pub fn encodeU64BE(value: u64) [8]u8 {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .big);
    return buf;
}

/// Encode a composite key: root(32) ++ column_index(8 BE).
pub fn rootColumnKey(root: [32]u8, column_index: u64) [40]u8 {
    var key: [40]u8 = undefined;
    @memcpy(key[0..32], &root);
    std.mem.writeInt(u64, key[32..40], column_index, .big);
    return key;
}

/// Encode a composite key: slot(8 BE) ++ column_index(8 BE).
pub fn slotColumnKey(slot: u64, column_index: u64) [16]u8 {
    var key: [16]u8 = undefined;
    std.mem.writeInt(u64, key[0..8], slot, .big);
    std.mem.writeInt(u64, key[8..16], column_index, .big);
    return key;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "DatabaseId: all names are unique" {
    // Verify at runtime that all DBI names are distinct.
    const names = comptime blk: {
        var result: [DatabaseId.count][:0]const u8 = undefined;
        for (DatabaseId.all, 0..) |id, i| {
            result[i] = id.name();
        }
        break :blk result;
    };
    for (names, 0..) |a, i| {
        for (names[i + 1 ..]) |b| {
            if (std.mem.eql(u8, a, b)) {
                std.debug.panic("Duplicate database name: {s}", .{a});
            }
        }
    }
}

test "DatabaseId: count is reasonable" {
    // LMDB supports up to 128 named DBs; we should be well under
    try std.testing.expect(DatabaseId.count > 0);
    try std.testing.expect(DatabaseId.count <= 128);
}

test "slotKey: encodes u64 as BE" {
    const key = slotKey(0x1234);
    // Big-endian: most significant byte first
    for (key[0..6]) |b| try std.testing.expectEqual(@as(u8, 0), b);
    try std.testing.expectEqual(@as(u8, 0x12), key[6]);
    try std.testing.expectEqual(@as(u8, 0x34), key[7]);
}

test "rootColumnKey: 40-byte composite key" {
    const root = [_]u8{0xaa} ** 32;
    const key = rootColumnKey(root, 5);
    try std.testing.expectEqualSlices(u8, &root, key[0..32]);
    // Big-endian: value 5 is at the last byte
    try std.testing.expectEqual(@as(u8, 0), key[32]); // leading zeros in BE
    try std.testing.expectEqual(@as(u8, 5), key[39]); // least-significant byte last
}

test "slotColumnKey: 16-byte composite key" {
    const key = slotColumnKey(17, 5);
    try std.testing.expectEqual(@as(u8, 0), key[0]);
    try std.testing.expectEqual(@as(u8, 17), key[7]);
    try std.testing.expectEqual(@as(u8, 0), key[8]);
    try std.testing.expectEqual(@as(u8, 5), key[15]);
}
