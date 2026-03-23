//! Checkpoint sync: bootstrap from a trusted finalized state.
//!
//! Instead of syncing from genesis, a node can start from a recent
//! finalized checkpoint state + the corresponding block. This drastically
//! reduces initial sync time (minutes instead of hours/days).
//!
//! The trusted root must be verified out-of-band (from a block explorer,
//! a trusted friend's node, etc.).
//!
//! Reference: Lodestar `packages/beacon-node/src/chain/initState.ts`

const std = @import("std");
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const db_mod = @import("db");
const BeaconDB = db_mod.BeaconDB;

pub const CheckpointSyncResult = struct {
    state_slot: u64,
    state_root: [32]u8,
    block_root: [32]u8,
};

pub const CheckpointSyncError = error{
    /// The computed state root does not match the trusted root.
    StateRootMismatch,
    /// The checkpoint state bytes are empty.
    EmptyState,
    /// The checkpoint block bytes are empty.
    EmptyBlock,
};

pub const CheckpointSync = struct {
    allocator: Allocator,
    db: *BeaconDB,

    pub fn init(allocator: Allocator, db: *BeaconDB) CheckpointSync {
        return .{
            .allocator = allocator,
            .db = db,
        };
    }

    /// Bootstrap from a checkpoint: validate, persist state + block.
    ///
    /// `checkpoint_state_bytes`: SSZ-encoded BeaconState at the finalized slot.
    /// `checkpoint_block_bytes`: SSZ-encoded SignedBeaconBlock at the same slot.
    /// `trusted_root`: the expected SHA-256 hash of `checkpoint_state_bytes`.
    ///
    /// The caller is responsible for obtaining these from a trusted source
    /// (e.g. a `/eth/v2/debug/beacon/states/finalized` endpoint).
    pub fn syncFromCheckpoint(
        self: *CheckpointSync,
        checkpoint_state_bytes: []const u8,
        checkpoint_block_bytes: []const u8,
        trusted_root: [32]u8,
    ) !CheckpointSyncResult {
        if (checkpoint_state_bytes.len == 0) return CheckpointSyncError.EmptyState;
        if (checkpoint_block_bytes.len == 0) return CheckpointSyncError.EmptyBlock;

        // Compute the SHA-256 hash of the state bytes as a simple
        // integrity check. In production this would be an SSZ hash-tree-root,
        // but at this layer we operate on opaque bytes and use the hash
        // the caller provides.
        var state_hash: [32]u8 = undefined;
        Sha256.hash(checkpoint_state_bytes, &state_hash, .{});

        if (!std.mem.eql(u8, &state_hash, &trusted_root)) {
            return CheckpointSyncError.StateRootMismatch;
        }

        // Compute block root similarly.
        var block_root: [32]u8 = undefined;
        Sha256.hash(checkpoint_block_bytes, &block_root, .{});

        // Extract slot from the state bytes. In SSZ-encoded BeaconState,
        // the slot is at offset 40 (after genesis_time:u64 = offset 0..8,
        // genesis_validators_root:Bytes32 = offset 8..40, slot:u64 = 40..48).
        //
        // Note: this is a minimal extraction. A full implementation would
        // use the SSZ type to deserialize.
        const state_slot = extractSlotFromState(checkpoint_state_bytes) orelse 0;

        // Persist the checkpoint state and block.
        try self.db.putStateArchive(state_slot, state_hash, checkpoint_state_bytes);
        try self.db.putBlockArchive(state_slot, block_root, checkpoint_block_bytes);

        return .{
            .state_slot = state_slot,
            .state_root = state_hash,
            .block_root = block_root,
        };
    }

    /// Extract the slot field from SSZ-encoded BeaconState bytes.
    /// Returns null if the bytes are too short.
    pub fn extractSlotFromState(state_bytes: []const u8) ?u64 {
        // BeaconState layout: genesis_time(8) + genesis_validators_root(32) + slot(8)
        const slot_offset = 8 + 32; // 40
        if (state_bytes.len < slot_offset + 8) return null;
        return std.mem.readInt(u64, state_bytes[slot_offset..][0..8], .little);
    }
};

// ── Tests ────────────────────────────────────────────────────────────

test "CheckpointSync: successful checkpoint import" {
    const allocator = std.testing.allocator;
    var kv = db_mod.MemoryKVStore.init(allocator);
    defer kv.deinit();
    var db = BeaconDB.init(allocator, kv.kvStore());

    var cs = CheckpointSync.init(allocator, &db);

    // Build a fake state blob with a slot embedded at offset 40.
    var state_bytes: [128]u8 = [_]u8{0} ** 128;
    const slot: u64 = 12345;
    @memcpy(state_bytes[40..48], std.mem.asBytes(&std.mem.nativeToLittle(u64, slot)));

    // Compute expected hash.
    var expected_root: [32]u8 = undefined;
    Sha256.hash(&state_bytes, &expected_root, .{});

    var block_bytes: [64]u8 = [_]u8{0xBB} ** 64;

    const result = try cs.syncFromCheckpoint(&state_bytes, &block_bytes, expected_root);

    try std.testing.expectEqual(slot, result.state_slot);
    try std.testing.expectEqual(expected_root, result.state_root);

    // Verify block was persisted.
    const stored_block = try db.getBlockArchive(slot);
    defer if (stored_block) |b| allocator.free(b);
    try std.testing.expect(stored_block != null);

    // Verify state was persisted.
    const stored_state = try db.getStateArchive(slot);
    defer if (stored_state) |s| allocator.free(s);
    try std.testing.expect(stored_state != null);
}

test "CheckpointSync: rejects mismatched state root" {
    const allocator = std.testing.allocator;
    var kv = db_mod.MemoryKVStore.init(allocator);
    defer kv.deinit();
    var db = BeaconDB.init(allocator, kv.kvStore());

    var cs = CheckpointSync.init(allocator, &db);

    const state_bytes = [_]u8{0xAA} ** 64;
    const block_bytes = [_]u8{0xBB} ** 64;
    const wrong_root = [_]u8{0xFF} ** 32;

    const result = cs.syncFromCheckpoint(&state_bytes, &block_bytes, wrong_root);
    try std.testing.expectError(CheckpointSyncError.StateRootMismatch, result);
}

test "CheckpointSync: rejects empty state" {
    const allocator = std.testing.allocator;
    var kv = db_mod.MemoryKVStore.init(allocator);
    defer kv.deinit();
    var db = BeaconDB.init(allocator, kv.kvStore());

    var cs = CheckpointSync.init(allocator, &db);

    const result = cs.syncFromCheckpoint("", "block", [_]u8{0} ** 32);
    try std.testing.expectError(CheckpointSyncError.EmptyState, result);
}

test "CheckpointSync: rejects empty block" {
    const allocator = std.testing.allocator;
    var kv = db_mod.MemoryKVStore.init(allocator);
    defer kv.deinit();
    var db = BeaconDB.init(allocator, kv.kvStore());

    var cs = CheckpointSync.init(allocator, &db);

    const result = cs.syncFromCheckpoint("state", "", [_]u8{0} ** 32);
    try std.testing.expectError(CheckpointSyncError.EmptyBlock, result);
}

test "CheckpointSync: extractSlotFromState parses correctly" {
    var buf: [64]u8 = [_]u8{0} ** 64;
    const slot: u64 = 98765;
    @memcpy(buf[40..48], std.mem.asBytes(&std.mem.nativeToLittle(u64, slot)));

    const extracted = CheckpointSync.extractSlotFromState(&buf);
    try std.testing.expectEqual(@as(?u64, slot), extracted);
}

test "CheckpointSync: extractSlotFromState returns null for short input" {
    const buf = [_]u8{0} ** 20;
    try std.testing.expect(CheckpointSync.extractSlotFromState(&buf) == null);
}
