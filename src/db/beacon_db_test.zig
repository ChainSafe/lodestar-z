//! Tests for the BeaconDB high-level interface.
//!
//! Exercises all typed accessors using the MemoryKVStore backend.

const std = @import("std");
const beacon_db_mod = @import("beacon_db.zig");
const BeaconDB = beacon_db_mod.BeaconDB;
const memory_kv_store = @import("memory_kv_store.zig");
const MemoryKVStore = memory_kv_store.MemoryKVStore;

fn makeTestDB(allocator: std.mem.Allocator) struct { store: *MemoryKVStore, db: BeaconDB } {
    const store = allocator.create(MemoryKVStore) catch @panic("OOM");
    store.* = MemoryKVStore.init(allocator);
    return .{
        .store = store,
        .db = BeaconDB.init(allocator, store.kvStore()),
    };
}

fn destroyTestDB(allocator: std.mem.Allocator, store: *MemoryKVStore) void {
    store.deinit();
    allocator.destroy(store);
}

// ---- Block operations (hot) ----

test "BeaconDB: put and get block by root" {
    const allocator = std.testing.allocator;
    var t = makeTestDB(allocator);
    defer destroyTestDB(allocator, t.store);

    const root = [_]u8{0xaa} ** 32;
    const block_data = "signed_beacon_block_ssz_bytes";

    try t.db.putBlock(root, block_data);
    const result = try t.db.getBlock(root);
    defer if (result) |r| allocator.free(r);

    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, block_data, result.?);
}

test "BeaconDB: get missing block returns null" {
    const allocator = std.testing.allocator;
    var t = makeTestDB(allocator);
    defer destroyTestDB(allocator, t.store);

    const result = try t.db.getBlock([_]u8{0x00} ** 32);
    try std.testing.expect(result == null);
}

test "BeaconDB: delete block" {
    const allocator = std.testing.allocator;
    var t = makeTestDB(allocator);
    defer destroyTestDB(allocator, t.store);

    const root = [_]u8{0xbb} ** 32;
    try t.db.putBlock(root, "block_data");
    try t.db.deleteBlock(root);

    const result = try t.db.getBlock(root);
    try std.testing.expect(result == null);
}

// ---- Block archive operations ----

test "BeaconDB: put and get block archive by slot" {
    const allocator = std.testing.allocator;
    var t = makeTestDB(allocator);
    defer destroyTestDB(allocator, t.store);

    const slot: u64 = 12345;
    const root = [_]u8{0xcc} ** 32;
    const block_data = "finalized_block_ssz";

    try t.db.putBlockArchive(slot, root, block_data);

    // Get by slot
    const by_slot = try t.db.getBlockArchive(slot);
    defer if (by_slot) |b| allocator.free(b);
    try std.testing.expect(by_slot != null);
    try std.testing.expectEqualSlices(u8, block_data, by_slot.?);

    // Get by root (via index)
    const by_root = try t.db.getBlockArchiveByRoot(root);
    defer if (by_root) |b| allocator.free(b);
    try std.testing.expect(by_root != null);
    try std.testing.expectEqualSlices(u8, block_data, by_root.?);

    // Get root by slot
    const looked_up_root = try t.db.getBlockRootBySlot(slot);
    try std.testing.expect(looked_up_root != null);
    try std.testing.expectEqualSlices(u8, &root, &looked_up_root.?);
}

test "BeaconDB: get missing block archive returns null" {
    const allocator = std.testing.allocator;
    var t = makeTestDB(allocator);
    defer destroyTestDB(allocator, t.store);

    const result = try t.db.getBlockArchive(99999);
    try std.testing.expect(result == null);

    const by_root = try t.db.getBlockArchiveByRoot([_]u8{0x00} ** 32);
    try std.testing.expect(by_root == null);
}

// ---- State archive operations ----

test "BeaconDB: put and get state archive" {
    const allocator = std.testing.allocator;
    var t = makeTestDB(allocator);
    defer destroyTestDB(allocator, t.store);

    const slot: u64 = 64;
    const state_root = [_]u8{0xdd} ** 32;
    const state_data = "beacon_state_ssz_data";

    try t.db.putStateArchive(slot, state_root, state_data);

    // Get by slot
    const by_slot = try t.db.getStateArchive(slot);
    defer if (by_slot) |s| allocator.free(s);
    try std.testing.expect(by_slot != null);
    try std.testing.expectEqualSlices(u8, state_data, by_slot.?);

    // Look up slot by state root
    const looked_up_slot = try t.db.getStateArchiveSlotByRoot(state_root);
    try std.testing.expect(looked_up_slot != null);
    try std.testing.expectEqual(slot, looked_up_slot.?);
}

// ---- Blob sidecar operations ----

test "BeaconDB: put and get blob sidecars (hot)" {
    const allocator = std.testing.allocator;
    var t = makeTestDB(allocator);
    defer destroyTestDB(allocator, t.store);

    const root = [_]u8{0xee} ** 32;
    const blob_data = "blob_sidecars_ssz";

    try t.db.putBlobSidecars(root, blob_data);

    const result = try t.db.getBlobSidecars(root);
    defer if (result) |r| allocator.free(r);
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, blob_data, result.?);
}

test "BeaconDB: delete blob sidecars" {
    const allocator = std.testing.allocator;
    var t = makeTestDB(allocator);
    defer destroyTestDB(allocator, t.store);

    const root = [_]u8{0xee} ** 32;
    try t.db.putBlobSidecars(root, "blob_data");
    try t.db.deleteBlobSidecars(root);

    const result = try t.db.getBlobSidecars(root);
    try std.testing.expect(result == null);
}

test "BeaconDB: put and get blob sidecars archive" {
    const allocator = std.testing.allocator;
    var t = makeTestDB(allocator);
    defer destroyTestDB(allocator, t.store);

    const slot: u64 = 256;
    try t.db.putBlobSidecarsArchive(slot, "archived_blobs");

    const result = try t.db.getBlobSidecarsArchive(slot);
    defer if (result) |r| allocator.free(r);
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, "archived_blobs", result.?);
}

// ---- Data column sidecars ----

test "BeaconDB: put and get data column sidecars" {
    const allocator = std.testing.allocator;
    var t = makeTestDB(allocator);
    defer destroyTestDB(allocator, t.store);

    const root = [_]u8{0x11} ** 32;
    try t.db.putDataColumnSidecars(root, "columns_data");

    const result = try t.db.getDataColumnSidecars(root);
    defer if (result) |r| allocator.free(r);
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, "columns_data", result.?);
}

test "BeaconDB: put and get data column sidecars archive" {
    const allocator = std.testing.allocator;
    var t = makeTestDB(allocator);
    defer destroyTestDB(allocator, t.store);

    const slot: u64 = 1024;
    try t.db.putDataColumnSidecarsArchive(slot, "archived_columns");

    const result = try t.db.getDataColumnSidecarsArchive(slot);
    defer if (result) |r| allocator.free(r);
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, "archived_columns", result.?);
}

// ---- Fork choice persistence ----

test "BeaconDB: put and get fork choice data" {
    const allocator = std.testing.allocator;
    var t = makeTestDB(allocator);
    defer destroyTestDB(allocator, t.store);

    const fc_data = "serialized_fork_choice_store";
    try t.db.putForkChoiceData(fc_data);

    const result = try t.db.getForkChoiceData();
    defer if (result) |r| allocator.free(r);
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, fc_data, result.?);
}

// ---- Validator index ----

test "BeaconDB: put and get validator index" {
    const allocator = std.testing.allocator;
    var t = makeTestDB(allocator);
    defer destroyTestDB(allocator, t.store);

    const pubkey = [_]u8{0x42} ** 48;
    const index: u64 = 12345;

    try t.db.putValidatorIndex(pubkey, index);

    const result = try t.db.getValidatorIndex(pubkey);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(index, result.?);
}

test "BeaconDB: get missing validator index returns null" {
    const allocator = std.testing.allocator;
    var t = makeTestDB(allocator);
    defer destroyTestDB(allocator, t.store);

    const result = try t.db.getValidatorIndex([_]u8{0x00} ** 48);
    try std.testing.expect(result == null);
}

// ---- Chain info ----

test "BeaconDB: put and get chain info" {
    const allocator = std.testing.allocator;
    var t = makeTestDB(allocator);
    defer destroyTestDB(allocator, t.store);

    const finalized_root = [_]u8{0xff} ** 32;
    try t.db.putChainInfo(.finalized_root, &finalized_root);

    const result = try t.db.getChainInfo(.finalized_root);
    defer if (result) |r| allocator.free(r);
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, &finalized_root, result.?);
}

// ---- Op pool ----

test "BeaconDB: put and get voluntary exit" {
    const allocator = std.testing.allocator;
    var t = makeTestDB(allocator);
    defer destroyTestDB(allocator, t.store);

    try t.db.putVoluntaryExit(42, "exit_data");

    const result = try t.db.getVoluntaryExit(42);
    defer if (result) |r| allocator.free(r);
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, "exit_data", result.?);
}

test "BeaconDB: put and get proposer slashing" {
    const allocator = std.testing.allocator;
    var t = makeTestDB(allocator);
    defer destroyTestDB(allocator, t.store);

    try t.db.putProposerSlashing(100, "slashing_data");

    const result = try t.db.getProposerSlashing(100);
    defer if (result) |r| allocator.free(r);
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, "slashing_data", result.?);
}

test "BeaconDB: put and get attester slashing" {
    const allocator = std.testing.allocator;
    var t = makeTestDB(allocator);
    defer destroyTestDB(allocator, t.store);

    const root = [_]u8{0x33} ** 32;
    try t.db.putAttesterSlashing(root, "attester_slashing_data");

    const result = try t.db.getAttesterSlashing(root);
    defer if (result) |r| allocator.free(r);
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, "attester_slashing_data", result.?);
}

// ---- Bucket isolation ----

test "BeaconDB: different bucket types do not collide" {
    const allocator = std.testing.allocator;
    var t = makeTestDB(allocator);
    defer destroyTestDB(allocator, t.store);

    // Store a block and blob sidecars with the same root
    const root = [_]u8{0x55} ** 32;
    try t.db.putBlock(root, "block_data");
    try t.db.putBlobSidecars(root, "blob_data");
    try t.db.putDataColumnSidecars(root, "column_data");

    // Each should return its own data
    const block = try t.db.getBlock(root);
    defer if (block) |b| allocator.free(b);
    const blob = try t.db.getBlobSidecars(root);
    defer if (blob) |b| allocator.free(b);
    const col = try t.db.getDataColumnSidecars(root);
    defer if (col) |c| allocator.free(c);

    try std.testing.expectEqualSlices(u8, "block_data", block.?);
    try std.testing.expectEqualSlices(u8, "blob_data", blob.?);
    try std.testing.expectEqualSlices(u8, "column_data", col.?);
}

test "BeaconDB: slot-keyed buckets do not collide" {
    const allocator = std.testing.allocator;
    var t = makeTestDB(allocator);
    defer destroyTestDB(allocator, t.store);

    const slot: u64 = 100;
    const root = [_]u8{0x66} ** 32;

    try t.db.putBlockArchive(slot, root, "finalized_block");
    try t.db.putStateArchive(slot, [_]u8{0x77} ** 32, "state_archive");
    try t.db.putBlobSidecarsArchive(slot, "blob_archive");

    const block = try t.db.getBlockArchive(slot);
    defer if (block) |b| allocator.free(b);
    const state = try t.db.getStateArchive(slot);
    defer if (state) |s| allocator.free(s);
    const blob = try t.db.getBlobSidecarsArchive(slot);
    defer if (blob) |b| allocator.free(b);

    try std.testing.expectEqualSlices(u8, "finalized_block", block.?);
    try std.testing.expectEqualSlices(u8, "state_archive", state.?);
    try std.testing.expectEqualSlices(u8, "blob_archive", blob.?);
}
