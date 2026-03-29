//! BeaconDB: high-level database interface for the beacon chain.
//!
//! Wraps a KVStore with typed accessors for beacon chain data:
//! blocks, state archives, blob sidecars, indices, and metadata.
//!
//! Uses LMDB named databases for namespace isolation — no key prefixes.

const std = @import("std");
const Allocator = std.mem.Allocator;
const kv_store_mod = @import("kv_store.zig");
const KVStore = kv_store_mod.KVStore;
const Database = kv_store_mod.Database;
const BatchOp = kv_store_mod.BatchOp;
const buckets = @import("buckets.zig");
const DatabaseId = buckets.DatabaseId;

pub const BeaconDB = struct {
    allocator: Allocator,
    kv: KVStore,

    // Pre-resolved database handles for hot-path operations.
    block_db: Database,
    block_archive_db: Database,
    idx_block_root_db: Database,
    idx_main_chain_db: Database,
    state_archive_db: Database,
    idx_state_root_db: Database,
    blob_sidecar_db: Database,
    blob_sidecar_archive_db: Database,
    data_column_db: Database,
    data_column_archive_db: Database,
    data_column_single_db: Database,
    fork_choice_db: Database,
    validator_index_db: Database,
    chain_info_db: Database,
    exit_db: Database,
    proposer_slashing_db: Database,
    attester_slashing_db: Database,
    bls_change_db: Database,

    pub fn init(allocator: Allocator, kv: KVStore) BeaconDB {
        return .{
            .allocator = allocator,
            .kv = kv,
            .block_db = kv.getDatabase(.block),
            .block_archive_db = kv.getDatabase(.block_archive),
            .idx_block_root_db = kv.getDatabase(.idx_block_root),
            .idx_main_chain_db = kv.getDatabase(.idx_main_chain),
            .state_archive_db = kv.getDatabase(.state_archive),
            .idx_state_root_db = kv.getDatabase(.idx_state_root),
            .blob_sidecar_db = kv.getDatabase(.blob_sidecar),
            .blob_sidecar_archive_db = kv.getDatabase(.blob_sidecar_archive),
            .data_column_db = kv.getDatabase(.data_column),
            .data_column_archive_db = kv.getDatabase(.data_column_archive),
            .data_column_single_db = kv.getDatabase(.data_column_single),
            .fork_choice_db = kv.getDatabase(.fork_choice),
            .validator_index_db = kv.getDatabase(.validator_index),
            .chain_info_db = kv.getDatabase(.chain_info),
            .exit_db = kv.getDatabase(.exit),
            .proposer_slashing_db = kv.getDatabase(.proposer_slashing),
            .attester_slashing_db = kv.getDatabase(.attester_slashing),
            .bls_change_db = kv.getDatabase(.bls_change),
        };
    }

    pub fn close(self: *BeaconDB) void {
        self.kv.close();
    }

    // ---------------------------------------------------------------
    // Block operations (hot — unfinalized, keyed by root)
    // ---------------------------------------------------------------

    pub fn putBlock(self: *BeaconDB, root: [32]u8, data: []const u8) !void {
        try self.block_db.put(&root, data);
    }

    pub fn getBlock(self: *BeaconDB, root: [32]u8) !?[]const u8 {
        return self.block_db.get(&root);
    }

    pub fn deleteBlock(self: *BeaconDB, root: [32]u8) !void {
        try self.block_db.delete(&root);
    }

    // ---------------------------------------------------------------
    // Block archive operations (finalized, keyed by slot)
    // ---------------------------------------------------------------

    pub fn putBlockArchive(self: *BeaconDB, slot: u64, root: [32]u8, data: []const u8) !void {
        const slot_key = buckets.slotKey(slot);
        const ops = [_]BatchOp{
            .{ .put = .{ .db = .block_archive, .key = &slot_key, .value = data } },
            .{ .put = .{ .db = .idx_block_root, .key = &root, .value = &buckets.slotKey(slot) } },
            .{ .put = .{ .db = .idx_main_chain, .key = &slot_key, .value = &root } },
        };
        try self.kv.writeBatch(&ops);
    }

    pub fn getBlockArchive(self: *BeaconDB, slot: u64) !?[]const u8 {
        const key = buckets.slotKey(slot);
        return self.block_archive_db.get(&key);
    }

    pub fn getBlockArchiveByRoot(self: *BeaconDB, root: [32]u8) !?[]const u8 {
        const slot_bytes = try self.idx_block_root_db.get(&root) orelse return null;
        defer self.allocator.free(slot_bytes);

        if (slot_bytes.len != 8) return error.CorruptedIndex;
        const slot = std.mem.readInt(u64, slot_bytes[0..8], .big);
        return self.getBlockArchive(slot);
    }

    pub fn getBlockRootBySlot(self: *BeaconDB, slot: u64) !?[32]u8 {
        const key = buckets.slotKey(slot);
        const root_bytes = try self.idx_main_chain_db.get(&key) orelse return null;
        defer self.allocator.free(root_bytes);

        if (root_bytes.len != 32) return error.CorruptedIndex;
        var root: [32]u8 = undefined;
        @memcpy(&root, root_bytes[0..32]);
        return root;
    }

    // ---------------------------------------------------------------
    // State archive operations
    // ---------------------------------------------------------------

    pub fn putStateArchive(self: *BeaconDB, slot: u64, state_root: [32]u8, data: []const u8) !void {
        const slot_key = buckets.slotKey(slot);
        const ops = [_]BatchOp{
            .{ .put = .{ .db = .state_archive, .key = &slot_key, .value = data } },
            .{ .put = .{ .db = .idx_state_root, .key = &state_root, .value = &buckets.slotKey(slot) } },
        };
        try self.kv.writeBatch(&ops);
    }

    pub fn getStateArchive(self: *BeaconDB, slot: u64) !?[]const u8 {
        const key = buckets.slotKey(slot);
        return self.state_archive_db.get(&key);
    }

    pub fn getStateArchiveSlotByRoot(self: *BeaconDB, state_root: [32]u8) !?u64 {
        const slot_bytes = try self.idx_state_root_db.get(&state_root) orelse return null;
        defer self.allocator.free(slot_bytes);

        if (slot_bytes.len != 8) return error.CorruptedIndex;
        return std.mem.readInt(u64, slot_bytes[0..8], .big);
    }

    pub fn getStateArchiveByRoot(self: *BeaconDB, state_root: [32]u8) !?[]const u8 {
        const slot = try self.getStateArchiveSlotByRoot(state_root) orelse return null;
        return self.getStateArchive(slot);
    }

    pub fn getLatestStateArchiveSlot(self: *BeaconDB) !?u64 {
        // Use cursor MDB_LAST for O(1) lookup — LMDB keys are sorted so the
        // last key is the highest slot. This avoids loading all keys into memory.
        const last = try self.state_archive_db.lastKey() orelse return null;
        defer self.allocator.free(last);
        if (last.len != 8) return error.InvalidKeyLength;
        return std.mem.readInt(u64, last[0..8], .big);
    }

    // ---------------------------------------------------------------
    // Blob sidecar operations
    // ---------------------------------------------------------------

    pub fn putBlobSidecars(self: *BeaconDB, root: [32]u8, data: []const u8) !void {
        try self.blob_sidecar_db.put(&root, data);
    }

    pub fn getBlobSidecars(self: *BeaconDB, root: [32]u8) !?[]const u8 {
        return self.blob_sidecar_db.get(&root);
    }

    pub fn deleteBlobSidecars(self: *BeaconDB, root: [32]u8) !void {
        try self.blob_sidecar_db.delete(&root);
    }

    pub fn putBlobSidecarsArchive(self: *BeaconDB, slot: u64, data: []const u8) !void {
        const key = buckets.slotKey(slot);
        try self.blob_sidecar_archive_db.put(&key, data);
    }

    pub fn getBlobSidecarsArchive(self: *BeaconDB, slot: u64) !?[]const u8 {
        const key = buckets.slotKey(slot);
        return self.blob_sidecar_archive_db.get(&key);
    }

    // ---------------------------------------------------------------
    // Data column sidecars (PeerDAS / Fulu)
    // ---------------------------------------------------------------

    pub fn putDataColumnSidecars(self: *BeaconDB, root: [32]u8, data: []const u8) !void {
        try self.data_column_db.put(&root, data);
    }

    pub fn getDataColumnSidecars(self: *BeaconDB, root: [32]u8) !?[]const u8 {
        return self.data_column_db.get(&root);
    }

    pub fn putDataColumnSidecarsArchive(self: *BeaconDB, slot: u64, data: []const u8) !void {
        const key = buckets.slotKey(slot);
        try self.data_column_archive_db.put(&key, data);
    }

    pub fn getDataColumnSidecarsArchive(self: *BeaconDB, slot: u64) !?[]const u8 {
        const key = buckets.slotKey(slot);
        return self.data_column_archive_db.get(&key);
    }

    // ---------------------------------------------------------------
    // Data column sidecar per-column operations
    // ---------------------------------------------------------------

    pub fn putDataColumn(self: *BeaconDB, root: [32]u8, column_index: u64, data: []const u8) !void {
        const key = buckets.rootColumnKey(root, column_index);
        try self.data_column_single_db.put(&key, data);
    }

    pub fn getDataColumn(self: *BeaconDB, root: [32]u8, column_index: u64) !?[]const u8 {
        const key = buckets.rootColumnKey(root, column_index);
        return self.data_column_single_db.get(&key);
    }

    pub fn deleteDataColumn(self: *BeaconDB, root: [32]u8, column_index: u64) !void {
        const key = buckets.rootColumnKey(root, column_index);
        try self.data_column_single_db.delete(&key);
    }

    pub fn deleteDataColumnSidecars(self: *BeaconDB, root: [32]u8) !void {
        try self.data_column_db.delete(&root);
    }

    // ---------------------------------------------------------------
    // Fork choice persistence
    // ---------------------------------------------------------------

    pub fn putForkChoiceData(self: *BeaconDB, data: []const u8) !void {
        try self.fork_choice_db.put("fc", data);
    }

    pub fn getForkChoiceData(self: *BeaconDB) !?[]const u8 {
        return self.fork_choice_db.get("fc");
    }

    // ---------------------------------------------------------------
    // Validator index
    // ---------------------------------------------------------------

    pub fn putValidatorIndex(self: *BeaconDB, pubkey: [48]u8, index: u64) !void {
        try self.validator_index_db.put(&pubkey, &buckets.slotKey(index));
    }

    pub fn getValidatorIndex(self: *BeaconDB, pubkey: [48]u8) !?u64 {
        const idx_bytes = try self.validator_index_db.get(&pubkey) orelse return null;
        defer self.allocator.free(idx_bytes);

        if (idx_bytes.len != 8) return error.CorruptedIndex;
        return std.mem.readInt(u64, idx_bytes[0..8], .big);
    }

    // ---------------------------------------------------------------
    // Chain info metadata
    // ---------------------------------------------------------------

    pub const ChainInfoKey = enum {
        finalized_slot,
        finalized_root,
        justified_slot,
        justified_root,
    };

    fn chainInfoKeyBytes(info_key: ChainInfoKey) []const u8 {
        return switch (info_key) {
            .finalized_slot => "fs",
            .finalized_root => "fr",
            .justified_slot => "js",
            .justified_root => "jr",
        };
    }

    pub fn putChainInfo(self: *BeaconDB, info_key: ChainInfoKey, data: []const u8) !void {
        try self.chain_info_db.put(chainInfoKeyBytes(info_key), data);
    }

    pub fn getChainInfo(self: *BeaconDB, info_key: ChainInfoKey) !?[]const u8 {
        return self.chain_info_db.get(chainInfoKeyBytes(info_key));
    }

    // ---------------------------------------------------------------
    // Op pool
    // ---------------------------------------------------------------

    pub fn putVoluntaryExit(self: *BeaconDB, validator_index: u64, data: []const u8) !void {
        const key = buckets.slotKey(validator_index);
        try self.exit_db.put(&key, data);
    }

    pub fn getVoluntaryExit(self: *BeaconDB, validator_index: u64) !?[]const u8 {
        const key = buckets.slotKey(validator_index);
        return self.exit_db.get(&key);
    }

    pub fn putProposerSlashing(self: *BeaconDB, validator_index: u64, data: []const u8) !void {
        const key = buckets.slotKey(validator_index);
        try self.proposer_slashing_db.put(&key, data);
    }

    pub fn getProposerSlashing(self: *BeaconDB, validator_index: u64) !?[]const u8 {
        const key = buckets.slotKey(validator_index);
        return self.proposer_slashing_db.get(&key);
    }

    pub fn putAttesterSlashing(self: *BeaconDB, root: [32]u8, data: []const u8) !void {
        try self.attester_slashing_db.put(&root, data);
    }

    pub fn getAttesterSlashing(self: *BeaconDB, root: [32]u8) !?[]const u8 {
        return self.attester_slashing_db.get(&root);
    }

    pub fn putBlsChange(self: *BeaconDB, validator_index: u64, data: []const u8) !void {
        const key = buckets.slotKey(validator_index);
        try self.bls_change_db.put(&key, data);
    }

    pub fn getBlsChange(self: *BeaconDB, validator_index: u64) !?[]const u8 {
        const key = buckets.slotKey(validator_index);
        return self.bls_change_db.get(&key);
    }
};
