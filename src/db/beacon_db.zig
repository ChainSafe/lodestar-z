//! BeaconDB: high-level database interface for the beacon chain.
//!
//! Wraps a KVStore with typed accessors for beacon chain data:
//! blocks, state archives, blob sidecars, indices, and metadata.
//!
//! Key encoding uses single-byte bucket prefixes (see buckets.zig)
//! matching Lodestar's scheme for cross-client compatibility.

const std = @import("std");
const Allocator = std.mem.Allocator;
const kv_store_mod = @import("kv_store.zig");
const KVStore = kv_store_mod.KVStore;
const BatchOp = kv_store_mod.BatchOp;
const buckets = @import("buckets.zig");
const Bucket = buckets.Bucket;

pub const BeaconDB = struct {
    allocator: Allocator,
    kv: KVStore,

    pub fn init(allocator: Allocator, kv: KVStore) BeaconDB {
        return .{
            .allocator = allocator,
            .kv = kv,
        };
    }

    pub fn close(self: *BeaconDB) void {
        self.kv.close();
    }

    // ---------------------------------------------------------------
    // Block operations (hot — unfinalized, keyed by root)
    // ---------------------------------------------------------------

    /// Store an unfinalized block by its root.
    pub fn putBlock(self: *BeaconDB, root: [32]u8, data: []const u8) !void {
        const key = try buckets.bucketRootKey(self.allocator, .all_forks_block, root);
        defer self.allocator.free(key);
        try self.kv.put(key, data);
    }

    /// Retrieve an unfinalized block by root. Caller owns returned slice.
    pub fn getBlock(self: *BeaconDB, root: [32]u8) !?[]const u8 {
        const key = try buckets.bucketRootKey(self.allocator, .all_forks_block, root);
        defer self.allocator.free(key);
        return self.kv.get(key);
    }

    /// Delete an unfinalized block by root.
    pub fn deleteBlock(self: *BeaconDB, root: [32]u8) !void {
        const key = try buckets.bucketRootKey(self.allocator, .all_forks_block, root);
        defer self.allocator.free(key);
        try self.kv.delete(key);
    }

    // ---------------------------------------------------------------
    // Block archive operations (finalized, keyed by slot)
    // ---------------------------------------------------------------

    /// Store a finalized block by slot, and update the root->slot index.
    pub fn putBlockArchive(self: *BeaconDB, slot: u64, root: [32]u8, data: []const u8) !void {
        const slot_key = try buckets.bucketSlotKey(self.allocator, .all_forks_block_archive, slot);
        defer self.allocator.free(slot_key);
        const root_idx_key = try buckets.bucketRootKey(self.allocator, .index_block_archive_root, root);
        defer self.allocator.free(root_idx_key);
        const main_chain_key = try buckets.bucketSlotKey(self.allocator, .index_main_chain, slot);
        defer self.allocator.free(main_chain_key);

        const ops = [_]BatchOp{
            .{ .put = .{ .key = slot_key, .value = data } },
            .{ .put = .{ .key = root_idx_key, .value = std.mem.asBytes(&slot) } },
            .{ .put = .{ .key = main_chain_key, .value = &root } },
        };
        try self.kv.writeBatch(&ops);
    }

    /// Retrieve a finalized block by slot. Caller owns returned slice.
    pub fn getBlockArchive(self: *BeaconDB, slot: u64) !?[]const u8 {
        const key = try buckets.bucketSlotKey(self.allocator, .all_forks_block_archive, slot);
        defer self.allocator.free(key);
        return self.kv.get(key);
    }

    /// Retrieve a finalized block by root (via index). Caller owns returned slice.
    pub fn getBlockArchiveByRoot(self: *BeaconDB, root: [32]u8) !?[]const u8 {
        // First look up slot from root index
        const idx_key = try buckets.bucketRootKey(self.allocator, .index_block_archive_root, root);
        defer self.allocator.free(idx_key);

        const slot_bytes = try self.kv.get(idx_key) orelse return null;
        defer self.allocator.free(slot_bytes);

        if (slot_bytes.len != 8) return error.CorruptedIndex;
        const slot = std.mem.readInt(u64, slot_bytes[0..8], .little);

        return self.getBlockArchive(slot);
    }

    /// Get the block root for a given slot on the main chain.
    pub fn getBlockRootBySlot(self: *BeaconDB, slot: u64) !?[32]u8 {
        const key = try buckets.bucketSlotKey(self.allocator, .index_main_chain, slot);
        defer self.allocator.free(key);

        const root_bytes = try self.kv.get(key) orelse return null;
        defer self.allocator.free(root_bytes);

        if (root_bytes.len != 32) return error.CorruptedIndex;
        var root: [32]u8 = undefined;
        @memcpy(&root, root_bytes[0..32]);
        return root;
    }

    // ---------------------------------------------------------------
    // State archive operations
    // ---------------------------------------------------------------

    /// Store a state archive by slot.
    pub fn putStateArchive(self: *BeaconDB, slot: u64, state_root: [32]u8, data: []const u8) !void {
        const slot_key = try buckets.bucketSlotKey(self.allocator, .all_forks_state_archive, slot);
        defer self.allocator.free(slot_key);
        const root_idx_key = try buckets.bucketRootKey(self.allocator, .index_state_archive_root, state_root);
        defer self.allocator.free(root_idx_key);

        const ops = [_]BatchOp{
            .{ .put = .{ .key = slot_key, .value = data } },
            .{ .put = .{ .key = root_idx_key, .value = std.mem.asBytes(&slot) } },
        };
        try self.kv.writeBatch(&ops);
    }

    /// Retrieve a state archive by slot. Caller owns returned slice.
    pub fn getStateArchive(self: *BeaconDB, slot: u64) !?[]const u8 {
        const key = try buckets.bucketSlotKey(self.allocator, .all_forks_state_archive, slot);
        defer self.allocator.free(key);
        return self.kv.get(key);
    }

    /// Look up a state archive slot by state root.
    pub fn getStateArchiveSlotByRoot(self: *BeaconDB, state_root: [32]u8) !?u64 {
        const key = try buckets.bucketRootKey(self.allocator, .index_state_archive_root, state_root);
        defer self.allocator.free(key);

        const slot_bytes = try self.kv.get(key) orelse return null;
        defer self.allocator.free(slot_bytes);

        if (slot_bytes.len != 8) return error.CorruptedIndex;
        return std.mem.readInt(u64, slot_bytes[0..8], .little);
    }

    /// Retrieve a state archive by state root (via index). Caller owns returned slice.
    pub fn getStateArchiveByRoot(self: *BeaconDB, state_root: [32]u8) !?[]const u8 {
        const slot = try self.getStateArchiveSlotByRoot(state_root) orelse return null;
        return self.getStateArchive(slot);
    }

    /// Find the latest (highest slot) state archive in the DB.
    /// Scans all keys with the state archive bucket prefix, decodes the
    /// slot from each key, and returns the highest one found.
    /// Returns null if no state archives exist (fresh DB).
    pub fn getLatestStateArchiveSlot(self: *BeaconDB) !?u64 {
        const prefix = buckets.bucketPrefix(.all_forks_state_archive);
        const keys = try self.kv.keysWithPrefix(&prefix);
        defer {
            for (keys) |k| self.allocator.free(k);
            self.allocator.free(keys);
        }

        var max_slot: ?u64 = null;
        for (keys) |key| {
            // Key format: [1-byte bucket] ++ [8-byte slot LE]
            if (key.len != 9) continue;
            const slot = std.mem.readInt(u64, key[1..9], .little);
            if (max_slot == null or slot > max_slot.?) {
                max_slot = slot;
            }
        }
        return max_slot;
    }

    // ---------------------------------------------------------------
    // Blob sidecar operations
    // ---------------------------------------------------------------

    /// Store blob sidecars for a block (hot, keyed by root).
    pub fn putBlobSidecars(self: *BeaconDB, root: [32]u8, data: []const u8) !void {
        const key = try buckets.bucketRootKey(self.allocator, .deneb_blob_sidecars, root);
        defer self.allocator.free(key);
        try self.kv.put(key, data);
    }

    /// Retrieve blob sidecars by block root. Caller owns returned slice.
    pub fn getBlobSidecars(self: *BeaconDB, root: [32]u8) !?[]const u8 {
        const key = try buckets.bucketRootKey(self.allocator, .deneb_blob_sidecars, root);
        defer self.allocator.free(key);
        return self.kv.get(key);
    }

    /// Delete blob sidecars by block root.
    pub fn deleteBlobSidecars(self: *BeaconDB, root: [32]u8) !void {
        const key = try buckets.bucketRootKey(self.allocator, .deneb_blob_sidecars, root);
        defer self.allocator.free(key);
        try self.kv.delete(key);
    }

    /// Store archived blob sidecars (finalized, keyed by slot).
    pub fn putBlobSidecarsArchive(self: *BeaconDB, slot: u64, data: []const u8) !void {
        const key = try buckets.bucketSlotKey(self.allocator, .deneb_blob_sidecars_archive, slot);
        defer self.allocator.free(key);
        try self.kv.put(key, data);
    }

    /// Retrieve archived blob sidecars by slot. Caller owns returned slice.
    pub fn getBlobSidecarsArchive(self: *BeaconDB, slot: u64) !?[]const u8 {
        const key = try buckets.bucketSlotKey(self.allocator, .deneb_blob_sidecars_archive, slot);
        defer self.allocator.free(key);
        return self.kv.get(key);
    }

    // ---------------------------------------------------------------
    // Data column sidecars (PeerDAS / Fulu)
    // ---------------------------------------------------------------

    /// Store data column sidecars for a block (hot, keyed by root).
    pub fn putDataColumnSidecars(self: *BeaconDB, root: [32]u8, data: []const u8) !void {
        const key = try buckets.bucketRootKey(self.allocator, .fulu_data_column_sidecars, root);
        defer self.allocator.free(key);
        try self.kv.put(key, data);
    }

    /// Retrieve data column sidecars by block root. Caller owns returned slice.
    pub fn getDataColumnSidecars(self: *BeaconDB, root: [32]u8) !?[]const u8 {
        const key = try buckets.bucketRootKey(self.allocator, .fulu_data_column_sidecars, root);
        defer self.allocator.free(key);
        return self.kv.get(key);
    }

    /// Store archived data column sidecars (finalized, keyed by slot).
    pub fn putDataColumnSidecarsArchive(self: *BeaconDB, slot: u64, data: []const u8) !void {
        const key = try buckets.bucketSlotKey(self.allocator, .fulu_data_column_sidecars_archive, slot);
        defer self.allocator.free(key);
        try self.kv.put(key, data);
    }

    /// Retrieve archived data column sidecars by slot. Caller owns returned slice.
    pub fn getDataColumnSidecarsArchive(self: *BeaconDB, slot: u64) !?[]const u8 {
        const key = try buckets.bucketSlotKey(self.allocator, .fulu_data_column_sidecars_archive, slot);
        defer self.allocator.free(key);
        return self.kv.get(key);
    }

    // ---------------------------------------------------------------
    // Fork choice persistence
    // ---------------------------------------------------------------

    /// Store fork choice data. Key is a short identifier (e.g. "fc").
    pub fn putForkChoiceData(self: *BeaconDB, data: []const u8) !void {
        const key = try buckets.bucketKey(self.allocator, .fork_choice, "fc");
        defer self.allocator.free(key);
        try self.kv.put(key, data);
    }

    /// Retrieve fork choice data. Caller owns returned slice.
    pub fn getForkChoiceData(self: *BeaconDB) !?[]const u8 {
        const key = try buckets.bucketKey(self.allocator, .fork_choice, "fc");
        defer self.allocator.free(key);
        return self.kv.get(key);
    }

    // ---------------------------------------------------------------
    // Validator index
    // ---------------------------------------------------------------

    /// Store a validator pubkey -> index mapping.
    pub fn putValidatorIndex(self: *BeaconDB, pubkey: [48]u8, index: u64) !void {
        const key = try buckets.bucketKey(self.allocator, .validator_index, &pubkey);
        defer self.allocator.free(key);
        try self.kv.put(key, std.mem.asBytes(&index));
    }

    /// Look up a validator index by pubkey.
    pub fn getValidatorIndex(self: *BeaconDB, pubkey: [48]u8) !?u64 {
        const key = try buckets.bucketKey(self.allocator, .validator_index, &pubkey);
        defer self.allocator.free(key);

        const idx_bytes = try self.kv.get(key) orelse return null;
        defer self.allocator.free(idx_bytes);

        if (idx_bytes.len != 8) return error.CorruptedIndex;
        return std.mem.readInt(u64, idx_bytes[0..8], .little);
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

    /// Store chain info metadata.
    pub fn putChainInfo(self: *BeaconDB, info_key: ChainInfoKey, data: []const u8) !void {
        const key = try buckets.bucketKey(self.allocator, .index_chain_info, chainInfoKeyBytes(info_key));
        defer self.allocator.free(key);
        try self.kv.put(key, data);
    }

    /// Retrieve chain info metadata. Caller owns returned slice.
    pub fn getChainInfo(self: *BeaconDB, info_key: ChainInfoKey) !?[]const u8 {
        const key = try buckets.bucketKey(self.allocator, .index_chain_info, chainInfoKeyBytes(info_key));
        defer self.allocator.free(key);
        return self.kv.get(key);
    }

    // ---------------------------------------------------------------
    // Op pool
    // ---------------------------------------------------------------

    /// Store a voluntary exit by validator index.
    pub fn putVoluntaryExit(self: *BeaconDB, validator_index: u64, data: []const u8) !void {
        const key = try buckets.bucketSlotKey(self.allocator, .phase0_exit, validator_index);
        defer self.allocator.free(key);
        try self.kv.put(key, data);
    }

    /// Retrieve a voluntary exit by validator index. Caller owns returned slice.
    pub fn getVoluntaryExit(self: *BeaconDB, validator_index: u64) !?[]const u8 {
        const key = try buckets.bucketSlotKey(self.allocator, .phase0_exit, validator_index);
        defer self.allocator.free(key);
        return self.kv.get(key);
    }

    /// Store a proposer slashing by validator index.
    pub fn putProposerSlashing(self: *BeaconDB, validator_index: u64, data: []const u8) !void {
        const key = try buckets.bucketSlotKey(self.allocator, .phase0_proposer_slashing, validator_index);
        defer self.allocator.free(key);
        try self.kv.put(key, data);
    }

    /// Retrieve a proposer slashing by validator index. Caller owns returned slice.
    pub fn getProposerSlashing(self: *BeaconDB, validator_index: u64) !?[]const u8 {
        const key = try buckets.bucketSlotKey(self.allocator, .phase0_proposer_slashing, validator_index);
        defer self.allocator.free(key);
        return self.kv.get(key);
    }

    /// Store an attester slashing by root.
    pub fn putAttesterSlashing(self: *BeaconDB, root: [32]u8, data: []const u8) !void {
        const key = try buckets.bucketRootKey(self.allocator, .all_forks_attester_slashing, root);
        defer self.allocator.free(key);
        try self.kv.put(key, data);
    }

    /// Retrieve an attester slashing by root. Caller owns returned slice.
    pub fn getAttesterSlashing(self: *BeaconDB, root: [32]u8) !?[]const u8 {
        const key = try buckets.bucketRootKey(self.allocator, .all_forks_attester_slashing, root);
        defer self.allocator.free(key);
        return self.kv.get(key);
    }
};
