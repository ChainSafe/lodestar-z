//! ArchiveStore — background archival of finalized blocks and states.
//!
//! When the chain finalizes a new checkpoint, this module:
//! 1. Moves finalized blocks from hot DB (keyed by root) to cold storage (keyed by slot)
//! 2. Periodically snapshots epoch boundary states to the archive
//!
//! This frees hot DB space and allows the hot DB to act as a short-lived buffer
//! for unfinalized chain data.
//!
//! The module is designed to be called synchronously from onFinalized() — it does
//! the work inline (no background thread). The caller decides the threading model.

const std = @import("std");
const Allocator = std.mem.Allocator;

const preset = @import("preset").preset;
const preset_root = @import("preset");
const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const db_mod = @import("db");
const BeaconDB = db_mod.BeaconDB;
const fork_types = @import("fork_types");
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;

const state_transition = @import("state_transition");
const BlockStateCache = state_transition.BlockStateCache;

const Root = [32]u8;
const Slot = u64;
const SlotToRootMap = std.AutoArrayHashMap(u64, Root);
const BlockToStateMap = std.AutoArrayHashMap(Root, Root);

/// Configuration for the archive store.
pub const ArchiveConfig = struct {
    /// Archive a state snapshot every N epochs.
    state_archive_every_n_epochs: u64 = 1024,
    /// Whether to delete hot blocks after archiving.
    prune_hot_blocks_after_archive: bool = true,
    /// Whether to delete hot blob sidecars after archiving.
    prune_hot_blobs_after_archive: bool = true,
    /// Whether to delete hot data columns after archiving.
    prune_hot_data_columns_after_archive: bool = true,
};

/// Finalized checkpoint descriptor.
pub const FinalizedCheckpoint = struct {
    epoch: u64,
    root: [32]u8,
};

pub const ArchiveStore = struct {
    allocator: Allocator,
    db: *BeaconDB,
    block_state_cache: *BlockStateCache,
    beacon_config: ?*const BeaconConfig,
    config: ArchiveConfig,

    /// Last epoch for which we archived a state snapshot.
    last_archived_state_epoch: u64,
    /// Last finalized slot we have processed.
    last_finalized_slot: u64,

    pub fn init(
        allocator: Allocator,
        db: *BeaconDB,
        block_state_cache: *BlockStateCache,
        config: ArchiveConfig,
    ) ArchiveStore {
        return .{
            .allocator = allocator,
            .db = db,
            .block_state_cache = block_state_cache,
            .beacon_config = null,
            .config = config,
            .last_archived_state_epoch = 0,
            .last_finalized_slot = 0,
        };
    }

    pub fn deinit(_: *ArchiveStore) void {}

    pub fn bindBeaconConfig(self: *ArchiveStore, beacon_config: *const BeaconConfig) void {
        self.beacon_config = beacon_config;
    }

    pub fn restoreProgress(self: *ArchiveStore, finalized_slot: Slot) !void {
        if (finalized_slot > self.last_finalized_slot) {
            self.last_finalized_slot = finalized_slot;
        }

        const latest_state_slot = try self.db.getLatestStateArchiveSlot() orelse return;
        const archived_epoch = latest_state_slot / preset.SLOTS_PER_EPOCH;
        if (archived_epoch > self.last_archived_state_epoch) {
            self.last_archived_state_epoch = archived_epoch;
        }
    }

    /// Called when the chain finalizes a new checkpoint.
    ///
    /// Archives all blocks between the previous and new finalized slots,
    /// and optionally archives an epoch state snapshot.
    pub fn onFinalized(
        self: *ArchiveStore,
        checkpoint: FinalizedCheckpoint,
        slot_to_root: *const SlotToRootMap,
        block_to_state: *const BlockToStateMap,
    ) !void {
        const finalized_slot = checkpoint.epoch * preset.SLOTS_PER_EPOCH;
        if (finalized_slot <= self.last_finalized_slot) return;

        const from_slot = self.last_finalized_slot + 1;
        const to_slot = finalized_slot;

        // Archive blocks in the finalized range.
        try self.archiveBlocks(from_slot, to_slot, slot_to_root);

        // Archive state snapshot if due.
        const epochs_since_last = checkpoint.epoch -| self.last_archived_state_epoch;
        if (epochs_since_last >= self.config.state_archive_every_n_epochs) {
            try self.archiveStateAtEpoch(checkpoint.epoch, slot_to_root, block_to_state);
        }

        self.last_finalized_slot = finalized_slot;
        std.log.info("ArchiveStore: archived slots {d}..{d} (epoch {d})", .{
            from_slot, to_slot, checkpoint.epoch,
        });
    }

    /// Move blocks for slots [from_slot, to_slot] from hot DB to archive.
    ///
    /// Reads each block by root (looked up from slot_to_root), writes to archive,
    /// and optionally deletes from hot DB.
    pub fn archiveBlocks(
        self: *ArchiveStore,
        from_slot: u64,
        to_slot: u64,
        slot_to_root: *const SlotToRootMap,
    ) !void {
        var slot = from_slot;
        while (slot <= to_slot) : (slot += 1) {
            const root = slot_to_root.get(slot) orelse continue;

            // Read from hot DB.
            const data = try self.db.getBlock(root) orelse continue;
            defer self.allocator.free(data);

            // Write to archive (slot-keyed cold store).
            try self.db.putBlockArchive(slot, root, data);
            try self.archiveBlobSidecars(slot, root);
            try self.archiveDataColumns(slot, root);

            // Prune from hot DB if configured.
            if (self.config.prune_hot_blocks_after_archive) {
                self.db.deleteBlock(root) catch |err| {
                    std.log.warn("ArchiveStore: failed to delete hot block slot={d}: {}", .{ slot, err });
                };
            }
        }
    }

    /// Archive the beacon state at the given epoch boundary.
    ///
    /// Looks up the post-state in the block state cache by the epoch block root.
    pub fn archiveState(
        self: *ArchiveStore,
        slot: u64,
        state_root: Root,
    ) !void {
        const cached = self.block_state_cache.get(state_root) orelse {
            std.log.debug("ArchiveStore: state not in cache for slot {d}", .{slot});
            return;
        };
        const bytes = try cached.state.serialize(self.allocator);
        defer self.allocator.free(bytes);
        try self.db.putStateArchive(slot, state_root, bytes);
        const epoch = slot / preset.SLOTS_PER_EPOCH;
        if (epoch > self.last_archived_state_epoch) {
            self.last_archived_state_epoch = epoch;
        }
        std.log.debug("ArchiveStore: archived state at slot {d}", .{slot});
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn archiveStateAtEpoch(
        self: *ArchiveStore,
        epoch: u64,
        slot_to_root: *const SlotToRootMap,
        block_to_state: *const BlockToStateMap,
    ) !void {
        const slot = epoch * preset.SLOTS_PER_EPOCH;
        const block_root = slot_to_root.get(slot) orelse
            (try self.db.getBlockRootBySlot(slot) orelse return);
        const state_root = try self.stateRootForBlock(slot, block_root, block_to_state) orelse return;
        try self.archiveState(slot, state_root);
    }

    fn stateRootForBlock(
        self: *ArchiveStore,
        slot: Slot,
        block_root: Root,
        block_to_state: *const BlockToStateMap,
    ) !?Root {
        if (block_to_state.get(block_root)) |state_root| return state_root;

        const beacon_config = self.beacon_config orelse return null;
        const block_bytes = if (try self.db.getBlock(block_root)) |bytes|
            bytes
        else if (try self.db.getBlockArchiveByRoot(block_root)) |bytes|
            bytes
        else
            return null;
        defer self.allocator.free(block_bytes);

        const fork_seq = beacon_config.forkSeq(slot);
        const any_signed = try AnySignedBeaconBlock.deserialize(
            self.allocator,
            .full,
            fork_seq,
            block_bytes,
        );
        defer any_signed.deinit(self.allocator);
        return any_signed.beaconBlock().stateRoot().*;
    }

    fn archiveBlobSidecars(self: *ArchiveStore, slot: Slot, root: Root) !void {
        const blob_bytes = try self.db.getBlobSidecars(root) orelse return;
        defer self.allocator.free(blob_bytes);

        try self.db.putBlobSidecarsArchive(slot, blob_bytes);
        if (self.config.prune_hot_blobs_after_archive) {
            self.db.deleteBlobSidecars(root) catch |err| {
                std.log.warn("ArchiveStore: failed to delete hot blob sidecars slot={d}: {}", .{ slot, err });
            };
        }
    }

    fn archiveDataColumns(self: *ArchiveStore, slot: Slot, root: Root) !void {
        if (try self.db.getDataColumnSidecars(root)) |columns_bytes| {
            defer self.allocator.free(columns_bytes);
            try self.db.putDataColumnSidecarsArchive(slot, columns_bytes);
            if (self.config.prune_hot_data_columns_after_archive) {
                self.db.deleteDataColumnSidecars(root) catch |err| {
                    std.log.warn("ArchiveStore: failed to delete hot data column sidecars slot={d}: {}", .{ slot, err });
                };
            }
        }

        for (0..preset_root.NUMBER_OF_COLUMNS) |column_index_usize| {
            const column_index: u64 = @intCast(column_index_usize);
            const column_bytes = try self.db.getDataColumn(root, column_index) orelse continue;
            defer self.allocator.free(column_bytes);

            try self.db.putDataColumnArchive(slot, column_index, column_bytes);
            if (self.config.prune_hot_data_columns_after_archive) {
                self.db.deleteDataColumn(root, column_index) catch |err| {
                    std.log.warn("ArchiveStore: failed to delete hot data column slot={d} index={d}: {}", .{
                        slot,
                        column_index,
                        err,
                    });
                };
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ArchiveStore: init/deinit is safe" {
    const MemoryKVStore = db_mod.MemoryKVStore;
    const store_ptr = try std.testing.allocator.create(MemoryKVStore);
    store_ptr.* = MemoryKVStore.init(std.testing.allocator);
    defer {
        store_ptr.deinit();
        std.testing.allocator.destroy(store_ptr);
    }
    var db = db_mod.BeaconDB.init(std.testing.allocator, store_ptr.kvStore());
    defer db.close();

    var bsc = state_transition.BlockStateCache.init(std.testing.allocator, 64);
    defer bsc.deinit();

    var store = ArchiveStore.init(std.testing.allocator, &db, &bsc, .{});
    defer store.deinit();

    try std.testing.expectEqual(@as(u64, 0), store.last_finalized_slot);
}

test "ArchiveStore: archiveBlocks moves data from hot to archive" {
    const MemoryKVStore = db_mod.MemoryKVStore;
    const store_ptr = try std.testing.allocator.create(MemoryKVStore);
    store_ptr.* = MemoryKVStore.init(std.testing.allocator);
    defer {
        store_ptr.deinit();
        std.testing.allocator.destroy(store_ptr);
    }
    var db = db_mod.BeaconDB.init(std.testing.allocator, store_ptr.kvStore());
    defer db.close();

    var bsc = state_transition.BlockStateCache.init(std.testing.allocator, 64);
    defer bsc.deinit();

    var store = ArchiveStore.init(std.testing.allocator, &db, &bsc, .{
        .state_archive_every_n_epochs = 1024,
        .prune_hot_blocks_after_archive = true,
    });
    defer store.deinit();

    // Insert a block into the hot DB.
    const root = [_]u8{0xAB} ** 32;
    const data = "fake block bytes";
    try db.putBlock(root, data);

    // Build a slot_to_root mapping.
    var slot_to_root = std.AutoArrayHashMap(u64, [32]u8).init(std.testing.allocator);
    defer slot_to_root.deinit();
    try slot_to_root.put(10, root);

    // Archive slot 10.
    try store.archiveBlocks(10, 10, &slot_to_root);

    // Block should now be in archive and removed from hot.
    const archived = try db.getBlockArchive(10);
    try std.testing.expect(archived != null);
    defer if (archived) |b| std.testing.allocator.free(b);
    try std.testing.expectEqualSlices(u8, data, archived.?);

    const hot = try db.getBlock(root);
    defer if (hot) |b| std.testing.allocator.free(b);
    try std.testing.expect(hot == null);
}

test "ArchiveStore: onFinalized archives epoch boundary state" {
    const Node = @import("persistent_merkle_tree").Node;
    const TestCachedBeaconState = @import("state_transition").test_utils.TestCachedBeaconState;
    const MemoryKVStore = db_mod.MemoryKVStore;

    const allocator = std.testing.allocator;
    const store_ptr = try allocator.create(MemoryKVStore);
    store_ptr.* = MemoryKVStore.init(allocator);
    defer {
        store_ptr.deinit();
        allocator.destroy(store_ptr);
    }
    var db = db_mod.BeaconDB.init(allocator, store_ptr.kvStore());
    defer db.close();

    var bsc = state_transition.BlockStateCache.init(allocator, 64);
    defer bsc.deinit();

    const pool_size = 256 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    const cached_state = try test_state.cached_state.clone(allocator, .{});
    try cached_state.state.setSlot(preset.SLOTS_PER_EPOCH);
    try cached_state.state.commit();
    const state_root = try bsc.add(cached_state, false);

    const block_root = [_]u8{0xBC} ** 32;
    try db.putBlock(block_root, "epoch-boundary-block");

    var slot_to_root = SlotToRootMap.init(allocator);
    defer slot_to_root.deinit();
    try slot_to_root.put(preset.SLOTS_PER_EPOCH, block_root);

    var block_to_state = BlockToStateMap.init(allocator);
    defer block_to_state.deinit();
    try block_to_state.put(block_root, state_root);

    var store = ArchiveStore.init(allocator, &db, &bsc, .{
        .state_archive_every_n_epochs = 1,
        .prune_hot_blocks_after_archive = true,
    });
    defer store.deinit();

    try store.onFinalized(.{
        .epoch = 1,
        .root = block_root,
    }, &slot_to_root, &block_to_state);

    const archived_block = try db.getBlockArchive(preset.SLOTS_PER_EPOCH);
    try std.testing.expect(archived_block != null);
    defer if (archived_block) |bytes| allocator.free(bytes);

    const archived_state = try db.getStateArchive(preset.SLOTS_PER_EPOCH);
    try std.testing.expect(archived_state != null);
    defer if (archived_state) |bytes| allocator.free(bytes);
}

test "ArchiveStore: archiveBlocks archives blob sidecars and data columns" {
    const MemoryKVStore = db_mod.MemoryKVStore;
    const allocator = std.testing.allocator;
    const store_ptr = try allocator.create(MemoryKVStore);
    store_ptr.* = MemoryKVStore.init(allocator);
    defer {
        store_ptr.deinit();
        allocator.destroy(store_ptr);
    }
    var db = db_mod.BeaconDB.init(allocator, store_ptr.kvStore());
    defer db.close();

    var bsc = state_transition.BlockStateCache.init(allocator, 64);
    defer bsc.deinit();

    var store = ArchiveStore.init(allocator, &db, &bsc, .{
        .prune_hot_blocks_after_archive = true,
        .prune_hot_blobs_after_archive = true,
        .prune_hot_data_columns_after_archive = true,
    });
    defer store.deinit();

    const slot: u64 = 10;
    const root = [_]u8{0xAC} ** 32;
    try db.putBlock(root, "finalized-block");
    try db.putBlobSidecars(root, "blob-sidecars");
    try db.putDataColumn(root, 3, "column-3");
    try db.putDataColumn(root, 7, "column-7");

    var slot_to_root = SlotToRootMap.init(allocator);
    defer slot_to_root.deinit();
    try slot_to_root.put(slot, root);

    try store.archiveBlocks(slot, slot, &slot_to_root);

    const archived_blob = try db.getBlobSidecarsArchive(slot);
    defer if (archived_blob) |bytes| allocator.free(bytes);
    try std.testing.expect(archived_blob != null);
    try std.testing.expectEqualSlices(u8, "blob-sidecars", archived_blob.?);

    const archived_col_3 = try db.getDataColumnArchive(slot, 3);
    defer if (archived_col_3) |bytes| allocator.free(bytes);
    try std.testing.expect(archived_col_3 != null);
    try std.testing.expectEqualSlices(u8, "column-3", archived_col_3.?);

    const archived_col_7 = try db.getDataColumnArchive(slot, 7);
    defer if (archived_col_7) |bytes| allocator.free(bytes);
    try std.testing.expect(archived_col_7 != null);
    try std.testing.expectEqualSlices(u8, "column-7", archived_col_7.?);

    const hot_blob = try db.getBlobSidecars(root);
    defer if (hot_blob) |bytes| allocator.free(bytes);
    try std.testing.expect(hot_blob == null);

    const hot_col_3 = try db.getDataColumn(root, 3);
    defer if (hot_col_3) |bytes| allocator.free(bytes);
    try std.testing.expect(hot_col_3 == null);
}
