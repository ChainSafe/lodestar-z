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

const db_mod = @import("db");
const BeaconDB = db_mod.BeaconDB;

const state_transition = @import("state_transition");
const BlockStateCache = state_transition.BlockStateCache;

/// Configuration for the archive store.
pub const ArchiveConfig = struct {
    /// Archive a state snapshot every N epochs.
    state_archive_every_n_epochs: u64 = 1024,
    /// Whether to delete hot blocks after archiving.
    prune_hot_blocks_after_archive: bool = true,
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
            .config = config,
            .last_archived_state_epoch = 0,
            .last_finalized_slot = 0,
        };
    }

    pub fn deinit(_: *ArchiveStore) void {}

    /// Called when the chain finalizes a new checkpoint.
    ///
    /// Archives all blocks between the previous and new finalized slots,
    /// and optionally archives an epoch state snapshot.
    pub fn onFinalized(
        self: *ArchiveStore,
        checkpoint: FinalizedCheckpoint,
        slot_to_root: *const std.AutoArrayHashMap(u64, [32]u8),
    ) !void {
        const finalized_slot = checkpoint.epoch * 32; // SLOTS_PER_EPOCH for phase0/mainnet
        if (finalized_slot <= self.last_finalized_slot) return;

        const from_slot = self.last_finalized_slot + 1;
        const to_slot = finalized_slot;

        // Archive blocks in the finalized range.
        try self.archiveBlocks(from_slot, to_slot, slot_to_root);

        // Archive state snapshot if due.
        const epochs_since_last = checkpoint.epoch -| self.last_archived_state_epoch;
        if (epochs_since_last >= self.config.state_archive_every_n_epochs) {
            try self.archiveStateAtEpoch(checkpoint.epoch, checkpoint.root, slot_to_root);
            self.last_archived_state_epoch = checkpoint.epoch;
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
        slot_to_root: *const std.AutoArrayHashMap(u64, [32]u8),
    ) !void {
        var slot = from_slot;
        while (slot <= to_slot) : (slot += 1) {
            const root = slot_to_root.get(slot) orelse continue;

            // Read from hot DB.
            const data = try self.db.getBlock(root) orelse continue;
            defer self.allocator.free(data);

            // Write to archive (slot-keyed cold store).
            try self.db.putBlockArchive(slot, root, data);

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
        state_root: [32]u8,
    ) !void {
        const cached = self.block_state_cache.get(state_root) orelse {
            std.log.debug("ArchiveStore: state not in cache for slot {d}", .{slot});
            return;
        };
        const bytes = try cached.state.serialize(self.allocator);
        defer self.allocator.free(bytes);
        try self.db.putStateArchive(slot, state_root, bytes);
        std.log.debug("ArchiveStore: archived state at slot {d}", .{slot});
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn archiveStateAtEpoch(
        self: *ArchiveStore,
        epoch: u64,
        _: [32]u8,
        slot_to_root: *const std.AutoArrayHashMap(u64, [32]u8),
    ) !void {
        _ = self;
        _ = slot_to_root;
        _ = epoch;

        // Stub: epoch state archival not yet implemented.
        // Would look up the block_root→state_root mapping and archive the boundary state.
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
