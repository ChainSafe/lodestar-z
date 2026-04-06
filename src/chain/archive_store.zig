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
const db_mod = @import("db");
const BeaconDB = db_mod.BeaconDB;
const BatchOp = db_mod.BatchOp;
const DatabaseId = db_mod.DatabaseId;
const fork_types = @import("fork_types");
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;

const StateRegen = @import("regen/root.zig").StateRegen;
const finalization_plan_mod = @import("finalization_plan.zig");
const FinalizationPlan = finalization_plan_mod.FinalizationPlan;
const Root = finalization_plan_mod.Root;
const Slot = u64;
const SlotToRootMap = finalization_plan_mod.SlotToRootMap;
const BlockToStateMap = finalization_plan_mod.BlockToStateMap;
const BlockToParentMap = finalization_plan_mod.BlockToParentMap;

const FinalizationBatch = struct {
    allocator: Allocator,
    arena: std.heap.ArenaAllocator,
    ops: std.ArrayListUnmanaged(BatchOp),
    owned_values: std.ArrayListUnmanaged([]const u8),

    fn init(allocator: Allocator) FinalizationBatch {
        const arena = std.heap.ArenaAllocator.init(allocator);
        return .{
            .allocator = allocator,
            .arena = arena,
            .ops = .empty,
            .owned_values = .empty,
        };
    }

    fn deinit(self: *FinalizationBatch) void {
        for (self.owned_values.items) |bytes| self.allocator.free(bytes);
        self.owned_values.deinit(self.allocator);
        self.ops.deinit(self.arena.allocator());
        self.arena.deinit();
    }

    fn takeOwnedValue(self: *FinalizationBatch, bytes: []const u8) ![]const u8 {
        try self.owned_values.append(self.allocator, bytes);
        return bytes;
    }

    fn dup(self: *FinalizationBatch, bytes: []const u8) ![]const u8 {
        return try self.arena.allocator().dupe(u8, bytes);
    }

    fn appendPut(self: *FinalizationBatch, db: DatabaseId, key: []const u8, value: []const u8) !void {
        try self.ops.append(self.arena.allocator(), .{ .put = .{ .db = db, .key = key, .value = value } });
    }

    fn appendDelete(self: *FinalizationBatch, db: DatabaseId, key: []const u8) !void {
        try self.ops.append(self.arena.allocator(), .{ .delete = .{ .db = db, .key = key } });
    }

    fn slotKey(self: *FinalizationBatch, slot: u64) ![]const u8 {
        const key = db_mod.slotKey(slot);
        return self.dup(&key);
    }

    fn rootKey(self: *FinalizationBatch, root: Root) ![]const u8 {
        return self.dup(&root);
    }

    fn slotColumnKey(self: *FinalizationBatch, slot: u64, column_index: u64) ![]const u8 {
        const key = db_mod.buckets.slotColumnKey(slot, column_index);
        return self.dup(&key);
    }

    fn rootColumnKey(self: *FinalizationBatch, root: Root, column_index: u64) ![]const u8 {
        const key = db_mod.rootColumnKey(root, column_index);
        return self.dup(&key);
    }

    fn u64Value(self: *FinalizationBatch, value: u64) ![]const u8 {
        const bytes = db_mod.slotKey(value);
        return self.dup(&bytes);
    }
};

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
    state_regen: *StateRegen,
    config: ArchiveConfig,

    /// Last epoch for which we archived a state snapshot.
    last_archived_state_epoch: u64,
    /// Last finalized slot we have processed.
    last_finalized_slot: u64,

    pub fn init(
        allocator: Allocator,
        db: *BeaconDB,
        state_regen: *StateRegen,
        config: ArchiveConfig,
    ) ArchiveStore {
        return .{
            .allocator = allocator,
            .db = db,
            .state_regen = state_regen,
            .config = config,
            .last_archived_state_epoch = 0,
            .last_finalized_slot = 0,
        };
    }

    pub fn deinit(_: *ArchiveStore) void {}

    pub fn restoreProgress(self: *ArchiveStore, finalized_slot: Slot) !void {
        const persisted_finalized_slot = try self.db.getChainInfoU64(.archive_finalized_slot) orelse 0;
        const persisted_state_epoch = try self.db.getChainInfoU64(.archive_state_epoch) orelse 0;
        const max_finalized_slot = @min(persisted_finalized_slot, finalized_slot);

        // Never trust metadata alone. Archive progress must correspond to a contiguous
        // canonical finalized chain in the archive indices.
        const archived_head = try self.db.getContiguousArchivedCanonicalHead(finalized_slot);
        const archived_finalized_slot = if (archived_head) |head|
            if (persisted_finalized_slot == 0) head.slot else @min(head.slot, max_finalized_slot)
        else
            0;

        self.last_finalized_slot = archived_finalized_slot;
        self.last_archived_state_epoch = @min(
            persisted_state_epoch,
            archived_finalized_slot / preset.SLOTS_PER_EPOCH,
        );
    }

    /// Called when the chain finalizes a new checkpoint.
    ///
    /// Archives all blocks between the previous and new finalized slots,
    /// and optionally archives an epoch state snapshot.
    pub fn onFinalized(
        self: *ArchiveStore,
        plan: *const FinalizationPlan,
        block_to_state: *const BlockToStateMap,
    ) !void {
        const finalized_slot = plan.finalized_slot;
        if (finalized_slot <= self.last_finalized_slot) return;
        const from_slot = self.last_finalized_slot + 1;
        try self.persistFinalizedIndices(plan, from_slot);
        try self.catchUpToFinalized(.{
            .epoch = plan.finalized_epoch,
            .root = plan.finalized_root,
        }, block_to_state);
    }

    /// Archive finalized history up to the given checkpoint using the durable
    /// finalized-history indices already present in the DB.
    pub fn catchUpToFinalized(
        self: *ArchiveStore,
        checkpoint: FinalizedCheckpoint,
        block_to_state: *const BlockToStateMap,
    ) !void {
        const finalized_slot = checkpoint.epoch * preset.SLOTS_PER_EPOCH;
        if (finalized_slot <= self.last_finalized_slot) return;

        const from_slot = self.last_finalized_slot + 1;
        const to_slot = finalized_slot;

        var batch = FinalizationBatch.init(self.allocator);
        defer batch.deinit();

        try self.appendFinalizedRangeOps(&batch, from_slot, to_slot);

        const archived_state_epoch = try self.appendDueStateArchiveOps(
            &batch,
            checkpoint.epoch,
            block_to_state,
        );

        try self.appendProgressOps(&batch, finalized_slot, archived_state_epoch);
        try self.db.writeBatch(batch.ops.items);

        self.last_finalized_slot = finalized_slot;
        if (archived_state_epoch) |epoch| {
            self.last_archived_state_epoch = epoch;
        }
        std.log.info("ArchiveStore: archived slots {d}..{d} (epoch {d})", .{
            from_slot, to_slot, checkpoint.epoch,
        });
    }

    /// Move blocks for slots [from_slot, to_slot] from hot DB to archive.
    ///
    /// Reads each block by root (looked up from slot_to_root), writes to archive,
    /// and optionally deletes from hot DB.
    fn archiveBlocks(
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
    fn archiveState(
        self: *ArchiveStore,
        slot: u64,
        state_root: Root,
    ) !void {
        const cached = self.state_regen.block_cache.get(state_root) orelse {
            std.log.debug("ArchiveStore: state not in cache for slot {d}", .{slot});
            return;
        };
        const bytes = try cached.state.serialize(self.allocator);
        defer self.allocator.free(bytes);
        try self.db.putStateArchive(slot, state_root, bytes);
        const epoch = slot / preset.SLOTS_PER_EPOCH;
        if (epoch > self.last_archived_state_epoch) {
            try self.db.putChainInfoU64(.archive_state_epoch, epoch);
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
            (try self.db.getFinalizedBlockRootBySlot(slot) orelse return);
        const state_root = try self.stateRootForBlock(slot, block_root, block_to_state) orelse return;
        try self.archiveState(slot, state_root);
    }

    fn appendProgressOps(
        self: *ArchiveStore,
        batch: *FinalizationBatch,
        finalized_slot: Slot,
        archived_state_epoch: ?u64,
    ) !void {
        _ = self;
        try batch.appendPut(
            .chain_info,
            BeaconDB.chainInfoKeyBytes(.archive_finalized_slot),
            try batch.u64Value(finalized_slot),
        );
        if (archived_state_epoch) |epoch| {
            try batch.appendPut(
                .chain_info,
                BeaconDB.chainInfoKeyBytes(.archive_state_epoch),
                try batch.u64Value(epoch),
            );
        }
    }

    fn persistFinalizedIndices(
        self: *ArchiveStore,
        plan: *const FinalizationPlan,
        from_slot: Slot,
    ) !void {
        var index_batch = FinalizationBatch.init(self.allocator);
        defer index_batch.deinit();
        try self.appendFinalizedIndexOps(&index_batch, plan, from_slot);
        try self.db.writeBatch(index_batch.ops.items);
    }

    fn appendDueStateArchiveOps(
        self: *ArchiveStore,
        batch: *FinalizationBatch,
        finalized_epoch: u64,
        block_to_state: *const BlockToStateMap,
    ) !?u64 {
        const frequency = self.config.state_archive_every_n_epochs;
        if (frequency == 0) return null;

        var next_epoch = if (self.last_archived_state_epoch == 0)
            frequency
        else
            self.last_archived_state_epoch + frequency;
        var archived_state_epoch: ?u64 = null;

        while (next_epoch <= finalized_epoch) : (next_epoch += frequency) {
            if (self.appendStateArchiveAtEpochOps(batch, next_epoch, block_to_state)) |did_archive| {
                if (did_archive) archived_state_epoch = next_epoch;
            } else |err| switch (err) {
                error.MissingFinalizedStateArchiveSource => {
                    std.log.debug(
                        "ArchiveStore: stopping state snapshot backfill at epoch {d}: {}",
                        .{ next_epoch, err },
                    );
                    break;
                },
                else => return err,
            }
        }

        return archived_state_epoch;
    }

    fn appendFinalizedIndexOps(
        self: *ArchiveStore,
        batch: *FinalizationBatch,
        plan: *const FinalizationPlan,
        from_slot: Slot,
    ) !void {
        _ = self;
        var slot = from_slot;
        while (slot <= plan.finalized_slot) : (slot += 1) {
            const root = plan.finalized_slot_roots.get(slot) orelse continue;
            const parent_root = plan.finalized_parent_roots.get(root) orelse
                return error.MissingFinalizedParentRootIndexSource;

            const slot_key = try batch.slotKey(slot);
            try batch.appendPut(.idx_main_chain, slot_key, try batch.rootKey(root));
            try batch.appendPut(.idx_block_root, try batch.rootKey(root), try batch.u64Value(slot));
            try batch.appendPut(.idx_block_parent_root, try batch.rootKey(parent_root), try batch.u64Value(slot));
        }

        try batch.appendPut(
            .chain_info,
            BeaconDB.chainInfoKeyBytes(.finalized_slot),
            try batch.u64Value(plan.finalized_slot),
        );
        try batch.appendPut(
            .chain_info,
            BeaconDB.chainInfoKeyBytes(.finalized_root),
            try batch.rootKey(plan.finalized_root),
        );
    }

    fn appendFinalizedRangeOps(
        self: *ArchiveStore,
        batch: *FinalizationBatch,
        from_slot: Slot,
        to_slot: Slot,
    ) !void {
        var slot = from_slot;
        while (slot <= to_slot) : (slot += 1) {
            const root = try self.db.getFinalizedBlockRootBySlot(slot) orelse continue;
            try self.appendArchivedBlockOps(batch, slot, root);
            try self.appendArchivedBlobOps(batch, slot, root);
            try self.appendArchivedDataColumnOps(batch, slot, root);
        }
    }

    fn appendArchivedBlockOps(
        self: *ArchiveStore,
        batch: *FinalizationBatch,
        slot: Slot,
        root: Root,
    ) !void {
        const hot = try self.db.getBlock(root);
        if (hot) |data| {
            const value = try batch.takeOwnedValue(data);
            const slot_key = try batch.slotKey(slot);
            try batch.appendPut(.block_archive, slot_key, value);
            if (self.config.prune_hot_blocks_after_archive) {
                try batch.appendDelete(.block, try batch.rootKey(root));
            }
        } else if (try self.db.getBlockArchive(slot)) |bytes| {
            self.allocator.free(bytes);
        } else {
            return error.MissingFinalizedBlockArchiveSource;
        }
    }

    fn appendArchivedBlobOps(
        self: *ArchiveStore,
        batch: *FinalizationBatch,
        slot: Slot,
        root: Root,
    ) !void {
        const hot = try self.db.getBlobSidecars(root);
        if (hot) |bytes| {
            const value = try batch.takeOwnedValue(bytes);
            try batch.appendPut(.blob_sidecar_archive, try batch.slotKey(slot), value);
            if (self.config.prune_hot_blobs_after_archive) {
                try batch.appendDelete(.blob_sidecar, try batch.rootKey(root));
            }
        }
    }

    fn appendArchivedDataColumnOps(
        self: *ArchiveStore,
        batch: *FinalizationBatch,
        slot: Slot,
        root: Root,
    ) !void {
        const hot_sidecars = try self.db.getDataColumnSidecars(root);
        if (hot_sidecars) |bytes| {
            const value = try batch.takeOwnedValue(bytes);
            try batch.appendPut(.data_column_archive, try batch.slotKey(slot), value);
            if (self.config.prune_hot_data_columns_after_archive) {
                try batch.appendDelete(.data_column, try batch.rootKey(root));
            }
        }

        for (0..preset_root.NUMBER_OF_COLUMNS) |column_index_usize| {
            const column_index: u64 = @intCast(column_index_usize);
            const hot_column = try self.db.getDataColumn(root, column_index);
            if (hot_column) |bytes| {
                const value = try batch.takeOwnedValue(bytes);
                try batch.appendPut(
                    .data_column_single_archive,
                    try batch.slotColumnKey(slot, column_index),
                    value,
                );
                if (self.config.prune_hot_data_columns_after_archive) {
                    try batch.appendDelete(.data_column_single, try batch.rootColumnKey(root, column_index));
                }
            }
        }
    }

    fn appendStateArchiveAtEpochOps(
        self: *ArchiveStore,
        batch: *FinalizationBatch,
        epoch: u64,
        block_to_state: *const BlockToStateMap,
    ) !bool {
        const slot = epoch * preset.SLOTS_PER_EPOCH;
        const block_root = try self.db.getFinalizedBlockRootBySlot(slot) orelse
            return error.MissingFinalizedStateArchiveSource;
        const state_root = try self.stateRootForBlock(slot, block_root, block_to_state) orelse
            return error.MissingFinalizedStateArchiveSource;

        if (try self.db.getStateArchive(slot)) |bytes| {
            self.allocator.free(bytes);
        } else {
            const encoded = blk: {
                if (self.state_regen.block_cache.get(state_root)) |cached| {
                    break :blk try cached.state.serialize(self.allocator);
                }

                const regenerated = try self.state_regen.getStateBySlot(slot) orelse
                    return error.MissingFinalizedStateArchiveSource;
                const regenerated_root = (try regenerated.state.hashTreeRoot()).*;
                if (!std.mem.eql(u8, &regenerated_root, &state_root)) {
                    return error.MissingFinalizedStateArchiveSource;
                }
                break :blk try regenerated.state.serialize(self.allocator);
            };
            const value = try batch.takeOwnedValue(encoded);
            try batch.appendPut(.state_archive, try batch.slotKey(slot), value);
        }
        try batch.appendPut(.idx_state_root, try batch.rootKey(state_root), try batch.u64Value(slot));
        return true;
    }

    fn stateRootForBlock(
        self: *ArchiveStore,
        slot: Slot,
        block_root: Root,
        block_to_state: *const BlockToStateMap,
    ) !?Root {
        if (block_to_state.get(block_root)) |state_root| return state_root;

        const beacon_config = self.state_regen.shared_state_graph.config;
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

const RegenRuntimeFixture = @import("regen/test_fixture.zig").RegenRuntimeFixture;

test "ArchiveStore: init/deinit is safe" {
    var fixture = try RegenRuntimeFixture.init(std.testing.allocator, 16);
    defer fixture.deinit();

    var store = ArchiveStore.init(std.testing.allocator, fixture.db, fixture.regen, .{});
    defer store.deinit();

    try std.testing.expectEqual(@as(u64, 0), store.last_finalized_slot);
}

test "ArchiveStore: archiveBlocks moves data from hot to archive" {
    var fixture = try RegenRuntimeFixture.init(std.testing.allocator, 16);
    defer fixture.deinit();

    var store = ArchiveStore.init(std.testing.allocator, fixture.db, fixture.regen, .{
        .state_archive_every_n_epochs = 1024,
        .prune_hot_blocks_after_archive = true,
    });
    defer store.deinit();

    // Insert a block into the hot DB.
    const root = [_]u8{0xAB} ** 32;
    const data = "fake block bytes";
    try fixture.db.putBlock(root, data);

    // Build a slot_to_root mapping.
    var slot_to_root = std.AutoArrayHashMap(u64, [32]u8).init(std.testing.allocator);
    defer slot_to_root.deinit();
    try slot_to_root.put(10, root);

    // Archive slot 10.
    try store.archiveBlocks(10, 10, &slot_to_root);

    // Block should now be in archive and removed from hot.
    const archived = try fixture.db.getBlockArchive(10);
    try std.testing.expect(archived != null);
    defer if (archived) |b| std.testing.allocator.free(b);
    try std.testing.expectEqualSlices(u8, data, archived.?);

    const hot = try fixture.db.getBlock(root);
    defer if (hot) |b| std.testing.allocator.free(b);
    try std.testing.expect(hot == null);
}

fn testFinalizationPlan(
    allocator: Allocator,
    epoch: u64,
    root: Root,
    slot_to_root: *const SlotToRootMap,
    block_to_parent: *const BlockToParentMap,
) !FinalizationPlan {
    var finalized_slot_roots = SlotToRootMap.init(allocator);
    errdefer finalized_slot_roots.deinit();
    var finalized_parent_roots = BlockToParentMap.init(allocator);
    errdefer finalized_parent_roots.deinit();

    var slot_iter = slot_to_root.iterator();
    while (slot_iter.next()) |entry| {
        try finalized_slot_roots.put(entry.key_ptr.*, entry.value_ptr.*);
    }

    var parent_iter = block_to_parent.iterator();
    while (parent_iter.next()) |entry| {
        try finalized_parent_roots.put(entry.key_ptr.*, entry.value_ptr.*);
    }

    return .{
        .allocator = allocator,
        .finalized_epoch = epoch,
        .finalized_root = root,
        .finalized_slot = epoch * preset.SLOTS_PER_EPOCH,
        .prune_slot = if (epoch > 2)
            (epoch - 2) * preset.SLOTS_PER_EPOCH
        else
            0,
        .finalized_slot_roots = finalized_slot_roots,
        .finalized_parent_roots = finalized_parent_roots,
    };
}

test "ArchiveStore: onFinalized archives epoch boundary state" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    const cached_state = try fixture.clonePublishedState();
    try cached_state.state.setSlot(preset.SLOTS_PER_EPOCH);
    try cached_state.state.commit();
    const state_root = try fixture.block_cache.add(cached_state, false);

    const block_root = [_]u8{0xBC} ** 32;
    try fixture.db.putBlock(block_root, "epoch-boundary-block");

    var slot_to_root = SlotToRootMap.init(allocator);
    defer slot_to_root.deinit();
    try slot_to_root.put(preset.SLOTS_PER_EPOCH, block_root);

    var block_to_state = BlockToStateMap.init(allocator);
    defer block_to_state.deinit();
    try block_to_state.put(block_root, state_root);
    var block_to_parent = BlockToParentMap.init(allocator);
    defer block_to_parent.deinit();
    try block_to_parent.put(block_root, [_]u8{0xAA} ** 32);

    var store = ArchiveStore.init(allocator, fixture.db, fixture.regen, .{
        .state_archive_every_n_epochs = 1,
        .prune_hot_blocks_after_archive = true,
    });
    defer store.deinit();

    var plan = try testFinalizationPlan(allocator, 1, block_root, &slot_to_root, &block_to_parent);
    defer plan.deinit();
    try store.onFinalized(&plan, &block_to_state);

    const archived_block = try fixture.db.getBlockArchive(preset.SLOTS_PER_EPOCH);
    try std.testing.expect(archived_block != null);
    defer if (archived_block) |bytes| allocator.free(bytes);

    const archived_by_parent = try fixture.db.getBlockArchiveByParentRoot([_]u8{0xAA} ** 32);
    try std.testing.expect(archived_by_parent != null);
    defer if (archived_by_parent) |bytes| allocator.free(bytes);

    const archived_state = try fixture.db.getStateArchive(preset.SLOTS_PER_EPOCH);
    try std.testing.expect(archived_state != null);
    defer if (archived_state) |bytes| allocator.free(bytes);

    const archived_finalized_slot = try fixture.db.getChainInfoU64(.archive_finalized_slot);
    try std.testing.expectEqual(@as(?u64, preset.SLOTS_PER_EPOCH), archived_finalized_slot);

    const archived_state_epoch = try fixture.db.getChainInfoU64(.archive_state_epoch);
    try std.testing.expectEqual(@as(?u64, 1), archived_state_epoch);
}

test "ArchiveStore: onFinalized archives blocks even when state snapshot source is missing" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    const slot = preset.SLOTS_PER_EPOCH;
    const block_root = [_]u8{0xCB} ** 32;
    const parent_root = [_]u8{0xCA} ** 32;
    const state_root = [_]u8{0xCC} ** 32;

    try fixture.db.putBlock(block_root, "finalized-block");

    var slot_to_root = SlotToRootMap.init(allocator);
    defer slot_to_root.deinit();
    try slot_to_root.put(slot, block_root);

    var block_to_parent = BlockToParentMap.init(allocator);
    defer block_to_parent.deinit();
    try block_to_parent.put(block_root, parent_root);

    var block_to_state = BlockToStateMap.init(allocator);
    defer block_to_state.deinit();
    try block_to_state.put(block_root, state_root);

    var store = ArchiveStore.init(allocator, fixture.db, fixture.regen, .{
        .state_archive_every_n_epochs = 1,
        .prune_hot_blocks_after_archive = true,
    });
    defer store.deinit();

    var plan = try testFinalizationPlan(allocator, 1, block_root, &slot_to_root, &block_to_parent);
    defer plan.deinit();
    try store.onFinalized(&plan, &block_to_state);

    const archived_block = try fixture.db.getBlockArchive(slot);
    try std.testing.expect(archived_block != null);
    defer if (archived_block) |bytes| allocator.free(bytes);
    try std.testing.expectEqualSlices(u8, "finalized-block", archived_block.?);

    const archived_state = try fixture.db.getStateArchive(slot);
    defer if (archived_state) |bytes| allocator.free(bytes);
    try std.testing.expectEqual(@as(?[]const u8, null), archived_state);

    const archive_progress = try fixture.db.getChainInfoU64(.archive_finalized_slot);
    try std.testing.expectEqual(@as(?u64, slot), archive_progress);

    const archived_state_epoch = try fixture.db.getChainInfoU64(.archive_state_epoch);
    try std.testing.expectEqual(@as(?u64, null), archived_state_epoch);
}

test "ArchiveStore: onFinalized backfills multiple due state snapshots" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    var slot_to_root = SlotToRootMap.init(allocator);
    defer slot_to_root.deinit();
    var block_to_parent = BlockToParentMap.init(allocator);
    defer block_to_parent.deinit();
    var block_to_state = BlockToStateMap.init(allocator);
    defer block_to_state.deinit();

    const epochs = [_]u64{ 2, 4, 6 };
    const roots = [_]Root{
        [_]u8{0xA2} ** 32,
        [_]u8{0xA4} ** 32,
        [_]u8{0xA6} ** 32,
    };
    const parent_roots = [_]Root{
        [_]u8{0x01} ** 32,
        roots[0],
        roots[1],
    };

    for (epochs, roots, parent_roots) |epoch, root, parent_root| {
        const state = try fixture.clonePublishedState();
        try state.state.setSlot(epoch * preset.SLOTS_PER_EPOCH);
        try state.state.commit();
        const state_root = try fixture.block_cache.add(state, false);

        try fixture.db.putBlock(root, "finalized-block");
        try slot_to_root.put(epoch * preset.SLOTS_PER_EPOCH, root);
        try block_to_parent.put(root, parent_root);
        try block_to_state.put(root, state_root);
    }

    var store = ArchiveStore.init(allocator, fixture.db, fixture.regen, .{
        .state_archive_every_n_epochs = 2,
        .prune_hot_blocks_after_archive = true,
    });
    defer store.deinit();

    var plan = try testFinalizationPlan(allocator, 6, roots[2], &slot_to_root, &block_to_parent);
    defer plan.deinit();
    try store.onFinalized(&plan, &block_to_state);

    for (epochs) |epoch| {
        const archived_state = try fixture.db.getStateArchive(epoch * preset.SLOTS_PER_EPOCH);
        try std.testing.expect(archived_state != null);
        defer if (archived_state) |bytes| allocator.free(bytes);
    }

    const archived_state_epoch = try fixture.db.getChainInfoU64(.archive_state_epoch);
    try std.testing.expectEqual(@as(?u64, 6), archived_state_epoch);
}

test "ArchiveStore: restoreProgress uses persisted archive progress" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    const root_a = [_]u8{0x11} ** 32;
    const root_b = [_]u8{0x22} ** 32;
    try fixture.db.putBlockArchiveCanonical(32, root_a, [_]u8{0x01} ** 32, "block_a");
    try fixture.db.putBlockArchiveCanonical(64, root_b, root_a, "block_b");

    try fixture.db.putChainInfoU64(.archive_finalized_slot, 64);
    try fixture.db.putChainInfoU64(.archive_state_epoch, 8);

    var store = ArchiveStore.init(allocator, fixture.db, fixture.regen, .{});
    defer store.deinit();

    try store.restoreProgress(128);

    try std.testing.expectEqual(@as(u64, 64), store.last_finalized_slot);
    try std.testing.expectEqual(@as(u64, 2), store.last_archived_state_epoch);
}

test "ArchiveStore: restoreProgress derives archived progress without metadata" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    const root_a = [_]u8{0x31} ** 32;
    const root_b = [_]u8{0x32} ** 32;
    try fixture.db.putBlockArchiveCanonical(32, root_a, [_]u8{0x21} ** 32, "block_a");
    try fixture.db.putBlockArchiveCanonical(64, root_b, root_a, "block_b");

    var store = ArchiveStore.init(allocator, fixture.db, fixture.regen, .{});
    defer store.deinit();

    try store.restoreProgress(128);

    try std.testing.expectEqual(@as(u64, 64), store.last_finalized_slot);
    try std.testing.expectEqual(@as(u64, 0), store.last_archived_state_epoch);
}

test "ArchiveStore: onFinalized repairs missing finalized parent-root index" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    const slot = preset.SLOTS_PER_EPOCH;
    const root = [_]u8{0xBC} ** 32;
    const parent_root = [_]u8{0xAD} ** 32;

    try fixture.db.putBlockArchive(slot, root, "epoch-boundary-block");

    var slot_to_root = SlotToRootMap.init(allocator);
    defer slot_to_root.deinit();
    try slot_to_root.put(slot, root);

    var block_to_parent = BlockToParentMap.init(allocator);
    defer block_to_parent.deinit();
    try block_to_parent.put(root, parent_root);

    var block_to_state = BlockToStateMap.init(allocator);
    defer block_to_state.deinit();

    var store = ArchiveStore.init(allocator, fixture.db, fixture.regen, .{
        .state_archive_every_n_epochs = 1024,
        .prune_hot_blocks_after_archive = true,
    });
    defer store.deinit();

    var plan = try testFinalizationPlan(allocator, 1, root, &slot_to_root, &block_to_parent);
    defer plan.deinit();
    try store.onFinalized(&plan, &block_to_state);

    const archived_by_parent = try fixture.db.getBlockArchiveByParentRoot(parent_root);
    try std.testing.expect(archived_by_parent != null);
    defer if (archived_by_parent) |bytes| allocator.free(bytes);
    try std.testing.expectEqualSlices(u8, "epoch-boundary-block", archived_by_parent.?);
}

test "ArchiveStore: onFinalized persists finalized indices before archival completes" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    const slot = preset.SLOTS_PER_EPOCH;
    const root = [_]u8{0xD1} ** 32;
    const parent_root = [_]u8{0xE2} ** 32;

    var slot_to_root = SlotToRootMap.init(allocator);
    defer slot_to_root.deinit();
    try slot_to_root.put(slot, root);

    var block_to_parent = BlockToParentMap.init(allocator);
    defer block_to_parent.deinit();
    try block_to_parent.put(root, parent_root);

    var block_to_state = BlockToStateMap.init(allocator);
    defer block_to_state.deinit();

    var store = ArchiveStore.init(allocator, fixture.db, fixture.regen, .{});
    defer store.deinit();

    var plan = try testFinalizationPlan(allocator, 1, root, &slot_to_root, &block_to_parent);
    defer plan.deinit();
    try std.testing.expectError(
        error.MissingFinalizedBlockArchiveSource,
        store.onFinalized(&plan, &block_to_state),
    );

    const finalized_root = try fixture.db.getFinalizedBlockRootBySlot(slot);
    try std.testing.expectEqual(root, finalized_root.?);

    const finalized_slot_by_parent = try fixture.db.getFinalizedBlockSlotByParentRoot(parent_root);
    try std.testing.expectEqual(@as(?u64, slot), finalized_slot_by_parent);

    const persisted_finalized_slot = try fixture.db.getChainInfoU64(.finalized_slot);
    try std.testing.expectEqual(@as(?u64, slot), persisted_finalized_slot);

    const persisted_finalized_root = try fixture.db.getChainInfo(.finalized_root);
    defer if (persisted_finalized_root) |bytes| allocator.free(bytes);
    try std.testing.expect(persisted_finalized_root != null);
    try std.testing.expectEqualSlices(u8, &root, persisted_finalized_root.?);

    const archive_progress = try fixture.db.getChainInfoU64(.archive_finalized_slot);
    try std.testing.expectEqual(@as(?u64, null), archive_progress);
}

test "ArchiveStore: onFinalized retries archival from durable finalized indices" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    const slot = preset.SLOTS_PER_EPOCH;
    const root = [_]u8{0xD3} ** 32;
    const parent_root = [_]u8{0xE4} ** 32;

    var initial_slot_to_root = SlotToRootMap.init(allocator);
    defer initial_slot_to_root.deinit();
    try initial_slot_to_root.put(slot, root);

    var initial_block_to_parent = BlockToParentMap.init(allocator);
    defer initial_block_to_parent.deinit();
    try initial_block_to_parent.put(root, parent_root);

    var block_to_state = BlockToStateMap.init(allocator);
    defer block_to_state.deinit();

    var store = ArchiveStore.init(allocator, fixture.db, fixture.regen, .{});
    defer store.deinit();

    var initial_plan = try testFinalizationPlan(allocator, 1, root, &initial_slot_to_root, &initial_block_to_parent);
    defer initial_plan.deinit();
    try std.testing.expectError(
        error.MissingFinalizedBlockArchiveSource,
        store.onFinalized(&initial_plan, &block_to_state),
    );

    try fixture.db.putBlock(root, "retryable-finalized-block");

    var empty_slot_to_root = SlotToRootMap.init(allocator);
    defer empty_slot_to_root.deinit();
    var empty_block_to_parent = BlockToParentMap.init(allocator);
    defer empty_block_to_parent.deinit();

    var retry_plan = try testFinalizationPlan(allocator, 1, root, &empty_slot_to_root, &empty_block_to_parent);
    defer retry_plan.deinit();
    try store.onFinalized(&retry_plan, &block_to_state);

    const archived = try fixture.db.getBlockArchive(slot);
    try std.testing.expect(archived != null);
    defer if (archived) |bytes| allocator.free(bytes);
    try std.testing.expectEqualSlices(u8, "retryable-finalized-block", archived.?);

    const archive_progress = try fixture.db.getChainInfoU64(.archive_finalized_slot);
    try std.testing.expectEqual(@as(?u64, slot), archive_progress);
}

test "ArchiveStore: archiveBlocks archives blob sidecars and data columns" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    var store = ArchiveStore.init(allocator, fixture.db, fixture.regen, .{
        .prune_hot_blocks_after_archive = true,
        .prune_hot_blobs_after_archive = true,
        .prune_hot_data_columns_after_archive = true,
    });
    defer store.deinit();

    const slot: u64 = 10;
    const root = [_]u8{0xAC} ** 32;
    try fixture.db.putBlock(root, "finalized-block");
    try fixture.db.putBlobSidecars(root, "blob-sidecars");
    try fixture.db.putDataColumn(root, 3, "column-3");
    try fixture.db.putDataColumn(root, 7, "column-7");

    var slot_to_root = SlotToRootMap.init(allocator);
    defer slot_to_root.deinit();
    try slot_to_root.put(slot, root);

    try store.archiveBlocks(slot, slot, &slot_to_root);

    const archived_blob = try fixture.db.getBlobSidecarsArchive(slot);
    defer if (archived_blob) |bytes| allocator.free(bytes);
    try std.testing.expect(archived_blob != null);
    try std.testing.expectEqualSlices(u8, "blob-sidecars", archived_blob.?);

    const archived_col_3 = try fixture.db.getDataColumnArchive(slot, 3);
    defer if (archived_col_3) |bytes| allocator.free(bytes);
    try std.testing.expect(archived_col_3 != null);
    try std.testing.expectEqualSlices(u8, "column-3", archived_col_3.?);

    const archived_col_7 = try fixture.db.getDataColumnArchive(slot, 7);
    defer if (archived_col_7) |bytes| allocator.free(bytes);
    try std.testing.expect(archived_col_7 != null);
    try std.testing.expectEqualSlices(u8, "column-7", archived_col_7.?);

    const hot_blob = try fixture.db.getBlobSidecars(root);
    defer if (hot_blob) |bytes| allocator.free(bytes);
    try std.testing.expect(hot_blob == null);

    const hot_col_3 = try fixture.db.getDataColumn(root, 3);
    defer if (hot_col_3) |bytes| allocator.free(bytes);
    try std.testing.expect(hot_col_3 == null);
}
