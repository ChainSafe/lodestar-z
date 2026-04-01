//! Pending blocks waiting for data availability.
//!
//! Data sidecars are tracked separately by the data availability manager.
//! This module only owns fully decoded blocks until their associated DA
//! requirements are satisfied and the block is ready for the import pipeline.

const std = @import("std");
const Allocator = std.mem.Allocator;

const chain_types = @import("types.zig");
const consensus_types = @import("consensus_types");
const AnySignedBeaconBlock = @import("fork_types").AnySignedBeaconBlock;

const Root = [32]u8;
const Slot = consensus_types.primitive.Slot.Type;
const BlockSource = chain_types.BlockSource;
const ReadyBlockInput = chain_types.ReadyBlockInput;
const DataAvailabilityStatus = chain_types.DataAvailabilityStatus;

pub const PendingBlock = struct {
    block: AnySignedBeaconBlock,
    source: BlockSource,
    block_root: Root,
    slot: Slot,
    seen_timestamp_sec: u64,
};

pub const PendingDaBlocks = struct {
    allocator: Allocator,
    pending: std.AutoHashMap(Root, *PendingBlock),

    pub fn init(allocator: Allocator) PendingDaBlocks {
        return .{
            .allocator = allocator,
            .pending = std.AutoHashMap(Root, *PendingBlock).init(allocator),
        };
    }

    pub fn deinit(self: *PendingDaBlocks) void {
        var it = self.pending.valueIterator();
        while (it.next()) |pending_ptr| {
            destroyPending(self, pending_ptr.*);
        }
        self.pending.deinit();
    }

    pub fn onBlock(
        self: *PendingDaBlocks,
        block: AnySignedBeaconBlock,
        block_root: Root,
        slot: Slot,
        source: BlockSource,
        seen_timestamp_sec: u64,
        da_status: DataAvailabilityStatus,
    ) !?ReadyBlockInput {
        if (isReadyStatus(da_status)) {
            if (self.pending.fetchRemove(block_root)) |entry| {
                destroyPending(self, entry.value);
            }
            return .{
                .block = block,
                .source = source,
                .block_root = block_root,
                .slot = slot,
                .da_status = da_status,
                .seen_timestamp_sec = seen_timestamp_sec,
            };
        }

        if (self.pending.fetchRemove(block_root)) |entry| {
            destroyPending(self, entry.value);
        }

        const pending = try self.allocator.create(PendingBlock);
        pending.* = .{
            .block = block,
            .source = source,
            .block_root = block_root,
            .slot = slot,
            .seen_timestamp_sec = seen_timestamp_sec,
        };
        try self.pending.put(block_root, pending);
        return null;
    }

    pub fn onDataAvailable(
        self: *PendingDaBlocks,
        block_root: Root,
        da_status: DataAvailabilityStatus,
    ) ?ReadyBlockInput {
        if (!isReadyStatus(da_status)) return null;

        const entry = self.pending.fetchRemove(block_root) orelse return null;
        defer self.allocator.destroy(entry.value);

        return .{
            .block = entry.value.block,
            .source = entry.value.source,
            .block_root = entry.value.block_root,
            .slot = entry.value.slot,
            .da_status = da_status,
            .seen_timestamp_sec = entry.value.seen_timestamp_sec,
        };
    }

    pub fn removePending(self: *PendingDaBlocks, block_root: Root) void {
        if (self.pending.fetchRemove(block_root)) |entry| {
            destroyPending(self, entry.value);
        }
    }

    pub fn pruneBeforeSlot(self: *PendingDaBlocks, min_slot: Slot) void {
        var to_remove = std.ArrayListUnmanaged(Root).empty;
        defer to_remove.deinit(self.allocator);

        var it = self.pending.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.slot < min_slot) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch return;
            }
        }

        for (to_remove.items) |root| {
            self.removePending(root);
        }
    }
};

fn isReadyStatus(status: DataAvailabilityStatus) bool {
    return switch (status) {
        .available, .not_required, .out_of_range, .pre_data => true,
        .pending => false,
    };
}

fn destroyPending(self: *PendingDaBlocks, pending: *PendingBlock) void {
    pending.block.deinit(self.allocator);
    self.allocator.destroy(pending);
}
