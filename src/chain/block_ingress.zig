//! Pending block ingress waiting for required attachments.
//!
//! The chain may receive a block before all required attachments are ready.
//! Today that means blobs / data columns that gate beacon block import.
//! Separated execution payload envelopes are handled by
//! `payload_envelope_ingress.zig`, not by this module. This module owns fully
//! decoded beacon blocks until the required pre-import attachments are
//! satisfied and the block is ready for import.

const std = @import("std");
const Allocator = std.mem.Allocator;

const chain_types = @import("types.zig");
const blocks = @import("blocks/root.zig");
const consensus_types = @import("consensus_types");
const AnySignedBeaconBlock = @import("fork_types").AnySignedBeaconBlock;

const Root = [32]u8;
const Slot = consensus_types.primitive.Slot.Type;
const BlockSource = blocks.BlockSource;
const BlockDataFetchPlan = chain_types.BlockDataFetchPlan;
const ReadyBlockInput = chain_types.ReadyBlockInput;
const DataAvailabilityStatus = blocks.DataAvailabilityStatus;

pub const PendingIngressBlock = struct {
    block: AnySignedBeaconBlock,
    source: BlockSource,
    block_root: Root,
    slot: Slot,
    block_data_plan: BlockDataFetchPlan,
    seen_timestamp_sec: u64,
};

pub const PendingBlockIngress = struct {
    allocator: Allocator,
    pending: std.AutoHashMap(Root, *PendingIngressBlock),

    pub fn init(allocator: Allocator) PendingBlockIngress {
        return .{
            .allocator = allocator,
            .pending = std.AutoHashMap(Root, *PendingIngressBlock).init(allocator),
        };
    }

    pub fn deinit(self: *PendingBlockIngress) void {
        var it = self.pending.valueIterator();
        while (it.next()) |pending_ptr| {
            destroyPending(self, pending_ptr.*);
        }
        self.pending.deinit();
    }

    pub fn acceptBlock(
        self: *PendingBlockIngress,
        block: AnySignedBeaconBlock,
        block_root: Root,
        slot: Slot,
        source: BlockSource,
        block_data_plan: BlockDataFetchPlan,
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
                .block_data_plan = block_data_plan,
                .seen_timestamp_sec = seen_timestamp_sec,
            };
        }

        if (self.pending.fetchRemove(block_root)) |entry| {
            destroyPending(self, entry.value);
        }

        const pending = try self.allocator.create(PendingIngressBlock);
        errdefer self.allocator.destroy(pending);
        pending.* = .{
            .block = block,
            .source = source,
            .block_root = block_root,
            .slot = slot,
            .block_data_plan = block_data_plan,
            .seen_timestamp_sec = seen_timestamp_sec,
        };
        errdefer {
            pending.block_data_plan.deinit(self.allocator);
            pending.block.deinit(self.allocator);
        }
        try self.pending.put(block_root, pending);
        return null;
    }

    pub fn resolveAttachments(
        self: *PendingBlockIngress,
        block_root: Root,
        da_status: DataAvailabilityStatus,
    ) ?ReadyBlockInput {
        if (!isReadyStatus(da_status)) return null;

        const entry = self.pending.fetchRemove(block_root) orelse return null;
        defer self.allocator.destroy(entry.value);
        entry.value.block_data_plan.deinit(self.allocator);

        return .{
            .block = entry.value.block,
            .source = entry.value.source,
            .block_root = entry.value.block_root,
            .slot = entry.value.slot,
            .da_status = da_status,
            .block_data_plan = .none,
            .seen_timestamp_sec = entry.value.seen_timestamp_sec,
        };
    }

    pub fn removePending(self: *PendingBlockIngress, block_root: Root) void {
        if (self.pending.fetchRemove(block_root)) |entry| {
            destroyPending(self, entry.value);
        }
    }

    pub fn pruneBeforeSlot(self: *PendingBlockIngress, min_slot: Slot) usize {
        var to_remove: std.ArrayListUnmanaged(Root) = .empty;
        defer to_remove.deinit(self.allocator);

        var it = self.pending.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.slot < min_slot) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch return 0;
            }
        }

        for (to_remove.items) |root| {
            self.removePending(root);
        }

        return to_remove.items.len;
    }

    pub fn len(self: *const PendingBlockIngress) usize {
        return self.pending.count();
    }
};

fn isReadyStatus(status: DataAvailabilityStatus) bool {
    return switch (status) {
        .available, .not_required, .out_of_range, .pre_data => true,
        .pending => false,
    };
}

fn destroyPending(self: *PendingBlockIngress, pending: *PendingIngressBlock) void {
    pending.block_data_plan.deinit(self.allocator);
    pending.block.deinit(self.allocator);
    self.allocator.destroy(pending);
}
