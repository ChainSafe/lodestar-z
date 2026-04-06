//! Pending payload-envelope ingress for Gloas-style separated execution payloads.
//!
//! This is intentionally separate from `block_ingress.zig`.
//! Beacon block ingress tracks data required before the beacon block itself can
//! be imported. Payload-envelope ingress tracks the second-stage input that may
//! arrive after the block has already been ingested.

const std = @import("std");
const consensus_types = @import("consensus_types");

const Allocator = std.mem.Allocator;
const Slot = consensus_types.primitive.Slot.Type;
const Root = [32]u8;

pub const PayloadEnvelopeFetchPlan = struct {
    column_indices: []const u64 = &.{},
    needs_execution_payload: bool = true,

    pub fn deinit(self: *PayloadEnvelopeFetchPlan, allocator: Allocator) void {
        if (self.column_indices.len > 0) allocator.free(self.column_indices);
        self.* = undefined;
    }
};

pub const PendingPayloadEnvelope = struct {
    block_root: Root,
    slot: Slot,
    fetch_plan: PayloadEnvelopeFetchPlan,

    pub fn deinit(self: *PendingPayloadEnvelope, allocator: Allocator) void {
        self.fetch_plan.deinit(allocator);
        self.* = undefined;
    }
};

pub const PayloadEnvelopeIngress = struct {
    allocator: Allocator,
    pending: std.AutoHashMap(Root, *PendingPayloadEnvelope),

    pub fn init(allocator: Allocator) PayloadEnvelopeIngress {
        return .{
            .allocator = allocator,
            .pending = std.AutoHashMap(Root, *PendingPayloadEnvelope).init(allocator),
        };
    }

    pub fn deinit(self: *PayloadEnvelopeIngress) void {
        var it = self.pending.valueIterator();
        while (it.next()) |pending_ptr| {
            pending_ptr.*.deinit(self.allocator);
            self.allocator.destroy(pending_ptr.*);
        }
        self.pending.deinit();
    }

    pub fn putOrReplace(
        self: *PayloadEnvelopeIngress,
        block_root: Root,
        slot: Slot,
        fetch_plan: PayloadEnvelopeFetchPlan,
    ) !void {
        if (self.pending.fetchRemove(block_root)) |entry| {
            entry.value.deinit(self.allocator);
            self.allocator.destroy(entry.value);
        }

        const pending = try self.allocator.create(PendingPayloadEnvelope);
        errdefer self.allocator.destroy(pending);
        pending.* = .{
            .block_root = block_root,
            .slot = slot,
            .fetch_plan = fetch_plan,
        };
        errdefer pending.fetch_plan.deinit(self.allocator);
        try self.pending.put(block_root, pending);
    }

    pub fn remove(self: *PayloadEnvelopeIngress, block_root: Root) void {
        if (self.pending.fetchRemove(block_root)) |entry| {
            entry.value.deinit(self.allocator);
            self.allocator.destroy(entry.value);
        }
    }

    pub fn pruneBeforeSlot(self: *PayloadEnvelopeIngress, min_slot: Slot) usize {
        var to_remove: std.ArrayListUnmanaged(Root) = .empty;
        defer to_remove.deinit(self.allocator);

        var it = self.pending.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.slot < min_slot) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch return 0;
            }
        }

        for (to_remove.items) |root| {
            self.remove(root);
        }

        return to_remove.items.len;
    }

    pub fn len(self: *const PayloadEnvelopeIngress) usize {
        return self.pending.count();
    }
};
