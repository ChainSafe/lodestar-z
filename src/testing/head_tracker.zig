//! Minimal head tracker for deterministic simulation testing.
//!
//! Implements a simple "latest slot wins" head selection strategy.
//! This is NOT fork choice — it assumes a single chain with no forks.
//! Sufficient for DST where all nodes process the same block sequence.
//!
//! When full proto-array fork choice lands, this becomes the fallback
//! for simple test scenarios.

const std = @import("std");
const types = @import("consensus_types");
const state_transition = @import("state_transition");
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const CachedBeaconState = state_transition.CachedBeaconState;

pub const HeadTracker = struct {
    head_root: [32]u8,
    head_slot: u64,
    finalized_epoch: u64,
    justified_epoch: u64,

    /// Block roots indexed by slot for ancestor lookups.
    /// Only tracks slots with blocks (not skipped slots).
    slot_roots: std.array_hash_map.Auto(u64, [32]u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, genesis_root: [32]u8) HeadTracker {
        return .{
            .head_root = genesis_root,
            .head_slot = 0,
            .finalized_epoch = 0,
            .justified_epoch = 0,
            .slot_roots = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *HeadTracker) void {
        self.slot_roots.deinit(self.allocator);
    }

    /// Update head after importing a block.
    /// Simple strategy: head is always the block with the highest slot.
    pub fn onBlock(self: *HeadTracker, block_root: [32]u8, slot: u64) !void {
        try self.slot_roots.put(self.allocator, slot, block_root);
        if (slot > self.head_slot) {
            self.head_root = block_root;
            self.head_slot = slot;
        }
    }

    /// Update finality checkpoints from a post-epoch-transition state.
    pub fn onEpochTransition(self: *HeadTracker, state: *CachedBeaconState) !void {
        var finalized_cp: types.phase0.Checkpoint.Type = undefined;
        try state.state.finalizedCheckpoint(&finalized_cp);
        self.finalized_epoch = finalized_cp.epoch;

        var justified_cp: types.phase0.Checkpoint.Type = undefined;
        try state.state.currentJustifiedCheckpoint(&justified_cp);
        self.justified_epoch = justified_cp.epoch;
    }

    /// Get the block root at a given slot (if a block was produced there).
    pub fn getBlockRoot(self: *const HeadTracker, slot: u64) ?[32]u8 {
        return self.slot_roots.get(slot);
    }

    /// Check whether the given epoch has been finalized.
    pub fn isFinalized(self: *const HeadTracker, epoch: u64) bool {
        return epoch <= self.finalized_epoch;
    }
};

// ── Tests ────────────────────────────────────────────────────────────

test "HeadTracker: basic head tracking" {
    var tracker = HeadTracker.init(std.testing.allocator, [_]u8{0x00} ** 32);
    defer tracker.deinit();

    try std.testing.expectEqual(@as(u64, 0), tracker.head_slot);

    // Add block at slot 1.
    const root_1 = [_]u8{0x01} ** 32;
    try tracker.onBlock(root_1, 1);
    try std.testing.expectEqual(@as(u64, 1), tracker.head_slot);
    try std.testing.expectEqualSlices(u8, &root_1, &tracker.head_root);

    // Add block at slot 3 (skip slot 2).
    const root_3 = [_]u8{0x03} ** 32;
    try tracker.onBlock(root_3, 3);
    try std.testing.expectEqual(@as(u64, 3), tracker.head_slot);
    try std.testing.expectEqualSlices(u8, &root_3, &tracker.head_root);

    // Slot 2 should have no root (skipped).
    try std.testing.expect(tracker.getBlockRoot(2) == null);
    // Slot 1 should have its root.
    const found = tracker.getBlockRoot(1);
    try std.testing.expect(found != null);
    try std.testing.expectEqualSlices(u8, &root_1, &found.?);
}

test "HeadTracker: out-of-order blocks do not rewind head" {
    var tracker = HeadTracker.init(std.testing.allocator, [_]u8{0x00} ** 32);
    defer tracker.deinit();

    const root_5 = [_]u8{0x05} ** 32;
    try tracker.onBlock(root_5, 5);
    try std.testing.expectEqual(@as(u64, 5), tracker.head_slot);

    // Receiving an older block does not change head.
    const root_2 = [_]u8{0x02} ** 32;
    try tracker.onBlock(root_2, 2);
    try std.testing.expectEqual(@as(u64, 5), tracker.head_slot);
    try std.testing.expectEqualSlices(u8, &root_5, &tracker.head_root);
}

test "HeadTracker: finality tracking" {
    var tracker = HeadTracker.init(std.testing.allocator, [_]u8{0x00} ** 32);
    defer tracker.deinit();

    try std.testing.expectEqual(@as(u64, 0), tracker.finalized_epoch);
    try std.testing.expect(tracker.isFinalized(0));
    try std.testing.expect(!tracker.isFinalized(1));
}
