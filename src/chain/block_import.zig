//! Block import pipeline: orchestrates the full sequence from raw block to chain head update.
//!
//! Pipeline stages:
//! 1. Sanity checks — slot bounds, parent known, not finalized, not duplicate
//! 2. State transition — processSlots + processBlock via STFN
//! 3. Post-STFN — cache post-state, persist block, update fork choice, track head
//!
//! This module is the Zig equivalent of TS Lodestar's chain/blocks/importBlock.ts
//! and verifyBlocksSanityChecks.ts, adapted for lodestar-z's architecture.
//!
//! Dependencies on db and fork_choice are avoided via the node-level BeaconNode
//! which owns the full wiring. This module provides the types (HeadTracker,
//! ImportResult, ImportError) and the sanity-check logic.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;
const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;
const computeEpochAtSlot = state_transition.computeEpochAtSlot;

// ---------------------------------------------------------------------------
// Import result — re-exported from chain/blocks/types.zig (canonical version).
// ---------------------------------------------------------------------------

const blocks_types = @import("blocks/types.zig");
pub const ImportResult = blocks_types.ImportResult;

// ---------------------------------------------------------------------------
// Import errors — expected operational errors, not assertions.
// ---------------------------------------------------------------------------

pub const ImportError = error{
    /// Block's parent root is not in our chain. Caller should trigger
    /// unknown block sync to fetch the parent.
    UnknownParentBlock,
    /// Block slot is at or before the finalized slot.
    BlockAlreadyFinalized,
    /// Block slot is zero — genesis block cannot be imported.
    GenesisBlock,
    /// Block has already been imported (duplicate).
    BlockAlreadyKnown,
};

// ---------------------------------------------------------------------------
// HeadTracker — tracks head root/slot and slot→root mapping.
// ---------------------------------------------------------------------------

pub const HeadTracker = struct {
    head_root: [32]u8,
    head_slot: u64,
    finalized_epoch: u64,
    justified_epoch: u64,
    head_state_root: [32]u8,

    slot_roots: std.AutoArrayHashMap(u64, [32]u8),
    allocator: Allocator,

    pub fn init(allocator: Allocator, genesis_root: [32]u8) HeadTracker {
        return .{
            .head_root = genesis_root,
            .head_slot = 0,
            .finalized_epoch = 0,
            .justified_epoch = 0,
            .head_state_root = [_]u8{0} ** 32,
            .slot_roots = std.AutoArrayHashMap(u64, [32]u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *HeadTracker) void {
        self.slot_roots.deinit();
    }

    pub fn onBlock(self: *HeadTracker, block_root: [32]u8, slot: u64, state_root: [32]u8) !void {
        // Record slot → block_root mapping for lookups (e.g. getStatus).
        // NOTE: Do NOT update head_root/head_slot/head_state_root here.
        // Head is authoritative only when set by fork choice (setHead).
        // Naive slot comparison (slot >= head_slot) fails during forks where a
        // lower-slot block on a heavier branch should become the new head.
        // See: P0-3 fix — head is set only by fork choice updateAndGetHead results.
        try self.slot_roots.put(slot, block_root);
        _ = state_root; // state_root stored by fork choice / block_to_state map
    }

    /// Update the head based on fork choice's authoritative head result.
    ///
    /// Called by importVerifiedBlock after updateAndGetHead succeeds.
    /// This is the ONLY place that should update head_root/head_slot.
    pub fn setHead(self: *HeadTracker, block_root: [32]u8, slot: u64, state_root: [32]u8) void {
        self.head_root = block_root;
        self.head_slot = slot;
        self.head_state_root = state_root;
    }

    pub fn onEpochTransition(self: *HeadTracker, state: *CachedBeaconState) !void {
        var finalized_cp: types.phase0.Checkpoint.Type = undefined;
        try state.state.finalizedCheckpoint(&finalized_cp);
        self.finalized_epoch = finalized_cp.epoch;

        var justified_cp: types.phase0.Checkpoint.Type = undefined;
        try state.state.currentJustifiedCheckpoint(&justified_cp);
        self.justified_epoch = justified_cp.epoch;
    }

    pub fn getBlockRoot(self: *const HeadTracker, slot: u64) ?[32]u8 {
        return self.slot_roots.get(slot);
    }

    /// Prune slot → root entries below the finalized slot.
    ///
    /// Called from onFinalized to prevent unbounded growth. Entries at or
    /// above `finalized_slot` are retained (we may still need them for
    /// fork choice lookups on the canonical chain).
    pub fn pruneBelow(self: *HeadTracker, finalized_slot: u64) void {
        if (finalized_slot == 0) return;
        var keys_to_remove = std.array_list.Managed(u64).init(self.allocator);
        defer keys_to_remove.deinit();

        var it = self.slot_roots.iterator();
        while (it.next()) |entry| {
            if (entry.key_ptr.* < finalized_slot) {
                keys_to_remove.append(entry.key_ptr.*) catch continue;
            }
        }
        for (keys_to_remove.items) |slot| {
            _ = self.slot_roots.swapRemove(slot);
        }
    }
};

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "HeadTracker: basic tracking — onBlock records slots, setHead updates head" {
    // P0-3 fix: onBlock no longer updates head_root/head_slot.
    // Head is ONLY updated via setHead (called by fork choice recompute).
    var tracker = HeadTracker.init(std.testing.allocator, [_]u8{0x00} ** 32);
    defer tracker.deinit();

    try std.testing.expectEqual(@as(u64, 0), tracker.head_slot);

    const root_1 = [_]u8{0x01} ** 32;
    try tracker.onBlock(root_1, 1, [_]u8{0x11} ** 32);
    // onBlock should NOT change head_slot — still 0 (genesis).
    try std.testing.expectEqual(@as(u64, 0), tracker.head_slot);

    // setHead is the only way to update the head.
    tracker.setHead(root_1, 1, [_]u8{0x11} ** 32);
    try std.testing.expectEqual(@as(u64, 1), tracker.head_slot);
    try std.testing.expectEqualSlices(u8, &root_1, &tracker.head_root);

    const root_3 = [_]u8{0x03} ** 32;
    try tracker.onBlock(root_3, 3, [_]u8{0x33} ** 32);
    // onBlock should NOT change head_slot — still 1.
    try std.testing.expectEqual(@as(u64, 1), tracker.head_slot);
    tracker.setHead(root_3, 3, [_]u8{0x33} ** 32);
    try std.testing.expectEqual(@as(u64, 3), tracker.head_slot);
    try std.testing.expectEqualSlices(u8, &root_3, &tracker.head_root);
}

test "HeadTracker: slot roots lookup" {
    var tracker = HeadTracker.init(std.testing.allocator, [_]u8{0x00} ** 32);
    defer tracker.deinit();

    const root_5 = [_]u8{0x05} ** 32;
    try tracker.onBlock(root_5, 5, [_]u8{0x55} ** 32);

    const found = tracker.getBlockRoot(5);
    try std.testing.expect(found != null);
    try std.testing.expectEqualSlices(u8, &root_5, &found.?);

    try std.testing.expect(tracker.getBlockRoot(6) == null);
}
