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
// Import result
// ---------------------------------------------------------------------------

pub const ImportResult = struct {
    block_root: [32]u8,
    state_root: [32]u8,
    slot: u64,
    epoch_transition: bool,
};

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
        try self.slot_roots.put(slot, block_root);
        if (slot >= self.head_slot) {
            self.head_root = block_root;
            self.head_slot = slot;
            self.head_state_root = state_root;
        }
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
};

// ---------------------------------------------------------------------------
// Sanity checks — cheap pre-STFN validation.
// ---------------------------------------------------------------------------

/// Run pre-STFN sanity checks on a block.
///
/// Checks:
/// - Not genesis (slot 0)
/// - Not already finalized
/// - Not a duplicate (block_root already in known_roots)
/// - Parent is known
///
/// Returns `ImportError` if the block should be rejected/ignored.
pub fn verifySanity(
    block_slot: u64,
    parent_root: [32]u8,
    block_root: [32]u8,
    finalized_epoch: u64,
    known_roots: *const std.AutoArrayHashMap([32]u8, [32]u8),
) ImportError!void {
    // Not genesis block.
    if (block_slot == 0) return ImportError.GenesisBlock;

    // Not already finalized.
    const finalized_slot = finalized_epoch * preset.SLOTS_PER_EPOCH;
    if (block_slot <= finalized_slot) return ImportError.BlockAlreadyFinalized;

    // Not a duplicate.
    if (known_roots.contains(block_root)) return ImportError.BlockAlreadyKnown;

    // Parent must be known.
    if (!known_roots.contains(parent_root)) return ImportError.UnknownParentBlock;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "HeadTracker: basic tracking" {
    var tracker = HeadTracker.init(std.testing.allocator, [_]u8{0x00} ** 32);
    defer tracker.deinit();

    try std.testing.expectEqual(@as(u64, 0), tracker.head_slot);

    const root_1 = [_]u8{0x01} ** 32;
    try tracker.onBlock(root_1, 1, [_]u8{0x11} ** 32);
    try std.testing.expectEqual(@as(u64, 1), tracker.head_slot);
    try std.testing.expectEqualSlices(u8, &root_1, &tracker.head_root);

    const root_3 = [_]u8{0x03} ** 32;
    try tracker.onBlock(root_3, 3, [_]u8{0x33} ** 32);
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

test "verifySanity: rejects genesis block" {
    var known = std.AutoArrayHashMap([32]u8, [32]u8).init(std.testing.allocator);
    defer known.deinit();
    const err = verifySanity(0, [_]u8{0} ** 32, [_]u8{1} ** 32, 0, &known);
    try std.testing.expectError(ImportError.GenesisBlock, err);
}

test "verifySanity: rejects finalized block" {
    var known = std.AutoArrayHashMap([32]u8, [32]u8).init(std.testing.allocator);
    defer known.deinit();
    // finalized_epoch=1 → finalized_slot=32, block at slot 30 is finalized.
    const err = verifySanity(30, [_]u8{0} ** 32, [_]u8{1} ** 32, 1, &known);
    try std.testing.expectError(ImportError.BlockAlreadyFinalized, err);
}

test "verifySanity: rejects duplicate block" {
    var known = std.AutoArrayHashMap([32]u8, [32]u8).init(std.testing.allocator);
    defer known.deinit();
    const root = [_]u8{0xAA} ** 32;
    try known.put(root, [_]u8{0xBB} ** 32);
    const err = verifySanity(33, [_]u8{0} ** 32, root, 0, &known);
    try std.testing.expectError(ImportError.BlockAlreadyKnown, err);
}

test "verifySanity: rejects unknown parent" {
    var known = std.AutoArrayHashMap([32]u8, [32]u8).init(std.testing.allocator);
    defer known.deinit();
    const err = verifySanity(33, [_]u8{0xCC} ** 32, [_]u8{0xDD} ** 32, 0, &known);
    try std.testing.expectError(ImportError.UnknownParentBlock, err);
}

test "verifySanity: accepts valid block" {
    var known = std.AutoArrayHashMap([32]u8, [32]u8).init(std.testing.allocator);
    defer known.deinit();
    const parent = [_]u8{0xAA} ** 32;
    try known.put(parent, [_]u8{0xBB} ** 32);
    // Valid: slot 33, known parent, not duplicate, not finalized.
    try verifySanity(33, parent, [_]u8{0xCC} ** 32, 0, &known);
}
