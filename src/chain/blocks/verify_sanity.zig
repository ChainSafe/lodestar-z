//! Sanity checks — cheap pre-STFN validation before any heavy work.
//!
//! These checks run in microseconds and reject obviously invalid blocks
//! before we spend CPU on state transition, BLS verification, or EL calls.
//!
//! Checks (following TS Lodestar verifyBlocksSanityChecks.ts):
//! 1. Not genesis block (slot 0)
//! 2. Not finalized (slot <= finalized_slot)
//! 3. Not from a future slot (> current_slot)
//! 4. Not already known (in fork choice)
//! 5. Parent is known (in fork choice)
//!
//! Some checks can be relaxed via ImportBlockOpts:
//! - ignore_if_known: skip AlreadyKnown error (range sync)
//! - ignore_if_finalized: skip WouldRevertFinalizedSlot error (range sync)
//!
//! Reference: Lodestar chain/blocks/verifyBlocksSanityChecks.ts

const std = @import("std");
const Allocator = std.mem.Allocator;

const consensus_types = @import("consensus_types");
const preset = @import("preset").preset;
const state_transition = @import("state_transition");
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const fork_choice_mod = @import("fork_choice");
const ForkChoice = fork_choice_mod.ForkChoiceStruct;
const ProtoNode = fork_choice_mod.ProtoNode;

const pipeline_types = @import("types.zig");
const BlockInput = pipeline_types.BlockInput;
const ImportBlockOpts = pipeline_types.ImportBlockOpts;
const SanityResult = pipeline_types.SanityResult;
const BlockImportError = pipeline_types.BlockImportError;

const Slot = consensus_types.primitive.Slot.Type;
const Root = [32]u8;

// ---------------------------------------------------------------------------
// Sanity check outcome
// ---------------------------------------------------------------------------

/// Outcome of verifySanity — either a valid SanityResult or a skip signal.
pub const SanityOutcome = union(enum) {
    /// Block passed sanity checks and should proceed through the pipeline.
    valid: SanityResult,
    /// Block was intentionally skipped (ignore_if_known / ignore_if_finalized).
    skipped: void,
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run pre-STFN sanity checks on a single block.
///
/// This is the cheap, fast first stage of the pipeline. No state access,
/// no I/O — just slot arithmetic and fork choice lookups.
///
/// `allocator` is needed for computing the block root (hash-tree-root
/// involves temporary allocations in the SSZ layer).
///
/// `block_to_state` is used as a fallback for parent detection when fork
/// choice doesn't have the parent yet (e.g., early in sync, test replay).
///
/// Returns:
/// - SanityOutcome.valid: block should continue through the pipeline
/// - SanityOutcome.skipped: block was intentionally ignored (not an error)
/// - BlockImportError: block is definitively invalid
pub fn verifySanity(
    allocator: Allocator,
    block_input: BlockInput,
    fork_choice: *const ForkChoice,
    current_slot: Slot,
    block_to_state: *const std.AutoArrayHashMap([32]u8, [32]u8),
    opts: ImportBlockOpts,
) BlockImportError!SanityOutcome {
    const block = block_input.block.beaconBlock();
    const block_slot = block.slot();
    const parent_root = block.parentRoot().*;

    // Compute block root via BeaconBlock hash-tree-root.
    // The SSZ hashTreeRoot needs an allocator for intermediate nodes.
    var block_root: Root = undefined;
    block.hashTreeRoot(allocator, &block_root) catch return BlockImportError.InternalError;

    // 1. Not genesis block.
    if (block_slot == 0) {
        if (opts.ignore_if_known) return .{ .skipped = {} };
        return BlockImportError.GenesisBlock;
    }

    // 2. Not finalized — block slot must be after the finalized slot.
    const finalized_slot = fork_choice.getFinalizedCheckpoint().epoch * preset.SLOTS_PER_EPOCH;
    if (block_slot <= finalized_slot) {
        if (opts.ignore_if_finalized) return .{ .skipped = {} };
        return BlockImportError.WouldRevertFinalizedSlot;
    }

    // 3. Not from a future slot.
    // TS Lodestar checks block_slot > current_slot (no tolerance on main pipeline).
    // Clock disparity tolerance is handled at the gossip layer.
    // Skip this check when the caller has already validated timing (e.g., API, range sync).
    if (!opts.skip_future_slot and block_slot > current_slot) {
        return BlockImportError.FutureSlot;
    }

    // 4. Not already known.
    if (fork_choice.hasBlock(block_root)) {
        if (opts.ignore_if_known) return .{ .skipped = {} };
        return BlockImportError.AlreadyKnown;
    }

    // 5. Parent must be known.
    // Try fork choice first (authoritative). If the parent isn't in fork choice yet
    // (e.g., early in sync or for test states where FC is newly initialized),
    // fall back to block_to_state map which tracks all known parent block roots.
    const parent_node_opt = fork_choice.getBlock(parent_root);
    const parent_known_in_map = block_to_state.contains(parent_root);

    if (parent_node_opt == null and !parent_known_in_map) {
        return BlockImportError.ParentUnknown;
    }

    const parent_slot = if (parent_node_opt) |pn| pn.slot else 0;

    return .{ .valid = .{
        .block_root = block_root,
        .block_slot = block_slot,
        .parent_root = parent_root,
        .parent_block = parent_node_opt,
        .parent_slot = parent_slot,
    } };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "SanityOutcome union layout" {
    const outcome = SanityOutcome{ .skipped = {} };
    try std.testing.expect(outcome == .skipped);
}

test "BlockImportError as error" {
    const err: BlockImportError!void = BlockImportError.GenesisBlock;
    try std.testing.expectError(BlockImportError.GenesisBlock, err);
}
