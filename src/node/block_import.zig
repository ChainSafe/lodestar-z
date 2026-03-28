//! Node-level block import re-exports.
//!
//! Provides backward-compatible re-exports from chain module.
//! The dead BlockImporter struct has been removed — the live import path
//! goes through chain/blocks/pipeline.zig via Chain.importBlock().
//!
//! registerGenesisRoot is now handled directly by Chain.registerGenesisRoot().

const chain_mod = @import("chain");

/// Re-export HeadTracker from chain module.
pub const HeadTracker = chain_mod.HeadTracker;

/// Re-export ImportResult (canonical: chain/blocks/types.zig).
pub const ImportResult = chain_mod.ImportResult;

/// Re-export ImportError for legacy callers.
pub const ImportError = chain_mod.ImportError;

/// Dummy JustifiedBalancesGetter — returns empty balances.
/// Used for fork choice initialization; replace with real getter once
/// state regen cache integration is complete.
const fork_choice_mod = @import("fork_choice");
const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;

pub fn dummyBalancesGetterFn(_: ?*anyopaque, _: fork_choice_mod.CheckpointWithPayloadStatus, _: *CachedBeaconState) fork_choice_mod.JustifiedBalances {
    const std = @import("std");
    return fork_choice_mod.JustifiedBalances.init(std.heap.page_allocator);
}
