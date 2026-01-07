const std = @import("std");
const Allocator = std.mem.Allocator;
const ssz = @import("consensus_types");
const preset = @import("preset").preset;
const c = @import("constants");
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const ValidatorIndex = ssz.primitive.ValidatorIndex.Type;
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;
const seed_utils = @import("../utils/seed.zig");
const getSeed = seed_utils.getSeed;
const computeProposers = seed_utils.computeProposers;

/// Updates `proposer_lookahead` during epoch processing.
/// Shifts out the oldest epoch and appends the new epoch at the end.
/// Uses active indices from the epoch transition cache for the new epoch.
pub fn processProposerLookahead(
    allocator: Allocator,
    cached_state: *CachedBeaconStateAllForks,
    epoch_transition_cache: *const EpochTransitionCache,
) !void {
    const state = cached_state.state;

    const fulu_state = switch (state.*) {
        .fulu => |s| s,
        // We already check for `state.isFulu()` in `processEpoch`
        // but if we do get in here we simply return.
        else => return,
    };

    const epoch_cache = cached_state.epoch_cache_ref.get();
    const lookahead_epochs = preset.MIN_SEED_LOOKAHEAD + 1;
    const last_epoch_start = (lookahead_epochs - 1) * preset.SLOTS_PER_EPOCH;

    // Shift out proposers in the first epoch
    std.mem.copyForwards(
        ValidatorIndex,
        fulu_state.proposer_lookahead[0..last_epoch_start],
        fulu_state.proposer_lookahead[preset.SLOTS_PER_EPOCH..],
    );

    // Fill in the last epoch with new proposer indices
    // The new epoch is current_epoch + MIN_SEED_LOOKAHEAD + 1 = current_epoch + 2
    const current_epoch = computeEpochAtSlot(state.slot());
    const new_epoch = current_epoch + preset.MIN_SEED_LOOKAHEAD + 1;

    // Active indices for the new epoch come from the epoch transition cache
    // (computed during beforeProcessEpoch for current_epoch + 2)
    const active_indices = epoch_transition_cache.next_shuffling_active_indices;
    const effective_balance_increments = epoch_cache.getEffectiveBalanceIncrements();

    var seed: [32]u8 = undefined;
    try getSeed(state, new_epoch, c.DOMAIN_BEACON_PROPOSER, &seed);

    try computeProposers(
        allocator,
        state.forkSeq(),
        seed,
        new_epoch,
        active_indices,
        effective_balance_increments,
        fulu_state.proposer_lookahead[last_epoch_start..],
    );
}
