const std = @import("std");
const Allocator = std.mem.Allocator;
const ssz = @import("consensus_types");
const preset = @import("preset").preset;
const c = @import("constants");
const BeaconStateAllForks = @import("../types/beacon_state.zig").BeaconStateAllForks;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const Epoch = ssz.primitive.Epoch.Type;
const ValidatorIndex = ssz.primitive.ValidatorIndex.Type;
const EffectiveBalanceIncrements = @import("../cache/effective_balance_increments.zig").EffectiveBalanceIncrements;
const computeEpochAtSlot = @import("./epoch.zig").computeEpochAtSlot;
const seed_utils = @import("./seed.zig");
const getSeed = seed_utils.getSeed;
const computeProposers = seed_utils.computeProposers;

/// Initializes `proposer_lookahead` during the Electra -> Fulu upgrade.
/// Fills the `proposer_lookahead` field with `(MIN_SEED_LOOKAHEAD + 1)` epochs worth of proposer indices.
/// Uses active indices from the epoch cache shufflings.
pub fn initializeProposerLookahead(
    allocator: Allocator,
    cached_state: *const CachedBeaconStateAllForks,
    out: []ValidatorIndex,
) !void {
    const epoch_cache = cached_state.epoch_cache_ref.get();
    const state = cached_state.state;

    const lookahead_epochs = preset.MIN_SEED_LOOKAHEAD + 1;
    const expected_len = lookahead_epochs * preset.SLOTS_PER_EPOCH;
    std.debug.assert(out.len == expected_len);

    const current_epoch = computeEpochAtSlot(state.slot());
    const effective_balance_increments = epoch_cache.getEffectiveBalanceIncrements();
    const fork_seq = state.forkSeq();

    // Fill proposer_lookahead with current epoch through current_epoch + MIN_SEED_LOOKAHEAD
    for (0..lookahead_epochs) |i| {
        const epoch = current_epoch + i;
        const offset = i * preset.SLOTS_PER_EPOCH;

        // Get active indices from the epoch cache
        const active_indices = epoch_cache.getActiveIndicesAtEpoch(epoch) orelse return error.ActiveIndicesNotFound;

        var seed: [32]u8 = undefined;
        try getSeed(state, epoch, c.DOMAIN_BEACON_PROPOSER, &seed);

        try computeProposers(
            allocator,
            fork_seq,
            seed,
            epoch,
            active_indices,
            effective_balance_increments,
            out[offset .. offset + preset.SLOTS_PER_EPOCH],
        );
    }
}

/// Updates `proposer_lookahead` during epoch processing.
/// Shifts out the oldest epoch and appends the new epoch at the end.
/// Uses active indices from the epoch transition cache for the new epoch.
pub fn processProposerLookahead(
    allocator: Allocator,
    cached_state: *CachedBeaconStateAllForks,
    epoch_transition_cache: *const EpochTransitionCache,
) !void {
    const state = cached_state.state;

    // Only process for Fulu fork
    if (!state.isFulu()) return;

    const fulu_state = switch (state.*) {
        .fulu => |s| s,
        else => return error.NotFuluState,
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
