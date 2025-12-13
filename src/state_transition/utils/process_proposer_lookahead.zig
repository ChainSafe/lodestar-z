const std = @import("std");
const Allocator = std.mem.Allocator;
const ssz = @import("consensus_types");
const preset = @import("preset").preset;
const c = @import("constants");
const BeaconStateAllForks = @import("../types/beacon_state.zig").BeaconStateAllForks;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const ValidatorIndex = ssz.primitive.ValidatorIndex.Type;
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
    const lookahead_epochs = preset.MIN_SEED_LOOKAHEAD + 1;
    const expected_len = lookahead_epochs * preset.SLOTS_PER_EPOCH;
    if (out.len != expected_len) return error.InvalidProposerLookaheadLength;

    const epoch_cache = cached_state.epoch_cache_ref.get();
    const state = cached_state.state;

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
