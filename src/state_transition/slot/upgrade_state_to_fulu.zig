const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const ct = @import("consensus_types");
const ValidatorIndex = ct.primitive.ValidatorIndex.Type;
const preset = @import("preset").preset;
const c = @import("constants");
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;
const seed_utils = @import("../utils/seed.zig");
const getSeed = seed_utils.getSeed;
const computeProposers = seed_utils.computeProposers;

pub fn upgradeStateToFulu(allocator: Allocator, cached_state: *CachedBeaconState) !void {
    var electra_state = cached_state.state;
    if (electra_state.forkSeq() != .electra) {
        return error.StateIsNotElectra;
    }

    var state = try electra_state.upgradeUnsafe();
    errdefer state.deinit();

    // Update fork version
    const new_fork = ct.phase0.Fork.Type{
        .previous_version = try electra_state.forkCurrentVersion(),
        .current_version = cached_state.config.chain.FULU_FORK_VERSION,
        .epoch = cached_state.getEpochCache().epoch,
    };
    try state.setFork(&new_fork);

    var proposer_lookahead = ct.fulu.ProposerLookahead.default_value;
    try initializeProposerLookahead(
        allocator,
        cached_state,
        &proposer_lookahead,
    );
    try state.setProposerLookahead(&proposer_lookahead);

    electra_state.deinit();
    cached_state.state.* = state;
}

/// Initializes `proposer_lookahead` during the Electra -> Fulu upgrade.
/// Fills the `proposer_lookahead` field with `(MIN_SEED_LOOKAHEAD + 1)` epochs worth of proposer indices.
/// Uses active indices from the epoch cache shufflings.
fn initializeProposerLookahead(
    allocator: Allocator,
    cached_state: *CachedBeaconState,
    out: []ValidatorIndex,
) !void {
    const lookahead_epochs = preset.MIN_SEED_LOOKAHEAD + 1;
    const expected_len = lookahead_epochs * preset.SLOTS_PER_EPOCH;
    if (out.len != expected_len) return error.InvalidProposerLookaheadLength;

    const epoch_cache = cached_state.epoch_cache_ref.get();
    const state = cached_state.state;

    const current_epoch = computeEpochAtSlot(try state.slot());
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
