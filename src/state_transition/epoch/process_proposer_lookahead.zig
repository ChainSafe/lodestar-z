const std = @import("std");
const Allocator = std.mem.Allocator;
const ssz = @import("consensus_types");
const preset = @import("preset").preset;
const c = @import("constants");
const ForkSeq = @import("config").ForkSeq;
const BeaconState = @import("fork_types").BeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const EpochShufflingRc = @import("../utils/epoch_shuffling.zig").EpochShufflingRc;
const computeEpochShufflingForFork = @import("../utils/epoch_shuffling.zig").computeEpochShufflingForFork;
const ValidatorIndex = ssz.primitive.ValidatorIndex.Type;
const computeEpochAtSlot = @import("../utils/epoch.zig").computeEpochAtSlot;
const seed_utils = @import("../utils/seed.zig");
const getSeed = seed_utils.getSeed;
const computeProposers = seed_utils.computeProposers;

/// Updates `proposer_lookahead` during epoch processing.
/// Shifts out the oldest epoch and appends the new epoch at the end.
/// Uses active indices from the epoch transition cache for the new epoch.
pub fn processProposerLookahead(
    comptime fork: ForkSeq,
    allocator: Allocator,
    epoch_cache: *EpochCache,
    state: *BeaconState(fork),
    epoch_transition_cache: *EpochTransitionCache,
) !void {
    var proposer_lookahead: [ssz.fulu.ProposerLookahead.length]u64 = undefined;
    try state.proposerLookaheadInto(&proposer_lookahead);

    const lookahead_epochs = preset.MIN_SEED_LOOKAHEAD + 1;
    const last_epoch_start = (lookahead_epochs - 1) * preset.SLOTS_PER_EPOCH;

    // Shift out proposers in the first epoch
    std.mem.copyForwards(
        ValidatorIndex,
        proposer_lookahead[0..last_epoch_start],
        proposer_lookahead[preset.SLOTS_PER_EPOCH..],
    );

    // Fill in the last epoch with new proposer indices
    // The new epoch is current_epoch + MIN_SEED_LOOKAHEAD + 1 = current_epoch + 2
    const current_epoch = computeEpochAtSlot(try state.slot());
    const new_epoch = current_epoch + preset.MIN_SEED_LOOKAHEAD + 1;

    // Active indices for the new epoch come from the epoch transition cache
    // (computed during beforeProcessEpoch for current_epoch + 2)
    const active_indices = epoch_transition_cache.next_shuffling_active_indices;
    const effective_balance_increments = epoch_cache.getEffectiveBalanceIncrements();

    var seed: [32]u8 = undefined;
    try getSeed(fork, state, new_epoch, c.DOMAIN_BEACON_PROPOSER, &seed);

    // Proposers need only the unshuffled active indices, so they overlap with the shuffling job.
    try computeProposers(
        fork,
        allocator,
        seed,
        new_epoch,
        active_indices,
        effective_balance_increments,
        proposer_lookahead[last_epoch_start..],
    );

    const next_shuffling = blk: {
        if (epoch_transition_cache.shuffling_job != null) {
            break :blk try epoch_transition_cache.joinShuffling();
        }
        const shuffling_active_indices = try epoch_cache.allocator.alloc(ValidatorIndex, active_indices.len);
        errdefer epoch_cache.allocator.free(shuffling_active_indices);
        std.mem.copyForwards(ValidatorIndex, shuffling_active_indices, active_indices);
        break :blk try computeEpochShufflingForFork(
            fork,
            epoch_cache.allocator,
            state,
            shuffling_active_indices,
            new_epoch,
        );
    };
    const next_shuffling_rc = blk: {
        errdefer next_shuffling.deinit();
        break :blk try EpochShufflingRc.create(epoch_cache.allocator, next_shuffling);
    };
    errdefer next_shuffling_rc.unref();

    try state.setProposerLookahead(&proposer_lookahead);
    epoch_transition_cache.next_shuffling = next_shuffling_rc;
}

test {
    _ = @import("process_proposer_lookahead_test.zig");
}
