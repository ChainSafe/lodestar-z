const std = @import("std");
const Allocator = std.mem.Allocator;
const ForkSeq = @import("config").ForkSeq;
const BeaconConfig = @import("config").BeaconConfig;
const BeaconState = @import("fork_types").BeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const GENESIS_EPOCH = @import("preset").GENESIS_EPOCH;
const getAttestationDeltas = @import("./get_attestation_deltas.zig").getAttestationDeltas;
const getRewardsAndPenaltiesAltair = @import("./get_rewards_and_penalties.zig").getRewardsAndPenaltiesAltair;

pub fn processRewardsAndPenalties(
    comptime fork: ForkSeq,
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *BeaconState(fork),
    cache: *EpochTransitionCache,
    slashing_penalties: ?[]const u64,
) !void {
    // No rewards are applied at the end of `GENESIS_EPOCH` because rewards are for work done in the previous epoch
    if (cache.current_epoch == GENESIS_EPOCH) {
        return;
    }

    const rewards = cache.rewards;
    const penalties = cache.penalties;
    try getRewardsAndPenalties(fork, config, epoch_cache, state, cache, rewards, penalties);

    const balances = try state.balancesSlice(allocator);
    errdefer allocator.free(balances);

    // Use saturating arithmetic for performance. Saturating operations are branchless, which
    // enables SIMD auto-vectorization of the balance update loop. This is safe because a
    // balance overflow is mathematically impossible: the maximum total ETH supply (~1.2e17 Gwei)
    // is more than 150x smaller than the max u64 value (~1.8e19 Gwei).
    if (slashing_penalties) |slashings| {
        for (rewards, penalties, balances, 0..) |reward, penalty, *balance, i| {
            const slashing: u64 = if (i < slashings.len) slashings[i] else 0;
            std.debug.assert(balance.* <= std.math.maxInt(u64) - reward);
            balance.* = ((balance.* +| reward) -| penalty) -| slashing;
        }
    } else {
        for (rewards, penalties, balances) |reward, penalty, *balance| {
            std.debug.assert(balance.* <= std.math.maxInt(u64) - reward);
            balance.* = (balance.* +| reward) -| penalty;
        }
    }

    // Populate cache.balances for reuse by the validator monitor and
    // more importantly processEffectiveBalanceUpdates() doesn't need to
    // get from tree view state which has to commit.
    var new_balances: std.ArrayList(u64) = .fromOwnedSlice(balances);
    try state.setBalances(&new_balances);

    if (cache.balances) |*old_balances| {
        old_balances.deinit(allocator);
    }
    cache.balances = new_balances;
}

pub fn getRewardsAndPenalties(
    comptime fork: ForkSeq,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *BeaconState(fork),
    cache: *const EpochTransitionCache,
    rewards: []u64,
    penalties: []u64,
) !void {
    if (comptime fork == .phase0) {
        return try getAttestationDeltas(epoch_cache, cache, try state.finalizedEpoch(), rewards, penalties);
    }
    return try getRewardsAndPenaltiesAltair(fork, config, epoch_cache, state, cache, rewards, penalties);
}
