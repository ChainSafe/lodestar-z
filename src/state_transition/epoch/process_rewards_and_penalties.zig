const std = @import("std");
const Allocator = std.mem.Allocator;
const ForkSeq = @import("config").ForkSeq;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const GENESIS_EPOCH = @import("preset").GENESIS_EPOCH;
const getAttestationDeltas = @import("./get_attestation_deltas.zig").getAttestationDeltas;
const getRewardsAndPenaltiesAltair = @import("./get_rewards_and_penalties.zig").getRewardsAndPenaltiesAltair;

pub fn processRewardsAndPenalties(allocator: Allocator, cached_state: *CachedBeaconState, cache: *const EpochTransitionCache) !void {
    // No rewards are applied at the end of `GENESIS_EPOCH` because rewards are for work done in the previous epoch
    if (cache.current_epoch == GENESIS_EPOCH) {
        return;
    }

    const state = cached_state.state;

    const rewards = cache.rewards;
    const penalties = cache.penalties;
    try getRewardsAndPenalties(allocator, cached_state, cache, rewards, penalties);

    const balances = try state.balancesSlice(allocator);
    defer allocator.free(balances);

    for (rewards, penalties, balances) |reward, penalty, *balance| {
        const result = balance.* + reward -| penalty;
        balance.* = result;
    }

    var balances_arraylist: std.ArrayListUnmanaged(u64) = .fromOwnedSlice(balances);
    try state.setBalances(&balances_arraylist);
}

pub fn getRewardsAndPenalties(
    allocator: Allocator,
    cached_state: *const CachedBeaconState,
    cache: *const EpochTransitionCache,
    rewards: []u64,
    penalties: []u64,
) !void {
    const state = cached_state.state;
    const fork = cached_state.config.forkSeq(try state.slot());
    return if (fork == ForkSeq.phase0)
        try getAttestationDeltas(allocator, cached_state, cache, rewards, penalties)
    else
        try getRewardsAndPenaltiesAltair(allocator, cached_state, cache, rewards, penalties);
}

test "processRewardsAndPenalties - sanity" {
    try @import("../test_utils/test_runner.zig").TestRunner(processRewardsAndPenalties, .{
        .alloc = true,
        .err_return = true,
        .void_return = true,
    }).testProcessEpochFn();
    defer @import("../state_transition.zig").deinitStateTransition();
}
