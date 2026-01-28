const std = @import("std");
const Allocator = std.mem.Allocator;
const ForkSeq = @import("config").ForkSeq;
const BeaconConfig = @import("config").BeaconConfig;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const GENESIS_EPOCH = @import("preset").GENESIS_EPOCH;
const getAttestationDeltas = @import("./get_attestation_deltas.zig").getAttestationDeltas;
const getRewardsAndPenaltiesAltair = @import("./get_rewards_and_penalties.zig").getRewardsAndPenaltiesAltair;
const Node = @import("persistent_merkle_tree").Node;

pub fn processRewardsAndPenalties(
    comptime fork: ForkSeq,
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *ForkBeaconState(fork),
    cache: *const EpochTransitionCache,
) !void {
    // No rewards are applied at the end of `GENESIS_EPOCH` because rewards are for work done in the previous epoch
    if (cache.current_epoch == GENESIS_EPOCH) {
        return;
    }

    const rewards = cache.rewards;
    const penalties = cache.penalties;
    try getRewardsAndPenalties(fork, allocator, config, epoch_cache, state, cache, rewards, penalties);

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
    comptime fork: ForkSeq,
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *ForkBeaconState(fork),
    cache: *const EpochTransitionCache,
    rewards: []u64,
    penalties: []u64,
) !void {
    if (comptime fork == .phase0) {
        return try getAttestationDeltas(allocator, epoch_cache, cache, try state.finalizedEpoch(), rewards, penalties);
    }
    return try getRewardsAndPenaltiesAltair(fork, allocator, config, epoch_cache, state, cache, rewards, penalties);
}

const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;

test "processRewardsAndPenalties - sanity" {
    const allocator = std.testing.allocator;
    const pool_size = 10_000 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 10_000);
    defer test_state.deinit();

    try processRewardsAndPenalties(
        .electra,
        allocator,
        test_state.cached_state.config,
        test_state.cached_state.getEpochCache(),
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
    );
}
