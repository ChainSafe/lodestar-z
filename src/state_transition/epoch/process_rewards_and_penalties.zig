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
const Node = @import("persistent_merkle_tree").Node;

pub fn processRewardsAndPenalties(
    comptime fork: ForkSeq,
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *BeaconState(fork),
    cache: *const EpochTransitionCache,
    slashing_penalties: ?[]const u64,
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

    // Use saturating arithmetic instead of checked (`std.math.add`):
    // - Overflow is impossible: max ETH supply ~120M ETH = ~1.2e17 Gwei,
    //   u64 max = ~1.8e19, giving 154x headroom even with all rewards summed.
    // - Saturating ops are branchless, enabling SIMD auto-vectorization of the
    //   balance loop (~3.4x speedup on the inner loop for 500k+ validators).
    if (slashing_penalties) |slashings| {
        for (rewards, penalties, balances, 0..) |reward, penalty, *balance, i| {
            const slashing: u64 = if (i < slashings.len) slashings[i] else 0;
            balance.* = ((balance.* +| reward) -| penalty) -| slashing;
        }
    } else {
        for (rewards, penalties, balances) |reward, penalty, *balance| {
            balance.* = (balance.* +| reward) -| penalty;
        }
    }

    var balances_arraylist: std.ArrayListUnmanaged(u64) = .fromOwnedSlice(balances);
    try state.setBalances(&balances_arraylist);
}

pub fn getRewardsAndPenalties(
    comptime fork: ForkSeq,
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *BeaconState(fork),
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
        test_state.cached_state.epoch_cache,
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
        null,
    );
}
