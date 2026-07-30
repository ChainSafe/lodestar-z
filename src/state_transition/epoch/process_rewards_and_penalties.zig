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
    cache: *EpochTransitionCache,
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
    errdefer allocator.free(balances);
    const new_balances: std.ArrayList(u64) = .fromOwnedSlice(balances);

    if (slashing_penalties) |slashings| {
        for (rewards, penalties, balances, 0..) |reward, penalty, *balance, i| {
            const slashing: u64 = if (i < slashings.len) slashings[i] else 0;
            balance.* = (try std.math.add(u64, balance.*, reward)) -| penalty -| slashing;
        }
    } else {
        for (rewards, penalties, balances) |reward, penalty, *balance| {
            balance.* = (try std.math.add(u64, balance.*, reward)) -| penalty;
        }
    }

    // The state tree copies the values, so the source allocation can move into the cache.
    try state.setBalances(&new_balances);

    if (cache.balances) |*old_balances| {
        old_balances.deinit(allocator);
    }
    cache.balances = new_balances;
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

test "processRewardsAndPenalties replaces cached balances without leaking" {
    const allocator = std.testing.allocator;
    const pool_size = 10_000 * 5;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = pool_size });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 10_000);
    defer test_state.deinit();

    var allocation_tracker = std.testing.FailingAllocator.init(allocator, .{});
    const tracking_allocator = allocation_tracker.allocator();
    defer {
        if (test_state.epoch_transition_cache.balances) |*balances| {
            balances.deinit(tracking_allocator);
            test_state.epoch_transition_cache.balances = null;
        }
    }

    try processRewardsAndPenalties(
        .electra,
        tracking_allocator,
        test_state.cached_state.config,
        test_state.cached_state.epoch_cache,
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
        null,
    );
    const outstanding_bytes = allocation_tracker.allocated_bytes - allocation_tracker.freed_bytes;
    try std.testing.expect(outstanding_bytes > 0);

    try processRewardsAndPenalties(
        .electra,
        tracking_allocator,
        test_state.cached_state.config,
        test_state.cached_state.epoch_cache,
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
        null,
    );
    try std.testing.expectEqual(
        outstanding_bytes,
        allocation_tracker.allocated_bytes - allocation_tracker.freed_bytes,
    );

    if (test_state.epoch_transition_cache.balances) |*balances| {
        balances.deinit(tracking_allocator);
        test_state.epoch_transition_cache.balances = null;
    }
    try std.testing.expectEqual(allocation_tracker.allocated_bytes, allocation_tracker.freed_bytes);
}
