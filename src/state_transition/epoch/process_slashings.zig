const std = @import("std");
const preset = @import("preset").preset;
const ForkSeq = @import("config").ForkSeq;
const BeaconState = @import("fork_types").BeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const decreaseBalance = @import("../utils//balance.zig").decreaseBalance;
const EFFECTIVE_BALANCE_INCREMENT = preset.EFFECTIVE_BALANCE_INCREMENT;
const PROPORTIONAL_SLASHING_MULTIPLIER = preset.PROPORTIONAL_SLASHING_MULTIPLIER;
const PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR = preset.PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR;
const PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX = preset.PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX;
const Node = @import("persistent_merkle_tree").Node;

pub fn processSlashings(
    comptime fork: ForkSeq,
    allocator: std.mem.Allocator,
    epoch_cache: *const EpochCache,
    state: *BeaconState(fork),
    cache: *const EpochTransitionCache,
    update_balance: bool,
) ![]const u64 {
    const slashing_penalties = cache.slashing_penalties;
    const empty_penalties = &[_]u64{};
    if (!update_balance) {
        @memset(slashing_penalties, 0);
    }

    // Return early if there no index to slash
    if (cache.indices_to_slash.items.len == 0) {
        return if (update_balance) empty_penalties else slashing_penalties;
    }
    const total_balance_by_increment = cache.total_active_stake_by_increment;
    const proportional_slashing_multiplier: u64 =
        if (comptime fork == .phase0)
            PROPORTIONAL_SLASHING_MULTIPLIER
        else if (comptime fork == .altair)
            PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR
        else
            PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX;

    const effective_balance_increments = epoch_cache.getEffectiveBalanceIncrements().items;
    const adjusted_total_slashing_balance_by_increment = @min((try getTotalSlashingsByIncrement(fork, state)) * proportional_slashing_multiplier, total_balance_by_increment);
    const increment = EFFECTIVE_BALANCE_INCREMENT;

    const penalty_per_effective_balance_increment = @divFloor((adjusted_total_slashing_balance_by_increment * increment), total_balance_by_increment);

    var penalties_by_effective_balance_increment = std.AutoHashMap(u64, u64).init(allocator);
    defer penalties_by_effective_balance_increment.deinit();

    for (cache.indices_to_slash.items) |index| {
        const effective_balance_increment = effective_balance_increments[index];
        const penalty: u64 = if (penalties_by_effective_balance_increment.get(effective_balance_increment)) |penalty| penalty else blk: {
            const p = if (comptime fork.gte(.electra))
                penalty_per_effective_balance_increment * effective_balance_increment
            else
                @divFloor(effective_balance_increment * adjusted_total_slashing_balance_by_increment, total_balance_by_increment) * increment;
            try penalties_by_effective_balance_increment.put(effective_balance_increment, p);
            break :blk p;
        };
        if (update_balance) {
            try decreaseBalance(fork, state, index, penalty);
        } else {
            slashing_penalties[index] = penalty;
        }
    }

    return if (update_balance) empty_penalties else slashing_penalties;
}

pub fn getTotalSlashingsByIncrement(
    comptime fork: ForkSeq,
    state: *BeaconState(fork),
) !u64 {
    var total_slashings_by_increment: u64 = 0;
    var slashings = try state.slashings();
    const slashings_len = @TypeOf(slashings).length;
    for (0..slashings_len) |i| {
        const slashing = try slashings.get(i);
        total_slashings_by_increment += @divFloor(slashing, preset.EFFECTIVE_BALANCE_INCREMENT);
    }

    return total_slashings_by_increment;
}

const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;

test "processSlashings - sanity" {
    const allocator = std.testing.allocator;
    const pool_size = 10_000 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 10_000);
    defer test_state.deinit();

    _ = try processSlashings(
        .electra,
        allocator,
        test_state.cached_state.getEpochCache(),
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
        true,
    );
}
