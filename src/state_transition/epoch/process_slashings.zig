const std = @import("std");
const preset = @import("preset").preset;
const ForkSeq = @import("config").ForkSeq;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const decreaseBalance = @import("../utils//balance.zig").decreaseBalance;
const EFFECTIVE_BALANCE_INCREMENT = preset.EFFECTIVE_BALANCE_INCREMENT;
const PROPORTIONAL_SLASHING_MULTIPLIER = preset.PROPORTIONAL_SLASHING_MULTIPLIER;
const PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR = preset.PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR;
const PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX = preset.PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX;

/// TODO: consider returning number[] when we switch to TreeView
pub fn processSlashings(
    comptime fork: ForkSeq,
    allocator: std.mem.Allocator,
    epoch_cache: *const EpochCache,
    state: *ForkBeaconState(fork),
    cache: *const EpochTransitionCache,
) !void {
    // Return early if there no index to slash
    if (cache.indices_to_slash.items.len == 0) {
        return;
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
        try decreaseBalance(fork, state, index, penalty);
    }
}

pub fn getTotalSlashingsByIncrement(
    comptime fork: ForkSeq,
    state: *ForkBeaconState(fork),
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

test "processSlashings - sanity" {
    try @import("../test_utils/test_runner.zig").TestRunner(processSlashings, .{
        .alloc = true,
        .err_return = true,
        .void_return = true,
    }).testProcessEpochFn();
    defer @import("../state_transition.zig").deinitStateTransition();
}
