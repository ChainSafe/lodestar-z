const std = @import("std");
const ct = @import("consensus_types");
const preset = @import("preset").preset;
const BeaconStateAllForks = @import("../types/beacon_state.zig").BeaconStateAllForks;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const ForkSeq = @import("config").ForkSeq;
const decreaseBalance = @import("../utils//balance.zig").decreaseBalance;
const EFFECTIVE_BALANCE_INCREMENT = preset.EFFECTIVE_BALANCE_INCREMENT;
const PROPORTIONAL_SLASHING_MULTIPLIER = preset.PROPORTIONAL_SLASHING_MULTIPLIER;
const PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR = preset.PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR;
const PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX = preset.PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX;

/// TODO: consider returning number[] when we switch to TreeView
pub fn processSlashings(
    allocator: std.mem.Allocator,
    cached_state: *CachedBeaconStateAllForks,
    cache: *const EpochTransitionCache,
) !void {
    // Return early if there no index to slash
    if (cache.indices_to_slash.items.len == 0) {
        return;
    }
    const config = cached_state.config;
    const epoch_cache = cached_state.getEpochCache();
    const state = cached_state.state;

    const total_balance_by_increment = cache.total_active_stake_by_increment;
    const fork = config.forkSeq(state.slot());
    const proportional_slashing_multiplier: u64 =
        if (fork == ForkSeq.phase0) PROPORTIONAL_SLASHING_MULTIPLIER else if (fork == ForkSeq.altair)
            PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR
        else
            PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX;

    const effective_balance_increments = epoch_cache.getEffectiveBalanceIncrements().items;
    const adjusted_total_slashing_balance_by_increment = @min(getTotalSlashingsByIncrement(state) * proportional_slashing_multiplier, total_balance_by_increment);
    const increment = EFFECTIVE_BALANCE_INCREMENT;

    const penalty_per_effective_balance_increment = @divFloor((adjusted_total_slashing_balance_by_increment * increment), total_balance_by_increment);

    var penalties_by_effective_balance_increment = std.AutoHashMap(u64, u64).init(allocator);
    defer penalties_by_effective_balance_increment.deinit();

    for (cache.indices_to_slash.items) |index| {
        const effective_balance_increment = effective_balance_increments[index];
        const penalty: u64 = if (penalties_by_effective_balance_increment.get(effective_balance_increment)) |penalty| penalty else blk: {
            const p = if (fork.isPostElectra())
                penalty_per_effective_balance_increment * effective_balance_increment
            else
                @divFloor(effective_balance_increment * adjusted_total_slashing_balance_by_increment, total_balance_by_increment) * increment;
            try penalties_by_effective_balance_increment.put(effective_balance_increment, p);
            break :blk p;
        };
        decreaseBalance(state, index, penalty);
    }
}

pub fn getTotalSlashingsByIncrement(state: *const BeaconStateAllForks) u64 {
    var total_slashings_by_increment: u64 = 0;
    const count = state.slashings().len;

    for (0..count) |i| {
        const slashing = state.slashings()[i];
        total_slashings_by_increment += @divFloor(slashing, preset.EFFECTIVE_BALANCE_INCREMENT);
    }

    return total_slashings_by_increment;
}
