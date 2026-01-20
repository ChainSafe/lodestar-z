const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconState = @import("../types/beacon_state.zig").BeaconState;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const EffectiveBalanceIncrements = @import("../cache/effective_balance_increments.zig").EffectiveBalanceIncrements;
const types = @import("consensus_types");
const ValidatorIndex = types.primitive.ValidatorIndex.Type;

/// Increase the balance for a validator with the given ``index`` by ``delta``.
pub fn increaseBalance(state: *BeaconState, index: ValidatorIndex, delta: u64) !void {
    var balances = try state.balances();
    const current = try balances.get(index);
    const next = try std.math.add(u64, current, delta);
    try balances.set(index, next);
}

/// Decrease the balance for a validator with the given ``index`` by ``delta``.
/// Set to 0 when underflow.
pub fn decreaseBalance(state: *BeaconState, index: ValidatorIndex, delta: u64) !void {
    var balances = try state.balances();
    const current = try balances.get(index);
    const next = if (current > delta) current - delta else 0;
    try balances.set(index, next);
}

pub fn getEffectiveBalanceIncrementsZeroInactive(allocator: Allocator, cached_state: *CachedBeaconState) !EffectiveBalanceIncrements {
    const active_indices = cached_state.getEpochCache().getCurrentShuffling().active_indices;
    // 5x faster than reading from state.validators, with validator Nodes as values
    const validators = try cached_state.state.validatorsSlice(allocator);
    defer allocator.free(validators);
    const validator_count = validators.len;
    const effective_balance_increments = cached_state.getEpochCache().getEffectiveBalanceIncrements();
    // Slice up to `validatorCount` since it won't be mutated, nor accessed beyond `validatorCount`
    var effective_balance_increments_zero_inactive = try EffectiveBalanceIncrements.initCapacity(allocator, validator_count);
    try effective_balance_increments_zero_inactive.appendSlice(effective_balance_increments.items[0..validator_count]);

    var j: usize = 0;
    for (validators, 0..) |validator, i| {
        const slashed = validator.slashed;
        if (j < active_indices.len and i == active_indices[j]) {
            // active validator
            j += 1;
            if (slashed) {
                // slashed validator
                effective_balance_increments_zero_inactive.items[i] = 0;
            }
        } else {
            // inactive validator
            effective_balance_increments_zero_inactive.items[i] = 0;
        }
    }

    return effective_balance_increments_zero_inactive;
}
