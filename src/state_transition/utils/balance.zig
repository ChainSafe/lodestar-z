const std = @import("std");
const BeaconState = @import("../types/beacon_state.zig").BeaconState;
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
