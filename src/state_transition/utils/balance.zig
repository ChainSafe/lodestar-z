const BeaconStateAllForks = @import("../types/beacon_state.zig").BeaconStateAllForks;
const types = @import("consensus_types");
const ValidatorIndex = types.primitive.ValidatorIndex.Type;

/// Increase the balance for a validator with the given ``index`` by ``delta``.
pub fn increaseBalance(state: *BeaconStateAllForks, index: ValidatorIndex, delta: u64) void {
    const balance = &state.balances().items[index];
    balance.* = state.balances().items[index] + delta;
}

/// Decrease the balance for a validator with the given ``index`` by ``delta``.
/// Set to 0 when underflow.
pub fn decreaseBalance(state: *BeaconStateAllForks, index: ValidatorIndex, delta: u64) void {
    const balance = &state.balances().items[index];
    const new_balance = if (balance.* > delta) balance.* - delta else 0;
    balance.* = @max(0, new_balance);
}
