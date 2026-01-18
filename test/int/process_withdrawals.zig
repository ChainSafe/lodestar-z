const Node = @import("persistent_merkle_tree").Node;

test "process withdrawals - sanity" {
    const allocator = std.testing.allocator;

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();
    var withdrawals_result = WithdrawalsResult{
        .withdrawals = try Withdrawals.initCapacity(
            allocator,
            preset.MAX_WITHDRAWALS_PER_PAYLOAD,
        ),
    };
    defer withdrawals_result.withdrawals.deinit(allocator);
    var withdrawal_balances = std.AutoHashMap(ValidatorIndex, usize).init(allocator);
    defer withdrawal_balances.deinit();

    var root: Root = undefined;
    try types.capella.Withdrawals.hashTreeRoot(allocator, &withdrawals_result.withdrawals, &root);

    try getExpectedWithdrawals(allocator, &withdrawals_result, &withdrawal_balances, test_state.cached_state);
    try processWithdrawals(allocator, test_state.cached_state, withdrawals_result, root);
}

const std = @import("std");
const state_transition = @import("state_transition");
const preset = @import("preset").preset;
const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
const processWithdrawals = state_transition.processWithdrawals;
const getExpectedWithdrawals = state_transition.getExpectedWithdrawals;
const WithdrawalsResult = state_transition.WithdrawalsResult;
const types = @import("consensus_types");
const Root = types.primitive.Root.Type;
const Withdrawals = types.capella.Withdrawals.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
