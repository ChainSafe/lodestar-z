const ForkSeq = @import("config").ForkSeq;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const decreaseBalance = @import("../utils/balance.zig").decreaseBalance;
const increaseBalance = @import("../utils/balance.zig").increaseBalance;

/// also modify balances inside EpochTransitionCache
pub fn processPendingConsolidations(
    comptime fork: ForkSeq,
    epoch_cache: *const EpochCache,
    state: *ForkBeaconState(fork),
    cache: *EpochTransitionCache,
) !void {
    const next_epoch = epoch_cache.epoch + 1;
    var next_pending_consolidation: usize = 0;
    var validators = try state.validators();
    var balances = try state.balances();

    var pending_consolidations = try state.pendingConsolidations();
    var pending_consolidations_it = pending_consolidations.iteratorReadonly(0);
    const pending_consolidations_length = try pending_consolidations.length();
    for (0..pending_consolidations_length) |_| {
        const pending_consolidation = try pending_consolidations_it.nextValue(undefined);
        const source_index = pending_consolidation.source_index;
        const target_index = pending_consolidation.target_index;
        var source_validator = try validators.get(source_index);

        if (try source_validator.get("slashed")) {
            next_pending_consolidation += 1;
            continue;
        }

        if ((try source_validator.get("withdrawable_epoch")) > next_epoch) {
            break;
        }

        // Calculate the consolidated balance
        const source_effective_balance = @min(try balances.get(source_index), try source_validator.get("effective_balance"));

        // Move active balance to target. Excess balance is withdrawable.
        try decreaseBalance(fork, state, source_index, source_effective_balance);
        try increaseBalance(fork, state, target_index, source_effective_balance);
        if (cache.balances) |cached_balances| {
            cached_balances.items[source_index] -= source_effective_balance;
            cached_balances.items[target_index] += source_effective_balance;
        }

        next_pending_consolidation += 1;
    }

    if (next_pending_consolidation > 0) {
        const new_pending_consolidations = try pending_consolidations.sliceFrom(next_pending_consolidation);
        try state.setPendingConsolidations(new_pending_consolidations);
    }
}

const std = @import("std");
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const Node = @import("persistent_merkle_tree").Node;

test "processPendingConsolidations - sanity" {
    const allocator = std.testing.allocator;
    const pool_size = 10_000 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 10_000);
    defer test_state.deinit();

    try processPendingConsolidations(
        .electra,
        test_state.cached_state.getEpochCache(),
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
    );
}
