const types = @import("consensus_types");
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const decreaseBalance = @import("../utils/balance.zig").decreaseBalance;
const increaseBalance = @import("../utils/balance.zig").increaseBalance;

/// also modify balances inside EpochTransitionCache
pub fn processPendingConsolidations(cached_state: *CachedBeaconState, cache: *EpochTransitionCache) !void {
    const epoch_cache = cached_state.getEpochCache();
    var state = &cached_state.state;
    const next_epoch = epoch_cache.epoch + 1;

    var validators = try state.validators();
    var balances = try state.balances();
    var pending_consolidations = try state.pendingConsolidations();
    const pending_consolidations_length = try pending_consolidations.length();

    var processed: usize = 0;
    while (processed < pending_consolidations_length) : (processed += 1) {
        const pending_consolidation = try pending_consolidations.get(processed);
        const source_index = try pending_consolidation.get("source_index");
        const target_index = try pending_consolidation.get("target_index");

        var source_validator = try validators.get(@intCast(source_index));
        const slashed = try source_validator.get("slashed");
        if (slashed) {
            continue;
        }

        const withdrawable_epoch = try source_validator.get("withdrawable_epoch");
        if (withdrawable_epoch > next_epoch) {
            break;
        }

        const source_balance = try balances.get(@intCast(source_index));
        const source_effective_balance = @min(source_balance, try source_validator.get("effective_balance"));

        try decreaseBalance(state, source_index, source_effective_balance);
        try increaseBalance(state, target_index, source_effective_balance);
        if (cache.balances) |cached_balances| {
            cached_balances.items[@intCast(source_index)] -= source_effective_balance;
            cached_balances.items[@intCast(target_index)] += source_effective_balance;
        }
    }

    if (processed > 0) {
        const truncated = try pending_consolidations.sliceFrom(processed);
        try state.setPendingConsolidations(truncated);
    }
}
