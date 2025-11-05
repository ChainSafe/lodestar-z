const std = @import("std");
const ct = @import("consensus_types");
const Allocator = std.mem.Allocator;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const ForkSeq = @import("config").ForkSeq;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const decreaseBalance = @import("../utils/balance.zig").decreaseBalance;
const increaseBalance = @import("../utils/balance.zig").increaseBalance;

/// also modify balances inside EpochTransitionCache
pub fn processPendingConsolidations(allocator: Allocator, cached_state: *CachedBeaconStateAllForks, cache: *EpochTransitionCache) !void {
    const epoch_cache = cached_state.getEpochCache();
    const state = cached_state.state;
    const next_epoch = epoch_cache.epoch + 1;
    var next_pending_consolidation: usize = 0;
    const validators = state.validators();

    var chunk_start_index: usize = 0;
    const chunk_size = 100;
    const pending_consolidations = state.pendingConsolidations();
    const pending_consolidations_length = pending_consolidations.items.len;
    outer: while (chunk_start_index < pending_consolidations_length) : (chunk_start_index += chunk_size) {
        // TODO(ssz): implement getReadonlyByRange api for TreeView
        const consolidation_chunk = state.pendingConsolidations().items[chunk_start_index..@min(chunk_start_index + chunk_size, pending_consolidations_length)];
        for (consolidation_chunk) |pending_consolidation| {
            const source_index = pending_consolidation.source_index;
            const target_index = pending_consolidation.target_index;
            const source_validator = validators.items[source_index];

            if (source_validator.slashed) {
                next_pending_consolidation += 1;
                continue;
            }

            if (source_validator.withdrawable_epoch > next_epoch) {
                break :outer;
            }

            // Calculate the consolidated balance
            const source_effective_balance = @min(state.balances().items[source_index], source_validator.effective_balance);

            // Move active balance to target. Excess balance is withdrawable.
            decreaseBalance(state, source_index, source_effective_balance);
            increaseBalance(state, target_index, source_effective_balance);
            if (cache.balances) |cached_balances| {
                cached_balances.items[source_index] -= source_effective_balance;
                cached_balances.items[target_index] += source_effective_balance;
            }

            next_pending_consolidation += 1;
        }
    }

    if (next_pending_consolidation > 0) {
        const new_len = pending_consolidations.items.len - next_pending_consolidation;

        std.mem.copyForwards(
            ct.electra.PendingConsolidation.Type,
            pending_consolidations.items[0..new_len],
            pending_consolidations.items[next_pending_consolidation .. next_pending_consolidation + new_len],
        );

        try pending_consolidations.resize(allocator, new_len);
    }
}
