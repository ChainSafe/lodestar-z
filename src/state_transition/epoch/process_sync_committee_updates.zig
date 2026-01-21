const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const preset = @import("preset").preset;
const getNextSyncCommittee = @import("../utils/sync_committee.zig").getNextSyncCommittee;
const SyncCommitteeInfo = @import("../utils/sync_committee.zig").SyncCommitteeInfo;

pub fn processSyncCommitteeUpdates(allocator: Allocator, cached_state: *CachedBeaconState) !void {
    const state = cached_state.state;
    const epoch_cache = cached_state.getEpochCache();
    const next_epoch = epoch_cache.epoch + 1;
    if (next_epoch % preset.EPOCHS_PER_SYNC_COMMITTEE_PERIOD == 0) {
        const active_validator_indices = epoch_cache.getNextEpochShuffling().active_indices;
        const effective_balance_increments = epoch_cache.getEffectiveBalanceIncrements();

        // Compute next
        var next_sync_committee_info: SyncCommitteeInfo = undefined;
        try getNextSyncCommittee(allocator, state, active_validator_indices, effective_balance_increments, &next_sync_committee_info);

        // Rotate syncCommittee in state
        try state.rotateSyncCommittees(&next_sync_committee_info.sync_committee);

        // Rotate syncCommittee cache
        // next_sync_committee_indices ownership is transferred to epoch_cache
        try epoch_cache.rotateSyncCommitteeIndexed(allocator, &next_sync_committee_info.indices);
    }
}
