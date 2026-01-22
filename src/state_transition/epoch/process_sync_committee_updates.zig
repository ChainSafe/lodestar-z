const std = @import("std");
const Allocator = std.mem.Allocator;
const ForkSeq = @import("config").ForkSeq;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const preset = @import("preset").preset;
const getNextSyncCommittee = @import("../utils/sync_committee.zig").getNextSyncCommittee;
const SyncCommitteeInfo = @import("../utils/sync_committee.zig").SyncCommitteeInfo;

pub fn processSyncCommitteeUpdates(
    comptime fork: ForkSeq,
    allocator: Allocator,
    epoch_cache: *EpochCache,
    state: *ForkBeaconState(fork),
) !void {
    const next_epoch = epoch_cache.epoch + 1;
    if (next_epoch % preset.EPOCHS_PER_SYNC_COMMITTEE_PERIOD == 0) {
        const active_validator_indices = epoch_cache.getNextEpochShuffling().active_indices;
        const effective_balance_increments = epoch_cache.getEffectiveBalanceIncrements();

        // Compute next
        var next_sync_committee_info: SyncCommitteeInfo = undefined;
        try getNextSyncCommittee(fork, allocator, state, active_validator_indices, effective_balance_increments, &next_sync_committee_info);

        // Rotate syncCommittee in state
        try state.rotateSyncCommittees(&next_sync_committee_info.sync_committee);

        // Rotate syncCommittee cache
        // next_sync_committee_indices ownership is transferred to epoch_cache
        try epoch_cache.rotateSyncCommitteeIndexed(allocator, &next_sync_committee_info.indices);
    }
}

const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;

test "processSyncCommitteeUpdates - sanity" {
    const allocator = std.testing.allocator;

    var test_state = try TestCachedBeaconState.init(allocator, 10_000);
    defer test_state.deinit();

    try processSyncCommitteeUpdates(
        .electra,
        allocator,
        test_state.cached_state.getEpochCache(),
        test_state.cached_state.state.castToFork(.electra),
    );
}
