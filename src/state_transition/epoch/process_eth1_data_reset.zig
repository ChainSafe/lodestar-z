const ForkSeq = @import("config").ForkSeq;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const EpochTransitionCache = @import("../cache/epoch_transition_cache.zig").EpochTransitionCache;
const preset = @import("preset").preset;
const EPOCHS_PER_ETH1_VOTING_PERIOD = preset.EPOCHS_PER_ETH1_VOTING_PERIOD;

/// Reset eth1DataVotes tree every `EPOCHS_PER_ETH1_VOTING_PERIOD`.
pub fn processEth1DataReset(
    comptime fork: ForkSeq,
    state: *ForkBeaconState(fork),
    cache: *const EpochTransitionCache,
) !void {
    const next_epoch = cache.current_epoch + 1;

    // reset eth1 data votes
    if (next_epoch % EPOCHS_PER_ETH1_VOTING_PERIOD == 0) {
        try state.resetEth1DataVotes();
    }
}

const std = @import("std");
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;

test "processEth1DataReset - sanity" {
    const allocator = std.testing.allocator;

    var test_state = try TestCachedBeaconState.init(allocator, 10_000);
    defer test_state.deinit();

    try processEth1DataReset(
        .electra,
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
    );
}
