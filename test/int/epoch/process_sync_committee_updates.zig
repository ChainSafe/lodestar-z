const std = @import("std");
const Allocator = std.mem.Allocator;
const TestCachedBeaconStateAllForks = state_transition.test_utils.TestCachedBeaconStateAllForks;
const state_transition = @import("state_transition");
const EpochTransitionCache = state_transition.EpochTransitionCache;
const processSyncCommitteeUpdates = state_transition.processSyncCommitteeUpdates;
// this function runs without EpochTransionCache so cannot use getTestProcessFn

test "processSyncCommitteeUpdates - sanity" {
    const allocator = std.testing.allocator;
    const validator_count_arr = &.{ 256, 10_000 };

    inline for (validator_count_arr) |validator_count| {
        var test_state = try TestCachedBeaconStateAllForks.init(allocator, validator_count);
        defer test_state.deinit();
        try processSyncCommitteeUpdates(allocator, test_state.cached_state);
    }
    defer state_transition.deinitStateTransition();
}
