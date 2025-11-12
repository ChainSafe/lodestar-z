const std = @import("std");
const Allocator = std.mem.Allocator;
const state_transition = @import("state_transition");
const TestCachedBeaconStateAllForks = state_transition.test_utils.TestCachedBeaconStateAllForks;
const EpochTransitionCache = state_transition.EpochTransitionCache;
const processParticipationFlagUpdates = state_transition.processParticipationFlagUpdates;
// this function runs without EpochTransionCache so cannot use getTestProcessFn

test "processParticipationFlagUpdates - sanity" {
    const allocator = std.testing.allocator;
    const validator_count_arr = &.{ 256, 10_000 };

    inline for (validator_count_arr) |validator_count| {
        var test_state = try TestCachedBeaconStateAllForks.init(allocator, validator_count);
        defer test_state.deinit();
        try processParticipationFlagUpdates(test_state.cached_state, allocator);
    }
    defer state_transition.deinitStateTransition();
}
