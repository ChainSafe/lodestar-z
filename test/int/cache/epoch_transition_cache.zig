const std = @import("std");
const Allocator = std.mem.Allocator;
const state_transition = @import("state_transition");
const TestCachedBeaconStateAllForks = state_transition.test_utils.TestCachedBeaconStateAllForks;
const ReusedEpochTransitionCache = state_transition.ReusedEpochTransitionCache;
const EpochTransitionCache = state_transition.EpochTransitionCache;

test "EpochTransitionCache.beforeProcessEpoch" {
    const allocator = std.testing.allocator;
    const validator_count_arr = &.{ 256, 10_000 };

    inline for (validator_count_arr) |validator_count| {
        var test_state = try TestCachedBeaconStateAllForks.init(allocator, validator_count);
        defer test_state.deinit();

        var epoch_transition_cache = try EpochTransitionCache.init(allocator, test_state.cached_state);
        defer {
            epoch_transition_cache.deinit();
            allocator.destroy(epoch_transition_cache);
        }
    }

    defer state_transition.deinitStateTransition();
}
