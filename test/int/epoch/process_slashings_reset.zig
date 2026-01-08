const std = @import("std");
const Allocator = std.mem.Allocator;
const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
const state_transition = @import("state_transition");
const ReusedEpochTransitionCache = state_transition.ReusedEpochTransitionCache;
const EpochTransitionCache = state_transition.EpochTransitionCache;
const TestRunner = @import("./test_runner.zig").TestRunner;

test "processSlashingsReset - sanity" {
    try TestRunner(state_transition.processSlashingsReset, .{
        .alloc = false,
        .err_return = false,
        .void_return = true,
    }).testProcessEpochFn();
    defer state_transition.deinitStateTransition();
}
