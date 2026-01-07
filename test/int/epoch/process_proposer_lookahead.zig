const std = @import("std");
const state_transition = @import("state_transition");
const TestRunner = @import("./test_runner.zig").TestRunner;

test "processProposerLookahead sanity" {
    try TestRunner(state_transition.processProposerLookahead, .{
        .alloc = true,
        .err_return = true,
        .void_return = true,
        .fulu = true,
    }).testProcessEpochFn();
    defer state_transition.deinitStateTransition();
}
