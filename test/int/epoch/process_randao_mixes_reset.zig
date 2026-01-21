const state_transition = @import("state_transition");
const TestRunner = @import("./test_runner.zig").TestRunner;

test "processRandaoMixesReset - sanity" {
    try TestRunner(
        state_transition.processRandaoMixesReset,
        .{
            .alloc = false,
            .err_return = true,
            .void_return = true,
        },
    ).testProcessEpochFn();
    defer state_transition.deinitStateTransition();
}
