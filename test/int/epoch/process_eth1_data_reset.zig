const state_transition = @import("state_transition");
const TestRunner = @import("./test_runner.zig").TestRunner;

test "processEth1DataReset - sanity" {
    try TestRunner(state_transition.processEth1DataReset, .{
        .alloc = false,
        .err_return = true,
        .void_return = true,
    }).testProcessEpochFn();
    defer state_transition.deinitStateTransition();
}
