const state_transition = @import("state_transition");
const TestRunner = @import("./test_runner.zig").TestRunner;

test "processPendingDeposits - sanity" {
    try TestRunner(state_transition.processPendingDeposits, .{
        // .no_alloc = false,
        .alloc = true,
        // .no_err_return = false,
        .err_return = true,
        // .no_void_return = false,
        .void_return = true,
    }).testProcessEpochFn();
    defer state_transition.deinitStateTransition();
}
