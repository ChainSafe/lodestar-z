const state_transition = @import("state_transition");
const TestRunner = @import("./test_runner.zig").TestRunner;

test "processEffectiveBalanceUpdates - sanity" {
    try TestRunner(
        state_transition.processEffectiveBalanceUpdates,
        .{
            .alloc = true,
            .err_return = true,
            .void_return = false,
        },
    ).testProcessEpochFn();
    defer state_transition.deinitStateTransition();
}
