const state_transition = @import("state_transition");
const TestRunner = @import("./test_runner.zig").TestRunner;

test "processSlashings - sanity" {
    try TestRunner(state_transition.processSlashings, .{
        .alloc = true,
        .err_return = true,
        .void_return = true,
    }).testProcessEpochFn();
    defer state_transition.deinitStateTransition();
}
