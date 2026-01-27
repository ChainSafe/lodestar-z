// Root file to run only state_transition/types tests.
//
// This exists because `zig test` compiles the entire root module before applying
// `--test-filter`. Keeping a small root lets us iterate on a subset without
// fixing unrelated compilation errors across the whole state_transition module.

test "state_transition types" {
    _ = @import("types/beacon_state.zig");
    _ = @import("types/execution_payload.zig");
}
