const std = @import("std");
const testing = std.testing;

/// Utils that could be used for different kinds of tests like int, perf
pub const TestCachedBeaconState = @import("./generate_state.zig").TestCachedBeaconState;
pub const generateElectraBlock = @import("./generate_block.zig").generateElectraBlock;
pub const interopSign = @import("./interop_pubkeys.zig").interopSign;

/// Normally set in preset. Mock a small value for testing.
pub const EFFECTIVE_BALANCE_INCREMENT = 32;

test {
    testing.refAllDecls(@This());
}
