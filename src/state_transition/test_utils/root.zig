const std = @import("std");
const testing = std.testing;

/// Utils that could be used for different kinds of tests like int, perf
pub const TestCachedBeaconStateAllForks = @import("./generate_state.zig").TestCachedBeaconStateAllForks;
pub const generateElectraBlock = @import("./generate_block.zig").generateElectraBlock;
pub const generateElectraBlindedBlock = @import("./generate_block.zig").generateElectraBlindedBlock;
pub const interopSign = @import("./interop_pubkeys.zig").interopSign;

test {
    testing.refAllDecls(@This());
}
