const std = @import("std");
const fmt = std.fmt;
const testing = std.testing;

/// Utils that could be used for different kinds of tests like int, perf
pub const TestCachedBeaconStateAllForks = @import("./generate_state.zig").TestCachedBeaconStateAllForks;
pub const generateElectraBlock = @import("./generate_block.zig").generateElectraBlock;

/// Convert hex to bytes with 0x-prefix support
pub fn hexToBytes(out: []u8, input: []const u8) ![]u8 {
    if (input[0] == '0' and input[1] == 'x') {
        return try fmt.hexToBytes(out, input[2..]);
    } else {
        return try fmt.hexToBytes(out, input);
    }
}

pub fn hexToRoot(input: *const [66]u8) ![32]u8 {
    var out: [32]u8 = undefined;
    _ = try hexToBytes(&out, input);
    return out;
}

test {
    testing.refAllDecls(@This());
}
