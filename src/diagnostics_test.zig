const std = @import("std");
const Diagnostics = @import("diagnostics.zig").Diagnostics;
const state_transition = @import("diagnostics.zig").state_transition;

test "diagnostics should preserve the error and own its details" {
    var expected = [_]u8{0xab} ** 32;
    var actual = [_]u8{0xcd} ** 32;
    var diagnostics: Diagnostics = .{};
    try std.testing.expectEqual(
        error.WithdrawalsRootMismatch,
        state_transition.withdrawalsRootMismatch(&diagnostics, &expected, &actual),
    );
    try std.testing.expectEqual(
        error.WithdrawalsRootMismatch,
        state_transition.withdrawalsRootMismatch(null, &expected, &actual),
    );
    @memset(&expected, 0);
    @memset(&actual, 0);

    var output: [192]u8 = undefined;
    try std.testing.expectEqualStrings(
        "WithdrawalsRootMismatch expected=0x" ++
            ("ab" ** 32) ++
            " actual=0x" ++
            ("cd" ** 32),
        try std.fmt.bufPrint(&output, "{f}", .{&diagnostics.detail.?}),
    );
}
