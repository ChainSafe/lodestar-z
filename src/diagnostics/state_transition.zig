const std = @import("std");
const Diagnostics = @import("../diagnostics.zig").Diagnostics;

pub const ErrorDetails = union(enum) {
    withdrawals_root_mismatch: struct {
        expected: [32]u8,
        actual: [32]u8,
    },

    pub fn format(self: *const ErrorDetails, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.*) {
            .withdrawals_root_mismatch => |*mismatch| try writer.print(
                "WithdrawalsRootMismatch expected=0x{x} actual=0x{x}",
                .{ &mismatch.expected, &mismatch.actual },
            ),
        }
    }
};

pub fn withdrawalsRootMismatch(
    diagnostics: ?*Diagnostics,
    expected: *const [32]u8,
    actual: *const [32]u8,
) error{WithdrawalsRootMismatch} {
    if (diagnostics) |diag| {
        diag.detail = .{ .state_transition = .{ .withdrawals_root_mismatch = .{
            .expected = expected.*,
            .actual = actual.*,
        } } };
    }
    return error.WithdrawalsRootMismatch;
}
