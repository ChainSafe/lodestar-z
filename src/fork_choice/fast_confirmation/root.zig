const std = @import("std");
const testing = std.testing;

pub const fast_confirmation = @import("fast_confirmation.zig");

pub const FastConfirmation = fast_confirmation.FastConfirmation;
pub const BalanceSourceData = fast_confirmation.BalanceSourceData;
pub const SlotAssignments = fast_confirmation.SlotAssignments;
pub const Error = fast_confirmation.Error;

test {
    testing.refAllDecls(@This());
}
