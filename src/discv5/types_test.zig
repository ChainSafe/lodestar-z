const std = @import("std");
const types = @import("types.zig");

test "log distance covers the complete node ID range" {
    const zero = [_]u8{0} ** 32;
    const far = [_]u8{0x80} ++ ([_]u8{0} ** 31);
    const near = ([_]u8{0} ** 31) ++ [_]u8{1};
    try std.testing.expectEqual(@as(u16, 0), types.logDistance(&zero, &zero));
    try std.testing.expectEqual(@as(u16, 256), types.logDistance(&zero, &far));
    try std.testing.expectEqual(@as(u16, 1), types.logDistance(&zero, &near));
}
