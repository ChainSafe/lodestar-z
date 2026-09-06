const std = @import("std");

pub fn uint(comptime T: type, data: []const u8) T {
    std.debug.assert(data.len == @sizeOf(T));
    var value: T = 0;
    for (data, 0..) |byte, i| value |= @as(T, byte) << @intCast(i * 8);
    return value;
}

pub fn bitLength(data: []const u8, limit: usize) ?usize {
    if (data.len == 0) return null;
    const last = data[data.len - 1];
    if (last == 0) return null;

    var sentinel: usize = 0;
    for (0..8) |index| {
        if (last & (@as(u8, 1) << @intCast(index)) != 0) sentinel = index;
    }
    const bit_len = (data.len - 1) * 8 + sentinel;
    return if (bit_len <= limit) bit_len else null;
}

pub fn bit(data: []const u8, index: usize) bool {
    return data[index / 8] & (@as(u8, 1) << @intCast(index % 8)) != 0;
}
