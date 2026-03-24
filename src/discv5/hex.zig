//! Hex utilities for discv5

const std = @import("std");

pub fn hexToBytesComptime(comptime n: usize, comptime input: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = hexToBytes(out[0..], input) catch unreachable;
    return out;
}

pub fn hexToBytes(out: []u8, input: []const u8) ![]u8 {
    const hex = if (std.mem.startsWith(u8, input, "0x")) input[2..] else input;
    return try std.fmt.hexToBytes(out, hex);
}
