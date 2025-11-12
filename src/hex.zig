const std = @import("std");
const fmt = std.fmt;

pub fn hexToBytesComptime(comptime n: usize, comptime input: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = hexToBytes(out[0..], input) catch unreachable;
    return out;
}

/// Convert hex to bytes with 0x-prefix support
pub fn hexToBytes(out: []u8, input: []const u8) ![]u8 {
    if (hasOxPrefix(input)) {
        return try fmt.hexToBytes(out, input[2..]);
    } else {
        return try fmt.hexToBytes(out, input);
    }
}

/// Convert bytes to hex with 0x-prefix
pub fn bytesToHex(out: []u8, input: []const u8) ![]u8 {
    return try fmt.bufPrint(out, "0x{x}", .{fmt.fmtSliceHexLower(input)});
}

pub fn hexToRoot(input: *const [66]u8) ![32]u8 {
    var out: [32]u8 = undefined;
    _ = try hexToBytes(&out, input);
    return out;
}

pub fn hexIntoRoot(out: *[32]u8, input: *const [66]u8) !void {
    _ = try hexToBytes(out, input);
}

pub fn rootToHex(input: *const [32]u8) ![66]u8 {
    var out: [66]u8 = undefined;
    _ = try bytesToHex(&out, input);
    return out;
}

pub fn rootIntoHex(out: *[66]u8, input: *const [32]u8) !void {
    _ = try bytesToHex(out, input);
}

pub fn hasOxPrefix(hex: []const u8) bool {
    return hex[0] == '0' and hex[1] == 'x';
}

pub fn hexByteLen(hex: []const u8) usize {
    return if (hasOxPrefix(hex)) (hex.len - 2) / 2 else hex.len / 2;
}

pub fn hexLenFromBytes(bytes: []const u8) usize {
    return 2 + bytes.len * 2;
}

test "rootToHex" {
    const TestCase = struct {
        root: *const [32]u8,
        expected: []const u8,
    };

    const test_cases = [_]TestCase{
        TestCase{ .root = &[_]u8{0} ** 32, .expected = "0x0000000000000000000000000000000000000000000000000000000000000000" },
        TestCase{ .root = &[_]u8{10} ** 32, .expected = "0x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a" },
        TestCase{ .root = &[_]u8{17} ** 32, .expected = "0x1111111111111111111111111111111111111111111111111111111111111111" },
        TestCase{ .root = &[_]u8{255} ** 32, .expected = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" },
    };

    for (test_cases) |tc| {
        const hex = try rootToHex(tc.root);
        try std.testing.expectEqualSlices(u8, tc.expected, &hex);
    }
}

test "hexToBytes" {
    const TestCase = struct {
        hex: []const u8,
        expected: []const u8,
    };

    const test_cases = [_]TestCase{
        TestCase{ .hex = "00000000", .expected = &[_]u8{ 0, 0, 0, 0 } },
        TestCase{ .hex = "c78009fd", .expected = &[_]u8{ 199, 128, 9, 253 } },
        TestCase{ .hex = "C78009FD", .expected = &[_]u8{ 199, 128, 9, 253 } },
        TestCase{ .hex = "0x00000000", .expected = &[_]u8{ 0, 0, 0, 0 } },
        TestCase{ .hex = "0xc78009fd", .expected = &[_]u8{ 199, 128, 9, 253 } },
        TestCase{ .hex = "0xC78009FD", .expected = &[_]u8{ 199, 128, 9, 253 } },
    };

    inline for (test_cases) |tc| {
        var out = [_]u8{0} ** tc.expected.len;
        _ = try hexToBytes(&out, tc.hex);
        try std.testing.expectEqualSlices(u8, tc.expected, &out);
    }
}
