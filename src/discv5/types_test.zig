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

test "XOR closeness compares the complete distance" {
    const target = [_]u8{0xff} ** 32;
    const closest = [_]u8{0xff} ** 31 ++ [_]u8{0xfe};
    const farther = [_]u8{0xff} ** 31 ++ [_]u8{0xfc};
    try std.testing.expect(types.xorCloser(&closest, &farther, &target));
    try std.testing.expect(!types.xorCloser(&farther, &closest, &target));
    try std.testing.expect(!types.xorCloser(&closest, &closest, &target));
}

test "relay policy does not cross special address scopes" {
    const public = address4(203, 0, 113, 1);
    const other_public = address4(198, 51, 100, 1);
    const private = address4(10, 0, 0, 1);
    const other_private = address4(192, 168, 1, 1);
    const loopback = address4(127, 0, 0, 1);
    const unspecified = address4(0, 0, 0, 0);
    try std.testing.expect(types.relayAllowed(public, other_public));
    try std.testing.expect(!types.relayAllowed(public, private));
    try std.testing.expect(types.relayAllowed(private, other_private));
    try std.testing.expect(types.relayAllowed(loopback, loopback));
    try std.testing.expect(!types.relayAllowed(private, loopback));
    try std.testing.expect(!types.relayAllowed(public, unspecified));

    const public6 = address6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
    const private6 = address6(.{ 0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
    const other_private6 = address6(.{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 });
    const multicast6 = address6(.{ 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
    try std.testing.expect(!types.relayAllowed(public6, private6));
    try std.testing.expect(types.relayAllowed(private6, other_private6));
    try std.testing.expect(!types.relayAllowed(private, private6));
    try std.testing.expect(!types.relayAllowed(public6, multicast6));
}

fn address4(a: u8, b: u8, c: u8, d: u8) types.Address {
    return .{ .ip4 = .{ .octets = .{ a, b, c, d }, .port = 9_000 } };
}

fn address6(octets: [16]u8) types.Address {
    return .{ .ip6 = .{ .octets = octets, .port = 9_000 } };
}
