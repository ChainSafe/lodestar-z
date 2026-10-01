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

test "IPv6 interface scope is part of endpoint identity" {
    const first = types.Address{ .ip6 = .{
        .octets = [_]u8{0x22} ** 16,
        .port = 9_001,
        .interface = 1,
    } };
    var second = first;
    second.ip6.interface = 2;
    try std.testing.expect(!std.meta.eql(first, second));
}

test "endpoint equality and subnet grouping preserve distinct identity policies" {
    const support = @import("test_support.zig");
    var left = support.fakeEndpoint(1, 9000);
    var right = left;
    try std.testing.expect(left.eql(&right));
    right.node_id[0] ^= 1;
    try std.testing.expect(!left.eql(&right));
    try std.testing.expect(types.sameSubnet(left.address, right.address));
    right = left;
    right.address.ip4.port += 1;
    right.address.ip4.octets[3] += 1;
    try std.testing.expect(!left.eql(&right));
    try std.testing.expect(types.sameSubnet(left.address, right.address));
    right.address.ip4.octets[2] += 1;
    try std.testing.expect(!types.sameSubnet(left.address, right.address));
    right.address = support.address6(@splat(0x20), 9000);
    try std.testing.expect(!types.sameSubnet(left.address, right.address));
    left.address = right.address;
    right.address.ip6.interface = 1;
    try std.testing.expect(!left.eql(&right));
    right.address.ip6.octets[8] += 1;
    try std.testing.expect(types.sameSubnet(left.address, right.address));
    right.address.ip6.octets[7] += 1;
    try std.testing.expect(!types.sameSubnet(left.address, right.address));
}
