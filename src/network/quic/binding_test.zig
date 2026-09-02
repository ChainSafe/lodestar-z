const std = @import("std");
const binding = @import("binding.zig");
const constants = @import("../constants.zig");

test "quiche config initializes with the transport bounds" {
    var config = try binding.Config.init(constants.idle_timeout_ms);
    defer config.deinit();
    try std.testing.expect(binding.versionSupported(1));
    try std.testing.expect(!binding.versionSupported(0xdead_beef));
}

test "quiche error codes map to tagged errors" {
    try std.testing.expectError(error.Done, binding.check(binding.c.QUICHE_ERR_DONE));
    try std.testing.expectError(error.StreamReset, binding.check(binding.c.QUICHE_ERR_STREAM_RESET));
    try std.testing.expectError(error.Unknown, binding.check(@as(isize, -999)));
    try std.testing.expectEqual(@as(usize, 7), try binding.check(@as(isize, 7)));
}

test "socket addresses convert to posix storage" {
    const ip4 = binding.SockAddr.fromAddress(.{ .ip4 = .{ .octets = .{ 10, 0, 0, 1 }, .port = 4001 } });
    try std.testing.expectEqual(@as(std.posix.socklen_t, @sizeOf(std.posix.sockaddr.in)), ip4.len);
    try std.testing.expectEqual(std.posix.AF.INET, ip4.any().family);
    const ip6 = binding.SockAddr.fromAddress(.{ .ip6 = .{ .octets = [_]u8{0} ** 15 ++ [_]u8{1}, .port = 9000 } });
    try std.testing.expectEqual(@as(std.posix.socklen_t, @sizeOf(std.posix.sockaddr.in6)), ip6.len);
    try std.testing.expectEqual(std.posix.AF.INET6, ip6.any().family);
}

test "header info parses initial and short headers" {
    const initial = [_]u8{ 0xc3, 0x00, 0x00, 0x00, 0x01, 0x08 } ++ [_]u8{0xaa} ** 8 ++ [_]u8{0x04} ++ [_]u8{0xbb} ** 4 ++ [_]u8{0x00};
    const parsed = try binding.headerInfo(&initial);
    try std.testing.expectEqual(binding.PacketType.initial, parsed.packet_type);
    try std.testing.expectEqual(@as(u32, 1), parsed.version);
    try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 8), parsed.dcid.slice());
    try std.testing.expectEqualSlices(u8, &([_]u8{0xbb} ** 4), parsed.scid.slice());
    try std.testing.expectEqual(@as(usize, 0), parsed.token_len);

    const short = [_]u8{0x40} ++ [_]u8{0xcc} ** constants.local_cid_length ++ [_]u8{ 1, 2, 3, 4 };
    const short_parsed = try binding.headerInfo(&short);
    try std.testing.expectEqual(binding.PacketType.short, short_parsed.packet_type);
    try std.testing.expectEqualSlices(u8, &([_]u8{0xcc} ** constants.local_cid_length), short_parsed.dcid.slice());

    try std.testing.expectError(error.BufferTooShort, binding.headerInfo(&.{0xc3}));
}
