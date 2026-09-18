const Admission = @import("admission.zig").Admission;
const Outcome = @import("admission.zig").Outcome;
const global_quota = @import("admission.zig").global_quota;
const source_quota = @import("admission.zig").source_quota;
const std = @import("std");
const types = @import("types.zig");

test "discovery admission ignores ports and separates challenge and verification credit" {
    var admission = try Admission.init(std.testing.allocator);
    defer admission.deinit(std.testing.allocator);
    var source = types.Address{ .ip4 = .{ .octets = .{ 192, 0, 2, 1 }, .port = 1 } };
    for (0..source_quota.burst) |i| {
        source.ip4.port = @intCast(i + 1);
        try std.testing.expect(admission.allow(.challenge, &source, 0));
        try std.testing.expect(admission.allow(.handshake, &source, 0));
    }
    try std.testing.expect(!admission.allow(.challenge, &source, 249));
    try std.testing.expect(!admission.allow(.handshake, &source, 249));
    try std.testing.expect(admission.allow(.challenge, &source, 250));
    try std.testing.expect(admission.allow(.handshake, &source, 250));
    try std.testing.expect(!admission.allow(.handshake, &source, 0));
    try std.testing.expect(admission.allow(.handshake, &source, 1_250));
}

test "discovery admission groups IPv6 prefixes and shares global credit across families" {
    var admission = try Admission.init(std.testing.allocator);
    defer admission.deinit(std.testing.allocator);
    var source = types.Address{ .ip6 = .{ .octets = .{ 0x20, 1, 0xd, 0xb8 } ++ .{0} ** 12, .port = 1 } };
    for (0..source_quota.burst) |i| {
        source.ip6.octets[15] = @intCast(i);
        try std.testing.expect(admission.allow(.handshake, &source, 0));
    }
    source.ip6.octets[15] += 1;
    try std.testing.expect(!admission.allow(.handshake, &source, 0));
    for (0..global_quota.burst - source_quota.burst) |i| {
        const other = types.Address{ .ip4 = .{ .octets = .{ 192, 0, 2, @intCast(i) }, .port = 1 } };
        try std.testing.expect(admission.allow(.handshake, &other, 0));
    }
    source.ip6.octets[7] = 1;
    try std.testing.expect(!admission.allow(.handshake, &source, 49));
    try std.testing.expect(admission.allow(.handshake, &source, 50));
    try std.testing.expect(admission.allow(.challenge, &source, 50));
}

test "discovery admission refuses full source accounting until credit has replenished" {
    var admission = try Admission.init(std.testing.allocator);
    defer admission.deinit(std.testing.allocator);
    for (admission.sources, 0..) |*source, i| source.* = .{
        .address = .{ .ip4 = .{ .octets = .{ 192, 0, 2, @intCast(i) }, .port = 1 } },
        .buckets = .{ .{}, .{ .charged_until_ms = 250 } },
    };
    const other = types.Address{ .ip4 = .{ .octets = .{ 192, 0, 3, 1 }, .port = 1 } };
    try std.testing.expect(!admission.allow(.challenge, &other, 249));
    try std.testing.expectEqual(@as(u64, 1), admission.counts[0][@intFromEnum(Outcome.source_capacity)]);
    try std.testing.expect(admission.allow(.challenge, &other, 250));
    try std.testing.expect(admission.sources[0].address.eql(other));
}

test "discovery admission fails closed when a charge would overflow monotonic time" {
    var admission = try Admission.init(std.testing.allocator);
    defer admission.deinit(std.testing.allocator);
    const source = types.Address{ .ip4 = .{ .octets = .{ 192, 0, 2, 1 }, .port = 1 } };
    try std.testing.expect(!admission.allow(.handshake, &source, std.math.maxInt(u64)));
    try std.testing.expectEqual(@as(u64, 0), admission.global[1].charged_until_ms);
}
