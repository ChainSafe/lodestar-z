const topic_policy = @import("topic_policy.zig");

pub fn full(digest: [4]u8) topic_policy.Boundary {
    var boundary: topic_policy.Boundary = .{ .digest = digest };
    for (&boundary.rules) |*rule| rule.* = .{ .count = 1, .ssz_min = 10, .ssz_max = 100 };
    boundary.rules[2].count = 64;
    boundary.rules[7].count = 4;
    boundary.rules[11].count = 128;
    boundary.rules[12].count = 128;
    return boundary;
}

pub fn hoodi() [5]topic_policy.Boundary {
    var out: [5]topic_policy.Boundary = undefined;
    const digests = [_][4]u8{ .{ 0xd2, 0xf1, 0x99, 0x7f }, .{ 0x82, 0x55, 0x6a, 0x32 }, .{ 0xe2, 0xab, 0xcc, 0xa4 }, .{ 0xae, 0x9f, 0x70, 0xa0 }, .{ 0xc6, 0xec, 0xb7, 0x6c } };
    for (&out, digests, 0..) |*b, digest, i| {
        b.* = full(digest);
        b.rules[11] = if (i < 2) .{ .count = if (i == 0) 6 else 9, .ssz_min = 10, .ssz_max = 100 } else .{};
        if (i < 2) b.rules[12] = .{};
    }
    return out;
}
