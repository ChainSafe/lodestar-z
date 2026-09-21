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

const local = @import("local_intent.zig");
const topic = @import("topic.zig");
const std = @import("std");

pub fn subscriptions(comptime names: []const []const u8) []const local.Boundary {
    return comptime blk: {
        @setEvalBranchQuota(100_000);
        var buffer: [topic_policy.boundary_max]local.Boundary = undefined;
        const value = subscriptionsInto(names, &buffer) catch unreachable;
        const result = buffer[0..value.len].*;
        break :blk &result;
    };
}

pub fn subscriptionsInto(names: []const []const u8, out: *[topic_policy.boundary_max]local.Boundary) ![]const local.Boundary {
    std.debug.assert(names.len <= topic_policy.topic_max);
    var len: usize = 0;
    for (names) |name| {
        const parsed = topic.parseCanonical(name) orelse return error.InvalidTopic;
        const index = for (out[0..len], 0..) |*entry, i| {
            if (std.mem.eql(u8, &entry.digest, &parsed.digest)) break i;
        } else index: {
            if (len == out.len) return error.TopicCapacity;
            out[len] = .{ .digest = parsed.digest };
            len += 1;
            break :index len - 1;
        };
        const entry = &out[index];
        const byte = parsed.name.subnet / 8;
        entry.mask(parsed.name.kind)[byte] |= @as(u8, 1) << @intCast(parsed.name.subnet % 8);
        const k = @intFromEnum(parsed.name.kind);
        entry.lengths[k] = @max(entry.lengths[k], @as(u8, @intCast(byte + 1)));
    }
    return out[0..len];
}
