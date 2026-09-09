const std = @import("std");

pub const Reason = enum { shutdown, irrelevant_network, fault, unable_to_verify, too_many_peers, bad_score, banned, banned_ip, unknown };
pub const count = @typeInfo(Reason).@"enum".fields.len;

pub fn reason(code: u64) Reason {
    return switch (code) {
        1 => .shutdown,
        2 => .irrelevant_network,
        3 => .fault,
        128 => .unable_to_verify,
        129 => .too_many_peers,
        250 => .bad_score,
        251 => .banned,
        252 => .banned_ip,
        else => .unknown,
    };
}

pub fn cooldownMs(code: u64) u64 {
    return switch (reason(code)) {
        .irrelevant_network, .bad_score, .banned, .banned_ip => 600_000,
        .too_many_peers => 300_000,
        else => 60_000,
    };
}

test "goodbye labels and cooldowns bound unknown peer codes" {
    try std.testing.expectEqual(Reason.too_many_peers, reason(129));
    try std.testing.expectEqual(Reason.unknown, reason(std.math.maxInt(u64)));
    try std.testing.expectEqual(@as(u64, 300_000), cooldownMs(129));
    try std.testing.expectEqual(@as(u64, 60_000), cooldownMs(std.math.maxInt(u64)));
    try std.testing.expectEqual(@as(u64, 600_000), cooldownMs(250));
}
