const std = @import("std");
const metadata = @import("metadata.zig");
const Kind = @import("../gossip_limits.zig").Kind;
const slots = @import("preset").preset.SLOTS_PER_EPOCH;
const extract = metadata.extract;
const eligible = metadata.eligible;

test "gossip metadata bounds offsets and rejects far future retention" {
    const t = std.testing;
    var data: [240]u8 = @splat(0);
    std.mem.writeInt(u64, data[16..24], 9999999, .little);
    const meta = extract(.beacon_attestation, true, &data);
    try t.expect(!eligible(&meta, .beacon_attestation, true, 100));
    try t.expect(extract(.beacon_block, false, data[0..100]).slot == null);
    try t.expect(extract(.beacon_block, false, &data).root == null);
    try t.expect(meta.group != null and meta.root != null);
}

test "Deneb single and aggregate metadata retain the full previous epoch" {
    for ([_]Kind{ .beacon_attestation, .beacon_aggregate_and_proof }) |kind| {
        const current = 3 * slots - 1;
        try std.testing.expect(eligible(&.{ .slot = slots }, kind, true, current));
        try std.testing.expect(!eligible(&.{ .slot = slots - 1 }, kind, true, current));
        try std.testing.expect(eligible(&.{ .slot = current }, kind, true, current));
        try std.testing.expect(eligible(&.{ .slot = current + 1 }, kind, true, current));
        try std.testing.expect(!eligible(&.{ .slot = current + 2 }, kind, true, current));
    }
}

test "attestation metadata preserves past disparity only across the current slot boundary" {
    for ([_]Kind{ .beacon_attestation, .beacon_aggregate_and_proof }) |kind| {
        try std.testing.expect(eligible(&.{ .slot = slots }, kind, true, 3 * slots));
        try std.testing.expect(!eligible(&.{ .slot = slots - 1 }, kind, true, 3 * slots));
        try std.testing.expect(!eligible(&.{ .slot = slots }, kind, true, 3 * slots + 1));
        try std.testing.expect(eligible(&.{ .slot = 2 * slots }, kind, true, 3 * slots + 1));
        try std.testing.expect(eligible(&.{ .slot = 31 }, kind, false, 64));
        try std.testing.expect(!eligible(&.{ .slot = 30 }, kind, false, 64));
        try std.testing.expect(!eligible(&.{ .slot = 31 }, kind, false, 65));
        try std.testing.expect(eligible(&.{ .slot = 32 }, kind, false, 65));
    }
    try std.testing.expect(!eligible(&.{ .slot = 31 }, .beacon_block, true, 64));
}

test "attestation metadata slot bounds saturate at genesis and u64 maximum" {
    for ([_]Kind{ .beacon_attestation, .beacon_aggregate_and_proof }) |kind| {
        for ([_]bool{ false, true }) |deneb| {
            try std.testing.expect(eligible(&.{ .slot = 0 }, kind, deneb, 0));
            try std.testing.expect(eligible(&.{ .slot = 1 }, kind, deneb, 0));
            try std.testing.expect(!eligible(&.{ .slot = 2 }, kind, deneb, 0));
            try std.testing.expect(eligible(&.{ .slot = std.math.maxInt(u64) }, kind, deneb, std.math.maxInt(u64)));
            try std.testing.expect(eligible(&.{}, kind, deneb, 0));
        }
    }
}
