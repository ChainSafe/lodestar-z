const std = @import("std");
const history = @import("dial_history.zig");
const t = @import("types.zig");

const peer: t.PeerId = .{ .bytes = @splat(3) };
const other: t.PeerId = .{ .bytes = @splat(4) };
const endpoint: t.Address = .{ .ip4 = .{ .octets = .{ 192, 0, 2, 1 }, .port = 9001 } };
const moved: t.Address = .{ .ip4 = .{ .octets = .{ 192, 0, 2, 1 }, .port = 9002 } };

fn fixture(entries: []history.Entry) history.History {
    @memset(entries, .{});
    return .{ .entries = entries, .seed = 7 };
}

test "dial history keys separate peers endpoints and identities" {
    var storage: [64]history.Entry = undefined;
    const h = fixture(&storage);
    const key = h.endpointKey(&peer, endpoint);
    try std.testing.expectEqual(key, h.endpointKey(&peer, endpoint));
    try std.testing.expect(key != h.endpointKey(&other, endpoint));
    try std.testing.expect(key != h.endpointKey(&peer, moved));
    try std.testing.expect(key != h.identityKey(&peer));
    try std.testing.expect(key != 0 and h.identityKey(&peer) != 0);
}

test "dial history blocks an endpoint after two strikes until its memory expires" {
    var storage: [64]history.Entry = undefined;
    var h = fixture(&storage);
    const key = h.endpointKey(&peer, endpoint);
    h.recordEndpoint(key, .unanswered, 5, 0);
    try std.testing.expect(!h.blocked(key, 5, 1));
    try std.testing.expectEqual(@as(u8, 1), h.strikesFor(key, 5, 1));
    h.recordEndpoint(key, .handshake_timeout, 5, 1);
    h.markRetry(key, .handshake_timeout, 1);
    try std.testing.expect(h.blocked(key, 5, 2));
    try std.testing.expect(h.blocked(key, 4, 2));
    try std.testing.expect(!h.blocked(key, 6, 2));
    try std.testing.expectEqual(@as(u8, 0), h.strikesFor(key, 6, 2));
    try std.testing.expectEqual(@as(?t.DialFailure, .handshake_timeout), h.takeRetry(key, 2));
    try std.testing.expectEqual(@as(?t.DialFailure, null), h.takeRetry(key, 2));
    try std.testing.expect(!h.blocked(key, 5, 1 + history.endpoint_memory_ms));
    try std.testing.expectEqual(@as(u8, 0), h.strikesFor(key, 5, 1 + history.endpoint_memory_ms));
}

test "dial history mismatch blocks every sequence for its longer window" {
    var storage: [64]history.Entry = undefined;
    var h = fixture(&storage);
    const key = h.endpointKey(&peer, endpoint);
    h.recordEndpoint(key, .peer_id_mismatch, 5, 0);
    try std.testing.expectEqual(@as(?t.DialFailure, null), h.takeRetry(key, 1));
    try std.testing.expect(h.blocked(key, 99, history.endpoint_memory_ms));
    try std.testing.expect(!h.blocked(key, 99, history.mismatch_memory_ms));
}

test "dial history clear forgets a proven endpoint" {
    var storage: [64]history.Entry = undefined;
    var h = fixture(&storage);
    const key = h.endpointKey(&peer, endpoint);
    h.recordEndpoint(key, .refused, 1, 0);
    h.recordEndpoint(key, .refused, 1, 1);
    try std.testing.expect(h.blocked(key, 1, 2));
    h.clear(key);
    try std.testing.expect(!h.blocked(key, 1, 2));
    try std.testing.expectEqual(@as(u8, 0), h.strikesFor(key, 1, 2));
}

test "dial history escalates remote full cooldowns and forgets them after the memory window" {
    var storage: [64]history.Entry = undefined;
    var h = fixture(&storage);
    const key = h.identityKey(&peer);
    try std.testing.expectEqual(@as(u64, 300_000), h.remoteFull(key, 0));
    try std.testing.expectEqual(@as(?t.DialFailure, null), h.takeRetry(key, 0));
    try std.testing.expectEqual(@as(u64, 900_000), h.remoteFull(key, 300_000));
    try std.testing.expectEqual(@as(u64, 3_600_000), h.remoteFull(key, 1_200_000));
    try std.testing.expectEqual(@as(u64, 3_600_000), h.remoteFull(key, 4_800_000));
    try std.testing.expectEqual(@as(u64, 300_000), h.remoteFull(key, 4_800_000 + history.remote_full_memory_ms));
}

test "dial history stays within its table and keeps the newest entry" {
    var storage: [64]history.Entry = undefined;
    var h = fixture(&storage);
    for (0..1_000) |index| {
        var identity = peer;
        std.mem.writeInt(u32, identity.bytes[0..4], @intCast(index), .little);
        h.recordEndpoint(h.endpointKey(&identity, endpoint), .unanswered, 1, index);
    }
    var newest = peer;
    std.mem.writeInt(u32, newest.bytes[0..4], 999, .little);
    try std.testing.expectEqual(@as(u8, 1), h.strikesFor(h.endpointKey(&newest, endpoint), 1, 1_000));
    try std.testing.expectEqual(@as(usize, 64), history.History.capacityFor(0));
    try std.testing.expectEqual(@as(usize, 1_024), history.History.capacityFor(256));
    try std.testing.expectEqual(@as(usize, 4_096), history.History.capacityFor(4_096));
}

test "dial history marks a redial per endpoint without adding evidence" {
    var storage: [64]history.Entry = undefined;
    var h = fixture(&storage);
    const key = h.endpointKey(&peer, endpoint);
    const other_key = h.endpointKey(&peer, moved);
    h.markRetry(key, .peer_id_mismatch, 0);
    try std.testing.expect(!h.blocked(key, 1, 1));
    try std.testing.expectEqual(@as(u8, 0), h.strikesFor(key, 0, 1));
    try std.testing.expectEqual(@as(?t.DialFailure, null), h.takeRetry(other_key, 1));
    try std.testing.expectEqual(@as(?t.DialFailure, .peer_id_mismatch), h.takeRetry(key, 1));
    try std.testing.expectEqual(@as(?t.DialFailure, null), h.takeRetry(key, 1));
    h.markRetry(key, .expired, 1);
    try std.testing.expectEqual(@as(?t.DialFailure, .expired), h.takeRetry(key, history.endpoint_memory_ms - 1));
    h.markRetry(key, .unanswered, history.endpoint_memory_ms - 1);
    try std.testing.expectEqual(@as(?t.DialFailure, null), h.takeRetry(key, history.endpoint_memory_ms));
}
