const std = @import("std");
const peer_index = @import("peer_index.zig");

const PeerIndex = peer_index.PeerIndex;

fn collect(index: *const PeerIndex, key: u64, out: []u16) usize {
    var count: usize = 0;
    var candidates = index.candidates(key);
    while (candidates.next()) |entry| {
        if (count == out.len) break;
        out[count] = entry.index;
        count += 1;
    }
    return count;
}

test "peer index keeps every entry under one key reachable across removals" {
    var index = try PeerIndex.init(std.testing.allocator, 8);
    defer index.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 16), index.entries.len);

    var slot: u16 = 0;
    while (slot < 6) : (slot += 1) {
        index.insert(.{ .key = 0xabcd, .index = slot, .generation = 1, .used = true });
    }
    index.insert(.{ .key = 0x1234, .index = 6, .generation = 3, .used = true });
    var found: [8]u16 = undefined;
    try std.testing.expectEqual(@as(usize, 6), collect(&index, 0xabcd, &found));
    try std.testing.expectEqual(@as(usize, 1), collect(&index, 0x1234, &found));
    try std.testing.expectEqual(@as(u16, 6), found[0]);

    index.remove(0xabcd, 2);
    index.remove(0xabcd, 4);
    try std.testing.expectEqual(@as(usize, 4), collect(&index, 0xabcd, &found));
    for (found[0..4]) |seen| try std.testing.expect(seen != 2 and seen != 4);
    try std.testing.expectEqual(@as(usize, 1), collect(&index, 0x1234, &found));
    try std.testing.expectEqual(@as(usize, 0), collect(&index, 0x9999, &found));

    index.remove(0xabcd, 2);
    try std.testing.expectEqual(@as(usize, 4), collect(&index, 0xabcd, &found));
}

test "peer index hashes identity bytes beyond the structured prefix" {
    const wire_peer_id = @import("../wire/peer_id.zig");
    var a = wire_peer_id.PeerId{ .bytes = [_]u8{7} ** wire_peer_id.length };
    var b = a;
    b.bytes[wire_peer_id.length - 1] = 8;
    try std.testing.expect(peer_index.keyOf(42, &a) != peer_index.keyOf(42, &b));
    try std.testing.expect(peer_index.keyOf(42, &a) != peer_index.keyOf(43, &a));
}

test "peer index spreads structured identities across the full hash space" {
    const wire_peer_id = @import("../wire/peer_id.zig");
    var id = wire_peer_id.PeerId{ .bytes = [_]u8{0} ** wire_peer_id.length };
    @memcpy(id.bytes[0..7], &[_]u8{ 0, 37, 8, 2, 18, 33, 2 });
    var buckets = std.StaticBitSet(1024).initEmpty();
    for (0..1024) |identity| {
        std.mem.writeInt(u16, id.bytes[wire_peer_id.length - 2 ..], @intCast(identity), .big);
        buckets.set(@intCast(peer_index.keyOf(42, &id) & 1023));
    }
    try std.testing.expect(buckets.count() > 600);
}
