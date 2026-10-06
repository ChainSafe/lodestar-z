const std = @import("std");
const mcache = @import("mcache.zig");
const SeenCache = mcache.SeenCache;
const History = mcache.History;
const HistoryEntry = mcache.HistoryEntry;
const MessageId = @import("topic.zig").MessageId;
const Index = mcache.IdIndex(MessageId);
const PeerRef = @import("peer_book.zig").Ref;
const storage = @import("message_store.zig");
const constants = @import("constants.zig");
const topic = @import("topic.zig");

test "gossip history visits only matching topics and keeps owned keys through eviction and replacement" {
    const a = std.testing.allocator;
    var store = try storage.Store.init(a, 65, storage.page_bytes);
    defer store.deinit(a);
    var history = try History.init(a, 64, 1);
    defer history.deinit(a);
    var names: [32][32]u8 = undefined;
    var lengths: [32]usize = undefined;
    for (&names, &lengths, 0..) |*name, *len, i| len.* = (try std.fmt.bufPrint(name, "topic-{d}", .{i})).len;
    for (0..64) |i| {
        const h = store.put(@splat(@intCast(i)), names[i % 32][0..lengths[i % 32]], "payload").?;
        history.put(&store, h, 0);
        store.seal(h);
    }
    var ids: [64]MessageId = undefined;
    for (names, lengths) |name, len| try std.testing.expectEqual(@as(usize, 2), history.gossip(name[0..len], &ids, 1));
    try std.testing.expectEqual(@as(u64, 64), history.gossip_entries_visited);
    try std.testing.expectEqual(@as(usize, 0), history.gossip("absent", &ids, 1));
    try std.testing.expectEqual(@as(u64, 64), history.gossip_entries_visited);
    const replacement = store.put(@splat(0), "replacement", "new").?;
    history.put(&store, replacement, 1);
    store.seal(replacement);
    try std.testing.expectEqual(@as(usize, 1), history.gossip("topic-0", &ids, 2));
    try std.testing.expectEqualSlices(u8, &(@as(MessageId, @splat(32))), &ids[0]);
    try std.testing.expectEqual(@as(usize, 1), history.gossip("replacement", &ids, 2));
    history.age(&store, constants.mcache_len);
    try std.testing.expectEqual(@as(usize, 1), history.count);
    for (names, lengths) |name, len| try std.testing.expectEqual(@as(usize, 0), history.gossip(name[0..len], &ids, constants.mcache_len));
    history.age(&store, constants.mcache_len + 1);
    try std.testing.expectEqual(@as(usize, 0), history.count);
    for (0..64) |i| {
        const h = store.put(@splat(@intCast(i)), "reused", "payload").?;
        history.put(&store, h, 10);
        store.seal(h);
    }
    try std.testing.expectEqual(@as(usize, 64), history.gossip("reused", &ids, 11));
    try std.testing.expectEqual(@as(usize, 0), history.gossip("replacement", &ids, 11));
}

test "gossip history cleans up every partial index allocation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, initHistory, .{});
}

fn initHistory(a: std.mem.Allocator) !void {
    var history = try History.init(a, 8, 2);
    defer history.deinit(a);
}

test "gossip history owned topic keys survive wrapped hash collisions and slot reuse" {
    const a = std.testing.allocator;
    var store = try storage.Store.init(a, 5, storage.page_bytes);
    defer store.deinit(a);
    var history = try History.init(a, 4, 1);
    defer history.deinit(a);
    var names: [5][32]u8 = undefined;
    var lengths: [5]usize = undefined;
    var count: usize = 0;
    for (0..4096) |candidate| {
        const name = try std.fmt.bufPrint(&names[count], "collision-{d}", .{candidate});
        if (std.hash.Wyhash.hash(history.topic_index.seed, name) & history.topic_index.mask != history.topic_index.mask) continue;
        lengths[count] = name.len;
        count += 1;
        if (count == names.len) break;
    }
    try std.testing.expectEqual(names.len, count);
    for (names, lengths, 0..) |name, len, i| {
        const h = store.put(@splat(@intCast(i)), name[0..len], "payload").?;
        history.put(&store, h, 0);
        store.seal(h);
    }
    var ids: [4]MessageId = undefined;
    try std.testing.expectEqual(@as(usize, 0), history.gossip(names[0][0..lengths[0]], &ids, 1));
    for (1..5) |i| {
        try std.testing.expectEqual(@as(usize, 1), history.gossip(names[i][0..lengths[i]], &ids, 1));
        try std.testing.expectEqual(@as(MessageId, @splat(@intCast(i))), ids[0]);
    }
    const h = store.put(@splat(2), names[0][0..lengths[0]], "replacement").?;
    history.put(&store, h, 0);
    store.seal(h);
    try std.testing.expectEqual(@as(usize, 0), history.gossip(names[2][0..lengths[2]], &ids, 1));
    for ([_]usize{ 0, 1, 3, 4 }) |i| try std.testing.expectEqual(@as(usize, 1), history.gossip(names[i][0..lengths[i]], &ids, 1));
}

test "seen cache dedupes, evicts oldest when full, and expires by ttl" {
    var cache = try SeenCache.init(std.testing.allocator, 4, 1_000);
    defer cache.deinit(std.testing.allocator);
    const a = [_]u8{1} ** 20;
    const b = [_]u8{2} ** 20;
    try std.testing.expect(cache.add(a, 0));
    try std.testing.expect(!cache.add(a, 0));
    try std.testing.expect(cache.contains(a, 400));
    try std.testing.expect(cache.add(b, 100));
    // fill past capacity: a evicts
    try std.testing.expect(cache.add([_]u8{3} ** 20, 200));
    try std.testing.expect(cache.add([_]u8{4} ** 20, 300));
    try std.testing.expect(cache.add([_]u8{5} ** 20, 400));
    try std.testing.expect(!cache.contains(a, 400));
    try std.testing.expect(cache.contains(b, 400));
    // ttl expiry from the tail
    try std.testing.expect(cache.add([_]u8{6} ** 20, 1_500));
    try std.testing.expect(!cache.contains(b, 400));
}

test "gossip seen TTL applies to duplicate only traffic" {
    var cache = try SeenCache.init(std.testing.allocator, 4, 10);
    defer cache.deinit(std.testing.allocator);
    const id = [_]u8{1} ** 20;
    try std.testing.expect(cache.add(id, 1));
    try std.testing.expect(!cache.add(id, 10));
    try std.testing.expect(!cache.contains(id, 11));
    try std.testing.expect(cache.add(id, 11));
}

test "gossip history indexed replacement keeps FIFO age and invalidates old handles" {
    var store = try storage.Store.init(std.testing.allocator, 4, 16384);
    defer store.deinit(std.testing.allocator);
    var history = try History.init(std.testing.allocator, 2, constants.retained_peers_cap);
    defer history.deinit(std.testing.allocator);
    const a = [_]u8{1} ** 20;
    const b = [_]u8{2} ** 20;
    const first = store.put(a, "a", "old").?;
    history.put(&store, first, 0);
    store.seal(first);
    const second = store.put(b, "b", "other").?;
    history.put(&store, second, 0);
    store.seal(second);
    history.age(&store, 1);
    const replacement = store.put(a, "a", "new").?;
    history.put(&store, replacement, 1);
    store.seal(replacement);
    try std.testing.expectEqual(@as(usize, 2), history.count);
    try std.testing.expectEqual(replacement, history.message(history.get(&store, a).?));
    try std.testing.expect(store.get(first) == null);
    history.age(&store, constants.mcache_len);
    try std.testing.expect(history.get(&store, b) == null);
    try std.testing.expect(history.get(&store, a) != null);
    history.age(&store, constants.mcache_len + 1);
    try std.testing.expectEqual(@as(usize, 0), history.count);
    try std.testing.expectEqual(@as(usize, 0), store.used_entries);
}

test "gossip ID index bounds sparse misses and repairs wrapped collision clusters" {
    var ids: [64]MessageId = undefined;
    var index = try Index.init(std.testing.allocator, &ids);
    defer index.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), index.probe_limit);
    try std.testing.expect(index.find(@splat(0)) == null);
    var count: usize = 0;
    for (0..65_536) |candidate| {
        var id: MessageId = @splat(0);
        std.mem.writeInt(u64, id[0..8], candidate, .little);
        if (std.hash.Wyhash.hash(index.seed, &id) & index.mask != index.mask) continue;
        ids[count] = id;
        index.insert(id, @intCast(count));
        count += 1;
        try std.testing.expectEqual(count, index.probe_limit);
        if (count == ids.len) break;
    }
    try std.testing.expectEqual(ids.len, count);
    var present = std.StaticBitSet(64).full;
    for ([_]usize{ 0, 32, 63, 1, 31, 62 }) |removed| {
        index.remove(ids[removed]);
        present.unset(removed);
        try std.testing.expectEqual(ids.len, index.probe_limit);
        for (ids, 0..) |id, i| try std.testing.expectEqual(if (present.isSet(i)) @as(?u32, @intCast(i)) else null, index.find(id));
    }
    index.clear();
    try std.testing.expectEqual(@as(usize, 0), index.probe_limit);
    for (ids) |id| try std.testing.expect(index.find(id) == null);
    index.insert(ids[63], 63);
    try std.testing.expectEqual(@as(usize, 1), index.probe_limit);
    try std.testing.expect(index.find(ids[0]) == null);
    try std.testing.expectEqual(@as(?u32, 63), index.find(ids[63]));
}

test "gossip policy recovery permits more than sixteen distinct recipients" {
    var history = try History.init(std.testing.allocator, 2, constants.retained_peers_cap);
    defer history.deinit(std.testing.allocator);
    const slot: u32 = 0;
    for (0..32) |i| {
        const peer: PeerRef = .{ .index = @intCast(i), .generation = 1 };
        history.bindPeer(peer);
        try std.testing.expect(history.iwantAllowed(slot, peer, 3));
        for (0..3) |_| history.sent(slot, peer);
        try std.testing.expect(!history.iwantAllowed(slot, peer, 3));
    }
    history.bindPeer(.{ .index = 0, .generation = 2 });
    try std.testing.expect(history.iwantAllowed(slot, .{ .index = 0, .generation = 2 }, 3));
}

test "gossip history entries keep peer generations outside message rows" {
    try std.testing.expect(@sizeOf(HistoryEntry) < 1024);
}

test "gossip history stale peer cannot restore retransmission allowance" {
    var history = try History.init(std.testing.allocator, 2, constants.retained_peers_cap);
    defer history.deinit(std.testing.allocator);
    const slot: u32 = 0;
    const current: PeerRef = .{ .index = 0, .generation = (@as(u64, 1) << 40) + 2 };
    const stale: PeerRef = .{ .index = 0, .generation = current.generation - 1 };
    history.bindPeer(current);
    for (0..3) |_| history.sent(slot, current);
    try std.testing.expect(!history.iwantAllowed(slot, stale, 3));
    history.bindPeer(stale);
    history.sent(slot, stale);
    try std.testing.expect(!history.iwantAllowed(slot, current, 3));
}

test "gossip history replacement resets message retransmission counts" {
    var store = try storage.Store.init(std.testing.allocator, 4, 16384);
    defer store.deinit(std.testing.allocator);
    var history = try History.init(std.testing.allocator, 1, constants.retained_peers_cap);
    defer history.deinit(std.testing.allocator);
    const id: MessageId = @splat(1);
    const first = store.put(id, "t", "first").?;
    history.put(&store, first, 0);
    store.seal(first);
    const peer: PeerRef = .{ .index = 0, .generation = 1 };
    history.bindPeer(peer);
    for (0..3) |_| history.sent(history.get(&store, id).?, peer);
    const replacement = store.put(id, "t", "replacement").?;
    history.put(&store, replacement, 0);
    store.seal(replacement);
    try std.testing.expect(history.iwantAllowed(history.get(&store, id).?, peer, 3));
    try std.testing.expectEqual(@as(u8, 0), history.countsRow(history.get(&store, id).?)[peer.index]);
    try std.testing.expectEqual(@as(usize, 1), store.used_entries);
}

test "gossip history canonical identity replacement clears only its bounded peer column" {
    var history = try History.init(std.testing.allocator, 3, constants.retained_peers_cap);
    defer history.deinit(std.testing.allocator);
    const peer: PeerRef = .{ .index = 0, .generation = (@as(u64, 1) << 40) + 1 };
    const other: PeerRef = .{ .index = 1, .generation = 1 };
    history.bindPeer(peer);
    history.bindPeer(other);
    for (0..history.entries.len) |i| {
        for (0..3) |_| history.sent(@intCast(i), peer);
        history.sent(@intCast(i), other);
    }
    history.bindPeer(peer);
    for (0..history.entries.len) |i| try std.testing.expect(!history.iwantAllowed(@intCast(i), peer, 3));
    const replacement: PeerRef = .{ .index = 0, .generation = std.math.maxInt(u64) };
    history.bindPeer(replacement);
    for (0..history.entries.len) |i| {
        try std.testing.expect(history.iwantAllowed(@intCast(i), replacement, 3));
        try std.testing.expect(!history.iwantAllowed(@intCast(i), peer, 3));
        try std.testing.expectEqual(@as(u8, 0), history.countsRow(@intCast(i))[0]);
        try std.testing.expectEqual(@as(u8, 1), history.countsRow(@intCast(i))[1]);
        for (0..3) |_| history.sent(@intCast(i), replacement);
    }
    history.bindPeer(peer);
    for (0..history.entries.len) |i| {
        history.sent(@intCast(i), peer);
        try std.testing.expect(!history.iwantAllowed(@intCast(i), replacement, 3));
    }
}

test "history resolved retained capacity bounds counters and stale peers" {
    var history = try History.init(std.testing.allocator, 2, 4);
    defer history.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 4), history.generations.len);
    try std.testing.expectEqual(@as(usize, 8), history.counts.len);
    try std.testing.expectEqual(@as(usize, 4), history.countsRow(0).len);
    try std.testing.expect(!history.iwantAllowed(0, .{ .index = 4, .generation = 1 }, 3));
    history.sent(0, .{ .index = 4, .generation = 1 });
}

test "gossip failed admission preserves history borrowed by validation" {
    const a = std.testing.allocator;
    var store = try storage.Store.init(a, 3, storage.page_bytes * 2);
    defer store.deinit(a);
    var history = try History.init(a, 2, 2);
    defer history.deinit(a);
    var handles: [2]storage.Handle = undefined;
    for (&handles, 0..) |*handle, i| {
        const id: MessageId = @splat(@intCast(i));
        handle.* = history.admitPayload(&store, id, "topic", &([_]u8{1} ** (storage.inline_bytes + 1))).?;
        history.put(&store, handle.*, 0);
        store.seal(handle.*);
        store.retainValidation(handle.*);
    }
    defer for (handles) |handle| store.releaseValidation(handle);
    try std.testing.expectEqual(@as(usize, 2), history.count);
    try std.testing.expect(history.admitPayload(&store, @splat(9), "topic", &([_]u8{1} ** (storage.inline_bytes + 1))) == null);
    try std.testing.expectEqual(@as(usize, 2), history.count);
    try std.testing.expectEqual(@as(usize, 0), store.free_pages);
}

test "gossip history emits three windows and defers arrivals during a cycle" {
    const a = std.testing.allocator;
    var store = try storage.Store.init(a, 3, 3 * storage.page_bytes);
    defer store.deinit(a);
    var history = try History.init(a, 3, 2);
    defer history.deinit(a);
    const first = store.put(@splat(1), "topic", "first").?;
    history.put(&store, first, 0);
    store.seal(first);
    var epoch: u64 = 1;
    const second = store.put(@splat(2), "topic", "second").?;
    history.put(&store, second, epoch);
    store.seal(second);
    var ids: [3]MessageId = undefined;
    try std.testing.expectEqual(@as(usize, 1), history.gossip("topic", &ids, epoch));
    history.age(&store, epoch);
    for (0..2) |_| {
        epoch += 1;
        try std.testing.expectEqual(@as(usize, 2), history.gossip("topic", &ids, epoch));
        history.age(&store, epoch);
    }
    epoch += 1;
    try std.testing.expectEqual(@as(usize, 1), history.gossip("topic", &ids, epoch));
    try std.testing.expectEqual(@as(MessageId, @splat(2)), ids[0]);
    history.age(&store, epoch);
    epoch += 1;
    try std.testing.expectEqual(@as(usize, 0), history.gossip("topic", &ids, epoch));
    history.age(&store, epoch);
}

fn retainNext(history: *History, store: *storage.Store, index: u32, name: []const u8) bool {
    var id: MessageId = @splat(0);
    std.mem.writeInt(u32, id[0..4], index, .little);
    const h = store.put(id, name, "x").?;
    defer store.seal(h);
    if (!history.makeRoom(store, h)) return false;
    history.put(store, h, 0);
    return true;
}

test "gossip retention reclaims its own kind's old copies however many other messages follow them" {
    const a = std.testing.allocator;
    const limits_mod = @import("../gossip_limits.zig");
    const attestation = "/eth2/01020304/beacon_attestation_1/ssz_snappy";
    const exit = "/eth2/01020304/voluntary_exit/ssz_snappy";
    var limits: limits_mod.Limits = @splat(.{ .items = 2, .bytes = storage.page_bytes });
    limits[@intFromEnum(topic.Kind.beacon_attestation)].items = 9000;
    limits[@intFromEnum(topic.Kind.voluntary_exit)].items = 8;
    // The old 8,192-entry history and one holding the whole retention window admit the same exits:
    // the smaller one ages the first exits out by capacity, the larger reclaims one by retention.
    for ([_]usize{ 8192, 8300 }, [_]usize{ 8192, 8264 }) |capacity, retained| {
        var store = try storage.Store.init(a, capacity + 2, storage.page_bytes);
        defer store.deinit(a);
        store.limits = limits;
        var history = try History.init(a, capacity, 1);
        defer history.deinit(a);
        var index: u32 = 0;
        for ([_]struct { []const u8, usize }{ .{ attestation, 64 }, .{ exit, 8 }, .{ attestation, 8192 }, .{ exit, 1 } }) |run| {
            for (0..run[1]) |_| {
                try std.testing.expect(retainNext(&history, &store, index, run[0]));
                index += 1;
            }
        }
        try std.testing.expectEqual(retained, history.count);
        history.age(&store, constants.mcache_len);
        try std.testing.expectEqual(@as(usize, 0), store.used_entries);
    }
}
