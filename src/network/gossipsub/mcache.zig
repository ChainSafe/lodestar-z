const std = @import("std");
const constants = @import("constants.zig");

const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const MessageId = [constants.message_id_length]u8;

const empty_slot: u32 = std.math.maxInt(u32);

fn hashId(id: MessageId) usize {
    // Stored IDs are computed SHA-256 truncations. Remote query IDs still use bounded probing.
    return std.mem.readInt(u64, id[0..8], .little);
}

/// An open-addressed id-to-index table with backward-shift deletion, shared by
/// both caches. Capacity is a power of two so the mask is cheap.
const Index = struct {
    slots: []u32,
    ids: []MessageId,
    mask: usize,

    fn init(allocator: Allocator, capacity: usize, ids: []MessageId) Allocator.Error!Index {
        const table_len = std.math.ceilPowerOfTwo(usize, @max(capacity * 2, 2)) catch unreachable;
        const slots = try allocator.alloc(u32, table_len);
        @memset(slots, empty_slot);
        return .{ .slots = slots, .ids = ids, .mask = table_len - 1 };
    }

    fn deinit(self: *Index, allocator: Allocator) void {
        allocator.free(self.slots);
    }

    fn find(self: *const Index, id: MessageId) ?u32 {
        var pos = hashId(id) & self.mask;
        for (0..self.slots.len) |_| {
            if (self.slots[pos] == empty_slot) return null;
            if (std.mem.eql(u8, &self.ids[self.slots[pos]], &id)) return self.slots[pos];
            pos = (pos + 1) & self.mask;
        }
        unreachable;
    }

    fn insert(self: *Index, id: MessageId, entry: u32) void {
        assert(entry < self.ids.len);
        var pos = hashId(id) & self.mask;
        for (0..self.slots.len) |_| {
            if (self.slots[pos] == empty_slot) {
                self.slots[pos] = entry;
                return;
            }
            pos = (pos + 1) & self.mask;
        }
        unreachable;
    }

    fn remove(self: *Index, id: MessageId) void {
        var pos = hashId(id) & self.mask;
        var found = false;
        for (0..self.slots.len) |_| {
            if (self.slots[pos] == empty_slot) return;
            if (std.mem.eql(u8, &self.ids[self.slots[pos]], &id)) {
                found = true;
                break;
            }
            pos = (pos + 1) & self.mask;
        }
        assert(found);
        var hole = pos;
        pos = (pos + 1) & self.mask;
        for (0..self.slots.len) |_| {
            if (self.slots[pos] == empty_slot) {
                self.slots[hole] = empty_slot;
                return;
            }
            const home = hashId(self.ids[self.slots[pos]]) & self.mask;
            if ((pos -% home) & self.mask >= (pos -% hole) & self.mask) {
                self.slots[hole] = self.slots[pos];
                hole = pos;
            }
            pos = (pos + 1) & self.mask;
        }
        unreachable;
    }
};

/// A fixed-capacity FIFO set of message ids with a TTL, used to drop duplicates.
/// The oldest ids evict first, which is also TTL order since entries are added
/// in time order.
pub const SeenCache = struct {
    index: Index,
    ids: []MessageId,
    added_ms: []u64,
    capacity: usize,
    ttl_ms: u64,
    head: usize = 0,
    tail: usize = 0,
    count: usize = 0,

    pub fn init(allocator: Allocator, capacity: usize, ttl_ms: u64) Allocator.Error!SeenCache {
        assert(capacity > 0);
        const ids = try allocator.alloc(MessageId, capacity);
        errdefer allocator.free(ids);
        const added_ms = try allocator.alloc(u64, capacity);
        errdefer allocator.free(added_ms);
        var index = try Index.init(allocator, capacity, ids);
        errdefer index.deinit(allocator);
        return .{
            .index = index,
            .ids = ids,
            .added_ms = added_ms,
            .capacity = capacity,
            .ttl_ms = ttl_ms,
        };
    }

    pub fn deinit(self: *SeenCache, allocator: Allocator) void {
        self.index.deinit(allocator);
        allocator.free(self.added_ms);
        allocator.free(self.ids);
        self.* = undefined;
    }

    pub fn contains(self: *const SeenCache, id: MessageId, now_ms: u64) bool {
        const slot = self.index.find(id) orelse return false;
        return now_ms -| self.added_ms[slot] < self.ttl_ms;
    }

    /// Records `id` as seen and returns true when it was not already present.
    pub fn add(self: *SeenCache, id: MessageId, now_ms: u64) bool {
        self.pruneExpired(now_ms);
        if (self.contains(id, now_ms)) return false;
        if (self.count == self.capacity) self.evictOldest();
        const slot = self.head;
        self.ids[slot] = id;
        self.added_ms[slot] = now_ms;
        self.index.insert(id, @intCast(slot));
        self.head = (self.head + 1) % self.capacity;
        self.count += 1;
        return true;
    }

    fn evictOldest(self: *SeenCache) void {
        assert(self.count > 0);
        self.index.remove(self.ids[self.tail]);
        self.tail = (self.tail + 1) % self.capacity;
        self.count -= 1;
    }

    fn pruneExpired(self: *SeenCache, now_ms: u64) void {
        while (self.count > 0 and now_ms -| self.added_ms[self.tail] >= self.ttl_ms) {
            self.evictOldest();
        }
    }
};

const storage = @import("message_store.zig");
const PeerRef = @import("validation.zig").PeerRef;
pub const HistoryEntry = struct {
    next: u32 = empty_slot,
    prev: u32 = empty_slot,
    message: storage.Handle = undefined,
    window: u8 = 0,
    counts: []u8,
};
pub const History = struct {
    generations: []u64,
    counts: []u8,
    entries: []HistoryEntry,
    ids: []MessageId,
    index: Index,
    head: u32 = empty_slot,
    tail: u32 = empty_slot,
    free: u32 = 0,
    count: usize = 0,

    pub fn init(a: Allocator, capacity: usize) !History {
        return initCapacity(a, capacity, @import("peers.zig").capacity);
    }
    pub fn initCapacity(a: Allocator, capacity: usize, retained: u16) !History {
        if (retained == 0 or retained > @import("peers.zig").capacity) return error.InvalidLimits;
        if (capacity == 0 or capacity > 65536) return error.InvalidLimits;
        const entries = try a.alloc(HistoryEntry, capacity);
        errdefer a.free(entries);
        const ids = try a.alloc(MessageId, capacity);
        errdefer a.free(ids);
        const generations = try a.alloc(u64, retained);
        errdefer a.free(generations);
        @memset(generations, 0);
        const counts = try a.alloc(u8, capacity * retained);
        errdefer a.free(counts);
        @memset(counts, 0);
        const index = try Index.init(a, capacity, ids);
        for (entries, 0..) |*e, i| e.* = .{ .next = if (i + 1 == capacity) empty_slot else @intCast(i + 1), .counts = counts[i * retained ..][0..retained] };
        return .{ .entries = entries, .ids = ids, .index = index, .generations = generations, .counts = counts };
    }
    pub fn deinit(self: *History, a: Allocator) void {
        a.free(self.counts);
        a.free(self.generations);
        self.index.deinit(a);
        a.free(self.ids);
        a.free(self.entries);
        self.* = undefined;
    }
    pub fn admitPayload(self: *History, store: *storage.Store, id: MessageId, name: []const u8, bytes: []const u8) ?storage.Handle {
        for (0..self.entries.len) |_| {
            if (store.canReserve(bytes.len)) break;
            if (!self.evictOldest(store)) return null;
        }
        return store.put(id, name, bytes);
    }
    pub fn put(self: *History, store: *storage.Store, h: storage.Handle) void {
        const message = store.get(h).?;
        if (message.history) return;
        const id = message.id;
        if (self.index.find(id)) |old| self.remove(store, old);
        if (self.count == self.entries.len) _ = self.evictOldest(store);
        const slot = self.free;
        assert(slot != empty_slot);
        self.free = self.entries[slot].next;
        const counts = self.entries[slot].counts;
        @memset(counts, 0);
        self.entries[slot] = .{ .message = h, .prev = self.tail, .counts = counts };
        if (self.tail != empty_slot) self.entries[self.tail].next = slot else self.head = slot;
        self.tail = slot;
        self.ids[slot] = id;
        self.index.insert(id, slot);
        self.count += 1;
        store.retainHistory(h);
    }
    pub fn get(self: *History, store: *const storage.Store, id: MessageId) ?*HistoryEntry {
        const slot = self.index.find(id) orelse return null;
        const e = &self.entries[slot];
        assert(store.get(e.message) != null);
        return e;
    }
    /// Called only with a canonical admitted identity. Older references never reset a column.
    pub fn bindPeer(self: *History, peer: PeerRef) void {
        assert(peer.index < self.generations.len and peer.generation != 0);
        if (peer.generation <= self.generations[peer.index]) return;
        for (self.entries) |*entry| entry.counts[peer.index] = 0;
        self.generations[peer.index] = peer.generation;
    }
    pub fn iwantAllowed(self: *const History, e: *const HistoryEntry, peer: PeerRef, max: u8) bool {
        if (peer.index >= self.generations.len or peer.generation == 0) return false;
        return self.generations[peer.index] == peer.generation and e.counts[peer.index] < max;
    }
    pub fn sent(self: *const History, e: *HistoryEntry, peer: PeerRef) void {
        if (peer.index >= self.generations.len or peer.generation == 0) return;
        if (self.generations[peer.index] != peer.generation) return;
        assert(e.counts[peer.index] < 255);
        e.counts[peer.index] += 1;
    }
    pub fn evictOldest(self: *History, store: *storage.Store) bool {
        if (self.count == 0) return false;
        self.remove(store, self.head);
        return true;
    }
    fn remove(self: *History, store: *storage.Store, slot: u32) void {
        const e = &self.entries[slot];
        if (e.prev != empty_slot) self.entries[e.prev].next = e.next else self.head = e.next;
        if (e.next != empty_slot) self.entries[e.next].prev = e.prev else self.tail = e.prev;
        self.index.remove(self.ids[slot]);
        store.releaseHistory(e.message);
        e.next = self.free;
        self.free = slot;
        self.count -= 1;
    }
    pub fn shift(self: *History, store: *storage.Store) void {
        var slot = self.head;
        for (0..self.count) |_| {
            self.entries[slot].window +|= 1;
            slot = self.entries[slot].next;
        }
        for (0..self.entries.len) |_| {
            if (self.count == 0 or self.entries[self.head].window < constants.mcache_len) break;
            _ = self.evictOldest(store);
        }
    }
    pub fn gossip(self: *const History, store: *const storage.Store, name: []const u8, out: []MessageId) usize {
        var count: usize = 0;
        var slot = self.head;
        for (0..self.count) |_| {
            if (count == out.len) break;
            const e = &self.entries[slot];
            slot = e.next;
            const m = store.get(e.message).?;
            if (e.window >= constants.mcache_gossip or !std.mem.eql(u8, name, m.topicString())) continue;
            out[count] = m.id;
            count += 1;
        }
        return count;
    }
};

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

test "gossip history indexed replacement keeps FIFO age and independent TX retention" {
    var store = try storage.Store.init(std.testing.allocator, 4, 16384);
    defer store.deinit(std.testing.allocator);
    var history = try History.init(std.testing.allocator, 2);
    defer history.deinit(std.testing.allocator);
    const a = [_]u8{1} ** 20;
    const b = [_]u8{2} ** 20;
    const first = store.put(a, "a", "old").?;
    history.put(&store, first);
    store.seal(first);
    store.retainTx(first);
    const second = store.put(b, "b", "other").?;
    history.put(&store, second);
    store.seal(second);
    history.shift(&store);
    const replacement = store.put(a, "a", "new").?;
    history.put(&store, replacement);
    store.seal(replacement);
    try std.testing.expectEqual(@as(usize, 2), history.count);
    try std.testing.expectEqual(replacement, history.get(&store, a).?.message);
    try std.testing.expect(!store.get(first).?.history);
    for (0..constants.mcache_len - 1) |_| history.shift(&store);
    try std.testing.expect(history.get(&store, b) == null);
    try std.testing.expect(history.get(&store, a) != null);
    history.shift(&store);
    try std.testing.expectEqual(@as(usize, 0), history.count);
    store.releaseTx(first);
    try std.testing.expectEqual(@as(usize, 0), store.used_entries);
}

test "gossip ID index repairs a full admitted collision cluster" {
    var ids: [64]MessageId = undefined;
    var index = try Index.init(std.testing.allocator, ids.len, &ids);
    defer index.deinit(std.testing.allocator);
    for (&ids, 0..) |*id, i| {
        id.* = [_]u8{0} ** 20;
        id[19] = @intCast(i);
        index.insert(id.*, @intCast(i));
    }
    index.remove(ids[0]);
    for (1..ids.len) |i| try std.testing.expectEqual(@as(?u32, @intCast(i)), index.find(ids[i]));
    try std.testing.expect(index.find(ids[0]) == null);
}

test "gossip policy recovery permits more than sixteen distinct recipients" {
    var history = try History.init(std.testing.allocator, 2);
    defer history.deinit(std.testing.allocator);
    const entry = &history.entries[0];
    for (0..32) |i| {
        const peer: PeerRef = .{ .index = @intCast(i), .generation = 1 };
        history.bindPeer(peer);
        try std.testing.expect(history.iwantAllowed(entry, peer, 3));
        for (0..3) |_| history.sent(entry, peer);
        try std.testing.expect(!history.iwantAllowed(entry, peer, 3));
    }
    history.bindPeer(.{ .index = 0, .generation = 2 });
    try std.testing.expect(history.iwantAllowed(entry, .{ .index = 0, .generation = 2 }, 3));
}

test "gossip history entries keep peer generations outside message rows" {
    try std.testing.expect(@sizeOf(HistoryEntry) < 1024);
}

test "gossip history stale peer cannot restore retransmission allowance" {
    var history = try History.init(std.testing.allocator, 2);
    defer history.deinit(std.testing.allocator);
    const entry = &history.entries[0];
    const current: PeerRef = .{ .index = 0, .generation = (@as(u64, 1) << 40) + 2 };
    const stale: PeerRef = .{ .index = 0, .generation = current.generation - 1 };
    history.bindPeer(current);
    for (0..3) |_| history.sent(entry, current);
    try std.testing.expect(!history.iwantAllowed(entry, stale, 3));
    history.bindPeer(stale);
    history.sent(entry, stale);
    try std.testing.expect(!history.iwantAllowed(entry, current, 3));
}

test "gossip history replacement resets message retransmission counts" {
    var store = try storage.Store.init(std.testing.allocator, 4, 16384);
    defer store.deinit(std.testing.allocator);
    var history = try History.init(std.testing.allocator, 1);
    defer history.deinit(std.testing.allocator);
    const id: MessageId = @splat(1);
    const first = store.put(id, "t", "first").?;
    history.put(&store, first);
    store.seal(first);
    const peer: PeerRef = .{ .index = 0, .generation = 1 };
    history.bindPeer(peer);
    for (0..3) |_| history.sent(history.get(&store, id).?, peer);
    const replacement = store.put(id, "t", "replacement").?;
    history.put(&store, replacement);
    store.seal(replacement);
    try std.testing.expect(history.iwantAllowed(history.get(&store, id).?, peer, 3));
    try std.testing.expectEqual(@as(u8, 0), history.get(&store, id).?.counts[peer.index]);
    try std.testing.expectEqual(@as(usize, 1), store.used_entries);
}

test "gossip history canonical identity replacement clears only its bounded peer column" {
    var history = try History.init(std.testing.allocator, 3);
    defer history.deinit(std.testing.allocator);
    const peer: PeerRef = .{ .index = 0, .generation = (@as(u64, 1) << 40) + 1 };
    const other: PeerRef = .{ .index = 1, .generation = 1 };
    history.bindPeer(peer);
    history.bindPeer(other);
    for (history.entries) |*entry| {
        for (0..3) |_| history.sent(entry, peer);
        history.sent(entry, other);
    }
    history.bindPeer(peer);
    for (history.entries) |*entry| try std.testing.expect(!history.iwantAllowed(entry, peer, 3));
    const replacement: PeerRef = .{ .index = 0, .generation = std.math.maxInt(u64) };
    history.bindPeer(replacement);
    for (history.entries) |*entry| {
        try std.testing.expect(history.iwantAllowed(entry, replacement, 3));
        try std.testing.expect(!history.iwantAllowed(entry, peer, 3));
        try std.testing.expectEqual(@as(u8, 0), entry.counts[0]);
        try std.testing.expectEqual(@as(u8, 1), entry.counts[1]);
        for (0..3) |_| history.sent(entry, replacement);
    }
    history.bindPeer(peer);
    for (history.entries) |*entry| {
        history.sent(entry, peer);
        try std.testing.expect(!history.iwantAllowed(entry, replacement, 3));
    }
}

test "history resolved retained capacity bounds counters and stale peers" {
    var history = try History.initCapacity(std.testing.allocator, 2, 4);
    defer history.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 4), history.generations.len);
    try std.testing.expectEqual(@as(usize, 8), history.counts.len);
    try std.testing.expectEqual(@as(usize, 4), history.entries[0].counts.len);
    try std.testing.expect(!history.iwantAllowed(&history.entries[0], .{ .index = 4, .generation = 1 }, 3));
    history.sent(&history.entries[0], .{ .index = 4, .generation = 1 });
}
