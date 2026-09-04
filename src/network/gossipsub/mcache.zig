const std = @import("std");
const constants = @import("constants.zig");

const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const MessageId = [constants.message_id_length]u8;

const empty_slot: u32 = std.math.maxInt(u32);

fn hashId(id: MessageId) usize {
    // Message ids are already SHA-256 truncations, so the low bytes are uniform.
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
        while (self.slots[pos] != empty_slot) : (pos = (pos + 1) & self.mask) {
            if (std.mem.eql(u8, &self.ids[self.slots[pos]], &id)) return self.slots[pos];
        }
        return null;
    }

    fn insert(self: *Index, id: MessageId, entry: u32) void {
        var pos = hashId(id) & self.mask;
        while (self.slots[pos] != empty_slot) : (pos = (pos + 1) & self.mask) {}
        self.slots[pos] = entry;
    }

    fn remove(self: *Index, id: MessageId) void {
        var pos = hashId(id) & self.mask;
        while (self.slots[pos] != empty_slot) : (pos = (pos + 1) & self.mask) {
            if (std.mem.eql(u8, &self.ids[self.slots[pos]], &id)) break;
        } else return;
        // Backward-shift deletion keeps the probe chains intact.
        var hole = pos;
        pos = (pos + 1) & self.mask;
        while (self.slots[pos] != empty_slot) : (pos = (pos + 1) & self.mask) {
            const home = hashId(self.ids[self.slots[pos]]) & self.mask;
            const shift = (pos -% home) & self.mask >= (pos -% hole) & self.mask;
            if (shift) {
                self.slots[hole] = self.slots[pos];
                hole = pos;
            }
        }
        self.slots[hole] = empty_slot;
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

    pub fn contains(self: *const SeenCache, id: MessageId) bool {
        return self.index.find(id) != null;
    }

    /// Records `id` as seen and returns true when it was not already present.
    pub fn add(self: *SeenCache, id: MessageId, now_ms: u64) bool {
        if (self.contains(id)) return false;
        self.pruneExpired(now_ms);
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

pub const Cached = struct {
    topic: []const u8,
    data: []const u8,
};

/// Retains full messages for `mcache_len` heartbeat windows so the engine can
/// answer IWANT, and reports the ids to gossip about. Message data lives in one
/// byte ring; entries and data both evict oldest-first, in FIFO order.
pub const MessageCache = struct {
    index: Index,
    ids: []MessageId,
    topic: []MessageId,
    topic_len: []u8,
    data_off: []usize,
    data_len: []usize,
    window: []u8,
    arena: []u8,
    capacity: usize,
    entry_head: usize = 0,
    entry_tail: usize = 0,
    count: usize = 0,
    data_head: usize = 0,
    data_used: usize = 0,

    pub fn init(
        allocator: Allocator,
        capacity: usize,
        arena_bytes: usize,
    ) Allocator.Error!MessageCache {
        assert(capacity > 0);
        const ids = try allocator.alloc(MessageId, capacity);
        errdefer allocator.free(ids);
        const topic = try allocator.alloc(MessageId, capacity);
        errdefer allocator.free(topic);
        const topic_len = try allocator.alloc(u8, capacity);
        errdefer allocator.free(topic_len);
        const data_off = try allocator.alloc(usize, capacity);
        errdefer allocator.free(data_off);
        const data_len = try allocator.alloc(usize, capacity);
        errdefer allocator.free(data_len);
        const window = try allocator.alloc(u8, capacity);
        errdefer allocator.free(window);
        const arena = try allocator.alloc(u8, arena_bytes);
        errdefer allocator.free(arena);
        var index = try Index.init(allocator, capacity, ids);
        errdefer index.deinit(allocator);
        return .{
            .index = index,
            .ids = ids,
            .topic = topic,
            .topic_len = topic_len,
            .data_off = data_off,
            .data_len = data_len,
            .window = window,
            .arena = arena,
            .capacity = capacity,
        };
    }

    pub fn deinit(self: *MessageCache, allocator: Allocator) void {
        self.index.deinit(allocator);
        allocator.free(self.arena);
        allocator.free(self.window);
        allocator.free(self.data_len);
        allocator.free(self.data_off);
        allocator.free(self.topic_len);
        allocator.free(self.topic);
        allocator.free(self.ids);
        self.* = undefined;
    }

    pub fn contains(self: *const MessageCache, id: MessageId) bool {
        return self.index.find(id) != null;
    }

    /// Stores a message in the current window. Returns false when the data does
    /// not fit the arena even after evicting everything, leaving the cache clean.
    pub fn put(self: *MessageCache, id: MessageId, topic_str: []const u8, data: []const u8) bool {
        if (data.len > self.arena.len or topic_str.len > constants.message_id_length) return false;
        if (self.contains(id)) return true;
        while (self.count == self.capacity or self.arena.len - self.data_used < data.len) {
            if (self.count == 0) return false;
            self.evictOldest();
        }
        const slot = self.entry_head;
        self.ids[slot] = id;
        @memcpy(self.topic[slot][0..topic_str.len], topic_str);
        self.topic_len[slot] = @intCast(topic_str.len);
        self.data_off[slot] = self.data_head;
        self.data_len[slot] = data.len;
        self.window[slot] = 0;
        writeRing(self.arena, self.data_head, data);
        self.data_head = (self.data_head + data.len) % self.arena.len;
        self.data_used += data.len;
        self.index.insert(id, @intCast(slot));
        self.entry_head = (self.entry_head + 1) % self.capacity;
        self.count += 1;
        return true;
    }

    /// Copies a cached message into `out` when present and it fits.
    pub fn get(self: *const MessageCache, id: MessageId, out: []u8) ?Cached {
        const slot = self.index.find(id) orelse return null;
        const len = self.data_len[slot];
        if (len > out.len) return null;
        readRing(self.arena, self.data_off[slot], out[0..len]);
        return .{ .topic = self.topic[slot][0..self.topic_len[slot]], .data = out[0..len] };
    }

    /// Advances every entry one heartbeat window and drops those that aged out.
    pub fn shift(self: *MessageCache) void {
        var seen: usize = 0;
        var slot = self.entry_tail;
        while (seen < self.count) : (seen += 1) {
            if (self.window[slot] < 255) self.window[slot] += 1;
            slot = (slot + 1) % self.capacity;
        }
        while (self.count > 0 and self.window[self.entry_tail] >= constants.mcache_len) {
            self.evictOldest();
        }
    }

    /// Writes the ids in the gossip windows for `topic_str` into `out`, returning
    /// the count written.
    pub fn gossip(self: *const MessageCache, topic_str: []const u8, out: []MessageId) usize {
        var written: usize = 0;
        var seen: usize = 0;
        var slot = self.entry_tail;
        while (seen < self.count and written < out.len) : (seen += 1) {
            if (self.window[slot] < constants.mcache_gossip and
                std.mem.eql(u8, self.topic[slot][0..self.topic_len[slot]], topic_str))
            {
                out[written] = self.ids[slot];
                written += 1;
            }
            slot = (slot + 1) % self.capacity;
        }
        return written;
    }

    fn evictOldest(self: *MessageCache) void {
        assert(self.count > 0);
        const slot = self.entry_tail;
        self.index.remove(self.ids[slot]);
        self.data_used -= self.data_len[slot];
        self.entry_tail = (self.entry_tail + 1) % self.capacity;
        self.count -= 1;
    }
};

fn writeRing(arena: []u8, at: usize, data: []const u8) void {
    const first = @min(data.len, arena.len - at);
    @memcpy(arena[at..][0..first], data[0..first]);
    if (first < data.len) @memcpy(arena[0 .. data.len - first], data[first..]);
}

fn readRing(arena: []const u8, at: usize, out: []u8) void {
    const first = @min(out.len, arena.len - at);
    @memcpy(out[0..first], arena[at..][0..first]);
    if (first < out.len) @memcpy(out[first..], arena[0 .. out.len - first]);
}

test "seen cache dedupes, evicts oldest when full, and expires by ttl" {
    var cache = try SeenCache.init(std.testing.allocator, 4, 1_000);
    defer cache.deinit(std.testing.allocator);
    const a = [_]u8{1} ** 20;
    const b = [_]u8{2} ** 20;
    try std.testing.expect(cache.add(a, 0));
    try std.testing.expect(!cache.add(a, 0));
    try std.testing.expect(cache.contains(a));
    try std.testing.expect(cache.add(b, 100));
    // fill past capacity: a evicts
    try std.testing.expect(cache.add([_]u8{3} ** 20, 200));
    try std.testing.expect(cache.add([_]u8{4} ** 20, 300));
    try std.testing.expect(cache.add([_]u8{5} ** 20, 400));
    try std.testing.expect(!cache.contains(a));
    try std.testing.expect(cache.contains(b));
    // ttl expiry from the tail
    try std.testing.expect(cache.add([_]u8{6} ** 20, 1_500));
    try std.testing.expect(!cache.contains(b));
}

test "message cache stores, answers get, gossips windows, and ages out" {
    var cache = try MessageCache.init(std.testing.allocator, 8, 1024);
    defer cache.deinit(std.testing.allocator);
    const id1 = [_]u8{1} ** 20;
    try std.testing.expect(cache.put(id1, "topic_a", "hello world"));
    var out: [64]u8 = undefined;
    const got = cache.get(id1, &out).?;
    try std.testing.expectEqualStrings("topic_a", got.topic);
    try std.testing.expectEqualStrings("hello world", got.data);

    var gossip_ids: [8]MessageId = undefined;
    try std.testing.expectEqual(@as(usize, 1), cache.gossip("topic_a", &gossip_ids));
    try std.testing.expectEqual(@as(usize, 0), cache.gossip("topic_b", &gossip_ids));

    // after mcache_gossip shifts it leaves the gossip window, after mcache_len it is dropped
    var i: usize = 0;
    while (i < constants.mcache_gossip) : (i += 1) cache.shift();
    try std.testing.expectEqual(@as(usize, 0), cache.gossip("topic_a", &gossip_ids));
    try std.testing.expect(cache.contains(id1));
    while (i < constants.mcache_len) : (i += 1) cache.shift();
    try std.testing.expect(!cache.contains(id1));
    try std.testing.expect(cache.get(id1, &out) == null);
}

test "message cache evicts oldest and wraps data around the arena" {
    var cache = try MessageCache.init(std.testing.allocator, 8, 32);
    defer cache.deinit(std.testing.allocator);
    var out: [64]u8 = undefined;
    // fill the 32-byte arena with 10-byte messages; the third eviction wraps
    var n: u8 = 0;
    while (n < 6) : (n += 1) {
        const id = [_]u8{n} ** 20;
        try std.testing.expect(cache.put(id, "t", "0123456789"));
    }
    // only the most recent messages survive the ring
    const last = cache.get([_]u8{5} ** 20, &out).?;
    try std.testing.expectEqualStrings("0123456789", last.data);
    try std.testing.expect(!cache.contains([_]u8{0} ** 20));
}
