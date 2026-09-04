const std = @import("std");
const constants = @import("constants.zig");
const topic_mod = @import("topic.zig");

const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const MessageId = [constants.message_id_length]u8;
const topic_max = topic_mod.topic_max_len;

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

/// Per-message validation state, mirroring rust-libp2p's DeliveryStatus. A
/// message starts `unknown` (received, awaiting the host verdict) and resolves
/// to one of the others, which decides how later duplicate senders are scored.
pub const Status = enum { unknown, valid, invalid, ignored };

/// The set of peers that sent a duplicate of a message before it resolved.
const DupSet = std.StaticBitSet(constants.peers_cap);

/// Outcome of recording a duplicate sender, driving the score credit/penalty.
pub const DupOutcome = enum { no_record, already, unknown, valid, invalid, ignored };

/// Per-message IWANT retransmission counts, one small table per cached message.
/// A message is served to a given peer at most `gossip_retransmission` times.
const iwant_peers_per_msg = 16;
const IwantTable = struct {
    peers: [iwant_peers_per_msg]u16 = undefined,
    counts: [iwant_peers_per_msg]u8 = undefined,
    len: u8 = 0,
};

/// Retains full messages for `mcache_len` heartbeat windows so the engine can
/// answer IWANT, and reports the ids to gossip about. Message data lives in one
/// byte ring; entries and data both evict oldest-first, in FIFO order.
pub const MessageCache = struct {
    index: Index,
    ids: []MessageId,
    topic: []u8,
    topic_len: []u8,
    data_off: []usize,
    data_len: []usize,
    window: []u8,
    status: []Status,
    source: []u16,
    source_gen: []u32,
    dup: []DupSet,
    iwant: []IwantTable,
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
        const topic = try allocator.alloc(u8, capacity * topic_max);
        errdefer allocator.free(topic);
        const topic_len = try allocator.alloc(u8, capacity);
        errdefer allocator.free(topic_len);
        const data_off = try allocator.alloc(usize, capacity);
        errdefer allocator.free(data_off);
        const data_len = try allocator.alloc(usize, capacity);
        errdefer allocator.free(data_len);
        const window = try allocator.alloc(u8, capacity);
        errdefer allocator.free(window);
        const status = try allocator.alloc(Status, capacity);
        errdefer allocator.free(status);
        const source = try allocator.alloc(u16, capacity);
        errdefer allocator.free(source);
        const source_gen = try allocator.alloc(u32, capacity);
        errdefer allocator.free(source_gen);
        const dup = try allocator.alloc(DupSet, capacity);
        errdefer allocator.free(dup);
        const iwant = try allocator.alloc(IwantTable, capacity);
        errdefer allocator.free(iwant);
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
            .status = status,
            .source = source,
            .source_gen = source_gen,
            .dup = dup,
            .iwant = iwant,
            .arena = arena,
            .capacity = capacity,
        };
    }

    pub fn deinit(self: *MessageCache, allocator: Allocator) void {
        self.index.deinit(allocator);
        allocator.free(self.arena);
        allocator.free(self.iwant);
        allocator.free(self.dup);
        allocator.free(self.source_gen);
        allocator.free(self.source);
        allocator.free(self.status);
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

    /// Stores a message in the current window, marked unvalidated and owned by
    /// `source`. Returns false when the data does not fit the arena even after
    /// evicting everything, leaving the cache clean.
    pub fn put(
        self: *MessageCache,
        id: MessageId,
        topic_str: []const u8,
        data: []const u8,
        source: u16,
        source_gen: u32,
    ) bool {
        if (data.len > self.arena.len or topic_str.len > topic_max) return false;
        if (self.contains(id)) return true;
        while (self.count == self.capacity or self.arena.len - self.data_used < data.len) {
            if (self.count == 0) return false;
            self.evictOldest();
        }
        const slot = self.entry_head;
        self.ids[slot] = id;
        @memcpy(self.topic[slot * topic_max ..][0..topic_str.len], topic_str);
        self.topic_len[slot] = @intCast(topic_str.len);
        self.data_off[slot] = self.data_head;
        self.data_len[slot] = data.len;
        self.window[slot] = 0;
        self.status[slot] = .unknown;
        self.source[slot] = source;
        self.source_gen[slot] = source_gen;
        self.dup[slot] = DupSet.initEmpty();
        self.iwant[slot] = .{};
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
        const topic_str = self.topic[slot * topic_max ..][0..self.topic_len[slot]];
        return .{ .topic = topic_str, .data = out[0..len] };
    }

    /// Marks a message validated so gossip and IWANT may offer it.
    pub fn validate(self: *MessageCache, id: MessageId) void {
        self.setStatus(id, .valid);
    }

    pub fn setStatus(self: *MessageCache, id: MessageId, status: Status) void {
        if (self.index.find(id)) |slot| self.status[slot] = status;
    }

    pub fn statusOf(self: *const MessageCache, id: MessageId) ?Status {
        const slot = self.index.find(id) orelse return null;
        return self.status[slot];
    }

    pub fn isValidated(self: *const MessageCache, id: MessageId) bool {
        const slot = self.index.find(id) orelse return false;
        return self.status[slot] == .valid;
    }

    /// Records `peer` as a duplicate sender of `id` (deduped per peer), returning
    /// what the caller should do based on the message's current status.
    pub fn recordDuplicate(self: *MessageCache, id: MessageId, peer: u16) DupOutcome {
        const slot = self.index.find(id) orelse return .no_record;
        if (self.dup[slot].isSet(peer)) return .already;
        self.dup[slot].set(peer);
        return switch (self.status[slot]) {
            .unknown => .unknown,
            .valid => .valid,
            .invalid => .invalid,
            .ignored => .ignored,
        };
    }

    /// The peers that sent a duplicate of `id` before it resolved.
    pub fn dupPeers(self: *const MessageCache, id: MessageId) ?*const DupSet {
        const slot = self.index.find(id) orelse return null;
        return &self.dup[slot];
    }

    /// The generation of the peer slot `id` arrived from, so the caller can
    /// detect the original sender disconnecting and its slot being reused.
    pub fn sourceGen(self: *const MessageCache, id: MessageId) ?u32 {
        const slot = self.index.find(id) orelse return null;
        return self.source_gen[slot];
    }

    /// Whether an IWANT for `id` from `peer` should be answered: the message must
    /// be cached and validated, and served to that peer at most `max` times.
    pub fn iwantAllowed(self: *MessageCache, id: MessageId, peer: u16, max: u8) bool {
        const slot = self.index.find(id) orelse return false;
        if (self.status[slot] != .valid) return false;
        const table = &self.iwant[slot];
        for (table.peers[0..table.len], 0..) |tracked, i| {
            if (tracked == peer) {
                if (table.counts[i] >= max) return false;
                table.counts[i] += 1;
                return true;
            }
        }
        if (table.len == table.peers.len) return false;
        table.peers[table.len] = peer;
        table.counts[table.len] = 1;
        table.len += 1;
        return true;
    }

    /// The topic of a cached message without copying its data.
    pub fn topicOf(self: *const MessageCache, id: MessageId) ?[]const u8 {
        const slot = self.index.find(id) orelse return null;
        return self.topic[slot * topic_max ..][0..self.topic_len[slot]];
    }

    /// The peer a cached message arrived from, or null when self-published.
    pub fn sourceOf(self: *const MessageCache, id: MessageId) ?u16 {
        const slot = self.index.find(id) orelse return null;
        const value = self.source[slot];
        return if (value == std.math.maxInt(u16)) null else value;
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
            const name = self.topic[slot * topic_max ..][0..self.topic_len[slot]];
            if (self.status[slot] == .valid and self.window[slot] < constants.mcache_gossip and
                std.mem.eql(u8, name, topic_str))
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
    try std.testing.expect(cache.put(id1, "topic_a", "hello world", 0, 0));
    var out: [64]u8 = undefined;
    const got = cache.get(id1, &out).?;
    try std.testing.expectEqualStrings("topic_a", got.topic);
    try std.testing.expectEqualStrings("hello world", got.data);

    var gossip_ids: [8]MessageId = undefined;
    // unvalidated messages are not gossiped
    try std.testing.expectEqual(@as(usize, 0), cache.gossip("topic_a", &gossip_ids));
    cache.validate(id1);
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
        try std.testing.expect(cache.put(id, "t", "0123456789", 0, 0));
    }
    // only the most recent messages survive the ring
    const last = cache.get([_]u8{5} ** 20, &out).?;
    try std.testing.expectEqualStrings("0123456789", last.data);
    try std.testing.expect(!cache.contains([_]u8{0} ** 20));
}
