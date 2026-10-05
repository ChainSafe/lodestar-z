const std = @import("std");
const constants = @import("constants.zig");
const topic_mod = @import("topic.zig");
const peer_book = @import("peer_book.zig");

const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const MessageId = [constants.message_id_length]u8;

const empty_slot: u32 = std.math.maxInt(u32);

pub fn indexCapacity(capacity: usize) usize {
    return std.math.ceilPowerOfTwo(usize, @max(capacity * 2, 2)) catch unreachable;
}

/// Borrows stable keys from MessageId values or records with an `id` field.
/// Remove membership before overwriting a key. Backward-shift deletion can only
/// reduce displacement, so the insertion high-water bound also bounds misses.
pub fn IdIndex(comptime Entry: type) type {
    return KeyIndex(Entry, MessageId, if (Entry == MessageId) null else "id");
}

fn KeyIndex(comptime Entry: type, comptime Key: type, comptime field: ?[]const u8) type {
    return struct {
        const Self = @This();
        slots: []u32,
        entries: []Entry,
        mask: usize,
        probe_limit: usize = 0,
        seed: u64 = 0,

        pub fn init(allocator: Allocator, entries: []Entry) Allocator.Error!Self {
            const table_len = indexCapacity(entries.len);
            const slots = try allocator.alloc(u32, table_len);
            @memset(slots, empty_slot);
            return .{ .slots = slots, .entries = entries, .mask = table_len - 1 };
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            allocator.free(self.slots);
        }

        pub fn clear(self: *Self) void {
            @memset(self.slots, empty_slot);
            self.probe_limit = 0;
        }

        fn key(self: *const Self, entry: u32) *const Key {
            if (field) |name| return &@field(self.entries[entry], name);
            return &self.entries[entry];
        }

        fn bytes(value: *const Key) []const u8 {
            return if (Key == MessageId) value else value.*;
        }

        fn hash(self: *const Self, id: Key) usize {
            return @truncate(std.hash.Wyhash.hash(self.seed, bytes(&id)));
        }

        pub fn find(self: *const Self, id: Key) ?u32 {
            var pos = self.hash(id) & self.mask;
            for (0..self.probe_limit) |_| {
                if (self.slots[pos] == empty_slot) return null;
                if (std.mem.eql(u8, bytes(self.key(self.slots[pos])), bytes(&id))) return self.slots[pos];
                pos = (pos + 1) & self.mask;
            }
            return null;
        }

        pub fn insert(self: *Self, id: Key, entry: u32) void {
            assert(entry < self.entries.len and std.mem.eql(u8, bytes(self.key(entry)), bytes(&id)));
            var pos = self.hash(id) & self.mask;
            for (0..self.slots.len) |distance| {
                if (self.slots[pos] == empty_slot) {
                    self.slots[pos] = entry;
                    self.probe_limit = @max(self.probe_limit, distance + 1);
                    return;
                }
                pos = (pos + 1) & self.mask;
            }
            unreachable;
        }

        pub fn remove(self: *Self, id: Key) void {
            var pos = self.hash(id) & self.mask;
            var found = false;
            for (0..self.probe_limit) |_| {
                if (self.slots[pos] == empty_slot) return;
                if (std.mem.eql(u8, bytes(self.key(self.slots[pos])), bytes(&id))) {
                    found = true;
                    break;
                }
                pos = (pos + 1) & self.mask;
            }
            if (!found) return;
            var hole = pos;
            pos = (pos + 1) & self.mask;
            for (0..self.slots.len) |_| {
                if (self.slots[pos] == empty_slot) {
                    self.slots[hole] = empty_slot;
                    return;
                }
                const home = self.hash(self.key(self.slots[pos]).*) & self.mask;
                if ((pos -% home) & self.mask >= (pos -% hole) & self.mask) {
                    self.slots[hole] = self.slots[pos];
                    hole = pos;
                }
                pos = (pos + 1) & self.mask;
            }
            unreachable;
        }
    };
}

const Index = IdIndex(MessageId);

/// A fixed-capacity FIFO set of message ids with a TTL, used to drop duplicates.
/// The oldest ids evict first, which is also TTL order since entries are added
/// in time order.
pub const SeenCache = struct {
    index: Index,
    ids: []MessageId,
    added_ms: []u64,
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
        var index = try Index.init(allocator, ids);
        errdefer index.deinit(allocator);
        return .{
            .index = index,
            .ids = ids,
            .added_ms = added_ms,
            .ttl_ms = ttl_ms,
        };
    }

    pub fn backingBytes(capacity: usize) usize {
        return capacity * (@sizeOf(MessageId) + @sizeOf(u64)) + indexCapacity(capacity) * @sizeOf(u32);
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
        if (self.count == self.ids.len) self.evictOldest();
        const slot = self.head;
        self.ids[slot] = id;
        self.added_ms[slot] = now_ms;
        self.index.insert(id, @intCast(slot));
        self.head = (self.head + 1) % self.ids.len;
        self.count += 1;
        return true;
    }

    fn evictOldest(self: *SeenCache) void {
        assert(self.count > 0);
        self.index.remove(self.ids[self.tail]);
        self.tail = (self.tail + 1) % self.ids.len;
        self.count -= 1;
    }

    fn pruneExpired(self: *SeenCache, now_ms: u64) void {
        while (self.count > 0 and now_ms -| self.added_ms[self.tail] >= self.ttl_ms) {
            self.evictOldest();
        }
    }
};

const storage = @import("message_store.zig");
const PeerRef = @import("peer_book.zig").Ref;
pub const HistoryEntry = struct {
    next: u32 = empty_slot,
    prev: u32 = empty_slot,
    message: storage.Handle = undefined,
    born_epoch: u64 = 0,
    topic: u32 = empty_slot,
    topic_prev: u32 = empty_slot,
    topic_next: u32 = empty_slot,
    kind_prev: u32 = empty_slot,
    kind_next: u32 = empty_slot,
};
const KindList = struct { head: u32 = empty_slot, tail: u32 = empty_slot };
const HistoryTopic = struct {
    bytes: [topic_mod.topic_max_len]u8 = undefined,
    name: []const u8 = undefined,
    head: u32 = empty_slot,
    tail: u32 = empty_slot,
    next_free: u32 = empty_slot,
};

pub const History = struct {
    /// The hard ceiling on entries: retransmission counts cost `capacity × retained` bytes.
    pub const capacity_max = 65536;
    /// Entries of its kind a refused retention examines, oldest first, for copies to evict.
    const reclaim_scan = 64;

    generations: []u64,
    counts: []u8,
    entries: []HistoryEntry,
    ids: []MessageId,
    index: Index,
    topics: []HistoryTopic,
    topic_index: KeyIndex(HistoryTopic, []const u8, "name"),
    /// Each kind's entries, oldest first.
    kinds: [@typeInfo(topic_mod.Kind).@"enum".fields.len]KindList = @splat(.{}),
    free_topic: u32 = 0,
    /// Entries `gossip` examined, which the bounded-work test reads.
    gossip_entries_visited: u64 = 0,
    head: u32 = empty_slot,
    tail: u32 = empty_slot,
    free: u32 = 0,
    count: usize = 0,

    pub fn init(a: Allocator, capacity: usize, retained: u16) !History {
        if (retained == 0 or retained > peer_book.capacity) return error.InvalidLimits;
        if (capacity == 0 or capacity > capacity_max) return error.InvalidLimits;
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
        var index = try Index.init(a, ids);
        errdefer index.deinit(a);
        const topics = try a.alloc(HistoryTopic, capacity);
        errdefer a.free(topics);
        const topic_index = try KeyIndex(HistoryTopic, []const u8, "name").init(a, topics);
        for (topics, 0..) |*t, i| t.* = .{ .next_free = if (i + 1 == capacity) empty_slot else @intCast(i + 1) };
        for (entries, 0..) |*e, i| e.* = .{ .next = if (i + 1 == capacity) empty_slot else @intCast(i + 1) };
        return .{ .entries = entries, .ids = ids, .index = index, .generations = generations, .counts = counts, .topics = topics, .topic_index = topic_index };
    }
    pub fn backingBytes(capacity: usize, retained: usize) usize {
        return capacity * (@sizeOf(HistoryEntry) + @sizeOf(HistoryTopic) + @sizeOf(MessageId) + retained) +
            retained * @sizeOf(u64) + 2 * indexCapacity(capacity) * @sizeOf(u32);
    }

    /// Frees backing storage during joint History/Store destruction. Live eviction uses remove.
    pub fn deinit(self: *History, a: Allocator) void {
        self.topic_index.deinit(a);
        a.free(self.topics);
        a.free(self.counts);
        a.free(self.generations);
        self.index.deinit(a);
        a.free(self.ids);
        a.free(self.entries);
        self.* = undefined;
    }
    pub fn canAdmitPayload(self: *const History, store: *const storage.Store, len: usize, free_pages: usize, free_entries: usize) bool {
        const required = storage.Store.pagesFor(len);
        var pages = free_pages;
        var entries = free_entries;
        if (pages >= required and entries > 0) return true;
        var slot = self.head;
        for (0..self.count) |_| {
            const entry = store.get(self.entries[slot].message).?;
            slot = self.entries[slot].next;
            if (!reclaimable(entry)) continue;
            pages += storage.Store.pagesFor(entry.len);
            entries += @intFromBool(entry.generation != std.math.maxInt(u64));
            if (pages >= required and entries > 0) return true;
        }
        return false;
    }

    pub fn admitPayload(self: *History, store: *storage.Store, id: MessageId, name: []const u8, bytes: []const u8) ?storage.Handle {
        if (!store.canReserve(bytes.len)) {
            if (!self.canAdmitPayload(store, bytes.len, store.free_pages, store.entries.len - store.used_entries - store.retired_entries)) return null;
            var slot = self.head;
            const count = self.count;
            for (0..count) |_| {
                if (store.canReserve(bytes.len)) break;
                const candidate = slot;
                slot = self.entries[slot].next;
                if (reclaimable(store.get(self.entries[candidate].message).?)) self.remove(store, candidate);
            }
            assert(store.canReserve(bytes.len));
        }
        return store.put(id, name, bytes);
    }
    fn reclaimable(e: *const storage.Entry) bool {
        return e.history and !e.provisional and !e.validation and e.tx == 0;
    }
    pub fn put(self: *History, store: *storage.Store, h: storage.Handle, epoch: u64) void {
        if (self.tail != empty_slot) assert(self.entries[self.tail].born_epoch <= epoch);
        const payload = store.get(h).?;
        if (payload.history) return;
        const id = payload.id;
        if (self.index.find(id)) |old| self.remove(store, old);
        if (self.count == self.entries.len) self.remove(store, self.head);
        const topic = self.topic_index.find(payload.topicString()) orelse blk: {
            const index = self.free_topic;
            assert(index != empty_slot);
            const t = &self.topics[index];
            self.free_topic = t.next_free;
            t.* = .{};
            @memcpy(t.bytes[0..payload.topic_len], payload.topicString());
            t.name = t.bytes[0..payload.topic_len];
            self.topic_index.insert(t.name, index);
            break :blk index;
        };
        const topic_list = &self.topics[topic];
        const kind_list = &self.kinds[@intFromEnum(payload.kind)];
        const slot = self.free;
        assert(slot != empty_slot);
        self.free = self.entries[slot].next;
        @memset(self.countsRow(slot), 0);
        self.entries[slot] = .{ .message = h, .prev = self.tail, .born_epoch = epoch, .topic = topic, .topic_prev = topic_list.tail, .kind_prev = kind_list.tail };
        if (topic_list.tail != empty_slot) self.entries[topic_list.tail].topic_next = slot else topic_list.head = slot;
        topic_list.tail = slot;
        if (kind_list.tail != empty_slot) self.entries[kind_list.tail].kind_next = slot else kind_list.head = slot;
        kind_list.tail = slot;
        if (self.tail != empty_slot) self.entries[self.tail].next = slot else self.head = slot;
        self.tail = slot;
        self.ids[slot] = id;
        self.index.insert(id, slot);
        self.count += 1;
        store.retainHistory(h);
    }
    /// The slot remains valid until the next history mutation in this owner call.
    pub fn get(self: *const History, store: *const storage.Store, id: MessageId) ?u32 {
        const slot = self.index.find(id) orelse return null;
        const e = &self.entries[slot];
        assert(store.get(e.message) != null);
        return slot;
    }

    pub fn message(self: *const History, slot: u32) storage.Handle {
        return self.entries[slot].message;
    }

    pub fn countsRow(self: *const History, slot: u32) []u8 {
        assert(slot < self.entries.len);
        return self.counts[@as(usize, slot) * self.generations.len ..][0..self.generations.len];
    }

    /// Called only with a canonical admitted identity. Older references never reset a column.
    pub fn bindPeer(self: *History, peer: PeerRef) void {
        assert(peer.index < self.generations.len and peer.generation != 0);
        if (peer.generation <= self.generations[peer.index]) return;
        for (0..self.entries.len) |slot| self.countsRow(@intCast(slot))[peer.index] = 0;
        self.generations[peer.index] = peer.generation;
    }
    pub fn iwantAllowed(self: *const History, slot: u32, peer: PeerRef, max: u8) bool {
        if (peer.index >= self.generations.len or peer.generation == 0) return false;
        return self.generations[peer.index] == peer.generation and self.countsRow(slot)[peer.index] < max;
    }
    pub fn sent(self: *const History, slot: u32, peer: PeerRef) void {
        if (peer.index >= self.generations.len or peer.generation == 0) return;
        if (self.generations[peer.index] != peer.generation) return;
        assert(self.countsRow(slot)[peer.index] < 255);
        self.countsRow(slot)[peer.index] += 1;
    }
    /// Whether `handle` fits its kind's retention allowance, evicting old copies of its kind to
    /// make room: a new message is worth more than an old copy, and a message the history cannot
    /// retain is not forwarded. Victims are chosen among the kind's `reclaim_scan` oldest entries,
    /// from those whose eviction frees retention the message lacks, and are evicted only when
    /// together they free enough; otherwise the history is unchanged.
    pub fn makeRoom(self: *History, store: *storage.Store, handle: storage.Handle) bool {
        const lacking = store.retentionShortfall(handle);
        if (lacking.pages == 0 and lacking.entries == 0) return true;
        var victims: [reclaim_scan]u32 = undefined;
        var chosen: usize = 0;
        var pages: usize = 0;
        var slot = self.kinds[@intFromEnum(store.get(handle).?.kind)].head;
        for (0..reclaim_scan) |_| {
            if (slot == empty_slot or (pages >= lacking.pages and chosen >= lacking.entries)) break;
            const entry = store.get(self.entries[slot].message).?;
            const freed = storage.Store.pagesFor(entry.len);
            if (reclaimable(entry) and (chosen < lacking.entries or (freed > 0 and pages < lacking.pages))) {
                victims[chosen] = slot;
                chosen += 1;
                pages += freed;
            }
            slot = self.entries[slot].kind_next;
        }
        if (pages < lacking.pages or chosen < lacking.entries) return false;
        for (victims[0..chosen]) |victim| self.remove(store, victim);
        assert(store.canRetain(handle));
        return true;
    }

    fn remove(self: *History, store: *storage.Store, slot: u32) void {
        const e = &self.entries[slot];
        const t = &self.topics[e.topic];
        if (e.topic_prev != empty_slot) self.entries[e.topic_prev].topic_next = e.topic_next else t.head = e.topic_next;
        if (e.topic_next != empty_slot) self.entries[e.topic_next].topic_prev = e.topic_prev else t.tail = e.topic_prev;
        const kind_list = &self.kinds[@intFromEnum(store.get(e.message).?.kind)];
        if (e.kind_prev != empty_slot) self.entries[e.kind_prev].kind_next = e.kind_next else kind_list.head = e.kind_next;
        if (e.kind_next != empty_slot) self.entries[e.kind_next].kind_prev = e.kind_prev else kind_list.tail = e.kind_prev;
        if (t.head == empty_slot) {
            assert(t.tail == empty_slot);
            self.topic_index.remove(t.name);
            t.next_free = self.free_topic;
            self.free_topic = e.topic;
        }
        if (e.prev != empty_slot) self.entries[e.prev].next = e.next else self.head = e.next;
        if (e.next != empty_slot) self.entries[e.next].prev = e.prev else self.tail = e.prev;
        self.index.remove(self.ids[slot]);
        store.releaseHistory(e.message);
        e.next = self.free;
        self.free = slot;
        self.count -= 1;
    }
    pub fn age(self: *History, store: *storage.Store, epoch: u64) void {
        for (0..self.entries.len) |_| {
            if (self.count == 0) break;
            assert(self.entries[self.head].born_epoch <= epoch);
            if (epoch - self.entries[self.head].born_epoch < constants.mcache_len) break;
            self.remove(store, self.head);
        }
    }
    pub fn gossip(self: *History, name: []const u8, out: []MessageId, epoch: u64) usize {
        const topic = self.topic_index.find(name) orelse return 0;
        var count: usize = 0;
        var slot = self.topics[topic].head;
        for (0..self.count) |_| {
            if (slot == empty_slot or count == out.len) break;
            const e = &self.entries[slot];
            const id = self.ids[slot];
            slot = e.topic_next;
            self.gossip_entries_visited +|= 1;
            assert(e.born_epoch <= epoch);
            // Arrivals in this epoch receive their first advertising window in the next one.
            const windows = epoch - e.born_epoch;
            if (windows == 0) break;
            if (windows > constants.mcache_gossip) continue;
            out[count] = id;
            count += 1;
        }
        return count;
    }
};

test {
    _ = @import("mcache_test.zig");
}
