const std = @import("std");
const storage = @import("message_store.zig");
const constants = @import("constants.zig");
const assert = std.debug.assert;
const none = std.math.maxInt(u32);

pub const per_peer_limit = 512;
pub const per_peer_reserve = 64;

pub const Transmission = struct {
    message: storage.Handle,
    enqueued_ms: u64,
    page: storage.Cursor,
    stage: enum { prefix, data, trailer, done } = .prefix,
    offset: usize = 0,

    fn init(store: *const storage.Store, message: storage.Handle, now: u64) Transmission {
        return .{ .message = message, .enqueued_ms = now, .page = store.cursor(message) };
    }

    pub fn segment(self: *const Transmission, store: *const storage.Store) []const u8 {
        const entry = store.get(self.message).?;
        return switch (self.stage) {
            .prefix => entry.prefix[0..entry.prefix_len][self.offset..],
            .data => store.segment(self.message, self.page),
            .trailer => entry.trailer[0 .. entry.topic_len + 2][self.offset..],
            .done => &.{},
        };
    }

    fn advance(self: *Transmission, store: *const storage.Store, len: usize) void {
        const segment_len = self.segment(store).len;
        assert(len > 0 and len <= segment_len);
        switch (self.stage) {
            .prefix, .trailer => {
                self.offset += len;
                if (len == segment_len) {
                    self.stage = if (self.stage == .trailer) .done else if (self.page.remaining == 0) .trailer else .data;
                    self.offset = 0;
                }
            },
            .data => {
                store.advance(&self.page, len);
                if (self.page.remaining == 0) self.stage = .trailer;
            },
            .done => unreachable,
        }
    }
};

const Slot = struct { tx: Transmission = undefined, next: u32 = none };

/// Empty queues retain a protected share of the pool. Above that share, a queue
/// can use only unreserved slots, up to its per-peer limit. Control uses no slots.
pub const Pool = struct {
    slots: []Slot,
    free: u32 = 0,
    available: usize,
    protected: usize,

    pub fn capacity(peers: usize, validations: usize) usize {
        assert(peers > 0 and peers <= constants.peers_cap);
        return peers * per_peer_reserve + @min(peers * (per_peer_limit - per_peer_reserve), @max(per_peer_limit - per_peer_reserve, validations * constants.mesh_d));
    }

    pub fn init(a: std.mem.Allocator, peers: usize, validations: usize) !Pool {
        return initCapacity(a, peers, capacity(peers, validations));
    }

    pub fn initCapacity(a: std.mem.Allocator, peers: usize, count: usize) !Pool {
        assert(peers > 0 and peers <= constants.peers_cap);
        assert(count >= peers * per_peer_reserve and count <= peers * per_peer_limit);
        const slots = try a.alloc(Slot, count);
        for (slots, 0..) |*slot, i| slot.* = .{ .next = if (i + 1 == count) none else @intCast(i + 1) };
        return .{ .slots = slots, .available = count, .protected = peers * per_peer_reserve };
    }

    pub fn deinit(self: *Pool, a: std.mem.Allocator) void {
        assert(self.available == self.slots.len);
        a.free(self.slots);
        self.* = undefined;
    }

    pub fn memoryBytes(count: usize) usize {
        return @sizeOf(Pool) + count * @sizeOf(Slot);
    }

    fn acquire(self: *Pool, queued: usize) ?u32 {
        assert(self.available >= self.protected and queued < per_peer_limit);
        if (queued >= per_peer_reserve and self.available == self.protected) return null;
        assert(self.free != none);
        const slot = self.free;
        self.free = self.slots[slot].next;
        self.slots[slot].next = none;
        self.available -= 1;
        if (queued < per_peer_reserve) self.protected -= 1;
        return slot;
    }

    fn release(self: *Pool, slot: u32, queued: usize) void {
        assert(queued > 0 and queued <= per_peer_limit and slot < self.slots.len);
        self.slots[slot].next = self.free;
        self.free = slot;
        self.available += 1;
        if (queued <= per_peer_reserve) self.protected += 1;
        assert(self.available >= self.protected and self.available <= self.slots.len);
    }
};

pub const Queue = struct {
    pool: *Pool,
    head: u32 = none,
    tail: u32 = none,
    count: usize = 0,
    bytes: usize = 0,
    bytes_high_water: usize = 0,
    descriptors_high_water: usize = 0,

    pub fn append(self: *Queue, store: *storage.Store, message: storage.Handle, byte_limit: usize, now: u64) error{ Descriptors, PoolFull, Bytes }!void {
        const entry = store.get(message).?;
        assert(!entry.provisional and self.bytes <= byte_limit);
        if (self.count == per_peer_limit) return error.Descriptors;
        if (entry.len > byte_limit - self.bytes) return error.Bytes;
        const slot = self.pool.acquire(self.count) orelse return error.PoolFull;
        self.pool.slots[slot].tx = Transmission.init(store, message, now);
        if (self.tail == none) self.head = slot else self.pool.slots[self.tail].next = slot;
        self.tail = slot;
        self.count += 1;
        self.bytes += entry.len;
        self.bytes_high_water = @max(self.bytes_high_water, self.bytes);
        self.descriptors_high_water = @max(self.descriptors_high_water, self.count);
        store.retainTx(message);
    }

    pub fn first(self: *const Queue) ?*const Transmission {
        return if (self.head == none) null else &self.pool.slots[self.head].tx;
    }

    pub fn advance(self: *Queue, store: *storage.Store, len: usize) bool {
        assert(self.count > 0);
        const tx = &self.pool.slots[self.head].tx;
        tx.advance(store, len);
        if (tx.stage != .done) return false;
        self.remove(store);
        return true;
    }

    fn remove(self: *Queue, store: *storage.Store) void {
        const slot = self.head;
        const message = self.pool.slots[slot].tx.message;
        self.head = self.pool.slots[slot].next;
        if (self.head == none) self.tail = none;
        self.bytes -= store.get(message).?.len;
        store.releaseTx(message);
        self.pool.release(slot, self.count);
        self.count -= 1;
    }

    pub fn reset(self: *Queue, store: *storage.Store) void {
        for (0..self.count) |_| self.remove(store);
        assert(self.head == none and self.tail == none and self.bytes == 0);
    }

    pub fn retains(self: *const Queue, message: storage.Handle) usize {
        var count: usize = 0;
        var slot = self.head;
        for (0..self.count) |_| {
            const entry = &self.pool.slots[slot];
            count += @intFromBool(std.meta.eql(entry.tx.message, message));
            slot = entry.next;
        }
        assert(slot == none);
        return count;
    }
};

test "gossip shared deliveries preserve every peer reserve under global pressure" {
    const a = std.testing.allocator;
    var pool = try Pool.init(a, 3, 1);
    defer pool.deinit(a);
    var store = try storage.Store.init(a, 1, storage.page_bytes);
    defer store.deinit(a);
    const message = store.put(@splat(1), "topic", "payload").?;
    store.retainHistory(message);
    store.seal(message);
    var queues: [3]Queue = @splat(.{ .pool = &pool });
    for (0..per_peer_limit) |_| try queues[0].append(&store, message, 8192, 1);
    try std.testing.expectError(error.Descriptors, queues[0].append(&store, message, 8192, 2));
    for (queues[1..]) |*queue| {
        for (0..per_peer_reserve) |_| try queue.append(&store, message, 8192, 3);
        try std.testing.expectError(error.PoolFull, queue.append(&store, message, 8192, 4));
    }
    try std.testing.expectEqual(@as(usize, 0), pool.available);
    try std.testing.expectEqual(@as(usize, 0), pool.protected);
    queues[1].reset(&store);
    try std.testing.expectError(error.PoolFull, queues[2].append(&store, message, 8192, 5));
    for (0..per_peer_reserve) |_| try queues[1].append(&store, message, 8192, 6);
    store.releaseHistory(message);
    for (&queues) |*queue| queue.reset(&store);
    try std.testing.expectEqual(@as(usize, 3 * per_peer_reserve), pool.protected);
    try std.testing.expectEqual(pool.slots.len, pool.available);
    try std.testing.expectEqual(@as(usize, 0), store.used_entries);
}

test "gossip delivery byte refusal acquires no descriptor or payload retain" {
    const a = std.testing.allocator;
    var pool = try Pool.init(a, 1, 1);
    defer pool.deinit(a);
    var store = try storage.Store.init(a, 1, storage.page_bytes);
    defer store.deinit(a);
    const message = store.put(@splat(1), "topic", "payload").?;
    store.retainHistory(message);
    store.seal(message);
    var queue: Queue = .{ .pool = &pool };
    try std.testing.expectError(error.Bytes, queue.append(&store, message, 6, 0));
    try std.testing.expectEqual(pool.slots.len, pool.available);
    try std.testing.expectEqual(@as(u32, 0), store.get(message).?.tx);
    store.releaseHistory(message);
}
