const std = @import("std");
const storage = @import("message_store.zig");
const constants = @import("constants.zig");
const assert = std.debug.assert;
const none = std.math.maxInt(u32);

pub const per_peer_limit = 512;
pub const per_peer_reserve = 64;

/// What produced a queued frame. Each delivery attempt has its own origin, so an IWANT response
/// for a message we published is `iwant`.
pub const Origin = enum { forward, publication, iwant };
pub const origin_count = @typeInfo(Origin).@"enum".fields.len;

pub const Transmission = struct {
    message: storage.Handle,
    enqueued_ms: u64,
    origin: Origin,
    cursor: storage.FrameCursor,

    pub fn segment(self: *const Transmission, store: *const storage.Store) []const u8 {
        return store.frameSegment(self.message, self.cursor);
    }
};

/// A frame that QUIC accepted in full.
pub const Receipt = struct { origin: Origin, enqueued_ms: u64 };

const Slot = struct { tx: Transmission = undefined, next: u32 = none };

/// Empty queues retain a protected share of the pool. Above that share, a queue
/// can use only unreserved slots, up to its per-peer limit. Control uses no slots.
pub const Pool = struct {
    slots: []Slot,
    free: u32 = 0,
    available: usize,
    protected: usize,
    /// Each peer's descriptors that only local publications may use.
    local_descriptors: usize = 0,

    pub fn capacity(peers: usize, validations: usize) usize {
        assert(peers > 0 and peers <= constants.peers_cap);
        return peers * per_peer_reserve + @min(peers * (per_peer_limit - per_peer_reserve), @max(per_peer_limit - per_peer_reserve, validations * constants.mesh_d));
    }

    pub fn init(a: std.mem.Allocator, peers: usize, count: usize) !Pool {
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

    pub fn backingBytes(count: usize) usize {
        return count * @sizeOf(Slot);
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

/// Local publications queue apart from ordinary frames, which are forwards and IWANT responses.
/// Both classes share the peer's descriptor and byte limits and the pool's per-peer protected
/// share, which follows the combined count.
pub const Class = enum { local, ordinary };

/// Per-peer byte limits. Ordinary frames leave the unused part of the local reserve, and of the
/// pool's local descriptors, free; local publications may use the reserve and any other room.
pub const Limits = struct { bytes: usize, local_bytes: usize = 0 };

/// Local frames chosen in a row while an ordinary frame waits, by count or bytes, before the
/// ordinary frame goes next.
const local_run_frames = 4;
const local_run_bytes = 64 * 1024;

const Fifo = struct { head: u32 = none, tail: u32 = none };

pub const Queue = struct {
    pool: *Pool,
    fifos: [2]Fifo = @splat(.{}),
    origins: [origin_count]usize = @splat(0),
    count: usize = 0,
    bytes: usize = 0,
    local_bytes: usize = 0,
    /// The class of the frame being written. It stays chosen until the frame completes, so
    /// frames never interleave.
    current: ?Class = null,
    /// Local frames and their bytes chosen in a row while an ordinary frame waited.
    run_frames: usize = 0,
    run_bytes: usize = 0,
    bytes_high_water: usize = 0,
    descriptors_high_water: usize = 0,

    pub fn classOf(origin: Origin) Class {
        return if (origin == .publication) .local else .ordinary;
    }

    pub fn classCount(self: *const Queue, class: Class) usize {
        const local = self.origins[@intFromEnum(Origin.publication)];
        return if (class == .local) local else self.count - local;
    }

    pub fn append(self: *Queue, store: *storage.Store, message: storage.Handle, origin: Origin, limits: Limits, now: u64) error{ Descriptors, PoolFull, Bytes }!void {
        const entry = store.get(message).?;
        assert(!entry.provisional and self.bytes <= limits.bytes);
        assert(self.pool.local_descriptors < per_peer_limit and limits.local_bytes <= limits.bytes);
        const class = classOf(origin);
        const reserved_bytes = if (class == .local) 0 else limits.local_bytes -| self.local_bytes;
        if (if (class == .local) self.count >= per_peer_limit else self.full()) return error.Descriptors;
        if (entry.len + reserved_bytes > limits.bytes - self.bytes) return error.Bytes;
        const slot = self.pool.acquire(self.count) orelse return error.PoolFull;
        self.pool.slots[slot].tx = .{ .message = message, .enqueued_ms = now, .origin = origin, .cursor = store.frameCursor(message) };
        const fifo = &self.fifos[@intFromEnum(class)];
        if (fifo.tail == none) fifo.head = slot else self.pool.slots[fifo.tail].next = slot;
        fifo.tail = slot;
        self.count += 1;
        self.origins[@intFromEnum(origin)] += 1;
        self.bytes += entry.len;
        if (class == .local) self.local_bytes += entry.len;
        self.bytes_high_water = @max(self.bytes_high_water, self.bytes);
        self.descriptors_high_water = @max(self.descriptors_high_water, self.count);
        store.retainTx(message);
    }

    /// Whether an ordinary frame would be refused for want of a descriptor.
    pub fn full(self: *const Queue) bool {
        return self.count + (self.pool.local_descriptors -| self.classCount(.local)) >= per_peer_limit;
    }

    /// The frame to write next. A frame in progress continues. At a frame boundary a local frame
    /// goes first, unless a full run of them already went while an ordinary frame waited.
    pub fn next(self: *Queue, store: *const storage.Store) ?*const Transmission {
        if (self.count == 0) return null;
        const class = self.current orelse self.choose(store);
        self.current = class;
        return &self.pool.slots[self.fifos[@intFromEnum(class)].head].tx;
    }

    fn choose(self: *Queue, store: *const storage.Store) Class {
        const waiting = self.classCount(.ordinary) > 0;
        if (self.classCount(.local) > 0 and (!waiting or (self.run_frames < local_run_frames and self.run_bytes < local_run_bytes))) {
            if (waiting) {
                self.run_frames += 1;
                self.run_bytes += store.get(self.pool.slots[self.fifos[@intFromEnum(Class.local)].head].tx.message).?.frameLen();
            } else self.endRun();
            return .local;
        }
        self.endRun();
        return .ordinary;
    }

    fn endRun(self: *Queue) void {
        self.run_frames = 0;
        self.run_bytes = 0;
    }

    pub fn oldest(self: *const Queue) ?u64 {
        var result: ?u64 = null;
        for (self.fifos) |fifo| if (fifo.head != none) {
            const since = self.pool.slots[fifo.head].tx.enqueued_ms;
            result = @min(result orelse since, since);
        };
        return result;
    }

    /// Moves the chosen frame past `len` sent bytes, and removes it once QUIC holds all of it.
    pub fn advance(self: *Queue, store: *storage.Store, len: usize) ?Receipt {
        const class = self.current.?;
        const tx = &self.pool.slots[self.fifos[@intFromEnum(class)].head].tx;
        if (!store.advanceFrame(tx.message, &tx.cursor, len)) return null;
        const receipt: Receipt = .{ .origin = tx.origin, .enqueued_ms = tx.enqueued_ms };
        self.remove(store, class);
        self.current = null;
        return receipt;
    }

    fn remove(self: *Queue, store: *storage.Store, class: Class) void {
        const fifo = &self.fifos[@intFromEnum(class)];
        const slot = fifo.head;
        const tx = &self.pool.slots[slot].tx;
        const len = store.get(tx.message).?.len;
        fifo.head = self.pool.slots[slot].next;
        if (fifo.head == none) fifo.tail = none;
        self.origins[@intFromEnum(tx.origin)] -= 1;
        self.bytes -= len;
        if (class == .local) self.local_bytes -= len;
        store.releaseTx(tx.message);
        self.pool.release(slot, self.count);
        self.count -= 1;
    }

    pub fn reset(self: *Queue, store: *storage.Store) void {
        for (0..self.count) |_| self.remove(store, if (self.classCount(.local) > 0) .local else .ordinary);
        assert(self.count == 0 and self.bytes == 0 and self.local_bytes == 0);
        assert(self.fifos[0].head == none and self.fifos[1].head == none);
        self.current = null;
        self.endRun();
    }

    pub fn retains(self: *const Queue, message: storage.Handle) usize {
        var count: usize = 0;
        for (self.fifos) |fifo| {
            var slot = fifo.head;
            for (0..self.count) |_| {
                if (slot == none) break;
                count += @intFromBool(std.meta.eql(self.pool.slots[slot].tx.message, message));
                slot = self.pool.slots[slot].next;
            }
            assert(slot == none);
        }
        return count;
    }
};

test {
    _ = @import("delivery_test.zig");
}
