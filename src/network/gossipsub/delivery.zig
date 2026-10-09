const std = @import("std");
const storage = @import("message_store.zig");
const constants = @import("constants.zig");
const gossip_limits = @import("../gossip_limits.zig");
const assert = std.debug.assert;
const none = std.math.maxInt(u32);

pub const per_peer_limit = 512;
pub const per_peer_reserve = 64;

/// What produced a queued frame. Each delivery attempt has its own origin, so an IWANT response
/// for a message we published is `iwant`.
pub const Origin = enum { forward, publication, iwant };
pub const origin_count = @typeInfo(Origin).@"enum".fields.len;

/// A cancellable delivery attempt. Its handle does not retain the history payload.
pub const Transmission = struct {
    message: storage.Handle,
    enqueued_ms: u64,
    origin: Origin,
    kind: gossip_limits.Kind,
    len: u32,
    frame_len: u32,
};

/// A frame that QUIC accepted in full.
pub const Receipt = struct { origin: Origin };

const Slot = struct { tx: Transmission = undefined, next: u32 = none };

/// Each queue protects its initial descriptors and unused local reservation.
/// Other work borrows unreserved slots, up to the per-peer limit. Control uses no slots.
pub const Pool = struct {
    slots: []Slot,
    free: u32 = 0,
    available: usize,
    protected: usize,
    /// The part of each peer's protected share that only local publications may use.
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

    fn reserved(self: *const Pool, queued: usize, local: usize) usize {
        assert(local <= queued and self.local_descriptors <= per_peer_reserve);
        return @max(per_peer_reserve -| queued, self.local_descriptors -| local);
    }

    fn acquire(self: *Pool, queued: usize, local: usize, class: Class) ?u32 {
        assert(self.available >= self.protected and queued < per_peer_limit);
        const taken = self.reserved(queued, local) - self.reserved(queued + 1, local + @intFromBool(class == .local));
        if (taken == 0 and self.available == self.protected) return null;
        assert(self.free != none);
        const slot = self.free;
        self.free = self.slots[slot].next;
        self.slots[slot].next = none;
        self.available -= 1;
        self.protected -= taken;
        return slot;
    }

    fn release(self: *Pool, slot: u32, queued: usize, local: usize, class: Class) void {
        assert(queued > 0 and queued <= per_peer_limit and slot < self.slots.len);
        self.slots[slot].next = self.free;
        self.free = slot;
        self.available += 1;
        self.protected += self.reserved(queued - 1, local - @intFromBool(class == .local)) - self.reserved(queued, local);
        assert(self.available >= self.protected and self.available <= self.slots.len);
    }
};

/// Local publications queue apart from ordinary frames, which are forwards and IWANT responses.
/// Both classes share the peer's descriptor and byte limits and the pool's per-peer protected
/// share. Its unused local reservation remains protected when other peers exhaust the pool.
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
    ordinary_kind_entries: [gossip_limits.kind_count]usize = @splat(0),
    ordinary_kind_bytes: [gossip_limits.kind_count]usize = @splat(0),
    /// The class of the frame being written. It stays chosen until the frame completes, so
    /// frames never interleave.
    current: ?Class = null,
    /// Local frames and their bytes chosen in a row while an ordinary frame waited.
    run_frames: usize = 0,
    run_bytes: usize = 0,

    fn classOf(origin: Origin) Class {
        return if (origin == .publication) .local else .ordinary;
    }

    pub fn classCount(self: *const Queue, class: Class) usize {
        const local = self.origins[@intFromEnum(Origin.publication)];
        return if (class == .local) local else self.count - local;
    }

    pub fn append(self: *Queue, store: *const storage.Store, message: storage.Handle, origin: Origin, limits: Limits, now: u64) error{ Descriptors, PoolFull, Bytes }!void {
        const entry = store.get(message).?;
        assert(!entry.provisional and entry.history and self.bytes <= limits.bytes);
        assert(self.pool.local_descriptors < per_peer_limit and limits.local_bytes <= limits.bytes);
        const kind = @intFromEnum(entry.kind);
        const class = classOf(origin);
        if (class == .ordinary) if (store.limits) |allowances| {
            const allowance = allowances[kind];
            // A recipient may queue a quarter of a kind, or one maximum-sized message.
            if (self.ordinary_kind_entries[kind] >= @max(1, allowance.items / 4)) return error.Descriptors;
            if (self.ordinary_kind_entries[kind] > 0 and entry.len > allowance.bytes / 4 -| self.ordinary_kind_bytes[kind]) return error.Bytes;
        };
        const reserved_bytes = if (class == .local) 0 else limits.local_bytes -| self.local_bytes;
        if (if (class == .local) self.count >= per_peer_limit else self.full()) return error.Descriptors;
        if (entry.len + reserved_bytes > limits.bytes - self.bytes) return error.Bytes;
        const slot = self.pool.acquire(self.count, self.classCount(.local), class) orelse return error.PoolFull;
        self.pool.slots[slot].tx = .{
            .message = message,
            .enqueued_ms = now,
            .origin = origin,
            .kind = entry.kind,
            .len = entry.len,
            .frame_len = @intCast(entry.frameLen()),
        };
        const fifo = &self.fifos[@intFromEnum(class)];
        if (fifo.tail == none) fifo.head = slot else self.pool.slots[fifo.tail].next = slot;
        fifo.tail = slot;
        self.count += 1;
        if (class == .ordinary) {
            self.ordinary_kind_entries[kind] += 1;
            self.ordinary_kind_bytes[kind] += entry.len;
        }
        self.origins[@intFromEnum(origin)] += 1;
        self.bytes += entry.len;
        if (class == .local) self.local_bytes += entry.len;
    }

    /// Whether an ordinary frame would be refused for want of a descriptor.
    pub fn full(self: *const Queue) bool {
        return self.count + (self.pool.local_descriptors -| self.classCount(.local)) >= per_peer_limit;
    }

    /// Drops expired or evicted pending frames. Active sends own their backing in the outbox.
    pub fn next(self: *Queue, store: *const storage.Store, now_ms: u64, timeout_ms: u64) ?*const Transmission {
        for (0..self.count + 1) |_| {
            if (self.count == 0) return null;
            const class = self.current orelse self.choose();
            self.current = class;
            const tx = &self.pool.slots[self.fifos[@intFromEnum(class)].head].tx;
            if (now_ms < tx.enqueued_ms +| timeout_ms) {
                if (store.get(tx.message)) |entry| if (entry.history) return tx;
            }
            self.remove(class);
            self.current = null;
        }
        unreachable;
    }

    pub fn complete(self: *Queue) Receipt {
        const class = self.current.?;
        const receipt: Receipt = .{ .origin = self.pool.slots[self.fifos[@intFromEnum(class)].head].tx.origin };
        self.remove(class);
        self.current = null;
        return receipt;
    }

    fn choose(self: *Queue) Class {
        const waiting = self.classCount(.ordinary) > 0;
        if (self.classCount(.local) > 0 and (!waiting or (self.run_frames < local_run_frames and self.run_bytes < local_run_bytes))) {
            if (waiting) {
                self.run_frames += 1;
                self.run_bytes += self.pool.slots[self.fifos[@intFromEnum(Class.local)].head].tx.frame_len;
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

    fn remove(self: *Queue, class: Class) void {
        const fifo = &self.fifos[@intFromEnum(class)];
        const slot = fifo.head;
        const tx = &self.pool.slots[slot].tx;
        const len = tx.len;
        if (class == .ordinary) {
            self.ordinary_kind_entries[@intFromEnum(tx.kind)] -= 1;
            self.ordinary_kind_bytes[@intFromEnum(tx.kind)] -= len;
        }
        fifo.head = self.pool.slots[slot].next;
        if (fifo.head == none) fifo.tail = none;
        self.pool.release(slot, self.count, self.classCount(.local), class);
        self.origins[@intFromEnum(tx.origin)] -= 1;
        self.bytes -= len;
        if (class == .local) self.local_bytes -= len;
        self.count -= 1;
    }

    pub fn reset(self: *Queue) void {
        for (0..self.count) |_| self.remove(if (self.classCount(.local) > 0) .local else .ordinary);
        assert(self.count == 0 and self.bytes == 0 and self.local_bytes == 0);
        assert(self.fifos[0].head == none and self.fifos[1].head == none);
        self.current = null;
        self.endRun();
    }
};

test {
    _ = @import("delivery_test.zig");
}
